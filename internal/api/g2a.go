package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openbasalt/samba-conductor-sync/internal/app"
	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/g2a"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// ---- Google-first mode (Google Workspace to AD) ----

// g2aPlan reads Google and AD (read-only on both sides), records the plan
// as a run of action g2a and returns it. Audit: g2a.plan with the request
// and the counts, never personal data.
func (s *Server) g2aPlan(ctx context.Context, req syncapi.Request, p *syncapi.G2APlanParams) (*syncapi.G2APlan, error) {
	cfg, err := s.rt.Effective(ctx)
	if err != nil {
		return nil, err
	}
	pl, runID, err := s.rt.G2APlan(ctx, cfg, *p, actorName(req.Actor), "manual")
	if err != nil {
		s.audit(ctx, req, "g2a.plan", "google-first", app.G2APlanSummary(*p, nil, runID)+"; "+app.G2AErrorSummary(err), store.ResultFailed)
		var se *g2a.SelectionError
		switch {
		case errors.Is(err, app.ErrG2ADisabled):
			return nil, &syncapi.Error{Code: syncapi.CodeConflict, Message: err.Error()}
		case errors.Is(err, app.ErrG2AUnknownScope):
			return nil, &syncapi.Error{Code: syncapi.CodeNotFound, Message: err.Error()}
		case errors.As(err, &se):
			return nil, errInvalid{msg: "the Google selection stops the read", details: []string{se.Code + ": " + se.Error()}}
		case errors.Is(err, g2a.ErrNoMarkerAttribute):
			return nil, errInvalid{msg: err.Error()}
		case errors.Is(err, connector.ErrAuth) || errors.Is(err, app.ErrNoKey):
			return nil, &syncapi.Error{Code: syncapi.CodeUnavailable, Message: err.Error()}
		}
		return nil, err
	}
	s.audit(ctx, req, "g2a.plan", "google-first", app.G2APlanSummary(*p, pl, runID), store.ResultInfo)
	// One answer must fit in a message; the whole plan stays readable page
	// by page with run.get.
	if b, err := json.Marshal(pl); err != nil {
		return nil, err
	} else if len(b) > syncapi.MaxMessageSize-64<<10 {
		return nil, errInvalid{msg: fmt.Sprintf("the plan of run %d is too large for one answer", runID),
			details: []string{fmt.Sprintf("read it page by page with run.get (run %d), or plan one scope at a time", runID)}}
	}
	return pl, nil
}

// g2aConfirm records what conductor applied: links written, run closed.
func (s *Server) g2aConfirm(ctx context.Context, req syncapi.Request, p *syncapi.G2AConfirmParams) (*syncapi.G2AConfirmResult, error) {
	res, err := s.rt.G2AConfirm(ctx, *p)
	detail := fmt.Sprintf("run %d, digest %s, approved by %s, %d results", p.RunID, p.Digest, p.Actor, len(p.Results))
	if err != nil {
		s.audit(ctx, req, "g2a.confirm", fmt.Sprintf("run %d", p.RunID), detail+"; refused: "+g2aConfirmReason(err), store.ResultFailed)
		var ce *g2a.ConfirmError
		switch {
		case errors.Is(err, app.ErrG2ANoPlan):
			return nil, &syncapi.Error{Code: syncapi.CodeNotFound, Message: err.Error()}
		case errors.Is(err, app.ErrG2ADigest), errors.Is(err, store.ErrG2AClosed):
			return nil, &syncapi.Error{Code: syncapi.CodeConflict, Message: err.Error()}
		case errors.As(err, &ce):
			return nil, errInvalid{msg: "the results do not match the plan", details: []string{ce.Message}}
		}
		return nil, err
	}
	s.audit(ctx, req, "g2a.confirm", fmt.Sprintf("run %d", p.RunID), fmt.Sprintf("%s; status %s, done %d, failed %d, skipped %d, links %d",
		detail, res.Status, res.Done, res.Failed, res.Skipped, res.Links), store.ResultOK)
	return res, nil
}

// g2aConfirmReason is the audit text of a refused confirmation (no
// personal data: the plan's mismatch messages name operation numbers and
// scopes only).
func g2aConfirmReason(err error) string {
	var ce *g2a.ConfirmError
	switch {
	case errors.As(err, &ce):
		return ce.Message
	case errors.Is(err, app.ErrG2ANoPlan), errors.Is(err, app.ErrG2ADigest), errors.Is(err, store.ErrG2AClosed):
		return err.Error()
	}
	return "internal error"
}

// g2aRunGet fills the detail of a g2a run: its plan with one page of
// operations (Offset and Limit over the operations of every scope, in Seq
// order) and the results conductor reported.
func (s *Server) g2aRunGet(ctx context.Context, out *syncapi.RunDetail, p *syncapi.RunGetParams) (*syncapi.RunDetail, error) {
	pl, results, err := s.rt.LoadG2A(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if pl == nil {
		return out, nil
	}
	out.HasPlan, out.Digest = true, pl.Digest
	out.Counts = map[string]int{}
	limit := p.Limit
	if limit == 0 {
		limit = 100
	}
	failed := map[int]bool{}
	for _, r := range results {
		if r.Status != syncapi.G2AOpDone {
			failed[r.Seq] = true
		}
	}
	page := *pl
	page.Scopes = nil
	for _, sc := range pl.Scopes {
		for k, n := range g2a.Counts(sc) {
			out.Counts[k] += n
		}
		ps := sc
		ps.Ops = []syncapi.G2AOp{}
		for _, o := range sc.Ops {
			if p.FailedOnly && !failed[o.Seq] {
				continue
			}
			out.OpsMatching++
			if out.OpsMatching > p.Offset && countOps(page.Scopes)+len(ps.Ops) < limit {
				ps.Ops = append(ps.Ops, o)
			}
		}
		page.Scopes = append(page.Scopes, ps)
	}
	out.G2A, out.G2AResults = &page, results
	out.NotApply = "g2a"
	return out, nil
}

func countOps(scopes []syncapi.G2AScopePlan) int {
	n := 0
	for _, s := range scopes {
		n += len(s.Ops)
	}
	return n
}
