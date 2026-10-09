package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/openbasalt/samba-conductor-sync/internal/config"
	"github.com/openbasalt/samba-conductor-sync/internal/g2a"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// G2ASource is implemented by AD sources that can read what a Google-first
// plan needs (adsource.Reader, through LazySource; tests use fixtures).
type G2ASource interface {
	ReadG2A(ctx context.Context, req g2a.ADRequest) (*g2a.ADState, error)
}

// ReadG2A implements G2ASource.
func (l *LazySource) ReadG2A(ctx context.Context, req g2a.ADRequest) (*g2a.ADState, error) {
	r, err := l.reader()
	if err != nil {
		return nil, err
	}
	return r.ReadG2A(ctx, req)
}

// Errors of the Google-first plan that are the caller's to fix.
var (
	ErrG2ADisabled     = errors.New("the Google-first mode is not enabled (google_first.enabled)")
	ErrG2AUnknownScope = errors.New("no such Google-first scope")
)

// storedG2A is the stored form of a g2a plan: the plan the API returns and
// the accounts with their Google values (link snapshots).
type storedG2A struct {
	Plan     *syncapi.G2APlan `json:"plan"`
	Accounts []g2a.Account    `json:"accounts,omitempty"`
}

// g2aSummary is the summary of a g2a run, readable as an engine summary
// (counts, violations, warnings, skipped) plus each scope's source size.
type g2aSummary struct {
	Counts     map[string]int      `json:"counts"`
	Violations []syncapi.Violation `json:"violations,omitempty"`
	Warnings   int                 `json:"warnings"`
	Skipped    int                 `json:"skipped_source_objects"`
	Scopes     map[string]int      `json:"scopes,omitempty"`
}

func summarizeG2A(p *syncapi.G2APlan) g2aSummary {
	s := g2aSummary{Counts: map[string]int{}, Scopes: map[string]int{}}
	for _, sc := range p.Scopes {
		for k, n := range g2a.Counts(sc) {
			s.Counts[k] += n
		}
		for _, r := range sc.Limits {
			if r.Exceeded {
				s.Violations = append(s.Violations, syncapi.Violation{Limit: sc.Name + "." + r.Limit, Value: r.Value, Max: r.Max})
			}
		}
		s.Warnings += len(sc.Warnings)
		s.Skipped += len(sc.Skipped)
		s.Scopes[sc.Name] = sc.SourceSize
	}
	return s
}

// G2APlan reads Google (read-only scopes) and AD (read-only account),
// builds the Google-first plan of one scope (or all) and records it as a
// run of action g2a. Nothing is written to Google or AD. A read that fails
// (an empty selection, a missing org unit or group, the schema without the
// marker attribute) records a failed run and returns the error.
func (r *Runtime) G2APlan(ctx context.Context, cfg *config.Config, p syncapi.G2APlanParams, actor, trigger string) (*syncapi.G2APlan, int64, error) {
	started := r.Now()
	pl, accounts, err := r.g2aBuild(ctx, cfg, p)
	run := store.G2ARun{Connector: cfg.Connector, Trigger: trigger, Actor: actor, StartedAt: started}
	if err != nil {
		if errors.Is(err, ErrG2ADisabled) || errors.Is(err, ErrG2AUnknownScope) {
			return nil, 0, err
		}
		run.Status, run.Error = store.StatusFailed, err.Error()
		id, serr := r.Store.SaveG2ARun(context.WithoutCancel(ctx), run)
		if serr != nil {
			return nil, 0, errors.Join(err, serr)
		}
		return nil, id, err
	}
	raw, err := json.Marshal(storedG2A{Plan: pl, Accounts: accounts})
	if err != nil {
		return nil, 0, err
	}
	run.Status, run.Digest, run.Plan, run.Summary = store.StatusPlanned, pl.Digest, raw, summarizeG2A(pl)
	for _, sc := range pl.Scopes {
		run.SourceUsers += sc.SourceSize
		run.OpsTotal += len(sc.Ops)
	}
	id, err := r.Store.SaveG2ARun(context.WithoutCancel(ctx), run)
	if err != nil {
		return nil, 0, err
	}
	pl.RunID = id
	return pl, id, nil
}

func (r *Runtime) g2aBuild(ctx context.Context, cfg *config.Config, p syncapi.G2APlanParams) (*syncapi.G2APlan, []g2a.Account, error) {
	if !cfg.GoogleFirst.Enabled {
		return nil, nil, ErrG2ADisabled
	}
	all := cfg.G2AScopes()
	var scopes []g2a.Scope
	inPlan := map[string]bool{}
	for _, sc := range all {
		if p.Scope == "" || sc.Name == p.Scope {
			scopes = append(scopes, sc)
			inPlan[sc.Name] = true
		}
	}
	if p.Scope != "" && len(scopes) == 0 {
		return nil, nil, fmt.Errorf("%w: %s", ErrG2AUnknownScope, p.Scope)
	}
	if len(scopes) == 0 {
		return nil, nil, fmt.Errorf("%w: no scope is configured", ErrG2AUnknownScope)
	}
	src, ok := r.NewSource(cfg).(G2ASource)
	if !ok {
		return nil, nil, errors.New("the AD source cannot read for the Google-first mode")
	}
	// Google: the read-only scopes only.
	conn, err := r.Connector(ctx, cfg, false)
	if err != nil {
		return nil, nil, err
	}
	needGroups := false
	for _, sc := range all {
		needGroups = needGroups || len(sc.MemberOf) > 0
	}
	snap, err := conn.Snapshot(ctx, needGroups)
	if err != nil {
		return nil, nil, err
	}
	sel, err := g2a.Select(g2a.FromTarget(snap.Users, cfg.Google.AdminSubject), snap.Groups, all, cfg.GoogleFirst.GoogleDomain, inPlan)
	if err != nil {
		return nil, nil, err
	}
	realm := strings.ToLower(cfg.Source.Realm)
	state, err := src.ReadG2A(ctx, g2a.Request(sel, scopes, realm, p.RoleGroupSIDs))
	if err != nil {
		return nil, nil, err
	}
	links, err := r.g2aLinks(ctx)
	if err != nil {
		return nil, nil, err
	}
	prev, err := r.g2aPreviousSizes(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	res, err := g2a.Build(g2a.Input{Now: r.Now(), GoogleDomain: cfg.GoogleFirst.GoogleDomain, Realm: realm, Scopes: scopes,
		Selection: sel, AD: state, Links: links, PreviousSourceSize: prev})
	if err != nil {
		return nil, nil, err
	}
	return res.Plan, res.Accounts, nil
}

func (r *Runtime) g2aLinks(ctx context.Context) ([]g2a.Link, error) {
	rows, err := r.Store.G2ALinks(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]g2a.Link, 0, len(rows))
	for _, l := range rows {
		out = append(out, g2a.Link{Scope: l.Scope, GoogleID: l.GoogleID, ObjectGUID: l.ObjectGUID, SID: l.SID, SAM: l.SAM,
			DisabledBySync: l.DisabledBySync, Snapshot: l.Snapshot})
	}
	return out, nil
}

// g2aPreviousSizes returns each scope's source size at the newest g2a run
// that applied something (the drop limit compares with it).
func (r *Runtime) g2aPreviousSizes(ctx context.Context, cfg *config.Config) (map[string]int, error) {
	run, err := r.Store.LastRunWithStatus(ctx, cfg.Connector, store.RunActionG2A, store.StatusApplied, store.StatusPartial)
	if err != nil || run == nil {
		return nil, err
	}
	var s g2aSummary
	if err := json.Unmarshal(run.Summary, &s); err != nil {
		return nil, nil
	}
	return s.Scopes, nil
}

// LoadG2A returns the stored plan of a g2a run and the results conductor
// reported (nil plan when the run has none).
func (r *Runtime) LoadG2A(ctx context.Context, runID int64) (*syncapi.G2APlan, []syncapi.G2AOpResult, error) {
	st, results, err := r.loadG2A(ctx, runID)
	if err != nil || st == nil {
		return nil, nil, err
	}
	return st.Plan, results, nil
}

func (r *Runtime) loadG2A(ctx context.Context, runID int64) (*storedG2A, []syncapi.G2AOpResult, error) {
	raw, rawResults, err := r.Store.LoadG2APlan(ctx, runID)
	if err != nil || raw == nil {
		return nil, nil, err
	}
	var st storedG2A
	if err := json.Unmarshal(raw, &st); err != nil || st.Plan == nil {
		return nil, nil, fmt.Errorf("stored g2a plan of run %d: unreadable", runID)
	}
	st.Plan.RunID = runID
	var results []syncapi.G2AOpResult
	_ = json.Unmarshal(rawResults, &results)
	return &st, results, nil
}

// ErrG2ANoPlan: the run recorded no g2a plan.
var ErrG2ANoPlan = errors.New("no g2a plan")

// ErrG2ADigest: the digest is not the plan's.
var ErrG2ADigest = errors.New("the digest does not match the plan of that run")

// G2AConfirm records what conductor applied of the plan of run p.RunID:
// it checks the results against the plan (g2a.Confirm), writes the links
// and closes the run, in one transaction.
func (r *Runtime) G2AConfirm(ctx context.Context, p syncapi.G2AConfirmParams) (*syncapi.G2AConfirmResult, error) {
	run, err := r.Store.GetRun(ctx, p.RunID)
	if err != nil {
		return nil, err
	}
	if run == nil || run.Action != store.RunActionG2A {
		return nil, fmt.Errorf("%w: run %d", ErrG2ANoPlan, p.RunID)
	}
	st, _, err := r.loadG2A(ctx, p.RunID)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("%w: run %d", ErrG2ANoPlan, p.RunID)
	}
	if st.Plan.Digest != p.Digest {
		return nil, ErrG2ADigest
	}
	if run.Status != store.StatusPlanned {
		return nil, store.ErrG2AClosed
	}
	links, err := r.g2aLinks(ctx)
	if err != nil {
		return nil, err
	}
	out, err := g2a.Confirm(&g2a.Result{Plan: st.Plan, Accounts: st.Accounts}, links, p.Results)
	if err != nil {
		return nil, err
	}
	results := append([]syncapi.G2AOpResult(nil), p.Results...)
	sort.Slice(results, func(i, j int) bool { return results[i].Seq < results[j].Seq })
	raw, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	rows := make([]store.G2ALink, 0, len(out.Links))
	for _, l := range out.Links {
		rows = append(rows, store.G2ALink{Scope: l.Scope, GoogleID: l.GoogleID, ObjectGUID: l.ObjectGUID, SID: l.SID, SAM: l.SAM,
			DisabledBySync: l.DisabledBySync, Snapshot: l.Snapshot})
	}
	if err := r.Store.ConfirmG2A(ctx, p.RunID, out.Status, out.Done, out.Failed, raw, rows); err != nil {
		return nil, err
	}
	return &syncapi.G2AConfirmResult{RunID: p.RunID, Status: out.Status, Done: out.Done, Failed: out.Failed, Skipped: out.Skipped,
		Links: len(rows)}, nil
}

// G2APlanSummary is one audit line for a g2a plan: the request, each
// scope's mode, sizes and counts (no personal data: no address, name or
// logon name).
func G2APlanSummary(p syncapi.G2APlanParams, pl *syncapi.G2APlan, runID int64) string {
	var b strings.Builder
	scope := p.Scope
	if scope == "" {
		scope = "all"
	}
	fmt.Fprintf(&b, "scope=%s role_groups=%d", scope, len(p.RoleGroupSIDs))
	if runID > 0 {
		fmt.Fprintf(&b, "; run %d", runID)
	}
	if pl == nil {
		return b.String()
	}
	fmt.Fprintf(&b, ", digest %s", pl.Digest)
	for _, sc := range pl.Scopes {
		fmt.Fprintf(&b, "; %s mode=%s source=%d managed=%d blocked=%v", sc.Name, sc.Mode, sc.SourceSize, sc.Managed, sc.Blocked)
		counts := g2a.Counts(sc)
		for _, k := range syncapi.G2AKinds {
			if counts[k] > 0 {
				fmt.Fprintf(&b, " %s=%d", k, counts[k])
			}
		}
		skips := map[string]int{}
		for _, s := range sc.Skipped {
			skips[s.Reason]++
		}
		var reasons []string
		for k := range skips {
			reasons = append(reasons, k)
		}
		sort.Strings(reasons)
		for _, k := range reasons {
			fmt.Fprintf(&b, " skipped:%s=%d", k, skips[k])
		}
	}
	return b.String()
}

// G2AErrorSummary describes a failed g2a read for the audit log without
// personal data: selection errors name the scope and the org unit or
// group; anything else only says which side failed.
func G2AErrorSummary(err error) string {
	var se *g2a.SelectionError
	switch {
	case errors.As(err, &se):
		return se.Code + ": " + se.Error()
	case errors.Is(err, g2a.ErrNoMarkerAttribute):
		return "schema: " + syncapi.G2AMarkerAttribute + " missing"
	case errors.Is(err, ErrG2ADisabled), errors.Is(err, ErrG2AUnknownScope):
		return err.Error()
	}
	return "read failed (the run records the error)"
}
