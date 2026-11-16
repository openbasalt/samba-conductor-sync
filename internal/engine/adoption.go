package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/source"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
)

// Adoption approvals: an administrator approves one candidate of the
// latest recorded plan (one AD object, one existing target object, one
// address). The approval is checked at once (privilege and address
// uniqueness in AD) and audited; the next plan adopts the object when
// everything still matches. Revoking an approval stops a pending adoption
// and the self-service password reset of an adopted account; it does not
// unlink an object already adopted.

// ErrApprovalRefused is returned when an approval is not allowed.
var ErrApprovalRefused = errors.New("adoption approval refused")

// Adoptions returns the candidates of the latest recorded plan (0 and nil
// when no plan exists) and the recorded approvals.
func (e *Engine) Adoptions(ctx context.Context) (runID int64, cands []plan.Candidate, approvals []store.ApprovalRow, err error) {
	if runID, err = e.Store.LatestPlanRun(ctx, e.ConnectorName); err != nil {
		return 0, nil, nil, err
	}
	if runID != 0 {
		p, err := e.Store.LoadPlan(ctx, runID)
		if err != nil {
			return 0, nil, nil, err
		}
		if p != nil {
			cands = p.Candidates
		}
	}
	approvals, err = e.Store.Approvals(ctx, e.ConnectorName)
	return runID, cands, approvals, err
}

// ApproveRequest names the candidate to approve.
type ApproveRequest struct {
	Kind     model.Kind
	SourceID string
	TargetID string
	Comment  string
}

// ApproveAdoption records an administrator's approval of one candidate of
// the latest plan, or the confirmation of an object adopted before
// approvals existed (an adopted link with the same target). It refuses
// target administrators, groups with an administrator role, AD objects that
// are privileged and addresses that another AD object carries.
func (e *Engine) ApproveAdoption(ctx context.Context, req ApproveRequest) (*plan.Approval, error) {
	if req.Kind != model.KindUser && req.Kind != model.KindGroup {
		return nil, fmt.Errorf("%w: kind must be user or group", ErrApprovalRefused)
	}
	if req.SourceID == "" || req.TargetID == "" {
		return nil, fmt.Errorf("%w: the AD objectGUID and the target ID are required", ErrApprovalRefused)
	}
	runID, cands, _, err := e.Adoptions(ctx)
	if err != nil {
		return nil, err
	}
	var found *plan.Candidate
	for i := range cands {
		c := &cands[i]
		if c.Kind == req.Kind && strings.EqualFold(c.SourceID, req.SourceID) {
			found = c
			break
		}
	}
	ap := plan.Approval{Kind: req.Kind, SourceID: req.SourceID, TargetID: req.TargetID, By: e.Actor}
	what := ""
	switch {
	case found != nil:
		if found.TargetID != req.TargetID {
			return nil, fmt.Errorf("%w: plan run %d pairs this AD object with target %s, not %s", ErrApprovalRefused, runID, found.TargetID, req.TargetID)
		}
		if found.Status == plan.CandidateRefused && (found.Reason == plan.RefuseTargetAdmin || found.Reason == plan.RefuseGroupAdminRole) {
			return nil, fmt.Errorf("%w: %s %s can never be adopted (%s)", ErrApprovalRefused, found.Kind, found.Address, found.Reason)
		}
		ap.SourceID, ap.Address = found.SourceID, found.Address
		what = fmt.Sprintf("candidate of plan run %d: AD %s (%s)", runID, found.Account, found.SourceDN)
	default:
		// A link adopted before approvals existed: confirm it.
		l, err := e.userOrGroupLink(ctx, req.Kind, req.SourceID)
		if err != nil {
			return nil, err
		}
		if l == nil || !l.Adopted || l.TargetID != req.TargetID {
			if runID == 0 {
				return nil, fmt.Errorf("%w: no recorded plan; run conductor-sync plan first", ErrApprovalRefused)
			}
			return nil, fmt.Errorf("%w: plan run %d has no adoption candidate %s %s, and no adopted link to target %s",
				ErrApprovalRefused, runID, req.Kind, req.SourceID, req.TargetID)
		}
		ap.SourceID, ap.Address = l.SourceID, l.Key
		what = "confirmation of an adoption made before approvals existed: " + l.SourceDN
	}
	// Check now, so an approval that could never apply is refused at once.
	checker, ok := e.Source.(source.AdoptionChecker)
	if !ok {
		return nil, fmt.Errorf("%w: the source can not check adoption candidates", ErrApprovalRefused)
	}
	checks, err := checker.CheckAdoption(ctx, []source.AdoptionQuery{{Kind: ap.Kind, ID: ap.SourceID, Address: ap.Address}})
	if err != nil {
		return nil, fmt.Errorf("adoption check: %w", err)
	}
	chk, ok := checks[plan.AdoptionKey(ap.Kind, ap.SourceID)]
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: the AD checks did not answer for %s", ErrApprovalRefused, ap.SourceID)
	case len(chk.Privileged) > 0:
		e.audit(ctx, "adoption.approve", string(ap.Kind)+" "+ap.Address, "refused: privileged in AD: "+strings.Join(chk.Privileged, "; "), store.ResultBlocked)
		return nil, fmt.Errorf("%w: the AD object is privileged (%s)", ErrApprovalRefused, strings.Join(chk.Privileged, "; "))
	case len(chk.Duplicates) > 0:
		e.audit(ctx, "adoption.approve", string(ap.Kind)+" "+ap.Address, "refused: address also on "+strings.Join(chk.Duplicates, "; "), store.ResultBlocked)
		return nil, fmt.Errorf("%w: %s is also carried by %s; the address must be unique in the directory",
			ErrApprovalRefused, ap.Address, strings.Join(chk.Duplicates, "; "))
	}
	if err := e.Store.PutApproval(ctx, e.ConnectorName, ap, req.Comment); err != nil {
		return nil, err
	}
	detail := fmt.Sprintf("source %s, target %s; %s", ap.SourceID, ap.TargetID, what)
	if req.Comment != "" {
		detail += "; comment: " + req.Comment
	}
	e.audit(ctx, "adoption.approve", string(ap.Kind)+" "+ap.Address, detail, store.ResultOK)
	return &ap, nil
}

// RevokeAdoption removes an approval (audited). It reports whether one
// existed.
func (e *Engine) RevokeAdoption(ctx context.Context, kind model.Kind, sourceID string) (bool, error) {
	ok, err := e.Store.DeleteApproval(ctx, e.ConnectorName, kind, sourceID)
	if err != nil {
		return false, err
	}
	if ok {
		e.audit(ctx, "adoption.revoke", string(kind)+" "+sourceID, "approval removed", store.ResultOK)
	}
	return ok, nil
}

func (e *Engine) userOrGroupLink(ctx context.Context, kind model.Kind, sourceID string) (*store.LinkRow, error) {
	rows, err := e.Store.Links(ctx, e.ConnectorName)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Kind == kind && strings.EqualFold(rows[i].SourceID, sourceID) {
			return &rows[i], nil
		}
	}
	return nil, nil
}

// adoptionConfirmed reports whether an approval matches an adopted link
// (the same target): only then may the self-service reset its password.
func (e *Engine) adoptionConfirmed(ctx context.Context, l *store.LinkRow) (bool, error) {
	rows, err := e.Store.Approvals(ctx, e.ConnectorName)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.Kind == l.Kind && r.SourceID == l.SourceID && r.TargetID == l.TargetID {
			return true, nil
		}
	}
	return false, nil
}
