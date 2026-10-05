package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/passwd"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/source"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// Self-service: what a signed-in user may do with their own account on the
// target, requested in conductor ("Connected accounts") and never by the
// scheduler. The user is always the request's actor, found in AD by SID.
//
// Rules enforced here:
//   - the sync must be in apply mode (dry-run writes nothing, not even
//     this);
//   - only users in the sync scope, enabled, with a valid mapping, get an
//     account; an activation goes through the same plan as a sync run (the
//     mapping, the scope, the address checks, the ownership marker), and
//     applies only that user's create (and its memberships in existing
//     groups), journaled as a run of its own;
//   - a password is set only on the user's linked account that carries the
//     sync's marker for them, never on a target administrator (or the
//     sync's own subject), never on a suspended account, and on an adopted
//     account only when self_service.password_reset allows it;
//   - actions are rate limited per user and per target;
//   - the password (generated or chosen) goes to the target once and is
//     returned once when generated; it is never stored, logged or audited.

// SelfServicePolicy is the [self_service] policy of the target.
type SelfServicePolicy struct {
	// Activation: "auto" or "self-service".
	Activation string
	// PasswordReset: "created", "created-and-adopted" or "off".
	PasswordReset string
	// ChosenPassword lets users type their own password.
	ChosenPassword bool
	// PasswordMinLength raises the target's minimum length.
	PasswordMinLength int
	// MaxPerUserHour and MaxPerTargetHour bound the actions in any hour.
	MaxPerUserHour, MaxPerTargetHour int
}

// SelfServiceError is a self-service action that is not allowed, with its
// reason code (syncapi.Reason*). The message never holds a password.
type SelfServiceError struct {
	Reason  string
	Message string
}

func (e *SelfServiceError) Error() string { return e.Message }

func refuse(reason, format string, args ...any) error {
	return &SelfServiceError{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// ErrRateLimited: too many self-service actions in the last hour.
var ErrRateLimited = errors.New("too many self-service actions in the last hour; try again later")

func (e *Engine) limits() store.SelfServiceLimit {
	return store.SelfServiceLimit{PerUser: max(1, e.SelfService.MaxPerUserHour), PerTarget: max(1, e.SelfService.MaxPerTargetHour), Window: time.Hour}
}

// rules are the connector's password rules raised by the policy.
func (e *Engine) rules(ss connector.SelfService) passwd.Rules {
	if ss == nil {
		return passwd.Rules{}
	}
	r := ss.Rules()
	out := passwd.Rules{MinLength: max(r.MinLength, e.SelfService.PasswordMinLength), MaxLength: r.MaxLength,
		PrintableASCII: r.PrintableASCII, NoEdgeSpaces: r.NoEdgeSpaces}
	if out.MaxLength > 0 && out.MinLength > out.MaxLength {
		out.MinLength = out.MaxLength
	}
	return out
}

// accountView is what the engine knows of the actor's account.
type accountView struct {
	acct syncapi.TargetAccount
	ss   connector.SelfService
	user *model.SourceUser
	link *store.LinkRow
	tu   *model.TargetUser
}

// AccountStatus returns the actor's account on the target, with the actions
// allowed now. It writes nothing.
func (e *Engine) AccountStatus(ctx context.Context, actorSID string) (*syncapi.TargetAccount, error) {
	conn, err := e.Connect(false)
	if err != nil {
		return nil, err
	}
	v, err := e.inspect(ctx, conn, actorSID)
	if err != nil {
		return nil, err
	}
	return &v.acct, nil
}

func (e *Engine) userLink(ctx context.Context, sourceID string) (*store.LinkRow, error) {
	rows, err := e.Store.Links(ctx, e.ConnectorName)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Kind == model.KindUser && rows[i].SourceID == sourceID {
			return &rows[i], nil
		}
	}
	return nil, nil
}

// inspect reads the actor's AD user (one lookup) and their account on the
// target (one read) and decides what is allowed.
func (e *Engine) inspect(ctx context.Context, conn connector.Connector, actorSID string) (*accountView, error) {
	v := &accountView{acct: syncapi.TargetAccount{Target: e.ConnectorName, Title: e.ConnectorName, State: syncapi.AccountUnknown}}
	a := &v.acct
	if ss, ok := conn.(connector.SelfService); ok {
		v.ss = ss
		c := ss.Capabilities()
		a.Title = c.Title
		a.Capabilities = syncapi.Capabilities{OnDemandCreate: c.OnDemandCreate, SetPassword: c.SetPassword, PasswordRules: c.PasswordRules, Status: c.Status}
		r := e.rules(ss)
		a.Rules = syncapi.PasswordRules{MinLength: r.MinLength, MaxLength: r.MaxLength, PrintableASCII: r.PrintableASCII, NoEdgeSpaces: r.NoEdgeSpaces}
		a.ChosenPassword = e.SelfService.ChosenPassword && (c.SetPassword || c.OnDemandCreate)
	} else {
		a.Capabilities.Status = true
	}
	left, err := e.Store.SelfServiceLeft(ctx, e.ConnectorName, actorSID, e.limits())
	if err != nil {
		return nil, err
	}
	a.ActionsLeft = left
	a.ActivateReason, a.PasswordReason = syncapi.ReasonNotLinked, syncapi.ReasonNotLinked

	look, err := source.Lookup(ctx, e.Source, actorSID)
	if err != nil {
		fmt.Fprintf(e.out(), "self-service: AD lookup of %s: %v\n", actorSID, err)
		a.Reason, a.ActivateReason, a.PasswordReason = syncapi.ReasonUnavailable, syncapi.ReasonUnavailable, syncapi.ReasonUnavailable
		return v, nil
	}
	v.user = look.User
	if look.User != nil {
		if v.link, err = e.userLink(ctx, look.User.ID); err != nil {
			return nil, err
		}
	}
	if v.link != nil {
		e.inspectLinked(ctx, conn, v, look)
		return v, nil
	}
	a.ActivateReason = ""
	su := look.User
	switch {
	case su == nil || !look.InScope:
		a.State, a.Reason = syncapi.AccountNotEligible, syncapi.ReasonOutOfScope
	case !su.Enabled:
		a.State, a.Reason = syncapi.AccountNotEligible, syncapi.ReasonDisabled
	case su.Error != "":
		a.State, a.Reason = syncapi.AccountNotEligible, syncapi.ReasonMappingError
	case model.NormalizeEmail(su.Attrs[model.FieldPrimaryEmail]) == "":
		a.State, a.Reason = syncapi.AccountNotEligible, syncapi.ReasonNoAddress
	}
	if a.State == syncapi.AccountNotEligible {
		a.ActivateReason = a.Reason
		return v, nil
	}
	email := model.NormalizeEmail(su.Attrs[model.FieldPrimaryEmail])
	a.Address = email
	tu, err := conn.GetUser(ctx, email)
	switch {
	case err == nil:
		switch {
		case tu.Owner == su.ID && model.NormalizeEmail(tu.Attrs[model.FieldPrimaryEmail]) == email:
			// Carries the marker: the next run relinks it.
			a.State, a.Reason = syncapi.AccountPendingSync, syncapi.ReasonExistingAccount
		case tu.Owner == "" && model.NormalizeEmail(tu.Attrs[model.FieldPrimaryEmail]) == email && e.Policy.Adopt == plan.AdoptEmail:
			a.State, a.Reason = syncapi.AccountPendingSync, syncapi.ReasonExistingAccount
		default:
			a.State, a.Reason = syncapi.AccountNotEligible, syncapi.ReasonAddressTaken
		}
		a.ActivateReason = a.Reason
	case errors.Is(err, connector.ErrNotFound):
		if e.SelfService.Activation != "self-service" {
			a.State, a.Reason, a.ActivateReason = syncapi.AccountPendingSync, syncapi.ReasonActivationAuto, syncapi.ReasonActivationAuto
			return v, nil
		}
		a.State = syncapi.AccountNotActivated
		switch {
		case v.ss == nil || !a.Capabilities.OnDemandCreate:
			a.ActivateReason = syncapi.ReasonNotSupported
		case e.Mode != ModeApply:
			a.ActivateReason = syncapi.ReasonDryRun
		default:
			a.CanActivate = true
		}
	default:
		fmt.Fprintf(e.out(), "self-service: reading %s: %v\n", email, err)
		a.State, a.Reason, a.ActivateReason = syncapi.AccountUnknown, syncapi.ReasonUnavailable, syncapi.ReasonUnavailable
	}
	return v, nil
}

// inspectLinked fills the view of a linked account.
func (e *Engine) inspectLinked(ctx context.Context, conn connector.Connector, v *accountView, look *source.UserScope) {
	a := &v.acct
	a.ActivateReason = syncapi.ReasonAlreadyActive
	a.Address = v.link.Key
	tu, err := conn.GetUser(ctx, v.link.TargetID)
	if errors.Is(err, connector.ErrNotFound) {
		// Removed outside the sync: the next run unlinks it (and creates
		// it again when the user is eligible).
		a.State, a.Reason, a.PasswordReason = syncapi.AccountPendingSync, syncapi.ReasonNotLinked, syncapi.ReasonNotLinked
		return
	}
	if err != nil {
		fmt.Fprintf(e.out(), "self-service: reading %s: %v\n", v.link.TargetID, err)
		a.State, a.Reason, a.PasswordReason = syncapi.AccountUnknown, syncapi.ReasonUnavailable, syncapi.ReasonUnavailable
		return
	}
	v.tu = tu
	a.Address = model.NormalizeEmail(tu.Attrs[model.FieldPrimaryEmail])
	a.State = syncapi.AccountActive
	if tu.Suspended {
		a.State = syncapi.AccountSuspended
	}
	adopted := v.link.Adopted || tu.Adopted
	a.Origin = syncapi.OriginCreated
	if adopted {
		a.Origin = syncapi.OriginAdopted
	}
	a.PasswordReason = ""
	switch {
	case v.ss == nil || !a.Capabilities.SetPassword:
		a.PasswordReason = syncapi.ReasonNotSupported
	case e.Mode != ModeApply:
		a.PasswordReason = syncapi.ReasonDryRun
	case e.SelfService.PasswordReset == "off":
		a.PasswordReason = syncapi.ReasonResetOff
	case tu.Protected:
		// Target administrators and the sync's own subject: never.
		a.PasswordReason = syncapi.ReasonAdmin
	case tu.Owner != v.link.SourceID:
		a.PasswordReason = syncapi.ReasonNotOwned
	case tu.Suspended:
		a.PasswordReason = syncapi.ReasonSuspended
	case adopted && e.SelfService.PasswordReset != "created-and-adopted":
		a.PasswordReason = syncapi.ReasonAdopted
	case look.User == nil || !look.InScope:
		a.PasswordReason = syncapi.ReasonOutOfScope
	case !look.User.Enabled:
		a.PasswordReason = syncapi.ReasonDisabled
	default:
		a.CanSetPassword = true
	}
}

// newPassword returns the password of an action: the user's own (checked
// against the rules) or a generated one (returned to show once).
func (e *Engine) newPassword(v *accountView, choice syncapi.PasswordChoice) (pw string, generated bool, err error) {
	rules := e.rules(v.ss)
	switch choice.Mode {
	case syncapi.PasswordChosen:
		if !v.acct.ChosenPassword {
			return "", false, refuse(syncapi.ReasonChosenOff, "typed passwords are not allowed for this target; use a generated one")
		}
		if err := passwd.Check(choice.Password, rules); err != nil {
			return "", false, refuse(syncapi.ReasonPasswordRules, "%v", err)
		}
		return choice.Password, false, nil
	case syncapi.PasswordGenerate:
		pw, err := passwd.Generate(rules)
		return pw, true, err
	}
	return "", false, errors.New("unknown password mode")
}

// takeSlot applies the rate limits.
func (e *Engine) takeSlot(ctx context.Context, actorSID, sourceID, action string) (int64, error) {
	id, err := e.Store.TakeSelfServiceSlot(ctx, e.ConnectorName, actorSID, sourceID, action, e.limits())
	if errors.Is(err, store.ErrRateLimited) {
		e.audit(ctx, action, sourceID, "rate limited", store.ResultBlocked)
		return 0, ErrRateLimited
	}
	return id, err
}

func ssDetail(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

// SetPassword sets a new password on the actor's linked account: generated
// (and returned once) or chosen by the user. The value goes to the target
// once; it is never stored, logged or audited.
func (e *Engine) SetPassword(ctx context.Context, actorSID string, choice syncapi.PasswordChoice) (*syncapi.AccountActionResult, error) {
	conn, err := e.Connect(true)
	if err != nil {
		return nil, err
	}
	v, err := e.inspect(ctx, conn, actorSID)
	if err != nil {
		return nil, err
	}
	if !v.acct.CanSetPassword {
		return nil, refuse(v.acct.PasswordReason, "the password of this account cannot be set here (%s)", v.acct.PasswordReason)
	}
	pw, generated, err := e.newPassword(v, choice)
	if err != nil {
		return nil, err
	}
	target := fmt.Sprintf("%s [%s]", v.acct.Address, v.tu.ID)
	slot, err := e.takeSlot(ctx, actorSID, v.user.ID, "self.set_password")
	if err != nil {
		return nil, err
	}
	detail := map[string]any{"source_id": v.user.ID, "origin": v.acct.Origin, "mode": choice.Mode}
	if err := v.ss.SetPassword(ctx, v.tu.ID, pw); err != nil {
		_ = e.Store.FinishSelfService(context.WithoutCancel(ctx), slot, "failed")
		detail["error"] = err.Error()
		e.audit(ctx, "self.set_password", target, ssDetail(detail), store.ResultFailed)
		if errors.Is(err, connector.ErrInvalid) {
			return nil, refuse(syncapi.ReasonTargetRefused, "%s refused the password (its own password policy may require more)", v.acct.Title)
		}
		return nil, err
	}
	_ = e.Store.FinishSelfService(context.WithoutCancel(ctx), slot, "ok")
	e.audit(ctx, "self.set_password", target, ssDetail(detail), store.ResultOK)
	res := &syncapi.AccountActionResult{}
	if generated {
		res.Password = pw
	}
	if v.acct.ActionsLeft > 0 {
		v.acct.ActionsLeft--
	}
	res.Account = v.acct
	return res, nil
}

// blockingWarnings are the plan warnings that stop an activation of the
// user they are about.
var blockingWarnings = map[string]string{
	plan.WarnDuplicateAddress:  syncapi.ReasonAddressTaken,
	plan.WarnAliasCollision:    syncapi.ReasonAddressTaken,
	plan.WarnOwnedByOther:      syncapi.ReasonAddressTaken,
	plan.WarnUnmanagedExists:   syncapi.ReasonAddressTaken,
	plan.WarnAdoptDisabled:     syncapi.ReasonDisabled,
	plan.WarnDisabledNotCreate: syncapi.ReasonDisabled,
}

// selectActivation picks, from a full plan with the user activated, the
// operations of that user's activation: the create (and a preceding unlink
// of an account removed outside the sync) and the user's memberships in
// groups that exist already. Anything else about the user (an adoption, a
// relink) is left to the sync runs and refuses the activation.
func selectActivation(p *plan.Plan, sourceID, email string) ([]plan.Op, error) {
	for _, w := range p.Errors {
		if w.Key == email {
			return nil, refuse(syncapi.ReasonMappingError, "%s", w.Message)
		}
	}
	for _, w := range p.Warnings {
		if r, ok := blockingWarnings[w.Code]; ok && w.Key == email {
			return nil, refuse(r, "%s", w.Message)
		}
	}
	var out []plan.Op
	created := false
	for _, op := range p.Ops {
		switch {
		case op.SourceID == sourceID && op.Kind == plan.UserCreate:
			out = append(out, op)
			created = true
		case op.SourceID == sourceID && op.Kind == plan.UserUnlink:
			out = append(out, op)
		case op.SourceID == sourceID && (op.Kind == plan.UserAdopt || op.Kind == plan.UserRelink):
			return nil, refuse(syncapi.ReasonExistingAccount, "an account with this address exists; the next sync run links it")
		case op.Kind == plan.MemberAdd && op.Member != nil && op.Member.MemberSourceID == sourceID && op.Member.GroupTargetID != "":
			out = append(out, op)
		}
	}
	if !created {
		return nil, refuse(syncapi.ReasonAlreadyActive, "nothing to create for this user")
	}
	return out, nil
}

// Activate creates the actor's account on the target now (on-demand
// provisioning): the plan of a sync run with this user activated, of which
// only this user's create and its memberships in existing groups are
// applied, journaled as a run of its own ("activate", trigger
// "self-service"). The password is the user's own (shown once when
// generated) and the account is not asked to change it.
func (e *Engine) Activate(ctx context.Context, actorSID string, choice syncapi.PasswordChoice) (*syncapi.AccountActionResult, error) {
	lk, err := e.lock()
	if err != nil {
		return nil, err
	}
	defer lk.Release()
	conn, err := e.Connect(true)
	if err != nil {
		return nil, err
	}
	v, err := e.inspect(ctx, conn, actorSID)
	if err != nil {
		return nil, err
	}
	if !v.acct.CanActivate {
		return nil, refuse(v.acct.ActivateReason, "the account cannot be activated here (%s)", v.acct.ActivateReason)
	}
	pw, generated, err := e.newPassword(v, choice)
	if err != nil {
		return nil, err
	}
	interrupted, err := e.Store.MarkInterrupted(ctx, e.ConnectorName)
	if err != nil {
		return nil, err
	}
	for _, id := range interrupted {
		e.audit(ctx, "run.interrupted", fmt.Sprintf("run %d", id), "the run ended before finishing; the next plan resumes it", store.ResultInfo)
	}
	c, err := e.computeWith(ctx, conn, v.user.ID)
	if err != nil {
		return nil, err
	}
	ops, err := selectActivation(c.Plan, v.user.ID, v.acct.Address)
	if err != nil {
		return nil, err
	}
	slot, err := e.takeSlot(ctx, actorSID, v.user.ID, "self.activate")
	if err != nil {
		return nil, err
	}
	sub := &plan.Plan{Connector: e.ConnectorName, Ops: ops, Digest: plan.ComputeDigest(ops), SourceUsers: c.Plan.SourceUsers,
		SourceGroups: c.Plan.SourceGroups, ManagedUsers: c.Plan.ManagedUsers, ManagedGroups: c.Plan.ManagedGroups}
	runID, err := e.Store.StartRun(ctx, e.ConnectorName, "activate", "self-service", e.Actor)
	if err != nil {
		return nil, err
	}
	e.started(runID)
	finish := func(status string, done, failed int, errText string) {
		rr := store.RunResult{Status: status, PlanDigest: sub.Digest, SourceUsers: sub.SourceUsers, SourceGroups: sub.SourceGroups,
			OpsTotal: len(ops), OpsDone: done, OpsFailed: failed, Error: errText,
			Summary: Summary{Counts: sub.Counts(), Note: "self-service activation of " + v.acct.Address}}
		if err := e.Store.FinishRun(context.WithoutCancel(ctx), runID, rr); err != nil {
			fmt.Fprintf(e.out(), "warning: recording the run failed: %v\n", err)
		}
	}
	if err := e.Store.SavePlan(ctx, runID, sub); err != nil {
		return nil, err
	}
	e.audit(ctx, "activate.start", fmt.Sprintf("run %d", runID), ssDetail(map[string]any{"source_id": v.user.ID, "address": v.acct.Address,
		"digest": sub.Digest, "ops": countsText(sub), "password": choice.Mode}), store.ResultInfo)
	if err := e.Store.JournalOps(ctx, runID, ops); err != nil {
		return nil, err
	}
	x := &executor{e: e, conn: conn, runID: runID, createPassword: pw}
	if err := x.loadLinks(ctx); err != nil {
		return nil, err
	}
	_, runErr := x.run(ctx, ops)
	createdOK := false
	if l, ok := x.links[linkKey(model.KindUser, v.user.ID)]; ok && l.TargetID != "" {
		createdOK = true
	}
	status := store.StatusApplied
	if x.failed > 0 || x.skipped > 0 || runErr != nil {
		status = store.StatusPartial
	}
	if !createdOK {
		status = store.StatusFailed
	}
	errText := strings.Join(firstN(x.failures, 5), "; ")
	finish(status, x.done, x.failed, errText)
	result := store.ResultOK
	if status != store.StatusApplied {
		result = store.ResultFailed
	}
	e.audit(ctx, "activate.end", fmt.Sprintf("run %d", runID), fmt.Sprintf("%s: %d done, %d failed, %d skipped", status, x.done, x.failed, x.skipped), result)
	if !createdOK {
		_ = e.Store.FinishSelfService(context.WithoutCancel(ctx), slot, "failed")
		if len(x.failures) > 0 && strings.Contains(x.failures[0], connector.ErrInvalid.Error()) {
			return nil, refuse(syncapi.ReasonTargetRefused, "%s refused the account or the password (its own password policy may require more)", v.acct.Title)
		}
		if runErr != nil {
			return nil, runErr
		}
		return nil, fmt.Errorf("the account was not created: %s", errText)
	}
	_ = e.Store.FinishSelfService(context.WithoutCancel(ctx), slot, "ok")
	if err := e.Store.Activate(context.WithoutCancel(ctx), e.ConnectorName, v.user.ID, e.Actor); err != nil {
		fmt.Fprintf(e.out(), "warning: recording the activation failed: %v\n", err)
	}
	// The account as it is now.
	after, err := e.inspect(ctx, conn, actorSID)
	if err != nil {
		return nil, err
	}
	acct := after.acct
	if acct.State != syncapi.AccountActive {
		// A target read right after a create may lag behind it (eventual
		// consistency): the create succeeded, so the account is active.
		acct.State, acct.Reason, acct.Origin, acct.Address = syncapi.AccountActive, "", syncapi.OriginCreated, v.acct.Address
	}
	res := &syncapi.AccountActionResult{Account: acct}
	if generated {
		res.Password = pw
	}
	res.Warnings = append(res.Warnings, x.failures...)
	return res, nil
}
