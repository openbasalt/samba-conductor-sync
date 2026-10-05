// Package engine runs conductor-sync: it reads the source and the target,
// computes the plan, records it, checks the safety limits and, when
// allowed, applies it one journaled operation at a time.
//
// Rules enforced here (on top of the plan's own rules):
//   - mode "dry-run" (the default of a new installation) never writes;
//   - a scheduled run never applies before one manual apply succeeded, and
//     never outside the safety limits: it stops, records the plan as
//     blocked and alerts;
//   - a manual apply can be pinned to a reviewed plan (its digest), shows
//     the plan and asks for confirmation; overriding the limits is an
//     explicit flag;
//   - every operation is journaled before it is sent ("started") and after
//     ("done"/"failed"); an interrupted run is detected by the next one and
//     its unknown outcomes are resolved by the next plan (ownership marker,
//     in-flight creates), so re-running is always safe;
//   - a run holds an exclusive lock; every run, operation and deletion is
//     in the hash-chained audit log.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/alert"
	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/metrics"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/source"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
)

// Modes.
const (
	ModeDryRun = "dry-run"
	ModeApply  = "apply"
)

// Meta keys.
const metaFirstApply = "first_manual_apply"

// Errors returned to the CLI (exit codes are chosen from them).
var (
	ErrBlocked       = errors.New("plan exceeds the safety limits; nothing applied")
	ErrDryRun        = errors.New("mode is dry-run; nothing applied")
	ErrNotConfirmed  = errors.New("not confirmed; nothing applied")
	ErrPlanChanged   = errors.New("the plan changed since it was reviewed; review the new plan")
	ErrFirstManual   = errors.New("the first apply must be manual; scheduled runs stay blocked until then")
	ErrPartial       = errors.New("some operations failed")
	ErrDeleteRefused = errors.New("delete refused")
)

// Engine runs plans and applies.
type Engine struct {
	Store  *store.Store
	Source source.Source
	// Connect opens the target connector; write selects the write scopes.
	Connect func(write bool) (connector.Connector, error)
	// ConnectorName is the connector's name in state and audit.
	ConnectorName string
	Policy        plan.Policy
	Limits        plan.Limits
	Mode          string
	// MaxFailures aborts an apply after this many failed operations.
	MaxFailures int
	Alert       alert.Sender
	MetricsPath string
	LockPath    string
	// Actor is recorded in the audit log (the OS user, or "timer").
	Actor string
	Host  string
	Out   io.Writer
	Now   func() time.Time
	// OnRun, when set, is told the ID of the run as soon as it is
	// recorded (the management API tracks background jobs with it).
	OnRun func(runID int64)
	// SelfService is the self-service policy (selfservice.go).
	SelfService SelfServicePolicy
	// Hooks are for tests only.
	Hooks Hooks
}

func (e *Engine) started(id int64) {
	if e.OnRun != nil {
		e.OnRun(id)
	}
}

// Hooks let tests simulate a crash between a target write and its
// confirmation in the journal.
type Hooks struct {
	// AfterTargetWrite runs after operation seq reached the target and
	// before it is confirmed; an error stops the run right there, as a
	// crash would (run left "running", operation left "started").
	AfterTargetWrite func(seq int, op plan.Op) error
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) out() io.Writer {
	if e.Out == nil {
		return io.Discard
	}
	return e.Out
}

func (e *Engine) audit(ctx context.Context, action, target, detail, result string) {
	if _, err := e.Store.AppendAudit(ctx, store.AuditEvent{Actor: e.Actor, Action: action, Target: target, Detail: detail, Result: result}); err != nil {
		fmt.Fprintf(e.out(), "warning: audit write failed: %v\n", err)
	}
}

func (e *Engine) alert(ctx context.Context, kind string, runID int64, subject, text string) {
	if e.Alert == nil {
		return
	}
	a := alert.Alert{Kind: kind, Connector: e.ConnectorName, RunID: runID, Host: e.Host, Subject: subject, Text: text, At: e.now().UTC()}
	if err := e.Alert.Send(ctx, a); err != nil {
		fmt.Fprintf(e.out(), "warning: alert delivery failed: %v\n", err)
	}
}

func (e *Engine) lock() (*store.Lock, error) {
	if e.LockPath == "" {
		return nil, nil
	}
	return store.AcquireLock(e.LockPath)
}

// Computed is a plan with everything needed to judge it.
type Computed struct {
	RunID      int64
	Plan       *plan.Plan
	Violations []plan.Violation
	Skipped    []source.Skipped
	// PreviousSourceUsers is the source size of the last applied run.
	PreviousSourceUsers int
	// sourceDNs maps source IDs to their current DN (kept on the links for
	// display).
	sourceDNs map[string]string
}

func inflightOf(entries []store.JournalEntry) []plan.InFlight {
	var out []plan.InFlight
	for _, j := range entries {
		if j.Kind == plan.UserCreate || j.Kind == plan.GroupCreate {
			out = append(out, plan.InFlight{Kind: j.Kind, SourceID: j.SourceID, Key: j.Key})
		}
	}
	return out
}

// confirmLinked reads directly every linked target object that the list
// did not return and adds the ones that still exist to the snapshot. A
// target's list can lag behind its writes (the Google Directory API is
// eventually consistent: a user created seconds ago may be missing from
// users.list while users.get finds it); without this the plan would call
// the object "removed outside the sync", unlink it and create it again.
// Only a 404 on the direct read confirms that an object is gone.
func confirmLinked(ctx context.Context, c connector.Connector, snap *connector.Snapshot, links []plan.Link, manageGroups bool) error {
	users := make(map[string]bool, len(snap.Users))
	for _, u := range snap.Users {
		users[u.ID] = true
	}
	groups := make(map[string]bool, len(snap.Groups))
	for _, g := range snap.Groups {
		groups[g.ID] = true
	}
	gg, canGetGroups := c.(connector.GroupGetter)
	for _, l := range links {
		switch {
		case l.TargetID == "":
			continue
		case l.Kind == model.KindUser && !users[l.TargetID]:
			u, err := c.GetUser(ctx, l.TargetID)
			if errors.Is(err, connector.ErrNotFound) {
				continue
			}
			if err != nil {
				return fmt.Errorf("confirm linked user %s: %w", l.Key, err)
			}
			if u.ID == l.TargetID {
				users[u.ID] = true
				snap.Users = append(snap.Users, *u)
			}
		case l.Kind == model.KindGroup && manageGroups && canGetGroups && !groups[l.TargetID]:
			g, err := gg.GetGroup(ctx, l.TargetID)
			if errors.Is(err, connector.ErrNotFound) {
				continue
			}
			if err != nil {
				return fmt.Errorf("confirm linked group %s: %w", l.Key, err)
			}
			if g.ID == l.TargetID {
				groups[g.ID] = true
				snap.Groups = append(snap.Groups, *g)
			}
		}
	}
	return nil
}

func (e *Engine) compute(ctx context.Context, c connector.Connector) (*Computed, error) {
	return e.computeWith(ctx, c, "")
}

// computeWith is compute with one more user counted as activated (the plan
// of a self-service activation, which creates that user's account).
func (e *Engine) computeWith(ctx context.Context, c connector.Connector, activate string) (*Computed, error) {
	src, err := e.Source.Read(ctx)
	if err != nil {
		return nil, err
	}
	snap, err := c.Snapshot(ctx, e.Policy.ManageGroups)
	if err != nil {
		return nil, err
	}
	rows, err := e.Store.Links(ctx, e.ConnectorName)
	if err != nil {
		return nil, err
	}
	links := make([]plan.Link, len(rows))
	for i, r := range rows {
		links[i] = r.Link
	}
	if err := confirmLinked(ctx, c, snap, links, e.Policy.ManageGroups); err != nil {
		return nil, err
	}
	inflight, err := e.Store.InFlight(ctx, e.ConnectorName)
	if err != nil {
		return nil, err
	}
	activated, err := e.Store.Activated(ctx, e.ConnectorName)
	if err != nil {
		return nil, err
	}
	if activate != "" {
		activated[activate] = true
	}
	p := plan.Compute(plan.Input{Connector: e.ConnectorName, Users: src.Users, Groups: src.Groups,
		TargetUsers: snap.Users, TargetGroups: snap.Groups, Links: links, InFlight: inflightOf(inflight), Policy: e.Policy,
		Activated: activated})
	// Display fields (not part of the digest).
	p.Scope, p.NotIncluded, p.Excluded = src.Scope, src.NotIncluded, src.Excluded
	for _, s := range src.Skipped {
		p.Skipped = append(p.Skipped, plan.SkippedObject{DN: s.DN, Reason: s.Reason})
	}
	prev := 0
	if last, err := e.Store.LastRunWithStatus(ctx, e.ConnectorName, "apply", store.StatusApplied, store.StatusPartial, store.StatusNothing); err != nil {
		return nil, err
	} else if last != nil {
		prev = last.SourceUsers
	}
	dns := make(map[string]string, len(src.Users)+len(src.Groups))
	for _, u := range src.Users {
		dns[u.ID] = u.DN
	}
	for _, g := range src.Groups {
		dns[g.ID] = g.DN
	}
	return &Computed{Plan: p, Violations: e.Limits.Check(p, prev), Skipped: src.Skipped, PreviousSourceUsers: prev, sourceDNs: dns}, nil
}

// Summary is what a run records about its plan (runs.summary).
type Summary struct {
	Counts     map[plan.OpKind]int `json:"counts"`
	Violations []plan.Violation    `json:"violations,omitempty"`
	Warnings   int                 `json:"warnings"`
	Errors     int                 `json:"errors,omitempty"`
	Skipped    int                 `json:"skipped_source_objects"`
	Note       string              `json:"note,omitempty"`
}

func summarize(c *Computed, note string) Summary {
	return Summary{Counts: c.Plan.Counts(), Violations: c.Violations, Warnings: len(c.Plan.Warnings), Errors: len(c.Plan.Errors),
		Skipped: len(c.Skipped), Note: note}
}

func countsText(p *plan.Plan) string {
	c := p.Counts()
	if len(c) == 0 {
		return "no changes"
	}
	var parts []string
	for _, k := range []plan.OpKind{plan.UserCreate, plan.UserUpdate, plan.UserRename, plan.UserAdopt, plan.UserSuspend, plan.UserUnsuspend,
		plan.UserRelink, plan.UserUnlink, plan.GroupCreate, plan.GroupUpdate, plan.GroupAdopt, plan.GroupRelink, plan.GroupUnlink,
		plan.MemberAdd, plan.MemberRemove} {
		if c[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, c[k]))
		}
	}
	return strings.Join(parts, " ")
}

func (e *Engine) writeMetrics(ctx context.Context, action, status string, started time.Time, c *Computed, done, failed int, conn connector.Connector) {
	if e.MetricsPath == "" {
		return
	}
	r := metrics.Run{Connector: e.ConnectorName, Action: action, Status: status, Started: started, Finished: e.now(), Ops: map[string]int{}}
	if c != nil {
		r.SourceUsers, r.SourceGroups, r.ManagedUsers = c.Plan.SourceUsers, c.Plan.SourceGroups, c.Plan.ManagedUsers
		for k, v := range c.Plan.Counts() {
			r.Ops[string(k)] = v
		}
		r.Violations, r.Warnings = len(c.Violations), len(c.Plan.Warnings)
	}
	r.OpsDone, r.OpsFailed = done, failed
	if s, ok := conn.(interface{ Stats() (int, int) }); ok {
		r.Requests, r.Retries = s.Stats()
	}
	var lastOK time.Time
	if last, err := e.Store.LastRunWithStatus(ctx, e.ConnectorName, "apply", store.StatusApplied, store.StatusNothing); err == nil && last != nil {
		lastOK = last.FinishedAt
	}
	if err := metrics.Write(e.MetricsPath, r, lastOK); err != nil {
		fmt.Fprintf(e.out(), "warning: metrics: %v\n", err)
	}
}

// Plan computes and records a plan without writing anything to the target
// (read-only scopes).
func (e *Engine) Plan(ctx context.Context, trigger string) (*Computed, error) {
	lk, err := e.lock()
	if err != nil {
		return nil, err
	}
	defer lk.Release()
	started := e.now()
	runID, err := e.Store.StartRun(ctx, e.ConnectorName, "plan", trigger, e.Actor)
	if err != nil {
		return nil, err
	}
	e.started(runID)
	conn, err := e.Connect(false)
	if err != nil {
		_ = e.Store.FinishRun(ctx, runID, store.RunResult{Status: store.StatusFailed, Error: err.Error()})
		return nil, err
	}
	c, err := e.compute(ctx, conn)
	if err != nil {
		_ = e.Store.FinishRun(ctx, runID, store.RunResult{Status: store.StatusFailed, Error: err.Error()})
		e.audit(ctx, "plan", e.ConnectorName, err.Error(), store.ResultFailed)
		e.writeMetrics(ctx, "plan", store.StatusFailed, started, nil, 0, 0, conn)
		return nil, err
	}
	c.RunID = runID
	if err := e.Store.SavePlan(ctx, runID, c.Plan); err != nil {
		return nil, err
	}
	if err := e.Store.FinishRun(ctx, runID, store.RunResult{Status: store.StatusPlanned, PlanDigest: c.Plan.Digest,
		SourceUsers: c.Plan.SourceUsers, SourceGroups: c.Plan.SourceGroups, OpsTotal: len(c.Plan.Ops), Summary: summarize(c, "")}); err != nil {
		return nil, err
	}
	e.audit(ctx, "plan", fmt.Sprintf("run %d", runID), fmt.Sprintf("digest %s; %s; %d warnings; %d plan errors; %d limit violations",
		c.Plan.Digest, countsText(c.Plan), len(c.Plan.Warnings), len(c.Plan.Errors), len(c.Violations)), store.ResultInfo)
	e.writeMetrics(ctx, "plan", store.StatusPlanned, started, c, 0, 0, conn)
	return c, nil
}

// ApplyOptions control one apply.
type ApplyOptions struct {
	// Scheduled marks a timer run: no prompt, limits are binding, and the
	// first apply must have been manual.
	Scheduled bool
	// ExpectDigest pins the apply to a reviewed plan.
	ExpectDigest string
	// OverrideLimits applies a manual plan beyond the limits.
	OverrideLimits bool
	// Confirm shows the plan and asks; nil refuses unless Yes.
	Confirm func(c *Computed) bool
	Yes     bool
	// Note is added to the run's audit entries (e.g. "overrides blocked
	// run 12; reviewed plan run 14").
	Note string
}

// ApplyResult reports an apply.
type ApplyResult struct {
	*Computed
	Status      string
	Done        int
	Failed      int
	Skipped     int
	Interrupted []int64
	Failures    []string
}

// Apply computes a fresh plan and applies it when every rule allows.
func (e *Engine) Apply(ctx context.Context, opt ApplyOptions) (*ApplyResult, error) {
	lk, err := e.lock()
	if err != nil {
		return nil, err
	}
	defer lk.Release()
	started := e.now()
	trigger := "manual"
	if opt.Scheduled {
		trigger = "scheduled"
	}
	res := &ApplyResult{}
	interrupted, err := e.Store.MarkInterrupted(ctx, e.ConnectorName)
	if err != nil {
		return nil, err
	}
	res.Interrupted = interrupted
	for _, id := range interrupted {
		e.audit(ctx, "run.interrupted", fmt.Sprintf("run %d", id), "the run ended before finishing; this run resumes it from a fresh plan", store.ResultInfo)
		e.alert(ctx, alert.KindInterrupted, id, fmt.Sprintf("conductor-sync run %d was interrupted", id),
			"The next run re-plans from the current state and completes the remaining changes.")
	}
	runID, err := e.Store.StartRun(ctx, e.ConnectorName, "apply", trigger, e.Actor)
	if err != nil {
		return nil, err
	}
	e.started(runID)
	finish := func(status string, c *Computed, done, failed int, errText string, conn connector.Connector) {
		rr := store.RunResult{Status: status, OpsDone: done, OpsFailed: failed, Error: errText}
		if c != nil {
			rr.PlanDigest, rr.SourceUsers, rr.SourceGroups, rr.OpsTotal = c.Plan.Digest, c.Plan.SourceUsers, c.Plan.SourceGroups, len(c.Plan.Ops)
			rr.Summary = summarize(c, errText)
		}
		if err := e.Store.FinishRun(ctx, runID, rr); err != nil {
			fmt.Fprintf(e.out(), "warning: recording the run failed: %v\n", err)
		}
		e.writeMetrics(ctx, "apply", status, started, c, done, failed, conn)
	}

	// Dry-run mode: plan with the read-only scopes and stop.
	if e.Mode != ModeApply {
		conn, err := e.Connect(false)
		if err != nil {
			finish(store.StatusFailed, nil, 0, 0, err.Error(), nil)
			return nil, err
		}
		c, err := e.compute(ctx, conn)
		if err != nil {
			finish(store.StatusFailed, nil, 0, 0, err.Error(), conn)
			return nil, err
		}
		c.RunID = runID
		_ = e.Store.SavePlan(ctx, runID, c.Plan)
		finish(store.StatusDryRun, c, 0, 0, "mode is dry-run", conn)
		e.audit(ctx, "apply.dry-run", fmt.Sprintf("run %d", runID), fmt.Sprintf("digest %s; %s", c.Plan.Digest, countsText(c.Plan)), store.ResultInfo)
		res.Computed, res.Status = c, store.StatusDryRun
		return res, ErrDryRun
	}
	if opt.Scheduled {
		if v, err := e.Store.Meta(ctx, metaFirstApply); err != nil {
			return nil, err
		} else if v == "" {
			finish(store.StatusBlocked, nil, 0, 0, ErrFirstManual.Error(), nil)
			e.audit(ctx, "apply.blocked", fmt.Sprintf("run %d", runID), ErrFirstManual.Error(), store.ResultBlocked)
			e.alert(ctx, alert.KindBlocked, runID, "conductor-sync scheduled run blocked", ErrFirstManual.Error())
			res.Status = store.StatusBlocked
			return res, ErrFirstManual
		}
	}
	conn, err := e.Connect(true)
	if err != nil {
		finish(store.StatusFailed, nil, 0, 0, err.Error(), nil)
		e.alert(ctx, alert.KindFailed, runID, "conductor-sync apply failed", err.Error())
		return nil, err
	}
	c, err := e.compute(ctx, conn)
	if err != nil {
		finish(store.StatusFailed, nil, 0, 0, err.Error(), conn)
		e.audit(ctx, "apply", fmt.Sprintf("run %d", runID), err.Error(), store.ResultFailed)
		e.alert(ctx, alert.KindFailed, runID, "conductor-sync apply failed", err.Error())
		return nil, err
	}
	c.RunID = runID
	res.Computed = c
	if err := e.Store.SavePlan(ctx, runID, c.Plan); err != nil {
		return nil, err
	}
	if opt.ExpectDigest != "" && opt.ExpectDigest != c.Plan.Digest {
		finish(store.StatusFailed, c, 0, 0, ErrPlanChanged.Error(), conn)
		e.audit(ctx, "apply", fmt.Sprintf("run %d", runID), fmt.Sprintf("reviewed digest %s, current %s", opt.ExpectDigest, c.Plan.Digest), store.ResultFailed)
		res.Status = store.StatusFailed
		return res, ErrPlanChanged
	}
	if len(c.Violations) > 0 && (opt.Scheduled || !opt.OverrideLimits) {
		var vs []string
		for _, v := range c.Violations {
			vs = append(vs, v.String())
		}
		text := strings.Join(vs, "; ")
		finish(store.StatusBlocked, c, 0, 0, text, conn)
		e.audit(ctx, "apply.blocked", fmt.Sprintf("run %d", runID), fmt.Sprintf("digest %s; %s; %s", c.Plan.Digest, countsText(c.Plan), text), store.ResultBlocked)
		e.alert(ctx, alert.KindBlocked, runID, "conductor-sync run stopped at the safety limits",
			fmt.Sprintf("Plan %s (%s) exceeds: %s. Review it with 'conductor-sync plan' and apply by hand if intended.", short(c.Plan.Digest), countsText(c.Plan), text))
		res.Status = store.StatusBlocked
		return res, ErrBlocked
	}
	if c.Plan.Empty() {
		_ = e.Store.Supersede(ctx, e.ConnectorName, runID)
		_ = e.Store.RefreshSourceDNs(ctx, e.ConnectorName, c.sourceDNs)
		finish(store.StatusNothing, c, 0, 0, "", conn)
		e.audit(ctx, "apply", fmt.Sprintf("run %d", runID), "nothing to do", store.ResultOK)
		res.Status = store.StatusNothing
		return res, nil
	}
	if !opt.Scheduled && !opt.Yes {
		if opt.Confirm == nil || !opt.Confirm(c) {
			finish(store.StatusPlanned, c, 0, 0, ErrNotConfirmed.Error(), conn)
			e.audit(ctx, "apply", fmt.Sprintf("run %d", runID), "declined at confirmation; digest "+c.Plan.Digest, store.ResultInfo)
			res.Status = store.StatusPlanned
			return res, ErrNotConfirmed
		}
	}
	note := ""
	if len(c.Violations) > 0 {
		note = "safety limits overridden by the operator"
		detail := fmt.Sprintf("digest %s; %v", c.Plan.Digest, c.Violations)
		if opt.Note != "" {
			detail += "; " + opt.Note
		}
		e.audit(ctx, "apply.override-limits", fmt.Sprintf("run %d", runID), detail, store.ResultInfo)
	}
	startDetail := fmt.Sprintf("%s run; digest %s; %s", trigger, c.Plan.Digest, countsText(c.Plan))
	if opt.Note != "" {
		startDetail += "; " + opt.Note
	}
	e.audit(ctx, "apply.start", fmt.Sprintf("run %d", runID), startDetail, store.ResultInfo)
	if err := e.Store.JournalOps(ctx, runID, c.Plan.Ops); err != nil {
		return nil, err
	}
	x := &executor{e: e, conn: conn, runID: runID}
	if err := x.loadLinks(ctx); err != nil {
		return nil, err
	}
	crashed, runErr := x.run(ctx, c.Plan.Ops)
	res.Done, res.Failed, res.Skipped, res.Failures = x.done, x.failed, x.skipped, x.failures
	if crashed {
		// Simulated crash (tests): leave the run and the journal as a real
		// crash would.
		return res, runErr
	}
	_ = e.Store.Supersede(ctx, e.ConnectorName, runID)
	_ = e.Store.RefreshSourceDNs(context.WithoutCancel(ctx), e.ConnectorName, c.sourceDNs)
	status := store.StatusApplied
	switch {
	case runErr != nil && ctx.Err() != nil:
		status = store.StatusInterrupted
	case x.failed > 0 || x.skipped > 0 || runErr != nil:
		status = store.StatusPartial
	}
	errText := note
	if runErr != nil {
		errText = strings.TrimSpace(note + " " + runErr.Error())
	}
	finish(status, c, x.done, x.failed, errText, conn)
	if !opt.Scheduled && x.done > 0 {
		_ = e.Store.SetMeta(ctx, metaFirstApply, fmt.Sprintf("run %d at %s", runID, e.now().UTC().Format(time.RFC3339)))
	}
	result := store.ResultOK
	if status != store.StatusApplied {
		result = store.ResultFailed
	}
	e.audit(ctx, "apply.end", fmt.Sprintf("run %d", runID), fmt.Sprintf("%s: %d done, %d failed, %d skipped", status, x.done, x.failed, x.skipped), result)
	res.Status = status
	if status != store.StatusApplied {
		text := fmt.Sprintf("%d done, %d failed, %d skipped.", x.done, x.failed, x.skipped)
		if len(x.failures) > 0 {
			text += " First failures: " + strings.Join(firstN(x.failures, 5), "; ")
		}
		e.alert(ctx, alert.KindPartial, runID, fmt.Sprintf("conductor-sync run %d %s", runID, status), text)
		if runErr != nil {
			return res, runErr
		}
		return res, ErrPartial
	}
	return res, nil
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// executor applies the operations of one run.
type executor struct {
	e     *Engine
	conn  connector.Connector
	runID int64
	links map[string]plan.Link // kind|sourceID
	// failedSources marks objects whose create failed, so dependent
	// memberships are skipped instead of failing.
	failedSources map[string]bool
	// createPassword is the user's own password of a self-service
	// activation (the only create of that run); empty: CreateUser with a
	// random password.
	createPassword string

	done, failed, skipped int
	failures              []string
}

func linkKey(kind model.Kind, src string) string { return string(kind) + "|" + src }

func (x *executor) loadLinks(ctx context.Context) error {
	rows, err := x.e.Store.Links(ctx, x.e.ConnectorName)
	if err != nil {
		return err
	}
	x.links = map[string]plan.Link{}
	x.failedSources = map[string]bool{}
	for _, r := range rows {
		x.links[linkKey(r.Kind, r.SourceID)] = r.Link
	}
	return nil
}

func (x *executor) putLink(ctx context.Context, l plan.Link) error {
	if err := x.e.Store.PutLink(ctx, x.e.ConnectorName, l, ""); err != nil {
		return err
	}
	x.links[linkKey(l.Kind, l.SourceID)] = l
	return nil
}

func (x *executor) dropLink(ctx context.Context, kind model.Kind, src string) error {
	if err := x.e.Store.DeleteLink(ctx, x.e.ConnectorName, kind, src); err != nil {
		return err
	}
	delete(x.links, linkKey(kind, src))
	return nil
}

// errSystemic stops the run: every following operation would fail too.
func systemic(err error) bool {
	return errors.Is(err, connector.ErrAuth) || errors.Is(err, connector.ErrRateLimited) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

type errDependency struct{ msg string }

func (e errDependency) Error() string { return e.msg }

func (x *executor) run(ctx context.Context, ops []plan.Op) (crashed bool, err error) {
	maxFail := x.e.MaxFailures
	if maxFail <= 0 {
		maxFail = 25
	}
	for i, op := range ops {
		if err := ctx.Err(); err != nil {
			x.skipRest(ctx, ops, i, "run cancelled")
			return false, err
		}
		if err := x.e.Store.MarkOp(ctx, x.runID, i, store.OpStarted, "", ""); err != nil {
			return false, err
		}
		targetID, opErr := x.exec(ctx, i, op)
		if c, ok := opErr.(crash); ok {
			return true, c.err
		}
		var dep errDependency
		switch {
		case opErr == nil:
			x.done++
			_ = x.e.Store.MarkOp(ctx, x.runID, i, store.OpDone, targetID, "")
			if op.Kind.WritesTarget() || op.Kind == plan.UserRelink || op.Kind == plan.GroupRelink {
				x.e.audit(ctx, string(op.Kind), auditTarget(op, targetID), opDetail(op), store.ResultOK)
			}
		case errors.As(opErr, &dep):
			x.skipped++
			_ = x.e.Store.MarkOp(ctx, x.runID, i, store.OpSkipped, "", dep.msg)
			x.e.audit(ctx, string(op.Kind), auditTarget(op, ""), "skipped: "+dep.msg, store.ResultFailed)
		default:
			x.failed++
			x.failures = append(x.failures, fmt.Sprintf("%s %s: %v", op.Kind, op.Key, opErr))
			_ = x.e.Store.MarkOp(ctx, x.runID, i, store.OpFailed, "", opErr.Error())
			x.e.audit(ctx, string(op.Kind), auditTarget(op, ""), opDetail(op)+"; error: "+opErr.Error(), store.ResultFailed)
			fmt.Fprintf(x.e.out(), "FAILED %s %s: %v\n", op.Kind, op.Key, opErr)
			if op.Kind == plan.UserCreate || op.Kind == plan.GroupCreate {
				x.failedSources[op.SourceID] = true
			}
			if systemic(opErr) {
				x.skipRest(ctx, ops, i+1, "stopped after a systemic error")
				return false, fmt.Errorf("stopped: %w", opErr)
			}
			if x.failed >= maxFail {
				x.skipRest(ctx, ops, i+1, "stopped after too many failures")
				return false, fmt.Errorf("stopped after %d failures", x.failed)
			}
		}
	}
	return false, nil
}

func (x *executor) skipRest(ctx context.Context, ops []plan.Op, from int, why string) {
	for j := from; j < len(ops); j++ {
		x.skipped++
		_ = x.e.Store.MarkOp(context.WithoutCancel(ctx), x.runID, j, store.OpSkipped, "", why)
	}
}

type crash struct{ err error }

func (c crash) Error() string { return c.err.Error() }

func (x *executor) hook(seq int, op plan.Op) error {
	if x.e.Hooks.AfterTargetWrite != nil {
		if err := x.e.Hooks.AfterTargetWrite(seq, op); err != nil {
			return crash{err}
		}
	}
	return nil
}

func (x *executor) exec(ctx context.Context, seq int, op plan.Op) (string, error) {
	switch op.Kind {
	case plan.UserRelink:
		return op.TargetID, x.putLink(ctx, plan.Link{Kind: model.KindUser, SourceID: op.SourceID, TargetID: op.TargetID, Key: op.Key, Adopted: op.Adopted})
	case plan.GroupRelink:
		return op.TargetID, x.putLink(ctx, plan.Link{Kind: model.KindGroup, SourceID: op.SourceID, TargetID: op.TargetID, Key: op.Key})
	case plan.UserUnlink:
		return "", x.dropLink(ctx, model.KindUser, op.SourceID)
	case plan.GroupUnlink:
		return "", x.dropLink(ctx, model.KindGroup, op.SourceID)
	case plan.UserCreate:
		var id string
		var err error
		if x.createPassword != "" {
			ss, ok := x.conn.(connector.SelfService)
			if !ok || op.Suspend {
				return "", errors.New("this create cannot carry the user's password")
			}
			id, err = ss.CreateUserWithPassword(ctx, op.SourceID, op.Attrs, x.createPassword)
		} else {
			id, err = x.conn.CreateUser(ctx, op.SourceID, op.Attrs, op.Suspend)
		}
		if err != nil {
			return "", err
		}
		if err := x.hook(seq, op); err != nil {
			return "", err
		}
		return id, x.putLink(ctx, plan.Link{Kind: model.KindUser, SourceID: op.SourceID, TargetID: id, Key: op.Key, SuspendedBySync: op.Suspend})
	case plan.UserAdopt, plan.UserUpdate, plan.UserRename:
		if err := x.conn.UpdateUser(ctx, op.TargetID, op.SourceID, op.Attrs, op.Changes, op.Kind == plan.UserAdopt); err != nil {
			return "", err
		}
		if err := x.hook(seq, op); err != nil {
			return "", err
		}
		l := x.links[linkKey(model.KindUser, op.SourceID)]
		same := l.TargetID == op.TargetID
		// An adoption records that the account was not created by the sync:
		// the adopted rules of the policy apply to it from now on.
		return op.TargetID, x.putLink(ctx, plan.Link{Kind: model.KindUser, SourceID: op.SourceID, TargetID: op.TargetID, Key: op.Key,
			SuspendedBySync: l.SuspendedBySync && same, Adopted: op.Kind == plan.UserAdopt || (l.Adopted && same)})
	case plan.UserSuspend, plan.UserUnsuspend:
		suspend := op.Kind == plan.UserSuspend
		if err := x.conn.SetSuspended(ctx, op.TargetID, suspend); err != nil {
			return "", err
		}
		if err := x.hook(seq, op); err != nil {
			return "", err
		}
		l, ok := x.links[linkKey(model.KindUser, op.SourceID)]
		if !ok || l.TargetID != op.TargetID {
			l = plan.Link{Kind: model.KindUser, SourceID: op.SourceID, TargetID: op.TargetID, Key: op.Key}
		}
		l.SuspendedBySync = suspend
		return op.TargetID, x.putLink(ctx, l)
	case plan.GroupCreate:
		id, err := x.conn.CreateGroup(ctx, *op.Group)
		if err != nil {
			return "", err
		}
		if err := x.hook(seq, op); err != nil {
			return "", err
		}
		return id, x.putLink(ctx, plan.Link{Kind: model.KindGroup, SourceID: op.SourceID, TargetID: id, Key: op.Key})
	case plan.GroupAdopt, plan.GroupUpdate:
		// An adoption with nothing to change only records the link: the
		// group is not written at all.
		if op.Kind == plan.GroupUpdate || len(op.Changes) > 0 {
			if err := x.conn.UpdateGroup(ctx, op.TargetID, *op.Group); err != nil {
				return "", err
			}
			if err := x.hook(seq, op); err != nil {
				return "", err
			}
		}
		l := x.links[linkKey(model.KindGroup, op.SourceID)]
		return op.TargetID, x.putLink(ctx, plan.Link{Kind: model.KindGroup, SourceID: op.SourceID, TargetID: op.TargetID, Key: op.Key,
			Adopted: op.Kind == plan.GroupAdopt || (l.Adopted && l.TargetID == op.TargetID)})
	case plan.MemberAdd, plan.MemberRemove:
		m := op.Member
		gid := m.GroupTargetID
		if gid == "" {
			gid = x.links[linkKey(model.KindGroup, m.GroupSourceID)].TargetID
		}
		mid := m.MemberTargetID
		if mid == "" && m.MemberSourceID != "" {
			mid = x.links[linkKey(m.Kind, m.MemberSourceID)].TargetID
		}
		if gid == "" {
			if x.failedSources[m.GroupSourceID] {
				return "", errDependency{"the group was not created"}
			}
			return "", errDependency{"the group has no target ID"}
		}
		if op.Kind == plan.MemberAdd && mid == "" {
			if x.failedSources[m.MemberSourceID] {
				return "", errDependency{"the member was not created"}
			}
			return "", errDependency{"the member has no target ID"}
		}
		var err error
		if op.Kind == plan.MemberAdd {
			err = x.conn.AddMember(ctx, gid, m.Kind, mid, m.MemberEmail)
		} else {
			err = x.conn.RemoveMember(ctx, gid, mid, m.MemberEmail)
		}
		if err != nil {
			return "", err
		}
		return "", x.hook(seq, op)
	}
	return "", fmt.Errorf("unknown operation %q", op.Kind)
}

func auditTarget(op plan.Op, targetID string) string {
	id := op.TargetID
	if id == "" {
		id = targetID
	}
	t := op.Key
	if op.Member != nil {
		t = fmt.Sprintf("%s <- %s", op.Member.GroupEmail, op.Member.MemberEmail)
	}
	if id != "" {
		t += " [" + id + "]"
	}
	return t
}

// opDetail is the before/after of an operation (no secrets: passwords are
// generated inside the connector and never reach the plan).
func opDetail(op plan.Op) string {
	d := map[string]any{"source_id": op.SourceID}
	if op.Reason != "" {
		d["reason"] = op.Reason
	}
	if len(op.Changes) > 0 {
		d["changes"] = op.Changes
	}
	if op.Kind == plan.UserCreate {
		d["attrs"] = op.Attrs
		d["suspended"] = op.Suspend
	}
	if op.Group != nil {
		d["group"] = op.Group
	}
	b, _ := json.Marshal(d)
	return string(b)
}

// DeleteRequest is a manual deletion.
type DeleteRequest struct {
	// Key is the account's address, target ID or AD objectGUID.
	Key string
	// Confirm must equal the account's current primary address.
	Confirm string
	// MinSuspended is how long the account must have been suspended by
	// the sync (from the link's last update).
	MinSuspended time.Duration
}

// DeletePreview describes what a deletion would do.
type DeletePreview struct {
	TargetID      string
	Email         string
	SourceID      string
	SourceDN      string
	SuspendedFor  time.Duration
	InSourceScope bool
}

// PreviewDelete checks a deletion without doing it.
func (e *Engine) PreviewDelete(ctx context.Context, key string, minSuspended time.Duration) (*DeletePreview, error) {
	link, err := e.Store.FindLink(ctx, e.ConnectorName, key)
	if err != nil {
		return nil, err
	}
	if link == nil || link.Kind != model.KindUser {
		return nil, fmt.Errorf("%w: %q is not an account managed by conductor-sync", ErrDeleteRefused, key)
	}
	conn, err := e.Connect(false)
	if err != nil {
		return nil, err
	}
	u, err := conn.GetUser(ctx, link.TargetID)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read the account: %v", ErrDeleteRefused, err)
	}
	p := &DeletePreview{TargetID: u.ID, Email: u.Attrs[model.FieldPrimaryEmail], SourceID: link.SourceID, SourceDN: link.SourceDN}
	if link.SuspendedBySync && !link.SuspendedAt.IsZero() {
		p.SuspendedFor = e.now().Sub(link.SuspendedAt)
	}
	switch {
	case u.Owner != link.SourceID:
		return p, fmt.Errorf("%w: the account does not carry the sync's ownership marker for this source", ErrDeleteRefused)
	case u.Protected:
		return p, fmt.Errorf("%w: administrator accounts are never deleted by conductor-sync", ErrDeleteRefused)
	case link.Adopted || u.Adopted:
		return p, fmt.Errorf("%w: the account existed before the sync and was adopted; conductor-sync never deletes it (delete it in the Google Admin console if intended)", ErrDeleteRefused)
	case !u.Suspended || !link.SuspendedBySync:
		return p, fmt.Errorf("%w: only accounts the sync has suspended can be deleted (suspend first)", ErrDeleteRefused)
	case p.SuspendedFor < minSuspended:
		return p, fmt.Errorf("%w: suspended for %s, less than the required %s", ErrDeleteRefused, p.SuspendedFor.Round(time.Minute), minSuspended)
	}
	src, err := e.Source.Read(ctx)
	if err != nil {
		return p, err
	}
	for _, su := range src.Users {
		if su.ID == link.SourceID {
			p.InSourceScope = true
			return p, fmt.Errorf("%w: the AD account is still in the sync scope", ErrDeleteRefused)
		}
	}
	return p, nil
}

// DeleteUser permanently deletes one suspended, sync-owned account after
// PreviewDelete's checks and an exact confirmation of its address.
func (e *Engine) DeleteUser(ctx context.Context, req DeleteRequest) (*DeletePreview, error) {
	lk, err := e.lock()
	if err != nil {
		return nil, err
	}
	defer lk.Release()
	p, err := e.PreviewDelete(ctx, req.Key, req.MinSuspended)
	if err != nil {
		e.audit(ctx, "user.delete", req.Key, err.Error(), store.ResultBlocked)
		return p, err
	}
	if req.Confirm != p.Email {
		e.audit(ctx, "user.delete", p.Email, "confirmation did not match the address", store.ResultBlocked)
		return p, fmt.Errorf("%w: confirmation must be exactly %q", ErrDeleteRefused, p.Email)
	}
	conn, err := e.Connect(true)
	if err != nil {
		return p, err
	}
	if err := conn.DeleteUser(ctx, p.TargetID); err != nil {
		e.audit(ctx, "user.delete", p.Email+" ["+p.TargetID+"]", err.Error(), store.ResultFailed)
		return p, err
	}
	if err := e.Store.DeleteLink(ctx, e.ConnectorName, model.KindUser, p.SourceID); err != nil {
		return p, err
	}
	e.audit(ctx, "user.delete", p.Email+" ["+p.TargetID+"]", fmt.Sprintf(`{"source_id":%q,"source_dn":%q}`, p.SourceID, p.SourceDN), store.ResultOK)
	e.alert(ctx, alert.KindDeleted, 0, "conductor-sync deleted an account", fmt.Sprintf("%s (%s) was deleted by %s", p.Email, p.TargetID, e.Actor))
	return p, nil
}

// Hostname is the host name for alerts ("" when unknown).
func Hostname() string {
	h, _ := os.Hostname()
	return h
}
