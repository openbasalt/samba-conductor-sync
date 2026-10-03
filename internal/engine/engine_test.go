package engine_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/alert"
	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/connector/google"
	"github.com/openbasalt/samba-conductor-sync/internal/engine"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/source"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
)

// env is one engine wired to a fake Directory API over TLS.
type env struct {
	t      *testing.T
	fake   *fakegoogle.Server
	srv    *httptest.Server
	src    *source.Result
	eng    *engine.Engine
	alerts *alert.Recorder
	out    *bytes.Buffer
	st     *store.Store
	dir    string
}

type mutableSource struct{ e *env }

func (m mutableSource) Read(context.Context) (*source.Result, error) {
	// A copy, so the engine never sees later test edits mid-run.
	r := &source.Result{}
	for _, u := range m.e.src.Users {
		u.Attrs = u.Attrs.Clone()
		r.Users = append(r.Users, u)
	}
	for _, g := range m.e.src.Groups {
		g.Members = append([]model.MemberRef(nil), g.Members...)
		r.Groups = append(r.Groups, g)
	}
	return r, nil
}

func newEnv(t *testing.T) *env {
	t.Helper()
	fake := fakegoogle.New("example.com", "groups.example.com")
	fake.PageSize = 7
	for _, ou := range []string{"/Staff", "/Staff/Engineering", "/Staff/Sales", "/Contractors"} {
		fake.AddOrgUnit(ou)
	}
	srv := httptest.NewTLSServer(fake)
	t.Cleanup(srv.Close)
	fake.SetTokenURL(srv.URL + "/token")
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &env{t: t, fake: fake, srv: srv, src: &source.Result{}, alerts: &alert.Recorder{}, out: &bytes.Buffer{}, st: st, dir: dir}
	key := google.NewTestKey(fake.ClientEmail, fake.PrivateKey(), srv.URL+"/token")
	gcfg := google.Config{AdminSubject: fake.AdminSubject, KeyCredential: "test", APIBaseURL: srv.URL, RequestsPerSecond: 100000, MaxRetries: 6}
	e.eng = &engine.Engine{
		Store:  st,
		Source: mutableSource{e},
		Connect: func(write bool) (connector.Connector, error) {
			return google.New(gcfg, key, write, google.Options{HTTPClient: srv.Client(), Backoff: time.Millisecond, MaxBackoff: 4 * time.Millisecond})
		},
		ConnectorName: "google",
		Policy:        plan.Policy{SuspendDisabled: true, ManageGroups: true, Adopt: plan.AdoptNever, Optional: map[model.UserField]bool{model.FieldTitle: true, model.FieldDepartment: true}},
		Limits:        plan.DefaultLimits(),
		Mode:          engine.ModeApply,
		MaxFailures:   10,
		Alert:         e.alerts,
		LockPath:      filepath.Join(dir, "lock"),
		Actor:         "tester",
		Out:           e.out,
	}
	return e
}

func guid(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func user(n int, ou string, enabled bool) model.SourceUser {
	acct := fmt.Sprintf("user%04d", n)
	return model.SourceUser{ID: guid(n), DN: "CN=" + acct + ",OU=People,DC=lab", Account: acct, Enabled: enabled,
		Attrs: model.UserAttrs{
			model.FieldPrimaryEmail: acct + "@example.com", model.FieldGivenName: "User", model.FieldFamilyName: fmt.Sprintf("%04d", n),
			model.FieldOrgUnit: ou, model.FieldTitle: "Engineer", model.FieldDepartment: "R&D",
		}}
}

func group(n int, name string, members ...model.MemberRef) model.SourceGroup {
	return model.SourceGroup{ID: guid(900000 + n), DN: "CN=" + name + ",OU=Groups,DC=lab", Account: name,
		Email: strings.ToLower(name) + "@groups.example.com", Name: name, Members: members}
}

func uref(n int) model.MemberRef { return model.MemberRef{Kind: model.KindUser, ID: guid(n)} }
func gref(n int) model.MemberRef { return model.MemberRef{Kind: model.KindGroup, ID: guid(900000 + n)} }

// seed builds 30 users and three groups (Staff contains the nested Eng).
func (e *env) seed() {
	e.src.Users = nil
	for i := 1; i <= 30; i++ {
		ou := "/Staff/Engineering"
		if i > 20 {
			ou = "/Staff/Sales"
		}
		e.src.Users = append(e.src.Users, user(i, ou, true))
	}
	var eng, sales []model.MemberRef
	for i := 1; i <= 20; i++ {
		eng = append(eng, uref(i))
	}
	for i := 21; i <= 30; i++ {
		sales = append(sales, uref(i))
	}
	e.src.Groups = []model.SourceGroup{group(1, "Eng", eng...), group(2, "Sales", sales...), group(3, "Staff", gref(1), gref(2), uref(1))}
}

func (e *env) apply(opt engine.ApplyOptions) (*engine.ApplyResult, error) {
	e.t.Helper()
	if !opt.Scheduled && opt.Confirm == nil {
		opt.Yes = true
	}
	return e.eng.Apply(context.Background(), opt)
}

func (e *env) mustApply(opt engine.ApplyOptions) *engine.ApplyResult {
	e.t.Helper()
	r, err := e.apply(opt)
	if err != nil {
		e.t.Fatalf("apply: %v\n%s", err, e.out.String())
	}
	return r
}

func (e *env) plan() *engine.Computed {
	e.t.Helper()
	c, err := e.eng.Plan(context.Background(), "manual")
	if err != nil {
		e.t.Fatalf("plan: %v", err)
	}
	return c
}

func (e *env) noDeletes() {
	e.t.Helper()
	for _, w := range e.fake.Writes() {
		if w.Method == http.MethodDelete && strings.HasPrefix(w.Path, "/users") {
			e.t.Fatalf("the sync deleted an account: %+v", w)
		}
		if w.Method == http.MethodDelete && !strings.Contains(w.Path, "/members/") {
			e.t.Fatalf("the sync deleted a group: %+v", w)
		}
	}
}

func (e *env) userByEmail(email string) fakegoogle.User {
	e.t.Helper()
	u, ok := e.fake.User(email)
	if !ok {
		e.t.Fatalf("no account %s", email)
	}
	return u
}

func ownerOf(u fakegoogle.User) string {
	for _, x := range u.ExternalIDs {
		if x["type"] == "custom" && x["customType"] == "conductor-sync" {
			v, _ := x["value"].(string)
			return v
		}
	}
	return ""
}

func TestDryRunAndFirstManualApply(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.eng.Mode = engine.ModeDryRun
	if _, err := e.apply(engine.ApplyOptions{}); !errors.Is(err, engine.ErrDryRun) {
		t.Fatalf("dry-run apply: %v", err)
	}
	if n := len(e.fake.Writes()); n != 0 {
		t.Fatalf("dry-run wrote %d times", n)
	}
	e.eng.Mode = engine.ModeApply
	if _, err := e.apply(engine.ApplyOptions{Scheduled: true}); !errors.Is(err, engine.ErrFirstManual) {
		t.Fatalf("scheduled before first manual apply: %v", err)
	}
	if n := len(e.fake.Writes()); n != 0 {
		t.Fatalf("blocked scheduled run wrote %d times", n)
	}
	if len(e.alerts.Alerts) != 1 || e.alerts.Alerts[0].Kind != alert.KindBlocked {
		t.Fatalf("alerts: %+v", e.alerts.Alerts)
	}
	// Declining the confirmation applies nothing.
	if _, err := e.apply(engine.ApplyOptions{Confirm: func(*engine.Computed) bool { return false }}); !errors.Is(err, engine.ErrNotConfirmed) {
		t.Fatalf("declined apply: %v", err)
	}
	if n := len(e.fake.Writes()); n != 0 {
		t.Fatalf("declined apply wrote %d times", n)
	}
}

func TestInitialSyncThenIdempotent(t *testing.T) {
	e := newEnv(t)
	e.seed()
	r := e.mustApply(engine.ApplyOptions{})
	if r.Status != store.StatusApplied || r.Failed != 0 {
		t.Fatalf("status %s failed %d: %v", r.Status, r.Failed, r.Failures)
	}
	c := r.Plan.Counts()
	if c[plan.UserCreate] != 30 || c[plan.GroupCreate] != 3 || c[plan.MemberAdd] != 20+10+3 {
		t.Fatalf("counts %v", c)
	}
	users := e.fake.Users()
	if len(users) != 30 {
		t.Fatalf("users %d", len(users))
	}
	u := e.userByEmail("user0001@example.com")
	if ownerOf(u) != guid(1) || !u.ChangePasswordNext || !u.PasswordSet || u.OrgUnitPath != "/Staff/Engineering" {
		t.Fatalf("account: %+v", u)
	}
	if u.Organizations[0]["title"] != "Engineer" {
		t.Fatalf("organizations: %+v", u.Organizations)
	}
	_, members, _ := e.fake.GroupByEmail("staff@groups.example.com")
	want := []string{"eng@groups.example.com", "sales@groups.example.com", "user0001@example.com"}
	if strings.Join(members, ",") != strings.Join(want, ",") {
		t.Fatalf("staff members %v", members)
	}
	// A second run has nothing to do; the plan digest is stable.
	p1 := e.plan()
	p2 := e.plan()
	if !p1.Plan.Empty() || p1.Plan.Digest != p2.Plan.Digest {
		t.Fatalf("second plan not empty: %v", p1.Plan.Ops)
	}
	writes := len(e.fake.Writes())
	r = e.mustApply(engine.ApplyOptions{Scheduled: true})
	if r.Status != store.StatusNothing || len(e.fake.Writes()) != writes {
		t.Fatalf("idempotent run: %s, writes %d -> %d", r.Status, writes, len(e.fake.Writes()))
	}
	e.noDeletes()
	if v, err := e.st.VerifyAudit(context.Background()); err != nil || v.BrokenAt != 0 || v.Rows == 0 {
		t.Fatalf("audit: %+v %v", v, err)
	}
}

func TestADChangesIncremental(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.mustApply(engine.ApplyOptions{})
	// Six of 30 accounts change below: allow it (the default 10% is for
	// real-sized directories).
	e.eng.Limits.MaxTouchedPercent = 25

	// Rename (logon name -> new address), move to another OU, disable,
	// group membership change, display-name change, user left the scope.
	e.src.Users[1].Attrs[model.FieldPrimaryEmail] = "renamed0002@example.com"
	e.src.Users[1].Account = "renamed0002"
	e.src.Users[2].Attrs[model.FieldOrgUnit] = "/Contractors"
	e.src.Users[3].Enabled = false
	e.src.Users[4].Attrs[model.FieldGivenName] = "Changed"
	e.src.Users = append(e.src.Users[:29], e.src.Users[30:]...) // user0030 leaves the scope
	e.src.Groups[1].Members = append(e.src.Groups[1].Members[:0:0], e.src.Groups[1].Members[1:]...)
	e.src.Groups[1].Members = append(e.src.Groups[1].Members, uref(5))

	c := e.plan()
	got := c.Plan.Counts()
	if got[plan.UserRename] != 1 || got[plan.UserUpdate] != 2 || got[plan.UserSuspend] != 2 || got[plan.MemberAdd] != 1 || got[plan.MemberRemove] != 2 {
		t.Fatalf("incremental plan counts %v\n%v", got, c.Plan.Ops)
	}
	if len(c.Violations) != 0 {
		t.Fatalf("violations %v", c.Violations)
	}
	r := e.mustApply(engine.ApplyOptions{Scheduled: true, ExpectDigest: c.Plan.Digest})
	if r.Status != store.StatusApplied {
		t.Fatalf("status %s %v", r.Status, r.Failures)
	}
	renamed := e.userByEmail("renamed0002@example.com")
	if ownerOf(renamed) != guid(2) || len(renamed.Aliases) != 1 || renamed.Aliases[0] != "user0002@example.com" {
		t.Fatalf("renamed account %+v", renamed)
	}
	if u := e.userByEmail("user0003@example.com"); u.OrgUnitPath != "/Contractors" {
		t.Fatalf("moved account %+v", u)
	}
	if u := e.userByEmail("user0004@example.com"); !u.Suspended {
		t.Fatal("disabled user not suspended")
	}
	if u := e.userByEmail("user0030@example.com"); !u.Suspended {
		t.Fatal("out-of-scope user not suspended")
	}
	if u := e.userByEmail("user0005@example.com"); u.Name["givenName"] != "Changed" {
		t.Fatalf("name not updated: %+v", u.Name)
	}
	_, sales, _ := e.fake.GroupByEmail("sales@groups.example.com")
	if strings.Contains(strings.Join(sales, ","), "user0021@") || !strings.Contains(strings.Join(sales, ","), "user0005@") || strings.Contains(strings.Join(sales, ","), "user0030@") {
		t.Fatalf("sales members %v", sales)
	}
	if p := e.plan(); !p.Plan.Empty() {
		t.Fatalf("not converged: %v", p.Plan.Ops)
	}

	// Re-enabled in AD: unsuspended (the sync suspended it).
	e.src.Users[3].Enabled = true
	// Suspended by another admin: the sync leaves it suspended.
	other := e.userByEmail("user0006@example.com")
	e.fake.SuspendDirect(other.ID, true)
	c = e.plan()
	if c.Plan.Counts()[plan.UserUnsuspend] != 1 || !hasWarning(c.Plan, plan.WarnSuspendedOutside, "user0006@example.com") {
		t.Fatalf("unsuspend plan %v %v", c.Plan.Ops, c.Plan.Warnings)
	}
	e.mustApply(engine.ApplyOptions{Scheduled: true})
	if u := e.userByEmail("user0004@example.com"); u.Suspended {
		t.Fatal("re-enabled user still suspended")
	}
	if u := e.userByEmail("user0006@example.com"); !u.Suspended {
		t.Fatal("the sync unsuspended an account suspended by someone else")
	}
	e.noDeletes()
}

func hasWarning(p *plan.Plan, code, key string) bool {
	for _, w := range p.Warnings {
		if w.Code == code && w.Key == key {
			return true
		}
	}
	return false
}

func TestSafetyLimits(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.mustApply(engine.ApplyOptions{})
	writes := len(e.fake.Writes())

	// 15 users leave the scope (an OU filter mistake): more than
	// max_suspends (10) and the 10% touched limit.
	e.src.Users = e.src.Users[:15]
	r, err := e.apply(engine.ApplyOptions{Scheduled: true})
	if !errors.Is(err, engine.ErrBlocked) || r.Status != store.StatusBlocked {
		t.Fatalf("scheduled over limits: %v %+v", err, r)
	}
	if len(e.fake.Writes()) != writes {
		t.Fatal("a blocked run wrote to the target")
	}
	var names []string
	for _, v := range r.Violations {
		names = append(names, v.Limit)
	}
	if strings.Join(names, ",") != "max_source_drop_percent,max_suspends,max_touched_percent" {
		t.Fatalf("violations %v", r.Violations)
	}
	last := e.alerts.Alerts[len(e.alerts.Alerts)-1]
	if last.Kind != alert.KindBlocked || !strings.Contains(last.Text, "max_suspends") {
		t.Fatalf("alert %+v", last)
	}
	// Manual apply without the override is blocked too.
	if _, err := e.apply(engine.ApplyOptions{}); !errors.Is(err, engine.ErrBlocked) {
		t.Fatalf("manual over limits: %v", err)
	}
	// An empty source is refused even with generous limits.
	saved := e.src.Users
	e.src.Users = nil
	e.eng.Limits.MaxSuspends, e.eng.Limits.MaxTouchedPercent, e.eng.Limits.MaxSourceDropPercent = plan.Unlimited, plan.Unlimited, plan.Unlimited
	if r, err := e.apply(engine.ApplyOptions{Scheduled: true}); !errors.Is(err, engine.ErrBlocked) || r.Violations[0].Limit != "min_source_users" {
		t.Fatalf("empty source: %v", err)
	}
	e.src.Users = saved
	e.eng.Limits = plan.DefaultLimits()
	// The operator overrides explicitly.
	r = e.mustApply(engine.ApplyOptions{OverrideLimits: true})
	if r.Status != store.StatusApplied || r.Plan.Counts()[plan.UserSuspend] != 15 {
		t.Fatalf("override: %s %v", r.Status, r.Plan.Counts())
	}
	e.noDeletes()
	// Every suspended account still exists.
	if n := len(e.fake.Users()); n != 30 {
		t.Fatalf("accounts %d", n)
	}
}

func TestPlanDigestPin(t *testing.T) {
	e := newEnv(t)
	e.seed()
	c := e.plan()
	e.src.Users = e.src.Users[:29] // AD changed after the review
	if _, err := e.apply(engine.ApplyOptions{ExpectDigest: c.Plan.Digest}); !errors.Is(err, engine.ErrPlanChanged) {
		t.Fatalf("pinned apply after change: %v", err)
	}
	if len(e.fake.Writes()) != 0 {
		t.Fatal("wrote despite a changed plan")
	}
	c = e.plan()
	if r := e.mustApply(engine.ApplyOptions{ExpectDigest: c.Plan.Digest}); r.Status != store.StatusApplied {
		t.Fatalf("pinned apply: %s", r.Status)
	}
}

var errCrash = errors.New("simulated crash")

func TestResumeAfterCrash(t *testing.T) {
	e := newEnv(t)
	e.seed()
	// Crash right after the 5th user create reached Google but before the
	// link was recorded, then right after a group create.
	e.eng.Hooks.AfterTargetWrite = func(seq int, op plan.Op) error {
		if op.Kind == plan.UserCreate && op.Key == "user0005@example.com" {
			return errCrash
		}
		return nil
	}
	if _, err := e.apply(engine.ApplyOptions{}); !errors.Is(err, errCrash) {
		t.Fatalf("crash run: %v", err)
	}
	if n := len(e.fake.Users()); n != 5 {
		t.Fatalf("accounts after crash %d", n)
	}
	e.eng.Hooks.AfterTargetWrite = func(seq int, op plan.Op) error {
		if op.Kind == plan.GroupCreate && op.Key == "sales@groups.example.com" {
			return errCrash
		}
		return nil
	}
	if _, err := e.apply(engine.ApplyOptions{}); !errors.Is(err, errCrash) {
		t.Fatalf("second crash run: %v", err)
	}
	e.eng.Hooks.AfterTargetWrite = nil
	c := e.plan()
	counts := c.Plan.Counts()
	if counts[plan.GroupRelink] != 1 || counts[plan.GroupCreate] != 1 || counts[plan.UserCreate] != 0 {
		t.Fatalf("resume plan %v\n%v", counts, c.Plan.Ops)
	}
	r := e.mustApply(engine.ApplyOptions{})
	if r.Status != store.StatusApplied || len(r.Interrupted) != 1 {
		t.Fatalf("resume: %s interrupted=%v", r.Status, r.Interrupted)
	}
	if n := len(e.fake.Users()); n != 30 {
		t.Fatalf("accounts %d (duplicates?)", n)
	}
	if n := len(e.fake.Groups()); n != 3 {
		t.Fatalf("groups %d (duplicates?)", n)
	}
	if p := e.plan(); !p.Plan.Empty() {
		t.Fatalf("not converged after resume: %v", p.Plan.Ops)
	}
	runs, _ := e.st.Runs(context.Background(), "google", 20)
	interrupted := 0
	for _, r := range runs {
		if r.Status == store.StatusInterrupted {
			interrupted++
		}
	}
	if interrupted != 2 {
		t.Fatalf("interrupted runs %d", interrupted)
	}
	inflight, _ := e.st.InFlight(context.Background(), "google")
	if len(inflight) != 0 {
		t.Fatalf("in-flight left: %+v", inflight)
	}
}

func TestRateLimitsAndAmbiguousWrites(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.fake.RateLimitEvery = 4
	// A create that succeeds on Google but answers 503: the retry gets a
	// 409, recognizes its own account by the marker and carries on.
	e.fake.Fail(fakegoogle.Fault{Method: http.MethodPost, PathPrefix: "/users", Status: 503, Reason: "backendError", AfterCommit: true})
	// Same for a group create.
	e.fake.Fail(fakegoogle.Fault{Method: http.MethodPost, PathPrefix: "/groups", Status: 503, Reason: "backendError", AfterCommit: true})
	// A 403 rate limit with Retry-After.
	e.fake.Fail(fakegoogle.Fault{Method: http.MethodPatch, Status: 403, Reason: "userRateLimitExceeded", RetryAfter: 0, Count: 2})
	r := e.mustApply(engine.ApplyOptions{})
	if r.Status != store.StatusApplied {
		t.Fatalf("status %s %v", r.Status, r.Failures)
	}
	if n := len(e.fake.Users()); n != 30 {
		t.Fatalf("accounts %d", n)
	}
	if n := len(e.fake.Groups()); n != 3 {
		t.Fatalf("groups %d", n)
	}
	if p := e.plan(); !p.Plan.Empty() {
		t.Fatalf("not converged: %v", p.Plan.Ops)
	}
}

func TestPersistentRateLimitStopsRun(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.fake.Fail(fakegoogle.Fault{Method: http.MethodPost, PathPrefix: "/users", Status: 429, Reason: "rateLimitExceeded", Count: 1000})
	r, err := e.apply(engine.ApplyOptions{})
	if err == nil || r.Status != store.StatusPartial || r.Done != 0 || r.Failed != 1 {
		t.Fatalf("persistent rate limit: %v %+v", err, r)
	}
	if !errors.Is(err, connector.ErrRateLimited) {
		t.Fatalf("error %v", err)
	}
	e.fake.ClearFaults()
	if r := e.mustApply(engine.ApplyOptions{}); r.Status != store.StatusApplied {
		t.Fatalf("after recovery: %s", r.Status)
	}
}

func TestPerObjectFailuresAreReported(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.src.Users[0].Attrs[model.FieldOrgUnit] = "/Missing" // the target refuses this OU
	r, err := e.apply(engine.ApplyOptions{})
	if !errors.Is(err, engine.ErrPartial) || r.Failed != 1 {
		t.Fatalf("partial: %v %+v", err, r)
	}
	// Memberships of the account that was not created are skipped.
	if r.Skipped != 2 || !strings.Contains(r.Failures[0], "user0001@example.com") {
		t.Fatalf("skipped %d failures %v", r.Skipped, r.Failures)
	}
	if n := len(e.fake.Users()); n != 29 {
		t.Fatalf("accounts %d", n)
	}
	last := e.alerts.Alerts[len(e.alerts.Alerts)-1]
	if last.Kind != alert.KindPartial {
		t.Fatalf("alert %+v", last)
	}
}

func TestUnmanagedAndAdoption(t *testing.T) {
	e := newEnv(t)
	e.seed()
	pre := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "user0007@example.com", Name: map[string]any{"givenName": "Hand", "familyName": "Made"}})
	c := e.plan()
	if !hasWarning(c.Plan, plan.WarnUnmanagedExists, "user0007@example.com") || c.Plan.Counts()[plan.UserCreate] != 29 {
		t.Fatalf("unmanaged plan %v %v", c.Plan.Counts(), c.Plan.Warnings)
	}
	e.mustApply(engine.ApplyOptions{})
	if u := e.userByEmail("user0007@example.com"); ownerOf(u) != "" || u.Name["givenName"] != "Hand" {
		t.Fatalf("unmanaged account touched: %+v", u)
	}
	e.eng.Policy.Adopt = plan.AdoptEmail
	c = e.plan()
	if c.Plan.Counts()[plan.UserAdopt] != 1 {
		t.Fatalf("adopt plan %v", c.Plan.Ops)
	}
	e.mustApply(engine.ApplyOptions{})
	u := e.userByEmail("user0007@example.com")
	if u.ID != pre.ID || ownerOf(u) != guid(7) || u.Name["givenName"] != "User" {
		t.Fatalf("adopted account %+v", u)
	}
	if p := e.plan(); !p.Plan.Empty() {
		t.Fatalf("not converged: %v", p.Plan.Ops)
	}
}

func TestProtectedAdminNeverSuspended(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.mustApply(engine.ApplyOptions{})
	// user0008 becomes a Google super admin; then it is disabled in AD.
	admin := e.userByEmail("user0008@example.com")
	e.fake.SeedUser(fakegoogle.User{ID: admin.ID, PrimaryEmail: admin.PrimaryEmail, Name: admin.Name, IsAdmin: true,
		ExternalIDs: admin.ExternalIDs, Organizations: admin.Organizations, OrgUnitPath: admin.OrgUnitPath})
	e.src.Users[7].Enabled = false
	c := e.plan()
	if c.Plan.Counts()[plan.UserSuspend] != 0 || !hasWarning(c.Plan, plan.WarnProtected, "user0008@example.com") {
		t.Fatalf("admin plan %v %v", c.Plan.Ops, c.Plan.Warnings)
	}
}

func TestDeleteIsManualAndGuarded(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.mustApply(engine.ApplyOptions{})
	ctx := context.Background()
	// Still in scope and not suspended: refused.
	if _, err := e.eng.DeleteUser(ctx, engine.DeleteRequest{Key: "user0010@example.com", Confirm: "user0010@example.com"}); !errors.Is(err, engine.ErrDeleteRefused) {
		t.Fatalf("delete active: %v", err)
	}
	// Unmanaged account: refused.
	e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "boss@example.com", Name: map[string]any{"givenName": "B", "familyName": "S"}})
	if _, err := e.eng.DeleteUser(ctx, engine.DeleteRequest{Key: "boss@example.com", Confirm: "boss@example.com"}); !errors.Is(err, engine.ErrDeleteRefused) {
		t.Fatalf("delete unmanaged: %v", err)
	}
	// Leaves the scope, gets suspended by the sync.
	e.src.Users = append(e.src.Users[:9], e.src.Users[10:]...)
	e.mustApply(engine.ApplyOptions{Scheduled: true})
	// Minimum suspension time not reached: refused.
	if _, err := e.eng.DeleteUser(ctx, engine.DeleteRequest{Key: "user0010@example.com", Confirm: "user0010@example.com", MinSuspended: time.Hour}); !errors.Is(err, engine.ErrDeleteRefused) {
		t.Fatalf("delete too early: %v", err)
	}
	// Wrong confirmation: refused.
	if _, err := e.eng.DeleteUser(ctx, engine.DeleteRequest{Key: "user0010@example.com", Confirm: "USER0010@example.com"}); !errors.Is(err, engine.ErrDeleteRefused) {
		t.Fatalf("delete with wrong confirmation: %v", err)
	}
	if _, ok := e.fake.User("user0010@example.com"); !ok {
		t.Fatal("deleted despite refusals")
	}
	if _, err := e.eng.DeleteUser(ctx, engine.DeleteRequest{Key: "user0010@example.com", Confirm: "user0010@example.com"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := e.fake.User("user0010@example.com"); ok {
		t.Fatal("not deleted")
	}
	if l, _ := e.st.FindLink(ctx, "google", guid(10)); l != nil {
		t.Fatal("link kept after delete")
	}
	events, _ := e.st.ListAudit(ctx, 50)
	found := false
	for _, ev := range events {
		if ev.Action == "user.delete" && ev.Result == store.ResultOK && strings.Contains(ev.Target, "user0010@example.com") {
			found = true
		}
	}
	if !found {
		t.Fatal("deletion not audited")
	}
	if p := e.plan(); !p.Plan.Empty() {
		t.Fatalf("plan after delete: %v", p.Plan.Ops)
	}
}

func TestReadOnlyScopesForPlan(t *testing.T) {
	e := newEnv(t)
	e.seed()
	// Only the read-only scopes are delegated: plan works, apply cannot
	// even get a token.
	e.fake.Delegated = map[string]bool{fakegoogle.ScopeUserReadonly: true, fakegoogle.ScopeGroupReadonly: true}
	if c := e.plan(); c.Plan.Counts()[plan.UserCreate] != 30 {
		t.Fatalf("plan %v", c.Plan.Counts())
	}
	_, err := e.apply(engine.ApplyOptions{})
	if !errors.Is(err, connector.ErrAuth) {
		t.Fatalf("apply without write scopes: %v", err)
	}
	if len(e.fake.Writes()) != 0 {
		t.Fatal("wrote without write scopes")
	}
}

func TestTargetAccountRemovedOutsideSync(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.mustApply(engine.ApplyOptions{})
	u := e.userByEmail("user0011@example.com")
	e.fake.DeleteUserDirect(u.ID)
	c := e.plan()
	counts := c.Plan.Counts()
	if counts[plan.UserUnlink] != 1 || counts[plan.UserCreate] != 1 || counts[plan.MemberAdd] != 1 {
		t.Fatalf("plan %v", c.Plan.Ops)
	}
	e.mustApply(engine.ApplyOptions{Scheduled: true})
	if p := e.plan(); !p.Plan.Empty() {
		t.Fatalf("not converged: %v", p.Plan.Ops)
	}
}

func TestStateLossRecovery(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.mustApply(engine.ApplyOptions{})
	// The state database is lost: users come back through the marker;
	// groups need an explicit adoption run.
	st, err := store.Open(context.Background(), filepath.Join(e.dir, "new.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	e.eng.Store = st
	e.st = st
	c := e.plan()
	counts := c.Plan.Counts()
	if counts[plan.UserRelink] != 30 || counts[plan.UserCreate] != 0 || counts[plan.GroupCreate] != 0 || len(c.Plan.Warnings) != 3 {
		t.Fatalf("plan after state loss %v %v", counts, c.Plan.Warnings)
	}
	e.eng.Policy.Adopt = plan.AdoptEmail
	e.mustApply(engine.ApplyOptions{})
	e.eng.Policy.Adopt = plan.AdoptNever
	if p := e.plan(); !p.Plan.Empty() {
		t.Fatalf("not converged: %v", p.Plan.Ops)
	}
	if n := len(e.fake.Users()); n != 30 {
		t.Fatalf("accounts %d", n)
	}
}

func TestLockExcludesConcurrentRuns(t *testing.T) {
	e := newEnv(t)
	lk, err := store.AcquireLock(e.eng.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	if _, err := e.eng.Plan(context.Background(), "manual"); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("plan under lock: %v", err)
	}
}
