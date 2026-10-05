package engine_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/engine"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

func usid(n int) string { return fmt.Sprintf("S-1-5-21-1-2-3-%d", 1000+n) }

// selfEnv is env with self-service activation and SIDs on the AD users.
func selfEnv(t *testing.T, activation string) *env {
	t.Helper()
	e := newEnv(t)
	e.seed()
	for i := range e.src.Users {
		e.src.Users[i].SID = usid(i + 1)
	}
	e.eng.SelfService = engine.SelfServicePolicy{Activation: activation, PasswordReset: "created", PasswordMinLength: 12,
		MaxPerUserHour: 3, MaxPerTargetHour: 30}
	e.eng.Policy.SelfServiceActivation = activation == "self-service"
	return e
}

func (e *env) status(n int) *syncapi.TargetAccount {
	e.t.Helper()
	a, err := e.eng.AccountStatus(context.Background(), usid(n))
	if err != nil {
		e.t.Fatalf("status: %v", err)
	}
	return a
}

func reasonOf(err error) string {
	var se *engine.SelfServiceError
	if errors.As(err, &se) {
		return se.Reason
	}
	return ""
}

var generate = syncapi.PasswordChoice{Mode: syncapi.PasswordGenerate}

// passwordWrites lists the writes that carry a password field.
func passwordWrites(fake *fakegoogle.Server) []fakegoogle.Write {
	var out []fakegoogle.Write
	for _, w := range fake.Writes() {
		if slices.Contains(w.Fields, "password") || slices.Contains(w.Fields, "changePasswordAtNextLogin") {
			out = append(out, w)
		}
	}
	return out
}

// noSecretAt fails when pw appears in the state database, the engine's
// output or the fake's recorded writes.
func (e *env) noSecretAt(pw string) {
	e.t.Helper()
	if pw == "" {
		e.t.Fatal("empty password")
	}
	for _, f := range []string{"state.db", "state.db-wal"} {
		b, err := os.ReadFile(filepath.Join(e.dir, f))
		if err != nil && !os.IsNotExist(err) {
			e.t.Fatal(err)
		}
		if bytes.Contains(b, []byte(pw)) {
			e.t.Fatalf("the password is stored in %s", f)
		}
	}
	if strings.Contains(e.out.String(), pw) {
		e.t.Fatal("the password is in the engine output")
	}
	if strings.Contains(fmt.Sprint(e.fake.Writes()), pw) {
		e.t.Fatal("the password is in the recorded writes")
	}
}

// TestSelfServiceActivation: with activation = self-service the scheduled
// runs create nobody and show everyone as pending activation; a user who
// activates gets the account at once (same mapping, through a journaled
// run of its own), in the groups that exist, with the password they were
// shown and no change required; nothing else is touched.
func TestSelfServiceActivation(t *testing.T) {
	e := selfEnv(t, "self-service")
	c := e.plan()
	if n := c.Plan.Counts()[plan.UserCreate]; n != 0 {
		t.Fatalf("self-service plan creates %d accounts", n)
	}
	pending := 0
	for _, w := range c.Plan.Warnings {
		if w.Code == plan.WarnPendingActivation {
			pending++
		}
	}
	if pending != 30 {
		t.Fatalf("pending activations: %d", pending)
	}
	// Groups are created (empty of users who did not activate).
	e.mustApply(engine.ApplyOptions{})
	if len(e.fake.Users()) != 0 {
		t.Fatalf("accounts created without activation: %d", len(e.fake.Users()))
	}

	a := e.status(1)
	if a.State != syncapi.AccountNotActivated || !a.CanActivate || a.Address != "user0001@example.com" || a.Title != "Google Workspace" ||
		!a.Capabilities.OnDemandCreate || !a.Capabilities.SetPassword || a.Rules.MinLength != 12 || a.Rules.MaxLength != 100 || a.ActionsLeft != 3 {
		t.Fatalf("status before activation: %+v", a)
	}
	e.fake.ResetCounters()
	res, err := e.eng.Activate(context.Background(), usid(1), generate)
	if err != nil {
		t.Fatalf("activate: %v\n%s", err, e.out.String())
	}
	if res.Password == "" || res.Account.State != syncapi.AccountActive || res.Account.Origin != syncapi.OriginCreated || len(res.Warnings) != 0 {
		t.Fatalf("result: %+v", res.Account)
	}
	u := e.userByEmail("user0001@example.com")
	if ownerOf(u) != guid(1) || u.ChangePasswordNext || !e.fake.PasswordMatches(u.ID, res.Password) || u.OrgUnitPath != "/Staff/Engineering" {
		t.Fatalf("account %+v", u)
	}
	// Only this user: one create plus the memberships in existing groups.
	if len(e.fake.Users()) != 1 {
		t.Fatalf("accounts: %d", len(e.fake.Users()))
	}
	_, eng, _ := e.fake.GroupByEmail("eng@groups.example.com")
	_, staff, _ := e.fake.GroupByEmail("staff@groups.example.com")
	if !slices.Contains(eng, "user0001@example.com") || !slices.Contains(staff, "user0001@example.com") {
		t.Fatalf("memberships: eng %v staff %v", eng, staff)
	}
	pw := passwordWrites(e.fake)
	if len(pw) != 1 || pw[0].Method != http.MethodPost || pw[0].Path != "/users" {
		t.Fatalf("password writes: %+v", pw)
	}
	e.noSecretAt(res.Password)

	// A journaled run of its own.
	runs, err := e.st.Runs(context.Background(), "google", 1)
	if err != nil || len(runs) != 1 || runs[0].Action != "activate" || runs[0].Trigger != "self-service" || runs[0].Status != store.StatusApplied {
		t.Fatalf("runs %+v %v", runs, err)
	}
	j, _ := e.st.Journal(context.Background(), runs[0].ID)
	if len(j) != 3 || j[0].Kind != plan.UserCreate || j[0].Status != store.OpDone {
		t.Fatalf("journal %+v", j)
	}

	// The next scheduled plan: only the remaining pending users, no change
	// for the activated one.
	c = e.plan()
	if len(c.Plan.Ops) != 0 {
		t.Fatalf("plan after activation: %v", c.Plan.Ops)
	}
	if a := e.status(1); a.State != syncapi.AccountActive || a.CanActivate || !a.CanSetPassword || a.ActionsLeft != 2 {
		t.Fatalf("status after activation: %+v", a)
	}
	if _, err := e.eng.Activate(context.Background(), usid(1), generate); reasonOf(err) != syncapi.ReasonAlreadyActive {
		t.Fatalf("second activation: %v", err)
	}
	// The account was removed outside the sync: it is created again by the
	// runs (the user activated it once).
	e.fake.DeleteUserDirect(u.ID)
	c = e.plan()
	if c.Plan.Counts()[plan.UserCreate] != 1 {
		t.Fatalf("re-create of an activated user: %v", c.Plan.Ops)
	}
}

// TestSelfServiceAutoActivation: with activation = auto the runs create
// accounts as before and activation is not offered.
func TestSelfServiceAutoActivation(t *testing.T) {
	e := selfEnv(t, "auto")
	a := e.status(2)
	if a.State != syncapi.AccountPendingSync || a.CanActivate || a.ActivateReason != syncapi.ReasonActivationAuto {
		t.Fatalf("status: %+v", a)
	}
	if _, err := e.eng.Activate(context.Background(), usid(2), generate); reasonOf(err) != syncapi.ReasonActivationAuto {
		t.Fatalf("activate in auto: %v", err)
	}
	if c := e.plan(); c.Plan.Counts()[plan.UserCreate] != 30 {
		t.Fatalf("auto plan: %v", c.Plan.Counts())
	}
}

// TestSelfServiceEligibility: out of scope, disabled, dry-run, an existing
// account (adopted by the runs) or a taken address are never activated.
func TestSelfServiceEligibility(t *testing.T) {
	e := selfEnv(t, "self-service")
	ctx := context.Background()
	// Not in the source (out of scope).
	if a, err := e.eng.AccountStatus(ctx, "S-1-5-21-1-2-3-9999"); err != nil || a.State != syncapi.AccountNotEligible || a.Reason != syncapi.ReasonOutOfScope {
		t.Fatalf("out of scope: %+v %v", a, err)
	}
	if _, err := e.eng.Activate(ctx, "S-1-5-21-1-2-3-9999", generate); reasonOf(err) != syncapi.ReasonOutOfScope {
		t.Fatalf("activate out of scope: %v", err)
	}
	// Disabled in AD.
	e.src.Users[2].Enabled = false
	if a := e.status(3); a.State != syncapi.AccountNotEligible || a.Reason != syncapi.ReasonDisabled {
		t.Fatalf("disabled: %+v", a)
	}
	// Dry-run: nothing is written, not even this.
	e.eng.Mode = engine.ModeDryRun
	if a := e.status(4); a.State != syncapi.AccountNotActivated || a.CanActivate || a.ActivateReason != syncapi.ReasonDryRun {
		t.Fatalf("dry-run: %+v", a)
	}
	if _, err := e.eng.Activate(ctx, usid(4), generate); reasonOf(err) != syncapi.ReasonDryRun {
		t.Fatalf("activate in dry-run: %v", err)
	}
	e.eng.Mode = engine.ModeApply
	// An unmanaged account with the address: taken (adopt = never) ...
	e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "user0005@example.com", Name: map[string]any{"givenName": "Old", "familyName": "Account"}})
	if a := e.status(5); a.State != syncapi.AccountNotEligible || a.Reason != syncapi.ReasonAddressTaken {
		t.Fatalf("taken: %+v", a)
	}
	// ... or linked by the next run (adopt = email): never by activation.
	e.eng.Policy.Adopt = plan.AdoptEmail
	if a := e.status(5); a.State != syncapi.AccountPendingSync || a.Reason != syncapi.ReasonExistingAccount || a.CanActivate {
		t.Fatalf("adoptable: %+v", a)
	}
	// An alias of another account.
	e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "other@example.com", Aliases: []string{"user0006@example.com"},
		Name: map[string]any{"givenName": "Other", "familyName": "Person"}})
	if a := e.status(6); a.State != syncapi.AccountNotEligible || a.Reason != syncapi.ReasonAddressTaken {
		t.Fatalf("alias: %+v", a)
	}
	// A duplicate address in AD is only visible to the full plan: the
	// activation is refused, nothing written.
	e.src.Users[7].Attrs[model.FieldPrimaryEmail] = "user0009@example.com"
	e.fake.ResetCounters()
	if _, err := e.eng.Activate(ctx, usid(9), generate); reasonOf(err) != syncapi.ReasonAddressTaken {
		t.Fatalf("duplicate: %v", err)
	}
	if len(e.fake.Writes()) != 0 {
		t.Fatalf("refused activation wrote: %+v", e.fake.Writes())
	}
	if runs, _ := e.st.Runs(ctx, "google", 5); len(runs) != 0 {
		t.Fatalf("refused activation recorded a run: %+v", runs)
	}
}

// TestSelfServiceChosenPassword: typed passwords only when allowed, checked
// against the target's rules raised by the policy; a target that refuses
// the password (its own policy) is reported as such.
func TestSelfServiceChosenPassword(t *testing.T) {
	e := selfEnv(t, "self-service")
	ctx := context.Background()
	chosen := syncapi.PasswordChoice{Mode: syncapi.PasswordChosen, Password: "my own long passphrase"}
	if _, err := e.eng.Activate(ctx, usid(1), chosen); reasonOf(err) != syncapi.ReasonChosenOff {
		t.Fatalf("chosen while off: %v", err)
	}
	e.eng.SelfService.ChosenPassword = true
	if _, err := e.eng.Activate(ctx, usid(1), syncapi.PasswordChoice{Mode: syncapi.PasswordChosen, Password: "short1A"}); reasonOf(err) != syncapi.ReasonPasswordRules {
		t.Fatalf("short password: %v", err)
	}
	if _, err := e.eng.Activate(ctx, usid(1), syncapi.PasswordChoice{Mode: syncapi.PasswordChosen, Password: "acentuação longa demais"}); reasonOf(err) != syncapi.ReasonPasswordRules {
		t.Fatalf("non-ASCII password: %v", err)
	}
	res, err := e.eng.Activate(ctx, usid(1), chosen)
	if err != nil || res.Password != "" {
		t.Fatalf("chosen activation: %+v %v", res, err)
	}
	if !e.fake.PasswordMatches("user0001@example.com", chosen.Password) {
		t.Fatal("the chosen password was not set")
	}
	e.noSecretAt(chosen.Password)

	// The tenant requires 30 characters: the target refuses.
	e.fake.SetMinPasswordLength(30)
	if _, err := e.eng.SetPassword(ctx, usid(1), chosen); reasonOf(err) != syncapi.ReasonTargetRefused {
		t.Fatalf("target refusal: %v", err)
	}
	if !e.fake.PasswordMatches("user0001@example.com", chosen.Password) {
		t.Fatal("a refused password changed the account")
	}
}

// TestSelfServiceSetPassword: a reset sends only the password (no change
// required at next sign-in) to the user's own created account; adopted
// accounts only when the policy allows it, administrators and suspended
// accounts never; the rate limits hold.
func TestSelfServiceSetPassword(t *testing.T) {
	e := selfEnv(t, "auto")
	ctx := context.Background()
	if _, err := e.eng.SetPassword(ctx, usid(1), generate); reasonOf(err) != syncapi.ReasonNotLinked {
		t.Fatalf("reset before the account exists: %v", err)
	}
	// user0003 exists in Google before the sync and is adopted; user0004
	// is a Google administrator, adopted too.
	e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "user0003@example.com", Name: map[string]any{"givenName": "User", "familyName": "0003"}})
	e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "user0004@example.com", IsAdmin: true, Name: map[string]any{"givenName": "User", "familyName": "0004"}})
	e.eng.Policy.Adopt = plan.AdoptEmail
	e.mustApply(engine.ApplyOptions{OverrideLimits: true})
	e.fake.ResetCounters()

	res, err := e.eng.SetPassword(ctx, usid(1), generate)
	if err != nil {
		t.Fatalf("reset: %v\n%s", err, e.out.String())
	}
	u := e.userByEmail("user0001@example.com")
	if !e.fake.PasswordMatches(u.ID, res.Password) || u.ChangePasswordNext || u.PasswordChanges != 1 {
		t.Fatalf("account after reset: %+v", u)
	}
	w := e.fake.Writes()
	if len(w) != 1 || w[0].Method != http.MethodPatch || strings.Join(w[0].Fields, ",") != "changePasswordAtNextLogin,password" {
		t.Fatalf("reset writes: %+v", w)
	}
	e.noSecretAt(res.Password)
	// The audit records the action, never the password.
	ev, _ := e.st.ListAudit(ctx, 5)
	found := false
	for _, a := range ev {
		if a.Action == "self.set_password" && a.Result == store.ResultOK && strings.Contains(a.Target, "user0001@example.com") {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit: %+v", ev)
	}

	// Adopted: refused by default, allowed by created-and-adopted.
	if a := e.status(3); a.Origin != syncapi.OriginAdopted || a.CanSetPassword || a.PasswordReason != syncapi.ReasonAdopted {
		t.Fatalf("adopted status: %+v", a)
	}
	if _, err := e.eng.SetPassword(ctx, usid(3), generate); reasonOf(err) != syncapi.ReasonAdopted {
		t.Fatalf("adopted reset: %v", err)
	}
	if u := e.userByEmail("user0003@example.com"); u.PasswordChanges != 0 || u.PasswordSet {
		t.Fatalf("adopted account password touched: %+v", u)
	}
	// Administrators: never, whatever the policy.
	e.eng.SelfService.PasswordReset = "created-and-adopted"
	if _, err := e.eng.SetPassword(ctx, usid(4), generate); reasonOf(err) != syncapi.ReasonAdmin {
		t.Fatalf("admin reset: %v", err)
	}
	if _, err := e.eng.SetPassword(ctx, usid(3), generate); err != nil {
		t.Fatalf("adopted reset allowed by policy: %v", err)
	}
	// Off.
	e.eng.SelfService.PasswordReset = "off"
	if _, err := e.eng.SetPassword(ctx, usid(2), generate); reasonOf(err) != syncapi.ReasonResetOff {
		t.Fatalf("reset off: %v", err)
	}
	e.eng.SelfService.PasswordReset = "created"
	// Suspended account.
	e.fake.SuspendDirect(e.userByEmail("user0002@example.com").ID, true)
	if _, err := e.eng.SetPassword(ctx, usid(2), generate); reasonOf(err) != syncapi.ReasonSuspended {
		t.Fatalf("suspended reset: %v", err)
	}
	// Rate limit per user: user0001 made one reset; two more, then refused.
	for range 2 {
		if _, err := e.eng.SetPassword(ctx, usid(1), generate); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.eng.SetPassword(ctx, usid(1), generate); !errors.Is(err, engine.ErrRateLimited) {
		t.Fatalf("per-user limit: %v", err)
	}
	if a := e.status(1); a.ActionsLeft != 0 {
		t.Fatalf("actions left: %d", a.ActionsLeft)
	}
	// Per target: 5 actions so far (3 user0001, user0003); a limit of 5.
	e.eng.SelfService.MaxPerTargetHour = 5
	if _, err := e.eng.SetPassword(ctx, usid(5), generate); err != nil {
		t.Fatalf("fifth action: %v", err)
	}
	if _, err := e.eng.SetPassword(ctx, usid(6), generate); !errors.Is(err, engine.ErrRateLimited) {
		t.Fatalf("per-target limit: %v", err)
	}
	// No request other than these resets and the run's creates carried a
	// password.
	for _, w := range passwordWrites(e.fake) {
		if w.Method != http.MethodPatch || strings.Join(w.Fields, ",") != "changePasswordAtNextLogin,password" {
			t.Fatalf("password write %+v", w)
		}
	}
}

// TestSelfServiceStatusUnreachableTarget: a target that cannot be read
// gives an unknown state, not an error page.
func TestSelfServiceStatusUnreachableTarget(t *testing.T) {
	e := selfEnv(t, "self-service")
	e.fake.Fail(fakegoogle.Fault{Method: http.MethodGet, PathPrefix: "/users", Status: 403, Reason: "forbidden", Count: 50})
	a := e.status(1)
	if a.State != syncapi.AccountUnknown || a.Reason != syncapi.ReasonUnavailable || a.CanActivate {
		t.Fatalf("status: %+v", a)
	}
}
