package api

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// TestAccountSelfService drives the self-service operations as conductor
// does: the actor is the user (by SID), the generated password is in the
// result only (never in the audit, the state database or the log), refusals
// carry their reason code, and the rate limit has its own error code.
func TestAccountSelfService(t *testing.T) {
	e := newTEnv(t)
	e.src.mu.Lock()
	e.src.res.Users[3].SID = actor.SID // user0004 is the signed-in user
	e.src.mu.Unlock()
	e.must(syncapi.OpKeySet, syncapi.KeySetParams{KeyJSON: string(e.fake.KeyJSON())}, nil)
	v, s := e.settings()
	if s.SelfService != nil {
		t.Fatalf("defaults travel as nil: %+v", s.SelfService)
	}
	s.Mode = "apply"
	s.SelfService = &syncapi.SelfServiceSettings{Activation: "self-service"}
	e.must(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: v.Version, Settings: s}, nil)

	var st syncapi.AccountStatus
	e.must(syncapi.OpAccountStatus, syncapi.AccountStatusParams{}, &st)
	if len(st.Targets) != 1 {
		t.Fatalf("targets %+v", st.Targets)
	}
	a := st.Targets[0]
	if a.Target != "google" || a.State != syncapi.AccountNotActivated || !a.CanActivate || a.CanSetPassword || a.Address != "user0004@example.com" ||
		a.ChosenPassword || a.ActionsLeft != 3 {
		t.Fatalf("status %+v", a)
	}
	if err := e.call(syncapi.OpAccountStatus, syncapi.AccountStatusParams{Target: "entra"}, nil); err == nil || err.Code != syncapi.CodeNotFound {
		t.Fatalf("unknown target: %v", err)
	}
	// Protocol checks: a generated password takes no password; bad target.
	if _, err := syncapi.NewRequest("req-bad-0001", syncapi.OpAccountActivate, actor,
		syncapi.AccountActivateParams{Target: "google", PasswordChoice: syncapi.PasswordChoice{Mode: syncapi.PasswordGenerate, Password: "x"}}); err == nil {
		t.Fatal("a generated password with a password was accepted")
	}
	if _, err := syncapi.NewRequest("req-bad-0002", syncapi.OpAccountSetPassword, actor,
		syncapi.AccountSetPasswordParams{Target: "Google Workspace", PasswordChoice: syncapi.PasswordChoice{Mode: syncapi.PasswordGenerate}}); err == nil {
		t.Fatal("a bad target was accepted")
	}

	gen := syncapi.PasswordChoice{Mode: syncapi.PasswordGenerate}
	err := e.call(syncapi.OpAccountSetPassword, syncapi.AccountSetPasswordParams{Target: "google", PasswordChoice: gen}, nil)
	if err == nil || err.Code != syncapi.CodeForbidden || len(err.Details) != 1 || err.Details[0] != syncapi.ReasonNotLinked {
		t.Fatalf("reset before activation: %+v", err)
	}
	var res syncapi.AccountActionResult
	e.must(syncapi.OpAccountActivate, syncapi.AccountActivateParams{Target: "google", PasswordChoice: gen}, &res)
	if res.Password == "" || res.Account.State != syncapi.AccountActive || !e.fake.PasswordMatches("user0004@example.com", res.Password) {
		t.Fatalf("activation %+v", res.Account)
	}
	if u, _ := e.fake.User("user0004@example.com"); u.ChangePasswordNext {
		t.Fatal("a password the user saw must not need a change at next sign-in")
	}
	if len(e.fake.Users()) != 2 { // the admin subject and user0004
		t.Fatalf("accounts %d", len(e.fake.Users()))
	}
	chosen := syncapi.PasswordChoice{Mode: syncapi.PasswordChosen, Password: "a long passphrase of mine"}
	err = e.call(syncapi.OpAccountSetPassword, syncapi.AccountSetPasswordParams{Target: "google", PasswordChoice: chosen}, nil)
	if err == nil || err.Code != syncapi.CodeForbidden || err.Details[0] != syncapi.ReasonChosenOff {
		t.Fatalf("chosen while off: %+v", err)
	}
	var res2 syncapi.AccountActionResult
	e.must(syncapi.OpAccountSetPassword, syncapi.AccountSetPasswordParams{Target: "google", PasswordChoice: gen}, &res2)
	if res2.Password == "" || res2.Password == res.Password || !e.fake.PasswordMatches("user0004@example.com", res2.Password) {
		t.Fatal("reset did not set the returned password")
	}
	e.must(syncapi.OpAccountSetPassword, syncapi.AccountSetPasswordParams{Target: "google", PasswordChoice: gen}, &res2)
	err = e.call(syncapi.OpAccountSetPassword, syncapi.AccountSetPasswordParams{Target: "google", PasswordChoice: gen}, nil)
	if err == nil || err.Code != syncapi.CodeRateLimited {
		t.Fatalf("fourth action in an hour: %+v", err)
	}

	// Audited with the actor, never with a password.
	var audit bytes.Buffer
	_, _ = e.rt.Store.ExportAudit(context.Background(), &audit)
	for _, want := range []string{`"action":"api.account.activate"`, `"action":"api.account.set_password"`, `"action":"self.set_password"`,
		`"action":"activate.start"`, `"actor":"conductor:lab.admin@10.0.0.5"`} {
		if !strings.Contains(audit.String(), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
	for _, pw := range []string{res.Password, res2.Password} {
		if strings.Contains(audit.String(), pw) {
			t.Fatal("a password is in the audit")
		}
		for _, f := range []string{"state.db", "state.db-wal"} {
			b, _ := os.ReadFile(filepath.Join(e.dir, "state", f))
			if bytes.Contains(b, []byte(pw)) {
				t.Fatalf("a password is in %s", f)
			}
		}
	}
	// The activation is a run of its own, never applicable from the runs
	// page.
	var runs syncapi.RunsList
	e.must(syncapi.OpRunsList, syncapi.RunsListParams{}, &runs)
	if len(runs.Runs) != 1 || runs.Runs[0].Action != "activate" || runs.Runs[0].Trigger != "self-service" || runs.Runs[0].Status != syncapi.StatusApplied {
		t.Fatalf("runs %+v", runs.Runs)
	}
	var rd syncapi.RunDetail
	e.must(syncapi.OpRunGet, syncapi.RunGetParams{ID: runs.Runs[0].ID}, &rd)
	if rd.Applicable || rd.NotApply != "self-service" || rd.Counts["user.create"] != 1 {
		t.Fatalf("activation run %+v", rd)
	}
	// The settings carry the policy now.
	if _, s := e.settings(); s.SelfService == nil || s.SelfService.Activation != "self-service" {
		t.Fatalf("settings %+v", s.SelfService)
	}
}
