package google_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/connector/google"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
)

// connect builds a connector on a fresh fake with cfg's mode, subject and
// group setting.
func connect(t *testing.T, cfg google.Config, write bool) (*fakegoogle.Server, *google.Connector) {
	t.Helper()
	fake := fakegoogle.New("example.com")
	srv := httptest.NewTLSServer(fake)
	t.Cleanup(srv.Close)
	fake.SetTokenURL(srv.URL + "/token")
	key, err := google.ParseServiceAccountKey(fake.KeyJSON())
	if err != nil {
		t.Fatal(err)
	}
	cfg.KeyCredential, cfg.APIBaseURL, cfg.RequestsPerSecond = "x", srv.URL, 1e6
	c, err := google.New(cfg, key, write, google.Options{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return fake, c
}

// TestServiceAccountModeImpersonatesNobody: the default mode sends no sub
// claim (the service account acts with its own role), needs no admin
// subject, and fails when the service account holds no role.
func TestServiceAccountModeImpersonatesNobody(t *testing.T) {
	ctx := context.Background()
	fake, c := connect(t, google.Config{}, false)
	if _, err := c.Snapshot(ctx, true); err != nil {
		t.Fatal(err)
	}
	if subs := fake.TokenSubjects(); len(subs) == 0 || slices.ContainsFunc(subs, func(s string) bool { return s != "" }) {
		t.Fatalf("subjects %q", subs)
	}
	if _, err := c.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	fake2, c2 := connect(t, google.Config{}, false)
	fake2.RoleAssigned = false
	if _, err := c2.Snapshot(ctx, false); !errors.Is(err, connector.ErrAuth) {
		t.Fatalf("no role: %v", err)
	}
}

// TestDelegationIsExplicit: domain-wide delegation needs auth_mode set to
// it and an admin subject, and then impersonates exactly that subject.
func TestDelegationIsExplicit(t *testing.T) {
	ctx := context.Background()
	fake, c := connect(t, google.Config{AuthMode: google.AuthDelegation, AdminSubject: "admin@example.com"}, false)
	if _, err := c.Snapshot(ctx, false); err != nil {
		t.Fatal(err)
	}
	if subs := fake.TokenSubjects(); len(subs) != 1 || subs[0] != "admin@example.com" {
		t.Fatalf("subjects %q", subs)
	}
	for name, cfg := range map[string]google.Config{
		"no subject":   {AuthMode: google.AuthDelegation},
		"unknown mode": {AuthMode: "impersonate-everyone", AdminSubject: "admin@example.com"},
	} {
		cfg.Defaults()
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	sa := google.Config{}
	sa.Defaults()
	if err := sa.Validate(); err != nil || sa.AuthMode != google.AuthServiceAccount || sa.Delegated() {
		t.Fatalf("default mode %q: %v", sa.AuthMode, err)
	}
	if !strings.Contains(google.DelegationWarning, "any user") {
		t.Fatal("the warning does not say what is at stake")
	}
}

// TestMinimalScopes: the write scopes carry the group scope only when
// groups are synced; reads are read-only; the role read has its own token.
func TestMinimalScopes(t *testing.T) {
	if got := google.Scopes(false, true); !slices.Equal(got, []string{google.ScopeUserReadonly, google.ScopeGroupReadonly}) {
		t.Fatalf("read %v", got)
	}
	if got := google.Scopes(true, false); !slices.Equal(got, []string{google.ScopeUser}) {
		t.Fatalf("write without groups %v", got)
	}
	if got := google.Scopes(true, true); !slices.Equal(got, []string{google.ScopeUser, google.ScopeGroup}) {
		t.Fatalf("write with groups %v", got)
	}
	// A role without group privileges is enough for a users-only sync.
	ctx := context.Background()
	fake, c := connect(t, google.Config{}, true)
	fake.RoleScopes = map[string]bool{fakegoogle.ScopeUser: true}
	if _, err := c.CreateUser(ctx, "g", attrs("a@example.com"), false); err != nil {
		t.Fatalf("users-only write: %v", err)
	}
	fake2, c2 := connect(t, google.Config{ManageGroups: true}, true)
	fake2.RoleScopes = map[string]bool{fakegoogle.ScopeUser: true}
	if _, err := c2.CreateUser(ctx, "g", attrs("a@example.com"), false); !errors.Is(err, connector.ErrAuth) {
		t.Fatalf("group scope not requested: %v", err)
	}
}

// TestAdminRoleGroups reads the role assignments with the role scope only
// and fails (so no group is adopted) when it is not granted.
func TestAdminRoleGroups(t *testing.T) {
	ctx := context.Background()
	fake, c := connect(t, google.Config{}, false)
	fake.RoleAssignments = []fakegoogle.RoleAssignment{{RoleID: "1", AssignedTo: "G1", AssigneeType: "group"}}
	if _, err := c.AdminRoleGroups(ctx); err == nil {
		t.Fatal("role assignments read without the scope")
	}
	fake.RoleScopes[fakegoogle.ScopeRoleReadonly] = true
	got, err := c.AdminRoleGroups(ctx)
	if err != nil || !got["G1"] || len(got) != 1 {
		t.Fatalf("roles %v %v", got, err)
	}
}

// TestAuthModeReport: the mode in force, where it comes from, and the
// unused admin subject of the service-account mode.
func TestAuthModeReport(t *testing.T) {
	cases := []struct {
		cfg      google.Config
		line     string
		warnings int
	}{
		{google.Config{}, "service-account (the default: no auth_mode in the file)", 0},
		{google.Config{AdminSubject: "a@example.com"}, "service-account (the default", 1},
		{google.Config{AuthMode: google.AuthServiceAccount, AdminSubject: "a@example.com"}, "service-account (set in the file)", 1},
		{google.Config{AuthMode: google.AuthServiceAccount}, "service-account (set in the file)", 0},
		{google.Config{AuthMode: google.AuthDelegation, AdminSubject: "a@example.com"}, "domain-wide-delegation (set in the file), acting as a@example.com", 0},
	}
	for _, c := range cases {
		cfg := c.cfg
		cfg.Defaults()
		line, warnings := cfg.AuthModeReport()
		if !strings.Contains(line, c.line) || len(warnings) != c.warnings {
			t.Errorf("%+v: %q %q", c.cfg, line, warnings)
		}
		for _, w := range warnings {
			if !strings.Contains(w, cfg.AdminSubject) || !strings.Contains(w, google.AuthDelegation) {
				t.Errorf("warning %q", w)
			}
		}
	}
}
