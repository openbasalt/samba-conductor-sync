package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samba-conductor/conductor-sync/internal/model"
	"github.com/samba-conductor/conductor-sync/internal/plan"
	"github.com/samba-conductor/conductor-sync/syncapi"
)

func TestExampleLoads(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "conductor-sync.toml.example"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "dry-run" || c.Limits.MaxSuspends != 10 || c.Delete.MinSuspendedDays != 30 {
		t.Fatalf("%+v", c)
	}
	p := c.PlanPolicy()
	if !p.SuspendDisabled || !p.ManageGroups || p.Adopt != plan.AdoptNever || !p.Optional[model.FieldTitle] || p.Optional[model.FieldEmployeeID] {
		t.Fatalf("policy %+v", p)
	}
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimal = `
[source]
realm = "LAB.TEST"
ca_file = "/ca.pem"
bind_user = "svc"
password_credential = "ad-bind"
user_bases = ["OU=People,DC=lab,DC=test"]
[mapping]
primary_email = ["{sAMAccountName}@example.com"]
allowed_domains = ["example.com"]
[google]
admin_subject = "admin@example.com"
key_credential = "google-sa"
`

func TestDefaultsAndErrors(t *testing.T) {
	c, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "dry-run" || c.Limits != plan.DefaultLimits() || c.PlanPolicy().ManageGroups {
		t.Fatalf("defaults %+v", c)
	}
	_, err = Load(write(t, minimal+"\nmode = \"yolo\"\n"))
	if err == nil {
		t.Fatal("bad mode accepted")
	}
	_, err = Load(write(t, "typo_key = 1\n"+minimal))
	if err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("unknown key: %v", err)
	}
	_, err = Load(write(t, minimal+"[limits]\nmax_creates = -5\n[alert]\nwebhook_url = \"http://example.com\"\n[policy]\nadopt = \"all\"\n"))
	for _, want := range []string{"max_creates", "webhook_url", "policy.adopt"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestSettingsRoundTripAndExport(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "conductor-sync.toml.example"))
	if err != nil {
		t.Fatal(err)
	}
	s := SettingsOf(c)
	n, err := c.Overlay(s, 3)
	if err != nil {
		t.Fatal(err)
	}
	if d := syncapi.DiffSettings(s, SettingsOf(n)); len(d) != 0 {
		t.Fatalf("round trip changed %v", d)
	}
	if n.SettingsVersion != 3 || c.SettingsVersion != 0 {
		t.Fatal("version")
	}
	// Group scope and group rules through the overlay.
	s.Scope.IncludeGroups = []string{"CN=Google Users,OU=Groups,DC=example,DC=com", " "}
	s.Scope.ExcludeGroups = []string{"S-1-5-21-1-2-3-1500"}
	s.Mapping.OrgUnits = append(s.Mapping.OrgUnits, syncapi.OrgUnitRule{Group: "S-1-5-21-1-2-3-1600", Target: "/Finance", Priority: 10})
	s.Mode = "apply"
	n, err = c.Overlay(s, 4)
	if err != nil {
		t.Fatal(err)
	}
	if n.Mode != "apply" || len(n.Source.IncludeGroups) != 1 || len(n.Rules.GroupRules()) != 1 || c.Mode != "dry-run" {
		t.Fatalf("overlay %+v", n.Source)
	}
	out, err := Export(n)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`mode = "apply"`, `include_groups = ["CN=Google Users,OU=Groups,DC=example,DC=com"]`, `priority = 10`, `interval = "15m0s"`} {
		if !strings.Contains(out, want) {
			t.Errorf("export lacks %q:\n%s", want, out)
		}
	}
	// The export is a loadable configuration with the same settings.
	back, err := Load(write(t, out))
	if err != nil {
		t.Fatalf("export does not load: %v\n%s", err, out)
	}
	if d := syncapi.DiffSettings(SettingsOf(n), SettingsOf(back)); len(d) != 0 {
		t.Fatalf("export round trip changed %v", d)
	}
	// Invalid settings are refused with every reason.
	bad := SettingsOf(c)
	bad.Mode = "yolo"
	bad.Scope.UserBases = nil
	bad.Mapping.OrgUnits = []syncapi.OrgUnitRule{{Group: "CN=G,DC=x", Target: "/a"}}
	bad.Limits.MaxTouchedPercent = 250
	bad.Schedule.Interval = "soon"
	_, err = c.Overlay(bad, 5)
	msgs := strings.Join(ErrorList(err), "|")
	for _, want := range []string{"mode", "user_bases", "explicit priority", "max_touched_percent", "schedule.interval"} {
		if !strings.Contains(msgs, want) {
			t.Errorf("missing %q in %s", want, msgs)
		}
	}
}

func TestRequireGroupAlias(t *testing.T) {
	c, err := Load(write(t, strings.Replace(minimal, "user_bases =", "require_group = \"CN=Sync,DC=lab,DC=test\"\nuser_bases =", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := SettingsOf(c).Scope.IncludeGroups; len(got) != 1 || got[0] != "CN=Sync,DC=lab,DC=test" {
		t.Fatalf("alias: %v", got)
	}
}
