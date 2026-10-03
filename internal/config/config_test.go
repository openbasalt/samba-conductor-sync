package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samba-conductor/conductor-sync/internal/model"
	"github.com/samba-conductor/conductor-sync/internal/plan"
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
