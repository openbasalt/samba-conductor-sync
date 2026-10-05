package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCLIUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"version"}, nil, &out, &errb); rc != exitOK || !strings.Contains(out.String(), "conductor-sync") {
		t.Fatalf("version: %d %q", rc, out.String())
	}
	if rc := run(nil, nil, &out, &errb); rc != exitUsage {
		t.Fatalf("no args: %d", rc)
	}
	if rc := run([]string{"frobnicate"}, nil, &out, &errb); rc != exitUsage {
		t.Fatalf("unknown command: %d", rc)
	}
	errb.Reset()
	if rc := run([]string{"plan", "--config", "/nonexistent.toml"}, nil, &out, &errb); rc != exitError || !strings.Contains(errb.String(), "nonexistent") {
		t.Fatalf("missing config: %d %q", rc, errb.String())
	}
	if rc := run([]string{"apply", "--bogus"}, nil, &out, &errb); rc != exitUsage {
		t.Fatalf("bad flag: %d", rc)
	}
	var f importFlags
	fs := flag.NewFlagSet("import-plan", flag.ContinueOnError)
	f.register(fs)
	if err := fs.Parse([]string{"--org-unit", "/Sales", "--org-unit", "/IT", "--sub-org-units", "--groups", "--group", "a@example.com", "--max-users", "10"}); err != nil {
		t.Fatal(err)
	}
	p := f.params()
	if strings.Join(p.OrgUnits, ",") != "/Sales,/IT" || !p.SubOrgUnits || !p.Groups || len(p.GroupEmails) != 1 || p.MaxUsers != 10 || p.Validate() != nil {
		t.Fatalf("import-plan flags: %+v", p)
	}
}

func TestCLISecret(t *testing.T) {
	dir := t.TempDir()
	creds := filepath.Join(dir, "creds")
	if err := os.MkdirAll(creds, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(creds, "state-key"), bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "c.toml")
	body := `state_dir = "` + dir + `/state"
credentials_dir = "` + creds + `"
[source]
realm = "LAB.TEST"
ca_file = "/ca.pem"
bind_user = "svc"
user_bases = ["OU=People,DC=lab,DC=test"]
[mapping]
primary_email = ["{sAMAccountName}@example.com"]
allowed_domains = ["example.com"]
[google]
admin_subject = "admin@example.com"
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	const value = "a-webhook-secret-of-some-length"
	var out, errb bytes.Buffer
	if rc := run([]string{"secret", "set", "alert-webhook-secret", "--config", cfg}, strings.NewReader(value+"\n"), &out, &errb); rc != exitOK {
		t.Fatalf("set: %d %s", rc, errb.String())
	}
	out.Reset()
	if rc := run([]string{"secret", "status", "--config", cfg}, nil, &out, &errb); rc != exitOK ||
		!regexp.MustCompile(`alert_webhook_secret +configured +database`).MatchString(out.String()) || strings.Contains(out.String(), value) {
		t.Fatalf("status: %d\n%s", rc, out.String())
	}
	if rc := run([]string{"secret", "set", "google-key", "--config", cfg}, strings.NewReader("x\n"), &out, &errb); rc != exitUsage {
		t.Fatalf("google key through secret set: %d", rc)
	}
	if rc := run([]string{"secret", "remove", "alert-webhook-secret", "--config", cfg}, nil, &out, &errb); rc != exitOK {
		t.Fatalf("remove: %d", rc)
	}
	out.Reset()
	if rc := run([]string{"audit", "export", "--config", cfg}, nil, &out, &errb); rc != exitOK || strings.Contains(out.String(), value) ||
		!strings.Contains(out.String(), "secret alert_webhook_secret: removed") {
		t.Fatalf("audit: %d\n%s", rc, out.String())
	}
}
