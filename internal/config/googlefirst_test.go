package config

import (
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/g2a"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

const googleFirst = `
[google_first]
enabled = true
google_domain = "Example.com"

[[google_first.scopes]]
name = "people"
managed_ou = "OU=People,OU=Google,DC=lab,DC=test"
groups_ou = "OU=Groups,OU=People,OU=Google,DC=lab,DC=test"
quarantine_ou = "OU=Quarantine,OU=People,OU=Google,DC=lab,DC=test"
org_units = ["/Staff"]
sub_org_units = true
member_of = ["Team@example.com"]
fields = ["title", "department"]
`

func TestGoogleFirstLoads(t *testing.T) {
	c, err := Load(write(t, minimal+googleFirst))
	if err != nil {
		t.Fatal(err)
	}
	gf := c.GoogleFirst
	if !gf.Enabled || gf.GoogleDomain != "example.com" || len(gf.Scopes) != 1 || gf.Scopes[0].Mode != syncapi.G2AModeDryRun ||
		gf.Scopes[0].MemberOf[0] != "team@example.com" {
		t.Fatalf("%+v", gf)
	}
	sc := c.G2AScopes()[0]
	if sc.Limits != g2a.DefaultLimits() || sc.LogonTemplate != g2a.DefaultLogonTemplate || len(sc.Fields) != 2 {
		t.Fatalf("defaults %+v", sc)
	}
	// Settings round trip: limits travel explicitly, and the overlay
	// gives back the same section.
	s := SettingsOf(c)
	if s.GoogleFirst == nil || s.GoogleFirst.Scopes[0].Limits == nil || s.GoogleFirst.Scopes[0].Limits.MaxCreates != 20 {
		t.Fatalf("settings %+v", s.GoogleFirst)
	}
	s.GoogleFirst.Scopes[0].Mode = syncapi.G2AModeApply
	s.GoogleFirst.Scopes[0].Limits.MaxDisables = 0
	n, err := c.Overlay(s, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := n.G2AScopes()[0]; got.Mode != syncapi.G2AModeApply || got.Limits.MaxDisables != 0 || got.Limits.MaxCreates != 20 {
		t.Fatalf("overlay %+v", got)
	}
	if c.GoogleFirst.Scopes[0].Mode != syncapi.G2AModeDryRun {
		t.Fatal("the overlay changed the file's configuration")
	}
	// A client that does not send the section keeps the file's.
	s.GoogleFirst = nil
	if n, err = c.Overlay(s, 3); err != nil || !n.GoogleFirst.Enabled || len(n.GoogleFirst.Scopes) != 1 {
		t.Fatalf("%v %+v", err, n.GoogleFirst)
	}
	// Off by default: nothing travels.
	plain, err := Load(write(t, minimal))
	if err != nil || SettingsOf(plain).GoogleFirst != nil {
		t.Fatalf("%v", err)
	}
	if out, err := Export(c); err != nil || !strings.Contains(out, "[google_first]") || !strings.Contains(out, `managed_ou = "OU=People,OU=Google`) {
		t.Fatalf("export: %v\n%s", err, out)
	}
}

func TestGoogleFirstValidation(t *testing.T) {
	cases := []struct {
		name, edit, want string
	}{
		{"groups below managed", `groups_ou = "OU=Groups,DC=lab,DC=test"`, "groups_ou must be below managed_ou"},
		{"quarantine below managed", `quarantine_ou = "OU=Quarantine,DC=lab,DC=test"`, "quarantine_ou must be below managed_ou"},
		{"inside a user base", `managed_ou = "OU=Google,OU=People,DC=lab,DC=test"`, "overlaps source.user_bases"},
		{"containing a user base", `managed_ou = "DC=lab,DC=test"`, "overlaps source.user_bases"},
		{"equal to a group base", `managed_ou = "OU=Groups,DC=lab,DC=test"`, "overlaps source.group_bases"},
		{"a mapping target", `org_units = ["/Sales"]`, "a target of the AD to Google mapping"},
		{"the root with sub", `org_units = ["/"]`, "a target of the AD to Google mapping"},
		{"a bad field", `fields = ["password"]`, `"password" is not one of`},
		{"a bad mode", `mode = "yolo"`, "dry-run or apply"},
		{"a bad template", `logon_template = "{nick}"`, "logon_template"},
		{"a bad limit", "[google_first.scopes.limits]\nmax_creates = -2", "limits.max_creates"},
		{"a bad percent", "[google_first.scopes.limits]\nmax_touched_percent = 120", "max_touched_percent"},
		{"no org unit", `org_units = []`, "at least one Google org unit"},
		{"a bad name", `name = "People!"`, "name"},
	}
	base := `
[google_first]
enabled = true
google_domain = "example.com"
[[google_first.scopes]]
name = "people"
managed_ou = "OU=People,OU=Google,DC=lab,DC=test"
groups_ou = "OU=Groups,OU=People,OU=Google,DC=lab,DC=test"
quarantine_ou = "OU=Quarantine,OU=People,OU=Google,DC=lab,DC=test"
org_units = ["/Staff"]
sub_org_units = true
`
	extra := "group_bases = [\"OU=Groups,DC=lab,DC=test\"]\n[mapping]\nprimary_email = [\"{sAMAccountName}@example.com\"]\nallowed_domains = [\"example.com\"]\norg_units = [{ ad = \"OU=Sales,OU=People,DC=lab,DC=test\", target = \"/Sales\" }]\n"
	src := strings.Replace(minimal, "[mapping]\nprimary_email = [\"{sAMAccountName}@example.com\"]\nallowed_domains = [\"example.com\"]\n", extra, 1)
	if _, err := Load(write(t, src+base)); err != nil {
		t.Fatalf("the base configuration: %v", err)
	}
	for _, c := range cases {
		body := base
		key, _, _ := strings.Cut(c.edit, " ")
		if strings.HasPrefix(c.edit, "[") {
			body += c.edit + "\n"
		} else {
			lines := strings.Split(body, "\n")
			replaced := false
			for i, l := range lines {
				if strings.HasPrefix(l, key+" ") {
					lines[i], replaced = c.edit, true
				}
			}
			if !replaced {
				lines = append(lines, c.edit)
			}
			body = strings.Join(lines, "\n")
		}
		_, err := Load(write(t, src+body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.want)
		}
	}
	// Two scopes: unique names, disjoint managed OUs.
	two := base + `
[[google_first.scopes]]
name = "people"
managed_ou = "OU=Sub,OU=People,OU=Google,DC=lab,DC=test"
groups_ou = "OU=G,OU=Sub,OU=People,OU=Google,DC=lab,DC=test"
quarantine_ou = "OU=Q,OU=Sub,OU=People,OU=Google,DC=lab,DC=test"
org_units = ["/Other"]
`
	_, err := Load(write(t, src+two))
	if err == nil || !strings.Contains(err.Error(), "used twice") || !strings.Contains(err.Error(), "overlaps the managed_ou of scope people") {
		t.Fatalf("two scopes: %v", err)
	}
	// A domain is required once the mode is on.
	if _, err := Load(write(t, src+"[google_first]\nenabled = true\n")); err == nil || !strings.Contains(err.Error(), "google_domain is required") {
		t.Fatalf("domain: %v", err)
	}
}
