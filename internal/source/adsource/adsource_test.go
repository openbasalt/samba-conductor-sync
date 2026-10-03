package adsource

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/conductor-sync/internal/model"
)

func TestDNKey(t *testing.T) {
	a := DNKey(`CN=Escape\, Test #1,OU=Special,OU=Lab,DC=lab,DC=conductor,DC=test`)
	b := DNKey(`cn=escape\2C test #1, ou=special,ou=LAB,dc=Lab,dc=conductor,dc=test`)
	if a != b {
		t.Fatalf("%q != %q", a, b)
	}
	if DNKey("CN=a,DC=x") == DNKey("CN=b,DC=x") {
		t.Fatal("different DNs collide")
	}
}

func TestEntryAttrs(t *testing.T) {
	e := ldap.NewEntry("CN=a,DC=x", map[string][]string{"sAMAccountName": {"alice"}, "mail": {}})
	a := entryAttrs{e}
	if a.Get("samaccountname") != "alice" || a.Get("mail") != "" || a.Get("dn") != "CN=a,DC=x" {
		t.Fatal("lookup")
	}
}

func TestValidate(t *testing.T) {
	c := Config{Auth: "ntlm", UserBases: []string{"not a dn"}}
	err := c.Validate()
	for _, want := range []string{"realm", "ca_file", "bind_user", "auth", "invalid DN"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestExcluded(t *testing.T) {
	r := &Reader{cfg: Config{ExcludeBases: []string{"OU=Service,OU=People,DC=x"}}}
	if !r.excluded("CN=svc,OU=service,OU=People,DC=x") || r.excluded("CN=a,OU=People,DC=x") || !r.excluded("garbage") {
		t.Fatal("exclusion")
	}
}

func TestScopeDecision(t *testing.T) {
	inc := &refGroup{key: "sid:S-1-5-21-1-2-3-1500", ref: "S-1-5-21-1-2-3-1500", found: true, name: "Google Users",
		members: map[string]bool{"a": true, "b": true, "c": true}}
	inc2 := &refGroup{key: "dn:cn=contractors,dc=x", ref: "CN=Contractors,DC=x", found: true, name: "Contractors",
		members: map[string]bool{"d": true}}
	exc := &refGroup{key: "sid:S-1-5-21-1-2-3-1600", ref: "S-1-5-21-1-2-3-1600", found: true, name: "Leavers",
		members: map[string]bool{"b": true, "d": true, "e": true}}
	g := &scopeGroups{byKey: map[string]*refGroup{inc.key: inc, inc2.key: inc2, exc.key: exc},
		include: []*refGroup{inc, inc2}, exclude: []*refGroup{exc}}
	cases := map[string]string{"a": "", "b": "exclude", "c": "", "d": "exclude", "e": "not a member", "f": "not a member"}
	for guid, want := range cases {
		in, reason := g.decide(guid)
		if (want == "") != in || !strings.Contains(reason, want) {
			t.Errorf("%s: in=%v reason=%q, want %q", guid, in, reason, want)
		}
	}
	// No include group: everyone below the bases, minus exclusions.
	g.include = nil
	if in, _ := g.decide("f"); !in {
		t.Error("no include group must not filter")
	}
	if in, reason := g.decide("e"); in || !strings.Contains(reason, "Leavers") {
		t.Errorf("exclusion reason %q", reason)
	}
	m := membership{g: g, guid: "d"}
	if !m.Member(inc2.key) || m.Member(inc.key) || m.GroupName(inc2.key) != "Contractors" || m.GroupName("dn:unknown") != "dn:unknown" {
		t.Error("membership")
	}
	g.report = []model.ScopeGroup{{Role: model.RoleInclude, Ref: "CN=Gone,DC=x", Found: false}, {Role: model.RoleExclude, Ref: "x", Found: true}}
	if miss := g.missing(); len(miss) != 1 || !strings.Contains(miss[0], "CN=Gone") {
		t.Errorf("missing %v", miss)
	}
}

func TestScopeValidation(t *testing.T) {
	c := Config{Realm: "R", CAFile: "/ca", BindUser: "u", PasswordCredential: "p", UserBases: []string{"OU=P,DC=x"},
		IncludeGroups: []string{"S-1-5-21-1-2-3-1500", "not a group"}, ExcludeGroups: []string{"s-1-5-21-1-2-3-1500"},
		RequireGroup: "CN=Old,DC=x"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "not a group") || !strings.Contains(err.Error(), "both included and excluded") {
		t.Fatalf("validate: %v", err)
	}
	if inc := c.Includes(); len(inc) != 3 || inc[2] != "CN=Old,DC=x" {
		t.Fatalf("require_group alias: %v", inc)
	}
	c.RequireGroup = "cn=OLD,dc=x"
	c.IncludeGroups = []string{"CN=Old,DC=x"}
	if inc := c.Includes(); len(inc) != 1 {
		t.Fatalf("alias duplicates an include group: %v", inc)
	}
}
