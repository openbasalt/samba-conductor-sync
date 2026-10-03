package adsource

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
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
