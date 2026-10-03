package mapping

import (
	"errors"
	"strings"
	"testing"

	"github.com/samba-conductor/conductor-sync/internal/model"
)

func TestTemplate(t *testing.T) {
	a := MapAttrs{"samaccountname": "José.Silva", "userprincipalname": "jsilva@corp.local", "mail": "", "cn": "Sales Team (BR)"}
	cases := []struct{ tpl, want, err string }{
		{"{sAMAccountName|ascii|lower}@example.com", "jose.silva@example.com", ""},
		{"{userPrincipalName|localpart}@example.com", "jsilva@example.com", ""},
		{"{userPrincipalName|domain}", "corp.local", ""},
		{"{cn|slug}@groups.example.com", "sales-team-br@groups.example.com", ""},
		{"{mail}", "", "attribute empty"},
		{"plain", "plain", ""},
		{"{sAMAccountName|nope}", "", "unknown filter"},
		{"{bad attr}", "", "invalid attribute"},
		{"{unterminated", "", "unterminated"},
		{"x}", "", "unmatched"},
	}
	for _, c := range cases {
		tp, err := ParseTemplate(c.tpl)
		if err == nil {
			var v string
			v, err = tp.Render(a)
			if err == nil && v != c.want {
				t.Errorf("%s: got %q want %q", c.tpl, v, c.want)
			}
		}
		if (err != nil) != (c.err != "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: err %v, want %q", c.tpl, err, c.err)
		}
	}
}

func TestChainFallbackAndValidation(t *testing.T) {
	ch, err := ParseChain([]string{"{mail|lower}", "{sAMAccountName|lower}@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	valid := func(v string) error { return ValidateEmail(v, []string{"example.com"}) }
	v, err := ch.Render(MapAttrs{"mail": "Someone@Other.org", "samaccountname": "Bob"}, valid)
	if err != nil || v != "bob@example.com" {
		t.Fatalf("fallback past a foreign domain: %q %v", v, err)
	}
	if _, err := ch.Render(MapAttrs{}, valid); err == nil || !errors.Is(err, ErrMissing) {
		t.Fatalf("no value: %v", err)
	}
}

func TestValidateEmail(t *testing.T) {
	ok := []string{"a@example.com", "a.b-c_d+e@EXAMPLE.com", "o'neil@example.com"}
	bad := []string{"a@evil.com", "a@@example.com", ".a@example.com", "a..b@example.com", "a b@example.com", "ação@example.com", "@example.com", "noat"}
	for _, s := range ok {
		if err := ValidateEmail(s, []string{"example.com"}); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range bad {
		if err := ValidateEmail(s, []string{"example.com"}); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestRules(t *testing.T) {
	r, err := Compile(Config{
		PrimaryEmail:   []string{"{sAMAccountName|ascii|lower}@example.com"},
		AllowedDomains: []string{"example.com"},
		Attributes:     map[string]string{"title": "{title}", "phone_work": "{telephoneNumber}"},
		OrgUnits: []OUConfig{
			{AD: "OU=People,OU=Lab,DC=x", Target: "/Staff"},
			{AD: "ou=engineering,OU=People,OU=Lab,DC=x", Target: "/Staff/Engineering"},
		},
		GroupEmail:          []string{"{mail}", "{sAMAccountName|slug}@groups.example.com"},
		GroupAllowedDomains: []string{"groups.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := r.User("CN=x,OU=Engineering,OU=People,OU=Lab,DC=x", MapAttrs{"samaccountname": "Zoë", "givenname": "", "displayname": "Zoë Q", "sn": "Q", "title": "CTO"})
	if err != nil {
		t.Fatal(err)
	}
	if u[model.FieldPrimaryEmail] != "zoe@example.com" || u[model.FieldGivenName] != "Zoë Q" || u[model.FieldOrgUnit] != "/Staff/Engineering" ||
		u[model.FieldTitle] != "CTO" || u[model.FieldPhoneWork] != "" {
		t.Fatalf("user %v", u)
	}
	if _, ok := u[model.FieldDepartment]; ok {
		t.Fatal("unmapped field present")
	}
	if got := r.OrgUnitFor("CN=y,OU=Sales,OU=People,OU=Lab,DC=x"); got != "/Staff" {
		t.Fatalf("parent mapping %q", got)
	}
	if got := r.OrgUnitFor("CN=y,OU=Other,DC=x"); got != "/" {
		t.Fatalf("default %q", got)
	}
	email, name, _, err := r.Group(MapAttrs{"samaccountname": "Big Group", "cn": "Big Group"})
	if err != nil || email != "big-group@groups.example.com" || name != "Big Group" {
		t.Fatalf("group %q %q %v", email, name, err)
	}
	if !r.Optional()[model.FieldTitle] || r.Optional()[model.FieldDepartment] {
		t.Fatal("optional fields")
	}
	attrs := strings.Join(r.UserAttributes(), ",")
	for _, a := range []string{"sAMAccountName", "title", "telephoneNumber", "givenName", "sn"} {
		if !strings.Contains(attrs, a) {
			t.Errorf("UserAttributes lacks %s: %s", a, attrs)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	_, err := Compile(Config{PrimaryEmail: []string{"{x|bogus}"}, Attributes: map[string]string{"shoe_size": "{x}"},
		OrgUnits: []OUConfig{{AD: "not a dn", Target: "/x"}, {AD: "OU=a,DC=x", Target: "relative"}}, DefaultOrgUnit: "nope"})
	if err == nil {
		t.Fatal("bad config accepted")
	}
	for _, want := range []string{"unknown filter", "allowed_domains", "shoe_size", "invalid DN", "must start with /"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

func FuzzTemplate(f *testing.F) {
	for _, s := range []string{"{a}", "{a|lower}@x", "x{", "}{", "{a|slug|ascii}", ""} {
		f.Add(s, "Valué")
	}
	f.Fuzz(func(t *testing.T, tpl, val string) {
		tp, err := ParseTemplate(tpl)
		if err != nil {
			return
		}
		attrs := MapAttrs{}
		for _, a := range tp.Attributes() {
			attrs[strings.ToLower(a)] = val
		}
		_, _ = tp.Render(attrs)
		_ = Slug(val)
		_ = FoldASCII(val)
	})
}
