package mapping

import (
	"errors"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
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
	u, placement, err := r.User("CN=x,OU=Engineering,OU=People,OU=Lab,DC=x", MapAttrs{"samaccountname": "Zoë", "givenname": "", "displayname": "Zoë Q", "sn": "Q", "title": "CTO"}, nil)
	if err != nil || !strings.HasPrefix(placement, "container ") {
		t.Fatal(err, placement)
	}
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
	if got, _, _ := r.OrgUnitFor("CN=y,OU=Sales,OU=People,OU=Lab,DC=x", nil); got != "/Staff" {
		t.Fatalf("parent mapping %q", got)
	}
	if got, how, _ := r.OrgUnitFor("CN=y,OU=Other,DC=x", nil); got != "/" || how != "default" {
		t.Fatalf("default %q %q", got, how)
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

// groups is a test membership: the set of group keys a user belongs to.
type groups map[string]bool

func (g groups) Member(k string) bool { return g[k] }
func (g groups) GroupName(k string) string {
	return strings.TrimPrefix(strings.TrimPrefix(k, "sid:"), "dn:")
}

func key(t *testing.T, ref string) string {
	t.Helper()
	k, err := GroupKey(ref)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestGroupRules(t *testing.T) {
	const (
		finance  = "CN=Finance,OU=Groups,DC=x"
		managers = "S-1-5-21-1-2-3-1105"
		contract = "cn=contractors,ou=groups,dc=X"
		auditors = "S-1-5-21-1-2-3-1200"
	)
	r, err := Compile(Config{
		PrimaryEmail:   []string{"{sAMAccountName}@example.com"},
		AllowedDomains: []string{"example.com"},
		DefaultOrgUnit: "/Default",
		OrgUnits: []OUConfig{
			{AD: "OU=People,DC=x", Target: "/Staff"},
			{Group: finance, Target: "/Finance", Priority: 20},
			{Group: managers, Target: "/Managers", Priority: 10},
			{Group: contract, Target: "/Contractors", Priority: 20},
			{Group: auditors, Target: "/finance", Priority: 20},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dn := "CN=u,OU=Sales,OU=People,DC=x"
	cases := []struct {
		name      string
		in        []string
		want, how string
		err       bool
	}{
		{"no group: container rule", nil, "/Staff", "container OU=People,DC=x", false},
		{"one group", []string{finance}, "/Finance", "group cn=finance,ou=groups,dc=x (priority 20)", false},
		{"lower priority number wins", []string{finance, managers}, "/Managers", "group S-1-5-21-1-2-3-1105 (priority 10)", false},
		{"same priority, different targets", []string{finance, contract}, "", "", true},
		{"same priority, same target (case-insensitive)", []string{finance, auditors}, "/Finance", "group", false},
		{"DN keys are normalized", []string{"CN=Contractors,OU=Groups,DC=x"}, "/Contractors", "group", false},
	}
	for _, c := range cases {
		m := groups{}
		for _, ref := range c.in {
			m[key(t, ref)] = true
		}
		got, how, err := r.OrgUnitFor(dn, m)
		if c.err {
			if !errors.Is(err, ErrAmbiguousOrgUnit) {
				t.Errorf("%s: err %v, want ambiguous", c.name, err)
			}
			continue
		}
		if err != nil || got != c.want || !strings.HasPrefix(how, c.how) {
			t.Errorf("%s: %q %q %v, want %q %q", c.name, got, how, err, c.want, c.how)
		}
	}
	if got, how, _ := r.OrgUnitFor("CN=u,OU=Elsewhere,DC=x", groups{}); got != "/Default" || how != "default" {
		t.Errorf("default: %q %q", got, how)
	}
	// The user method reports the ambiguity as an error for that user.
	if _, _, err := r.User(dn, MapAttrs{"samaccountname": "u", "sn": "U"}, groups{key(t, finance): true, key(t, contract): true}); !errors.Is(err, ErrAmbiguousOrgUnit) {
		t.Errorf("User: %v", err)
	}
	if rules := r.GroupRules(); len(rules) != 4 || rules[0].Priority != 10 {
		t.Errorf("GroupRules order: %+v", rules)
	}
}

func TestGroupRuleErrors(t *testing.T) {
	_, err := Compile(Config{PrimaryEmail: []string{"{a}@example.com"}, AllowedDomains: []string{"example.com"},
		OrgUnits: []OUConfig{
			{Group: "CN=G,DC=x", Target: "/a"},                  // no priority
			{Group: "S-1-bogus", Target: "/a", Priority: 1},     // bad SID
			{AD: "OU=a,DC=x", Group: "CN=G,DC=x", Target: "/a"}, // both
			{AD: "OU=b,DC=x", Target: "/b", Priority: 3},        // priority on a container rule
			{Group: "CN=H,DC=x", Target: "/h", Priority: 1},     // fine
			{Group: "cn=h,dc=X", Target: "/other", Priority: 2}, // same group twice
		}})
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"explicit priority", "invalid SID", "not both", "group rules only", "more than one rule"} {
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
