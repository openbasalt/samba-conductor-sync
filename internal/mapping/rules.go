package mapping

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/conductor-sync/internal/model"
)

// Config is the [mapping] section of the configuration.
type Config struct {
	// PrimaryEmail is tried in order; the first template that renders an
	// address in AllowedDomains wins.
	PrimaryEmail   []string `toml:"primary_email"`
	AllowedDomains []string `toml:"allowed_domains"`
	GivenName      []string `toml:"given_name"`
	FamilyName     []string `toml:"family_name"`
	// Attributes maps optional target fields (title, department,
	// employee_id, phone_work, phone_mobile) to one template each. Only
	// fields listed here are managed.
	Attributes     map[string]string `toml:"attributes"`
	DefaultOrgUnit string            `toml:"default_org_unit"`
	OrgUnits       []OUConfig        `toml:"org_units"`

	GroupEmail          []string `toml:"group_email"`
	GroupName           []string `toml:"group_name"`
	GroupDescription    []string `toml:"group_description"`
	GroupAllowedDomains []string `toml:"group_allowed_domains"`
}

// OUConfig maps an AD container (and everything below it) to a target org
// unit path. The most specific match wins.
type OUConfig struct {
	AD     string `toml:"ad"`
	Target string `toml:"target"`
}

// Defaults fills unset fields.
func (c *Config) Defaults() {
	if len(c.GivenName) == 0 {
		c.GivenName = []string{"{givenName}", "{displayName}", "{sAMAccountName}"}
	}
	if len(c.FamilyName) == 0 {
		c.FamilyName = []string{"{sn}", "{sAMAccountName}"}
	}
	if c.DefaultOrgUnit == "" {
		c.DefaultOrgUnit = "/"
	}
	if len(c.GroupName) == 0 {
		c.GroupName = []string{"{cn}"}
	}
	if len(c.GroupDescription) == 0 {
		c.GroupDescription = []string{"{description}"}
	}
	if len(c.GroupAllowedDomains) == 0 {
		c.GroupAllowedDomains = c.AllowedDomains
	}
}

type ouRule struct {
	dn   *ldap.DN
	path string
}

// Rules is a compiled mapping.
type Rules struct {
	primaryEmail     Chain
	allowed          []string
	givenName        Chain
	familyName       Chain
	attributes       map[model.UserField]Template
	defaultOU        string
	ous              []ouRule
	groupEmail       Chain
	groupName        Chain
	groupDescription Chain
	groupAllowed     []string
}

var optionalByName = func() map[string]model.UserField {
	m := map[string]model.UserField{}
	for _, f := range model.OptionalUserFields {
		m[string(f)] = f
	}
	return m
}()

// Compile validates and compiles a mapping configuration.
func Compile(c Config) (*Rules, error) {
	c.Defaults()
	var errs []error
	r := &Rules{allowed: c.AllowedDomains, defaultOU: c.DefaultOrgUnit, groupAllowed: c.GroupAllowedDomains,
		attributes: map[model.UserField]Template{}}
	chain := func(name string, srcs []string, required bool) Chain {
		if required && len(srcs) == 0 {
			errs = append(errs, fmt.Errorf("mapping.%s: at least one template is required", name))
			return nil
		}
		ch, err := ParseChain(srcs)
		if err != nil {
			errs = append(errs, fmt.Errorf("mapping.%s: %w", name, err))
		}
		return ch
	}
	r.primaryEmail = chain("primary_email", c.PrimaryEmail, true)
	r.givenName = chain("given_name", c.GivenName, true)
	r.familyName = chain("family_name", c.FamilyName, true)
	r.groupEmail = chain("group_email", c.GroupEmail, false)
	r.groupName = chain("group_name", c.GroupName, true)
	r.groupDescription = chain("group_description", c.GroupDescription, false)
	if len(c.AllowedDomains) == 0 {
		errs = append(errs, errors.New("mapping.allowed_domains: at least one domain is required"))
	}
	for name, src := range c.Attributes {
		f, ok := optionalByName[name]
		if !ok {
			errs = append(errs, fmt.Errorf("mapping.attributes: unknown target field %q", name))
			continue
		}
		t, err := ParseTemplate(src)
		if err != nil {
			errs = append(errs, fmt.Errorf("mapping.attributes.%s: %w", name, err))
			continue
		}
		r.attributes[f] = t
	}
	if err := validOrgUnit(c.DefaultOrgUnit); err != nil {
		errs = append(errs, fmt.Errorf("mapping.default_org_unit: %w", err))
	}
	for _, o := range c.OrgUnits {
		dn, err := ldap.ParseDN(o.AD)
		if err != nil || len(dn.RDNs) == 0 {
			errs = append(errs, fmt.Errorf("mapping.org_units: invalid DN %q", o.AD))
			continue
		}
		if err := validOrgUnit(o.Target); err != nil {
			errs = append(errs, fmt.Errorf("mapping.org_units (%s): %w", o.AD, err))
			continue
		}
		r.ous = append(r.ous, ouRule{dn: dn, path: o.Target})
	}
	// Most specific (longest DN) first.
	sort.SliceStable(r.ous, func(i, j int) bool { return len(r.ous[i].dn.RDNs) > len(r.ous[j].dn.RDNs) })
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return r, nil
}

func validOrgUnit(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("org unit path %q must start with /", p)
	}
	if strings.ContainsAny(p, "\x00\r\n") || strings.Contains(p, "//") {
		return fmt.Errorf("org unit path %q is invalid", p)
	}
	return nil
}

// ManagesGroups reports whether group addresses are mapped (groups are
// synced only then).
func (r *Rules) ManagesGroups() bool { return len(r.groupEmail) > 0 }

// Optional returns the mapped optional fields.
func (r *Rules) Optional() map[model.UserField]bool {
	out := map[model.UserField]bool{}
	for f := range r.attributes {
		out[f] = true
	}
	return out
}

// UserAttributes lists the LDAP attributes the user templates read.
func (r *Rules) UserAttributes() []string {
	var out []string
	out = append(out, r.primaryEmail.Attributes()...)
	out = append(out, r.givenName.Attributes()...)
	out = append(out, r.familyName.Attributes()...)
	for _, t := range r.attributes {
		out = append(out, t.Attributes()...)
	}
	return dedupFold(out)
}

// GroupAttributes lists the LDAP attributes the group templates read.
func (r *Rules) GroupAttributes() []string {
	var out []string
	out = append(out, r.groupEmail.Attributes()...)
	out = append(out, r.groupName.Attributes()...)
	out = append(out, r.groupDescription.Attributes()...)
	return dedupFold(out)
}

func dedupFold(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := strings.ToLower(s)
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// maxNameLen is Google's limit for given and family names.
const maxNameLen = 60

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n]))
}

// User maps a source user (its DN and attributes) to target attributes.
func (r *Rules) User(dn string, a Attrs) (model.UserAttrs, error) {
	out := model.UserAttrs{}
	email, err := r.primaryEmail.Render(a, func(v string) error { return ValidateEmail(v, r.allowed) })
	if err != nil {
		return nil, fmt.Errorf("primary_email: %w", err)
	}
	out[model.FieldPrimaryEmail] = model.NormalizeEmail(email)
	gn, err := r.givenName.Render(a, nil)
	if err != nil {
		return nil, fmt.Errorf("given_name: %w", err)
	}
	fn, err := r.familyName.Render(a, nil)
	if err != nil {
		return nil, fmt.Errorf("family_name: %w", err)
	}
	out[model.FieldGivenName] = clipRunes(gn, maxNameLen)
	out[model.FieldFamilyName] = clipRunes(fn, maxNameLen)
	out[model.FieldOrgUnit] = r.OrgUnitFor(dn)
	for f, t := range r.attributes {
		out[f] = clipRunes(t.RenderOptional(a), 256)
	}
	return out, nil
}

// OrgUnitFor returns the target org unit for an object at dn: the most
// specific mapped AD container that holds it, else the default.
func (r *Rules) OrgUnitFor(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return r.defaultOU
	}
	for _, o := range r.ous {
		if o.dn.AncestorOfFold(parsed) {
			return o.path
		}
	}
	return r.defaultOU
}

// Group maps a source group to its target address, name and description.
func (r *Rules) Group(a Attrs) (email, name, description string, err error) {
	if !r.ManagesGroups() {
		return "", "", "", errors.New("mapping: group_email is not configured")
	}
	email, err = r.groupEmail.Render(a, func(v string) error { return ValidateEmail(v, r.groupAllowed) })
	if err != nil {
		return "", "", "", fmt.Errorf("group_email: %w", err)
	}
	name, err = r.groupName.Render(a, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("group_name: %w", err)
	}
	description, _ = r.groupDescription.Render(a, nil)
	return model.NormalizeEmail(email), clipRunes(name, 75), clipRunes(description, 4096), nil
}
