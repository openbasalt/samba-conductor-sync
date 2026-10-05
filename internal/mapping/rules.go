package mapping

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
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

// OUConfig is one org unit placement rule: either an AD container (AD, and
// everything below it) or an AD group (Group, a DN or a SID; nested
// membership counts) mapped to a target org unit path. Group rules carry an
// explicit Priority (1 is evaluated first). Resolution order: group rules
// by priority, then the most specific container rule, then
// default_org_unit. A user matching group rules of the same (best)
// priority that point at different org units is a plan error for that
// user, never a silent pick.
type OUConfig struct {
	AD       string `toml:"ad,omitempty"`
	Group    string `toml:"group,omitempty"`
	Target   string `toml:"target"`
	Priority int    `toml:"priority,omitempty"`
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
	src  string // as configured
	path string
}

// groupRule places members of a group.
type groupRule struct {
	ref      string // as configured (DN or SID)
	key      string // GroupKey(ref)
	path     string
	priority int
}

// GroupRule is a compiled group placement rule (for scope reports).
type GroupRule struct {
	Ref      string
	Key      string
	Target   string
	Priority int
}

// Membership answers group questions about one source user.
type Membership interface {
	// Member reports whether the user is a (nested) member of the group
	// with this key (GroupKey).
	Member(key string) bool
	// GroupName is the display name of a group key (its cn, or the
	// configured reference when unknown).
	GroupName(key string) string
}

// NoGroups is the membership of a user when no group is referenced.
type NoGroups struct{}

// Member implements Membership.
func (NoGroups) Member(string) bool { return false }

// GroupName implements Membership.
func (NoGroups) GroupName(k string) string { return k }

// ErrAmbiguousOrgUnit is a user matching group rules of the same priority
// that point at different org units.
var ErrAmbiguousOrgUnit = errors.New("ambiguous org unit")

// GroupKey normalizes a group reference: "sid:S-1-5-..." for a SID (which
// survives renames and moves), "dn:<normalized DN>" for a DN.
func GroupKey(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if len(ref) > 4 && strings.EqualFold(ref[:4], "S-1-") {
		s, err := sid.Parse(strings.ToUpper(ref))
		if err != nil {
			return "", fmt.Errorf("invalid SID %q", ref)
		}
		return "sid:" + s.String(), nil
	}
	dn, err := ldap.ParseDN(ref)
	if err != nil || len(dn.RDNs) == 0 {
		return "", fmt.Errorf("invalid group reference %q (a DN or a SID)", ref)
	}
	return "dn:" + escape.NormalizeDN(ref), nil
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
	groupRules       []groupRule
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
	seenGroup := map[string]groupRule{}
	for _, o := range c.OrgUnits {
		switch {
		case o.AD != "" && o.Group != "":
			errs = append(errs, fmt.Errorf("mapping.org_units: a rule has either ad or group, not both (%s, %s)", o.AD, o.Group))
			continue
		case o.Group != "":
			key, err := GroupKey(o.Group)
			if err != nil {
				errs = append(errs, fmt.Errorf("mapping.org_units: %w", err))
				continue
			}
			if o.Priority < 1 {
				errs = append(errs, fmt.Errorf("mapping.org_units (group %s): an explicit priority >= 1 is required (1 is evaluated first)", o.Group))
				continue
			}
			if err := validOrgUnit(o.Target); err != nil {
				errs = append(errs, fmt.Errorf("mapping.org_units (group %s): %w", o.Group, err))
				continue
			}
			if prev, dup := seenGroup[key]; dup {
				errs = append(errs, fmt.Errorf("mapping.org_units: group %s has more than one rule (targets %s and %s)", o.Group, prev.path, o.Target))
				continue
			}
			g := groupRule{ref: strings.TrimSpace(o.Group), key: key, path: o.Target, priority: o.Priority}
			seenGroup[key] = g
			r.groupRules = append(r.groupRules, g)
		default:
			dn, err := ldap.ParseDN(o.AD)
			if err != nil || len(dn.RDNs) == 0 {
				errs = append(errs, fmt.Errorf("mapping.org_units: invalid DN %q", o.AD))
				continue
			}
			if o.Priority != 0 {
				errs = append(errs, fmt.Errorf("mapping.org_units (%s): priority applies to group rules only (container rules: the most specific wins)", o.AD))
				continue
			}
			if err := validOrgUnit(o.Target); err != nil {
				errs = append(errs, fmt.Errorf("mapping.org_units (%s): %w", o.AD, err))
				continue
			}
			r.ous = append(r.ous, ouRule{dn: dn, src: strings.TrimSpace(o.AD), path: o.Target})
		}
	}
	// Most specific (longest DN) first.
	sort.SliceStable(r.ous, func(i, j int) bool { return len(r.ous[i].dn.RDNs) > len(r.ous[j].dn.RDNs) })
	// Group rules by priority (1 first), declaration order within one.
	sort.SliceStable(r.groupRules, func(i, j int) bool { return r.groupRules[i].priority < r.groupRules[j].priority })
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

// GroupRules lists the compiled group placement rules, by priority.
func (r *Rules) GroupRules() []GroupRule {
	out := make([]GroupRule, len(r.groupRules))
	for i, g := range r.groupRules {
		out[i] = GroupRule{Ref: g.ref, Key: g.key, Target: g.path, Priority: g.priority}
	}
	return out
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

// User maps a source user (its DN, attributes and group memberships) to
// target attributes. placement says which rule chose the org unit. An
// ErrAmbiguousOrgUnit comes with the other attributes rendered.
func (r *Rules) User(dn string, a Attrs, m Membership) (attrs model.UserAttrs, placement string, err error) {
	if m == nil {
		m = NoGroups{}
	}
	out, err := r.userAttrs(a)
	if err != nil {
		return nil, "", err
	}
	ou, placement, err := r.OrgUnitFor(dn, m)
	if err != nil {
		// The rendered attributes (address, names) are still returned so
		// the plan can name the user it reports.
		return out, "", err
	}
	out[model.FieldOrgUnit] = ou
	return out, placement, nil
}

func (r *Rules) userAttrs(a Attrs) (model.UserAttrs, error) {
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
	for f, t := range r.attributes {
		out[f] = clipRunes(t.RenderOptional(a), 256)
	}
	return out, nil
}

// FallbackFields reports which name fields a user's attributes render
// through a fallback template (any template after the first of the list):
// with the default lists, a given name taken from displayName or
// sAMAccountName because givenName is empty. The plan never writes such a
// value over an adopted account's name under the default policy.
func (r *Rules) FallbackFields(a Attrs) map[model.UserField]bool {
	out := map[model.UserField]bool{}
	if _, i, err := r.givenName.RenderIndex(a, nil); err == nil && i > 0 {
		out[model.FieldGivenName] = true
	}
	if _, i, err := r.familyName.RenderIndex(a, nil); err == nil && i > 0 {
		out[model.FieldFamilyName] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// OrgUnitFor returns the target org unit for a user at dn with the given
// memberships, and which rule chose it: group rules by priority (the best
// matching priority wins; two matches of that priority with different
// targets are ErrAmbiguousOrgUnit), then the most specific mapped AD
// container that holds it, then the default.
func (r *Rules) OrgUnitFor(dn string, m Membership) (path, placement string, err error) {
	if m == nil {
		m = NoGroups{}
	}
	best := 0
	var hits []groupRule
	for _, g := range r.groupRules {
		if best != 0 && g.priority != best {
			break
		}
		if m.Member(g.key) {
			best = g.priority
			hits = append(hits, g)
		}
	}
	if len(hits) > 0 {
		for _, h := range hits[1:] {
			if !strings.EqualFold(h.path, hits[0].path) {
				var names []string
				for _, x := range hits {
					names = append(names, fmt.Sprintf("%s -> %s", m.GroupName(x.key), x.path))
				}
				return "", "", fmt.Errorf("%w: member of groups with the same priority %d and different org units (%s)",
					ErrAmbiguousOrgUnit, best, strings.Join(names, "; "))
			}
		}
		return hits[0].path, fmt.Sprintf("group %s (priority %d)", m.GroupName(hits[0].key), best), nil
	}
	parsed, err := ldap.ParseDN(dn)
	if err == nil {
		for _, o := range r.ous {
			if o.dn.AncestorOfFold(parsed) {
				return o.path, "container " + o.src, nil
			}
		}
	}
	return r.defaultOU, "default", nil
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
