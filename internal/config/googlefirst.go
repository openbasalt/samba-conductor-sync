package config

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-sync/internal/g2a"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// GoogleFirst is the [google_first] section: the Google-first mode, where
// Google Workspace is the source of truth for the people of each scope and
// AD follows (conductor-sync only plans; conductor applies). Off by
// default.
type GoogleFirst struct {
	Enabled bool `toml:"enabled"`
	// GoogleDomain is the Google Workspace domain whose accounts the mode
	// manages.
	GoogleDomain string     `toml:"google_domain,omitempty"`
	Scopes       []G2AScope `toml:"scopes,omitempty"`
}

// G2AScope is one [[google_first.scopes]] entry.
type G2AScope struct {
	Name          string   `toml:"name"`
	Mode          string   `toml:"mode"`
	ManagedOU     string   `toml:"managed_ou"`
	GroupsOU      string   `toml:"groups_ou"`
	QuarantineOU  string   `toml:"quarantine_ou"`
	OrgUnits      []string `toml:"org_units"`
	SubOrgUnits   bool     `toml:"sub_org_units"`
	MemberOf      []string `toml:"member_of"`
	Fields        []string `toml:"fields"`
	LogonTemplate string   `toml:"logon_template,omitempty"`
	// Limits nil means g2a.DefaultLimits. A table given replaces the
	// defaults: a key left out is 0 (none allowed).
	Limits *g2a.Limits `toml:"limits,omitempty"`
}

var (
	domainRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}\.)+[a-z0-9-]{1,63}$`)
	ouPathRE  = regexp.MustCompile(`^/[^\x00-\x1f]{0,511}$`)
	addressRE = regexp.MustCompile(`^[^@\s\x00-\x1f]{1,64}@[A-Za-z0-9.-]{1,253}$`)
)

// maxG2AScopes bounds the number of scopes.
const maxG2AScopes = 50

// validateGoogleFirst normalizes and checks the section against the rest
// of the configuration (the AD-to-Google scope and mapping): the two
// directions never share an OU tree or a Google org unit.
func (c *Config) validateGoogleFirst() []error {
	gf := &c.GoogleFirst
	var errs []error
	gf.GoogleDomain = strings.ToLower(strings.TrimSpace(gf.GoogleDomain))
	if gf.GoogleDomain != "" && (!domainRE.MatchString(gf.GoogleDomain) || len(gf.GoogleDomain) > 253) {
		errs = append(errs, fmt.Errorf("google_first.google_domain %q: a DNS domain name", gf.GoogleDomain))
	}
	if (gf.Enabled || len(gf.Scopes) > 0) && gf.GoogleDomain == "" {
		errs = append(errs, errors.New("google_first.google_domain is required with scopes or when enabled"))
	}
	if len(gf.Scopes) > maxG2AScopes {
		errs = append(errs, fmt.Errorf("google_first.scopes: at most %d", maxG2AScopes))
	}
	targets := []string{c.Mapping.DefaultOrgUnit}
	if targets[0] == "" {
		targets[0] = "/"
	}
	for _, o := range c.Mapping.OrgUnits {
		targets = append(targets, o.Target)
	}
	names := map[string]bool{}
	type managed struct {
		name string
		dn   *ldap.DN
	}
	var managedOUs []managed
	for i := range gf.Scopes {
		s := &gf.Scopes[i]
		s.Name = strings.TrimSpace(s.Name)
		p := fmt.Sprintf("google_first.scopes[%s]", s.Name)
		if !syncapi.ValidG2AScopeName(s.Name) {
			p = fmt.Sprintf("google_first.scopes[%d]", i)
			errs = append(errs, fmt.Errorf("%s.name %q: 1-32 lower-case letters, digits, '-' or '_'", p, s.Name))
		}
		if names[s.Name] {
			errs = append(errs, fmt.Errorf("%s: the scope name is used twice", p))
		}
		names[s.Name] = true
		s.Mode = strings.TrimSpace(s.Mode)
		if s.Mode == "" {
			s.Mode = syncapi.G2AModeDryRun
		}
		if s.Mode != syncapi.G2AModeDryRun && s.Mode != syncapi.G2AModeApply {
			errs = append(errs, fmt.Errorf("%s.mode %q: dry-run or apply", p, s.Mode))
		}
		s.ManagedOU, s.GroupsOU, s.QuarantineOU = strings.TrimSpace(s.ManagedOU), strings.TrimSpace(s.GroupsOU), strings.TrimSpace(s.QuarantineOU)
		mdn := parseOU(s.ManagedOU, p+".managed_ou", &errs)
		gdn := parseOU(s.GroupsOU, p+".groups_ou", &errs)
		qdn := parseOU(s.QuarantineOU, p+".quarantine_ou", &errs)
		if mdn != nil {
			for _, sub := range []struct {
				key string
				dn  *ldap.DN
			}{{"groups_ou", gdn}, {"quarantine_ou", qdn}} {
				if sub.dn != nil && !mdn.AncestorOfFold(sub.dn) {
					errs = append(errs, fmt.Errorf("%s.%s must be below managed_ou", p, sub.key))
				}
			}
			if gdn != nil && qdn != nil && (gdn.EqualFold(qdn) || gdn.AncestorOfFold(qdn) || qdn.AncestorOfFold(gdn)) {
				errs = append(errs, fmt.Errorf("%s: groups_ou and quarantine_ou must be separate OUs", p))
			}
			// Never both directions on the same OU tree.
			for _, list := range []struct {
				key   string
				bases []string
			}{{"source.user_bases", c.Source.UserBases}, {"source.group_bases", c.Source.GroupBases}} {
				for _, b := range list.bases {
					bdn, err := ldap.ParseDN(b)
					if err != nil {
						continue
					}
					if mdn.EqualFold(bdn) || mdn.AncestorOfFold(bdn) || bdn.AncestorOfFold(mdn) {
						errs = append(errs, fmt.Errorf("%s.managed_ou overlaps %s entry %q: the two directions never share an OU tree", p, list.key, b))
					}
				}
			}
			for _, m := range managedOUs {
				if mdn.EqualFold(m.dn) || mdn.AncestorOfFold(m.dn) || m.dn.AncestorOfFold(mdn) {
					errs = append(errs, fmt.Errorf("%s.managed_ou overlaps the managed_ou of scope %s", p, m.name))
				}
			}
			managedOUs = append(managedOUs, managed{name: s.Name, dn: mdn})
		}
		s.OrgUnits = trimList(s.OrgUnits)
		if len(s.OrgUnits) == 0 {
			errs = append(errs, fmt.Errorf("%s.org_units: at least one Google org unit path", p))
		}
		if len(s.OrgUnits) > 100 || len(s.MemberOf) > 100 {
			errs = append(errs, fmt.Errorf("%s: at most 100 org units and 100 groups", p))
		}
		for _, ou := range s.OrgUnits {
			if !ouPathRE.MatchString(ou) {
				errs = append(errs, fmt.Errorf("%s.org_units: %q is not an org unit path (it starts with /)", p, ou))
				continue
			}
			for _, t := range targets {
				if orgUnitCovers(ou, t, s.SubOrgUnits) {
					errs = append(errs, fmt.Errorf("%s.org_units: %s selects the org unit %s, a target of the AD to Google mapping", p, ou, t))
				}
			}
		}
		s.MemberOf = trimList(s.MemberOf)
		for i, m := range s.MemberOf {
			if !addressRE.MatchString(m) {
				errs = append(errs, fmt.Errorf("%s.member_of: %q is not a group address", p, m))
			}
			s.MemberOf[i] = model.NormalizeEmail(m)
		}
		s.Fields = trimList(s.Fields)
		for i, f := range s.Fields {
			if !slices.Contains(model.OptionalUserFields, model.UserField(f)) {
				errs = append(errs, fmt.Errorf("%s.fields: %q is not one of %v", p, f, model.OptionalUserFields))
			}
			if slices.Contains(s.Fields[:i], f) {
				errs = append(errs, fmt.Errorf("%s.fields: %q is listed twice", p, f))
			}
		}
		s.LogonTemplate = strings.TrimSpace(s.LogonTemplate)
		if s.LogonTemplate != "" && !g2a.ValidLogonTemplate(s.LogonTemplate) {
			errs = append(errs, fmt.Errorf("%s.logon_template %q: placeholders {given}, {family}, {g}, {f}, {local} and the characters a-z 0-9 . - _", p, s.LogonTemplate))
		}
		if s.Limits != nil {
			errs = append(errs, s.Limits.Validate(p+".limits")...)
		}
	}
	return errs
}

func parseOU(dn, key string, errs *[]error) *ldap.DN {
	if dn == "" {
		*errs = append(*errs, fmt.Errorf("%s is required", key))
		return nil
	}
	if _, err := escape.ParseDN(dn); err != nil {
		*errs = append(*errs, fmt.Errorf("%s: invalid DN %q", key, dn))
		return nil
	}
	d, err := ldap.ParseDN(dn)
	if err != nil || len(d.RDNs) == 0 {
		*errs = append(*errs, fmt.Errorf("%s: invalid DN %q", key, dn))
		return nil
	}
	return d
}

// orgUnitCovers reports whether a Google-first org unit selection (ou,
// with sub) selects the org unit target.
func orgUnitCovers(ou, target string, sub bool) bool {
	o := strings.ToLower(strings.TrimRight(ou, "/"))
	t := strings.ToLower(strings.TrimRight(target, "/"))
	if o == t {
		return true
	}
	if !sub {
		return false
	}
	return o == "" || strings.HasPrefix(t, o+"/")
}

// G2AScopes returns the scopes as the plan needs them (defaults applied).
func (c *Config) G2AScopes() []g2a.Scope {
	var out []g2a.Scope
	for _, s := range c.GoogleFirst.Scopes {
		sc := g2a.Scope{Name: s.Name, Mode: s.Mode, ManagedOU: s.ManagedOU, GroupsOU: s.GroupsOU, QuarantineOU: s.QuarantineOU,
			OrgUnits: slices.Clone(s.OrgUnits), SubOrgUnits: s.SubOrgUnits, MemberOf: slices.Clone(s.MemberOf),
			LogonTemplate: s.LogonTemplate, Limits: g2a.DefaultLimits()}
		if sc.LogonTemplate == "" {
			sc.LogonTemplate = g2a.DefaultLogonTemplate
		}
		if s.Limits != nil {
			sc.Limits = *s.Limits
		}
		for _, f := range s.Fields {
			sc.Fields = append(sc.Fields, model.UserField(f))
		}
		out = append(out, sc)
	}
	return out
}

// GoogleFirstOf extracts the section as settings: nil when it is the
// default (off, no domain, no scope), so clients that predate it keep
// decoding. Limits are always explicit.
func GoogleFirstOf(c *Config) *syncapi.GoogleFirstSettings {
	gf := c.GoogleFirst
	if !gf.Enabled && gf.GoogleDomain == "" && len(gf.Scopes) == 0 {
		return nil
	}
	out := &syncapi.GoogleFirstSettings{Enabled: gf.Enabled, GoogleDomain: gf.GoogleDomain, Scopes: []syncapi.G2AScope{}}
	for _, sc := range c.G2AScopes() {
		l := sc.Limits
		var fields []string
		for _, f := range sc.Fields {
			fields = append(fields, string(f))
		}
		out.Scopes = append(out.Scopes, syncapi.G2AScope{Name: sc.Name, Mode: sc.Mode, ManagedOU: sc.ManagedOU, GroupsOU: sc.GroupsOU,
			QuarantineOU: sc.QuarantineOU, OrgUnits: clone(sc.OrgUnits), SubOrgUnits: sc.SubOrgUnits, MemberOf: clone(sc.MemberOf),
			Fields: clone(fields), LogonTemplate: sc.LogonTemplate,
			Limits: &syncapi.G2ALimits{MaxCreates: l.MaxCreates, MaxDisables: l.MaxDisables, MaxReenables: l.MaxReenables,
				MaxUpdates: l.MaxUpdates, MaxRenames: l.MaxRenames, MaxTouchedPercent: l.MaxTouchedPercent,
				MinSourceSize: l.MinSourceSize, MaxSourceDropPercent: l.MaxSourceDropPercent}})
	}
	return out
}

// overlayGoogleFirst converts settings to the section (nil keeps the
// file's section).
func overlayGoogleFirst(file GoogleFirst, s *syncapi.GoogleFirstSettings) GoogleFirst {
	if s == nil {
		// A copy: validation normalizes the scopes in place.
		out := file
		out.Scopes = nil
		for _, sc := range file.Scopes {
			sc.OrgUnits, sc.MemberOf, sc.Fields = slices.Clone(sc.OrgUnits), slices.Clone(sc.MemberOf), slices.Clone(sc.Fields)
			if sc.Limits != nil {
				l := *sc.Limits
				sc.Limits = &l
			}
			out.Scopes = append(out.Scopes, sc)
		}
		return out
	}
	out := GoogleFirst{Enabled: s.Enabled, GoogleDomain: s.GoogleDomain}
	for _, sc := range s.Scopes {
		n := G2AScope{Name: sc.Name, Mode: sc.Mode, ManagedOU: sc.ManagedOU, GroupsOU: sc.GroupsOU, QuarantineOU: sc.QuarantineOU,
			OrgUnits: slices.Clone(sc.OrgUnits), SubOrgUnits: sc.SubOrgUnits, MemberOf: slices.Clone(sc.MemberOf),
			Fields: slices.Clone(sc.Fields), LogonTemplate: sc.LogonTemplate}
		if l := sc.Limits; l != nil {
			n.Limits = &g2a.Limits{MaxCreates: l.MaxCreates, MaxDisables: l.MaxDisables, MaxReenables: l.MaxReenables,
				MaxUpdates: l.MaxUpdates, MaxRenames: l.MaxRenames, MaxTouchedPercent: l.MaxTouchedPercent,
				MinSourceSize: l.MinSourceSize, MaxSourceDropPercent: l.MaxSourceDropPercent}
		}
		out.Scopes = append(out.Scopes, n)
	}
	return out
}
