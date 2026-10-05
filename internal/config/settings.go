package config

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/openbasalt/samba-conductor-sync/internal/mapping"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// The configuration has two parts. Host settings (state directory,
// credential names, the API socket, the Google API endpoints and their CA,
// the CA file path) live only in the file. Sync settings (mode, scope,
// mapping, policy, limits, the tenant's customer and admin subject,
// schedule) and, since P5c, the connection settings (the AD realm, DCs,
// DNS servers, CA content, bind user and authentication; the Google client
// tuning; the ownership marker; the alert webhook URL) can also be edited
// through the management API: each edit is validated and stored as a new
// version in the state database, and the newest stored version overrides
// the file's values for those keys. A version stored before P5c has no
// connection settings and keeps the file's. The file is the bootstrap, and
// Export renders the effective configuration in the same format. Secrets
// are never part of a version.

// SettingsOf extracts the sync settings, with defaults made explicit.
func SettingsOf(c *Config) syncapi.Settings {
	m := c.Mapping
	m.Defaults()
	attrs := map[string]string{}
	maps.Copy(attrs, m.Attributes)
	var ous []syncapi.OrgUnitRule
	for _, o := range m.OrgUnits {
		ous = append(ous, syncapi.OrgUnitRule{AD: o.AD, Group: o.Group, Target: o.Target, Priority: o.Priority})
	}
	l := c.Limits
	return syncapi.Settings{
		Mode: c.Mode,
		Scope: syncapi.ScopeSettings{
			UserBases: clone(c.Source.UserBases), ExcludeBases: clone(c.Source.ExcludeBases), GroupBases: clone(c.Source.GroupBases),
			IncludeGroups: clone(c.Source.Includes()), ExcludeGroups: clone(c.Source.ExcludeGroups),
			ExpiredAsDisabled: c.Source.ExpiredAsDisabled == nil || *c.Source.ExpiredAsDisabled,
		},
		Mapping: syncapi.MappingSettings{
			PrimaryEmail: clone(m.PrimaryEmail), AllowedDomains: clone(m.AllowedDomains), GivenName: clone(m.GivenName),
			FamilyName: clone(m.FamilyName), DefaultOrgUnit: m.DefaultOrgUnit, OrgUnits: ous, Attributes: attrs,
			GroupEmail: clone(m.GroupEmail), GroupName: clone(m.GroupName), GroupDescription: clone(m.GroupDescription),
			GroupAllowedDomains: clone(m.GroupAllowedDomains),
		},
		Policy: syncapi.PolicySettings{
			SuspendDisabled: c.Policy.SuspendDisabled == nil || *c.Policy.SuspendDisabled,
			CreateDisabled:  c.Policy.CreateDisabled, Adopt: c.Policy.Adopt, RemoveUnmanagedMembers: c.Policy.RemoveUnmanagedMembers,
			AdoptedOrgUnit:      nonDefault(c.Policy.AdoptedOrgUnit, plan.AdoptedKeep),
			AdoptedEmail:        nonDefault(c.Policy.AdoptedEmail, plan.AdoptedKeep),
			AdoptedNames:        nonDefault(c.Policy.AdoptedNames, plan.AdoptedIfSet),
			AdoptedAttributes:   nonDefault(c.Policy.AdoptedAttributes, plan.AdoptedIfSet),
			AdoptedGroupMembers: nonDefault(c.Policy.AdoptedGroupMembers, plan.AdoptedAddOnly),
		},
		Limits: syncapi.LimitSettings{
			MaxCreates: l.MaxCreates, MaxSuspends: l.MaxSuspends, MaxUnsuspends: l.MaxUnsuspends, MaxRenames: l.MaxRenames,
			MaxUpdates: l.MaxUpdates, MaxGroupChanges: l.MaxGroupChanges, MaxMembershipChanges: l.MaxMembershipChanges,
			MaxTouchedPercent: l.MaxTouchedPercent, MinSourceUsers: l.MinSourceUsers, MaxSourceDropPercent: l.MaxSourceDropPercent,
		},
		Google:      syncapi.GoogleSettings{Customer: c.Google.Customer, AdminSubject: c.Google.AdminSubject, MemberRole: c.Google.MemberRole},
		Schedule:    syncapi.ScheduleSettings{Interval: c.Schedule.Interval.Duration.String()},
		Connection:  ConnectionOf(c),
		SelfService: SelfServiceOf(c),
	}
}

// SelfServiceOf extracts the self-service policy: nil when every value is
// the default (defaults travel as empty, so clients that predate the field
// keep decoding).
func SelfServiceOf(c *Config) *syncapi.SelfServiceSettings {
	e, d := c.SelfService.Effective(), SelfServiceDefaults
	s := syncapi.SelfServiceSettings{}
	if e.Activation != d.Activation {
		s.Activation = e.Activation
	}
	if e.PasswordReset != d.PasswordReset {
		s.PasswordReset = e.PasswordReset
	}
	if e.ChosenPassword != d.ChosenPassword {
		s.ChosenPassword = e.ChosenPassword
	}
	if e.PasswordMinLength != d.PasswordMinLength {
		s.PasswordMinLength = e.PasswordMinLength
	}
	if e.MaxPerUserHour != d.MaxPerUserHour {
		s.MaxPerUserHour = e.MaxPerUserHour
	}
	if e.MaxPerTargetHour != d.MaxPerTargetHour {
		s.MaxPerTargetHour = e.MaxPerTargetHour
	}
	if s == (syncapi.SelfServiceSettings{}) {
		return nil
	}
	return &s
}

// overlaySelfService applies the settings' self-service policy: nil keeps
// the file's section, and so does each empty value.
func overlaySelfService(file SelfService, s *syncapi.SelfServiceSettings) SelfService {
	if s == nil {
		return file
	}
	out := SelfService{Activation: orFile(s.Activation, file.Activation), PasswordReset: orFile(s.PasswordReset, file.PasswordReset),
		ChosenPassword: orFile(s.ChosenPassword, file.ChosenPassword), PasswordMinLength: s.PasswordMinLength,
		MaxPerUserHour: s.MaxPerUserHour, MaxPerTargetHour: s.MaxPerTargetHour}
	if out.PasswordMinLength == 0 {
		out.PasswordMinLength = file.PasswordMinLength
	}
	if out.MaxPerUserHour == 0 {
		out.MaxPerUserHour = file.MaxPerUserHour
	}
	if out.MaxPerTargetHour == 0 {
		out.MaxPerTargetHour = file.MaxPerTargetHour
	}
	return out
}

// ConnectionOf extracts the connection settings.
func ConnectionOf(c *Config) *syncapi.ConnectionSettings {
	src := c.Source
	auth := src.Auth
	if auth == "" {
		auth = "kerberos"
	}
	return &syncapi.ConnectionSettings{
		AD: syncapi.ADConnection{Realm: src.Realm, DCs: clone(src.DCs), Preferred: clone(src.Preferred), DNSServers: clone(src.DNSServers),
			CAPEM: src.CAPEM, CAFile: src.CAFile, BindUser: src.BindUser, Auth: auth},
		Google: syncapi.GoogleConnection{RequestsPerSecond: c.Google.RequestsPerSecond, MaxRetries: c.Google.MaxRetries,
			Timeout: c.Google.Timeout.Duration.String()},
		Marker: c.Google.Marker,
		Alert:  syncapi.AlertConnection{WebhookURL: c.Alert.WebhookURL},
	}
}

// ADConnectionChanged reports whether the way AD is reached differs (a
// change that is saved only after a successful sign-in).
func ADConnectionChanged(a, b *Config) bool {
	x, y := a.Source, b.Source
	return x.Realm != y.Realm || !slices.Equal(x.DCs, y.DCs) || !slices.Equal(x.Preferred, y.Preferred) ||
		!slices.Equal(x.DNSServers, y.DNSServers) || x.CAPEM != y.CAPEM || x.CAFile != y.CAFile ||
		x.BindUser != y.BindUser || authOf(x.Auth) != authOf(y.Auth)
}

func authOf(a string) string {
	if a == "" {
		return "kerberos"
	}
	return a
}

// GoogleConnectionChanged reports whether the tenant or the client tuning
// differs.
func GoogleConnectionChanged(a, b *Config) bool {
	x, y := a.Google, b.Google
	return x.Customer != y.Customer || x.AdminSubject != y.AdminSubject || x.RequestsPerSecond != y.RequestsPerSecond ||
		x.MaxRetries != y.MaxRetries || x.Timeout != y.Timeout
}

var (
	realmRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}$`)
	hostRE   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9-]{1,63})*\.?$`)
	markerRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	userRE   = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,256}$`)
)

// overlayConnection applies the connection settings to n, validating what
// the file loader does not (host names, DNS servers, bounds).
func overlayConnection(n *Config, cs *syncapi.ConnectionSettings) []error {
	var errs []error
	a := cs.AD
	n.Source.Realm = strings.ToUpper(strings.TrimSpace(a.Realm))
	if !realmRE.MatchString(n.Source.Realm) || len(n.Source.Realm) > 253 {
		errs = append(errs, fmt.Errorf("source.realm %q: a DNS domain name", a.Realm))
	}
	hosts := func(name string, in []string) []string {
		out := trimList(in)
		for _, h := range out {
			if net.ParseIP(h) == nil && (!hostRE.MatchString(h) || len(h) > 253) {
				errs = append(errs, fmt.Errorf("source.%s: %q is not a host name or IP address", name, h))
			}
		}
		return out
	}
	n.Source.DCs = hosts("dcs", a.DCs)
	n.Source.Preferred = hosts("preferred", a.Preferred)
	n.Source.DNSServers = trimList(a.DNSServers)
	for _, d := range n.Source.DNSServers {
		host := d
		if h, port, err := net.SplitHostPort(d); err == nil {
			if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
				errs = append(errs, fmt.Errorf("source.dns_servers: %q has an invalid port", d))
			}
			host = h
		}
		if net.ParseIP(host) == nil {
			errs = append(errs, fmt.Errorf("source.dns_servers: %q is not an IP address (with an optional port)", d))
		}
	}
	if len(n.Source.DCs)+len(n.Source.Preferred)+len(n.Source.DNSServers) > 32 {
		errs = append(errs, errors.New("source: at most 32 DCs, preferred DCs and DNS servers"))
	}
	n.Source.CAPEM = strings.TrimSpace(strings.ReplaceAll(a.CAPEM, "\r\n", "\n"))
	if n.Source.CAPEM != "" {
		n.Source.CAPEM += "\n"
	}
	n.Source.BindUser = strings.TrimSpace(a.BindUser)
	if !userRE.MatchString(n.Source.BindUser) {
		errs = append(errs, fmt.Errorf("source.bind_user %q: a logon name, user@REALM or a DN", a.BindUser))
	}
	n.Source.Auth = strings.TrimSpace(a.Auth)
	g := cs.Google
	if g.RequestsPerSecond <= 0 || g.RequestsPerSecond > 10000 {
		errs = append(errs, fmt.Errorf("google.requests_per_second %g: more than 0, at most 10000", g.RequestsPerSecond))
	}
	n.Google.RequestsPerSecond = g.RequestsPerSecond
	if g.MaxRetries < 0 || g.MaxRetries > 20 {
		errs = append(errs, fmt.Errorf("google.max_retries %d: 0-20", g.MaxRetries))
	}
	n.Google.MaxRetries = g.MaxRetries
	if t := strings.TrimSpace(g.Timeout); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil || d < 5*time.Second || d > 10*time.Minute {
			errs = append(errs, fmt.Errorf("google.timeout %q: a duration between 5s and 10m", t))
		}
		n.Google.Timeout.Duration = d
	} else {
		n.Google.Timeout.Duration = 0
	}
	n.Google.Marker = strings.TrimSpace(cs.Marker)
	if !markerRE.MatchString(n.Google.Marker) {
		errs = append(errs, fmt.Errorf("google.marker %q: 1-64 letters, digits, dots, dashes or underscores", cs.Marker))
	}
	n.Alert.WebhookURL = strings.TrimSpace(cs.Alert.WebhookURL)
	n.ConnectionStored = true
	return errs
}

func clone(s []string) []string {
	if len(s) == 0 {
		return []string{}
	}
	return slices.Clone(s)
}

// nonDefault returns v, or "" when v is the default (or empty): defaults
// travel as empty so clients that predate a field keep decoding.
func nonDefault(v string, def plan.AdoptedMode) string {
	if v = strings.TrimSpace(v); v == string(def) {
		return ""
	}
	return v
}

// orFile returns the settings value, or the file's when it is empty (a
// client that does not know the field never resets it).
func orFile(v, file string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return file
}

// trimList drops blank entries and surrounding spaces.
func trimList(in []string) []string {
	out := []string{}
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Overlay returns a copy of c with the sync settings replaced by s, then
// defaulted and validated like a file. c itself is not changed.
func (c *Config) Overlay(s syncapi.Settings, version int64) (*Config, error) {
	n := *c
	n.Mode = strings.TrimSpace(s.Mode)
	n.Source.UserBases = trimList(s.Scope.UserBases)
	n.Source.ExcludeBases = trimList(s.Scope.ExcludeBases)
	n.Source.GroupBases = trimList(s.Scope.GroupBases)
	n.Source.IncludeGroups = trimList(s.Scope.IncludeGroups)
	n.Source.ExcludeGroups = trimList(s.Scope.ExcludeGroups)
	n.Source.RequireGroup = "" // folded into include_groups
	ead := s.Scope.ExpiredAsDisabled
	n.Source.ExpiredAsDisabled = &ead
	attrs := map[string]string{}
	for k, v := range s.Mapping.Attributes {
		if v = strings.TrimSpace(v); v != "" {
			attrs[strings.TrimSpace(k)] = v
		}
	}
	var ous []mapping.OUConfig
	for _, o := range s.Mapping.OrgUnits {
		ous = append(ous, mapping.OUConfig{AD: strings.TrimSpace(o.AD), Group: strings.TrimSpace(o.Group), Target: strings.TrimSpace(o.Target), Priority: o.Priority})
	}
	n.Mapping = mapping.Config{
		PrimaryEmail: trimList(s.Mapping.PrimaryEmail), AllowedDomains: trimList(s.Mapping.AllowedDomains),
		GivenName: trimList(s.Mapping.GivenName), FamilyName: trimList(s.Mapping.FamilyName),
		Attributes: attrs, DefaultOrgUnit: strings.TrimSpace(s.Mapping.DefaultOrgUnit), OrgUnits: ous,
		GroupEmail: trimList(s.Mapping.GroupEmail), GroupName: trimList(s.Mapping.GroupName),
		GroupDescription: trimList(s.Mapping.GroupDescription), GroupAllowedDomains: trimList(s.Mapping.GroupAllowedDomains),
	}
	sd := s.Policy.SuspendDisabled
	n.Policy = Policy{SuspendDisabled: &sd, CreateDisabled: s.Policy.CreateDisabled, Adopt: strings.TrimSpace(s.Policy.Adopt),
		RemoveUnmanagedMembers: s.Policy.RemoveUnmanagedMembers,
		AdoptedOrgUnit:         orFile(s.Policy.AdoptedOrgUnit, c.Policy.AdoptedOrgUnit),
		AdoptedEmail:           orFile(s.Policy.AdoptedEmail, c.Policy.AdoptedEmail),
		AdoptedNames:           orFile(s.Policy.AdoptedNames, c.Policy.AdoptedNames),
		AdoptedAttributes:      orFile(s.Policy.AdoptedAttributes, c.Policy.AdoptedAttributes),
		AdoptedGroupMembers:    orFile(s.Policy.AdoptedGroupMembers, c.Policy.AdoptedGroupMembers)}
	n.SelfService = overlaySelfService(c.SelfService, s.SelfService)
	l := s.Limits
	n.Limits = plan.Limits{MaxCreates: l.MaxCreates, MaxSuspends: l.MaxSuspends, MaxUnsuspends: l.MaxUnsuspends, MaxRenames: l.MaxRenames,
		MaxUpdates: l.MaxUpdates, MaxGroupChanges: l.MaxGroupChanges, MaxMembershipChanges: l.MaxMembershipChanges,
		MaxTouchedPercent: l.MaxTouchedPercent, MinSourceUsers: l.MinSourceUsers, MaxSourceDropPercent: l.MaxSourceDropPercent}
	n.Google.Customer = strings.TrimSpace(s.Google.Customer)
	n.Google.AdminSubject = strings.TrimSpace(s.Google.AdminSubject)
	n.Google.MemberRole = strings.TrimSpace(s.Google.MemberRole)
	var errs []error
	n.ConnectionStored = false
	if s.Connection != nil {
		errs = append(errs, overlayConnection(&n, s.Connection)...)
	}
	if iv := strings.TrimSpace(s.Schedule.Interval); iv != "" {
		d, err := time.ParseDuration(iv)
		if err != nil {
			errs = append(errs, fmt.Errorf("schedule.interval %q: a duration like 15m", iv))
		}
		n.Schedule.Interval.Duration = d
	} else {
		n.Schedule.Interval.Duration = 0
	}
	if n.Mode == "" {
		errs = append(errs, errors.New("mode: dry-run or apply"))
	}
	for name, v := range map[string]float64{"max_touched_percent": l.MaxTouchedPercent, "max_source_drop_percent": l.MaxSourceDropPercent} {
		if v < plan.Unlimited || v > 100 {
			errs = append(errs, fmt.Errorf("limits.%s: %g (0-100, or -1 for no limit)", name, v))
		}
	}
	if err := n.finish(); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	n.SettingsVersion = version
	return &n, nil
}

// ErrorList splits a joined validation error into messages.
func ErrorList(err error) []string {
	if err == nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(err.Error(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// Export renders the effective configuration as TOML (the file format).
// It holds no secret: credentials are only named.
func Export(c *Config) (string, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# conductor-sync effective configuration, exported %s.\n", time.Now().UTC().Format(time.RFC3339))
	if c.SettingsVersion > 0 {
		fmt.Fprintf(&buf, "# Sync settings: stored version %d (management API); host settings: %s.\n", c.SettingsVersion, c.Path)
	} else {
		fmt.Fprintf(&buf, "# Sync settings and host settings: %s.\n", c.Path)
	}
	buf.WriteString("# Credentials are named, never included.\n\n")
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(c); err != nil {
		return "", err
	}
	return buf.String(), nil
}
