package config

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/openbasalt/samba-conductor-sync/internal/mapping"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// The configuration has two parts. Host settings (state directory,
// credentials, how AD and Google are reached, the ownership marker,
// alerts, the API socket) live only in the file. Sync settings (mode,
// scope, mapping, policy, limits, the tenant's admin subject, schedule) can
// also be edited through the management API: each edit is validated and
// stored as a new version in the state database, and the newest stored
// version overrides the file's values for those keys. The file is the
// bootstrap, and Export renders the effective configuration in the same
// format.

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
		},
		Limits: syncapi.LimitSettings{
			MaxCreates: l.MaxCreates, MaxSuspends: l.MaxSuspends, MaxUnsuspends: l.MaxUnsuspends, MaxRenames: l.MaxRenames,
			MaxUpdates: l.MaxUpdates, MaxGroupChanges: l.MaxGroupChanges, MaxMembershipChanges: l.MaxMembershipChanges,
			MaxTouchedPercent: l.MaxTouchedPercent, MinSourceUsers: l.MinSourceUsers, MaxSourceDropPercent: l.MaxSourceDropPercent,
		},
		Google:   syncapi.GoogleSettings{Customer: c.Google.Customer, AdminSubject: c.Google.AdminSubject, MemberRole: c.Google.MemberRole},
		Schedule: syncapi.ScheduleSettings{Interval: c.Schedule.Interval.Duration.String()},
	}
}

func clone(s []string) []string {
	if len(s) == 0 {
		return []string{}
	}
	return slices.Clone(s)
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
		RemoveUnmanagedMembers: s.Policy.RemoveUnmanagedMembers}
	l := s.Limits
	n.Limits = plan.Limits{MaxCreates: l.MaxCreates, MaxSuspends: l.MaxSuspends, MaxUnsuspends: l.MaxUnsuspends, MaxRenames: l.MaxRenames,
		MaxUpdates: l.MaxUpdates, MaxGroupChanges: l.MaxGroupChanges, MaxMembershipChanges: l.MaxMembershipChanges,
		MaxTouchedPercent: l.MaxTouchedPercent, MinSourceUsers: l.MinSourceUsers, MaxSourceDropPercent: l.MaxSourceDropPercent}
	n.Google.Customer = strings.TrimSpace(s.Google.Customer)
	n.Google.AdminSubject = strings.TrimSpace(s.Google.AdminSubject)
	n.Google.MemberRole = strings.TrimSpace(s.Google.MemberRole)
	var errs []error
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
