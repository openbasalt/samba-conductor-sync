// Package config loads /etc/conductor-sync/conductor-sync.toml. The file
// holds no secret: the AD bind password, the Google service account key and
// the webhook secret are named credentials (systemd LoadCredential= or a
// 0600 file), or are stored encrypted in the state database through the
// management API (which wins over the credential files).
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/openbasalt/samba-conductor-sync/internal/alert"
	"github.com/openbasalt/samba-conductor-sync/internal/connector/google"
	"github.com/openbasalt/samba-conductor-sync/internal/mapping"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/source/adsource"
)

// Policy is the [policy] section.
type Policy struct {
	SuspendDisabled        *bool  `toml:"suspend_disabled"`
	CreateDisabled         bool   `toml:"create_disabled"`
	Adopt                  string `toml:"adopt"`
	RemoveUnmanagedMembers bool   `toml:"remove_unmanaged_members"`
	// Rules for adopted accounts and groups (see plan.Policy); empty =
	// the safe default.
	AdoptedOrgUnit      string `toml:"adopted_org_unit,omitempty"`
	AdoptedEmail        string `toml:"adopted_email,omitempty"`
	AdoptedNames        string `toml:"adopted_names,omitempty"`
	AdoptedAttributes   string `toml:"adopted_attributes,omitempty"`
	AdoptedGroupMembers string `toml:"adopted_group_members,omitempty"`
}

// adoptedRules pairs each adopted rule's key with its value.
func (p *Policy) adoptedRules() map[string]*string {
	return map[string]*string{"adopted_org_unit": &p.AdoptedOrgUnit, "adopted_email": &p.AdoptedEmail,
		"adopted_names": &p.AdoptedNames, "adopted_attributes": &p.AdoptedAttributes, "adopted_group_members": &p.AdoptedGroupMembers}
}

// SelfService is the [self_service] section: what a user may do with their
// own account on the target from conductor's self-service ("Connected
// accounts"). Empty values take the defaults (SelfServiceDefaults).
type SelfService struct {
	// Activation: "auto" (the sync runs create accounts) or "self-service"
	// (an account is created only when its user activates it).
	Activation string `toml:"activation,omitempty"`
	// PasswordReset: "created" (only accounts the sync created),
	// "created-and-adopted" or "off".
	PasswordReset string `toml:"password_reset,omitempty"`
	// ChosenPassword: "off" (generated passwords only) or "allow".
	ChosenPassword string `toml:"chosen_password,omitempty"`
	// PasswordMinLength raises the target's minimum (8-100).
	PasswordMinLength int `toml:"password_min_length,omitempty"`
	// MaxPerUserHour and MaxPerTargetHour bound the actions in any hour.
	MaxPerUserHour   int `toml:"max_per_user_hour,omitempty"`
	MaxPerTargetHour int `toml:"max_per_target_hour,omitempty"`
}

// Self-service values.
const (
	ActivationAuto        = "auto"
	ActivationSelfService = "self-service"

	ResetCreated           = "created"
	ResetCreatedAndAdopted = "created-and-adopted"
	ResetOff               = "off"

	ChosenOff   = "off"
	ChosenAllow = "allow"
)

// SelfServiceDefaults are the defaults of [self_service].
var SelfServiceDefaults = SelfService{Activation: ActivationAuto, PasswordReset: ResetCreated, ChosenPassword: ChosenOff,
	PasswordMinLength: 12, MaxPerUserHour: 3, MaxPerTargetHour: 30}

// Effective returns the section with the defaults filled in.
func (s SelfService) Effective() SelfService {
	d := SelfServiceDefaults
	if v := strings.TrimSpace(s.Activation); v != "" {
		d.Activation = v
	}
	if v := strings.TrimSpace(s.PasswordReset); v != "" {
		d.PasswordReset = v
	}
	if v := strings.TrimSpace(s.ChosenPassword); v != "" {
		d.ChosenPassword = v
	}
	if s.PasswordMinLength != 0 {
		d.PasswordMinLength = s.PasswordMinLength
	}
	if s.MaxPerUserHour != 0 {
		d.MaxPerUserHour = s.MaxPerUserHour
	}
	if s.MaxPerTargetHour != 0 {
		d.MaxPerTargetHour = s.MaxPerTargetHour
	}
	return d
}

func (s *SelfService) validate() []error {
	var errs []error
	s.Activation, s.PasswordReset, s.ChosenPassword = strings.TrimSpace(s.Activation), strings.TrimSpace(s.PasswordReset), strings.TrimSpace(s.ChosenPassword)
	switch s.Activation {
	case "", ActivationAuto, ActivationSelfService:
	default:
		errs = append(errs, fmt.Errorf("self_service.activation %q: want auto or self-service", s.Activation))
	}
	switch s.PasswordReset {
	case "", ResetCreated, ResetCreatedAndAdopted, ResetOff:
	default:
		errs = append(errs, fmt.Errorf("self_service.password_reset %q: want created, created-and-adopted or off", s.PasswordReset))
	}
	switch s.ChosenPassword {
	case "", ChosenOff, ChosenAllow:
	default:
		errs = append(errs, fmt.Errorf("self_service.chosen_password %q: want off or allow", s.ChosenPassword))
	}
	if s.PasswordMinLength != 0 && (s.PasswordMinLength < 8 || s.PasswordMinLength > 100) {
		errs = append(errs, fmt.Errorf("self_service.password_min_length %d: 8-100", s.PasswordMinLength))
	}
	if s.MaxPerUserHour < 0 || s.MaxPerUserHour > 100 {
		errs = append(errs, fmt.Errorf("self_service.max_per_user_hour %d: 1-100", s.MaxPerUserHour))
	}
	if s.MaxPerTargetHour < 0 || s.MaxPerTargetHour > 10000 {
		errs = append(errs, fmt.Errorf("self_service.max_per_target_hour %d: 1-10000", s.MaxPerTargetHour))
	}
	return errs
}

// Alert is the [alert] section.
type Alert struct {
	WebhookURL string `toml:"webhook_url"`
	// WebhookSecretCredential names the HMAC key (optional).
	WebhookSecretCredential string `toml:"webhook_secret_credential"`
}

// Delete is the [delete] section (the manual delete command).
type Delete struct {
	MinSuspendedDays int `toml:"min_suspended_days"`
}

// Schedule is the [schedule] section.
type Schedule struct {
	// Interval between scheduled runs (default 15m). With the systemd
	// timer it must match OnUnitInactiveSec (it is only used to show the
	// next run); with InProcess, `conductor-sync serve` runs them itself.
	Interval google.Duration `toml:"interval"`
	// InProcess makes `conductor-sync serve` the scheduler (hosts without
	// systemd timers, e.g. containers). Keep the timer disabled then.
	InProcess bool `toml:"in_process"`
}

// API is the [api] section: the local management API of `serve`.
type API struct {
	// Socket path (default /run/conductor-sync/api.sock). Ignored under
	// systemd socket activation.
	Socket string `toml:"socket"`
	// AllowedUsers and AllowedUIDs are the only peers admitted
	// (SO_PEERCRED); default the "conductor" user.
	AllowedUsers []string `toml:"allowed_users"`
	AllowedUIDs  []int    `toml:"allowed_uids,omitempty"`
	// SocketGroup (name or numeric GID) owns the socket (mode 0660) so the
	// conductor user can connect; the conductor-sync user must be a member.
	SocketGroup string `toml:"socket_group,omitempty"`
	// StateKeyCredential names the 32-byte key that encrypts secrets set
	// through the API (the Google service account key) in the state
	// database: a systemd credential name or an absolute 0600 path.
	StateKeyCredential string `toml:"state_key_credential"`
}

// Config is the whole file.
type Config struct {
	// Mode is "dry-run" (default: plans only) or "apply".
	Mode        string `toml:"mode"`
	Connector   string `toml:"connector"`
	StateDir    string `toml:"state_dir"`
	MetricsFile string `toml:"metrics_file"`
	MaxFailures int    `toml:"max_failures"`
	// CredentialsDir holds named credentials for manual runs (outside
	// the systemd unit, where $CREDENTIALS_DIRECTORY is not set).
	CredentialsDir string `toml:"credentials_dir"`

	Source  adsource.Config `toml:"source"`
	Mapping mapping.Config  `toml:"mapping"`
	Policy  Policy          `toml:"policy"`
	// SelfService is the self-service policy of the target.
	SelfService SelfService   `toml:"self_service"`
	Limits      plan.Limits   `toml:"limits"`
	Google      google.Config `toml:"google"`
	Alert       Alert         `toml:"alert"`
	Delete      Delete        `toml:"delete"`
	Schedule    Schedule      `toml:"schedule"`
	API         API           `toml:"api"`

	// Rules is the compiled mapping (set by Load).
	Rules *mapping.Rules `toml:"-"`
	// Path is the file the configuration was loaded from.
	Path string `toml:"-"`
	// SettingsVersion is the stored settings version overlaid on the
	// file (0: the file's own settings).
	SettingsVersion int64 `toml:"-"`
	// ConnectionStored is set when the connection settings come from the
	// stored version, not from the file.
	ConnectionStored bool `toml:"-"`

	// adPassword replaces the AD bind password for one connection test
	// (never stored, never exported).
	adPassword string
}

// WithADPassword returns a copy of c whose AD source signs in with pw (a
// connection test of a password that is not stored yet).
func (c *Config) WithADPassword(pw string) *Config {
	n := *c
	n.adPassword = pw
	return &n
}

// ADPasswordOverride is the password set by WithADPassword ("" = none).
func (c *Config) ADPasswordOverride() string { return c.adPassword }

// Load reads, defaults and validates a configuration file.
func Load(path string) (*Config, error) {
	c := &Config{Limits: plan.DefaultLimits(), Delete: Delete{MinSuspendedDays: 30}}
	md, err := toml.DecodeFile(path, c)
	if err == nil {
		c.Path = path
	}
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("config %s: unknown keys %v", path, und)
	}
	if err := c.finish(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

func (c *Config) finish() error {
	var errs []error
	if c.Mode == "" {
		c.Mode = "dry-run"
	}
	if c.Mode != "dry-run" && c.Mode != "apply" {
		errs = append(errs, fmt.Errorf("mode %q: want dry-run or apply", c.Mode))
	}
	if c.Connector == "" {
		c.Connector = "google"
	}
	if c.Connector != "google" {
		errs = append(errs, fmt.Errorf("connector %q: only google is implemented", c.Connector))
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/conductor-sync"
	}
	if !filepath.IsAbs(c.StateDir) {
		errs = append(errs, errors.New("state_dir must be absolute"))
	}
	if c.CredentialsDir == "" {
		c.CredentialsDir = "/etc/conductor-sync/credentials"
	}
	if c.MaxFailures == 0 {
		c.MaxFailures = 25
	}
	if c.Schedule.Interval.Duration == 0 {
		c.Schedule.Interval.Duration = 15 * time.Minute
	}
	if c.Schedule.Interval.Duration < time.Minute || c.Schedule.Interval.Duration > 7*24*time.Hour {
		errs = append(errs, errors.New("schedule.interval: between 1m and 168h"))
	}
	if c.API.Socket == "" {
		c.API.Socket = "/run/conductor-sync/api.sock"
	}
	if !filepath.IsAbs(c.API.Socket) {
		errs = append(errs, errors.New("api.socket must be absolute"))
	}
	if len(c.API.AllowedUsers) == 0 && len(c.API.AllowedUIDs) == 0 {
		c.API.AllowedUsers = []string{"conductor"}
	}
	if c.API.StateKeyCredential == "" {
		c.API.StateKeyCredential = "state-key"
	}
	if err := c.Source.Validate(); err != nil {
		errs = append(errs, err)
	}
	rules, err := mapping.Compile(c.Mapping)
	if err != nil {
		errs = append(errs, err)
	}
	c.Rules = rules
	switch c.Policy.Adopt {
	case "":
		c.Policy.Adopt = string(plan.AdoptNever)
	case string(plan.AdoptNever), string(plan.AdoptEmail):
	default:
		errs = append(errs, fmt.Errorf("policy.adopt %q: want never or email", c.Policy.Adopt))
	}
	for key, v := range c.Policy.adoptedRules() {
		*v = strings.TrimSpace(*v)
		if !plan.ValidAdopted(key, plan.AdoptedMode(*v)) {
			errs = append(errs, fmt.Errorf("policy.%s %q: want one of %v", key, *v, plan.AdoptedChoices[key]))
		}
	}
	errs = append(errs, c.SelfService.validate()...)
	c.Google.Defaults()
	if err := c.Google.Validate(); err != nil {
		errs = append(errs, err)
	}
	if c.Alert.WebhookURL != "" {
		if err := alert.ValidateWebhookURL(c.Alert.WebhookURL); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Delete.MinSuspendedDays < 0 {
		errs = append(errs, errors.New("delete.min_suspended_days must not be negative"))
	}
	for name, v := range map[string]int{"max_creates": c.Limits.MaxCreates, "max_suspends": c.Limits.MaxSuspends,
		"max_unsuspends": c.Limits.MaxUnsuspends, "max_renames": c.Limits.MaxRenames, "max_updates": c.Limits.MaxUpdates,
		"max_group_changes": c.Limits.MaxGroupChanges, "max_membership_changes": c.Limits.MaxMembershipChanges,
		"min_source_users": c.Limits.MinSourceUsers} {
		if v < plan.Unlimited {
			errs = append(errs, fmt.Errorf("limits.%s: %d (use -1 for no limit)", name, v))
		}
	}
	return errors.Join(errs...)
}

// PlanPolicy builds the plan's policy.
func (c *Config) PlanPolicy() plan.Policy {
	p := plan.Policy{
		Optional:               c.Rules.Optional(),
		SuspendDisabled:        c.Policy.SuspendDisabled == nil || *c.Policy.SuspendDisabled,
		CreateDisabled:         c.Policy.CreateDisabled,
		Adopt:                  plan.AdoptMode(c.Policy.Adopt),
		ManageGroups:           c.Rules.ManagesGroups() && len(c.Source.GroupBases) > 0,
		RemoveUnmanagedMembers: c.Policy.RemoveUnmanagedMembers,
		AdoptedOrgUnit:         plan.AdoptedMode(c.Policy.AdoptedOrgUnit),
		AdoptedEmail:           plan.AdoptedMode(c.Policy.AdoptedEmail),
		AdoptedNames:           plan.AdoptedMode(c.Policy.AdoptedNames),
		AdoptedAttributes:      plan.AdoptedMode(c.Policy.AdoptedAttributes),
		AdoptedGroupMembers:    plan.AdoptedMode(c.Policy.AdoptedGroupMembers),
		SelfServiceActivation:  c.SelfService.Effective().Activation == ActivationSelfService,
	}
	p.Defaults()
	return p
}

// StatePath is the SQLite database.
func (c *Config) StatePath() string { return filepath.Join(c.StateDir, "state.db") }

// LockPath is the run lock.
func (c *Config) LockPath() string { return filepath.Join(c.StateDir, "run.lock") }

// EnsureStateDir creates the state directory (0700).
func (c *Config) EnsureStateDir() error {
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return err
	}
	return os.Chmod(c.StateDir, 0o700)
}
