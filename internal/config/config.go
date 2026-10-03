// Package config loads /etc/conductor-sync/conductor-sync.toml. The file
// holds no secret: the AD bind password, the Google service account key and
// the webhook secret are named credentials (systemd LoadCredential= or a
// 0600 file).
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/samba-conductor/conductor-sync/internal/alert"
	"github.com/samba-conductor/conductor-sync/internal/connector/google"
	"github.com/samba-conductor/conductor-sync/internal/mapping"
	"github.com/samba-conductor/conductor-sync/internal/plan"
	"github.com/samba-conductor/conductor-sync/internal/source/adsource"
)

// Policy is the [policy] section.
type Policy struct {
	SuspendDisabled        *bool  `toml:"suspend_disabled"`
	CreateDisabled         bool   `toml:"create_disabled"`
	Adopt                  string `toml:"adopt"`
	RemoveUnmanagedMembers bool   `toml:"remove_unmanaged_members"`
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
	Limits  plan.Limits     `toml:"limits"`
	Google  google.Config   `toml:"google"`
	Alert   Alert           `toml:"alert"`
	Delete  Delete          `toml:"delete"`

	// Rules is the compiled mapping (set by Load).
	Rules *mapping.Rules `toml:"-"`
}

// Load reads, defaults and validates a configuration file.
func Load(path string) (*Config, error) {
	c := &Config{Limits: plan.DefaultLimits(), Delete: Delete{MinSuspendedDays: 30}}
	md, err := toml.DecodeFile(path, c)
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
	return plan.Policy{
		Optional:               c.Rules.Optional(),
		SuspendDisabled:        c.Policy.SuspendDisabled == nil || *c.Policy.SuspendDisabled,
		CreateDisabled:         c.Policy.CreateDisabled,
		Adopt:                  plan.AdoptMode(c.Policy.Adopt),
		ManageGroups:           c.Rules.ManagesGroups() && len(c.Source.GroupBases) > 0,
		RemoveUnmanagedMembers: c.Policy.RemoveUnmanagedMembers,
	}
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
