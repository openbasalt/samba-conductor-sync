// Package app wires conductor-sync together for the CLI and for the
// management API server: the configuration file (host settings, and the
// bootstrap of the sync settings), the state database, the effective
// configuration (the newest stored settings version overlaid on the file),
// the Google service account key (stored encrypted through the API, or a
// credential file), and engines built for one actor.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/samba-conductor/conductor-sync/internal/alert"
	"github.com/samba-conductor/conductor-sync/internal/config"
	"github.com/samba-conductor/conductor-sync/internal/connector"
	"github.com/samba-conductor/conductor-sync/internal/connector/google"
	"github.com/samba-conductor/conductor-sync/internal/engine"
	"github.com/samba-conductor/conductor-sync/internal/model"
	"github.com/samba-conductor/conductor-sync/internal/secret"
	"github.com/samba-conductor/conductor-sync/internal/secretbox"
	"github.com/samba-conductor/conductor-sync/internal/source"
	"github.com/samba-conductor/conductor-sync/internal/source/adsource"
	"github.com/samba-conductor/conductor-sync/internal/store"
	"github.com/samba-conductor/conductor-sync/syncapi"
)

// GoogleKeySecret is the name of the stored service account key.
const GoogleKeySecret = "google-service-account-key"

// Settings version origins.
const (
	OriginBootstrap = "bootstrap"
	OriginAPI       = "api"
	OriginCLI       = "cli"
)

// Runtime is one process's view of conductor-sync.
type Runtime struct {
	// File is the configuration file as loaded (host settings and the
	// bootstrap sync settings).
	File  *config.Config
	Store *store.Store
	// Stderr receives warnings (journal).
	Stderr io.Writer
	// Connect builds the Google connector (replaceable in tests).
	Connect func(cfg google.Config, key *google.ServiceAccountKey, write bool) (connector.Connector, error)
	// NewSource builds the AD source (replaceable in tests).
	NewSource func(cfg *config.Config) Source
	// Now is the clock (tests).
	Now func() time.Time
}

// Source is the AD source with the extra read-only calls the API uses.
type Source interface {
	source.Source
	Check(ctx context.Context) (string, []model.ScopeGroup, error)
	Preview(ctx context.Context, query string, limit int) ([]adsource.Preview, []model.ScopeGroup, error)
}

// Open loads the configuration file, makes sure the state directory
// exists (0700) and opens the state database.
func Open(ctx context.Context, path string, stderr io.Writer) (*Runtime, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	secret.FallbackDir = cfg.CredentialsDir
	if err := cfg.EnsureStateDir(); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	st, err := store.Open(ctx, cfg.StatePath())
	if err != nil {
		return nil, err
	}
	return New(cfg, st, stderr), nil
}

// New builds a runtime around an already open store.
func New(cfg *config.Config, st *store.Store, stderr io.Writer) *Runtime {
	if stderr == nil {
		stderr = io.Discard
	}
	r := &Runtime{File: cfg, Store: st, Stderr: stderr, Now: time.Now}
	r.Connect = func(gc google.Config, key *google.ServiceAccountKey, write bool) (connector.Connector, error) {
		return google.New(gc, key, write, google.Options{})
	}
	r.NewSource = func(c *config.Config) Source { return &LazySource{Cfg: c} }
	return r
}

// Close closes the database.
func (r *Runtime) Close() error { return r.Store.Close() }

// Effective returns the configuration in force: the file, with the newest
// stored settings version (if any) overlaid.
func (r *Runtime) Effective(ctx context.Context) (*config.Config, error) {
	v, err := r.Store.LatestConfig(ctx)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return r.File, nil
	}
	var s syncapi.Settings
	if err := json.Unmarshal(v.Settings, &s); err != nil {
		return nil, fmt.Errorf("stored settings version %d: %w", v.ID, err)
	}
	c, err := r.File.Overlay(s, v.ID)
	if err != nil {
		return nil, fmt.Errorf("stored settings version %d no longer validate against %s: %w", v.ID, r.File.Path, err)
	}
	return c, nil
}

// SaveSettings validates s against the file's host settings and stores it
// as a new version based on base (ErrStaleVersion if another edit came
// first). An unchanged configuration stores nothing.
func (r *Runtime) SaveSettings(ctx context.Context, base int64, s syncapi.Settings, actor, origin, comment string) (int64, []syncapi.Change, error) {
	cur, err := r.Effective(ctx)
	if err != nil {
		return 0, nil, err
	}
	if base != cur.SettingsVersion {
		return 0, nil, store.ErrStaleVersion
	}
	next, err := r.File.Overlay(s, 0)
	if err != nil {
		return 0, nil, err
	}
	norm := config.SettingsOf(next)
	changes := syncapi.DiffSettings(config.SettingsOf(cur), norm)
	if len(changes) == 0 && cur.SettingsVersion != 0 {
		return cur.SettingsVersion, nil, nil
	}
	raw, err := json.Marshal(norm)
	if err != nil {
		return 0, nil, err
	}
	ch, _ := json.Marshal(changes)
	id, err := r.Store.SaveConfig(ctx, base, actor, origin, comment, raw, ch)
	if err != nil {
		return 0, nil, err
	}
	return id, changes, nil
}

// Box returns the state-key box (secrets at rest).
func (r *Runtime) Box() (*secretbox.Box, error) {
	b, err := secret.Load(r.File.API.StateKeyCredential)
	if err != nil {
		return nil, fmt.Errorf("state key (api.state_key_credential): %w", err)
	}
	return secretbox.New(b)
}

type keyMeta struct {
	ClientEmail string `json:"client_email"`
	KeyID       string `json:"key_id"`
}

// SetKey validates and stores a service account key, encrypted.
func (r *Runtime) SetKey(ctx context.Context, keyJSON []byte, actor string) (*syncapi.KeyInfo, error) {
	k, err := google.ParseServiceAccountKey(keyJSON)
	if err != nil {
		return nil, err
	}
	box, err := r.Box()
	if err != nil {
		return nil, err
	}
	nonce, ct, err := box.Seal(GoogleKeySecret, keyJSON)
	if err != nil {
		return nil, err
	}
	meta, _ := json.Marshal(keyMeta{ClientEmail: k.ClientEmail, KeyID: k.PrivateKeyID})
	if err := r.Store.PutSecret(ctx, store.SecretRow{Name: GoogleKeySecret, Nonce: nonce, Ciphertext: ct, Meta: meta, Actor: actor}); err != nil {
		return nil, err
	}
	return r.KeyInfo(ctx, r.File)
}

// KeyInfo describes the key in use (nil when there is none). The stored
// key wins over google.key_credential.
func (r *Runtime) KeyInfo(ctx context.Context, cfg *config.Config) (*syncapi.KeyInfo, error) {
	row, err := r.Store.GetSecret(ctx, GoogleKeySecret)
	if err != nil {
		return nil, err
	}
	if row != nil {
		var m keyMeta
		_ = json.Unmarshal(row.Meta, &m)
		return &syncapi.KeyInfo{ClientEmail: m.ClientEmail, KeyID: m.KeyID, SetAt: row.UpdatedAt, SetBy: row.Actor, Source: "database"}, nil
	}
	if cfg.Google.KeyCredential == "" {
		return nil, nil
	}
	b, err := secret.Load(cfg.Google.KeyCredential)
	if err != nil {
		return nil, nil
	}
	k, err := google.ParseServiceAccountKey(b)
	if err != nil {
		return nil, nil
	}
	return &syncapi.KeyInfo{ClientEmail: k.ClientEmail, KeyID: k.PrivateKeyID, Source: "credential"}, nil
}

// ErrNoKey means no service account key is configured.
var ErrNoKey = errors.New("no Google service account key: set it in conductor (Google Workspace sync > Setup) or name a credential in google.key_credential")

// ServiceAccountKey loads the key in use: the stored one (decrypted with
// the state key) or the credential file.
func (r *Runtime) ServiceAccountKey(ctx context.Context, cfg *config.Config) (*google.ServiceAccountKey, error) {
	row, err := r.Store.GetSecret(ctx, GoogleKeySecret)
	if err != nil {
		return nil, err
	}
	var raw []byte
	switch {
	case row != nil:
		box, err := r.Box()
		if err != nil {
			return nil, err
		}
		if raw, err = box.Open(GoogleKeySecret, row.Nonce, row.Ciphertext); err != nil {
			return nil, err
		}
	case cfg.Google.KeyCredential != "":
		if raw, err = secret.Load(cfg.Google.KeyCredential); err != nil {
			return nil, err
		}
	default:
		return nil, ErrNoKey
	}
	return google.ParseServiceAccountKey(raw)
}

// Connector opens the Google connector with the key in use.
func (r *Runtime) Connector(ctx context.Context, cfg *config.Config, write bool) (connector.Connector, error) {
	k, err := r.ServiceAccountKey(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return r.Connect(cfg.Google, k, write)
}

// Engine builds an engine for one actor with cfg.
func (r *Runtime) Engine(ctx context.Context, cfg *config.Config, actor string, out io.Writer) (*engine.Engine, error) {
	if out == nil {
		out = r.Stderr
	}
	var senders alert.Multi
	senders = append(senders, alert.Log{W: out})
	if cfg.Alert.WebhookURL != "" {
		wh := alert.Webhook{URL: cfg.Alert.WebhookURL}
		if cfg.Alert.WebhookSecretCredential != "" {
			b, err := secret.Load(cfg.Alert.WebhookSecretCredential)
			if err != nil {
				return nil, err
			}
			wh.Secret = []byte(strings.TrimSpace(string(b)))
		}
		senders = append(senders, wh)
	}
	var key *google.ServiceAccountKey
	connect := func(write bool) (connector.Connector, error) {
		if key == nil {
			k, err := r.ServiceAccountKey(context.WithoutCancel(ctx), cfg)
			if err != nil {
				return nil, err
			}
			key = k
		}
		return r.Connect(cfg.Google, key, write)
	}
	return &engine.Engine{
		Store:         r.Store,
		Source:        r.NewSource(cfg),
		Connect:       connect,
		ConnectorName: cfg.Connector,
		Policy:        cfg.PlanPolicy(),
		Limits:        cfg.Limits,
		Mode:          cfg.Mode,
		MaxFailures:   cfg.MaxFailures,
		Alert:         senders,
		MetricsPath:   cfg.MetricsFile,
		LockPath:      cfg.LockPath(),
		Actor:         actor,
		Host:          engine.Hostname(),
		Out:           out,
		Now:           r.Now,
	}, nil
}

// LazySource loads the bind password only when the source is read.
type LazySource struct {
	Cfg *config.Config
	r   *adsource.Reader
}

func (l *LazySource) reader() (*adsource.Reader, error) {
	if l.r == nil {
		pw, err := secret.LoadString(l.Cfg.Source.PasswordCredential)
		if err != nil {
			return nil, err
		}
		r, err := adsource.NewReader(l.Cfg.Source, l.Cfg.Rules, pw)
		if err != nil {
			return nil, err
		}
		l.r = r
	}
	return l.r, nil
}

// Read implements source.Source.
func (l *LazySource) Read(ctx context.Context) (*source.Result, error) {
	r, err := l.reader()
	if err != nil {
		return nil, err
	}
	return r.Read(ctx)
}

// Check implements Source.
func (l *LazySource) Check(ctx context.Context) (string, []model.ScopeGroup, error) {
	r, err := l.reader()
	if err != nil {
		return "", nil, err
	}
	return r.Check(ctx)
}

// Preview implements Source.
func (l *LazySource) Preview(ctx context.Context, query string, limit int) ([]adsource.Preview, []model.ScopeGroup, error) {
	r, err := l.reader()
	if err != nil {
		return nil, nil, err
	}
	return r.Preview(ctx, query, limit)
}
