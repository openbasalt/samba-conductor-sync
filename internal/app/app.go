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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/alert"
	"github.com/openbasalt/samba-conductor-sync/internal/config"
	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/connector/google"
	"github.com/openbasalt/samba-conductor-sync/internal/engine"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/secret"
	"github.com/openbasalt/samba-conductor-sync/internal/secretbox"
	"github.com/openbasalt/samba-conductor-sync/internal/source"
	"github.com/openbasalt/samba-conductor-sync/internal/source/adsource"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// Names of the secrets in the state database (also the additional data of
// their encryption).
const (
	GoogleKeySecret     = "google-service-account-key"
	ADPasswordSecret    = "ad-bind-password"
	WebhookSecretSecret = "alert-webhook-secret"
)

// storedName maps an API secret name to its database name.
var storedName = map[string]string{
	syncapi.SecretADBindPassword: ADPasswordSecret,
	syncapi.SecretGoogleKey:      GoogleKeySecret,
	syncapi.SecretWebhookSecret:  WebhookSecretSecret,
}

// StoredName returns the database name of an API secret name ("" when
// unknown).
func StoredName(apiName string) string { return storedName[apiName] }

// Settings version origins.
const (
	OriginBootstrap = "bootstrap"
	OriginAPI       = "api"
	OriginCLI       = "cli"
	OriginRollback  = "rollback"
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
	Ping(ctx context.Context) (string, error)
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

// RequestLogEnv names a file that receives the Google request log (field
// names only, see google.Options.RequestLog), for audits of what a run
// sent. Unset: no log.
const RequestLogEnv = "CONDUCTOR_SYNC_REQUEST_LOG"

var (
	reqLogOnce sync.Once
	reqLogFile io.Writer
)

// requestLog opens the request log once per process (append, 0600).
func requestLog() io.Writer {
	reqLogOnce.Do(func() {
		path := os.Getenv(RequestLogEnv)
		if path == "" {
			return
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "conductor-sync: %s: %v (request log off)\n", RequestLogEnv, err)
			return
		}
		reqLogFile = f
	})
	return reqLogFile
}

// New builds a runtime around an already open store.
func New(cfg *config.Config, st *store.Store, stderr io.Writer) *Runtime {
	if stderr == nil {
		stderr = io.Discard
	}
	r := &Runtime{File: cfg, Store: st, Stderr: stderr, Now: time.Now}
	r.Connect = func(gc google.Config, key *google.ServiceAccountKey, write bool) (connector.Connector, error) {
		return google.New(gc, key, write, google.Options{RequestLog: requestLog()})
	}
	r.NewSource = func(c *config.Config) Source {
		return &LazySource{Cfg: c, Password: func() (string, error) { return r.ADPassword(context.Background(), c) }}
	}
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
	return r.SaveSettingsWith(ctx, base, s, actor, origin, comment, nil)
}

// SealedSecret is a secret to store together with a settings version.
type SealedSecret struct {
	// APIName is the syncapi secret name.
	APIName string
	Value   []byte
}

// SaveSettingsWith is SaveSettings, also storing secrets (encrypted) in
// the same transaction. With secrets, a version is stored even when no
// setting changed (the version records who replaced them).
func (r *Runtime) SaveSettingsWith(ctx context.Context, base int64, s syncapi.Settings, actor, origin, comment string, secrets []SealedSecret) (int64, []syncapi.Change, error) {
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
	if len(changes) == 0 && cur.SettingsVersion != 0 && len(secrets) == 0 {
		return cur.SettingsVersion, nil, nil
	}
	raw, err := json.Marshal(norm)
	if err != nil {
		return 0, nil, err
	}
	var rows []store.SecretRow
	for _, sec := range secrets {
		row, err := r.seal(sec.APIName, sec.Value, actor)
		if err != nil {
			return 0, nil, err
		}
		rows = append(rows, row)
	}
	ch, _ := json.Marshal(changes)
	id, err := r.Store.SaveConfig(ctx, base, actor, origin, comment, raw, ch, rows...)
	if err != nil {
		return 0, nil, err
	}
	return id, changes, nil
}

// VersionSettings returns the settings of a stored version.
func (r *Runtime) VersionSettings(ctx context.Context, id int64) (*store.ConfigVersion, *syncapi.Settings, error) {
	v, err := r.Store.GetConfig(ctx, id)
	if err != nil || v == nil {
		return nil, nil, err
	}
	var s syncapi.Settings
	if err := json.Unmarshal(v.Settings, &s); err != nil {
		return nil, nil, fmt.Errorf("stored settings version %d: %w", id, err)
	}
	return v, &s, nil
}

// Box returns the state-key box (secrets at rest).
func (r *Runtime) Box() (*secretbox.Box, error) {
	b, err := secret.Load(r.File.API.StateKeyCredential)
	if err != nil {
		return nil, fmt.Errorf("state key (api.state_key_credential): %w", err)
	}
	return secretbox.New(b)
}

// seal encrypts a secret value into a row (not stored yet).
func (r *Runtime) seal(apiName string, value []byte, actor string) (store.SecretRow, error) {
	name := storedName[apiName]
	if name == "" {
		return store.SecretRow{}, fmt.Errorf("unknown secret %q", apiName)
	}
	box, err := r.Box()
	if err != nil {
		return store.SecretRow{}, err
	}
	nonce, ct, err := box.Seal(name, value)
	if err != nil {
		return store.SecretRow{}, err
	}
	return store.SecretRow{Name: name, Nonce: nonce, Ciphertext: ct, Actor: actor}, nil
}

// SetSecret validates and stores a secret (encrypted). The Google key goes
// through SetKey.
func (r *Runtime) SetSecret(ctx context.Context, apiName string, value []byte, actor string) error {
	if err := syncapi.ValidateSecret(apiName, string(value)); err != nil {
		return err
	}
	row, err := r.seal(apiName, value, actor)
	if err != nil {
		return err
	}
	return r.Store.PutSecret(ctx, row)
}

// RemoveSecret deletes a stored secret; it reports whether one was stored.
func (r *Runtime) RemoveSecret(ctx context.Context, apiName string) (bool, error) {
	name := storedName[apiName]
	if name == "" {
		return false, fmt.Errorf("unknown secret %q", apiName)
	}
	return r.Store.DeleteSecret(ctx, name)
}

// openStored decrypts a stored secret (nil when none is stored).
func (r *Runtime) openStored(ctx context.Context, name string) ([]byte, error) {
	row, err := r.Store.GetSecret(ctx, name)
	if err != nil || row == nil {
		return nil, err
	}
	box, err := r.Box()
	if err != nil {
		return nil, err
	}
	return box.Open(name, row.Nonce, row.Ciphertext)
}

// ErrNoADPassword means no AD bind password is configured.
var ErrNoADPassword = errors.New("no AD bind password: set it in conductor (Google Workspace sync > Settings > Connection), with `conductor-sync secret set ad-bind-password`, or name a credential in source.password_credential")

// ADPassword returns the AD bind password in use: a connection test's
// override, else the stored one (decrypted with the state key), else the
// credential named by source.password_credential.
func (r *Runtime) ADPassword(ctx context.Context, cfg *config.Config) (string, error) {
	if pw := cfg.ADPasswordOverride(); pw != "" {
		return pw, nil
	}
	b, err := r.openStored(ctx, ADPasswordSecret)
	if err != nil {
		return "", fmt.Errorf("stored AD bind password: %w", err)
	}
	if b != nil {
		return string(b), nil
	}
	if cfg.Source.PasswordCredential == "" {
		return "", ErrNoADPassword
	}
	return secret.LoadString(cfg.Source.PasswordCredential)
}

// WebhookSecret returns the HMAC key of the alert webhook (nil = unsigned):
// the stored one, else the credential named by
// alert.webhook_secret_credential.
func (r *Runtime) WebhookSecret(ctx context.Context, cfg *config.Config) ([]byte, error) {
	b, err := r.openStored(ctx, WebhookSecretSecret)
	if err != nil {
		return nil, fmt.Errorf("stored webhook secret: %w", err)
	}
	if b != nil {
		return b, nil
	}
	if cfg.Alert.WebhookSecretCredential == "" {
		return nil, nil
	}
	b, err = secret.Load(cfg.Alert.WebhookSecretCredential)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(b))), nil
}

// Secrets describes every secret: whether it is configured, where it comes
// from, who set it. Values are never returned (nor fingerprints).
func (r *Runtime) Secrets(ctx context.Context, cfg *config.Config) ([]syncapi.SecretInfo, error) {
	out := make([]syncapi.SecretInfo, 0, len(syncapi.SecretNames))
	for _, apiName := range syncapi.SecretNames {
		info := syncapi.SecretInfo{Name: apiName}
		var cred string
		switch apiName {
		case syncapi.SecretADBindPassword:
			cred = cfg.Source.PasswordCredential
		case syncapi.SecretGoogleKey:
			cred = cfg.Google.KeyCredential
		case syncapi.SecretWebhookSecret:
			cred = cfg.Alert.WebhookSecretCredential
		}
		info.Credential = cred
		row, err := r.Store.GetSecret(ctx, storedName[apiName])
		if err != nil {
			return nil, err
		}
		switch {
		case row != nil:
			info.Configured, info.Source, info.SetAt, info.SetBy = true, "database", row.UpdatedAt, row.Actor
		case cred != "":
			if _, err := secret.Load(cred); err != nil {
				// The reason names the file, never its content.
				info.Error = err.Error()
			} else {
				info.Configured, info.Source = true, "credential"
			}
		}
		out = append(out, info)
	}
	return out, nil
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
	row, err := r.seal(syncapi.SecretGoogleKey, keyJSON, actor)
	if err != nil {
		return nil, err
	}
	row.Meta, _ = json.Marshal(keyMeta{ClientEmail: k.ClientEmail, KeyID: k.PrivateKeyID})
	if err := r.Store.PutSecret(ctx, row); err != nil {
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
	raw, err := r.openStored(ctx, GoogleKeySecret)
	if err != nil {
		return nil, err
	}
	switch {
	case raw != nil:
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
		b, err := r.WebhookSecret(ctx, cfg)
		if err != nil {
			return nil, err
		}
		wh.Secret = b
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
	// Password returns the bind password (Runtime.ADPassword); nil: the
	// credential named by source.password_credential.
	Password func() (string, error)
	r        *adsource.Reader
}

func (l *LazySource) reader() (*adsource.Reader, error) {
	if l.r == nil {
		var pw string
		var err error
		if l.Password != nil {
			pw, err = l.Password()
		} else {
			pw, err = secret.LoadString(l.Cfg.Source.PasswordCredential)
		}
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

// Ping implements Source.
func (l *LazySource) Ping(ctx context.Context) (string, error) {
	r, err := l.reader()
	if err != nil {
		return "", err
	}
	return r.Ping(ctx)
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
