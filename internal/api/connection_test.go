package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/app"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// testCAPEM returns a self-signed CA certificate in PEM.
func testCAPEM(t *testing.T, cn string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// The secret values used below; none may ever leave conductor-sync.
const (
	pwOne   = "Bind-Password-One-7f3a"
	pwTwo   = "Bind-Password-Two-91c4"
	whValue = "webhook-hmac-secret-0123456789abcdef"
)

func TestConnectionSettingsSecretsAndRollback(t *testing.T) {
	e := newTEnv(t)
	var logs bytes.Buffer
	e.srv.log = slog.New(slog.NewTextHandler(&logs, nil))
	ctx := context.Background()

	// Initial view: the connection comes from the file; no secret stored
	// (the ad-bind credential file does not exist: reported, not fatal).
	v, s := e.settings()
	if v.Host.ConnectionStored || s.Connection == nil || s.Connection.AD.Realm != "LAB.TEST" || s.Connection.Marker != "conductor-sync" ||
		s.Connection.AD.Auth != "kerberos" || s.Connection.Google.RequestsPerSecond != 10000 {
		t.Fatalf("initial connection %+v host %+v", s.Connection, v.Host)
	}
	if bp := v.Secret(syncapi.SecretADBindPassword); bp.Configured || bp.Credential != "ad-bind" || bp.Error == "" {
		t.Fatalf("bind password state %+v", bp)
	}
	if gk := v.Secret(syncapi.SecretGoogleKey); gk.Configured {
		t.Fatalf("google key state %+v", gk)
	}

	// The AD bind password: refused when AD refuses it, stored encrypted
	// when the sign-in works; the state never carries the value.
	e.src.pingErr = errors.New("LDAP Result Code 49 \"Invalid Credentials\"")
	if err := e.call(syncapi.OpSecretSet, syncapi.SecretSetParams{Name: syncapi.SecretADBindPassword, Value: pwOne}, nil); err == nil || err.Code != syncapi.CodeInvalid {
		t.Fatalf("bad password stored: %v", err)
	}
	if row, _ := e.rt.Store.GetSecret(ctx, app.ADPasswordSecret); row != nil {
		t.Fatal("a refused password was stored")
	}
	e.src.pingErr = nil
	var si syncapi.SecretInfo
	e.must(syncapi.OpSecretSet, syncapi.SecretSetParams{Name: syncapi.SecretADBindPassword, Value: pwOne}, &si)
	if !si.Configured || si.Source != "database" || si.SetBy != "conductor:lab.admin@10.0.0.5" || si.SetAt.IsZero() {
		t.Fatalf("stored password state %+v", si)
	}
	if e.src.lastPassword != pwOne {
		t.Fatal("the sign-in test did not use the new password")
	}
	row, _ := e.rt.Store.GetSecret(ctx, app.ADPasswordSecret)
	if row == nil || bytes.Contains(row.Ciphertext, []byte(pwOne)) {
		t.Fatal("password not encrypted at rest")
	}
	cfg, _ := e.rt.Effective(ctx)
	if pw, err := e.rt.ADPassword(ctx, cfg); err != nil || pw != pwOne {
		t.Fatalf("password in use: %v", err)
	}
	e.must(syncapi.OpSecretSet, syncapi.SecretSetParams{Name: syncapi.SecretADBindPassword, Value: pwTwo}, &si)

	// The webhook secret: stored, used by the alert sender, never shown.
	e.must(syncapi.OpSecretSet, syncapi.SecretSetParams{Name: syncapi.SecretWebhookSecret, Value: whValue}, &si)
	if b, err := e.rt.WebhookSecret(ctx, cfg); err != nil || string(b) != whValue {
		t.Fatalf("webhook secret in use: %v", err)
	}

	// Connection: a new DC list and realm are saved only after a sign-in
	// with them works.
	v, s = e.settings()
	s.Connection.AD.Realm = "lab2.test"
	s.Connection.AD.DCs = []string{"dc1.lab2.test", "10.95.0.11"}
	s.Connection.AD.DNSServers = []string{"10.95.0.11", "10.95.0.12:5353"}
	e.src.pingErr = errors.New("connect: dial tcp: no route to host")
	pings := e.src.pings
	if err := e.call(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: v.Version, Settings: s}, nil); err == nil || err.Code != syncapi.CodeInvalid ||
		!strings.Contains(strings.Join(err.Details, " "), "no route") || e.src.pings != pings+1 {
		t.Fatalf("unreachable AD saved: %v", err)
	}
	e.src.pingErr = nil
	var ur syncapi.ConfigUpdateResult
	e.must(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: v.Version, Settings: s, Comment: "second site"}, &ur)
	if ur.Version != 1 || e.src.lastCfg.Source.Realm != "LAB2.TEST" {
		t.Fatalf("update %+v", ur)
	}
	v, s = e.settings()
	if !v.Host.ConnectionStored || s.Connection.AD.Realm != "LAB2.TEST" || len(s.Connection.AD.DNSServers) != 2 {
		t.Fatalf("stored connection %+v", s.Connection)
	}

	// Invalid values are rejected with every reason.
	bad := s
	badConn := *s.Connection
	badConn.AD.DCs = []string{"dc1 ; rm -rf", "-x"}
	badConn.AD.DNSServers = []string{"dns.example.com"}
	badConn.AD.CAPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	badConn.AD.Auth = "ntlm"
	badConn.Google.RequestsPerSecond = 0
	badConn.Google.Timeout = "1ms"
	badConn.Marker = "has space"
	badConn.Alert.WebhookURL = "http://203.0.113.5/hook"
	bad.Connection = &badConn
	var vr syncapi.ConfigValidateResult
	e.must(syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: bad}, &vr)
	if vr.Valid || len(vr.Errors) < 8 {
		t.Fatalf("validation %+v", vr.Errors)
	}

	// The CA content: diffs and the audit summarize it; the export has it.
	ca := testCAPEM(t, "Lab Root CA")
	s.Connection.AD.CAPEM = ca
	e.must(syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: s}, &vr)
	if !vr.Valid || len(vr.Changes) != 1 || vr.Changes[0].Path != "connection.ad.ca_pem" || !strings.HasPrefix(vr.Changes[0].New, "1 certificate(s), sha256 ") {
		t.Fatalf("CA diff %+v", vr)
	}
	e.must(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: v.Version, Settings: s}, &ur)
	var ex syncapi.ConfigExport
	e.must(syncapi.OpConfigExport, nil, &ex)
	if !strings.Contains(ex.TOML, "BEGIN CERTIFICATE") || !strings.Contains(ex.TOML, `realm = "LAB2.TEST"`) {
		t.Fatalf("export lacks the connection:\n%s", ex.TOML)
	}

	// The marker: refused without (or with a wrong) typed confirmation.
	v, s = e.settings()
	s.Connection.Marker = "conductor-sync-b"
	for _, conf := range []string{"", "change marker to conductor-sync"} {
		if err := e.call(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: v.Version, Settings: s, MarkerConfirmation: conf}, nil); err == nil || err.Code != syncapi.CodeInvalid {
			t.Fatalf("marker change with %q: %v", conf, err)
		}
	}
	e.must(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: v.Version, Settings: s,
		MarkerConfirmation: syncapi.MarkerConfirmation("conductor-sync-b")}, &ur)

	// A new bind account with its password, in one version.
	v, s = e.settings()
	s.Connection.AD.BindUser = "svc.sync2"
	e.must(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: v.Version, Settings: s, ADPassword: pwOne}, &ur)
	if len(ur.Secrets) != 1 || e.src.lastPassword != pwOne || e.src.lastCfg.Source.BindUser != "svc.sync2" {
		t.Fatalf("bind account change %+v", ur)
	}
	cfg, _ = e.rt.Effective(ctx)
	if pw, _ := e.rt.ADPassword(ctx, cfg); pw != pwOne {
		t.Fatal("password not replaced with the version")
	}

	// Connection test with a password that is not stored.
	var tr syncapi.TestResult
	e.must(syncapi.OpConnectionTest, syncapi.ConnectionTestParams{Settings: &s, ADPassword: pwTwo}, &tr)
	if e.src.lastPassword != pwTwo || !tr.AD.OK {
		t.Fatalf("test %+v", tr)
	}

	// Rollback to version 1: the settings come back (the marker change
	// needs its confirmation again), secrets stay as they are.
	v, _ = e.settings()
	var old syncapi.ConfigVersionDetail
	e.must(syncapi.OpConfigVersion, syncapi.ConfigVersionParams{ID: 1}, &old)
	if old.Settings.Connection == nil || old.Settings.Connection.Marker != "conductor-sync" || old.Comment != "second site" {
		t.Fatalf("version 1 %+v", old)
	}
	if err := e.call(syncapi.OpConfigRollback, syncapi.ConfigRollbackParams{BaseVersion: v.Version, Version: 1}, nil); err == nil || err.Code != syncapi.CodeInvalid {
		t.Fatalf("rollback across a marker change without confirmation: %v", err)
	}
	if err := e.call(syncapi.OpConfigRollback, syncapi.ConfigRollbackParams{BaseVersion: v.Version, Version: 99}, nil); err == nil || err.Code != syncapi.CodeNotFound {
		t.Fatalf("rollback to an unknown version: %v", err)
	}
	e.must(syncapi.OpConfigRollback, syncapi.ConfigRollbackParams{BaseVersion: v.Version, Version: 1, Comment: "undo",
		MarkerConfirmation: syncapi.MarkerConfirmation("conductor-sync")}, &ur)
	v, s = e.settings()
	if s.Connection.Marker != "conductor-sync" || s.Connection.AD.BindUser != "svc.sync" || s.Connection.AD.CAPEM != "" || v.Version != ur.Version {
		t.Fatalf("after rollback %+v", s.Connection)
	}
	var hist []syncapi.ConfigVersion
	e.must(syncapi.OpConfigHistory, syncapi.ConfigHistoryParams{}, &hist)
	if hist[0].Origin != app.OriginRollback || hist[0].Comment != "undo" {
		t.Fatalf("history head %+v", hist[0])
	}
	if pw, _ := e.rt.ADPassword(ctx, cfg); pw != pwOne {
		t.Fatal("a rollback changed a secret")
	}

	// Removal: the credential file (absent here) would be used again.
	e.must(syncapi.OpSecretRemove, syncapi.SecretRemoveParams{Name: syncapi.SecretWebhookSecret}, &si)
	if si.Configured {
		t.Fatalf("after removal %+v", si)
	}
	if err := e.call(syncapi.OpSecretRemove, syncapi.SecretRemoveParams{Name: syncapi.SecretWebhookSecret}, nil); err == nil || err.Code != syncapi.CodeNotFound {
		t.Fatalf("second removal: %v", err)
	}

	// No secret value in the audit, the logs or any result, and the chain
	// is intact.
	var audit bytes.Buffer
	_, _ = e.rt.Store.ExportAudit(ctx, &audit)
	var view bytes.Buffer
	v, _ = e.settings()
	_ = json.NewEncoder(&view).Encode(v)
	for _, where := range map[string]string{"audit": audit.String(), "logs": logs.String(), "view": view.String()} {
		for _, secret := range []string{pwOne, pwTwo, whValue} {
			if strings.Contains(where, secret) {
				t.Fatalf("a secret value leaked")
			}
		}
	}
	// (The export is JSON lines: ">" appears escaped as >.)
	for _, want := range []string{"secret ad_bind_password: set", "secret ad_bind_password: replaced", "secret alert_webhook_secret: removed",
		"rollback to version 1", "connection.ad.dcs", `connection.marker: conductor-sync -\\u003e conductor-sync-b`, `"action":"config.rollback"`} {
		if !strings.Contains(audit.String(), want) {
			t.Errorf("audit lacks %q", want)
		}
	}
	var av syncapi.AuditState
	e.must(syncapi.OpAuditVerify, nil, &av)
	if !av.Intact {
		t.Fatalf("audit %+v", av)
	}
}

// A stored version from before P5c has no connection settings: the file's
// stay in force until a version with them is stored.
func TestPreP5cVersionKeepsFileConnection(t *testing.T) {
	e := newTEnv(t)
	ctx := context.Background()
	_, s := e.settings()
	s.Connection = nil
	s.Mode = "apply"
	raw, _ := json.Marshal(s)
	if _, err := e.rt.Store.SaveConfig(ctx, 0, "test", app.OriginAPI, "", raw, nil); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.rt.Effective(ctx)
	if err != nil || cfg.Mode != "apply" || cfg.ConnectionStored || cfg.Source.Realm != "LAB.TEST" {
		t.Fatalf("effective %+v %v", cfg, err)
	}
}
