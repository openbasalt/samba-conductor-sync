// Package alert delivers conductor-sync alerts (a blocked scheduled run, a
// partial or failed apply, an interrupted run, a manual deletion): always
// to the log (journald via stderr), and optionally to a JSON webhook signed
// with HMAC-SHA256. Alerts carry counts and addresses, never secrets.
// The systemd unit's OnFailure= can chain any other notifier, since a
// blocked or failed scheduled run also exits non-zero.
package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Alert is one notification.
type Alert struct {
	Kind      string    `json:"kind"`
	Connector string    `json:"connector"`
	RunID     int64     `json:"run_id"`
	Host      string    `json:"host"`
	Subject   string    `json:"subject"`
	Text      string    `json:"text"`
	At        time.Time `json:"at"`
}

// Alert kinds.
const (
	KindBlocked     = "blocked"
	KindPartial     = "partial"
	KindFailed      = "failed"
	KindInterrupted = "interrupted"
	KindDeleted     = "deleted"
)

// Sender delivers alerts.
type Sender interface {
	Send(ctx context.Context, a Alert) error
}

// Log writes alerts as one line each.
type Log struct{ W io.Writer }

// Send implements Sender.
func (l Log) Send(_ context.Context, a Alert) error {
	_, err := fmt.Fprintf(l.W, "ALERT [%s] %s: %s\n", a.Kind, a.Subject, strings.ReplaceAll(a.Text, "\n", " | "))
	return err
}

// Webhook posts the alert as JSON. With a secret, the body's
// HMAC-SHA256 is sent in X-Conductor-Signature ("sha256=<hex>").
type Webhook struct {
	URL    string
	Secret []byte
	Client *http.Client
}

// ValidateWebhookURL accepts https, or http only to a loopback relay.
func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("alert.webhook_url is not a URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return errors.New("alert.webhook_url must be https (http only to a loopback relay)")
}

// Send implements Sender.
func (w Webhook) Send(ctx context.Context, a Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(w.Secret) > 0 {
		m := hmac.New(sha256.New, w.Secret)
		m.Write(body)
		req.Header.Set("X-Conductor-Signature", "sha256="+hex.EncodeToString(m.Sum(nil)))
	}
	hc := w.Client
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("alert webhook: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("alert webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Multi sends to every sender and joins the errors.
type Multi []Sender

// Send implements Sender.
func (m Multi) Send(ctx context.Context, a Alert) error {
	var errs []error
	for _, s := range m {
		if err := s.Send(ctx, a); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Recorder keeps alerts in memory (tests).
type Recorder struct{ Alerts []Alert }

// Send implements Sender.
func (r *Recorder) Send(_ context.Context, a Alert) error {
	r.Alerts = append(r.Alerts, a)
	return nil
}
