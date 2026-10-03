package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookSigned(t *testing.T) {
	var sig string
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get("X-Conductor-Signature")
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	wh := Webhook{URL: srv.URL, Secret: []byte("k"), Client: srv.Client()}
	if err := wh.Send(context.Background(), Alert{Kind: KindBlocked, Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, []byte("k"))
	m.Write(body)
	if sig != "sha256="+hex.EncodeToString(m.Sum(nil)) {
		t.Fatalf("signature %q", sig)
	}
}

func TestValidateWebhookURL(t *testing.T) {
	for _, ok := range []string{"https://hooks.example.com/x", "http://127.0.0.1:9000/a", "http://localhost/a"} {
		if err := ValidateWebhookURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://hooks.example.com", "ftp://x", "nope"} {
		if err := ValidateWebhookURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
