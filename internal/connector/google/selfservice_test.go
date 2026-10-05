package google_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/connector/google"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
)

// TestSelfServicePasswords: an on-demand create and a password change
// carry the user's password once, with no change required at next sign-in;
// the reset's PATCH has no other field; the request log has field names
// only; a password refused by the tenant is connector.ErrInvalid.
func TestSelfServicePasswords(t *testing.T) {
	fake := fakegoogle.New("example.com")
	srv := httptest.NewTLSServer(fake)
	t.Cleanup(srv.Close)
	fake.SetTokenURL(srv.URL + "/token")
	key, err := google.ParseServiceAccountKey(fake.KeyJSON())
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	c, err := google.New(google.Config{AdminSubject: fake.AdminSubject, KeyCredential: "x", APIBaseURL: srv.URL, RequestsPerSecond: 1e6},
		key, true, google.Options{HTTPClient: srv.Client(), RequestLog: &log})
	if err != nil {
		t.Fatal(err)
	}
	var ss connector.SelfService = c
	if caps := ss.Capabilities(); !caps.OnDemandCreate || !caps.SetPassword || !caps.PasswordRules || caps.Title == "" {
		t.Fatalf("capabilities %+v", caps)
	}
	if r := ss.Rules(); r.MinLength != 8 || r.MaxLength != 100 || !r.PrintableASCII {
		t.Fatalf("rules %+v", r)
	}
	ctx := context.Background()
	const first, second = "Kq7v-Xm2p-Rt4w-Hn8c", "another long passphrase 9"
	id, err := ss.CreateUserWithPassword(ctx, "guid-1", attrs("ana@example.com"), first)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := fake.User(id)
	if u.ChangePasswordNext || !fake.PasswordMatches(id, first) || u.Suspended {
		t.Fatalf("created %+v", u)
	}
	if err := ss.SetPassword(ctx, id, second); err != nil {
		t.Fatal(err)
	}
	if !fake.PasswordMatches(id, second) {
		t.Fatal("password not set")
	}
	w := fake.Writes()
	if last := w[len(w)-1]; last.Method != http.MethodPatch || strings.Join(last.Fields, ",") != "changePasswordAtNextLogin,password" {
		t.Fatalf("reset write %+v", last)
	}
	// The retried create of the same user (a timeout after the insert)
	// still leaves the account with the user's password.
	if id2, err := ss.CreateUserWithPassword(ctx, "guid-1", attrs("ana@example.com"), first); err != nil || id2 != id || !fake.PasswordMatches(id, first) {
		t.Fatalf("retried create: %v %s", err, id2)
	}
	fake.SetMinPasswordLength(40)
	err = ss.SetPassword(ctx, id, second)
	if !errors.Is(err, connector.ErrInvalid) || strings.Contains(err.Error(), second) {
		t.Fatalf("refused password: %v", err)
	}
	out := log.String()
	for _, secret := range []string{first, second} {
		if strings.Contains(out, secret) {
			t.Fatalf("request log carries the password:\n%s", out)
		}
	}
}
