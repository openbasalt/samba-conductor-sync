//go:build lab

package labtest

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/source/adsource"
)

// TestLabConnectionPing signs in to the lab AD the way a connection change
// is checked before it is saved (P5c): the CA given inline, both
// authentication methods; a wrong password and an unknown DC are refused.
func TestLabConnectionPing(t *testing.T) {
	l := loadLab(t)
	ca, err := os.ReadFile(l.caFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg := adsource.Config{Realm: realm, DCs: []string{dc}, DNSServers: []string{dcIP}, CAPEM: string(ca), BindUser: "svc.sync",
		UserBases: []string{lab}}
	ctx := context.Background()
	for _, auth := range []string{"simple", "kerberos"} {
		cfg.Auth = auth
		r, err := adsource.NewReader(cfg, rules(t), l.bindPW)
		if err != nil {
			t.Fatal(err)
		}
		detail, err := r.Ping(ctx)
		if err != nil || !strings.Contains(detail, "svc.sync") {
			t.Fatalf("%s ping: %q %v", auth, detail, err)
		}
		r, _ = adsource.NewReader(cfg, rules(t), l.bindPW+"-wrong")
		if _, err := r.Ping(ctx); err == nil {
			t.Fatalf("%s: a wrong password signed in", auth)
		} else if strings.Contains(err.Error(), l.bindPW) {
			t.Fatal("the error carries the password")
		}
	}
	cfg.Auth = "simple"
	cfg.DCs = []string{"dc9.sync.conductor.test"}
	r, _ := adsource.NewReader(cfg, rules(t), l.bindPW)
	if _, err := r.Ping(ctx); err == nil {
		t.Fatal("an unknown DC signed in")
	}
}
