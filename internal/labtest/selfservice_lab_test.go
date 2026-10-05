//go:build lab

package labtest

import (
	"context"
	"strings"
	"testing"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-sync/internal/engine"
	"github.com/openbasalt/samba-conductor-sync/internal/mapping"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// samSID returns the objectSid of a user by logon name.
func samSID(t *testing.T, c *ad.Conn, sam string) string {
	t.Helper()
	es, err := c.SearchAll(context.Background(), ad.SearchRequest{BaseDN: baseDN, Filter: escape.Eq("sAMAccountName", sam),
		Attributes: ad.UserAttributes, Limit: 2})
	if err != nil || len(es) != 1 {
		t.Fatalf("user %s: %v (%d entries)", sam, err, len(es))
	}
	return ad.UserFromEntry(es[0]).SID.String()
}

// TestLabSelfService: the one-user AD lookup against the real Samba (same
// scope rules as the full read: include groups, disabled and expired
// accounts, the mapping), then a self-service activation and a password
// reset through the engine against the fake Directory API.
func TestLabSelfService(t *testing.T) {
	l := loadLab(t)
	ctx := context.Background()
	admin := l.admin(t)
	allStaff, support, finance := groupSID(t, admin, "All Staff"), groupSID(t, admin, "Support"), groupSID(t, admin, "Finance")
	r := l.groupReader(t, []string{allStaff}, []string{support}, []mapping.OUConfig{{Group: finance, Target: "/Finance", Priority: 1}})

	sid1 := samSID(t, admin, "user0001")
	start := time.Now()
	look, err := r.LookupUser(ctx, sid1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("one-user lookup: %s", time.Since(start).Round(time.Millisecond))
	if !look.InScope || look.User == nil || look.User.SID != sid1 || look.User.Account != "user0001" || !look.User.Enabled ||
		look.User.Attrs[model.FieldPrimaryEmail] != "user0001@sync.example.com" || look.User.Attrs[model.FieldOrgUnit] != "/Staff" {
		t.Fatalf("user0001 %+v", look)
	}
	// The same user from the full read: same ID, same mapping.
	full, err := r.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fromRead *model.SourceUser
	for i := range full.Users {
		if full.Users[i].SID == sid1 {
			fromRead = &full.Users[i]
		}
	}
	if fromRead == nil || fromRead.ID != look.User.ID || fromRead.Attrs[model.FieldPrimaryEmail] != look.User.Attrs[model.FieldPrimaryEmail] {
		t.Fatalf("full read %+v vs lookup %+v", fromRead, look.User)
	}
	// A member of the exclude group (user0003 is in Support).
	if look, err := r.LookupUser(ctx, samSID(t, admin, "user0003")); err != nil || look.InScope || !strings.Contains(look.Reason, "exclude group") {
		t.Fatalf("user0003 %+v %v", look, err)
	}
	// An org unit group rule (user0004 is in Finance), as in the full read.
	if look, err := r.LookupUser(ctx, samSID(t, admin, "user0004")); err != nil || !look.InScope || look.User.Attrs[model.FieldOrgUnit] != "/Finance" {
		t.Fatalf("user0004 %+v %v", look, err)
	}
	// Not in the include group: out of scope.
	if look, err := r.LookupUser(ctx, samSID(t, admin, "escape.test")); err != nil || look.InScope || !strings.Contains(look.Reason, "include group") {
		t.Fatalf("escape.test %+v %v", look, err)
	}
	// The domain administrator: a critical object, never a sync user.
	if look, err := r.LookupUser(ctx, samSID(t, admin, "Administrator")); err != nil || look.InScope || look.User != nil {
		t.Fatalf("Administrator %+v %v", look, err)
	}

	// Activation and reset through the engine (all users below the lab).
	w := newWorld(t, l.reader(t, "kerberos"))
	w.eng.Policy.SelfServiceActivation = true
	w.eng.SelfService = engine.SelfServicePolicy{Activation: "self-service", PasswordReset: "created", PasswordMinLength: 12,
		MaxPerUserHour: 3, MaxPerTargetHour: 30}
	c := w.plan()
	if c.Plan.Counts()[plan.UserCreate] != 0 {
		t.Fatalf("self-service plan creates: %s", counts(c))
	}
	if _, err := w.apply(engine.ApplyOptions{OverrideLimits: true}); err != nil {
		t.Fatalf("groups apply: %v", err)
	}
	a, err := w.eng.AccountStatus(ctx, sid1)
	if err != nil || a.State != syncapi.AccountNotActivated || !a.CanActivate {
		t.Fatalf("status %+v %v", a, err)
	}
	start = time.Now()
	res, err := w.eng.Activate(ctx, sid1, syncapi.PasswordChoice{Mode: syncapi.PasswordGenerate})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	t.Logf("activation (full plan of the lab, one create): %s", time.Since(start).Round(time.Millisecond))
	u, ok := w.fake.User("user0001@sync.example.com")
	if !ok || u.ChangePasswordNext || !w.fake.PasswordMatches(u.ID, res.Password) || len(w.fake.Users()) != 1 {
		t.Fatalf("account %+v (%d accounts)", u, len(w.fake.Users()))
	}
	res2, err := w.eng.SetPassword(ctx, sid1, syncapi.PasswordChoice{Mode: syncapi.PasswordGenerate})
	if err != nil || !w.fake.PasswordMatches(u.ID, res2.Password) {
		t.Fatalf("reset: %v", err)
	}
	if c := w.plan(); len(c.Plan.Ops) != 0 {
		t.Fatalf("plan after activation: %s", counts(c))
	}
}
