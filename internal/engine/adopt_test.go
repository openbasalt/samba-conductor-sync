package engine_test

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/engine"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
)

func adoptedMark(u fakegoogle.User) bool {
	for _, x := range u.ExternalIDs {
		if x["type"] == "custom" && x["customType"] == "conductor-sync-adopted" {
			return true
		}
	}
	return false
}

// noPasswordOutsideCreate fails when any write other than a user insert
// carries a password or changePasswordAtNextLogin.
func noPasswordOutsideCreate(t *testing.T, fake *fakegoogle.Server) {
	t.Helper()
	for _, w := range fake.Writes() {
		create := w.Method == http.MethodPost && w.Path == "/users"
		for _, f := range []string{"password", "changePasswordAtNextLogin", "hashFunction"} {
			if slices.Contains(w.Fields, f) && !create {
				t.Fatalf("%s %s sent %s", w.Method, w.Path, f)
			}
		}
	}
}

// TestAdoptExistingWorkspace models a company that already uses Google:
// accounts in their own org units, an admin-suspended account, a group
// with members the sync does not know, and accounts not in AD at all.
func TestAdoptExistingWorkspace(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.eng.Policy.Adopt = plan.AdoptEmail
	e.eng.Policy.Defaults()
	// Three accounts: one leaving is a third of them.
	e.eng.Limits.MaxTouchedPercent, e.eng.Limits.MaxSourceDropPercent = 100, 100
	u1 := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "user0001@example.com", OrgUnitPath: "/Staff/Sales",
		Name: map[string]any{"givenName": "Hand", "familyName": "Made"}, Aliases: []string{"u1@example.com"},
		Phones: []map[string]any{{"type": "home", "value": "+55 11 5555-0000"}}})
	u2 := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "user0002@example.com", OrgUnitPath: "/Contractors",
		Name: map[string]any{"givenName": "Was", "familyName": "Suspended"}, Suspended: true})
	u5 := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "user0005@example.com", OrgUnitPath: "/Staff",
		Name: map[string]any{"givenName": "Not", "familyName": "InAD"}})
	g := e.fake.SeedGroup(fakegoogle.Group{Email: "sales@groups.example.com", Name: "Vendas", Description: "Equipe"})
	e.fake.AddMemberDirect(g.ID, "user0001@example.com")
	e.fake.AddMemberDirect(g.ID, "user0005@example.com")
	e.fake.AddMemberDirect(g.ID, "partner@other.com")

	// AD: users 1..3 in /Staff/Engineering; user 3 is new.
	for i := 1; i <= 3; i++ {
		e.src.Users = append(e.src.Users, user(i, "/Staff/Engineering", true))
	}
	e.src.Groups = []model.SourceGroup{group(2, "Sales", uref(1), uref(2))}

	c := e.plan()
	counts := c.Plan.Counts()
	if counts[plan.UserAdopt] != 2 || counts[plan.UserCreate] != 1 || counts[plan.GroupAdopt] != 1 || counts[plan.UserSuspend] != 0 || counts[plan.UserUnsuspend] != 0 {
		t.Fatalf("plan %v\n%v", counts, c.Plan.Ops)
	}
	e.mustApply(engine.ApplyOptions{})
	e.noDeletes()
	noPasswordOutsideCreate(t, e.fake)

	a1 := e.userByEmail("user0001@example.com")
	if a1.ID != u1.ID || a1.OrgUnitPath != "/Staff/Sales" || ownerOf(a1) != guid(1) || !adoptedMark(a1) {
		t.Fatalf("adopted account 1: %+v", a1)
	}
	if a1.Name["givenName"] != "User" || !slices.Equal(a1.Aliases, []string{"u1@example.com"}) || a1.PasswordSet || a1.ChangePasswordNext {
		t.Fatalf("adopted account 1 fields: %+v", a1)
	}
	if len(a1.Phones) != 1 || a1.Phones[0]["type"] != "home" {
		t.Fatalf("unmapped phone touched: %+v", a1.Phones)
	}
	a2 := e.userByEmail("user0002@example.com")
	if !a2.Suspended || a2.OrgUnitPath != "/Contractors" {
		t.Fatalf("admin-suspended account: %+v", a2)
	}
	if n := e.userByEmail("user0005@example.com"); n.Name["givenName"] != "Not" || ownerOf(n) != "" || n.OrgUnitPath != "/Staff" {
		t.Fatalf("account not in AD touched: %+v", n)
	}
	for _, w := range e.fake.Writes() {
		if strings.Contains(w.Path, u5.ID) || (strings.Contains(w.Path, u2.ID) && slices.Contains(w.Fields, "suspended")) {
			t.Fatalf("unexpected write %+v", w)
		}
	}
	created := e.userByEmail("user0003@example.com")
	if created.OrgUnitPath != "/Staff/Engineering" || adoptedMark(created) || !created.PasswordSet {
		t.Fatalf("created account: %+v", created)
	}
	grp, members, ok := e.fake.GroupByEmail("sales@groups.example.com")
	if !ok || grp.Name != "Sales" || grp.Description != "Equipe" {
		t.Fatalf("adopted group %+v", grp)
	}
	for _, m := range []string{"user0001@example.com", "user0002@example.com", "user0005@example.com", "partner@other.com"} {
		if !slices.Contains(members, m) {
			t.Fatalf("member %s missing from %v", m, members)
		}
	}
	if p := e.plan(); !p.Plan.Empty() {
		t.Fatalf("not converged: %v", p.Plan.Ops)
	}

	// Leaving the scope suspends only that adopted account; coming back
	// unsuspends it (the sync suspended it).
	e.src.Users = e.src.Users[1:]
	c = e.plan()
	if len(c.Plan.Ops) != 1 || c.Plan.Ops[0].Kind != plan.UserSuspend || c.Plan.Ops[0].Key != "user0001@example.com" {
		t.Fatalf("scope exit: %v", c.Plan.Ops)
	}
	e.mustApply(engine.ApplyOptions{})
	if !e.userByEmail("user0001@example.com").Suspended {
		t.Fatal("not suspended")
	}
	// An adopted account is never deleted by the sync.
	if _, err := e.eng.DeleteUser(ctx, engine.DeleteRequest{Key: "user0001@example.com", Confirm: "user0001@example.com"}); !errors.Is(err, engine.ErrDeleteRefused) || !strings.Contains(err.Error(), "adopted") {
		t.Fatalf("delete of an adopted account: %v", err)
	}
	e.src.Users = append([]model.SourceUser{user(1, "/Staff/Engineering", true)}, e.src.Users...)
	c = e.plan()
	if len(c.Plan.Ops) != 1 || c.Plan.Ops[0].Kind != plan.UserUnsuspend {
		t.Fatalf("back in scope: %v", c.Plan.Ops)
	}
	e.mustApply(engine.ApplyOptions{})
	if a := e.userByEmail("user0001@example.com"); a.Suspended || a.OrgUnitPath != "/Staff/Sales" {
		t.Fatalf("after return: %+v", a)
	}
	noPasswordOutsideCreate(t, e.fake)

	// State loss: the adoption mark on the account keeps the rules.
	st, err := store.Open(ctx, filepath.Join(e.dir, "lost.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	e.eng.Store, e.st = st, st
	c = e.plan()
	for _, o := range c.Plan.Ops {
		if o.Kind != plan.UserRelink && o.Kind != plan.GroupAdopt {
			t.Fatalf("after state loss: %v", c.Plan.Ops)
		}
		wantAdopted := o.Key == "user0001@example.com" || o.Key == "user0002@example.com"
		if o.Kind == plan.UserRelink && o.Adopted != wantAdopted {
			t.Fatalf("relink adopted flag: %+v", o)
		}
	}
	e.mustApply(engine.ApplyOptions{})
	if p := e.plan(); !p.Plan.Empty() {
		t.Fatalf("not converged after state loss: %v", p.Plan.Ops)
	}
	if a := e.userByEmail("user0001@example.com"); a.OrgUnitPath != "/Staff/Sales" {
		t.Fatalf("moved after state loss: %+v", a)
	}
}

func TestAdoptKeepsDisabledADUserAlone(t *testing.T) {
	e := newEnv(t)
	e.eng.Policy.Adopt = plan.AdoptEmail
	e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "user0001@example.com", Name: map[string]any{"givenName": "A", "familyName": "B"}})
	e.src.Users = append(e.src.Users, user(1, "/Staff", false))
	c := e.plan()
	if !c.Plan.Empty() || !hasWarning(c.Plan, plan.WarnAdoptDisabled, "user0001@example.com") {
		t.Fatalf("plan %v %v", c.Plan.Ops, c.Plan.Warnings)
	}
}
