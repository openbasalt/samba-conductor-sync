//go:build lab

package labtest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/conductor-sync/internal/engine"
	"github.com/samba-conductor/conductor-sync/internal/mapping"
	"github.com/samba-conductor/conductor-sync/internal/model"
	"github.com/samba-conductor/conductor-sync/internal/plan"
	"github.com/samba-conductor/conductor-sync/internal/source"
	"github.com/samba-conductor/conductor-sync/internal/source/adsource"
	"github.com/samba-conductor/conductor-sync/internal/store"
)

// switchable is a source whose reader can be replaced between runs (a
// configuration change).
type switchable struct{ r *adsource.Reader }

func (s *switchable) Read(ctx context.Context) (*source.Result, error) { return s.r.Read(ctx) }

func groupSID(t *testing.T, c *ad.Conn, cn string) string {
	t.Helper()
	e, err := c.Get(context.Background(), "CN="+cn+","+groups, ad.GroupAttributes...)
	if err != nil {
		t.Fatalf("group %s: %v", cn, err)
	}
	return ad.GroupFromEntry(e).SID.String()
}

func (l labEnv) groupReader(t *testing.T, include, exclude []string, ous []mapping.OUConfig) *adsource.Reader {
	t.Helper()
	r, err := mapping.Compile(mapping.Config{
		PrimaryEmail:   []string{"{sAMAccountName|ascii|lower}@sync.example.com"},
		AllowedDomains: []string{"sync.example.com"},
		OrgUnits:       append([]mapping.OUConfig{{AD: people, Target: "/Staff"}}, ous...),
	})
	if err != nil {
		t.Fatal(err)
	}
	rd, err := adsource.NewReader(adsource.Config{Realm: realm, DCs: []string{dc}, DNSServers: []string{dcIP}, CAFile: l.caFile,
		BindUser: "svc.sync", Auth: "simple", PasswordCredential: "unused", UserBases: []string{lab},
		IncludeGroups: include, ExcludeGroups: exclude}, r, l.bindPW)
	if err != nil {
		t.Fatal(err)
	}
	return rd
}

func scopeGroup(t *testing.T, c *engine.Computed, ref string) model.ScopeGroup {
	t.Helper()
	for _, g := range c.Plan.Scope {
		if g.Ref == ref {
			return g
		}
	}
	t.Fatalf("no scope group %s in %+v", ref, c.Plan.Scope)
	return model.ScopeGroup{}
}

func opFor(c *engine.Computed, kind plan.OpKind, key string) *plan.Op {
	for i := range c.Plan.Ops {
		if c.Plan.Ops[i].Kind == kind && c.Plan.Ops[i].Key == key {
			return &c.Plan.Ops[i]
		}
	}
	return nil
}

// TestLabGroupScope: include and exclude groups (by SID and by DN), group
// placement rules with priorities, against the lab's Samba AD: a
// membership change moves the org unit, an ambiguous placement is a plan
// error, an exclusion suspends, a mass exclusion is blocked by the limits,
// a SID reference survives a rename and a stale DN reference stops the run.
func TestLabGroupScope(t *testing.T) {
	l := loadLab(t)
	ctx := context.Background()
	admin := l.admin(t)
	allStaff, finance, sales, support := groupSID(t, admin, "All Staff"), groupSID(t, admin, "Finance"),
		groupSID(t, admin, "Sales"), groupSID(t, admin, "Support")
	leadsDN := "CN=Engineering Leads," + groups
	rulesV1 := []mapping.OUConfig{
		{Group: finance, Target: "/Finance", Priority: 10},
		{Group: leadsDN, Target: "/Leads", Priority: 5},
	}
	src := &switchable{r: l.groupReader(t, []string{allStaff}, nil, rulesV1)}
	w := newWorld(t, src)
	for _, ou := range []string{"/Staff", "/Finance", "/Leads", "/Sales"} {
		w.fake.AddOrgUnit(ou)
	}
	w.eng.Policy.ManageGroups = false

	// 1. Scope: members of All Staff (nested through the department
	// groups); the special accounts are in no include group.
	c := w.plan()
	if g := scopeGroup(t, c, allStaff); len(c.Plan.Scope) != 3 || g.Name != "All Staff" || g.Role != model.RoleInclude || g.Members < 2400 || c.Plan.NotIncluded == 0 {
		t.Fatalf("scope %+v, not included %d", c.Plan.Scope, c.Plan.NotIncluded)
	}
	if g := scopeGroup(t, c, leadsDN); g.Name != "Engineering Leads" || g.SID == "" || g.Role != model.RoleOrgUnit || g.Priority != 5 {
		t.Fatalf("DN reference resolved: %+v", g)
	}
	t.Logf("scope: %d users, %d not included; %s", c.Plan.SourceUsers, c.Plan.NotIncluded, counts(c))
	if _, err := w.apply(engine.ApplyOptions{OverrideLimits: true, ExpectDigest: c.Plan.Digest}); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	u504, _ := w.fake.User("user0504@sync.example.com") // Finance member
	if u504.OrgUnitPath != "/Finance" {
		t.Fatalf("group placement: user0504 in %s", u504.OrgUnitPath)
	}

	// 2. A membership change moves the org unit (scheduled, within limits).
	op, err := ad.AddGroupMember("CN=Finance,"+groups, userDN(501))
	applyAD(t, admin, op, err)
	c = w.plan()
	upd := opFor(c, plan.UserUpdate, "user0501@sync.example.com")
	if upd == nil || len(c.Plan.Ops) != 1 || upd.Reason != "org unit from group Finance (priority 10)" {
		t.Fatalf("membership change: %s %+v", counts(c), c.Plan.Ops)
	}
	if r, err := w.apply(engine.ApplyOptions{Scheduled: true}); err != nil || r.Status != store.StatusApplied {
		t.Fatalf("scheduled: %v", err)
	}
	if u, _ := w.fake.User("user0501@sync.example.com"); u.OrgUnitPath != "/Finance" {
		t.Fatalf("user0501 in %s", u.OrgUnitPath)
	}

	// 3. Same priority, different org units: a plan error for that user,
	// who is left untouched.
	op, err = ad.AddGroupMember("CN=Sales,"+groups, userDN(501))
	applyAD(t, admin, op, err)
	src.r = l.groupReader(t, []string{allStaff}, nil, append(append([]mapping.OUConfig(nil), rulesV1...),
		mapping.OUConfig{Group: sales, Target: "/Sales", Priority: 10}))
	c = w.plan()
	if len(c.Plan.Errors) != 1 || c.Plan.Errors[0].Key != "user0501@sync.example.com" || c.Plan.Errors[0].Code != plan.ErrOrgUnitAmbiguous {
		t.Fatalf("plan errors %+v", c.Plan.Errors)
	}
	for _, o := range c.Plan.Ops {
		if o.Key == "user0501@sync.example.com" {
			t.Fatalf("ambiguous user touched: %+v", o)
		}
	}
	t.Logf("ambiguous: %s; error: %s", counts(c), c.Plan.Errors[0].Message)
	op, err = ad.RemoveGroupMember("CN=Sales,"+groups, userDN(501))
	applyAD(t, admin, op, err)
	src.r = l.groupReader(t, []string{allStaff}, nil, rulesV1)

	// 4. An exclusion suspends: Engineering Leads (30 members, nested
	// through Platform Team; one may have left OU=Lab in TestLabEndToEnd),
	// applied by a scheduled run with the
	// operator's max_suspends raised to 50 for it.
	src.r = l.groupReader(t, []string{allStaff}, []string{leadsDN}, rulesV1)
	c = w.plan()
	if c.Plan.Excluded < 25 || c.Plan.Excluded > 30 || c.Plan.Counts()[plan.UserSuspend] != c.Plan.Excluded {
		t.Fatalf("exclusion: excluded %d, %s", c.Plan.Excluded, counts(c))
	}
	w.eng.Limits.MaxSuspends = 50
	if r, err := w.apply(engine.ApplyOptions{Scheduled: true}); err != nil || r.Status != store.StatusApplied {
		t.Fatalf("exclusion apply: %v %v", err, r.Violations)
	}
	w.eng.Limits = plan.DefaultLimits()
	t.Logf("exclusion of Engineering Leads: %d suspended", c.Plan.Excluded)

	// 5. A mass exclusion (Support, 500 users) is blocked by the limits;
	// nothing is written until an operator overrides it.
	src.r = l.groupReader(t, []string{allStaff}, []string{leadsDN, support}, rulesV1)
	writes := len(w.fake.Writes())
	r, err := w.apply(engine.ApplyOptions{Scheduled: true})
	if !errors.Is(err, engine.ErrBlocked) || len(w.fake.Writes()) != writes {
		t.Fatalf("mass exclusion not blocked: %v", err)
	}
	if r.Plan.Excluded < 520 || r.Plan.Counts()[plan.UserSuspend] < 490 {
		t.Fatalf("mass exclusion plan: excluded %d, %s", r.Plan.Excluded, counts(r.Computed))
	}
	t.Logf("mass exclusion blocked: %v", r.Violations)
	if r, err := w.apply(engine.ApplyOptions{OverrideLimits: true, ExpectDigest: r.Plan.Digest}); err != nil || r.Done < 500 {
		t.Fatalf("override: %v", err)
	}
	if u, _ := w.fake.User("user0503@sync.example.com"); !u.Suspended {
		t.Fatal("Support member not suspended")
	}

	// 6. A SID reference survives a rename (no change, new name shown); a
	// DN reference to a renamed group stops the read.
	op, err = ad.RenameObject("CN=Finance,"+groups, "Finance Dept")
	applyAD(t, admin, op, err)
	c = w.plan()
	if !c.Plan.Empty() || scopeGroup(t, c, finance).Name != "Finance Dept" {
		t.Fatalf("after renaming Finance: %s %+v", counts(c), c.Plan.Scope)
	}
	op, err = ad.RenameObject(leadsDN, "Eng Leads")
	applyAD(t, admin, op, err)
	if _, err := w.eng.Plan(ctx, "manual"); err == nil || !strings.Contains(err.Error(), "referenced groups not found") {
		t.Fatalf("stale DN reference: %v", err)
	}
}
