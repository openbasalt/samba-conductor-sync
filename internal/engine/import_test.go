package engine_test

import (
	"context"
	"slices"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/engine"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
	"github.com/openbasalt/samba-conductor-sync/internal/gimport"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// TestImportThenAdopt is the whole round trip of an import from Google on
// the sync side: the import plan is read without any write; AD users and
// groups made from it (as conductor creates them: mail = the Google
// address, the Google names and title) are then adopted by the sync, which
// writes only its marks: no create, no password, no rename, no org unit
// change, and no member removed from the adopted group.
func TestImportThenAdopt(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.eng.Policy.Adopt = plan.AdoptEmail
	e.eng.Policy.Defaults()
	e.eng.Limits.MaxTouchedPercent = -1
	people := []fakegoogle.User{
		{PrimaryEmail: "ana@example.com", OrgUnitPath: "/Staff/Sales", Name: map[string]any{"givenName": "Ana", "familyName": "Ribeiro"},
			Organizations: []map[string]any{{"title": "Manager", "department": "Sales", "primary": true}}, Aliases: []string{"ana.r@example.com"}},
		{PrimaryEmail: "bruno@example.com", OrgUnitPath: "/Staff/Sales", Name: map[string]any{"givenName": "Bruno", "familyName": "Costa"}},
		{PrimaryEmail: "carla@example.com", OrgUnitPath: "/Contractors", Name: map[string]any{"givenName": "Carla", "familyName": "Dias"},
			Suspended: true},
	}
	for _, p := range people {
		e.fake.SeedUser(p)
	}
	g := e.fake.SeedGroup(fakegoogle.Group{Email: "sales@groups.example.com", Name: "Sales", Description: "Sales team"})
	e.fake.AddMemberDirect(g.ID, "ana@example.com")
	e.fake.AddMemberDirect(g.ID, "bruno@example.com")
	e.fake.AddMemberDirect(g.ID, "partner@other.example")

	// 1. The import plan: read-only.
	conn, err := e.eng.Connect(false)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := conn.Snapshot(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := gimport.Build(snap, gimport.Options{ImportPlanParams: syncapi.ImportPlanParams{Groups: true, SkipEmptyGroups: true},
		AllowedDomains: []string{"example.com"}, GroupAllowedDomains: []string{"groups.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ip.Users) != 2 || len(ip.Groups) != 1 || len(e.fake.Writes()) != 0 {
		t.Fatalf("import plan %+v %+v, writes %v", ip.Users, ip.Groups, e.fake.Writes())
	}

	// 2. AD as conductor creates it from the plan (users placed in another
	// OU than their Google org unit: the sync keeps the org unit).
	ids := map[string]string{}
	for i, u := range ip.Users {
		su := user(i+1, "/Staff/Engineering", true)
		su.Attrs[model.FieldPrimaryEmail], su.Attrs[model.FieldGivenName], su.Attrs[model.FieldFamilyName] = u.Email, u.GivenName, u.FamilyName
		su.Attrs[model.FieldTitle], su.Attrs[model.FieldDepartment] = u.Title, u.Department
		ids[u.Email] = su.ID
		e.src.Users = append(e.src.Users, su)
	}
	sg := group(1, "Sales")
	sg.Email, sg.Description = ip.Groups[0].Email, ip.Groups[0].Description
	for _, m := range ip.Groups[0].Users {
		sg.Members = append(sg.Members, model.MemberRef{Kind: model.KindUser, ID: ids[m]})
	}
	e.src.Groups = []model.SourceGroup{sg}

	// 3. The sync adopts everything and changes nothing else.
	c := e.plan()
	counts := c.Plan.Counts()
	if counts[plan.UserAdopt] != 2 || counts[plan.GroupAdopt] != 1 || counts[plan.UserCreate] != 0 || counts[plan.GroupCreate] != 0 ||
		counts[plan.UserRename] != 0 || counts[plan.MemberRemove] != 0 || counts[plan.MemberAdd] != 0 {
		t.Fatalf("plan %v\n%v", counts, c.Plan.Ops)
	}
	for _, op := range c.Plan.Ops {
		if op.Kind == plan.UserAdopt && len(op.Changes) != 0 {
			t.Fatalf("an adoption of an imported account changes fields: %+v", op)
		}
	}
	e.mustApply(engine.ApplyOptions{})
	e.noDeletes()
	noPasswordOutsideCreate(t, e.fake)
	for _, p := range people[:2] {
		got := e.userByEmail(p.PrimaryEmail)
		if got.OrgUnitPath != p.OrgUnitPath || got.Name["givenName"] != p.Name["givenName"] || !adoptedMark(got) || got.PasswordSet ||
			!slices.Equal(got.Aliases, p.Aliases) {
			t.Fatalf("adopted %s: %+v", p.PrimaryEmail, got)
		}
	}
	if carla := e.userByEmail("carla@example.com"); !carla.Suspended || ownerOf(carla) != "" {
		t.Fatalf("an account left out of the import was touched: %+v", carla)
	}
	if _, members, _ := e.fake.GroupByEmail("sales@groups.example.com"); len(members) != 3 {
		t.Fatalf("adopted group members %v", members)
	}
	if again := e.plan(); !again.Plan.Empty() {
		t.Fatalf("not converged: %v", again.Plan.Ops)
	}
}
