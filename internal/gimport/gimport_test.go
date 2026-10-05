package gimport

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

func user(email, ou string, mod func(*model.TargetUser)) model.TargetUser {
	u := model.TargetUser{ID: "id-" + email, Attrs: model.UserAttrs{model.FieldPrimaryEmail: email, model.FieldGivenName: "G",
		model.FieldFamilyName: "F", model.FieldOrgUnit: ou}}
	if mod != nil {
		mod(&u)
	}
	return u
}

func member(kind model.Kind, email string) model.TargetMember {
	return model.TargetMember{Kind: kind, Email: email}
}

// company is a small existing Google Workspace: org units, an admin, a
// suspended account, an account already owned by the sync, nested groups
// and an external member.
func company() *connector.Snapshot {
	return &connector.Snapshot{
		Users: []model.TargetUser{
			user("ana@example.com", "/Sales", func(u *model.TargetUser) {
				u.Attrs[model.FieldTitle], u.Attrs[model.FieldDepartment] = "Manager", "Sales"
				u.Attrs[model.FieldPhoneWork], u.Attrs[model.FieldEmployeeID] = "+55 11 5555-0001", "E1"
				u.Aliases = []string{"Ana.Ribeiro@example.com"}
			}),
			user("bruno@example.com", "/Sales/South", nil),
			user("carla@example.com", "/IT", nil),
			user("diego@example.com", "/Sales", func(u *model.TargetUser) { u.Suspended = true }),
			user("boss@example.com", "/", func(u *model.TargetUser) { u.Protected = true }),
			user("synced@example.com", "/IT", func(u *model.TargetUser) { u.Owner = "guid-1" }),
			user("other@other.example", "/Sales", nil),
		},
		Groups: []model.TargetGroup{
			{ID: "g1", Email: "sales@example.com", Name: "Sales", Description: "Sales team", Members: []model.TargetMember{
				member(model.KindUser, "ana@example.com"), member(model.KindUser, "diego@example.com"),
				member(model.KindGroup, "south@example.com"), member("", "partner@external.example")}},
			{ID: "g2", Email: "south@example.com", Name: "South", Members: []model.TargetMember{member(model.KindUser, "bruno@example.com")}},
			{ID: "g3", Email: "it@example.com", Name: "IT", Members: []model.TargetMember{member(model.KindUser, "carla@example.com")}},
			{ID: "g4", Email: "empty@example.com", Name: "Empty"},
		},
	}
}

func build(t *testing.T, p syncapi.ImportPlanParams) *syncapi.ImportPlan {
	t.Helper()
	pl, err := Build(company(), Options{ImportPlanParams: p, AllowedDomains: []string{"example.com"}, Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

func emails(us []syncapi.ImportUser) []string {
	var out []string
	for _, u := range us {
		out = append(out, u.Email)
	}
	return out
}

func TestDefaultsLeaveOutSuspendedAdminsAndOwned(t *testing.T) {
	pl := build(t, syncapi.ImportPlanParams{})
	want := []string{"ana@example.com", "bruno@example.com", "carla@example.com", "other@other.example"}
	if got := emails(pl.Users); !reflect.DeepEqual(got, want) {
		t.Fatalf("users %v, want %v", got, want)
	}
	if pl.SkippedCounts[syncapi.ImportSkipSuspended] != 1 || pl.SkippedCounts[syncapi.ImportSkipAdmin] != 1 ||
		pl.SkippedCounts[syncapi.ImportSkipManaged] != 1 || pl.UsersRead != 7 || len(pl.Groups) != 0 || pl.AllGroups != nil {
		t.Fatalf("plan %+v", pl)
	}
	ana := pl.Users[0]
	if ana.Title != "Manager" || ana.Department != "Sales" || ana.PhoneWork != "+55 11 5555-0001" || ana.EmployeeID != "E1" ||
		ana.OrgUnit != "/Sales" || !reflect.DeepEqual(ana.Aliases, []string{"ana.ribeiro@example.com"}) || len(ana.Warnings) != 0 {
		t.Fatalf("ana %+v", ana)
	}
	if other := pl.Users[3]; !reflect.DeepEqual(other.Warnings, []string{syncapi.ImportWarnDomain}) {
		t.Fatalf("an address outside the allowed domains is not reported: %+v", other)
	}
	if len(pl.OrgUnits) != 4 || pl.OrgUnits[2] != (syncapi.ImportOrgUnit{Path: "/Sales", Users: 3}) {
		t.Fatalf("org units %+v", pl.OrgUnits)
	}
}

func TestIncludeSuspendedAndAdmins(t *testing.T) {
	pl := build(t, syncapi.ImportPlanParams{IncludeSuspended: true, IncludeAdmins: true})
	if len(pl.Users) != 6 || pl.SkippedCounts[syncapi.ImportSkipManaged] != 1 {
		t.Fatalf("users %v skipped %v", emails(pl.Users), pl.SkippedCounts)
	}
	for _, u := range pl.Users {
		if u.Email == "diego@example.com" && !u.Suspended || u.Email == "boss@example.com" && !u.Admin {
			t.Fatalf("flags lost: %+v", u)
		}
	}
}

func TestOrgUnitFilter(t *testing.T) {
	for _, tc := range []struct {
		ous  []string
		sub  bool
		want []string
	}{
		{[]string{"/Sales"}, false, []string{"ana@example.com", "other@other.example"}},
		{[]string{"/sales/"}, true, []string{"ana@example.com", "bruno@example.com", "other@other.example"}},
		{[]string{"/IT", "/Sales/South"}, false, []string{"bruno@example.com", "carla@example.com"}},
		{[]string{"/"}, false, nil},
		{[]string{"/"}, true, []string{"ana@example.com", "bruno@example.com", "carla@example.com", "other@other.example"}},
	} {
		pl := build(t, syncapi.ImportPlanParams{OrgUnits: tc.ous, SubOrgUnits: tc.sub})
		if got := emails(pl.Users); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v sub=%v: %v, want %v", tc.ous, tc.sub, got, tc.want)
		}
	}
}

func TestMemberOfFilterIsNested(t *testing.T) {
	pl := build(t, syncapi.ImportPlanParams{MemberOf: []string{"Sales@example.com"}})
	if got := emails(pl.Users); !reflect.DeepEqual(got, []string{"ana@example.com", "bruno@example.com"}) {
		t.Fatalf("users %v", got)
	}
	if pl.SkippedCounts[syncapi.ImportSkipSuspended] != 1 || len(pl.AllGroups) != 4 || len(pl.Groups) != 0 {
		t.Fatalf("plan %+v", pl)
	}
	if _, err := Build(company(), Options{ImportPlanParams: syncapi.ImportPlanParams{MemberOf: []string{"nope@example.com"}}}); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("a missing filter group must stop the plan: %v", err)
	}
}

func TestGroupsKeepOnlyPlannedMembers(t *testing.T) {
	pl := build(t, syncapi.ImportPlanParams{Groups: true})
	if len(pl.Groups) != 4 {
		t.Fatalf("groups %+v", pl.Groups)
	}
	byEmail := map[string]syncapi.ImportGroup{}
	for _, g := range pl.Groups {
		byEmail[g.Email] = g
	}
	sales := byEmail["sales@example.com"]
	// diego is suspended (not in the plan) and the partner is external:
	// both are left out; the nested group is kept.
	if !reflect.DeepEqual(sales.Users, []string{"ana@example.com"}) || !reflect.DeepEqual(sales.Groups, []string{"south@example.com"}) ||
		sales.LeftOut != 2 || sales.Description != "Sales team" {
		t.Fatalf("sales %+v", sales)
	}
	// Only some groups: a nested group that is not imported is left out.
	pl = build(t, syncapi.ImportPlanParams{Groups: true, GroupEmails: []string{"sales@example.com"}})
	if len(pl.Groups) != 1 || len(pl.Groups[0].Groups) != 0 || pl.Groups[0].LeftOut != 3 {
		t.Fatalf("selected groups %+v", pl.Groups)
	}
	if _, err := Build(company(), Options{ImportPlanParams: syncapi.ImportPlanParams{Groups: true, GroupEmails: []string{"x@example.com"}}}); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("a missing group must stop the plan: %v", err)
	}
}

func TestSkipEmptyGroupsCountsNestedMembers(t *testing.T) {
	pl := build(t, syncapi.ImportPlanParams{Groups: true, SkipEmptyGroups: true, OrgUnits: []string{"/Sales"}, SubOrgUnits: true})
	var got []string
	for _, g := range pl.Groups {
		got = append(got, g.Email)
	}
	// it@ has only carla (not in the plan), empty@ has nobody: both out;
	// sales@ has ana and, through south@, bruno.
	if !reflect.DeepEqual(got, []string{"sales@example.com", "south@example.com"}) || pl.SkippedCounts[syncapi.ImportSkipEmpty] != 2 {
		t.Fatalf("groups %v skipped %v", got, pl.SkippedCounts)
	}
}

func TestLimits(t *testing.T) {
	pl := build(t, syncapi.ImportPlanParams{MaxUsers: 2, Groups: true, MaxGroups: 1})
	if got := emails(pl.Users); !reflect.DeepEqual(got, []string{"ana@example.com", "bruno@example.com"}) {
		t.Fatalf("users %v", got)
	}
	if pl.SkippedCounts[syncapi.ImportSkipLimit] != 2+3 || len(pl.Groups) != 1 || pl.Groups[0].Email != "empty@example.com" {
		t.Fatalf("plan %+v %+v", pl.SkippedCounts, pl.Groups)
	}
}

func TestParamsValidation(t *testing.T) {
	for i, p := range []syncapi.ImportPlanParams{
		{MaxUsers: syncapi.MaxImportUsers + 1},
		{MaxGroups: -1},
		{OrgUnits: []string{"Sales"}},
		{MemberOf: []string{"not an address"}},
		{GroupEmails: []string{"g@example.com"}},
	} {
		if p.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if err := (syncapi.ImportPlanParams{OrgUnits: []string{"/"}, Groups: true, GroupEmails: []string{"g@example.com"}}).Validate(); err != nil {
		t.Fatal(err)
	}
}
