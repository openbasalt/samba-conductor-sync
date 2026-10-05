package plan

import (
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
)

// adoptIn is one AD user matching one existing, unmanaged account that
// lives in another org unit with other names.
func adoptIn() Input {
	s := su("a", "ana@x.com", true)
	s.Attrs[model.FieldOrgUnit] = "/Staff"
	s.Attrs[model.FieldGivenName] = "Ana"
	s.Attrs[model.FieldFamilyName] = "Lima"
	t := tu("1", "", "ana@x.com", false)
	t.Attrs[model.FieldOrgUnit] = "/Sales"
	t.Attrs[model.FieldGivenName] = "Ana Maria"
	t.Attrs[model.FieldFamilyName] = "Lima Souza"
	return Input{Users: []model.SourceUser{s}, TargetUsers: []model.TargetUser{t}, Policy: Policy{Adopt: AdoptEmail, SuspendDisabled: true}}
}

func changed(o Op) map[string]string {
	out := map[string]string{}
	for _, c := range o.Changes {
		out[c.Field] = c.New
	}
	return out
}

func warned(p *Plan, code string) bool {
	for _, w := range p.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

func TestPolicyDefaultsAreSafe(t *testing.T) {
	var p Policy
	p.Defaults()
	if p.Adopt != AdoptNever || p.AdoptedOrgUnit != AdoptedKeep || p.AdoptedEmail != AdoptedKeep ||
		p.AdoptedNames != AdoptedIfSet || p.AdoptedAttributes != AdoptedIfSet || p.AdoptedGroupMembers != AdoptedAddOnly {
		t.Fatalf("defaults %+v", p)
	}
	for key, choices := range AdoptedChoices {
		for _, c := range choices {
			if !ValidAdopted(key, c) {
				t.Errorf("%s rejects %s", key, c)
			}
		}
		if ValidAdopted(key, "bogus") {
			t.Errorf("%s accepts bogus", key)
		}
	}
	if ValidAdopted("adopted_org_unit", AdoptedIfSet) || ValidAdopted("adopted_group_members", AdoptedKeep) {
		t.Fatal("a mode outside the rule's choices was accepted")
	}
}

func TestAdoptKeepsOrgUnitByDefault(t *testing.T) {
	p := Compute(adoptIn())
	if len(p.Ops) != 1 || p.Ops[0].Kind != UserAdopt {
		t.Fatalf("ops %s", kinds(p))
	}
	op := p.Ops[0]
	c := changed(op)
	if _, ok := c["org_unit"]; ok {
		t.Fatalf("org unit changed on adoption: %+v", op.Changes)
	}
	if op.Attrs[model.FieldOrgUnit] != "/Sales" {
		t.Fatalf("desired org unit %q, want the account's own", op.Attrs[model.FieldOrgUnit])
	}
	if !strings.Contains(op.Reason, "kept on the account: org_unit") {
		t.Fatalf("reason %q does not say what is kept", op.Reason)
	}
	// Names AD has values for are written (if-set).
	if c["given_name"] != "Ana" || c["family_name"] != "Lima" {
		t.Fatalf("names %+v", op.Changes)
	}
	// manage moves it like a created account.
	in := adoptIn()
	in.Policy.AdoptedOrgUnit = AdoptedManage
	if c := changed(Compute(in).Ops[0]); c["org_unit"] != "/Staff" {
		t.Fatalf("manage: %+v", c)
	}
}

func TestAdoptedLinkKeepsOrgUnitOnLaterRuns(t *testing.T) {
	in := adoptIn()
	in.TargetUsers[0].Owner = "a"
	in.TargetUsers[0].Attrs[model.FieldGivenName] = "Ana"
	in.TargetUsers[0].Attrs[model.FieldFamilyName] = "Lima"
	in.Links = []Link{{Kind: model.KindUser, SourceID: "a", TargetID: "1", Key: "ana@x.com", Adopted: true}}
	if p := Compute(in); len(p.Ops) != 0 {
		t.Fatalf("adopted account touched: %s %+v", kinds(p), p.Ops)
	}
	// The same account created by the sync is moved by the mapping.
	in.Links[0].Adopted = false
	p := Compute(in)
	if len(p.Ops) != 1 || changed(p.Ops[0])["org_unit"] != "/Staff" {
		t.Fatalf("created account not placed: %+v", p.Ops)
	}
}

func TestRelinkByMarkerKeepsAdoptedRules(t *testing.T) {
	in := adoptIn()
	in.TargetUsers[0].Owner = "a"
	in.TargetUsers[0].Adopted = true // the adoption mark on the account
	p := Compute(in)
	if len(p.Ops) < 1 || p.Ops[0].Kind != UserRelink || !p.Ops[0].Adopted {
		t.Fatalf("relink %+v", p.Ops)
	}
	for _, o := range p.Ops {
		if _, ok := changed(o)["org_unit"]; ok {
			t.Fatalf("org unit changed after a state loss: %+v", o)
		}
	}
}

func TestAdoptedNames(t *testing.T) {
	// AD has no given name of its own: the value comes from a fallback.
	in := adoptIn()
	in.Users[0].Fallback = map[model.UserField]bool{model.FieldGivenName: true}
	in.Users[0].Attrs[model.FieldGivenName] = "ana.lima"
	c := changed(Compute(in).Ops[0])
	if _, ok := c["given_name"]; ok || c["family_name"] != "Lima" {
		t.Fatalf("if-set with a fallback: %+v", c)
	}
	// Empty AD value: kept.
	in = adoptIn()
	in.Users[0].Attrs[model.FieldFamilyName] = ""
	c = changed(Compute(in).Ops[0])
	if _, ok := c["family_name"]; ok {
		t.Fatalf("empty family name written: %+v", c)
	}
	// keep: never.
	in = adoptIn()
	in.Policy.AdoptedNames = AdoptedKeep
	if c := changed(Compute(in).Ops[0]); len(c) != 0 {
		t.Fatalf("keep: %+v", c)
	}
	// manage: fallbacks too.
	in = adoptIn()
	in.Policy.AdoptedNames = AdoptedManage
	in.Users[0].Fallback = map[model.UserField]bool{model.FieldGivenName: true}
	in.Users[0].Attrs[model.FieldGivenName] = "ana.lima"
	if c := changed(Compute(in).Ops[0]); c["given_name"] != "ana.lima" {
		t.Fatalf("manage: %+v", c)
	}
}

func TestAdoptedAttributesNeverClearedByEmptyAD(t *testing.T) {
	in := adoptIn()
	in.Policy.Optional = map[model.UserField]bool{model.FieldTitle: true, model.FieldDepartment: true}
	in.Users[0].Attrs[model.FieldTitle] = ""
	in.Users[0].Attrs[model.FieldDepartment] = "Sales"
	in.TargetUsers[0].Attrs[model.FieldTitle] = "Manager"
	in.TargetUsers[0].Attrs[model.FieldDepartment] = "Old"
	c := changed(Compute(in).Ops[0])
	if _, ok := c["title"]; ok || c["department"] != "Sales" {
		t.Fatalf("if-set: %+v", c)
	}
	in.Policy.AdoptedAttributes = AdoptedManage
	if c := changed(Compute(in).Ops[0]); c["title"] != "" || len(c) < 2 {
		t.Fatalf("manage clears: %+v", c)
	} else if _, ok := c["title"]; !ok {
		t.Fatalf("manage did not clear the title: %+v", c)
	}
	in.Policy.AdoptedAttributes = AdoptedKeep
	if c := changed(Compute(in).Ops[0]); c["department"] != "" {
		t.Fatalf("keep: %+v", c)
	}
}

func TestAdoptedAddressIsNeverRenamedByDefault(t *testing.T) {
	in := adoptIn()
	in.TargetUsers[0].Owner = "a"
	in.TargetUsers[0].Attrs[model.FieldGivenName] = "Ana"
	in.TargetUsers[0].Attrs[model.FieldFamilyName] = "Lima"
	in.Links = []Link{{Kind: model.KindUser, SourceID: "a", TargetID: "1", Key: "ana@x.com", Adopted: true}}
	in.Users[0].Attrs[model.FieldPrimaryEmail] = "ana.lima@x.com"
	p := Compute(in)
	if len(p.Ops) != 0 || !warned(p, WarnAdoptedAddress) {
		t.Fatalf("ops %s warnings %v", kinds(p), p.Warnings)
	}
	in.Policy.AdoptedEmail = AdoptedManage
	p = Compute(in)
	if len(p.Ops) != 1 || p.Ops[0].Kind != UserRename {
		t.Fatalf("manage: %s", kinds(p))
	}
}

func TestDisabledADUserNeverAdopts(t *testing.T) {
	in := adoptIn()
	in.Users[0].Enabled = false
	p := Compute(in)
	if len(p.Ops) != 0 || !warned(p, WarnAdoptDisabled) {
		t.Fatalf("ops %s warnings %v", kinds(p), p.Warnings)
	}
}

func TestAdoptedSuspensionRules(t *testing.T) {
	// An account suspended by an administrator is adopted but stays
	// suspended: the sync never undoes someone else's suspension.
	in := adoptIn()
	in.TargetUsers[0].Suspended = true
	p := Compute(in)
	for _, o := range p.Ops {
		if o.Kind == UserUnsuspend || o.Kind == UserSuspend {
			t.Fatalf("suspension changed: %s", kinds(p))
		}
	}
	if !warned(p, WarnSuspendedOutside) {
		t.Fatalf("warnings %v", p.Warnings)
	}
	// Linked (adopted) and still suspended by someone else, then out of
	// scope: no operation at all.
	in.Links = []Link{{Kind: model.KindUser, SourceID: "a", TargetID: "1", Key: "ana@x.com", Adopted: true}}
	in.TargetUsers[0].Owner = "a"
	in.Users = nil
	if p := Compute(in); len(p.Ops) != 0 {
		t.Fatalf("out of scope, already suspended: %s", kinds(p))
	}
	// An active adopted account that leaves the scope is suspended (only
	// that one), and unsuspended when it is back, since the sync did it.
	in = adoptIn()
	in.TargetUsers[0].Owner = "a"
	other := tu("2", "", "other@x.com", false)
	in.TargetUsers = append(in.TargetUsers, other)
	in.Links = []Link{{Kind: model.KindUser, SourceID: "a", TargetID: "1", Key: "ana@x.com", Adopted: true}}
	users := in.Users
	in.Users = nil
	p = Compute(in)
	if kinds(p) != "user.suspend:ana@x.com" {
		t.Fatalf("scope exit: %s", kinds(p))
	}
	in.Users = users
	in.TargetUsers[0].Suspended = true
	in.Links[0].SuspendedBySync = true
	in.TargetUsers[0].Attrs[model.FieldGivenName] = "Ana"
	in.TargetUsers[0].Attrs[model.FieldFamilyName] = "Lima"
	if p := Compute(in); kinds(p) != "user.unsuspend:ana@x.com" {
		t.Fatalf("back in scope: %s", kinds(p))
	}
}

func groupIn() Input {
	in := adoptIn()
	in.Policy.ManageGroups = true
	in.TargetUsers[0].Owner = "a"
	in.TargetUsers[0].Attrs[model.FieldGivenName] = "Ana"
	in.TargetUsers[0].Attrs[model.FieldFamilyName] = "Lima"
	b := tu("2", "b", "bia@x.com", false)
	in.TargetUsers = append(in.TargetUsers, b)
	in.Users = append(in.Users, su("b", "bia@x.com", true))
	in.Links = []Link{
		{Kind: model.KindUser, SourceID: "a", TargetID: "1", Key: "ana@x.com", Adopted: true},
		{Kind: model.KindUser, SourceID: "b", TargetID: "2", Key: "bia@x.com"},
	}
	in.Groups = []model.SourceGroup{{ID: "g", Email: "sales@x.com", Name: "Sales", Description: "",
		Members: []model.MemberRef{{Kind: model.KindUser, ID: "a"}}}}
	in.TargetGroups = []model.TargetGroup{{ID: "G", Email: "sales@x.com", Name: "Vendas", Description: "Sales team (BR)",
		Members: []model.TargetMember{
			{ID: "2", Email: "bia@x.com", Kind: model.KindUser}, // managed, not in the AD group
			{Email: "partner@other.com", Kind: model.KindUser},  // unmanaged
			{ID: "1", Email: "ana@x.com", Kind: model.KindUser}, // managed, in the AD group
		}}}
	return in
}

func TestGroupAdoptionIsAddOnlyAndKeepsDescription(t *testing.T) {
	in := groupIn()
	in.Policy.RemoveUnmanagedMembers = true // still not applied to adopted groups
	p := Compute(in)
	if kinds(p) != "group.adopt:sales@x.com" {
		t.Fatalf("ops %s", kinds(p))
	}
	op := p.Ops[0]
	if op.Group.Description != "Sales team (BR)" || op.Group.Name != "Sales" {
		t.Fatalf("spec %+v", op.Group)
	}
	if c := changed(op); len(c) != 1 || c["name"] != "Sales" {
		t.Fatalf("changes %+v", op.Changes)
	}
	if !warned(p, WarnAdoptedMemberKept) || !warned(p, WarnUnmanagedMember) {
		t.Fatalf("warnings %v", p.Warnings)
	}
	// Later runs: the link is adopted, still add-only.
	in.Links = append(in.Links, Link{Kind: model.KindGroup, SourceID: "g", TargetID: "G", Key: "sales@x.com", Adopted: true})
	in.TargetGroups[0].Name = "Sales"
	if p := Compute(in); len(p.Ops) != 0 {
		t.Fatalf("adopted group: %s", kinds(p))
	}
	// manage: AD decides the managed members; unmanaged ones follow
	// remove_unmanaged_members.
	in.Policy.AdoptedGroupMembers = AdoptedManage
	p = Compute(in)
	if got := kinds(p); got != "member.remove:sales@x.com member.remove:sales@x.com" {
		t.Fatalf("manage: %s", got)
	}
	in.Policy.RemoveUnmanagedMembers = false
	p = Compute(in)
	if len(p.Ops) != 1 || p.Ops[0].Member.MemberEmail != "bia@x.com" {
		t.Fatalf("manage without remove_unmanaged: %+v", p.Ops)
	}
	// A group the sync created keeps the old behaviour: AD decides the
	// description (empty clears it) and managed members are removed.
	in.Links[2].Adopted = false
	in.Policy.AdoptedGroupMembers = ""
	if p := Compute(in); kinds(p) != "group.update:sales@x.com member.remove:sales@x.com" {
		t.Fatalf("created group: %s", kinds(p))
	}
}

func TestGroupAdoptionKeepsAddress(t *testing.T) {
	in := groupIn()
	in.Links = append(in.Links, Link{Kind: model.KindGroup, SourceID: "g", TargetID: "G", Key: "sales@x.com", Adopted: true})
	in.TargetGroups[0].Name = "Sales"
	in.Groups[0].Email = "sales-br@x.com"
	p := Compute(in)
	if len(p.Ops) != 0 || !warned(p, WarnAdoptedAddress) {
		t.Fatalf("ops %s warnings %v", kinds(p), p.Warnings)
	}
	in.Policy.AdoptedNames = AdoptedKeep
	in.Groups[0].Email = "sales@x.com"
	in.Groups[0].Name = "Other"
	if p := Compute(in); len(p.Ops) != 0 {
		t.Fatalf("names keep: %s", kinds(p))
	}
}
