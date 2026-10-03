package plan

import (
	"strings"
	"testing"

	"github.com/samba-conductor/conductor-sync/internal/model"
)

func su(id, email string, enabled bool) model.SourceUser {
	return model.SourceUser{ID: id, DN: "CN=" + id, Account: id, Enabled: enabled, Attrs: model.UserAttrs{
		model.FieldPrimaryEmail: email, model.FieldGivenName: "G", model.FieldFamilyName: "F", model.FieldOrgUnit: "/"}}
}

func tu(id, owner, email string, suspended bool) model.TargetUser {
	return model.TargetUser{ID: id, Owner: owner, Suspended: suspended, Attrs: model.UserAttrs{
		model.FieldPrimaryEmail: email, model.FieldGivenName: "G", model.FieldFamilyName: "F", model.FieldOrgUnit: "/"}}
}

func kinds(p *Plan) string {
	var out []string
	for _, o := range p.Ops {
		out = append(out, string(o.Kind)+":"+o.Key)
	}
	return strings.Join(out, " ")
}

func TestComputeBasics(t *testing.T) {
	in := Input{
		Users: []model.SourceUser{
			su("a", "a@x.com", true),     // linked, unchanged
			su("b", "b-new@x.com", true), // linked, renamed
			su("c", "c@x.com", true),     // new
			su("d", "d@x.com", false),    // linked, disabled
			su("e", "dup@x.com", true),   // duplicate address
			su("f", "dup@x.com", true),   // duplicate address
			su("g", "g@x.com", false),    // disabled, not on target: not created
			su("h", "h@x.com", true),     // unmanaged account exists
			su("i", "i@x.com", true),     // marker but no link (state lost)
		},
		TargetUsers: []model.TargetUser{
			tu("1", "a", "a@x.com", false),
			tu("2", "b", "b@x.com", false),
			tu("4", "d", "d@x.com", false),
			tu("5", "z", "z@x.com", false), // linked, left the scope
			tu("8", "", "h@x.com", false),
			tu("9", "i", "i@x.com", false),
			tu("10", "", "other@x.com", true), // unmanaged, untouched
		},
		Links: []Link{
			{Kind: model.KindUser, SourceID: "a", TargetID: "1", Key: "a@x.com"},
			{Kind: model.KindUser, SourceID: "b", TargetID: "2", Key: "b@x.com"},
			{Kind: model.KindUser, SourceID: "d", TargetID: "4", Key: "d@x.com"},
			{Kind: model.KindUser, SourceID: "z", TargetID: "5", Key: "z@x.com"},
		},
		Policy: Policy{SuspendDisabled: true},
	}
	p := Compute(in)
	want := "user.relink:i@x.com user.rename:b-new@x.com user.create:c@x.com user.suspend:d@x.com user.suspend:z@x.com"
	if got := kinds(p); got != want {
		t.Fatalf("ops\n got %s\nwant %s", got, want)
	}
	codes := map[string]bool{}
	for _, w := range p.Warnings {
		codes[w.Code+":"+w.Key] = true
	}
	for _, k := range []string{"duplicate-address:dup@x.com", "disabled-not-created:g@x.com", "unmanaged-exists:h@x.com"} {
		if !codes[k] {
			t.Errorf("missing warning %s in %v", k, p.Warnings)
		}
	}
	if p.ManagedUsers != 4 {
		t.Errorf("managed %d", p.ManagedUsers)
	}
	// Deterministic.
	if Compute(in).Digest != p.Digest {
		t.Fatal("digest not stable")
	}
	for _, o := range p.Ops {
		if !o.Kind.WritesTarget() && o.Kind != UserRelink {
			t.Errorf("unexpected local op %v", o)
		}
	}
}

func TestDuplicateKeepsLinkedUserFromSuspension(t *testing.T) {
	in := Input{
		Users:       []model.SourceUser{su("a", "dup@x.com", true), su("b", "dup@x.com", true)},
		TargetUsers: []model.TargetUser{tu("1", "a", "a@x.com", false)},
		Links:       []Link{{Kind: model.KindUser, SourceID: "a", TargetID: "1", Key: "a@x.com"}},
	}
	if p := Compute(in); len(p.Ops) != 0 {
		t.Fatalf("a duplicate must freeze the account, got %s", kinds(p))
	}
}

func TestOwnershipConflicts(t *testing.T) {
	in := Input{
		Users: []model.SourceUser{su("new-guid", "a@x.com", true), su("c", "alias@x.com", true)},
		TargetUsers: []model.TargetUser{
			tu("1", "old-guid", "a@x.com", true), // AD account recreated: new GUID
			func() model.TargetUser {
				u := tu("2", "", "q@x.com", false)
				u.Aliases = []string{"alias@x.com"}
				return u
			}(),
		},
		Links:  []Link{{Kind: model.KindUser, SourceID: "old-guid", TargetID: "1", Key: "a@x.com", SuspendedBySync: true}},
		Policy: Policy{Adopt: AdoptEmail},
	}
	p := Compute(in)
	if len(p.Ops) != 0 {
		t.Fatalf("ops %s", kinds(p))
	}
	got := map[string]bool{}
	for _, w := range p.Warnings {
		got[w.Code] = true
	}
	if !got[WarnOwnedByOther] || !got[WarnAliasCollision] {
		t.Fatalf("warnings %v", p.Warnings)
	}
}

func TestOptionalFieldsOnlyWhenMapped(t *testing.T) {
	s := su("a", "a@x.com", true)
	s.Attrs[model.FieldTitle] = "Boss"
	tgt := tu("1", "a", "a@x.com", false)
	tgt.Attrs[model.FieldTitle] = "Intern"
	in := Input{Users: []model.SourceUser{s}, TargetUsers: []model.TargetUser{tgt},
		Links: []Link{{Kind: model.KindUser, SourceID: "a", TargetID: "1", Key: "a@x.com"}}}
	if p := Compute(in); len(p.Ops) != 0 {
		t.Fatalf("unmapped field changed: %s", kinds(p))
	}
	in.Policy.Optional = map[model.UserField]bool{model.FieldTitle: true}
	p := Compute(in)
	if len(p.Ops) != 1 || p.Ops[0].Changes[0].Field != "title" {
		t.Fatalf("mapped field: %+v", p.Ops)
	}
}

func TestGroupsAndMembers(t *testing.T) {
	users := []model.SourceUser{su("u1", "u1@x.com", true), su("u2", "u2@x.com", true), su("u3", "u3@x.com", true)}
	groups := []model.SourceGroup{
		{ID: "g1", Email: "g1@x.com", Name: "G1", Members: []model.MemberRef{{Kind: model.KindUser, ID: "u1"}, {Kind: model.KindUser, ID: "u3"}, {Kind: model.KindGroup, ID: "g2"}}},
		{ID: "g2", Email: "g2@x.com", Name: "G2"},
		{ID: "g3", Email: "g3@x.com", Name: "G3"},
	}
	in := Input{
		Users:  users,
		Groups: groups,
		TargetUsers: []model.TargetUser{tu("1", "u1", "u1@x.com", false), tu("2", "u2", "u2@x.com", false),
			tu("7", "", "ext@x.com", false)},
		TargetGroups: []model.TargetGroup{
			{ID: "G1", Email: "g1@x.com", Name: "Old name", Members: []model.TargetMember{
				{ID: "1", Email: "u1@x.com", Kind: model.KindUser},
				{ID: "2", Email: "u2@x.com", Kind: model.KindUser},  // managed, not desired: removed
				{ID: "7", Email: "ext@x.com", Kind: model.KindUser}, // unmanaged: kept
				{Email: "partner@other.org"},                        // external: kept
			}},
			{ID: "G3", Email: "g3@x.com", Name: "G3"}, // exists but unmanaged
			{ID: "G9", Email: "old@x.com", Name: "Old"},
		},
		Links: []Link{
			{Kind: model.KindUser, SourceID: "u1", TargetID: "1", Key: "u1@x.com"},
			{Kind: model.KindUser, SourceID: "u2", TargetID: "2", Key: "u2@x.com"},
			{Kind: model.KindGroup, SourceID: "g1", TargetID: "G1", Key: "g1@x.com"},
			{Kind: model.KindGroup, SourceID: "g9", TargetID: "G9", Key: "old@x.com"}, // left the scope
		},
		InFlight: []InFlight{},
		Policy:   Policy{ManageGroups: true},
	}
	p := Compute(in)
	want := "user.create:u3@x.com group.update:g1@x.com group.create:g2@x.com member.add:g1@x.com member.add:g1@x.com member.remove:g1@x.com"
	if got := kinds(p); got != want {
		t.Fatalf("ops\n got %s\nwant %s", got, want)
	}
	var codes []string
	for _, w := range p.Warnings {
		codes = append(codes, w.Code+":"+w.Key)
	}
	joined := strings.Join(codes, " ")
	for _, k := range []string{"group-out-of-scope:old@x.com", "unmanaged-exists:g3@x.com", "unmanaged-member-kept:g1@x.com"} {
		if !strings.Contains(joined, k) {
			t.Errorf("missing %s in %s", k, joined)
		}
	}
	// With RemoveUnmanagedMembers, the external and unmanaged members go.
	in.Policy.RemoveUnmanagedMembers = true
	if c := Compute(in).Counts(); c[MemberRemove] != 3 {
		t.Fatalf("remove unmanaged: %v", c)
	}
	// An in-flight create of g3 makes the existing group ours.
	in.InFlight = []InFlight{{Kind: GroupCreate, SourceID: "g3", Key: "g3@x.com"}}
	if c := Compute(in).Counts(); c[GroupRelink] != 1 {
		t.Fatalf("in-flight relink: %v", c)
	}
}

func TestLimits(t *testing.T) {
	p := &Plan{SourceUsers: 90, ManagedUsers: 100}
	for i := 0; i < 12; i++ {
		p.Ops = append(p.Ops, Op{Kind: UserSuspend, TargetID: string(rune('a' + i))})
	}
	v := DefaultLimits().Check(p, 100)
	var names []string
	for _, x := range v {
		names = append(names, x.Limit)
	}
	if strings.Join(names, ",") != "max_suspends,max_touched_percent" {
		t.Fatalf("violations %v", v)
	}
	l := DefaultLimits()
	l.MaxSuspends, l.MaxTouchedPercent = Unlimited, Unlimited
	if v := l.Check(p, 100); len(v) != 0 {
		t.Fatalf("unlimited: %v", v)
	}
	l.MaxSuspends = 0
	if v := l.Check(&Plan{Ops: []Op{{Kind: UserSuspend}}, SourceUsers: 1}, 0); len(v) != 1 {
		t.Fatalf("zero means none allowed: %v", v)
	}
	if v := DefaultLimits().Check(&Plan{SourceUsers: 50}, 100); len(v) != 1 || v[0].Limit != "max_source_drop_percent" {
		t.Fatalf("source drop: %v", v)
	}
	if v := DefaultLimits().Check(&Plan{SourceUsers: 0}, 0); len(v) != 1 || v[0].Limit != "min_source_users" {
		t.Fatalf("empty source: %v", v)
	}
}

func TestOpString(t *testing.T) {
	o := Op{Kind: UserCreate, Key: "a@x.com", Attrs: model.UserAttrs{model.FieldPrimaryEmail: "a@x.com"}, Suspend: true}
	s := o.String()
	if !strings.Contains(s, "user.create") || !strings.Contains(s, "suspended = true") {
		t.Fatal(s)
	}
}
