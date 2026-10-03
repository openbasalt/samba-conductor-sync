package fakegoogle

import "testing"

func TestStateRoundTrip(t *testing.T) {
	a := New("example.com")
	a.AddOrgUnit("/Staff/Sales")
	u := a.SeedUser(User{PrimaryEmail: "Ann@example.com", Suspended: true})
	g := a.SeedGroup(Group{Email: "team@example.com", Name: "Team"})
	a.AddMemberDirect(g.ID, u.PrimaryEmail)
	a.AddMemberDirect(g.ID, "outside@other.org")
	b, err := a.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	c := New("example.com")
	c.SetKey(a.PrivateKey())
	if err := c.LoadState(b); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.User("ann@example.com"); !ok || !got.Suspended || got.ID != u.ID {
		t.Fatalf("user %+v", got)
	}
	if _, members, ok := c.GroupByEmail("team@example.com"); !ok || len(members) != 2 {
		t.Fatalf("members %v", members)
	}
	if !c.orgUnits["/Staff/Sales"] || c.PrivateKey() != a.PrivateKey() {
		t.Fatal("org units or key")
	}
	if n := c.SeedUser(User{PrimaryEmail: "new@example.com"}); n.ID == u.ID {
		t.Fatal("ID reused")
	}
	if err := c.LoadState([]byte(`{}`)); err == nil {
		t.Fatal("garbage accepted")
	}
}
