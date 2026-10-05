package main

import (
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
)

// TestSeed: accounts, groups with user, nested group and external members,
// and a second seed that leaves existing objects alone.
func TestSeed(t *testing.T) {
	fake := fakegoogle.New("example.com")
	req := seedRequest{OrgUnits: []string{"/Sales"},
		Users: []fakegoogle.User{{PrimaryEmail: "ana@example.com", OrgUnitPath: "/Sales"}},
		Groups: []seedGroup{
			{Email: "all@example.com", Name: "All", Members: []string{"sales@example.com", "x@external.example"}},
			{Email: "sales@example.com", Name: "Sales", Members: []string{"ana@example.com"}},
		}}
	got := seed(fake, req)
	if got["users"] != 1 || got["groups"] != 2 || got["members"] != 3 {
		t.Fatalf("seed %v", got)
	}
	_, members, ok := fake.GroupByEmail("all@example.com")
	if !ok || len(members) != 2 {
		t.Fatalf("members %v", members)
	}
	if again := seed(fake, req); again["users_existing"] != 1 || again["groups_existing"] != 2 || again["members"] != 0 {
		t.Fatalf("second seed %v", again)
	}
}
