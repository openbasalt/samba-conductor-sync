package api

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/connector/google"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// TestImportPlanIsReadOnly: import.plan reads an existing company's
// directory through the read-only scopes, writes nothing to Google (no
// request but reads), records no run, and audits the read with the actor.
func TestImportPlanIsReadOnly(t *testing.T) {
	e := newTEnv(t)
	e.fake.AddOrgUnit("/Sales")
	e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "ana@example.com", OrgUnitPath: "/Sales", Name: map[string]any{"givenName": "Ana", "familyName": "Ribeiro"},
		Aliases: []string{"ana.ribeiro@example.com"}, Organizations: []map[string]any{{"title": "Manager", "department": "Sales", "primary": true}},
		Phones: []map[string]any{{"type": "mobile", "value": "+55 11 99999-0001"}}, ExternalIDs: []map[string]any{{"type": "organization", "value": "E1"}}})
	e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "bruno@example.com", OrgUnitPath: "/Sales", Suspended: true, Name: map[string]any{"givenName": "Bruno", "familyName": "Costa"}})
	g := e.fake.SeedGroup(fakegoogle.Group{Email: "sales@example.com", Name: "Sales", Description: "Sales team"})
	e.fake.AddMemberDirect(g.ID, "ana@example.com")
	e.fake.AddMemberDirect(g.ID, "bruno@example.com")
	e.fake.AddMemberDirect(g.ID, "partner@external.example")
	e.must(syncapi.OpKeySet, syncapi.KeySetParams{KeyJSON: string(e.fake.KeyJSON())}, nil)

	var writeScopes []bool
	connect := e.rt.Connect
	e.rt.Connect = func(gc google.Config, key *google.ServiceAccountKey, write bool) (connector.Connector, error) {
		writeScopes = append(writeScopes, write)
		return connect(gc, key, write)
	}
	e.fake.ResetCounters()

	var pl syncapi.ImportPlan
	e.must(syncapi.OpImportPlan, syncapi.ImportPlanParams{Groups: true}, &pl)
	if len(pl.Users) != 1 || pl.Users[0].Email != "ana@example.com" || pl.Users[0].Title != "Manager" || pl.Users[0].PhoneMobile != "+55 11 99999-0001" ||
		pl.Users[0].EmployeeID != "E1" || pl.Users[0].OrgUnit != "/Sales" || pl.Users[0].GivenName != "Ana" {
		t.Fatalf("users %+v", pl.Users)
	}
	// The sync's own admin subject is an administrator: left out by default.
	if pl.SkippedCounts[syncapi.ImportSkipSuspended] != 1 || pl.SkippedCounts[syncapi.ImportSkipAdmin] != 1 {
		t.Fatalf("skipped %+v", pl.SkippedCounts)
	}
	if len(pl.Groups) != 1 || strings.Join(pl.Groups[0].Users, ",") != "ana@example.com" || pl.Groups[0].LeftOut != 2 {
		t.Fatalf("groups %+v", pl.Groups)
	}
	if len(writeScopes) != 1 || writeScopes[0] {
		t.Fatalf("import.plan must use the read-only scopes only: %v", writeScopes)
	}
	if w := e.fake.Writes(); len(w) != 0 {
		t.Fatalf("import.plan wrote to Google: %+v", w)
	}
	if runs, total, _ := e.rt.Store.ListRuns(context.Background(), "google", "", 0, 10); total != 0 || len(runs) != 0 {
		t.Fatalf("import.plan recorded a run: %d", total)
	}
	var audit bytes.Buffer
	_, _ = e.rt.Store.ExportAudit(context.Background(), &audit)
	if !strings.Contains(audit.String(), `"action":"api.import.plan"`) || !strings.Contains(audit.String(), "planned 1 users, 1 groups") ||
		!strings.Contains(audit.String(), "conductor:lab.admin") {
		t.Fatalf("audit: %s", audit.String())
	}

	// A filter naming a missing group is refused, and invalid parameters
	// never reach Google.
	if err := e.call(syncapi.OpImportPlan, syncapi.ImportPlanParams{MemberOf: []string{"nobody@example.com"}}, nil); err == nil || err.Code != syncapi.CodeInvalid {
		t.Fatalf("missing group: %v", err)
	}
	if _, err := syncapi.NewRequest("req-bad-0001", syncapi.OpImportPlan, actor, syncapi.ImportPlanParams{OrgUnits: []string{"Sales"}}); err == nil {
		t.Fatal("an org unit without / was accepted")
	}
	if syncapi.OpImportPlan.Mutating() {
		t.Fatal("import.plan must not be a mutation")
	}
}

// TestImportPlanWithoutKey: no service account key is an unavailable
// service, not a crash.
func TestImportPlanWithoutKey(t *testing.T) {
	e := newTEnv(t)
	if err := e.call(syncapi.OpImportPlan, syncapi.ImportPlanParams{}, nil); err == nil || err.Code != syncapi.CodeUnavailable {
		t.Fatalf("without a key: %v", err)
	}
}
