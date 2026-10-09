package g2a

import (
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

const (
	managedOU    = "OU=People,OU=Google,DC=lab,DC=test"
	quarantineOU = "OU=Quarantine," + managedOU
	realm        = "lab.test"
)

func unlimited() Limits {
	return Limits{MaxCreates: -1, MaxDisables: -1, MaxReenables: -1, MaxUpdates: -1, MaxRenames: -1, MaxTouchedPercent: -1,
		MinSourceSize: -1, MaxSourceDropPercent: -1}
}

func testScope() Scope {
	return Scope{Name: "people", Mode: syncapi.G2AModeApply, ManagedOU: managedOU, GroupsOU: "OU=Groups," + managedOU,
		QuarantineOU: quarantineOU, OrgUnits: []string{"/Staff"}, SubOrgUnits: true, Fields: []model.UserField{model.FieldTitle},
		LogonTemplate: DefaultLogonTemplate, Limits: unlimited()}
}

func gu(id, email, given, family string) GoogleUser {
	return GoogleUser{ID: id, Email: email, Given: given, Family: family, OrgUnit: "/Staff", Fields: model.UserAttrs{}}
}

// marked is an AD account carrying the marker of a Google ID, holding the
// Google values of u.
func marked(u GoogleUser, sam string, n int) ADUser {
	v := googleValues(u, []model.UserField{model.FieldTitle})
	return ADUser{DN: "CN=" + displayName(u) + "," + managedOU, SAM: sam, SID: sidOf(n), GUID: guidOf(n), UPN: sam + "@" + realm,
		Mail: u.Email, Marker: syncapi.G2AMarker(u.ID), Enabled: true, PwdLastSet: true,
		Attrs: map[string]string{"givenName": v["givenName"], "sn": v["sn"], "displayName": v["displayName"], "title": v["title"]}}
}

func sidOf(n int) string  { return "S-1-5-21-1-2-3-" + itoa(1100+n) }
func guidOf(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func itoa(n int) string   { return strconv.Itoa(n) }

func emptyAD() *ADState {
	return &ADState{SchemaHasMarker: true, Managed: map[string][]ADUser{}, TakenSAM: map[string]bool{}, TakenUPN: map[string]bool{},
		TakenCN: map[string]bool{}, Privileged: map[string][]string{}}
}

// linkOf is the link a confirmed apply leaves for an account.
func linkOf(u GoogleUser, a ADUser) Link {
	return Link{Scope: "people", GoogleID: u.ID, ObjectGUID: a.GUID, SID: a.SID, SAM: a.SAM,
		Snapshot: googleValues(u, []model.UserField{model.FieldTitle})}
}

func plan(t *testing.T, users []GoogleUser, ad *ADState, links []Link, scopes ...Scope) *Result {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []Scope{testScope()}
	}
	sel, err := Select(users, nil, scopes, "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Taken names come from the AD objects (as the AD read reports them).
	for _, list := range append([][]ADUser{ad.Others}, mapValues(ad.Managed)...) {
		for _, o := range list {
			ad.TakenSAM[strings.ToLower(o.SAM)] = true
			ad.TakenUPN[strings.ToLower(o.UPN)] = true
			if p := parentOf(o.DN); p != "" {
				_, first, _ := strings.Cut(o.DN, "=")
				cnv, _, _ := strings.Cut(first, ",")
				ad.TakenCN[CNKey(p, cnv)] = true
			}
		}
	}
	res, err := Build(Input{Now: time.Unix(0, 0), GoogleDomain: "example.com", Realm: realm, Scopes: scopes, Selection: sel, AD: ad, Links: links})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func mapValues(m map[string][]ADUser) [][]ADUser {
	var out [][]ADUser
	for _, k := range sortedKeys(m) {
		out = append(out, m[k])
	}
	return out
}

func ops(r *Result, kind string) []syncapi.G2AOp {
	var out []syncapi.G2AOp
	for _, o := range r.Plan.Ops() {
		if o.Kind == kind {
			out = append(out, o)
		}
	}
	return out
}

func skipped(r *Result, reason string) []syncapi.G2ASkipped {
	var out []syncapi.G2ASkipped
	for _, s := range r.Plan.Scopes {
		for _, k := range s.Skipped {
			if k.Reason == reason {
				out = append(out, k)
			}
		}
	}
	return out
}

func change(o syncapi.G2AOp, field string) (syncapi.G2AChange, bool) {
	for _, c := range o.Changes {
		if c.Field == field {
			return c, true
		}
	}
	return syncapi.G2AChange{}, false
}

func TestLogonRulesMatchTheImport(t *testing.T) {
	cases := []struct{ given, family, email, tmpl, want string }{
		{"Ana", "Ribeiro", "ana@example.com", DefaultLogonTemplate, "ana,ana.ribeiro"},
		{"José", "da Silva", "jose.da.silva.from.sales@example.com", DefaultLogonTemplate, "jose.silva"},
		{"Zoë", "Ångström", "ZOE@example.com", "{g}{family}", "zoe,zangstrom"},
		{"Ana", "Ribeiro", "a+b@example.com", "{local}", "ab"},
	}
	for _, c := range cases {
		if got := strings.Join(LogonCandidates(c.tmpl, c.given, c.family, c.email), ","); got != c.want {
			t.Errorf("%s: %q, want %q", c.email, got, c.want)
		}
	}
	if ValidLogonTemplate("{given}.{family}x!") || ValidLogonTemplate("plain") || !ValidLogonTemplate("{g}{family}") {
		t.Error("template validation")
	}
}

func TestCreate(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	ana.Fields[model.FieldTitle] = "Manager"
	ana.Fields[model.FieldDepartment] = "Sales" // not a field of the scope
	bob := gu("102", "bob@example.com", "Bob", "Stone")
	ad := emptyAD()
	// "bob" is taken by an unrelated object: the template is used instead.
	ad.Others = []ADUser{{DN: "CN=bob,CN=Computers,DC=lab,DC=test", SAM: "bob", UPN: "bob@" + realm}}
	r := plan(t, []GoogleUser{bob, ana}, ad, nil)
	cr := ops(r, syncapi.G2AUserCreate)
	if len(cr) != 2 || cr[0].GoogleID != "101" || cr[1].GoogleID != "102" {
		t.Fatalf("creates %+v", cr)
	}
	a := cr[0]
	if a.SAM != "ana" || a.DN != "CN=Ana Ribeiro,"+managedOU || !a.Invite || a.Marker != "google-first:101" || a.ParentOU != managedOU ||
		a.Reason != syncapi.G2AReasonNew || a.Enable || a.SID != "" {
		t.Fatalf("create %+v", a)
	}
	for field, want := range map[string]string{"sAMAccountName": "ana", "userPrincipalName": "ana@lab.test", "cn": "Ana Ribeiro",
		"mail": "ana@example.com", "givenName": "Ana", "sn": "Ribeiro", "displayName": "Ana Ribeiro", "title": "Manager"} {
		if c, ok := change(a, field); !ok || c.After != want || c.Before != "" {
			t.Errorf("%s: %+v", field, c)
		}
	}
	if _, ok := change(a, "department"); ok {
		t.Error("a field outside the scope's fields was planned")
	}
	if cr[1].SAM != "bob.stone" {
		t.Fatalf("fallback logon name: %+v", cr[1])
	}
	if len(r.Accounts) != 2 || r.Accounts[0].Snapshot["title"] != "Manager" {
		t.Fatalf("accounts %+v", r.Accounts)
	}
}

func TestCreateConflicts(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	ana2 := gu("102", "ana+r@example.com", "Ana", "Ribeiro")   // fallback "ana.ribeiro"
	ana3 := gu("103", "ana.ribeiro@example.com", "Ana", "Lee") // local part "ana.ribeiro"
	cara := gu("104", "cara@example.com", "Cara", "Lima")
	dan := gu("105", "dan@example.com", "Dan", "Moss")
	eve := gu("106", "eve@example.com", "Eve", "Hart")
	ad := emptyAD()
	ad.Others = []ADUser{
		// ana's address is the proxy address of an AD user outside the
		// managed OU: never created.
		{DN: "CN=Old Ana,OU=Staff,DC=lab,DC=test", SAM: "oldana", ProxyAddresses: []string{"SMTP:ana@example.com"}},
		// cara's address is on an account marked for another Google ID.
		{DN: "CN=Cara,OU=Quarantine," + managedOU, SAM: "cara", Mail: "cara@example.com", Marker: "google-first:999"},
		// dan's local part and template are both taken.
		{DN: "CN=dan,CN=Users,DC=lab,DC=test", SAM: "dan"}, {DN: "CN=dmoss,CN=Users,DC=lab,DC=test", SAM: "dan.moss"},
	}
	// eve's marker sits on an object outside the managed OU.
	ad.Others = append(ad.Others, ADUser{DN: "CN=Eve,OU=Elsewhere,DC=lab,DC=test", SAM: "evex", Marker: "google-first:106"})
	r := plan(t, []GoogleUser{ana, ana2, ana3, cara, dan, eve}, ad, nil)
	if c := ops(r, syncapi.G2AUserCreate); len(c) != 0 {
		t.Fatalf("created %+v", c)
	}
	want := map[string]string{"101": syncapi.G2ASkipUnmanagedExists, "102": syncapi.G2ASkipDuplicateLogon, "103": syncapi.G2ASkipDuplicateLogon,
		"104": syncapi.G2ASkipMarkerMismatch, "105": syncapi.G2ASkipNoFreeLogon, "106": syncapi.G2ASkipUnmanagedExists}
	got := map[string]string{}
	for _, s := range r.Plan.Scopes[0].Skipped {
		got[s.GoogleID] = s.Reason
	}
	for id, reason := range want {
		if got[id] != reason {
			t.Errorf("%s: %q, want %q", id, got[id], reason)
		}
	}
}

func TestCNVariant(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	ad := emptyAD()
	ad.TakenCN[CNKey(managedOU, "ana ribeiro")] = true
	r := plan(t, []GoogleUser{ana}, ad, nil)
	if c := ops(r, syncapi.G2AUserCreate); len(c) != 1 || c[0].DN != "CN=Ana Ribeiro (ana),"+managedOU {
		t.Fatalf("%+v", c)
	}
}

func TestPrivilegedSkipped(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	ana.Suspended = true
	a := marked(ana, "ana", 1)
	a.Attrs["title"] = "drifted"
	ad := emptyAD()
	ad.Managed["people"] = []ADUser{a}
	ad.Privileged[a.SID] = []string{"group: S-1-5-21-1-2-3-512"}
	r := plan(t, []GoogleUser{ana}, ad, []Link{linkOf(ana, a)})
	if n := len(r.Plan.Ops()); n != 0 {
		t.Fatalf("a privileged account got %d operations", n)
	}
	s := skipped(r, syncapi.G2ASkipPrivileged)
	if len(s) != 1 || s[0].SAM != "ana" || len(s[0].Detail) != 1 {
		t.Fatalf("skips %+v", s)
	}
	// adminCount alone is enough.
	a.AdminCount = true
	ad.Privileged = map[string][]string{}
	ad.Managed["people"] = []ADUser{a}
	if r := plan(t, []GoogleUser{ana}, ad, nil); len(r.Plan.Ops()) != 0 || len(skipped(r, syncapi.G2ASkipPrivileged)) != 1 {
		t.Fatal("adminCount")
	}
}

func TestDriftAndGoogleChange(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	a := marked(ana, "ana", 1)
	link := linkOf(ana, a)
	ad := emptyAD()
	// An AD administrator changed the given name: reverted (P2).
	a.Attrs["givenName"] = "Anna"
	ad.Managed["people"] = []ADUser{a}
	r := plan(t, []GoogleUser{ana}, ad, []Link{link})
	up := ops(r, syncapi.G2AUserUpdate)
	if len(up) != 1 || up[0].Reason != syncapi.G2AReasonADDrift || up[0].SID != a.SID || up[0].ObjectGUID != a.GUID {
		t.Fatalf("drift %+v", up)
	}
	if c, _ := change(up[0], "givenName"); c.Before != "Anna" || c.After != "Ana" {
		t.Fatalf("change %+v", c)
	}
	// Google changed the title: a google-change.
	a.Attrs["givenName"] = "Ana"
	ad.Managed["people"] = []ADUser{a}
	ana.Fields[model.FieldTitle] = "Director"
	r = plan(t, []GoogleUser{ana}, ad, []Link{link})
	up = ops(r, syncapi.G2AUserUpdate)
	if len(up) != 1 || up[0].Reason != syncapi.G2AReasonGoogleChange {
		t.Fatalf("google change %+v", up)
	}
	// In sync: nothing to do.
	a.Attrs["title"] = "Director"
	ad.Managed["people"] = []ADUser{a}
	if r := plan(t, []GoogleUser{ana}, ad, []Link{link}); len(r.Plan.Ops()) != 0 {
		t.Fatalf("%+v", r.Plan.Ops())
	}
}

func TestRename(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	a := marked(ana, "ana", 1)
	a.ProxyAddresses = []string{"SMTP:ana@example.com", "smtp:ana.r@example.com"}
	link := linkOf(ana, a)
	ana.Email = "ana.ribeiro@example.com"
	ad := emptyAD()
	ad.Managed["people"] = []ADUser{a}
	r := plan(t, []GoogleUser{ana}, ad, []Link{link})
	rn := ops(r, syncapi.G2AUserRename)
	if len(rn) != 1 || len(ops(r, syncapi.G2AUserUpdate)) != 0 || rn[0].SAM != "ana" {
		t.Fatalf("%+v", r.Plan.Ops())
	}
	if c, _ := change(rn[0], "mail"); c.Before != "ana@example.com" || c.After != "ana.ribeiro@example.com" {
		t.Fatalf("mail %+v", c)
	}
	if c, _ := change(rn[0], "proxyAddresses"); c.After != "smtp:ana.r@example.com\nsmtp:ana@example.com" ||
		c.Before != "smtp:ana.r@example.com\nSMTP:ana@example.com" {
		t.Fatalf("proxyAddresses %+v", c)
	}
	// Without the snapshot, a different mail is an AD drift (no proxy
	// address is invented from a value Google never had).
	r = plan(t, []GoogleUser{ana}, ad, nil)
	if up := ops(r, syncapi.G2AUserUpdate); len(up) != 1 || up[0].Reason != syncapi.G2AReasonADDrift || len(ops(r, syncapi.G2AUserRename)) != 0 {
		t.Fatalf("%+v", r.Plan.Ops())
	}
}

func TestDisableAndReenable(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	a := marked(ana, "ana", 1)
	link := linkOf(ana, a)
	ad := emptyAD()
	ad.Managed["people"] = []ADUser{a}
	// Suspended in Google: disable and quarantine.
	ana.Suspended = true
	r := plan(t, []GoogleUser{ana}, ad, []Link{link})
	d := ops(r, syncapi.G2AUserDisable)
	if len(d) != 1 || !d[0].Disable || d[0].MoveTo != quarantineOU || d[0].Reason != syncapi.G2AReasonSuspended {
		t.Fatalf("disable %+v", d)
	}
	// Deleted in Google (ID gone): disabled too, never deleted. (bob keeps
	// the selection from being empty.)
	bob := gu("102", "bob@example.com", "Bob", "Stone")
	r = plan(t, []GoogleUser{bob}, ad, []Link{link})
	if d := ops(r, syncapi.G2AUserDisable); len(d) != 1 || d[0].Reason != syncapi.G2AReasonDeleted {
		t.Fatalf("deleted %+v", d)
	}
	// Out of the selection (moved to another org unit).
	moved := ana
	moved.Suspended, moved.OrgUnit = false, "/Other"
	r = plan(t, []GoogleUser{moved, bob}, ad, []Link{link})
	if d := ops(r, syncapi.G2AUserDisable); len(d) != 1 || d[0].Reason != syncapi.G2AReasonOutOfSelection {
		t.Fatalf("deselected %+v", d)
	}
	// Disabled and quarantined already: nothing more.
	q := a
	q.Enabled, q.DN = false, "CN=Ana Ribeiro,"+quarantineOU
	ad.Managed["people"] = []ADUser{q}
	link.DisabledBySync = true
	if r := plan(t, []GoogleUser{ana}, ad, []Link{link}); len(r.Plan.Ops()) != 0 {
		t.Fatalf("%+v", r.Plan.Ops())
	}
	// Active again, disabled by the sync: re-enable and move back.
	ana.Suspended = false
	r = plan(t, []GoogleUser{ana}, ad, []Link{link})
	re := ops(r, syncapi.G2AUserReenable)
	if len(re) != 1 || !re[0].Enable || re[0].MoveTo != managedOU {
		t.Fatalf("reenable %+v", r.Plan.Ops())
	}
	// Disabled by an AD administrator: never re-enabled.
	link.DisabledBySync = false
	r = plan(t, []GoogleUser{ana}, ad, []Link{link})
	if len(ops(r, syncapi.G2AUserReenable)) != 0 || len(skipped(r, syncapi.G2ASkipDisabledOutsideSync)) != 1 {
		t.Fatalf("%+v %+v", r.Plan.Ops(), r.Plan.Scopes[0].Skipped)
	}
	// Created by the sync and waiting for its invitation: left alone.
	w := a
	w.Enabled, w.PwdLastSet = false, false
	ad.Managed["people"] = []ADUser{w}
	r = plan(t, []GoogleUser{ana}, ad, []Link{link})
	if len(r.Plan.Ops()) != 0 || len(r.Plan.Scopes[0].Skipped) != 0 {
		t.Fatalf("%+v %+v", r.Plan.Ops(), r.Plan.Scopes[0].Skipped)
	}
}

func TestDeletedAndRecreatedIsANewPerson(t *testing.T) {
	old := gu("101", "ana@example.com", "Ana", "Ribeiro")
	a := marked(old, "ana", 1)
	ad := emptyAD()
	ad.Managed["people"] = []ADUser{a}
	ad.Others = []ADUser{a} // the AD read finds it by address too
	recreated := gu("202", "ana@example.com", "Ana", "Ribeiro")
	r := plan(t, []GoogleUser{recreated}, ad, []Link{linkOf(old, a)})
	if d := ops(r, syncapi.G2AUserDisable); len(d) != 1 || d[0].GoogleID != "101" || d[0].Reason != syncapi.G2AReasonDeleted {
		t.Fatalf("old account %+v", r.Plan.Ops())
	}
	if c := ops(r, syncapi.G2AUserCreate); len(c) != 0 {
		t.Fatalf("the new Google account took over: %+v", c)
	}
	if s := skipped(r, syncapi.G2ASkipMarkerMismatch); len(s) != 1 || s[0].GoogleID != "202" {
		t.Fatalf("skips %+v", r.Plan.Scopes[0].Skipped)
	}
}

func TestMarkerMismatch(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	a := marked(ana, "ana", 1)
	b := marked(ana, "ana2", 2) // the same marker on two accounts
	ad := emptyAD()
	ad.Managed["people"] = []ADUser{a, b}
	r := plan(t, []GoogleUser{ana}, ad, nil)
	if len(r.Plan.Ops()) != 0 || len(skipped(r, syncapi.G2ASkipMarkerMismatch)) != 2 {
		t.Fatalf("%+v", r.Plan.Scopes[0])
	}
	// The link names another AD account than the one with the marker.
	ad.Managed["people"] = []ADUser{a}
	l := linkOf(ana, a)
	l.ObjectGUID = guidOf(9)
	r = plan(t, []GoogleUser{ana}, ad, []Link{l})
	if len(r.Plan.Ops()) != 0 || len(skipped(r, syncapi.G2ASkipMarkerMismatch)) != 1 {
		t.Fatalf("%+v", r.Plan.Scopes[0])
	}
}

func TestAdminsAndADFirst(t *testing.T) {
	boss := gu("101", "boss@example.com", "Big", "Boss")
	boss.Admin = true
	synced := gu("102", "synced@example.com", "Sync", "Ed")
	synced.ADFirst = true
	other := gu("103", "x@other.example", "Out", "Side")
	ana := gu("104", "ana@example.com", "Ana", "Ribeiro")
	r := plan(t, []GoogleUser{boss, synced, other, ana}, emptyAD(), nil)
	c := ops(r, syncapi.G2AUserCreate)
	if len(c) != 1 || c[0].GoogleID != "104" || r.Plan.Scopes[0].SourceSize != 1 {
		t.Fatalf("creates %+v", c)
	}
	if s := skipped(r, syncapi.G2ASkipManagedByADFirst); len(s) != 1 || s[0].GoogleID != "102" {
		t.Fatalf("skips %+v", r.Plan.Scopes[0].Skipped)
	}
	// A linked account whose Google user becomes a super administrator:
	// the flag changes nothing in AD (no disable, updates go on).
	a := marked(ana, "ana", 1)
	bob := gu("105", "bob@example.com", "Bob", "Stone")
	bm := marked(bob, "bob", 2)
	ad := emptyAD()
	ad.Managed["people"] = []ADUser{a, bm}
	ana.Admin = true
	r = plan(t, []GoogleUser{ana, boss, bob}, ad, []Link{linkOf(ana, a), linkOf(bob, bm)})
	if len(r.Plan.Ops()) != 0 {
		t.Fatalf("admin flag changed AD: %+v", r.Plan.Ops())
	}
}

func TestTwoScopes(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	bob := gu("102", "bob@example.com", "Bob", "Stone")
	s1 := testScope()
	s2 := testScope()
	s2.Name, s2.ManagedOU, s2.QuarantineOU, s2.OrgUnits = "contractors", "OU=Contractors,OU=Google,DC=lab,DC=test",
		"OU=Quarantine,OU=Contractors,OU=Google,DC=lab,DC=test", []string{"/"}
	r := plan(t, []GoogleUser{ana, bob}, emptyAD(), nil, s1, s2)
	if len(r.Plan.Ops()) != 0 || len(skipped(r, syncapi.G2ASkipInTwoScopes)) != 4 {
		t.Fatalf("%+v", r.Plan.Scopes)
	}
	if r.Plan.Scopes[0].Name != "contractors" || r.Plan.Scopes[1].Name != "people" {
		t.Fatal("scopes are sorted by name")
	}
}

func TestSelectionStops(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	sc := testScope()
	var se *SelectionError
	// Every account of the org unit is out (an administrator): empty.
	boss := ana
	boss.Admin = true
	if _, err := Select([]GoogleUser{boss}, nil, []Scope{sc}, "example.com", nil); !errors.As(err, &se) || se.Code != ErrCodeEmptySelection {
		t.Fatalf("empty: %v", err)
	}
	// A configured org unit without any account.
	sc.OrgUnits = []string{"/Staff", "/Gone"}
	if _, err := Select([]GoogleUser{ana}, nil, []Scope{sc}, "example.com", nil); !errors.As(err, &se) || se.Code != ErrCodeMissingOrgUnit ||
		!strings.Contains(se.Error(), "/Gone") {
		t.Fatalf("missing org unit: %v", err)
	}
	// A member_of group that does not exist.
	sc.OrgUnits = []string{"/Staff"}
	sc.MemberOf = []string{"team@example.com"}
	if _, err := Select([]GoogleUser{ana}, nil, []Scope{sc}, "example.com", nil); !errors.As(err, &se) || se.Code != ErrCodeMissingGroup {
		t.Fatalf("missing group: %v", err)
	}
	// Nested membership selects.
	groups := []model.TargetGroup{{Email: "team@example.com", Members: []model.TargetMember{{Kind: model.KindGroup, Email: "sub@example.com"}}},
		{Email: "sub@example.com", Members: []model.TargetMember{{Kind: model.KindUser, Email: "ana@example.com"}}}}
	sel, err := Select([]GoogleUser{ana, gu("102", "bob@example.com", "Bob", "Stone")}, groups, []Scope{sc}, "example.com", nil)
	if err != nil || len(sel.Scopes["people"].Selected) != 1 || !sel.Scopes["people"].Selected["101"] {
		t.Fatalf("nested: %v %+v", err, sel)
	}
	// A broken scope that is not planned does not stop another one.
	if _, err := Select([]GoogleUser{ana}, nil, []Scope{sc}, "example.com", map[string]bool{"other": true}); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaWithoutMarker(t *testing.T) {
	sel, err := Select([]GoogleUser{gu("101", "ana@example.com", "Ana", "Ribeiro")}, nil, []Scope{testScope()}, "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	ad := emptyAD()
	ad.SchemaHasMarker = false
	if _, err := Build(Input{Scopes: []Scope{testScope()}, Selection: sel, AD: ad}); !errors.Is(err, ErrNoMarkerAttribute) {
		t.Fatalf("%v", err)
	}
}

func TestDeterministicDigest(t *testing.T) {
	var users []GoogleUser
	for i := 0; i < 30; i++ {
		u := gu(itoa(1000+i), "user"+itoa(i)+"@example.com", "User", "N"+itoa(i))
		if i%5 == 0 {
			u.Suspended = true
		}
		users = append(users, u)
	}
	ad := func() *ADState {
		a := emptyAD()
		for i := 0; i < 30; i += 3 {
			o := marked(users[i], "user"+itoa(i), i)
			if i%2 == 0 {
				o.Attrs["sn"] = "drift"
			}
			a.Managed["people"] = append(a.Managed["people"], o)
		}
		return a
	}
	first := plan(t, users, ad(), nil)
	shuffled := slices.Clone(users)
	rand.New(rand.NewSource(7)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	a2 := ad()
	slices.Reverse(a2.Managed["people"])
	second := plan(t, shuffled, a2, nil)
	if first.Plan.Digest != second.Plan.Digest || len(first.Plan.Digest) != 64 {
		t.Fatalf("digest %s != %s", first.Plan.Digest, second.Plan.Digest)
	}
	// Ops are in apply order, then by Google ID, numbered across the plan.
	all := first.Plan.Ops()
	for i, o := range all {
		if o.Seq != i {
			t.Fatalf("seq %d at %d", o.Seq, i)
		}
		if i > 0 && all[i-1].Kind == o.Kind && all[i-1].GoogleID > o.GoogleID {
			t.Fatal("not sorted by Google ID")
		}
	}
	// Another plan gives another digest.
	users[1].Given = "Changed"
	if third := plan(t, users, ad(), nil); third.Plan.Digest == first.Plan.Digest {
		t.Fatal("the digest ignores the operations")
	}
}

func TestLimits(t *testing.T) {
	var users []GoogleUser
	for i := 0; i < 5; i++ {
		users = append(users, gu(itoa(100+i), "u"+itoa(i)+"@example.com", "U", "N"+itoa(i)))
	}
	sc := testScope()
	sc.Limits = DefaultLimits()
	sc.Limits.MaxCreates = 3
	r := plan(t, users, emptyAD(), nil, sc)
	sp := r.Plan.Scopes[0]
	if !sp.Blocked {
		t.Fatalf("not blocked: %+v", sp.Limits)
	}
	for _, row := range sp.Limits {
		if (row.Limit == "max_creates") != row.Exceeded {
			t.Errorf("%+v", row)
		}
	}
	// Source size and drop.
	sc.Limits = unlimited()
	sc.Limits.MinSourceSize = 10
	sc.Limits.MaxSourceDropPercent = 20
	sel, _ := Select(users, nil, []Scope{sc}, "example.com", nil)
	res, err := Build(Input{Realm: realm, Scopes: []Scope{sc}, Selection: sel, AD: emptyAD(), PreviousSourceSize: map[string]int{"people": 10}})
	if err != nil {
		t.Fatal(err)
	}
	exceeded := map[string]bool{}
	for _, row := range res.Plan.Scopes[0].Limits {
		exceeded[row.Limit] = row.Exceeded
	}
	if !exceeded["min_source_size"] || !exceeded["max_source_drop_percent"] || exceeded["max_creates"] {
		t.Fatalf("%+v", res.Plan.Scopes[0].Limits)
	}
	// Touched share of the managed accounts.
	ad := emptyAD()
	for i, u := range users {
		o := marked(u, "u"+itoa(i), i)
		if i < 2 {
			o.Attrs["sn"] = "drift"
		}
		ad.Managed["people"] = append(ad.Managed["people"], o)
	}
	sc.Limits = unlimited()
	sc.Limits.MaxTouchedPercent = 30
	r = plan(t, users, ad, nil, sc)
	for _, row := range r.Plan.Scopes[0].Limits {
		if row.Limit == "max_touched_percent" && (row.Value != 40 || !row.Exceeded) {
			t.Fatalf("%+v", row)
		}
	}
}

func TestConfirm(t *testing.T) {
	ana := gu("101", "ana@example.com", "Ana", "Ribeiro")
	bob := gu("102", "bob@example.com", "Bob", "Stone")
	bob.Fields[model.FieldTitle] = "Chef"
	cara := gu("103", "cara@example.com", "Cara", "Lima")
	b := marked(bob, "bob", 2)
	b.Attrs["title"] = ""
	b.Attrs["sn"] = "Drift"
	c := marked(cara, "cara", 3)
	ad := emptyAD()
	ad.Managed["people"] = []ADUser{b, c}
	cara.Suspended = true
	r := plan(t, []GoogleUser{ana, bob, cara}, ad, []Link{linkOf(cara, c)})
	create, update, disable := ops(r, syncapi.G2AUserCreate)[0], ops(r, syncapi.G2AUserUpdate)[0], ops(r, syncapi.G2AUserDisable)[0]
	results := []syncapi.G2AOpResult{
		{Seq: create.Seq, Status: syncapi.G2AOpDone, SID: sidOf(1), ObjectGUID: guidOf(1)},
		{Seq: update.Seq, Status: syncapi.G2AOpDone},
		{Seq: disable.Seq, Status: syncapi.G2AOpFailed, Error: "conflict"},
	}
	out, err := Confirm(r, []Link{linkOf(cara, c)}, results)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != syncapi.StatusPartial || out.Done != 2 || out.Failed != 1 || len(out.Links) != 2 {
		t.Fatalf("%+v", out)
	}
	byID := map[string]Link{}
	for _, l := range out.Links {
		byID[l.GoogleID] = l
	}
	if l := byID["101"]; l.SID != sidOf(1) || l.ObjectGUID != guidOf(1) || l.SAM != "ana" || l.Snapshot["mail"] != "ana@example.com" {
		t.Fatalf("create link %+v", l)
	}
	if l := byID["102"]; l.Snapshot["title"] != "Chef" || l.Snapshot["sn"] != "Stone" || l.ObjectGUID != b.GUID {
		t.Fatalf("update link %+v", l)
	}
	// All done: applied; a disable records that the sync disabled it.
	results[2] = syncapi.G2AOpResult{Seq: disable.Seq, Status: syncapi.G2AOpDone}
	out, err = Confirm(r, []Link{linkOf(cara, c)}, results)
	if err != nil || out.Status != syncapi.StatusApplied {
		t.Fatalf("%v %+v", err, out)
	}
	for _, l := range out.Links {
		if l.GoogleID == "103" && !l.DisabledBySync {
			t.Fatal("disabled_by_sync not recorded")
		}
	}
	// Mismatches are refused.
	for _, bad := range [][]syncapi.G2AOpResult{
		{{Seq: 99, Status: syncapi.G2AOpDone}},
		{{Seq: create.Seq, Status: syncapi.G2AOpDone}}, // no SID for a create
	} {
		var ce *ConfirmError
		if _, err := Confirm(r, nil, bad); !errors.As(err, &ce) {
			t.Fatalf("accepted %+v", bad)
		}
	}
	// A dry-run scope and a blocked scope cannot have been applied.
	r.Plan.Scopes[0].Mode = syncapi.G2AModeDryRun
	if _, err := Confirm(r, nil, results[1:2]); err == nil {
		t.Fatal("a dry-run scope was confirmed")
	}
	if out, err := Confirm(r, nil, nil); err != nil || out.Status != syncapi.StatusDryRun {
		t.Fatalf("%v %+v", err, out)
	}
	r.Plan.Scopes[0].Mode, r.Plan.Scopes[0].Blocked = syncapi.G2AModeApply, true
	if out, err := Confirm(r, nil, nil); err != nil || out.Status != syncapi.StatusBlocked {
		t.Fatalf("%v %+v", err, out)
	}
}
