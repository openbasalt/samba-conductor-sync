package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/connector/google"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
	"github.com/openbasalt/samba-conductor-sync/internal/g2a"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

const (
	gfManaged    = "OU=People,OU=Google,DC=lab"
	gfQuarantine = "OU=Quarantine," + gfManaged
)

// fakeAD is the AD side of the Google-first tests: the read the plan
// needs (as adsource.ReadG2A answers it), and apply, which plays conductor
// and the provisioner (conductor-sync itself never writes to AD).
type fakeAD struct {
	mu        sync.Mutex
	users     []g2a.ADUser
	priv      map[string][]string
	noSchema  bool
	roleSIDs  []string
	nextID    int
	readCalls int
}

// ReadG2A makes the test source a Google-first source.
func (f *fakeSource) ReadG2A(ctx context.Context, req g2a.ADRequest) (*g2a.ADState, error) {
	if f.g2a == nil {
		return nil, errors.New("no fake AD")
	}
	return f.g2a.ReadG2A(ctx, req)
}

func below(dn, base string) bool {
	d, err1 := ldap.ParseDN(dn)
	b, err2 := ldap.ParseDN(base)
	return err1 == nil && err2 == nil && b.AncestorOfFold(d)
}

func (f *fakeAD) ReadG2A(_ context.Context, req g2a.ADRequest) (*g2a.ADState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readCalls++
	f.roleSIDs = req.RoleGroupSIDs
	st := &g2a.ADState{SchemaHasMarker: !f.noSchema, Managed: map[string][]g2a.ADUser{}, TakenSAM: map[string]bool{},
		TakenUPN: map[string]bool{}, TakenCN: map[string]bool{}, Privileged: map[string][]string{}}
	for k, v := range f.priv {
		st.Privileged[k] = v
	}
	mails, markers := map[string]bool{}, map[string]bool{}
	for _, m := range req.Mails {
		mails[m] = true
	}
	for _, m := range req.Markers {
		markers[m] = true
	}
	for name, ou := range req.ManagedOUs {
		st.Managed[name] = []g2a.ADUser{}
		for _, u := range f.users {
			if below(u.DN, ou) {
				st.Managed[name] = append(st.Managed[name], u)
			}
		}
	}
	for _, u := range f.users {
		hit := mails[strings.ToLower(u.Mail)] || mails[strings.ToLower(u.UPN)] || markers[u.Marker]
		for _, p := range u.ProxyAddresses {
			hit = hit || mails[strings.ToLower(strings.TrimPrefix(strings.ToLower(p), "smtp:"))]
		}
		if hit {
			st.Others = append(st.Others, u)
		}
		st.TakenSAM[strings.ToLower(u.SAM)] = true
		st.TakenUPN[strings.ToLower(u.UPN)] = true
		parent := u.DN[strings.Index(u.DN, ",")+1:]
		st.TakenCN[g2a.CNKey(parent, u.CN)] = true
	}
	return st, nil
}

func (f *fakeAD) find(sid string) *g2a.ADUser {
	for i := range f.users {
		if f.users[i].SID == sid {
			return &f.users[i]
		}
	}
	return nil
}

func (f *fakeAD) bySAM(sam string) *g2a.ADUser {
	for i := range f.users {
		if f.users[i].SAM == sam {
			return &f.users[i]
		}
	}
	return nil
}

// apply applies the operations of the scopes in apply mode within their
// limits, as conductor does through the provisioner, and returns the
// results for g2a.confirm.
func (f *fakeAD) apply(pl *syncapi.G2APlan) []syncapi.G2AOpResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []syncapi.G2AOpResult
	for _, sc := range pl.Scopes {
		if sc.Mode != syncapi.G2AModeApply || sc.Blocked {
			continue
		}
		for _, o := range sc.Ops {
			res := syncapi.G2AOpResult{Seq: o.Seq, Status: syncapi.G2AOpDone}
			move := func(u *g2a.ADUser) {
				if o.MoveTo != "" {
					u.DN = "CN=" + u.CN + "," + o.MoveTo
				}
			}
			switch o.Kind {
			case syncapi.G2AUserCreate:
				f.nextID++
				u := g2a.ADUser{DN: o.DN, SAM: o.SAM, Marker: o.Marker, Attrs: map[string]string{},
					SID: fmt.Sprintf("S-1-5-21-9-9-9-%d", 3000+f.nextID), GUID: fmt.Sprintf("00000000-0000-4000-9000-%012d", f.nextID)}
				for _, c := range o.Changes {
					switch c.Field {
					case "userPrincipalName":
						u.UPN = c.After
					case "cn":
						u.CN = c.After
					case "mail":
						u.Mail = c.After
					case "sAMAccountName":
					default:
						u.Attrs[c.Field] = c.After
					}
				}
				f.users = append(f.users, u)
				res.SID, res.ObjectGUID = u.SID, u.GUID
			case syncapi.G2AUserUpdate, syncapi.G2AUserRename:
				u := f.find(o.SID)
				for _, c := range o.Changes {
					switch c.Field {
					case "mail":
						u.Mail = c.After
					case "proxyAddresses":
						u.ProxyAddresses = strings.Split(c.After, "\n")
					default:
						u.Attrs[c.Field] = c.After
					}
				}
			case syncapi.G2AUserDisable:
				u := f.find(o.SID)
				u.Enabled = false
				move(u)
			case syncapi.G2AUserReenable:
				u := f.find(o.SID)
				u.Enabled = true
				move(u)
			}
			out = append(out, res)
		}
	}
	return out
}

// invited completes the invitation of an account (password set, enabled).
func (f *fakeAD) invited(sam string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.bySAM(sam)
	u.Enabled, u.PwdLastSet = true, true
}

func gfSettings(mode string, orgUnits []string, memberOf []string) *syncapi.GoogleFirstSettings {
	return &syncapi.GoogleFirstSettings{Enabled: true, GoogleDomain: "example.com", Scopes: []syncapi.G2AScope{{Name: "people", Mode: mode,
		ManagedOU: gfManaged, GroupsOU: "OU=Groups," + gfManaged, QuarantineOU: gfQuarantine, OrgUnits: orgUnits, SubOrgUnits: true,
		MemberOf: memberOf, Fields: []string{"title"},
		// Two accounts: any change touches half of them.
		Limits: &syncapi.G2ALimits{MaxCreates: 20, MaxDisables: 5, MaxReenables: 20, MaxUpdates: 50, MaxRenames: 5, MaxTouchedPercent: -1,
			MinSourceSize: 1, MaxSourceDropPercent: -1}}}}
}

func (e *tenv) setGoogleFirst(gf *syncapi.GoogleFirstSettings) {
	e.t.Helper()
	v, s := e.settings()
	s.GoogleFirst = gf
	e.must(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: v.Version, Settings: s}, nil)
}

func (e *tenv) g2aPlan() *syncapi.G2APlan {
	e.t.Helper()
	var pl syncapi.G2APlan
	e.must(syncapi.OpG2APlan, syncapi.G2APlanParams{RoleGroupSIDs: []string{"S-1-5-21-1-2-3-1600"}}, &pl)
	return &pl
}

func g2aOps(pl *syncapi.G2APlan, kind string) []syncapi.G2AOp {
	var out []syncapi.G2AOp
	for _, o := range pl.Ops() {
		if o.Kind == kind {
			out = append(out, o)
		}
	}
	return out
}

func g2aSkips(pl *syncapi.G2APlan) map[string]string {
	out := map[string]string{}
	for _, s := range pl.Scopes {
		for _, k := range s.Skipped {
			out[k.GoogleID] = k.Reason
		}
	}
	return out
}

// applyAndConfirm applies a plan in the fake AD and confirms it.
func (e *tenv) applyAndConfirm(ad *fakeAD, pl *syncapi.G2APlan) syncapi.G2AConfirmResult {
	e.t.Helper()
	var res syncapi.G2AConfirmResult
	e.must(syncapi.OpG2AConfirm, syncapi.G2AConfirmParams{RunID: pl.RunID, Digest: pl.Digest, Results: ad.apply(pl), Actor: "lab.admin"}, &res)
	return res
}

// TestG2AScenarios walks the life of Google-first accounts against the
// fake Directory API: create, invitation, drift, rename, suspend,
// unsuspend, the admin flag, delete and recreate, a privileged account,
// and the reads that must stop. conductor-sync never writes to Google.
func TestG2AScenarios(t *testing.T) {
	e := newTEnv(t)
	ad := &fakeAD{priv: map[string][]string{}}
	e.src.g2a = ad
	e.must(syncapi.OpKeySet, syncapi.KeySetParams{KeyJSON: string(e.fake.KeyJSON())}, nil)
	var writeScopes []bool
	connect := e.rt.Connect
	e.rt.Connect = func(gc google.Config, key *google.ServiceAccountKey, write bool) (connector.Connector, error) {
		writeScopes = append(writeScopes, write)
		return connect(gc, key, write)
	}
	e.fake.AddOrgUnit("/Staff")
	e.fake.AddOrgUnit("/Staff/Sales")
	ana := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "ana@example.com", OrgUnitPath: "/Staff/Sales",
		Name: map[string]any{"givenName": "Ana", "familyName": "Ribeiro"}, Organizations: []map[string]any{{"title": "Manager", "primary": true}}})
	bob := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "bob@example.com", OrgUnitPath: "/Staff", Name: map[string]any{"givenName": "Bob", "familyName": "Stone"}})
	boss := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "boss@example.com", OrgUnitPath: "/Staff", IsAdmin: true,
		Name: map[string]any{"givenName": "Big", "familyName": "Boss"}})
	synced := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "synced@example.com", OrgUnitPath: "/Staff",
		Name:        map[string]any{"givenName": "Sync", "familyName": "Ed"},
		ExternalIDs: []map[string]any{{"type": "custom", "customType": "conductor-sync", "value": "00000000-0000-4000-8000-000000000001"}}})
	e.fake.ResetCounters()

	// Off by default.
	if err := e.call(syncapi.OpG2APlan, syncapi.G2APlanParams{}, nil); err == nil || err.Code != syncapi.CodeConflict {
		t.Fatalf("disabled: %v", err)
	}
	e.setGoogleFirst(gfSettings(syncapi.G2AModeDryRun, []string{"/Staff"}, nil))

	// 1. The first plan: two creates; the super administrator is never
	// created; the AD-first account is skipped.
	pl := e.g2aPlan()
	cr := g2aOps(pl, syncapi.G2AUserCreate)
	if len(cr) != 2 || cr[0].SAM != "ana" || cr[1].SAM != "bob" || !cr[0].Invite || pl.RunID == 0 || len(pl.Digest) != 64 {
		t.Fatalf("first plan %+v", pl)
	}
	if c := cr[0].Changes; c[1].After != "ana@lab.test" {
		t.Fatalf("upn %+v", c)
	}
	if g2aSkips(pl)[synced.ID] != syncapi.G2ASkipManagedByADFirst || g2aSkips(pl)[boss.ID] != "" {
		t.Fatalf("skips %+v", pl.Scopes[0].Skipped)
	}
	if strings.Join(ad.roleSIDs, ",") != "S-1-5-21-1-2-3-1600" {
		t.Fatalf("role groups %v", ad.roleSIDs)
	}
	// Recorded as a run of action g2a, shown by runs.list and run.get, and
	// not counted as an AD to Google run.
	var runs syncapi.RunsList
	e.must(syncapi.OpRunsList, syncapi.RunsListParams{}, &runs)
	if runs.Total != 1 || runs.Runs[0].Action != syncapi.RunActionG2A || runs.Runs[0].Status != syncapi.StatusPlanned || !runs.Runs[0].HasPlan ||
		runs.Runs[0].Counts[syncapi.G2AUserCreate] != 2 {
		t.Fatalf("runs %+v", runs)
	}
	var d syncapi.RunDetail
	e.must(syncapi.OpRunGet, syncapi.RunGetParams{ID: pl.RunID, Limit: 1}, &d)
	if d.G2A == nil || d.G2A.Digest != pl.Digest || d.OpsMatching != 2 || len(d.G2A.Ops()) != 1 || d.Applicable {
		t.Fatalf("run.get %+v", d)
	}
	var st syncapi.Status
	e.must(syncapi.OpStatus, nil, &st)
	if st.LastRun != nil {
		t.Fatalf("a g2a run shows as the last AD to Google run: %+v", st.LastRun)
	}
	// A dry-run scope cannot have been applied; an empty confirmation
	// closes the run as dry-run.
	if err := e.call(syncapi.OpG2AConfirm, syncapi.G2AConfirmParams{RunID: pl.RunID, Digest: pl.Digest, Actor: "lab.admin",
		Results: []syncapi.G2AOpResult{{Seq: 0, Status: syncapi.G2AOpDone, SID: "S-1-5-21-9-9-9-1", ObjectGUID: "00000000-0000-4000-9000-000000000001"}}}, nil); err == nil ||
		err.Code != syncapi.CodeInvalid {
		t.Fatalf("dry-run confirm: %v", err)
	}
	var cres syncapi.G2AConfirmResult
	e.must(syncapi.OpG2AConfirm, syncapi.G2AConfirmParams{RunID: pl.RunID, Digest: pl.Digest, Actor: "lab.admin"}, &cres)
	if cres.Status != syncapi.StatusDryRun {
		t.Fatalf("%+v", cres)
	}
	if err := e.call(syncapi.OpG2AConfirm, syncapi.G2AConfirmParams{RunID: pl.RunID, Digest: pl.Digest, Actor: "lab.admin"}, nil); err == nil ||
		err.Code != syncapi.CodeConflict {
		t.Fatalf("second confirm: %v", err)
	}

	// 2. Apply mode: create, then the accounts wait for their invitation.
	e.setGoogleFirst(gfSettings(syncapi.G2AModeApply, []string{"/Staff"}, nil))
	pl = e.g2aPlan()
	if err := e.call(syncapi.OpG2AConfirm, syncapi.G2AConfirmParams{RunID: pl.RunID, Digest: strings.Repeat("0", 64), Actor: "lab.admin"}, nil); err == nil ||
		err.Code != syncapi.CodeConflict {
		t.Fatalf("wrong digest: %v", err)
	}
	if res := e.applyAndConfirm(ad, pl); res.Status != syncapi.StatusApplied || res.Done != 2 || res.Links != 2 {
		t.Fatalf("confirm %+v", res)
	}
	if links, _ := e.rt.Store.G2ALinks(context.Background()); len(links) != 2 || links[0].GoogleID != ana.ID || links[0].SID == "" {
		t.Fatalf("links %+v", links)
	}
	if pl = e.g2aPlan(); len(pl.Ops()) != 0 || len(pl.Scopes[0].Skipped) != 1 {
		t.Fatalf("waiting for invitations: %+v %+v", pl.Ops(), pl.Scopes[0].Skipped)
	}
	ad.invited("ana")
	ad.invited("bob")

	// 3. Drift: an AD administrator edits a Google-owned field; reverted.
	ad.bySAM("ana").Attrs["title"] = "Intern"
	pl = e.g2aPlan()
	if up := g2aOps(pl, syncapi.G2AUserUpdate); len(up) != 1 || up[0].Reason != syncapi.G2AReasonADDrift || up[0].Changes[0].After != "Manager" {
		t.Fatalf("drift %+v", pl.Ops())
	}
	e.applyAndConfirm(ad, pl)

	// 4. Rename in Google.
	u, _ := e.fake.User(ana.ID)
	u.PrimaryEmail = "ana.ribeiro@example.com"
	e.fake.SeedUser(u)
	pl = e.g2aPlan()
	if rn := g2aOps(pl, syncapi.G2AUserRename); len(rn) != 1 || rn[0].Changes[1].After != "smtp:ana@example.com" {
		t.Fatalf("rename %+v", pl.Ops())
	}
	e.applyAndConfirm(ad, pl)
	if a := ad.bySAM("ana"); a.Mail != "ana.ribeiro@example.com" || a.SAM != "ana" {
		t.Fatalf("after rename %+v", a)
	}

	// 5. Suspend, then unsuspend.
	e.fake.SuspendDirect(bob.ID, true)
	pl = e.g2aPlan()
	if dis := g2aOps(pl, syncapi.G2AUserDisable); len(dis) != 1 || dis[0].MoveTo != gfQuarantine || dis[0].Reason != syncapi.G2AReasonSuspended {
		t.Fatalf("suspend %+v", pl.Ops())
	}
	e.applyAndConfirm(ad, pl)
	if b := ad.bySAM("bob"); b.Enabled || !below(b.DN, gfQuarantine) {
		t.Fatalf("after suspend %+v", b)
	}
	e.fake.SuspendDirect(bob.ID, false)
	pl = e.g2aPlan()
	if re := g2aOps(pl, syncapi.G2AUserReenable); len(re) != 1 || re[0].MoveTo != gfManaged {
		t.Fatalf("unsuspend %+v", pl.Ops())
	}
	e.applyAndConfirm(ad, pl)

	// 6. The admin flag changes nothing in AD.
	u, _ = e.fake.User(ana.ID)
	u.IsAdmin = true
	e.fake.SeedUser(u)
	if pl = e.g2aPlan(); len(pl.Ops()) != 0 {
		t.Fatalf("admin flag: %+v", pl.Ops())
	}

	// 7. Deleted and recreated: the old account is disabled, the new
	// Google ID never takes it over.
	e.fake.DeleteUserDirect(bob.ID)
	bob2 := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "bob@example.com", OrgUnitPath: "/Staff", Name: map[string]any{"givenName": "Bob", "familyName": "Stone"}})
	pl = e.g2aPlan()
	if dis := g2aOps(pl, syncapi.G2AUserDisable); len(dis) != 1 || dis[0].GoogleID != bob.ID || dis[0].Reason != syncapi.G2AReasonDeleted ||
		len(g2aOps(pl, syncapi.G2AUserCreate)) != 0 || g2aSkips(pl)[bob2.ID] != syncapi.G2ASkipMarkerMismatch {
		t.Fatalf("recreate %+v %+v", pl.Ops(), pl.Scopes[0].Skipped)
	}
	e.applyAndConfirm(ad, pl)

	// 8. A privileged account (here: a role group member) is never
	// touched, even when Google suspends it.
	ad.priv[ad.bySAM("ana").SID] = []string{"group: S-1-5-21-1-2-3-1600"}
	e.fake.SuspendDirect(ana.ID, true)
	pl = e.g2aPlan()
	if len(pl.Ops()) != 0 || g2aSkips(pl)[ana.ID] != syncapi.G2ASkipPrivileged {
		t.Fatalf("privileged %+v %+v", pl.Ops(), pl.Scopes[0].Skipped)
	}

	// 9. Reads that stop: a missing group, an empty selection, the schema
	// without the marker attribute. Each records a failed run.
	e.setGoogleFirst(gfSettings(syncapi.G2AModeApply, []string{"/Staff"}, []string{"nobody@example.com"}))
	if err := e.call(syncapi.OpG2APlan, syncapi.G2APlanParams{}, nil); err == nil || err.Code != syncapi.CodeInvalid ||
		!strings.Contains(strings.Join(err.Details, " "), "missing-group") {
		t.Fatalf("missing group: %v", err)
	}
	e.fake.AddOrgUnit("/Bosses")
	u, _ = e.fake.User(boss.ID)
	u.OrgUnitPath = "/Bosses"
	e.fake.SeedUser(u)
	e.setGoogleFirst(gfSettings(syncapi.G2AModeApply, []string{"/Bosses"}, nil))
	if err := e.call(syncapi.OpG2APlan, syncapi.G2APlanParams{}, nil); err == nil || err.Code != syncapi.CodeInvalid ||
		!strings.Contains(strings.Join(err.Details, " "), "empty-selection") {
		t.Fatalf("empty selection: %v", err)
	}
	e.setGoogleFirst(gfSettings(syncapi.G2AModeApply, []string{"/Staff"}, nil))
	ad.noSchema = true
	if err := e.call(syncapi.OpG2APlan, syncapi.G2APlanParams{}, nil); err == nil || err.Code != syncapi.CodeInvalid ||
		!strings.Contains(err.Message, syncapi.G2AMarkerAttribute) {
		t.Fatalf("schema: %v", err)
	}
	if err := e.call(syncapi.OpG2APlan, syncapi.G2APlanParams{Scope: "nope"}, nil); err == nil || err.Code != syncapi.CodeNotFound {
		t.Fatalf("unknown scope: %v", err)
	}
	failed := 0
	e.must(syncapi.OpRunsList, syncapi.RunsListParams{Status: syncapi.StatusFailed}, &runs)
	for _, r := range runs.Runs {
		if r.Action == syncapi.RunActionG2A {
			failed++
		}
	}
	if failed != 3 {
		t.Fatalf("failed g2a runs: %d", failed)
	}

	// Read-only on Google: only the read-only scopes, no write request.
	for _, w := range writeScopes {
		if w {
			t.Fatal("a g2a plan asked for the write scopes")
		}
	}
	if w := e.fake.Writes(); len(w) != 0 {
		t.Fatalf("g2a wrote to Google: %+v", w)
	}

	// The audit names counts, scopes and runs, never a person.
	var audit bytes.Buffer
	_, _ = e.rt.Store.ExportAudit(context.Background(), &audit)
	sc := bufio.NewScanner(&audit)
	plans, confirms := 0, 0
	for sc.Scan() {
		var ev struct {
			Action, Detail string
		}
		_ = json.Unmarshal(sc.Bytes(), &ev)
		if !strings.HasPrefix(ev.Action, "g2a.") {
			continue
		}
		var d struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal([]byte(ev.Detail), &d)
		for _, personal := range []string{"ana@", "bob@", "ana.ribeiro", "Ribeiro", "Stone", "Manager", "S-1-5-21-9-9-9"} {
			if strings.Contains(d.Detail, personal) {
				t.Errorf("audit %s holds personal data %q: %s", ev.Action, personal, d.Detail)
			}
		}
		switch ev.Action {
		case "g2a.plan":
			plans++
		case "g2a.confirm":
			confirms++
		}
	}
	if plans < 10 || confirms < 6 {
		t.Fatalf("audit: %d plans, %d confirms", plans, confirms)
	}
}
