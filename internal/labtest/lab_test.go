//go:build lab

// Package labtest runs conductor-sync end to end against the real Samba AD
// of the sync lab (scripts/synclab.sh: conductor-synclab-dc1, 10.95.0.10,
// sync.conductor.test) and the fake Google Directory API. It changes the
// lab domain (renames, moves, disables, membership changes), so the lab is
// reset to its "seeded" snapshot first (scripts/lab-test.sh does it).
//
// Environment: SYNCLAB_STATE (default ~/conductor-synclab/state) holding
// secrets.env (LAB_ADMIN_PASSWORD), sync-secrets.env (SYNC_BIND_PASSWORD)
// and ca.pem. Secrets are read here and never printed.
package labtest

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/conductor-sync/internal/alert"
	"github.com/samba-conductor/conductor-sync/internal/connector"
	"github.com/samba-conductor/conductor-sync/internal/connector/google"
	"github.com/samba-conductor/conductor-sync/internal/engine"
	"github.com/samba-conductor/conductor-sync/internal/fakegoogle"
	"github.com/samba-conductor/conductor-sync/internal/mapping"
	"github.com/samba-conductor/conductor-sync/internal/model"
	"github.com/samba-conductor/conductor-sync/internal/plan"
	"github.com/samba-conductor/conductor-sync/internal/source"
	"github.com/samba-conductor/conductor-sync/internal/source/adsource"
	"github.com/samba-conductor/conductor-sync/internal/store"
)

const (
	realm  = "SYNC.CONDUCTOR.TEST"
	dc     = "dc1.sync.conductor.test"
	dcIP   = "10.95.0.10"
	baseDN = "DC=sync,DC=conductor,DC=test"
	lab    = "OU=Lab," + baseDN
	people = "OU=People," + lab
	groups = "OU=Groups," + lab
)

type labEnv struct {
	state, adminPW, bindPW, caFile string
}

func readEnvFile(t *testing.T, p string) map[string]string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Skipf("lab state not available: %v", err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

func loadLab(t *testing.T) labEnv {
	t.Helper()
	state := os.Getenv("SYNCLAB_STATE")
	if state == "" {
		home, _ := os.UserHomeDir()
		state = filepath.Join(home, "conductor-synclab", "state")
	}
	return labEnv{state: state,
		adminPW: readEnvFile(t, filepath.Join(state, "secrets.env"))["LAB_ADMIN_PASSWORD"],
		bindPW:  readEnvFile(t, filepath.Join(state, "sync-secrets.env"))["SYNC_BIND_PASSWORD"],
		caFile:  filepath.Join(state, "ca.pem")}
}

func (l labEnv) adConfig(t *testing.T) ad.Config {
	t.Helper()
	pemCA, err := os.ReadFile(l.caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := ad.CertPoolFromPEM(pemCA)
	if err != nil {
		t.Fatal(err)
	}
	return ad.Config{Realm: realm, DCs: []string{dc}, RootCAs: pool, Resolver: ad.NewDNSResolver(dcIP)}
}

// admin connects as Administrator to change the lab domain.
func (l labEnv) admin(t *testing.T) *ad.Conn {
	t.Helper()
	c, err := ad.Connect(context.Background(), l.adConfig(t), ad.SimpleAuth("Administrator", l.adminPW))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func applyAD(t *testing.T, c *ad.Conn, op *ad.Operation, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(context.Background(), op); err != nil {
		t.Fatalf("AD change %q: %v", op.Preview().Summary, err)
	}
}

// renameLogon changes sAMAccountName and userPrincipalName. The ad library
// has no operation for it yet (UpdateUser covers profile attributes only),
// so the lab test does a raw LDAP modify. Listed for upstreaming.
func (l labEnv) renameLogon(t *testing.T, dn, newSAM string) {
	t.Helper()
	pemCA, _ := os.ReadFile(l.caFile)
	pool, _ := ad.CertPoolFromPEM(pemCA)
	conn, err := ldap.DialURL("ldaps://"+dcIP+":636", ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: dc, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Bind("Administrator@"+realm, l.adminPW); err != nil {
		t.Fatal(err)
	}
	m := ldap.NewModifyRequest(dn, nil)
	m.Replace("sAMAccountName", []string{newSAM})
	m.Replace("userPrincipalName", []string{newSAM + "@sync.conductor.test"})
	if err := conn.Modify(m); err != nil {
		t.Fatal(err)
	}
}

func userDN(n int) string {
	depts := []string{"Engineering", "Sales", "Support", "Finance", "Operations"}
	return fmt.Sprintf("CN=User %04d,OU=%s,%s", n, depts[(n-1)%5], people)
}

func rules(t *testing.T) *mapping.Rules {
	t.Helper()
	r, err := mapping.Compile(mapping.Config{
		PrimaryEmail:   []string{"{sAMAccountName|ascii|lower}@sync.example.com"},
		AllowedDomains: []string{"sync.example.com"},
		Attributes:     map[string]string{"title": "{title}", "department": "{department}"},
		OrgUnits: []mapping.OUConfig{
			{AD: people, Target: "/Staff"},
			{AD: "OU=Engineering," + people, Target: "/Staff/Engineering"},
			{AD: "OU=Sales," + people, Target: "/Staff/Sales"},
			{AD: "OU=Special," + lab, Target: "/Special"},
		},
		GroupEmail:          []string{"{sAMAccountName|slug}@groups.sync.example.com"},
		GroupAllowedDomains: []string{"groups.sync.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (l labEnv) reader(t *testing.T, auth string) *adsource.Reader {
	t.Helper()
	r, err := adsource.NewReader(adsource.Config{Realm: realm, DCs: []string{dc}, DNSServers: []string{dcIP}, CAFile: l.caFile,
		BindUser: "svc.sync", Auth: auth, PasswordCredential: "unused", UserBases: []string{lab}, GroupBases: []string{groups}},
		rules(t), l.bindPW)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type world struct {
	t      *testing.T
	fake   *fakegoogle.Server
	eng    *engine.Engine
	st     *store.Store
	alerts *alert.Recorder
}

func newWorld(t *testing.T, src source.Source) *world {
	t.Helper()
	fake := fakegoogle.New("sync.example.com", "groups.sync.example.com")
	fake.PageSize = 200
	for _, ou := range []string{"/Staff/Engineering", "/Staff/Sales", "/Special"} {
		fake.AddOrgUnit(ou)
	}
	srv := httptest.NewTLSServer(fake)
	t.Cleanup(srv.Close)
	fake.SetTokenURL(srv.URL + "/token")
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	key := google.NewTestKey(fake.ClientEmail, fake.PrivateKey(), srv.URL+"/token")
	gcfg := google.Config{AdminSubject: fake.AdminSubject, KeyCredential: "x", APIBaseURL: srv.URL, RequestsPerSecond: 1e6}
	w := &world{t: t, fake: fake, st: st, alerts: &alert.Recorder{}}
	w.eng = &engine.Engine{Store: st, Source: src, ConnectorName: "google",
		Connect: func(write bool) (connector.Connector, error) {
			return google.New(gcfg, key, write, google.Options{HTTPClient: srv.Client(), Backoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond})
		},
		Policy: plan.Policy{SuspendDisabled: true, ManageGroups: true, Adopt: plan.AdoptNever,
			Optional: map[model.UserField]bool{model.FieldTitle: true, model.FieldDepartment: true}},
		Limits: plan.DefaultLimits(), Mode: engine.ModeApply, MaxFailures: 25, Alert: w.alerts,
		LockPath: filepath.Join(t.TempDir(), "lock"), Actor: "labtest", Out: os.Stderr}
	return w
}

func (w *world) plan() *engine.Computed {
	w.t.Helper()
	c, err := w.eng.Plan(context.Background(), "manual")
	if err != nil {
		w.t.Fatalf("plan: %v", err)
	}
	return c
}

func (w *world) apply(opt engine.ApplyOptions) (*engine.ApplyResult, error) {
	if !opt.Scheduled {
		opt.Yes = true
	}
	return w.eng.Apply(context.Background(), opt)
}

func counts(c *engine.Computed) string {
	cs := c.Plan.Counts()
	var parts []string
	for _, k := range []plan.OpKind{plan.UserCreate, plan.UserUpdate, plan.UserRename, plan.UserSuspend, plan.UserUnsuspend,
		plan.UserRelink, plan.GroupCreate, plan.GroupUpdate, plan.GroupRelink, plan.MemberAdd, plan.MemberRemove} {
		if cs[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, cs[k]))
		}
	}
	return strings.Join(parts, " ")
}

func TestLabSourceRead(t *testing.T) {
	l := loadLab(t)
	ctx := context.Background()
	start := time.Now()
	k, err := l.reader(t, "kerberos").Read(ctx)
	if err != nil {
		t.Fatalf("kerberos read: %v", err)
	}
	t.Logf("kerberos read: %d users, %d groups, %d skipped in %s", len(k.Users), len(k.Groups), len(k.Skipped), time.Since(start).Round(time.Millisecond))
	s, err := l.reader(t, "simple").Read(ctx)
	if err != nil {
		t.Fatalf("simple read: %v", err)
	}
	if len(k.Users) != len(s.Users) || len(k.Groups) != len(s.Groups) {
		t.Fatalf("kerberos %d/%d vs simple %d/%d", len(k.Users), len(k.Groups), len(s.Users), len(s.Groups))
	}
	if len(k.Users) < 2500 {
		t.Fatalf("users %d", len(k.Users))
	}
	var big *model.SourceGroup
	byEmail := map[string]model.SourceUser{}
	for _, u := range k.Users {
		byEmail[u.Attrs[model.FieldPrimaryEmail]] = u
	}
	for i := range k.Groups {
		if k.Groups[i].Name == "Big Group" {
			big = &k.Groups[i]
		}
	}
	if big == nil || len(big.Members) != 1600 {
		t.Fatalf("Big Group members (ranged retrieval): %v", big)
	}
	if u := byEmail["user0001@sync.example.com"]; u.Attrs[model.FieldOrgUnit] != "/Staff/Engineering" || u.Attrs[model.FieldDepartment] != "Engineering" || !u.Enabled {
		t.Fatalf("user0001 %+v", u)
	}
	if u := byEmail["user0003@sync.example.com"]; u.Attrs[model.FieldOrgUnit] != "/Staff" {
		t.Fatalf("user0003 OU fallback %+v", u)
	}
	if u, ok := byEmail["disabled.user@sync.example.com"]; !ok || u.Enabled {
		t.Fatalf("disabled.user %+v", u)
	}
	if u, ok := byEmail["expired.account@sync.example.com"]; !ok || u.Enabled {
		t.Fatalf("expired.account counts as disabled: %+v", u)
	}
	// The DN with every special character maps fine.
	if _, ok := byEmail["escape.test@sync.example.com"]; !ok {
		t.Fatal("escape.test missing")
	}
	// Read-only account: a write must be refused by AD itself.
	c, err := ad.Connect(ctx, l.adConfig(t), ad.SimpleAuth("svc.sync", l.bindPW))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	op, _ := ad.SetUserEnabled(ad.User{DN: userDN(1), UAC: ad.UACNormalAccount}, false)
	if err := c.Apply(ctx, op); err == nil {
		t.Fatal("the sync account could write to AD")
	}
}

// TestLabEndToEnd: initial plan and apply, then AD changes (CN rename,
// logon rename, OU move, disable, membership change, leaving the scope),
// incremental plans, the safety limit, and a resume after a crash.
func TestLabEndToEnd(t *testing.T) {
	l := loadLab(t)
	ctx := context.Background()
	w := newWorld(t, l.reader(t, "kerberos"))

	// 1. Initial plan: everything is a create; far beyond the limits.
	c := w.plan()
	t.Logf("initial plan: %s; %d warnings; violations %v", counts(c), len(c.Plan.Warnings), c.Violations)
	if c.Plan.Counts()[plan.UserCreate] < 2500 || len(c.Violations) == 0 {
		t.Fatalf("initial plan %s %v", counts(c), c.Violations)
	}
	if _, err := w.apply(engine.ApplyOptions{Scheduled: true}); !errors.Is(err, engine.ErrFirstManual) {
		t.Fatalf("scheduled first: %v", err)
	}
	start := time.Now()
	r, err := w.apply(engine.ApplyOptions{OverrideLimits: true, ExpectDigest: c.Plan.Digest})
	if err != nil {
		t.Fatalf("initial apply: %v %v", err, r.Failures)
	}
	t.Logf("initial apply: %d done in %s", r.Done, time.Since(start).Round(time.Millisecond))
	if n := len(w.fake.Users()); n != c.Plan.Counts()[plan.UserCreate] {
		t.Fatalf("accounts %d", n)
	}
	if _, m, _ := w.fake.GroupByEmail("big-group@groups.sync.example.com"); len(m) != 1600 {
		t.Fatalf("big group on target: %d", len(m))
	}
	if c := w.plan(); !c.Plan.Empty() {
		t.Fatalf("not idempotent: %s", counts(c))
	}

	// 2. AD changes.
	admin := l.admin(t)
	// CN rename: DN changes, objectGUID does not -> no target change.
	op, err := ad.RenameObject(userDN(1), "User 0001 Renamed")
	applyAD(t, admin, op, err)
	// Logon rename -> new address (rename on Google, old one kept as alias).
	l.renameLogon(t, userDN(2), "user0002b")
	// OU move Support -> Sales: org unit change.
	op, err = ad.MoveObject(userDN(3), "OU=Sales,"+people)
	applyAD(t, admin, op, err)
	// Disable -> suspend.
	u4, err := admin.GetUser(ctx, userDN(4))
	if err != nil {
		t.Fatal(err)
	}
	op, err = ad.SetUserEnabled(u4, false)
	applyAD(t, admin, op, err)
	// Group change: user0005 from Operations to Engineering.
	op, err = ad.RemoveGroupMember("CN=Operations,"+groups, userDN(5))
	applyAD(t, admin, op, err)
	op, err = ad.AddGroupMember("CN=Engineering,"+groups, userDN(5))
	applyAD(t, admin, op, err)
	// Out of scope: user0006 moves to an OU outside OU=Lab.
	op, err = ad.CreateOU(ad.NewOU{ParentDN: baseDN, Name: "Archive"})
	applyAD(t, admin, op, err)
	op, err = ad.MoveObject(userDN(6), "OU=Archive,"+baseDN)
	applyAD(t, admin, op, err)

	c = w.plan()
	t.Logf("incremental plan: %s", counts(c))
	got := c.Plan.Counts()
	// user0006 left the scope: suspended and removed from Engineering,
	// Platform Team and Big Group; user0005: removed from Operations,
	// added to Engineering. user0004 (disabled) stays a member.
	if got[plan.UserRename] != 1 || got[plan.UserUpdate] != 1 || got[plan.UserSuspend] != 2 ||
		got[plan.MemberAdd] != 1 || got[plan.MemberRemove] != 4 || got[plan.UserCreate] != 0 {
		t.Fatalf("incremental plan %s\n%v", counts(c), c.Plan.Ops)
	}
	if len(c.Violations) != 0 {
		t.Fatalf("violations %v", c.Violations)
	}
	r, err = w.apply(engine.ApplyOptions{Scheduled: true})
	if err != nil || r.Status != store.StatusApplied {
		t.Fatalf("scheduled incremental apply: %v %+v", err, r)
	}
	if u, ok := w.fake.User("user0002b@sync.example.com"); !ok || u.Aliases[0] != "user0002@sync.example.com" {
		t.Fatalf("logon rename %+v", u)
	}
	if u, _ := w.fake.User("user0003@sync.example.com"); u.OrgUnitPath != "/Staff/Sales" {
		t.Fatalf("moved %+v", u)
	}
	if u, _ := w.fake.User("user0004@sync.example.com"); !u.Suspended {
		t.Fatal("disabled not suspended")
	}
	if u, _ := w.fake.User("user0006@sync.example.com"); !u.Suspended {
		t.Fatal("out of scope not suspended")
	}
	if c := w.plan(); !c.Plan.Empty() {
		t.Fatalf("not converged: %s", counts(c))
	}

	// 3. Safety limit: 30 users moved out of the scope by mistake.
	writes := len(w.fake.Writes())
	for n := 10; n < 40; n++ {
		op, err := ad.MoveObject(userDN(n), "OU=Archive,"+baseDN)
		applyAD(t, admin, op, err)
	}
	r, err = w.apply(engine.ApplyOptions{Scheduled: true})
	if !errors.Is(err, engine.ErrBlocked) || len(w.fake.Writes()) != writes {
		t.Fatalf("limit: %v, writes %d -> %d", err, writes, len(w.fake.Writes()))
	}
	t.Logf("blocked: %v; alert: %s", r.Violations, w.alerts.Alerts[len(w.alerts.Alerts)-1].Text)
	// The mistake is undone in AD: nothing to do, nothing was ever suspended.
	for n := 10; n < 40; n++ {
		depts := []string{"Engineering", "Sales", "Support", "Finance", "Operations"}
		op, err := ad.MoveObject(fmt.Sprintf("CN=User %04d,OU=Archive,%s", n, baseDN), "OU="+depts[(n-1)%5]+","+people)
		applyAD(t, admin, op, err)
	}
	if c := w.plan(); !c.Plan.Empty() {
		t.Fatalf("after undo: %s", counts(c))
	}

	// 4. Resume after a crash: new users and a new group, crash mid-way.
	op, err = ad.CreateGroup(ad.NewGroup{ParentDN: groups, Name: "New Team"})
	applyAD(t, admin, op, err)
	for n := 1; n <= 5; n++ {
		op, err := ad.CreateUser(ad.NewUser{ParentDN: "OU=Engineering," + people, CN: fmt.Sprintf("New %d", n),
			SAMAccountName: fmt.Sprintf("new%d", n), UserPrincipalName: fmt.Sprintf("new%d@sync.conductor.test", n),
			GivenName: "New", Surname: fmt.Sprint(n), Password: l.bindPW + "x"})
		applyAD(t, admin, op, err)
		op, err = ad.AddGroupMember("CN=New Team,"+groups, fmt.Sprintf("CN=New %d,OU=Engineering,%s", n, people))
		applyAD(t, admin, op, err)
	}
	crash := errors.New("simulated crash")
	w.eng.Hooks.AfterTargetWrite = func(_ int, op plan.Op) error {
		if op.Kind == plan.UserCreate && op.Key == "new3@sync.example.com" {
			return crash
		}
		return nil
	}
	if _, err := w.apply(engine.ApplyOptions{Scheduled: true}); !errors.Is(err, crash) {
		t.Fatalf("crash run: %v", err)
	}
	w.eng.Hooks.AfterTargetWrite = nil
	c = w.plan()
	t.Logf("plan after crash: %s", counts(c))
	if got := c.Plan.Counts(); got[plan.UserRelink] != 1 || got[plan.UserCreate] != 2 {
		t.Fatalf("resume plan %s", counts(c))
	}
	r, err = w.apply(engine.ApplyOptions{Scheduled: true})
	if err != nil || len(r.Interrupted) != 1 {
		t.Fatalf("resume: %v %+v", err, r)
	}
	if _, m, _ := w.fake.GroupByEmail("new-team@groups.sync.example.com"); len(m) != 5 {
		t.Fatalf("new team members %v", m)
	}
	if c := w.plan(); !c.Plan.Empty() {
		t.Fatalf("not converged after resume: %s", counts(c))
	}

	// 5. Nothing was ever deleted; the audit chain is intact.
	for _, wr := range w.fake.Writes() {
		if wr.Method == http.MethodDelete && !strings.Contains(wr.Path, "/members/") {
			t.Fatalf("deleted: %+v", wr)
		}
	}
	if v, err := w.st.VerifyAudit(ctx); err != nil || v.BrokenAt != 0 {
		t.Fatalf("audit %+v %v", v, err)
	}
}
