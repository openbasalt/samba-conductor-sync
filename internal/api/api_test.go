package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samba-conductor/conductor-sync/internal/app"
	"github.com/samba-conductor/conductor-sync/internal/config"
	"github.com/samba-conductor/conductor-sync/internal/connector"
	"github.com/samba-conductor/conductor-sync/internal/connector/google"
	"github.com/samba-conductor/conductor-sync/internal/fakegoogle"
	"github.com/samba-conductor/conductor-sync/internal/model"
	"github.com/samba-conductor/conductor-sync/internal/secret"
	"github.com/samba-conductor/conductor-sync/internal/source"
	"github.com/samba-conductor/conductor-sync/internal/source/adsource"
	"github.com/samba-conductor/conductor-sync/internal/store"
	"github.com/samba-conductor/conductor-sync/syncapi"
)

// fakeSource is the AD side: a mutable result plus canned check/preview.
type fakeSource struct {
	mu  sync.Mutex
	res source.Result
}

func (f *fakeSource) Read(context.Context) (*source.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &source.Result{Scope: f.res.Scope}
	for _, u := range f.res.Users {
		u.Attrs = u.Attrs.Clone()
		r.Users = append(r.Users, u)
	}
	return r, nil
}

func (f *fakeSource) Check(context.Context) (string, []model.ScopeGroup, error) {
	return "connected to dc1 as svc.sync; 60 users below the user bases", f.res.Scope, nil
}

func (f *fakeSource) Preview(_ context.Context, _ string, limit int) ([]adsource.Preview, []model.ScopeGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []adsource.Preview
	for i, u := range f.res.Users {
		if i == limit {
			break
		}
		out = append(out, adsource.Preview{Account: u.Account, DN: u.DN, Enabled: true, InScope: true, Email: u.Attrs[model.FieldPrimaryEmail],
			OU: u.Attrs[model.FieldOrgUnit], Placement: "default"})
	}
	return out, f.res.Scope, nil
}

func (f *fakeSource) set(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.res.Users = nil
	for i := 1; i <= n; i++ {
		acct := fmt.Sprintf("user%04d", i)
		f.res.Users = append(f.res.Users, model.SourceUser{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), DN: "CN=" + acct + ",OU=People,DC=lab",
			Account: acct, Enabled: true, Placement: "default", Attrs: model.UserAttrs{model.FieldPrimaryEmail: acct + "@example.com",
				model.FieldGivenName: "User", model.FieldFamilyName: acct, model.FieldOrgUnit: "/"}})
	}
	f.res.Scope = []model.ScopeGroup{{Role: model.RoleInclude, Ref: "S-1-5-21-1-2-3-1500", Found: true, Name: "Google Users", Members: n}}
}

type tenv struct {
	t    *testing.T
	fake *fakegoogle.Server
	src  *fakeSource
	rt   *app.Runtime
	srv  *Server
	dir  string
	n    int
}

const testConfig = `
mode = "dry-run"
state_dir = "%[1]s/state"
credentials_dir = "%[1]s/creds"
[source]
realm = "LAB.TEST"
ca_file = "%[1]s/ca.pem"
bind_user = "svc.sync"
password_credential = "ad-bind"
user_bases = ["OU=People,DC=lab"]
[mapping]
primary_email = ["{sAMAccountName}@example.com"]
allowed_domains = ["example.com"]
[google]
admin_subject = "admin@example.com"
api_base_url = "%[2]s"
requests_per_second = 100000
[api]
allowed_uids = [%[3]d]
`

func newTEnv(t *testing.T) *tenv {
	t.Helper()
	fake := fakegoogle.New("example.com")
	// The administrator the sync acts as exists on a real tenant.
	fake.SeedUser(fakegoogle.User{PrimaryEmail: fake.AdminSubject, IsAdmin: true, Name: map[string]any{"givenName": "Admin", "familyName": "Sync"}})
	hs := httptest.NewTLSServer(fake)
	t.Cleanup(hs.Close)
	fake.SetTokenURL(hs.URL + "/token")
	dir := t.TempDir()
	for _, d := range []string{"state", "creds"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "creds", "state-key"), bytes.Repeat([]byte{9}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "sync.toml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(testConfig, dir, hs.URL, os.Getuid())), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	rt, err := app.Open(context.Background(), cfgPath, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close(); secret.FallbackDir = "/etc/conductor-sync/credentials" })
	src := &fakeSource{}
	src.set(60)
	rt.NewSource = func(*config.Config) app.Source { return src }
	rt.Connect = func(gc google.Config, key *google.ServiceAccountKey, write bool) (connector.Connector, error) {
		return google.New(gc, key, write, google.Options{HTTPClient: hs.Client(), Backoff: time.Millisecond, MaxBackoff: 4 * time.Millisecond})
	}
	srv, err := New(rt, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return &tenv{t: t, fake: fake, src: src, rt: rt, srv: srv, dir: dir}
}

var actor = syncapi.Actor{User: "lab.admin", SID: "S-1-5-21-1-2-3-1104", Session: "sess1234", IP: "10.0.0.5"}

func (e *tenv) call(op syncapi.Op, params syncapi.Params, out any) *syncapi.Error {
	e.t.Helper()
	e.n++
	req, err := syncapi.NewRequest(fmt.Sprintf("req-%06d", e.n), op, actor, params)
	if err != nil {
		e.t.Fatalf("%s: %v", op, err)
	}
	resp := e.srv.Handle(context.Background(), req)
	if !resp.OK {
		return resp.Error
	}
	if out != nil {
		if err := syncapi.DecodeResult(resp, out); err != nil {
			e.t.Fatalf("%s: %v", op, err)
		}
	}
	return nil
}

func (e *tenv) must(op syncapi.Op, params syncapi.Params, out any) {
	e.t.Helper()
	if err := e.call(op, params, out); err != nil {
		e.t.Fatalf("%s: %v %v", op, err, err.Details)
	}
}

// waitJob polls a job until it finishes.
func (e *tenv) waitJob(id string) syncapi.Job {
	e.t.Helper()
	for range 500 {
		var j syncapi.Job
		e.must(syncapi.OpJobGet, syncapi.JobGetParams{ID: id}, &j)
		if j.State != syncapi.JobRunning {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatal("job did not finish")
	return syncapi.Job{}
}

func (e *tenv) plan() syncapi.RunDetail {
	e.t.Helper()
	var js syncapi.JobStarted
	e.must(syncapi.OpPlanStart, nil, &js)
	j := e.waitJob(js.Job.ID)
	if j.State != syncapi.JobDone || j.RunID == 0 {
		e.t.Fatalf("plan job %+v", j)
	}
	var d syncapi.RunDetail
	e.must(syncapi.OpRunGet, syncapi.RunGetParams{ID: j.RunID}, &d)
	return d
}

func (e *tenv) settings() (syncapi.ConfigView, syncapi.Settings) {
	e.t.Helper()
	var v syncapi.ConfigView
	e.must(syncapi.OpConfigGet, nil, &v)
	return v, v.Settings
}

func TestManagementFlow(t *testing.T) {
	e := newTEnv(t)
	var st syncapi.Status
	e.must(syncapi.OpStatus, nil, &st)
	if st.Ready || st.Key != nil || st.Mode != "dry-run" || st.ConfigVersion != 0 || !st.Audit.Intact {
		t.Fatalf("initial status %+v", st)
	}

	// The key: invalid, then the fake's key; never returned, never audited.
	if err := e.call(syncapi.OpKeySet, syncapi.KeySetParams{KeyJSON: `{"type":"user"}`}, nil); err == nil || err.Code != syncapi.CodeInvalid {
		t.Fatalf("bad key: %v", err)
	}
	var ki syncapi.KeyInfo
	e.must(syncapi.OpKeySet, syncapi.KeySetParams{KeyJSON: string(e.fake.KeyJSON())}, &ki)
	if ki.ClientEmail != e.fake.ClientEmail || ki.Source != "database" || ki.SetBy != "conductor:lab.admin@10.0.0.5" {
		t.Fatalf("key info %+v", ki)
	}
	row, _ := e.rt.Store.GetSecret(context.Background(), app.GoogleKeySecret)
	if row == nil || bytes.Contains(row.Ciphertext, []byte("PRIVATE KEY")) {
		t.Fatal("key not encrypted at rest")
	}
	var audit bytes.Buffer
	_, _ = e.rt.Store.ExportAudit(context.Background(), &audit)
	if strings.Contains(audit.String(), "PRIVATE KEY") || !strings.Contains(audit.String(), `"action":"key.set"`) {
		t.Fatalf("audit: %s", audit.String())
	}
	e.must(syncapi.OpStatus, nil, &st)
	if !st.Ready || st.Key == nil {
		t.Fatal("not ready after the key")
	}

	// Connection test with the stored key.
	var tr syncapi.TestResult
	e.must(syncapi.OpConnectionTest, syncapi.ConnectionTestParams{}, &tr)
	if !tr.AD.OK || !tr.Google.OK || !strings.Contains(tr.Google.Detail, "administrator") {
		t.Fatalf("test %+v", tr)
	}

	// Settings: validation, versioned update, optimistic concurrency.
	v, s := e.settings()
	bad := s
	bad.Mode = "yolo"
	bad.Mapping.OrgUnits = []syncapi.OrgUnitRule{{Group: "S-1-5-21-1-2-3-1600", Target: "/Finance"}}
	var vr syncapi.ConfigValidateResult
	e.must(syncapi.OpConfigValidate, syncapi.ConfigValidateParams{Settings: bad}, &vr)
	if vr.Valid || len(vr.Errors) < 2 {
		t.Fatalf("validate %+v", vr)
	}
	if err := e.call(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: v.Version, Settings: bad}, nil); err == nil || err.Code != syncapi.CodeInvalid || len(err.Details) < 2 {
		t.Fatalf("invalid update: %v", err)
	}
	s.Mode = "apply"
	s.Scope.IncludeGroups = []string{"S-1-5-21-1-2-3-1500"}
	var ur syncapi.ConfigUpdateResult
	e.must(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: 0, Settings: s, Comment: "first setup"}, &ur)
	if ur.Version != 1 || len(ur.Changes) != 2 {
		t.Fatalf("update %+v", ur)
	}
	if err := e.call(syncapi.OpConfigUpdate, syncapi.ConfigUpdateParams{BaseVersion: 0, Settings: s}, nil); err == nil || err.Code != syncapi.CodeConflict {
		t.Fatalf("stale base: %v", err)
	}
	var hist []syncapi.ConfigVersion
	e.must(syncapi.OpConfigHistory, syncapi.ConfigHistoryParams{}, &hist)
	if len(hist) != 1 || hist[0].Actor != "conductor:lab.admin@10.0.0.5" || hist[0].Comment != "first setup" {
		t.Fatalf("history %+v", hist)
	}
	var ex syncapi.ConfigExport
	e.must(syncapi.OpConfigExport, nil, &ex)
	if !strings.Contains(ex.TOML, `mode = "apply"`) || !strings.Contains(ex.TOML, "S-1-5-21-1-2-3-1500") {
		t.Fatalf("export:\n%s", ex.TOML)
	}

	// The first plan exceeds max_creates (60 > 50): applying needs the
	// override, and the apply is bound to the digest.
	d := e.plan()
	if d.Counts["user.create"] != 60 || d.Sections["create"] != 60 || !d.Override || !d.Applicable ||
		d.Confirmation != syncapi.Confirmation(d.Digest, true) || len(d.Groups) != 1 || d.Groups[0].Name != "Google Users" {
		t.Fatalf("plan detail %+v", d)
	}
	var page syncapi.RunDetail
	e.must(syncapi.OpRunGet, syncapi.RunGetParams{ID: d.Run.ID, Section: "create", Offset: 50, Limit: 20}, &page)
	if page.OpsMatching != 60 || len(page.Ops) != 10 || page.Ops[0].Attrs["primary_email"] == "" {
		t.Fatalf("page %d %d", page.OpsMatching, len(page.Ops))
	}
	wrong := strings.Repeat("0", 64)
	if err := e.call(syncapi.OpApplyStart, syncapi.ApplyStartParams{RunID: d.Run.ID, Digest: wrong}, nil); err == nil || err.Code != syncapi.CodeConflict {
		t.Fatalf("wrong digest: %v", err)
	}
	var js syncapi.JobStarted
	e.must(syncapi.OpApplyStart, syncapi.ApplyStartParams{RunID: d.Run.ID, Digest: d.Digest}, &js)
	if j := e.waitJob(js.Job.ID); j.RunStatus != store.StatusBlocked {
		t.Fatalf("apply without override: %+v", j)
	}
	if n := len(e.fake.Users()); n != 1 {
		t.Fatalf("blocked apply wrote: %d users", n)
	}
	e.must(syncapi.OpApplyStart, syncapi.ApplyStartParams{RunID: d.Run.ID, Digest: d.Digest, OverrideLimits: true}, &js)
	j := e.waitJob(js.Job.ID)
	if j.RunStatus != store.StatusApplied || j.Progress.Done != 60 || j.Actor != "conductor:lab.admin@10.0.0.5" {
		t.Fatalf("override apply: %+v", j)
	}
	var rd syncapi.RunDetail
	e.must(syncapi.OpRunGet, syncapi.RunGetParams{ID: j.RunID}, &rd)
	if rd.Applicable || rd.Ops[0].Status != store.OpDone {
		t.Fatalf("applied run detail %+v", rd.Ops[0])
	}

	// A mass exclusion (20 of 60 leave the scope): the scheduled-style
	// run is blocked at max_suspends, then overridden by hand.
	e.src.set(40)
	e.must(syncapi.OpApplyStart, syncapi.ApplyStartParams{Scheduled: true}, &js)
	j = e.waitJob(js.Job.ID)
	if j.RunStatus != store.StatusBlocked {
		t.Fatalf("scheduled run: %+v", j)
	}
	e.must(syncapi.OpStatus, nil, &st)
	if len(st.OpenBlocked) != 1 || st.OpenBlocked[0].ID != j.RunID || len(st.OpenBlocked[0].Violations) == 0 {
		t.Fatalf("open blocked %+v", st.OpenBlocked)
	}
	var blocked syncapi.RunDetail
	e.must(syncapi.OpRunGet, syncapi.RunGetParams{ID: j.RunID}, &blocked)
	if !blocked.Applicable || !blocked.Override || blocked.Counts["user.suspend"] != 20 {
		t.Fatalf("blocked detail %+v", blocked)
	}
	e.must(syncapi.OpApplyStart, syncapi.ApplyStartParams{RunID: j.RunID, Digest: blocked.Digest, OverrideLimits: true}, &js)
	if j = e.waitJob(js.Job.ID); j.RunStatus != store.StatusApplied {
		t.Fatalf("override of the blocked run: %+v", j)
	}
	suspended := 0
	for _, u := range e.fake.Users() {
		if u.Suspended {
			suspended++
		}
	}
	if suspended != 20 {
		t.Fatalf("suspended %d", suspended)
	}
	st = syncapi.Status{}
	e.must(syncapi.OpStatus, nil, &st)
	if len(st.OpenBlocked) != 0 || st.LastSuccess == nil || st.Links.SuspendedBySync != 20 {
		t.Fatalf("status after override %+v last success %+v", st, st.LastSuccess)
	}
	var rl syncapi.RunsList
	e.must(syncapi.OpRunsList, syncapi.RunsListParams{Status: store.StatusBlocked}, &rl)
	if rl.Total != 2 {
		t.Fatalf("blocked runs %d", rl.Total)
	}

	// The audit log: intact, with the API actor on every mutation.
	var av syncapi.AuditState
	e.must(syncapi.OpAuditVerify, nil, &av)
	audit.Reset()
	_, _ = e.rt.Store.ExportAudit(context.Background(), &audit)
	for _, want := range []string{`"action":"config.update"`, `"action":"api.plan.start"`, `"action":"api.apply.start"`,
		`"action":"apply.override-limits"`, "overrides blocked run", `"actor":"conductor:lab.admin@10.0.0.5"`} {
		if !strings.Contains(audit.String(), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
	if !av.Intact || av.Rows < 10 {
		t.Fatalf("audit %+v", av)
	}
}

func TestBusyAndDryRun(t *testing.T) {
	e := newTEnv(t)
	e.must(syncapi.OpKeySet, syncapi.KeySetParams{KeyJSON: string(e.fake.KeyJSON())}, nil)
	d := e.plan()
	// Dry-run mode: a manual apply is refused before starting.
	if d.Applicable || d.NotApply != "dry-run" {
		t.Fatalf("dry-run detail %+v", d)
	}
	if err := e.call(syncapi.OpApplyStart, syncapi.ApplyStartParams{RunID: d.Run.ID, Digest: d.Digest, OverrideLimits: true}, nil); err == nil || err.Code != syncapi.CodeConflict {
		t.Fatalf("apply in dry-run: %v", err)
	}
	// One job at a time.
	e.fake.SetLatency(30 * time.Millisecond)
	var js syncapi.JobStarted
	e.must(syncapi.OpPlanStart, nil, &js)
	if err := e.call(syncapi.OpPlanStart, nil, nil); err == nil || err.Code != syncapi.CodeBusy {
		t.Fatalf("second job: %v", err)
	}
	e.fake.SetLatency(0)
	e.waitJob(js.Job.ID)
	if err := e.call(syncapi.OpJobGet, syncapi.JobGetParams{ID: "unknown-job-id"}, nil); err == nil || err.Code != syncapi.CodeNotFound {
		t.Fatalf("unknown job: %v", err)
	}
}

func TestRequestValidation(t *testing.T) {
	e := newTEnv(t)
	cases := []syncapi.Request{
		{Version: 2, ID: "abcdefgh", Op: syncapi.OpStatus, Actor: actor},
		{Version: 1, ID: "short", Op: syncapi.OpStatus, Actor: actor},
		{Version: 1, ID: "abcdefgh", Op: "shell.exec", Actor: actor},
		{Version: 1, ID: "abcdefgh", Op: syncapi.OpStatus, Actor: syncapi.Actor{User: "x", SID: "bogus", Session: "s"}},
		{Version: 1, ID: "abcdefgh", Op: syncapi.OpStatus, Actor: syncapi.Actor{SID: actor.SID, Session: "s"}},
		{Version: 1, ID: "abcdefgh", Op: syncapi.OpRunGet, Actor: actor, Params: json.RawMessage(`{"id":1,"rm":"-rf"}`)},
		{Version: 1, ID: "abcdefgh", Op: syncapi.OpApplyStart, Actor: actor, Params: json.RawMessage(`{"scheduled":true,"override_limits":true}`)},
		{Version: 1, ID: "abcdefgh", Op: syncapi.OpApplyStart, Actor: actor, Params: json.RawMessage(`{"run_id":3}`)},
	}
	for i, req := range cases {
		if resp := e.srv.Handle(context.Background(), req); resp.OK {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestSocketPeerCheck(t *testing.T) {
	e := newTEnv(t)
	sock := filepath.Join(e.dir, "api.sock")
	e.rt.File.API.Socket = sock
	if err := e.srv.Listen(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(sock); err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", st.Mode(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = e.srv.Serve(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	req, _ := syncapi.NewRequest("req-socket-1", syncapi.OpStatus, actor, nil)
	resp, err := syncapi.Call(context.Background(), sock, req)
	if err != nil || !resp.OK {
		t.Fatalf("allowed peer: %v", err)
	}
	// Another UID is refused: the connection is closed without an answer.
	e.srv.allowedMu.Lock()
	e.srv.allowed = map[int]bool{os.Getuid() + 1: true}
	e.srv.allowedMu.Unlock()
	if _, err := syncapi.Call(context.Background(), sock, req); err == nil || syncapi.ErrorCodeOf(err) != syncapi.CodeUnavailable {
		t.Fatalf("other peer: %v", err)
	}
}
