package google_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/connector/google"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
)

type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	s.d = append(s.d, d)
	s.mu.Unlock()
	return nil
}

func setup(t *testing.T, write bool) (*fakegoogle.Server, *google.Connector, *sleeps) {
	t.Helper()
	fake := fakegoogle.New("example.com")
	fake.PageSize = 3
	srv := httptest.NewTLSServer(fake)
	t.Cleanup(srv.Close)
	fake.SetTokenURL(srv.URL + "/token")
	key, err := google.ParseServiceAccountKey(fake.KeyJSON())
	if err != nil {
		t.Fatal(err)
	}
	sl := &sleeps{}
	c, err := google.New(google.Config{AdminSubject: fake.AdminSubject, KeyCredential: "x", APIBaseURL: srv.URL, RequestsPerSecond: 1e6},
		key, write, google.Options{HTTPClient: srv.Client(), Sleep: sl.sleep})
	if err != nil {
		t.Fatal(err)
	}
	return fake, c, sl
}

func attrs(email string) model.UserAttrs {
	return model.UserAttrs{model.FieldPrimaryEmail: email, model.FieldGivenName: "Ana", model.FieldFamilyName: "Lima", model.FieldOrgUnit: "/"}
}

func TestKeyParsing(t *testing.T) {
	fake := fakegoogle.New("example.com")
	if _, err := google.ParseServiceAccountKey(fake.KeyJSON()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{}`, `not json`, `{"type":"service_account","client_email":"a","private_key":"nope"}`, `{"type":"authorized_user"}`} {
		if _, err := google.ParseServiceAccountKey([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	c := google.Config{AdminSubject: "admin@x.com", KeyCredential: "k", APIBaseURL: "http://insecure", MemberRole: "BOSS"}
	c.Defaults()
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "https") || !strings.Contains(err.Error(), "member_role") {
		t.Fatalf("validation: %v", err)
	}
}

func TestSnapshotPagingAndMerge(t *testing.T) {
	fake, c, _ := setup(t, true)
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		fake.SeedUser(fakegoogle.User{PrimaryEmail: string(rune('a'+i)) + "@example.com", Name: map[string]any{"givenName": "x", "familyName": "y"}})
	}
	id, err := c.CreateUser(ctx, "guid-1", model.UserAttrs{model.FieldPrimaryEmail: "new@example.com", model.FieldGivenName: "N", model.FieldFamilyName: "U",
		model.FieldOrgUnit: "/", model.FieldTitle: "T", model.FieldEmployeeID: "E1", model.FieldPhoneWork: "+1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	// Foreign list entries set by an admin survive the sync's updates.
	u, _ := fake.User(id)
	fake.SeedUser(fakegoogle.User{ID: id, PrimaryEmail: u.PrimaryEmail, Name: u.Name, OrgUnitPath: "/",
		ExternalIDs:   append(u.ExternalIDs, map[string]any{"type": "account", "value": "keep-me"}),
		Organizations: append(u.Organizations, map[string]any{"name": "Side gig", "title": "Volunteer"}),
		Phones:        append(u.Phones, map[string]any{"type": "home", "value": "+9"})})
	snap, err := c.Snapshot(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Users) != 9 {
		t.Fatalf("paged snapshot: %d users", len(snap.Users))
	}
	var mine model.TargetUser
	for _, x := range snap.Users {
		if x.ID == id {
			mine = x
		}
	}
	if mine.Owner != "guid-1" || mine.Attrs[model.FieldTitle] != "T" || mine.Attrs[model.FieldEmployeeID] != "E1" || mine.Attrs[model.FieldPhoneWork] != "+1" {
		t.Fatalf("model %+v", mine)
	}
	want := attrs("renamed@example.com")
	want[model.FieldTitle], want[model.FieldEmployeeID], want[model.FieldPhoneWork] = "T2", "E2", ""
	changes := []plan.Change{{Field: "primary_email"}, {Field: "title"}, {Field: "employee_id"}, {Field: "phone_work"}}
	if err := c.UpdateUser(ctx, id, "guid-1", want, changes, false); err != nil {
		t.Fatal(err)
	}
	got, _ := fake.User(id)
	if got.PrimaryEmail != "renamed@example.com" || got.Aliases[0] != "new@example.com" {
		t.Fatalf("rename %+v", got)
	}
	ext := map[string]bool{}
	for _, e := range got.ExternalIDs {
		ext[e["type"].(string)+"="+e["value"].(string)] = true
	}
	if !ext["custom=guid-1"] || !ext["organization=E2"] || !ext["account=keep-me"] || ext["organization=E1"] {
		t.Fatalf("externalIds %v", got.ExternalIDs)
	}
	if len(got.Organizations) != 2 || got.Organizations[0]["title"] != "T2" || got.Organizations[1]["title"] != "Volunteer" {
		t.Fatalf("organizations %v", got.Organizations)
	}
	if len(got.Phones) != 1 || got.Phones[0]["type"] != "home" {
		t.Fatalf("phones %v", got.Phones)
	}
	// Lookups by old address (alias) and ID.
	if tu, err := c.GetUser(ctx, "new@example.com"); err != nil || tu.ID != id {
		t.Fatalf("alias lookup %v %v", tu, err)
	}
	if _, err := c.GetUser(ctx, "nobody@example.com"); !errors.Is(err, connector.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
}

func TestBackoffAndRetryAfter(t *testing.T) {
	fake, c, sl := setup(t, true)
	fake.Fail(fakegoogle.Fault{Method: http.MethodPost, PathPrefix: "/users", Status: 429, Reason: "rateLimitExceeded", RetryAfter: 7})
	fake.Fail(fakegoogle.Fault{Method: http.MethodPost, PathPrefix: "/users", Status: 503, Reason: "backendError"})
	if _, err := c.CreateUser(context.Background(), "g", attrs("a@example.com"), false); err != nil {
		t.Fatal(err)
	}
	if len(sl.d) != 2 || sl.d[0] < 7*time.Second {
		t.Fatalf("sleeps %v (Retry-After 7s must be honoured)", sl.d)
	}
	req, retries := c.Stats()
	if retries != 2 || req < 3 {
		t.Fatalf("stats %d %d", req, retries)
	}
}

func TestPermanentErrorsAreNotRetried(t *testing.T) {
	fake, c, sl := setup(t, true)
	fake.Fail(fakegoogle.Fault{Method: http.MethodPost, PathPrefix: "/users", Status: 400, Reason: "invalid"})
	_, err := c.CreateUser(context.Background(), "g", attrs("a@example.com"), false)
	if !errors.Is(err, connector.ErrInvalid) || len(sl.d) != 0 {
		t.Fatalf("400: %v, sleeps %v", err, sl.d)
	}
	fake.Fail(fakegoogle.Fault{Status: 403, Reason: "forbidden"})
	_, err = c.Snapshot(context.Background(), false)
	if !errors.Is(err, connector.ErrAuth) {
		t.Fatalf("403: %v", err)
	}
}

func TestConflictIsNotOursUnlessMarked(t *testing.T) {
	fake, c, _ := setup(t, true)
	fake.SeedUser(fakegoogle.User{PrimaryEmail: "taken@example.com", Name: map[string]any{"givenName": "a", "familyName": "b"}})
	_, err := c.CreateUser(context.Background(), "g", attrs("taken@example.com"), false)
	if !errors.Is(err, connector.ErrConflict) {
		t.Fatalf("conflict with a foreign account: %v", err)
	}
}

func TestTokenScopes(t *testing.T) {
	_, c, _ := setup(t, false)
	// Read-only connector cannot write even if asked to.
	_, err := c.CreateUser(context.Background(), "g", attrs("a@example.com"), false)
	if !errors.Is(err, connector.ErrAuth) {
		t.Fatalf("write with read scopes: %v", err)
	}
	// A subject the client is not delegated for gets no token.
	fake2 := fakegoogle.New("example.com")
	srv := httptest.NewTLSServer(fake2)
	defer srv.Close()
	fake2.SetTokenURL(srv.URL + "/token")
	key, _ := google.ParseServiceAccountKey(fake2.KeyJSON())
	c3, _ := google.New(google.Config{AdminSubject: "intruder@example.com", KeyCredential: "x", APIBaseURL: srv.URL}, key, false,
		google.Options{HTTPClient: srv.Client()})
	if _, err := c3.Snapshot(context.Background(), false); !errors.Is(err, connector.ErrAuth) || !strings.Contains(err.Error(), "unauthorized_client") {
		t.Fatalf("wrong subject: %v", err)
	}
}

func TestMembersIdempotent(t *testing.T) {
	fake, c, _ := setup(t, true)
	ctx := context.Background()
	uid, err := c.CreateUser(ctx, "g", attrs("a@example.com"), false)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := c.CreateGroup(ctx, plan.GroupSpec{Email: "team@example.com", Name: "Team"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := c.AddMember(ctx, gid, model.KindUser, uid, "a@example.com"); err != nil {
			t.Fatalf("add #%d: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := c.RemoveMember(ctx, gid, uid, "a@example.com"); err != nil {
			t.Fatalf("remove #%d: %v", i, err)
		}
	}
	if _, m, _ := fake.GroupByEmail("team@example.com"); len(m) != 0 {
		t.Fatalf("members %v", m)
	}
	if err := c.UpdateGroup(ctx, gid, plan.GroupSpec{Email: "team2@example.com", Name: "Team 2"}); err != nil {
		t.Fatal(err)
	}
	g, _, ok := fake.GroupByEmail("team@example.com") // old address is an alias
	if !ok || g.Email != "team2@example.com" {
		t.Fatalf("group rename %+v", g)
	}
}
