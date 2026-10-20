//go:build lab

package labtest

import (
	"context"
	"crypto/tls"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-sync/internal/g2a"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// The Google-first read path against the real DC: the marker attribute in
// the schema, the users below the managed OU, address conflicts anywhere,
// taken logon names and the privilege index, all through the read-only
// account. The Google side is built by hand (the plan only needs the
// accounts the snapshot would return).

const (
	g2aRoot       = "OU=Google," + lab
	g2aManaged    = "OU=People," + g2aRoot
	g2aGroups     = "OU=Groups," + g2aManaged
	g2aQuarantine = "OU=Quarantine," + g2aManaged
	g2aDomain     = "sync.example.com"
)

// ldapAdmin binds as Administrator over LDAPS for the raw changes the ad
// library has no operation for (OUs, the marker attribute).
func (l labEnv) ldapAdmin(t *testing.T) *ldap.Conn {
	t.Helper()
	pemCA, err := os.ReadFile(l.caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := ad.CertPoolFromPEM(pemCA)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ldap.DialURL("ldaps://"+dcIP+":636", ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: dc, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Bind("Administrator@"+realm, l.adminPW); err != nil {
		t.Fatal(err)
	}
	return conn
}

func addOU(t *testing.T, c *ldap.Conn, dn string) {
	t.Helper()
	r := ldap.NewAddRequest(dn, nil)
	r.Attribute("objectClass", []string{"organizationalUnit"})
	if err := c.Add(r); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		t.Fatalf("add %s: %v", dn, err)
	}
}

// quotedUTF16 encodes a password for unicodePwd.
func quotedUTF16(pw string) []byte {
	u := utf16.Encode([]rune(`"` + pw + `"`))
	out := make([]byte, 0, len(u)*2)
	for _, r := range u {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// addUser creates an enabled user with the given attributes.
func addUser(t *testing.T, c *ldap.Conn, parent, sam string, attrs map[string]string) string {
	t.Helper()
	dn := "CN=" + sam + "," + parent
	r := ldap.NewAddRequest(dn, nil)
	r.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	r.Attribute("sAMAccountName", []string{sam})
	r.Attribute("userPrincipalName", []string{sam + "@" + strings.ToLower(realm)})
	r.Attribute("unicodePwd", []string{string(quotedUTF16("Lab-" + sam + "-9x!Q"))})
	r.Attribute("userAccountControl", []string{"512"})
	for k, v := range attrs {
		r.Attribute(k, []string{v})
	}
	if err := c.Add(r); err != nil {
		t.Fatalf("add %s: %v", dn, err)
	}
	return dn
}

func TestLabG2APlan(t *testing.T) {
	l := loadLab(t)
	ctx := context.Background()
	c := l.ldapAdmin(t)
	for _, ou := range []string{g2aRoot, g2aManaged, g2aGroups, g2aQuarantine} {
		addOU(t, c, ou)
	}
	// Linked by its marker, with a title changed in AD (drift).
	addUser(t, c, g2aManaged, "g.marked", map[string]string{"mail": "marked@" + g2aDomain, "givenName": "Marked", "sn": "Person",
		"displayName": "Marked Person", "title": "Old title", syncapi.G2AMarkerAttribute: syncapi.G2AMarker("g-1001")})
	// Marked but a domain administrator: P1, never touched.
	adminDN := addUser(t, c, g2aManaged, "g.admin", map[string]string{"mail": "admin2@" + g2aDomain, "givenName": "Admin",
		"sn": "Two", "displayName": "Admin Two", syncapi.G2AMarkerAttribute: syncapi.G2AMarker("g-1003")})
	m := ldap.NewModifyRequest("CN=Domain Admins,CN=Users,DC=sync,DC=conductor,DC=test", nil)
	m.Add("member", []string{adminDN})
	if err := c.Modify(m); err != nil {
		t.Fatalf("Domain Admins: %v", err)
	}
	// An account outside the managed OU already holding a Google address.
	addUser(t, c, g2aRoot, "g.unmanaged", map[string]string{"mail": "taken@" + g2aDomain})

	users := []g2a.GoogleUser{
		{ID: "g-1001", Email: "marked@" + g2aDomain, Given: "Marked", Family: "Person", OrgUnit: "/Staff",
			Fields: model.UserAttrs{model.FieldTitle: "New title"}},
		{ID: "g-1003", Email: "admin2@" + g2aDomain, Given: "Admin", Family: "Two", OrgUnit: "/Staff"},
		{ID: "g-1004", Email: "taken@" + g2aDomain, Given: "Taken", Family: "Address", OrgUnit: "/Staff"},
		{ID: "g-1005", Email: "new.person@" + g2aDomain, Given: "New", Family: "Person", OrgUnit: "/Staff/Engineering"},
		// Outside the domain and a super administrator: never selected.
		{ID: "g-1006", Email: "other@elsewhere.example", Given: "Other", Family: "Domain", OrgUnit: "/Staff"},
		{ID: "g-1007", Email: "boss@" + g2aDomain, Given: "Super", Family: "Admin", OrgUnit: "/Staff", Admin: true},
	}
	limits := g2a.DefaultLimits()
	limits.MaxTouchedPercent = g2a.Unlimited
	scopes := []g2a.Scope{{Name: "people", Mode: syncapi.G2AModeDryRun, ManagedOU: g2aManaged, GroupsOU: g2aGroups,
		QuarantineOU: g2aQuarantine, OrgUnits: []string{"/Staff"}, SubOrgUnits: true, Fields: []model.UserField{model.FieldTitle},
		LogonTemplate: "{given}.{family}", Limits: limits}}
	sel, err := g2a.Select(users, nil, scopes, g2aDomain, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := strings.ToLower(realm)
	start := time.Now()
	state, err := l.reader(t, "kerberos").ReadG2A(ctx, g2a.Request(sel, scopes, r, nil))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	t.Logf("AD read in %s: schema marker %v, %d managed, %d others, %d privileged SIDs", time.Since(start).Round(time.Millisecond),
		state.SchemaHasMarker, len(state.Managed["people"]), len(state.Others), len(state.Privileged))
	if !state.SchemaHasMarker {
		t.Fatalf("the lab schema has no %s", syncapi.G2AMarkerAttribute)
	}
	res, err := g2a.Build(g2a.Input{Now: time.Now(), GoogleDomain: g2aDomain, Realm: r, Scopes: scopes, Selection: sel, AD: state})
	if err != nil {
		t.Fatal(err)
	}
	sp := res.Plan.Scopes[0]
	for _, op := range sp.Ops {
		t.Logf("op %s %s %s %s %v", op.Kind, op.GoogleID, op.SAM, op.Reason, op.Changes)
	}
	for _, s := range sp.Skipped {
		t.Logf("skip %s %s %s %v", s.GoogleID, s.SAM, s.Reason, s.Detail)
	}
	find := func(id string) []syncapi.G2AOp {
		var out []syncapi.G2AOp
		for _, op := range sp.Ops {
			if op.GoogleID == id {
				out = append(out, op)
			}
		}
		return out
	}
	skip := func(id string) *syncapi.G2ASkipped {
		for i := range sp.Skipped {
			if sp.Skipped[i].GoogleID == id {
				return &sp.Skipped[i]
			}
		}
		return nil
	}
	if ops := find("g-1001"); len(ops) != 1 || ops[0].Kind != syncapi.G2AUserUpdate || ops[0].Reason != syncapi.G2AReasonADDrift ||
		!slices.ContainsFunc(ops[0].Changes, func(ch syncapi.G2AChange) bool {
			return ch.Field == "title" && ch.Before == "Old title" && ch.After == "New title"
		}) {
		t.Fatalf("g-1001: %+v", ops)
	}
	// The reasons are cut (a domain administrator inherits dozens of ACL
	// entries), the group reasons first.
	if s := skip("g-1003"); s == nil || s.Reason != syncapi.G2ASkipPrivileged || len(find("g-1003")) != 0 || len(s.Detail) > 9 ||
		!strings.HasPrefix(s.Detail[0], "group: ") {
		t.Fatalf("g-1003 (domain administrator): %+v %+v", s, find("g-1003"))
	}
	if s := skip("g-1004"); s == nil || s.Reason != syncapi.G2ASkipUnmanagedExists || len(find("g-1004")) != 0 {
		t.Fatalf("g-1004 (address taken): %+v %+v", s, find("g-1004"))
	}
	if ops := find("g-1005"); len(ops) != 1 || ops[0].Kind != syncapi.G2AUserCreate || !ops[0].Invite || ops[0].SAM != "new.person" ||
		ops[0].ParentOU != g2aManaged {
		t.Fatalf("g-1005: %+v", ops)
	}
	for _, id := range []string{"g-1006", "g-1007"} {
		if len(find(id)) != 0 || skip(id) != nil {
			t.Fatalf("%s should not be in the plan", id)
		}
	}
	// Deterministic: a second read and build give the same digest.
	state2, err := l.reader(t, "simple").ReadG2A(ctx, g2a.Request(sel, scopes, r, nil))
	if err != nil {
		t.Fatal(err)
	}
	res2, err := g2a.Build(g2a.Input{Now: time.Now(), GoogleDomain: g2aDomain, Realm: r, Scopes: scopes, Selection: sel, AD: state2})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Plan.Digest != res.Plan.Digest {
		t.Fatalf("digest changed between two reads: %s %s", res.Plan.Digest, res2.Plan.Digest)
	}
}
