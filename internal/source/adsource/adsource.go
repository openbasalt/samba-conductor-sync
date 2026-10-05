// Package adsource reads the sync source from Samba AD with the ad library:
// a read-only service account, LDAPS with the domain CA pinned, paged
// searches below the configured bases, and ranged retrieval of group
// members. It returns users and groups already mapped to the target model.
//
// Scope: users below user_bases (minus exclude_bases) that are members,
// nested membership included, of at least one include group (when any is
// configured) and of no exclude group (exclusion wins). Groups are
// referenced by DN or by SID; SIDs survive renames and moves. Every
// referenced group must resolve: a group that cannot be found stops the
// read, so a deleted or renamed group never silently empties (or widens)
// the scope.
package adsource

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-sync/internal/mapping"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/source"
)

// Config is the [source] section of the configuration.
type Config struct {
	Realm string `toml:"realm"`
	// DCs replaces DNS SRV discovery; Preferred DCs are tried first.
	DCs       []string `toml:"dcs"`
	Preferred []string `toml:"preferred"`
	// DNSServers resolve the domain when the host resolver does not.
	DNSServers []string `toml:"dns_servers"`
	// CAFile is the domain CA (PEM) pinned for LDAPS; CAPEM, the same
	// content inline (set through the management API), wins over it.
	CAFile   string `toml:"ca_file"`
	CAPEM    string `toml:"ca_pem,omitempty"`
	BindUser string `toml:"bind_user"`
	// Auth is "kerberos" (default) or "simple" (LDAP simple bind over TLS).
	Auth string `toml:"auth"`
	// PasswordCredential names the bind password: a systemd credential
	// name (read from $CREDENTIALS_DIRECTORY) or an absolute path to a
	// file that only the service user can read. Optional when the password
	// is stored (encrypted) through the management API, which wins.
	PasswordCredential string `toml:"password_credential"`
	// UserBases and GroupBases are searched (subtree) for users and groups.
	UserBases    []string `toml:"user_bases"`
	GroupBases   []string `toml:"group_bases"`
	ExcludeBases []string `toml:"exclude_bases"`
	// IncludeGroups restricts users to (nested) members of any of these
	// groups (DN or SID); ExcludeGroups removes (nested) members of any of
	// them, even when included.
	IncludeGroups []string `toml:"include_groups,omitempty"`
	ExcludeGroups []string `toml:"exclude_groups,omitempty"`
	// RequireGroup is the P5 single-group form, accepted as a one-item
	// alias of IncludeGroups.
	RequireGroup string `toml:"require_group,omitempty"`
	// ExpiredAsDisabled treats accounts past accountExpires as disabled.
	ExpiredAsDisabled *bool `toml:"expired_as_disabled"`
	// PageSize of the paged searches (default 500).
	PageSize uint32 `toml:"page_size,omitempty"`
}

// Includes returns the include groups, with the require_group alias.
func (c *Config) Includes() []string {
	out := append([]string(nil), c.IncludeGroups...)
	if c.RequireGroup != "" {
		k, _ := mapping.GroupKey(c.RequireGroup)
		for _, g := range out {
			if gk, _ := mapping.GroupKey(g); gk == k {
				return out
			}
		}
		out = append(out, c.RequireGroup)
	}
	return out
}

// Validate checks the section.
func (c *Config) Validate() error {
	var errs []error
	if c.Realm == "" {
		errs = append(errs, errors.New("source.realm is required"))
	}
	if c.CAFile == "" && c.CAPEM == "" {
		errs = append(errs, errors.New("source.ca_file (or ca_pem) is required (the domain CA is pinned)"))
	}
	if c.CAPEM != "" {
		if _, err := ParseCAPEM(c.CAPEM); err != nil {
			errs = append(errs, err)
		}
	}
	if c.BindUser == "" {
		errs = append(errs, errors.New("source.bind_user is required"))
	}
	switch c.Auth {
	case "", "kerberos", "simple":
	default:
		errs = append(errs, fmt.Errorf("source.auth %q: want kerberos or simple", c.Auth))
	}
	errs = append(errs, c.ValidateScope())
	return errors.Join(errs...)
}

// ValidateScope checks the scope part (bases and groups).
func (c *Config) ValidateScope() error {
	var errs []error
	if len(c.UserBases) == 0 {
		errs = append(errs, errors.New("source.user_bases: at least one base DN is required"))
	}
	for _, list := range [][]string{c.UserBases, c.GroupBases, c.ExcludeBases} {
		for _, dn := range list {
			if _, err := escape.ParseDN(dn); err != nil || strings.TrimSpace(dn) == "" {
				errs = append(errs, fmt.Errorf("source: invalid DN %q", dn))
			}
		}
	}
	inc := map[string]bool{}
	for _, g := range c.Includes() {
		k, err := mapping.GroupKey(g)
		if err != nil {
			errs = append(errs, fmt.Errorf("source.include_groups: %w", err))
			continue
		}
		inc[k] = true
	}
	for _, g := range c.ExcludeGroups {
		k, err := mapping.GroupKey(g)
		if err != nil {
			errs = append(errs, fmt.Errorf("source.exclude_groups: %w", err))
			continue
		}
		if inc[k] {
			errs = append(errs, fmt.Errorf("source: group %s is both included and excluded", g))
		}
	}
	return errors.Join(errs...)
}

// MaxCAPEM bounds an inline CA bundle.
const MaxCAPEM = 64 << 10

// ParseCAPEM parses an inline CA bundle: only CERTIFICATE blocks, at least
// one, each a valid X.509 certificate.
func ParseCAPEM(text string) ([]*x509.Certificate, error) {
	if len(text) > MaxCAPEM {
		return nil, fmt.Errorf("source.ca_pem: larger than %d bytes", MaxCAPEM)
	}
	var out []*x509.Certificate
	rest := []byte(text)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("source.ca_pem: a %s block (only certificates are accepted)", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("source.ca_pem: %w", err)
		}
		out = append(out, c)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("source.ca_pem: text outside the PEM blocks")
	}
	if len(out) == 0 {
		return nil, errors.New("source.ca_pem: no certificate")
	}
	return out, nil
}

func (c *Config) expiredAsDisabled() bool { return c.ExpiredAsDisabled == nil || *c.ExpiredAsDisabled }

// Reader reads the source.
type Reader struct {
	cfg      Config
	rules    *mapping.Rules
	password string
	adCfg    ad.Config
	now      func() time.Time
	// connect is replaceable in tests.
	connect func(ctx context.Context) (*ad.Conn, func(), error)
}

// NewReader builds a reader. The password is held only in memory.
func NewReader(cfg Config, rules *mapping.Rules, password string) (*Reader, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	pemCA, field := []byte(cfg.CAPEM), "source.ca_pem"
	if cfg.CAPEM == "" {
		b, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("source.ca_file: %w", err)
		}
		pemCA, field = b, "source.ca_file"
	}
	pool, err := ad.CertPoolFromPEM(pemCA)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	adCfg := ad.Config{Realm: cfg.Realm, DCs: cfg.DCs, Preferred: cfg.Preferred, RootCAs: pool}
	if len(cfg.DNSServers) > 0 {
		adCfg.Resolver = ad.NewDNSResolver(cfg.DNSServers...)
	}
	r := &Reader{cfg: cfg, rules: rules, password: password, adCfg: adCfg, now: time.Now}
	r.connect = r.dial
	return r, nil
}

func (r *Reader) dial(ctx context.Context) (*ad.Conn, func(), error) {
	if r.cfg.Auth == "simple" {
		conn, err := ad.Connect(ctx, r.adCfg, ad.SimpleAuth(r.cfg.BindUser, r.password))
		if err != nil {
			return nil, nil, err
		}
		return conn, func() { _ = conn.Close() }, nil
	}
	s, err := ad.SignIn(ctx, r.adCfg, r.cfg.BindUser, r.password)
	if err != nil {
		return nil, nil, err
	}
	conn, err := ad.Connect(ctx, r.adCfg, ad.KerberosAuth(s))
	if err != nil {
		s.Close()
		return nil, nil, err
	}
	return conn, func() { _ = conn.Close(); s.Close() }, nil
}

// entryAttrs adapts an LDAP entry to mapping.Attrs.
type entryAttrs struct{ e *ldap.Entry }

func (a entryAttrs) Get(name string) string {
	if strings.EqualFold(name, "dn") || strings.EqualFold(name, "distinguishedName") {
		return a.e.DN
	}
	for _, at := range a.e.Attributes {
		if strings.EqualFold(at.Name, name) && len(at.Values) > 0 {
			return at.Values[0]
		}
	}
	return ""
}

// DNKey normalizes a DN for map lookups (escape.NormalizeDN).
func DNKey(dn string) string { return escape.NormalizeDN(dn) }

func union(a []string, b ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if k := strings.ToLower(s); !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

var (
	userClass  = escape.And(escape.Eq("objectCategory", "person"), escape.Eq("objectClass", "user"))
	groupClass = escape.Eq("objectClass", "group")
	// Critical system objects (Administrator, krbtgt, built-in groups) are
	// never synced, even when a base includes them.
	notCritical = escape.Not(escape.Eq("isCriticalSystemObject", "TRUE"))
)

// Read loads users and groups in scope.
func (r *Reader) Read(ctx context.Context) (*source.Result, error) {
	conn, closeFn, err := r.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("source: connect: %w", err)
	}
	defer closeFn()
	return r.ReadWith(ctx, conn)
}

func (r *Reader) excluded(dn string) bool {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return true
	}
	for _, x := range r.cfg.ExcludeBases {
		xd, err := ldap.ParseDN(x)
		if err != nil {
			continue
		}
		if xd.EqualFold(parsed) || xd.AncestorOfFold(parsed) {
			return true
		}
	}
	return false
}

// ---- referenced groups ----

// refGroup is one referenced group, resolved, with its user members below
// the user bases (by objectGUID).
type refGroup struct {
	key     string
	ref     string
	found   bool
	dn      string
	name    string
	sid     string
	members map[string]bool
}

// scopeGroups resolves every group the scope and the org unit rules
// reference. Missing groups are returned with found=false.
type scopeGroups struct {
	byKey   map[string]*refGroup
	include []*refGroup
	exclude []*refGroup
	report  []model.ScopeGroup
}

// membership implements mapping.Membership for one user.
type membership struct {
	g    *scopeGroups
	guid string
}

func (m membership) Member(key string) bool {
	rg := m.g.byKey[key]
	return rg != nil && rg.members[m.guid]
}

func (m membership) GroupName(key string) string {
	if rg := m.g.byKey[key]; rg != nil {
		if rg.name != "" {
			return rg.name
		}
		return rg.ref
	}
	return key
}

// decide applies the include and exclude groups to one user.
func (g *scopeGroups) decide(guid string) (in bool, reason string) {
	if len(g.include) > 0 {
		in = false
		for _, rg := range g.include {
			if rg.members[guid] {
				in = true
				break
			}
		}
		if !in {
			return false, "not a member of any include group"
		}
	}
	for _, rg := range g.exclude {
		if rg.members[guid] {
			return false, "member of the exclude group " + displayName(rg)
		}
	}
	return true, ""
}

func displayName(rg *refGroup) string {
	if rg.name != "" {
		return rg.name
	}
	return rg.ref
}

// missing lists the referenced groups that were not found.
func (g *scopeGroups) missing() []string {
	var out []string
	for _, s := range g.report {
		if !s.Found {
			out = append(out, fmt.Sprintf("%s group %s", s.Role, s.Ref))
		}
	}
	return out
}

func (r *Reader) resolveGroups(ctx context.Context, conn *ad.Conn) (*scopeGroups, error) {
	return r.resolveGroupsWith(ctx, conn, func(rg *refGroup) error { return r.groupUserMembers(ctx, conn, rg) })
}

// resolveGroupsWith resolves the referenced groups; members fills each
// found group's members (all of them, or only the one user of a lookup).
func (r *Reader) resolveGroupsWith(ctx context.Context, conn *ad.Conn, members func(*refGroup) error) (*scopeGroups, error) {
	g := &scopeGroups{byKey: map[string]*refGroup{}}
	get := func(ref string) (*refGroup, error) {
		key, err := mapping.GroupKey(ref)
		if err != nil {
			return nil, err
		}
		if rg, ok := g.byKey[key]; ok {
			return rg, nil
		}
		rg := &refGroup{key: key, ref: ref, members: map[string]bool{}}
		g.byKey[key] = rg
		if err := r.lookupGroup(ctx, conn, rg); err != nil {
			return nil, err
		}
		if rg.found {
			if err := members(rg); err != nil {
				return nil, err
			}
		}
		return rg, nil
	}
	add := func(role string, rg *refGroup, target string, prio int) {
		g.report = append(g.report, model.ScopeGroup{Role: role, Ref: rg.ref, Found: rg.found, DN: rg.dn, Name: rg.name,
			SID: rg.sid, Members: len(rg.members), Target: target, Priority: prio})
	}
	for _, ref := range r.cfg.Includes() {
		rg, err := get(ref)
		if err != nil {
			return nil, err
		}
		g.include = append(g.include, rg)
		add(model.RoleInclude, rg, "", 0)
	}
	for _, ref := range r.cfg.ExcludeGroups {
		rg, err := get(ref)
		if err != nil {
			return nil, err
		}
		g.exclude = append(g.exclude, rg)
		add(model.RoleExclude, rg, "", 0)
	}
	if r.rules != nil {
		for _, rule := range r.rules.GroupRules() {
			rg, err := get(rule.Ref)
			if err != nil {
				return nil, err
			}
			add(model.RoleOrgUnit, rg, rule.Target, rule.Priority)
		}
	}
	return g, nil
}

// lookupGroup finds a group by SID (anywhere in the domain) or by DN.
func (r *Reader) lookupGroup(ctx context.Context, conn *ad.Conn, rg *refGroup) error {
	attrs := []string{"cn", "objectSid", "objectGUID", "objectClass"}
	var e *ldap.Entry
	if strings.HasPrefix(rg.key, "sid:") {
		s, err := sid.Parse(strings.TrimPrefix(rg.key, "sid:"))
		if err != nil {
			return err
		}
		entries, err := conn.SearchAll(ctx, ad.SearchRequest{Filter: escape.And(groupClass, escape.EqBytes("objectSid", s.Bytes())),
			Attributes: attrs, Limit: 2})
		if err != nil {
			return fmt.Errorf("source: group %s: %w", rg.ref, err)
		}
		if len(entries) == 1 {
			e = entries[0]
		}
	} else {
		entry, err := conn.Get(ctx, rg.ref, attrs...)
		if err != nil && !errors.Is(err, ad.ErrNotFound) {
			return fmt.Errorf("source: group %s: %w", rg.ref, err)
		}
		if entry != nil && isGroup(entry) {
			e = entry
		}
	}
	if e == nil {
		return nil
	}
	rg.found, rg.dn, rg.name = true, e.DN, e.GetAttributeValue("cn")
	if raw := e.GetRawAttributeValue("objectSid"); len(raw) > 0 {
		if s, err := sid.FromBytes(raw); err == nil {
			rg.sid = s.String()
		}
	}
	return nil
}

func isGroup(e *ldap.Entry) bool {
	for _, c := range e.GetAttributeValues("objectClass") {
		if strings.EqualFold(c, "group") {
			return true
		}
	}
	return false
}

// groupUserMembers fills the (nested) user members of a group below the
// user bases. Primary-group membership (Domain Users) is not a member
// value and does not count.
func (r *Reader) groupUserMembers(ctx context.Context, conn *ad.Conn, rg *refGroup) error {
	for _, base := range r.cfg.UserBases {
		for e, err := range conn.Search(ctx, ad.SearchRequest{BaseDN: base, Filter: escape.And(userClass, escape.InChain("memberOf", rg.dn)),
			Attributes: []string{"objectGUID"}, PageSize: r.cfg.PageSize}) {
			if err != nil {
				return fmt.Errorf("source: members of %s below %s: %w", rg.ref, base, err)
			}
			raw := e.GetRawAttributeValue("objectGUID")
			if g, err := sid.GUIDFromBytes(raw); err == nil {
				rg.members[g.String()] = true
			}
		}
	}
	return nil
}

// ReadWith reads through an existing connection.
func (r *Reader) ReadWith(ctx context.Context, conn *ad.Conn) (*source.Result, error) {
	res := &source.Result{}
	sg, err := r.resolveGroups(ctx, conn)
	if err != nil {
		return nil, err
	}
	res.Scope = sg.report
	if miss := sg.missing(); len(miss) > 0 {
		return nil, fmt.Errorf("source: referenced groups not found: %s (fix the configuration; a SID reference survives renames and moves)",
			strings.Join(miss, ", "))
	}
	userFilter := escape.And(userClass, notCritical)
	attrs := union(ad.UserAttributes, r.rules.UserAttributes()...)
	seen := map[string]bool{}
	now := r.now()
	dnIndex := map[string]model.MemberRef{}
	for _, base := range r.cfg.UserBases {
		for e, err := range conn.Search(ctx, ad.SearchRequest{BaseDN: base, Filter: userFilter, Attributes: attrs, PageSize: r.cfg.PageSize}) {
			if err != nil {
				return nil, fmt.Errorf("source: users below %s: %w", base, err)
			}
			if r.excluded(e.DN) {
				continue
			}
			u := ad.UserFromEntry(e)
			if u.GUID.IsZero() {
				res.Skipped = append(res.Skipped, source.Skipped{DN: e.DN, Reason: "no objectGUID"})
				continue
			}
			id := u.GUID.String()
			if seen[id] {
				continue
			}
			seen[id] = true
			if in, reason := sg.decide(id); !in {
				if strings.HasPrefix(reason, "member of the exclude") {
					res.Excluded++
				} else {
					res.NotIncluded++
				}
				continue
			}
			mapped, placement, err := r.rules.User(e.DN, entryAttrs{e}, membership{g: sg, guid: id})
			userErr := ""
			if err != nil {
				if !errors.Is(err, mapping.ErrAmbiguousOrgUnit) || mapped == nil {
					res.Skipped = append(res.Skipped, source.Skipped{DN: e.DN, Reason: err.Error()})
					continue
				}
				userErr = err.Error()
			}
			enabled := u.Enabled()
			if enabled && r.cfg.expiredAsDisabled() && u.AccountExpired(now) {
				enabled = false
			}
			res.Users = append(res.Users, model.SourceUser{ID: id, DN: e.DN, Account: u.SAMAccountName, SID: u.SID.String(), Enabled: enabled, Attrs: mapped,
				Placement: placement, Error: userErr, Fallback: r.rules.FallbackFields(entryAttrs{e})})
			dnIndex[DNKey(e.DN)] = model.MemberRef{Kind: model.KindUser, ID: id}
		}
	}
	if !r.rules.ManagesGroups() || len(r.cfg.GroupBases) == 0 {
		return res, nil
	}
	gattrs := union(ad.GroupAttributes, r.rules.GroupAttributes()...)
	type rawGroup struct {
		g  model.SourceGroup
		dn string
	}
	var groups []rawGroup
	for _, base := range r.cfg.GroupBases {
		for e, err := range conn.Search(ctx, ad.SearchRequest{BaseDN: base, Filter: escape.And(groupClass, notCritical), Attributes: gattrs, PageSize: r.cfg.PageSize}) {
			if err != nil {
				return nil, fmt.Errorf("source: groups below %s: %w", base, err)
			}
			if r.excluded(e.DN) {
				continue
			}
			g := ad.GroupFromEntry(e)
			if g.GUID.IsZero() {
				res.Skipped = append(res.Skipped, source.Skipped{DN: e.DN, Reason: "no objectGUID"})
				continue
			}
			id := g.GUID.String()
			if seen[id] {
				continue
			}
			seen[id] = true
			email, name, desc, err := r.rules.Group(entryAttrs{e})
			if err != nil {
				res.Skipped = append(res.Skipped, source.Skipped{DN: e.DN, Reason: err.Error()})
				continue
			}
			groups = append(groups, rawGroup{g: model.SourceGroup{ID: id, DN: e.DN, Account: g.SAMAccountName,
				Email: email, Name: name, Description: desc}, dn: e.DN})
			dnIndex[DNKey(e.DN)] = model.MemberRef{Kind: model.KindGroup, ID: id}
		}
	}
	// Members: one ranged read per group (large groups exceed one range).
	// Only users and groups in scope become members.
	for i := range groups {
		members, err := conn.GroupMembers(ctx, groups[i].dn)
		if err != nil {
			return nil, fmt.Errorf("source: members of %s: %w", groups[i].dn, err)
		}
		for _, m := range members {
			if ref, ok := dnIndex[DNKey(m)]; ok {
				groups[i].g.Members = append(groups[i].g.Members, ref)
			}
		}
		sort.Slice(groups[i].g.Members, func(a, b int) bool { return groups[i].g.Members[a].ID < groups[i].g.Members[b].ID })
		res.Groups = append(res.Groups, groups[i].g)
	}
	return res, nil
}

// LookupUser reads one user by SID with the same scope rules as Read (the
// user bases, the excluded bases, the include and exclude groups, critical
// objects left out) and maps it. A SID that is not a user below the user
// bases returns a scope without a user. Every referenced group must resolve,
// as for Read.
func (r *Reader) LookupUser(ctx context.Context, userSID string) (*source.UserScope, error) {
	s, err := sid.Parse(userSID)
	if err != nil {
		return nil, fmt.Errorf("source: SID %q: %w", userSID, err)
	}
	conn, closeFn, err := r.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("source: connect: %w", err)
	}
	defer closeFn()
	attrs := union(ad.UserAttributes, r.rules.UserAttributes()...)
	filter := escape.And(userClass, notCritical, escape.EqBytes("objectSid", s.Bytes()))
	for _, base := range r.cfg.UserBases {
		entries, err := conn.SearchAll(ctx, ad.SearchRequest{BaseDN: base, Filter: filter, Attributes: attrs, Limit: 2})
		if err != nil {
			return nil, fmt.Errorf("source: user %s below %s: %w", userSID, base, err)
		}
		if len(entries) == 0 {
			continue
		}
		e := entries[0]
		u := ad.UserFromEntry(e)
		id := u.GUID.String()
		if u.GUID.IsZero() {
			return &source.UserScope{Reason: "no objectGUID"}, nil
		}
		enabled := u.Enabled()
		if enabled && r.cfg.expiredAsDisabled() && u.AccountExpired(r.now()) {
			enabled = false
		}
		su := &model.SourceUser{ID: id, DN: e.DN, Account: u.SAMAccountName, SID: u.SID.String(), Enabled: enabled}
		out := &source.UserScope{User: su}
		// The referenced groups, with this user's (nested) membership only:
		// the groups above the user (memberOf, walked upwards) instead of
		// every member of every group.
		above, err := r.groupsAbove(ctx, conn, e.GetAttributeValues("memberOf"))
		if err != nil {
			return nil, err
		}
		sg, err := r.resolveGroupsWith(ctx, conn, func(rg *refGroup) error {
			if above[DNKey(rg.dn)] {
				rg.members[id] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if miss := sg.missing(); len(miss) > 0 {
			return nil, fmt.Errorf("source: referenced groups not found: %s", strings.Join(miss, ", "))
		}
		if r.excluded(e.DN) {
			out.Reason = "below an excluded base"
			return out, nil
		}
		if in, reason := sg.decide(id); !in {
			out.Reason = reason
			return out, nil
		}
		mapped, placement, err := r.rules.User(e.DN, entryAttrs{e}, membership{g: sg, guid: id})
		if err != nil {
			if !errors.Is(err, mapping.ErrAmbiguousOrgUnit) || mapped == nil {
				// Read skips such a user: it is not synced.
				out.Reason = err.Error()
				return out, nil
			}
			su.Error = err.Error()
		}
		su.Attrs, su.Placement, su.Fallback = mapped, placement, r.rules.FallbackFields(entryAttrs{e})
		out.InScope = true
		return out, nil
	}
	return &source.UserScope{Reason: "not below the user bases"}, nil
}

// maxGroupsAbove bounds the walk up the group tree of one user.
const maxGroupsAbove = 2000

// groupsAbove returns every group a user is a member of, directly or
// through nested groups, by walking memberOf upwards from its direct
// groups (one read per group; cycles are visited once). As with the
// membership searches of Read, the primary group (Domain Users) does not
// count: it is not a memberOf value.
func (r *Reader) groupsAbove(ctx context.Context, conn *ad.Conn, direct []string) (map[string]bool, error) {
	seen := map[string]bool{}
	queue := append([]string(nil), direct...)
	for len(queue) > 0 {
		dn := queue[0]
		queue = queue[1:]
		k := DNKey(dn)
		if seen[k] {
			continue
		}
		if len(seen) >= maxGroupsAbove {
			return nil, fmt.Errorf("source: more than %d groups above one user", maxGroupsAbove)
		}
		seen[k] = true
		e, err := conn.Get(ctx, dn, "memberOf")
		if errors.Is(err, ad.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("source: group %s: %w", dn, err)
		}
		queue = append(queue, e.GetAttributeValues("memberOf")...)
	}
	return seen, nil
}

// ---- preview and connection test (no write anywhere) ----

// Ping signs in to AD (TLS with the pinned CA, then the bind) and closes
// the connection: the connection test of the AD settings, without reading
// anything.
func (r *Reader) Ping(ctx context.Context) (string, error) {
	conn, closeFn, err := r.connect(ctx)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer closeFn()
	return fmt.Sprintf("connected to %s as %s", conn.DC().Host, r.cfg.BindUser), nil
}

// Check connects, resolves the referenced groups (missing ones are
// reported, not fatal) and counts the users below the bases.
func (r *Reader) Check(ctx context.Context) (detail string, groups []model.ScopeGroup, err error) {
	conn, closeFn, err := r.connect(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("connect: %w", err)
	}
	defer closeFn()
	sg, err := r.resolveGroups(ctx, conn)
	if err != nil {
		return "", nil, err
	}
	total := 0
	for _, base := range r.cfg.UserBases {
		n, err := conn.Count(ctx, ad.SearchRequest{BaseDN: base, Filter: escape.And(userClass, notCritical)})
		if err != nil {
			return "", sg.report, fmt.Errorf("users below %s: %w", base, err)
		}
		total += n
	}
	detail = fmt.Sprintf("connected to %s as %s; %d users below the user bases", conn.DC().Host, r.cfg.BindUser, total)
	if miss := sg.missing(); len(miss) > 0 {
		return detail, sg.report, fmt.Errorf("referenced groups not found: %s", strings.Join(miss, ", "))
	}
	return detail, sg.report, nil
}

// Preview is the mapping of one sample user.
type Preview struct {
	Account, DN                      string
	Enabled, InScope                 bool
	OutReason                        string
	Email, GivenName, FamilyName, OU string
	Placement, Error                 string
}

// Preview renders the mapping of up to limit users below the user bases
// (matching query when set), whether in scope or not, with the reason.
func (r *Reader) Preview(ctx context.Context, query string, limit int) ([]Preview, []model.ScopeGroup, error) {
	if limit <= 0 {
		limit = 20
	}
	conn, closeFn, err := r.connect(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}
	defer closeFn()
	sg, err := r.resolveGroups(ctx, conn)
	if err != nil {
		return nil, nil, err
	}
	f := escape.And(userClass, notCritical)
	if q := strings.TrimSpace(query); q != "" {
		f = escape.And(userClass, notCritical, escape.Or(escape.Contains("sAMAccountName", q), escape.Contains("displayName", q),
			escape.Contains("mail", q), escape.Contains("cn", q)))
	}
	attrs := union(ad.UserAttributes, r.rules.UserAttributes()...)
	var out []Preview
	now := r.now()
	for _, base := range r.cfg.UserBases {
		for e, err := range conn.Search(ctx, ad.SearchRequest{BaseDN: base, Filter: f, Attributes: attrs, PageSize: r.cfg.PageSize,
			SortBy: "sAMAccountName", Limit: limit - len(out)}) {
			if err != nil {
				return nil, sg.report, fmt.Errorf("users below %s: %w", base, err)
			}
			u := ad.UserFromEntry(e)
			p := Preview{Account: u.SAMAccountName, DN: e.DN, Enabled: u.Enabled() && !(r.cfg.expiredAsDisabled() && u.AccountExpired(now))}
			id := u.GUID.String()
			switch {
			case r.excluded(e.DN):
				p.OutReason = "below an excluded base"
			default:
				p.InScope, p.OutReason = sg.decide(id)
			}
			mapped, placement, err := r.rules.User(e.DN, entryAttrs{e}, membership{g: sg, guid: id})
			if err != nil {
				p.Error = err.Error()
			}
			if mapped != nil {
				p.Email, p.GivenName, p.FamilyName, p.OU = mapped[model.FieldPrimaryEmail], mapped[model.FieldGivenName],
					mapped[model.FieldFamilyName], mapped[model.FieldOrgUnit]
			}
			p.Placement = placement
			out = append(out, p)
		}
		if len(out) >= limit {
			break
		}
	}
	return out, sg.report, nil
}
