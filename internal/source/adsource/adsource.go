// Package adsource reads the sync source from Samba AD with the ad library:
// a read-only service account, LDAPS with the domain CA pinned, paged
// searches below the configured bases, and ranged retrieval of group
// members. It returns users and groups already mapped to the target model.
package adsource

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/samba-conductor/ad"
	"github.com/samba-conductor/ad/escape"
	"github.com/samba-conductor/conductor-sync/internal/mapping"
	"github.com/samba-conductor/conductor-sync/internal/model"
	"github.com/samba-conductor/conductor-sync/internal/source"
)

// Config is the [source] section of the configuration.
type Config struct {
	Realm string `toml:"realm"`
	// DCs replaces DNS SRV discovery; Preferred DCs are tried first.
	DCs       []string `toml:"dcs"`
	Preferred []string `toml:"preferred"`
	// DNSServers resolve the domain when the host resolver does not.
	DNSServers []string `toml:"dns_servers"`
	CAFile     string   `toml:"ca_file"`
	BindUser   string   `toml:"bind_user"`
	// Auth is "kerberos" (default) or "simple" (LDAP simple bind over TLS).
	Auth string `toml:"auth"`
	// PasswordCredential names the bind password: a systemd credential
	// name (read from $CREDENTIALS_DIRECTORY) or an absolute path to a
	// file that only the service user can read.
	PasswordCredential string `toml:"password_credential"`
	// UserBases and GroupBases are searched (subtree) for users and groups.
	UserBases    []string `toml:"user_bases"`
	GroupBases   []string `toml:"group_bases"`
	ExcludeBases []string `toml:"exclude_bases"`
	// RequireGroup restricts users to (transitive) members of this group DN.
	RequireGroup string `toml:"require_group"`
	// ExpiredAsDisabled treats accounts past accountExpires as disabled.
	ExpiredAsDisabled *bool `toml:"expired_as_disabled"`
	// PageSize of the paged searches (default 500).
	PageSize uint32 `toml:"page_size"`
}

// Validate checks the section.
func (c *Config) Validate() error {
	var errs []error
	if c.Realm == "" {
		errs = append(errs, errors.New("source.realm is required"))
	}
	if c.CAFile == "" {
		errs = append(errs, errors.New("source.ca_file is required (the domain CA is pinned)"))
	}
	if c.BindUser == "" || c.PasswordCredential == "" {
		errs = append(errs, errors.New("source.bind_user and source.password_credential are required"))
	}
	switch c.Auth {
	case "", "kerberos", "simple":
	default:
		errs = append(errs, fmt.Errorf("source.auth %q: want kerberos or simple", c.Auth))
	}
	if len(c.UserBases) == 0 {
		errs = append(errs, errors.New("source.user_bases: at least one base DN is required"))
	}
	for _, list := range [][]string{c.UserBases, c.GroupBases, c.ExcludeBases} {
		for _, dn := range list {
			if _, err := escape.ParseDN(dn); err != nil {
				errs = append(errs, fmt.Errorf("source: invalid DN %q", dn))
			}
		}
	}
	if c.RequireGroup != "" {
		if _, err := escape.ParseDN(c.RequireGroup); err != nil {
			errs = append(errs, fmt.Errorf("source.require_group: invalid DN %q", c.RequireGroup))
		}
	}
	return errors.Join(errs...)
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
	pemCA, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("source.ca_file: %w", err)
	}
	pool, err := ad.CertPoolFromPEM(pemCA)
	if err != nil {
		return nil, fmt.Errorf("source.ca_file: %w", err)
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

// DNKey normalizes a DN for map lookups: RFC 4514 parsed, types and values
// lowercased (AD compares naming attributes case-insensitively).
func DNKey(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(dn)
	}
	parts := make([]string, 0, len(parsed.RDNs))
	for _, r := range parsed.RDNs {
		comps := make([]string, 0, len(r.Attributes))
		for _, a := range r.Attributes {
			comps = append(comps, strings.ToLower(a.Type)+"="+escape.DNValue(strings.ToLower(a.Value)))
		}
		sort.Strings(comps)
		parts = append(parts, strings.Join(comps, "+"))
	}
	return strings.Join(parts, ",")
}

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

// ReadWith reads through an existing connection.
func (r *Reader) ReadWith(ctx context.Context, conn *ad.Conn) (*source.Result, error) {
	res := &source.Result{}
	userFilter := escape.And(userClass, notCritical)
	if r.cfg.RequireGroup != "" {
		userFilter = escape.And(userClass, notCritical, escape.InChain("memberOf", r.cfg.RequireGroup))
	}
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
			mapped, err := r.rules.User(e.DN, entryAttrs{e})
			if err != nil {
				res.Skipped = append(res.Skipped, source.Skipped{DN: e.DN, Reason: err.Error()})
				continue
			}
			enabled := u.Enabled()
			if enabled && r.cfg.expiredAsDisabled() && u.AccountExpired(now) {
				enabled = false
			}
			res.Users = append(res.Users, model.SourceUser{ID: id, DN: e.DN, Account: u.SAMAccountName, Enabled: enabled, Attrs: mapped})
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
