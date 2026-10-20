package adsource

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-sync/internal/g2a"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// The Google-first read: AD only, through the same read-only account and
// connection as the sync source. Nothing here writes.

// g2aAttributes are read for every object of a Google-first plan.
var g2aAttributes = []string{"distinguishedName", "objectGUID", "objectSid", "sAMAccountName", "userPrincipalName", "cn", "mail",
	"proxyAddresses", syncapi.G2AMarkerAttribute, "givenName", "sn", "displayName", "title", "department", "employeeID",
	"telephoneNumber", "mobile", "userAccountControl", "pwdLastSet", "adminCount"}

// g2aOwnedAttributes are the Google-owned attributes kept in ADUser.Attrs.
var g2aOwnedAttributes = []string{"givenName", "sn", "displayName", "title", "department", "employeeID", "telephoneNumber", "mobile"}

// g2aBatch bounds the values of one OR filter.
const g2aBatch = 40

// ReadG2A reads what a Google-first plan needs from AD: whether the schema
// has the marker attribute, every user below each managed OU, the objects
// anywhere that hold a candidate address or marker, the logon names,
// principal names and common names already used, and the privilege index
// (with the role groups of the request).
func (r *Reader) ReadG2A(ctx context.Context, req g2a.ADRequest) (*g2a.ADState, error) {
	conn, closeFn, err := r.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("source: connect: %w", err)
	}
	defer closeFn()
	return r.readG2A(ctx, conn, req)
}

func (r *Reader) readG2A(ctx context.Context, conn *ad.Conn, req g2a.ADRequest) (*g2a.ADState, error) {
	st := &g2a.ADState{Managed: map[string][]g2a.ADUser{}, TakenSAM: map[string]bool{}, TakenUPN: map[string]bool{},
		TakenCN: map[string]bool{}, Privileged: map[string][]string{}}
	// The schema is checked once per run.
	schema := "CN=Schema," + conn.ConfigurationDN()
	found, err := conn.SearchAll(ctx, ad.SearchRequest{BaseDN: schema, Scope: ad.ScopeOneLevel,
		Filter: escape.Eq("lDAPDisplayName", syncapi.G2AMarkerAttribute), Attributes: []string{"lDAPDisplayName"}, Limit: 1})
	if err != nil {
		return nil, fmt.Errorf("source: schema: %w", err)
	}
	st.SchemaHasMarker = len(found) == 1
	if !st.SchemaHasMarker {
		return st, nil
	}
	sids := map[string]bool{}
	scopes := make([]string, 0, len(req.ManagedOUs))
	for name := range req.ManagedOUs {
		scopes = append(scopes, name)
	}
	sort.Strings(scopes)
	for _, name := range scopes {
		base := req.ManagedOUs[name]
		users := []g2a.ADUser{}
		for e, err := range conn.Search(ctx, ad.SearchRequest{BaseDN: base, Filter: escape.And(userClass, notCritical), Attributes: g2aAttributes,
			PageSize: r.cfg.PageSize}) {
			if err != nil {
				if errors.Is(err, ad.ErrNotFound) {
					return nil, fmt.Errorf("source: scope %s: the managed OU %s does not exist", name, base)
				}
				return nil, fmt.Errorf("source: users below %s: %w", base, err)
			}
			u := g2aUser(e)
			users = append(users, u)
			sids[u.SID] = true
		}
		st.Managed[name] = users
	}
	// Objects anywhere with a candidate address or marker (any class: an
	// address is unique across users, groups and contacts).
	var filters []escape.Filter
	for _, m := range req.Mails {
		filters = append(filters, escape.Eq("mail", m), escape.Eq("userPrincipalName", m), escape.Eq("proxyAddresses", "smtp:"+m))
	}
	for _, m := range req.Markers {
		filters = append(filters, escape.Eq(syncapi.G2AMarkerAttribute, m))
	}
	seen := map[string]bool{}
	if err := orBatches(filters, func(f escape.Filter) error {
		entries, err := conn.SearchAll(ctx, ad.SearchRequest{Filter: f, Attributes: g2aAttributes, PageSize: r.cfg.PageSize})
		if err != nil {
			return err
		}
		for _, e := range entries {
			k := DNKey(e.DN)
			if seen[k] {
				continue
			}
			seen[k] = true
			u := g2aUser(e)
			st.Others = append(st.Others, u)
			sids[u.SID] = true
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("source: address conflicts: %w", err)
	}
	sort.Slice(st.Others, func(i, j int) bool { return DNKey(st.Others[i].DN) < DNKey(st.Others[j].DN) })
	// Logon and principal names used by any object.
	for _, q := range []struct {
		attr   string
		values []string
		into   map[string]bool
	}{{"sAMAccountName", req.SAMs, st.TakenSAM}, {"userPrincipalName", req.UPNs, st.TakenUPN}} {
		var fs []escape.Filter
		for _, v := range q.values {
			fs = append(fs, escape.Eq(q.attr, v))
		}
		if err := orBatches(fs, func(f escape.Filter) error {
			entries, err := conn.SearchAll(ctx, ad.SearchRequest{Filter: f, Attributes: []string{q.attr}, PageSize: r.cfg.PageSize})
			if err != nil {
				return err
			}
			for _, e := range entries {
				for _, v := range e.GetEqualFoldAttributeValues(q.attr) {
					q.into[strings.ToLower(v)] = true
				}
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("source: %s in use: %w", q.attr, err)
		}
	}
	// Common names used directly in the managed OUs.
	parents := make([]string, 0, len(req.CNs))
	for p := range req.CNs {
		parents = append(parents, p)
	}
	sort.Strings(parents)
	for _, parent := range parents {
		var fs []escape.Filter
		for _, c := range req.CNs[parent] {
			fs = append(fs, escape.Eq("cn", c))
		}
		if err := orBatches(fs, func(f escape.Filter) error {
			entries, err := conn.SearchAll(ctx, ad.SearchRequest{BaseDN: parent, Scope: ad.ScopeOneLevel, Filter: f, Attributes: []string{"cn"}})
			if err != nil {
				return err
			}
			for _, e := range entries {
				st.TakenCN[g2a.CNKey(parent, e.GetEqualFoldAttributeValue("cn"))] = true
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("source: names in %s: %w", parent, err)
		}
	}
	// The privilege index (P1): the built-in administrative groups, the
	// role groups of the request, adminCount and rights on protected
	// objects.
	var extra []sid.SID
	for _, s := range req.RoleGroupSIDs {
		v, err := sid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("source: role group %q: %w", s, err)
		}
		extra = append(extra, v)
	}
	idx, err := privilege.Build(ctx, conn, privilege.Options{ExtraGroupSIDs: extra})
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	for s := range sids {
		if s == "" {
			continue
		}
		v, err := sid.Parse(s)
		if err != nil {
			continue
		}
		for _, reason := range idx.PrivilegedSID(v) {
			st.Privileged[s] = append(st.Privileged[s], reason.Kind+": "+reason.Detail)
		}
	}
	return st, nil
}

// orBatches runs fn over OR filters of at most g2aBatch parts.
func orBatches(parts []escape.Filter, fn func(escape.Filter) error) error {
	for len(parts) > 0 {
		n := min(len(parts), g2aBatch)
		if err := fn(escape.Or(parts[:n]...)); err != nil {
			return err
		}
		parts = parts[n:]
	}
	return nil
}

// g2aUser converts an entry.
func g2aUser(e *ldap.Entry) g2a.ADUser {
	u := ad.UserFromEntry(e)
	out := g2a.ADUser{DN: e.DN, SAM: u.SAMAccountName, UPN: u.UserPrincipalName, CN: e.GetEqualFoldAttributeValue("cn"), Mail: u.Mail,
		ProxyAddresses: e.GetEqualFoldAttributeValues("proxyAddresses"), Marker: e.GetEqualFoldAttributeValue(syncapi.G2AMarkerAttribute),
		Attrs: map[string]string{}, Enabled: u.Enabled(), PwdLastSet: u.PwdLastSet != 0, AdminCount: e.GetEqualFoldAttributeValue("adminCount") == "1"}
	if !u.SID.IsZero() {
		out.SID = u.SID.String()
	}
	if !u.GUID.IsZero() {
		out.GUID = u.GUID.String()
	}
	for _, a := range g2aOwnedAttributes {
		out.Attrs[a] = e.GetEqualFoldAttributeValue(a)
	}
	return out
}
