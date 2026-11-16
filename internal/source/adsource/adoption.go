package adsource

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/source"
)

// Adoption checks: before an approved adoption, the AD object must not be
// privileged in the domain, and no other object of the whole directory
// (not only of the sync scope) may carry the address it renders. Both
// reads go through the read-only account; any failed read fails the check
// (the caller then adopts nothing).

// addressFilter matches every object that claims addr: mail,
// userPrincipalName or an SMTP proxy address (primary or secondary; the
// attribute compares case-insensitively).
func addressFilter(addr string) escape.Filter {
	return escape.Or(escape.Eq("mail", addr), escape.Eq("userPrincipalName", addr), escape.Eq("proxyAddresses", "smtp:"+addr))
}

// duplicatesOf returns the DNs of the entries that are not the object
// itself (by objectGUID).
func duplicatesOf(selfGUID string, entries []*ldap.Entry) []string {
	var out []string
	for _, e := range entries {
		g, err := sid.GUIDFromBytes(e.GetRawAttributeValue("objectGUID"))
		if err == nil && strings.EqualFold(g.String(), selfGUID) {
			continue
		}
		out = append(out, e.DN)
	}
	return out
}

// CheckAdoption implements source.AdoptionChecker.
func (r *Reader) CheckAdoption(ctx context.Context, qs []source.AdoptionQuery) (map[string]plan.AdoptionCheck, error) {
	out := map[string]plan.AdoptionCheck{}
	if len(qs) == 0 {
		return out, nil
	}
	conn, closeFn, err := r.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	idx, err := privilege.Build(ctx, conn, privilege.Options{})
	if err != nil {
		return nil, fmt.Errorf("adoption check: %w", err)
	}
	for _, q := range qs {
		guid, err := sid.ParseGUID(q.ID)
		if err != nil {
			return nil, fmt.Errorf("adoption check: %s: %w", q.ID, err)
		}
		self, err := conn.SearchAll(ctx, ad.SearchRequest{Filter: escape.EqBytes("objectGUID", guid.Bytes()), Attributes: []string{"objectGUID"}, Limit: 2})
		if err != nil {
			return nil, fmt.Errorf("adoption check: %s: %w", q.ID, err)
		}
		if len(self) != 1 {
			return nil, fmt.Errorf("adoption check: AD object %s not found", q.ID)
		}
		var chk plan.AdoptionCheck
		reasons, err := idx.Privileged(ctx, conn, self[0].DN)
		if err != nil {
			return nil, fmt.Errorf("adoption check: %s: %w", self[0].DN, err)
		}
		for _, x := range reasons {
			chk.Privileged = append(chk.Privileged, x.Kind+": "+x.Detail)
		}
		addr := model.NormalizeEmail(q.Address)
		if addr == "" {
			return nil, fmt.Errorf("adoption check: %s has no address", self[0].DN)
		}
		others, err := conn.SearchAll(ctx, ad.SearchRequest{Filter: addressFilter(addr), Attributes: []string{"objectGUID"}})
		if err != nil {
			return nil, fmt.Errorf("adoption check: objects with %s: %w", addr, err)
		}
		chk.Duplicates = duplicatesOf(q.ID, others)
		out[plan.AdoptionKey(q.Kind, q.ID)] = chk
	}
	return out, nil
}
