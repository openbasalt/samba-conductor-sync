// Package source defines what the engine reads from the source directory.
// The AD implementation is in source/adsource; tests use in-memory sources.
package source

import (
	"context"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
)

// Skipped is a source object that could not be mapped (no address, a
// template that does not render, an address outside the allowed domains).
type Skipped struct {
	DN     string `json:"dn"`
	Reason string `json:"reason"`
}

// Result is one complete read of the source scope.
type Result struct {
	Users   []model.SourceUser
	Groups  []model.SourceGroup
	Skipped []Skipped
	// Scope lists the groups referenced by the scope and the org unit
	// rules, resolved (names, members).
	Scope []model.ScopeGroup
	// NotIncluded counts users below the bases that are in no include
	// group; Excluded counts users removed by an exclude group.
	NotIncluded int
	Excluded    int
}

// Source reads the scope.
type Source interface {
	Read(ctx context.Context) (*Result, error)
}

// Static is a fixed source (tests).
type Static struct{ R *Result }

// Read implements Source.
func (s Static) Read(context.Context) (*Result, error) { return s.R, nil }

// UserScope is one user looked up by SID: the mapped user (nil when the SID
// is not a user below the user bases) and whether it is in the sync scope,
// with the reason when it is not.
type UserScope struct {
	User    *model.SourceUser
	InScope bool
	Reason  string
}

// UserLookup is implemented by sources that read one user directly (the
// self-service status and password changes, without reading the whole
// scope). The scope rules are the same as Read's.
type UserLookup interface {
	LookupUser(ctx context.Context, sid string) (*UserScope, error)
}

// Lookup finds one user by SID: directly when src implements UserLookup,
// else through a full Read.
func Lookup(ctx context.Context, src Source, sid string) (*UserScope, error) {
	if l, ok := src.(UserLookup); ok {
		return l.LookupUser(ctx, sid)
	}
	r, err := src.Read(ctx)
	if err != nil {
		return nil, err
	}
	for i := range r.Users {
		if r.Users[i].SID != "" && r.Users[i].SID == sid {
			u := r.Users[i]
			u.Attrs = u.Attrs.Clone()
			return &UserScope{User: &u, InScope: true}, nil
		}
	}
	return &UserScope{Reason: "not in the sync scope"}, nil
}
