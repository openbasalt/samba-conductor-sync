// Package source defines what the engine reads from the source directory.
// The AD implementation is in source/adsource; tests use in-memory sources.
package source

import (
	"context"

	"github.com/samba-conductor/conductor-sync/internal/model"
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
