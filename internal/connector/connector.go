// Package connector defines what the sync engine needs from a target
// directory. Google Workspace is the first implementation; Microsoft Entra
// ID, SCIM 2.0 and GitHub fit the same interface: read the current state,
// then apply one typed operation at a time. A connector has no delete in
// the sync path: DeleteUser exists only for the separate, manual,
// confirmed delete command.
package connector

import (
	"context"
	"errors"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
)

// Errors a connector maps its failures to (wrapped with detail).
var (
	// ErrNotFound: the target object does not exist.
	ErrNotFound = errors.New("target object not found")
	// ErrConflict: the object (or address) already exists.
	ErrConflict = errors.New("target object already exists")
	// ErrRateLimited: still throttled after every retry.
	ErrRateLimited = errors.New("target rate limit exceeded")
	// ErrInvalid: the target refused the request as invalid; retrying the
	// same request will not help.
	ErrInvalid = errors.New("target refused the request")
	// ErrAuth: the credentials or the delegated scopes are not accepted.
	ErrAuth = errors.New("target authentication failed")
)

// Snapshot is the target's current state as the engine compares it.
type Snapshot struct {
	Users  []model.TargetUser
	Groups []model.TargetGroup
}

// GroupGetter is implemented by connectors that can read one group (with
// its members) directly, used to confirm a linked group that a list did
// not return (eventually consistent targets).
type GroupGetter interface {
	GetGroup(ctx context.Context, key string) (*model.TargetGroup, error)
}

// Connector is one target directory.
type Connector interface {
	// Name identifies the connector in state and audit ("google").
	Name() string
	// Snapshot reads every user and, when groups are true, every group with
	// its members.
	Snapshot(ctx context.Context, groups bool) (*Snapshot, error)
	// CreateUser creates an account carrying the ownership marker for
	// sourceID and returns its target ID.
	CreateUser(ctx context.Context, sourceID string, attrs model.UserAttrs, suspended bool) (string, error)
	// UpdateUser writes the changed managed fields. With claim it also
	// writes the ownership marker (adoption).
	UpdateUser(ctx context.Context, targetID, sourceID string, attrs model.UserAttrs, changes []plan.Change, claim bool) error
	// SetSuspended suspends or unsuspends an account.
	SetSuspended(ctx context.Context, targetID string, suspended bool) error
	// CreateGroup creates a group and returns its target ID.
	CreateGroup(ctx context.Context, spec plan.GroupSpec) (string, error)
	// UpdateGroup writes address, name and description.
	UpdateGroup(ctx context.Context, targetID string, spec plan.GroupSpec) error
	// AddMember adds a member; an existing membership is not an error.
	AddMember(ctx context.Context, groupID string, kind model.Kind, memberID, memberEmail string) error
	// RemoveMember removes a member; a missing membership is not an error.
	RemoveMember(ctx context.Context, groupID, memberID, memberEmail string) error
	// GetUser reads one account by ID or address (ErrNotFound if absent).
	GetUser(ctx context.Context, key string) (*model.TargetUser, error)
	// DeleteUser permanently deletes an account. Only the manual delete
	// command calls it, after its own checks and confirmation.
	DeleteUser(ctx context.Context, targetID string) error
}
