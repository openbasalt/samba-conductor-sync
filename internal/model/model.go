// Package model is conductor-sync's connector-agnostic view of a directory:
// users, groups and memberships, normalized so the source (AD) and any
// target (Google Workspace, later Entra ID, SCIM, GitHub) can be compared
// field by field.
package model

import (
	"sort"
	"strings"
)

// Kind of a directory object.
type Kind string

// Object kinds.
const (
	KindUser  Kind = "user"
	KindGroup Kind = "group"
)

// UserField names a user attribute the engine may manage. Only fields that
// the operator mapped are compared and written; the rest of a target
// account is never touched.
type UserField string

// Managed user fields. PrimaryEmail, GivenName, FamilyName, OrgUnit and
// Suspended are always managed; the others only when mapped.
const (
	FieldPrimaryEmail UserField = "primary_email"
	FieldGivenName    UserField = "given_name"
	FieldFamilyName   UserField = "family_name"
	FieldOrgUnit      UserField = "org_unit"
	FieldTitle        UserField = "title"
	FieldDepartment   UserField = "department"
	FieldEmployeeID   UserField = "employee_id"
	FieldPhoneWork    UserField = "phone_work"
	FieldPhoneMobile  UserField = "phone_mobile"
)

// OptionalUserFields are the fields managed only when mapped, in display
// order.
var OptionalUserFields = []UserField{FieldTitle, FieldDepartment, FieldEmployeeID, FieldPhoneWork, FieldPhoneMobile}

// AlwaysManagedUserFields are compared on every managed account.
var AlwaysManagedUserFields = []UserField{FieldPrimaryEmail, FieldGivenName, FieldFamilyName, FieldOrgUnit}

// UserAttrs holds the comparable attributes of a user. Empty means "no
// value" (a mapped field that becomes empty is cleared on the target).
type UserAttrs map[UserField]string

// Clone returns a copy.
func (a UserAttrs) Clone() UserAttrs {
	out := make(UserAttrs, len(a))
	for k, v := range a {
		out[k] = v
	}
	return out
}

// SourceUser is a user as read from the source and mapped to target form.
type SourceUser struct {
	// ID is the stable source identity (AD objectGUID, canonical string).
	ID string
	// DN and Account are for display only (they change on rename/move).
	DN      string
	Account string
	// Enabled is false for a disabled source account; disabled users are
	// suspended on the target (when the policy says so).
	Enabled bool
	Attrs   UserAttrs
	// Placement says which org unit rule placed the user (display).
	Placement string
	// Error is a per-user mapping error that must not be resolved by a
	// silent pick (an ambiguous org unit): the plan reports it and leaves
	// the user untouched (not created, not changed, not suspended).
	Error string
}

// ScopeGroup is an AD group referenced by the scope (include or exclude)
// or by an org unit rule, as resolved in the source. The configuration
// keeps a DN or a SID; the plan shows the group's current name.
type ScopeGroup struct {
	Role     string `json:"role"` // include | exclude | org_unit
	Ref      string `json:"ref"`
	Found    bool   `json:"found"`
	DN       string `json:"dn,omitempty"`
	Name     string `json:"name,omitempty"`
	SID      string `json:"sid,omitempty"`
	Members  int    `json:"members"`
	Target   string `json:"target,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

// Scope roles of a ScopeGroup.
const (
	RoleInclude = "include"
	RoleExclude = "exclude"
	RoleOrgUnit = "org_unit"
)

// SourceGroup is a group as read from the source and mapped to target form.
type SourceGroup struct {
	ID          string
	DN          string
	Account     string
	Email       string
	Name        string
	Description string
	// Members are direct members that are themselves in scope.
	Members []MemberRef
}

// MemberRef points at a source object by ID.
type MemberRef struct {
	Kind Kind
	ID   string
}

// TargetUser is a user as read from a target directory.
type TargetUser struct {
	// ID is the target's immutable identifier.
	ID string
	// Owner is the source ID recorded on the target object as the sync's
	// ownership marker (Google: an externalIds entry), empty when absent.
	Owner     string
	Suspended bool
	// Protected accounts (target administrators, the delegated admin the
	// connector acts as) are never suspended or renamed by the sync.
	Protected bool
	Attrs     UserAttrs
	// Aliases are other addresses that route to this account (a renamed
	// account keeps its old address as an alias on Google).
	Aliases []string
}

// TargetGroup is a group as read from a target directory, with members.
type TargetGroup struct {
	ID          string
	Email       string
	Name        string
	Description string
	Aliases     []string
	Members     []TargetMember
}

// TargetMember is one member of a target group.
type TargetMember struct {
	// ID is the member's target ID when the target reports one.
	ID    string
	Email string
	// Kind is user or group; anything else (external addresses, the whole
	// customer) is reported with an empty kind and never touched unless
	// the policy removes unmanaged members.
	Kind Kind
	Role string
}

// NormalizeEmail lowercases and trims an address for comparisons.
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// SortedFields returns the keys of a in a stable order (always-managed
// first, then optional, then anything else alphabetically).
func SortedFields(a UserAttrs) []UserField {
	order := map[UserField]int{}
	for i, f := range append(append([]UserField(nil), AlwaysManagedUserFields...), OptionalUserFields...) {
		order[f] = i
	}
	keys := make([]UserField, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		oi, iok := order[keys[i]]
		oj, jok := order[keys[j]]
		switch {
		case iok && jok:
			return oi < oj
		case iok != jok:
			return iok
		default:
			return keys[i] < keys[j]
		}
	})
	return keys
}
