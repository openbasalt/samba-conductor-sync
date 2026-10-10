package syncapi

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Google-first mode (Google Workspace to AD). conductor-sync reads Google
// with the read-only Directory API scopes and AD with its read-only
// account, and returns a plan of typed AD operations (g2a.plan). It never
// writes to Google or to AD: conductor applies the plan through
// conductor-provisioner, then reports what it applied (g2a.confirm) so the
// links are recorded and the run is closed.

// Operations of the Google-first mode.
const (
	// OpG2APlan reads Google and AD (read-only) and records a plan as a
	// run of action RunActionG2A.
	OpG2APlan Op = "g2a.plan"
	// OpG2AConfirm records what conductor applied of a g2a plan: links
	// are written and the run is closed (applied, partial or blocked).
	OpG2AConfirm Op = "g2a.confirm"
)

// RunActionG2A is the action of the runs that record a g2a plan.
const RunActionG2A = "g2a"

// G2A operation kinds.
const (
	G2AUserCreate   = "ad.user.create"
	G2AUserUpdate   = "ad.user.update"
	G2AUserRename   = "ad.user.rename"
	G2AUserDisable  = "ad.user.disable"
	G2AUserReenable = "ad.user.reenable"
)

// G2AKinds lists the operation kinds in apply order (updates, renames,
// re-enables, creates, disables last).
var G2AKinds = []string{G2AUserUpdate, G2AUserRename, G2AUserReenable, G2AUserCreate, G2AUserDisable}

// Reasons of g2a operations.
const (
	G2AReasonNew            = "new"             // create: a selected Google account without AD object
	G2AReasonGoogleChange   = "google-change"   // update: Google changed the field since the last apply
	G2AReasonADDrift        = "ad-drift"        // update: the AD value was changed in AD (P2: Google wins)
	G2AReasonPrimaryAddress = "primary-address" // rename: the Google primary address changed
	G2AReasonSuspended      = "suspended"       // disable: suspended in Google
	G2AReasonDeleted        = "deleted"         // disable: the Google account no longer exists
	G2AReasonOutOfSelection = "out-of-selection"
	G2AReasonActive         = "active" // re-enable: active and selected in Google again
)

// Skip reasons of g2a plans.
const (
	G2ASkipPrivileged          = "privileged-object"
	G2ASkipUnmanagedExists     = "ad-unmanaged-exists"
	G2ASkipDuplicateLogon      = "duplicate-logon-name"
	G2ASkipMarkerMismatch      = "marker-mismatch"
	G2ASkipManagedByADFirst    = "managed-by-ad-first"
	G2ASkipNoFreeLogon         = "no-free-logon-name"
	G2ASkipDisabledOutsideSync = "disabled-outside-sync"
	G2ASkipInTwoScopes         = "in-two-scopes"
)

// G2AMarkerAttribute is the AD attribute that carries the Google-first
// marker; G2AMarkerPrefix starts its value ("google-first:<google user id>").
const (
	G2AMarkerAttribute = "msDS-cloudExtensionAttribute1"
	G2AMarkerPrefix    = "google-first:"
)

// G2AMarker returns the marker value of a Google user ID.
func G2AMarker(googleID string) string { return G2AMarkerPrefix + googleID }

// G2A scope modes.
const (
	G2AModeDryRun = "dry-run"
	G2AModeApply  = "apply"
)

// GoogleFirstSettings is the [google_first] section: off by default. The
// scopes pair a managed AD OU with a Google selection.
type GoogleFirstSettings struct {
	Enabled bool `json:"enabled"`
	// GoogleDomain is the Google Workspace domain whose accounts the mode
	// manages (accounts in other domains are never selected).
	GoogleDomain string     `json:"google_domain"`
	Scopes       []G2AScope `json:"scopes"`
}

// G2AScope is one Google-first scope.
type G2AScope struct {
	Name string `json:"name"`
	// Mode is "dry-run" (default) or "apply" (conductor's confirmation
	// flow switches it).
	Mode string `json:"mode"`
	// ManagedOU holds the accounts; GroupsOU and QuarantineOU are below it.
	ManagedOU    string `json:"managed_ou"`
	GroupsOU     string `json:"groups_ou"`
	QuarantineOU string `json:"quarantine_ou"`
	// OrgUnits are Google org unit paths ("/Staff"); with SubOrgUnits, the
	// org units below them too.
	OrgUnits    []string `json:"org_units"`
	SubOrgUnits bool     `json:"sub_org_units"`
	// MemberOf restricts the selection to (nested) members of at least one
	// of these Google groups; empty: no restriction.
	MemberOf []string `json:"member_of"`
	// Fields are the optional user fields Google owns in this scope
	// (title, department, employee_id, phone_work, phone_mobile).
	Fields []string `json:"fields"`
	// LogonTemplate renders a logon name when the address's local part is
	// not usable (default "{given}.{family}").
	LogonTemplate string `json:"logon_template"`
	// Limits nil means the defaults.
	Limits *G2ALimits `json:"limits,omitempty"`
}

// G2ALimits bound what one plan may change in a scope (0 = none allowed,
// -1 = no limit). A plan outside them is blocked: conductor does not apply
// it.
type G2ALimits struct {
	MaxCreates           int     `json:"max_creates"`
	MaxDisables          int     `json:"max_disables"`
	MaxReenables         int     `json:"max_reenables"`
	MaxUpdates           int     `json:"max_updates"`
	MaxRenames           int     `json:"max_renames"`
	MaxTouchedPercent    float64 `json:"max_touched_percent"`
	MinSourceSize        int     `json:"min_source_size"`
	MaxSourceDropPercent float64 `json:"max_source_drop_percent"`
}

// G2AChange is one attribute change of an operation. Field is the AD
// attribute (givenName, sn, displayName, mail, proxyAddresses, title,
// department, employeeID, telephoneNumber, mobile; for a create also
// sAMAccountName, userPrincipalName and cn; "enabled" and "parent" for
// the state changes of a disable or re-enable). A multi-valued attribute
// (proxyAddresses) is its values sorted and joined with "\n".
type G2AChange struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// G2AOp is one planned AD operation. Seq numbers the operations of the
// whole plan (g2a.confirm refers to them).
type G2AOp struct {
	Seq      int    `json:"seq"`
	Kind     string `json:"kind"`
	GoogleID string `json:"google_id"`
	// SAM, DN, SID and ObjectGUID identify the AD account (for a create:
	// the planned logon name and DN, no SID or GUID yet).
	SAM        string `json:"sam,omitempty"`
	DN         string `json:"dn,omitempty"`
	SID        string `json:"sid,omitempty"`
	ObjectGUID string `json:"object_guid,omitempty"`
	Reason     string `json:"reason"`
	// Marker is the Google-first marker the account carries (or receives).
	Marker  string      `json:"marker"`
	Changes []G2AChange `json:"changes,omitempty"`
	// ParentOU is the OU a create places the account in; MoveTo the OU a
	// disable (quarantine) or re-enable (managed OU) moves it to ("" when
	// it is already there).
	ParentOU string `json:"parent_ou,omitempty"`
	MoveTo   string `json:"move_to,omitempty"`
	// Enable and Disable say whether the operation changes the account's
	// enabled state (a disable of an account already disabled only moves
	// it).
	Enable  bool `json:"enable,omitempty"`
	Disable bool `json:"disable,omitempty"`
	// Invite: conductor issues an invitation to set the first password
	// (creates; the account stays disabled until the invitation completes).
	Invite   bool     `json:"invite,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// G2ASkipped is a Google account or AD object the plan leaves alone, with
// the reason (G2ASkip*). Detail adds the privilege reasons of a
// privileged-object skip, or the conflicting object.
type G2ASkipped struct {
	GoogleID string   `json:"google_id,omitempty"`
	SAM      string   `json:"sam,omitempty"`
	DN       string   `json:"dn,omitempty"`
	Reason   string   `json:"reason"`
	Detail   []string `json:"detail,omitempty"`
}

// G2AScopePlan is the plan of one scope.
type G2AScopePlan struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
	// Ops are in apply order (G2AKinds), then by Google ID.
	Ops      []G2AOp      `json:"ops"`
	Skipped  []G2ASkipped `json:"skipped,omitempty"`
	Warnings []Warning    `json:"warnings,omitempty"`
	// Limits compares every limit with the plan; an exceeded row blocks
	// the scope.
	Limits []LimitRow `json:"limits"`
	// Blocked is set when a limit is exceeded.
	Blocked bool `json:"blocked"`
	// SourceSize counts the selected Google accounts; Managed the AD
	// accounts carrying a Google-first marker in the managed OU.
	SourceSize int `json:"source_size"`
	Managed    int `json:"managed"`
}

// G2APlan is the result of g2a.plan (and the plan of a g2a run).
type G2APlan struct {
	RunID  int64     `json:"run_id"`
	Digest string    `json:"digest"`
	ReadAt time.Time `json:"read_at"`
	// GoogleDomain is the domain the plan selected accounts in.
	GoogleDomain string         `json:"google_domain"`
	Scopes       []G2AScopePlan `json:"scopes"`
}

// Ops returns every operation of the plan in Seq order.
func (p *G2APlan) Ops() []G2AOp {
	var out []G2AOp
	for _, s := range p.Scopes {
		out = append(out, s.Ops...)
	}
	return out
}

var scopeNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidG2AScopeName reports whether a scope name is valid: 1-32 lower-case
// letters, digits, '-' and '_', starting with a letter or digit.
func ValidG2AScopeName(s string) bool { return scopeNameRE.MatchString(s) }

// G2APlanParams request a g2a plan: one scope (by name) or every scope
// (empty Scope). RoleGroupSIDs are conductor's admin, helpdesk and auditor
// role groups: their members are privileged (P1) like the members of the
// built-in administrative groups.
type G2APlanParams struct {
	Scope         string   `json:"scope,omitempty"`
	RoleGroupSIDs []string `json:"role_group_sids,omitempty"`
}

// Validate implements Params.
func (p G2APlanParams) Validate() error {
	if p.Scope != "" && !ValidG2AScopeName(p.Scope) {
		return fmt.Errorf("scope %q: not a scope name", p.Scope)
	}
	if len(p.RoleGroupSIDs) > 32 {
		return errors.New("role_group_sids: at most 32")
	}
	for _, s := range p.RoleGroupSIDs {
		if !sidRE.MatchString(s) {
			return fmt.Errorf("role_group_sids: %q is not a SID", s)
		}
	}
	return nil
}

// G2A result statuses of one operation.
const (
	G2AOpDone    = "done"
	G2AOpFailed  = "failed"
	G2AOpSkipped = "skipped"
)

// G2AOpResult is what conductor did with one operation. For a create that
// succeeded, SID and ObjectGUID name the new account (the link keeps them).
type G2AOpResult struct {
	Seq        int    `json:"seq"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	SID        string `json:"sid,omitempty"`
	ObjectGUID string `json:"object_guid,omitempty"`
}

// MaxG2AConfirmResults bounds one confirmation.
const MaxG2AConfirmResults = 20000

var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// G2AConfirmParams report what conductor applied of the plan recorded by
// run RunID (Digest must be that plan's). Actor is who approved the apply
// ("scheduled" for a scheduled run).
type G2AConfirmParams struct {
	RunID   int64         `json:"run_id"`
	Digest  string        `json:"digest"`
	Results []G2AOpResult `json:"results"`
	Actor   string        `json:"actor"`
}

// Validate implements Params.
func (p G2AConfirmParams) Validate() error {
	if p.RunID <= 0 || !digestRE.MatchString(p.Digest) {
		return errors.New("run_id and the digest of the plan are required")
	}
	if !userRE.MatchString(p.Actor) {
		return errors.New("actor: who approved the apply")
	}
	if len(p.Results) > MaxG2AConfirmResults {
		return fmt.Errorf("results: at most %d", MaxG2AConfirmResults)
	}
	seen := map[int]bool{}
	for _, r := range p.Results {
		if r.Seq < 0 || seen[r.Seq] {
			return fmt.Errorf("results: operation %d is missing or repeated", r.Seq)
		}
		seen[r.Seq] = true
		switch r.Status {
		case G2AOpDone, G2AOpFailed, G2AOpSkipped:
		default:
			return fmt.Errorf("results: operation %d: status %q (done, failed or skipped)", r.Seq, r.Status)
		}
		if len(r.Error) > 2048 {
			return fmt.Errorf("results: operation %d: error longer than 2048 bytes", r.Seq)
		}
		if r.SID != "" && !sidRE.MatchString(r.SID) {
			return fmt.Errorf("results: operation %d: invalid SID", r.Seq)
		}
		if r.ObjectGUID != "" && !guidRE.MatchString(r.ObjectGUID) {
			return fmt.Errorf("results: operation %d: invalid objectGUID", r.Seq)
		}
	}
	return nil
}

// G2AConfirmResult is the closed run.
type G2AConfirmResult struct {
	RunID int64 `json:"run_id"`
	// Status is applied, partial, blocked or dry-run.
	Status  string `json:"status"`
	Done    int    `json:"done"`
	Failed  int    `json:"failed"`
	Skipped int    `json:"skipped"`
	// Links counts the links written or updated.
	Links int `json:"links"`
}
