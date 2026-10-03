package syncapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Run statuses (as stored by conductor-sync).
const (
	StatusRunning     = "running"
	StatusPlanned     = "planned"
	StatusApplied     = "applied"
	StatusPartial     = "partial"
	StatusBlocked     = "blocked"
	StatusFailed      = "failed"
	StatusInterrupted = "interrupted"
	StatusDryRun      = "dry-run"
	StatusNothing     = "nothing-to-do"
)

var validStatus = map[string]bool{StatusRunning: true, StatusPlanned: true, StatusApplied: true, StatusPartial: true,
	StatusBlocked: true, StatusFailed: true, StatusInterrupted: true, StatusDryRun: true, StatusNothing: true}

// Sections group operation kinds for display, in display order.
var Sections = []string{"create", "update", "rename", "suspend", "unsuspend", "groups", "members", "links"}

var sectionKinds = map[string][]string{
	"create":    {"user.create"},
	"update":    {"user.update", "user.adopt"},
	"rename":    {"user.rename"},
	"suspend":   {"user.suspend"},
	"unsuspend": {"user.unsuspend"},
	"groups":    {"group.create", "group.update", "group.adopt"},
	"members":   {"member.add", "member.remove"},
	"links":     {"user.relink", "user.unlink", "group.relink", "group.unlink"},
}

// SectionKinds returns the operation kinds of a section.
func SectionKinds(section string) []string { return sectionKinds[section] }

// SectionOf returns the section of an operation kind ("" when unknown).
func SectionOf(kind string) string {
	for s, kinds := range sectionKinds {
		for _, k := range kinds {
			if k == kind {
				return s
			}
		}
	}
	return ""
}

// ---- settings: the part of the configuration editable through the API ----

// Settings are the sync settings an administrator edits in conductor. Host
// settings (state directory, credentials, how to reach AD and Google, the
// ownership marker, alerts) stay in the configuration file and are never
// changed through the API.
type Settings struct {
	Mode     string           `json:"mode"`
	Scope    ScopeSettings    `json:"scope"`
	Mapping  MappingSettings  `json:"mapping"`
	Policy   PolicySettings   `json:"policy"`
	Limits   LimitSettings    `json:"limits"`
	Google   GoogleSettings   `json:"google"`
	Schedule ScheduleSettings `json:"schedule"`
}

// ScopeSettings decide which AD users and groups are synced.
type ScopeSettings struct {
	UserBases    []string `json:"user_bases"`
	ExcludeBases []string `json:"exclude_bases"`
	GroupBases   []string `json:"group_bases"`
	// IncludeGroups and ExcludeGroups are group DNs or SIDs (SIDs survive
	// renames and moves). Nested membership counts; exclusion wins.
	IncludeGroups     []string `json:"include_groups"`
	ExcludeGroups     []string `json:"exclude_groups"`
	ExpiredAsDisabled bool     `json:"expired_as_disabled"`
}

// OrgUnitRule places users in a Google org unit: by AD container (AD) or
// by group membership (Group, with an explicit Priority; 1 is evaluated
// first).
type OrgUnitRule struct {
	AD       string `json:"ad,omitempty"`
	Group    string `json:"group,omitempty"`
	Target   string `json:"target"`
	Priority int    `json:"priority,omitempty"`
}

// MappingSettings render AD objects into Google accounts and groups.
type MappingSettings struct {
	PrimaryEmail        []string          `json:"primary_email"`
	AllowedDomains      []string          `json:"allowed_domains"`
	GivenName           []string          `json:"given_name"`
	FamilyName          []string          `json:"family_name"`
	DefaultOrgUnit      string            `json:"default_org_unit"`
	OrgUnits            []OrgUnitRule     `json:"org_units"`
	Attributes          map[string]string `json:"attributes"`
	GroupEmail          []string          `json:"group_email"`
	GroupName           []string          `json:"group_name"`
	GroupDescription    []string          `json:"group_description"`
	GroupAllowedDomains []string          `json:"group_allowed_domains"`
}

// PolicySettings are the behaviour switches.
type PolicySettings struct {
	SuspendDisabled        bool   `json:"suspend_disabled"`
	CreateDisabled         bool   `json:"create_disabled"`
	Adopt                  string `json:"adopt"`
	RemoveUnmanagedMembers bool   `json:"remove_unmanaged_members"`
}

// LimitSettings are the safety limits of scheduled runs (0 = none
// allowed, -1 = no limit).
type LimitSettings struct {
	MaxCreates           int     `json:"max_creates"`
	MaxSuspends          int     `json:"max_suspends"`
	MaxUnsuspends        int     `json:"max_unsuspends"`
	MaxRenames           int     `json:"max_renames"`
	MaxUpdates           int     `json:"max_updates"`
	MaxGroupChanges      int     `json:"max_group_changes"`
	MaxMembershipChanges int     `json:"max_membership_changes"`
	MaxTouchedPercent    float64 `json:"max_touched_percent"`
	MinSourceUsers       int     `json:"min_source_users"`
	MaxSourceDropPercent float64 `json:"max_source_drop_percent"`
}

// GoogleSettings are the tenant settings an administrator may change.
type GoogleSettings struct {
	Customer     string `json:"customer"`
	AdminSubject string `json:"admin_subject"`
	MemberRole   string `json:"member_role"`
}

// ScheduleSettings: how often scheduled runs happen.
type ScheduleSettings struct {
	// Interval is a Go duration ("15m"). With the systemd timer it must
	// match the timer (it is used to show the next run); with the
	// in-process scheduler it drives it.
	Interval string `json:"interval"`
}

// Change is one changed setting ("path: old -> new").
type Change struct {
	Path string `json:"path"`
	Old  string `json:"old"`
	New  string `json:"new"`
}

func (c Change) String() string { return fmt.Sprintf("%s: %s -> %s", c.Path, c.Old, c.New) }

// DiffSettings lists the settings that differ, by JSON path, sorted.
func DiffSettings(oldS, newS Settings) []Change {
	a, b := flatten(oldS), flatten(newS)
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var out []Change
	for k := range keys {
		if a[k] != b[k] {
			out = append(out, Change{Path: k, Old: a[k], New: b[k]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// flatten renders settings as path -> value; lists and maps are compared
// as a whole (their JSON), which keeps the diff short and readable.
func flatten(s Settings) map[string]string {
	raw, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if strings.HasSuffix(prefix, "attributes") {
				b, _ := json.Marshal(x)
				out[prefix] = string(b)
				return
			}
			for k, val := range x {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, val)
			}
		case nil:
			out[prefix] = ""
		case string:
			out[prefix] = x
		case []any:
			if len(x) == 0 {
				out[prefix] = "[]"
				return
			}
			b, _ := json.Marshal(x)
			out[prefix] = string(b)
		default:
			b, _ := json.Marshal(x)
			out[prefix] = string(b)
		}
	}
	walk("", m)
	return out
}

// ---- results ----

// LinkCounts are the recorded AD <-> Google links.
type LinkCounts struct {
	Users           int `json:"users"`
	SuspendedBySync int `json:"suspended_by_sync"`
	Groups          int `json:"groups"`
}

// AuditState is the result of verifying the hash chain.
type AuditState struct {
	Intact   bool   `json:"intact"`
	Rows     int    `json:"rows"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
	LastHash string `json:"last_hash,omitempty"`
}

// KeyInfo describes the stored service account key; the key itself is
// never returned.
type KeyInfo struct {
	ClientEmail string    `json:"client_email"`
	KeyID       string    `json:"key_id"`
	SetAt       time.Time `json:"set_at,omitzero"`
	SetBy       string    `json:"set_by,omitempty"`
	// Source is "database" (set through the API, encrypted at rest) or
	// "credential" (the file named by google.key_credential).
	Source string `json:"source"`
}

// Violation is one exceeded safety limit.
type Violation struct {
	Limit string  `json:"limit"`
	Value float64 `json:"value"`
	Max   float64 `json:"max"`
}

// LimitRow compares one limit with a plan.
type LimitRow struct {
	Limit    string  `json:"limit"`
	Value    float64 `json:"value"`
	Max      float64 `json:"max"`
	Exceeded bool    `json:"exceeded"`
}

// Run is one recorded run.
type Run struct {
	ID           int64          `json:"id"`
	Action       string         `json:"action"`
	Trigger      string         `json:"trigger"`
	Actor        string         `json:"actor"`
	StartedAt    time.Time      `json:"started_at"`
	FinishedAt   time.Time      `json:"finished_at,omitzero"`
	Status       string         `json:"status"`
	Digest       string         `json:"digest,omitempty"`
	SourceUsers  int            `json:"source_users"`
	SourceGroups int            `json:"source_groups"`
	OpsTotal     int            `json:"ops_total"`
	OpsDone      int            `json:"ops_done"`
	OpsFailed    int            `json:"ops_failed"`
	Error        string         `json:"error,omitempty"`
	Counts       map[string]int `json:"counts,omitempty"`
	Violations   []Violation    `json:"violations,omitempty"`
	Warnings     int            `json:"warnings"`
	Errors       int            `json:"errors"`
	Skipped      int            `json:"skipped"`
	// HasPlan is set when the run recorded a plan that can be reviewed.
	HasPlan bool `json:"has_plan"`
}

// Job is a background plan or apply started through the API.
type Job struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"` // plan | apply | scheduled
	State      string    `json:"state"`
	RunID      int64     `json:"run_id,omitempty"`
	RunStatus  string    `json:"run_status,omitempty"`
	Error      string    `json:"error,omitempty"`
	Actor      string    `json:"actor"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
	Progress   Progress  `json:"progress"`
}

// Job states.
const (
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
)

// Progress of an apply (from its journal).
type Progress struct {
	Total   int `json:"total"`
	Done    int `json:"done"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

// Status is the overview of the sync.
type Status struct {
	Version          string     `json:"version"`
	Mode             string     `json:"mode"`
	Connector        string     `json:"connector"`
	FirstManualApply string     `json:"first_manual_apply,omitempty"`
	Links            LinkCounts `json:"links"`
	LastRun          *Run       `json:"last_run,omitempty"`
	LastApply        *Run       `json:"last_apply,omitempty"`
	LastSuccess      *Run       `json:"last_success,omitempty"`
	// Scheduler is "timer" (systemd) or "in-process" (serve runs them).
	Scheduler        string    `json:"scheduler"`
	ScheduleInterval string    `json:"schedule_interval"`
	NextScheduled    time.Time `json:"next_scheduled,omitzero"`
	// OpenBlocked are blocked runs newer than the last successful apply.
	OpenBlocked   []Run      `json:"open_blocked,omitempty"`
	InFlight      int        `json:"in_flight"`
	Audit         AuditState `json:"audit"`
	ConfigVersion int64      `json:"config_version"`
	ConfigAt      time.Time  `json:"config_at,omitzero"`
	ConfigBy      string     `json:"config_by,omitempty"`
	Key           *KeyInfo   `json:"key,omitempty"`
	Job           *Job       `json:"job,omitempty"`
	// Ready is set when a key and an admin subject are configured.
	Ready bool `json:"ready"`
}

// HostInfo is the read-only part of the configuration (file only).
type HostInfo struct {
	ConfigPath   string   `json:"config_path"`
	Realm        string   `json:"realm"`
	DCs          []string `json:"dcs,omitempty"`
	BindUser     string   `json:"bind_user"`
	Auth         string   `json:"auth"`
	StateDir     string   `json:"state_dir"`
	Marker       string   `json:"marker"`
	APIBaseURL   string   `json:"api_base_url"`
	AlertWebhook bool     `json:"alert_webhook"`
}

// ConfigView is the current configuration.
type ConfigView struct {
	// Version 0 means the settings come from the file (never edited
	// through the API).
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	Settings  Settings  `json:"settings"`
	Host      HostInfo  `json:"host"`
}

// ConfigVersion is one entry of the configuration history.
type ConfigVersion struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Origin  string    `json:"origin"` // bootstrap | api | cli
	Comment string    `json:"comment,omitempty"`
	Changes []Change  `json:"changes,omitempty"`
}

// ConfigValidateResult is the outcome of a validation.
type ConfigValidateResult struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors,omitempty"`
	Changes []Change `json:"changes,omitempty"`
}

// ConfigUpdateResult is a saved version.
type ConfigUpdateResult struct {
	Version int64    `json:"version"`
	Changes []Change `json:"changes"`
}

// ConfigExport is the effective configuration as TOML.
type ConfigExport struct {
	TOML string `json:"toml"`
}

// ScopeGroup is an AD group referenced by the scope or the org unit rules,
// resolved: the plan shows names, the configuration keeps DNs or SIDs.
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

// Check is the result of one connection test.
type Check struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// TestResult is the outcome of connection.test.
type TestResult struct {
	AD     Check        `json:"ad"`
	Google Check        `json:"google"`
	Groups []ScopeGroup `json:"groups,omitempty"`
}

// PreviewUser is the mapping of one sample AD user.
type PreviewUser struct {
	Account    string `json:"account"`
	DN         string `json:"dn"`
	Enabled    bool   `json:"enabled"`
	InScope    bool   `json:"in_scope"`
	OutReason  string `json:"out_reason,omitempty"`
	Email      string `json:"email,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	OrgUnit    string `json:"org_unit,omitempty"`
	Placement  string `json:"placement,omitempty"`
	Error      string `json:"error,omitempty"`
}

// PreviewResult is the outcome of mapping.preview.
type PreviewResult struct {
	Users  []PreviewUser `json:"users"`
	Groups []ScopeGroup  `json:"groups,omitempty"`
}

// Warning is a plan warning or a per-object plan error.
type Warning struct {
	Code    string `json:"code"`
	Key     string `json:"key"`
	Message string `json:"message"`
}

// Skipped is a source object that could not be mapped.
type Skipped struct {
	DN     string `json:"dn"`
	Reason string `json:"reason"`
}

// FieldChange is one field difference of an operation.
type FieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// PlanOp is one planned operation, with its journal state once applied.
type PlanOp struct {
	Seq         int               `json:"seq"`
	Kind        string            `json:"kind"`
	Key         string            `json:"key"`
	Reason      string            `json:"reason,omitempty"`
	Changes     []FieldChange     `json:"changes,omitempty"`
	Attrs       map[string]string `json:"attrs,omitempty"`
	Suspend     bool              `json:"suspend,omitempty"`
	GroupName   string            `json:"group_name,omitempty"`
	MemberKind  string            `json:"member_kind,omitempty"`
	MemberEmail string            `json:"member_email,omitempty"`
	// Status and Error come from the journal of an apply ("" for a plan).
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// RunDetail is one run with its plan and a page of operations.
type RunDetail struct {
	Run Run `json:"run"`
	// Plan fields (absent when the run recorded no plan).
	HasPlan      bool           `json:"has_plan"`
	Digest       string         `json:"digest,omitempty"`
	Counts       map[string]int `json:"counts,omitempty"`
	Sections     map[string]int `json:"sections,omitempty"`
	Limits       []LimitRow     `json:"limits,omitempty"`
	Warnings     []Warning      `json:"warnings,omitempty"`
	Errors       []Warning      `json:"errors,omitempty"`
	Skipped      []Skipped      `json:"skipped,omitempty"`
	Groups       []ScopeGroup   `json:"groups,omitempty"`
	ManagedUsers int            `json:"managed_users"`
	Writes       int            `json:"writes"`
	// Ops is the requested page; OpsMatching counts the whole selection.
	Ops         []PlanOp `json:"ops"`
	OpsMatching int      `json:"ops_matching"`
	// Applicable: a manual apply of this plan is possible now (latest
	// plan, mode apply, no run in progress); Override: it needs the
	// limits override.
	Applicable bool   `json:"applicable"`
	Override   bool   `json:"override"`
	NotApply   string `json:"not_applicable,omitempty"`
	// Confirmation is the text an operator types to apply (bound to the
	// digest).
	Confirmation string `json:"confirmation,omitempty"`
}

// RunsList is a page of runs.
type RunsList struct {
	Runs  []Run `json:"runs"`
	Total int   `json:"total"`
}

// JobStarted answers plan.start and apply.start.
type JobStarted struct {
	Job Job `json:"job"`
}

// Confirmation returns the text an operator must type to apply a plan:
// "apply" or "override", then the first 8 characters of the digest, so the
// typed text is bound to the reviewed plan.
func Confirmation(digest string, override bool) string {
	word := "apply"
	if override {
		word = "override"
	}
	if len(digest) > 8 {
		digest = digest[:8]
	}
	return word + " " + digest
}
