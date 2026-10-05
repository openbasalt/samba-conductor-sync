// Package plan computes what a sync run would change on a target: it
// compares the source (AD, already mapped to target form) with the target's
// current state and the recorded source-to-target links, and produces an
// ordered list of operations plus warnings. It never talks to a directory:
// the same plan is shown, stored, checked against the safety limits and
// only then applied.
//
// Safety rules encoded here:
//   - nothing is ever deleted: a user that leaves the scope (or is removed
//     from AD) is suspended; a group that leaves the scope is kept as is;
//   - only objects the sync owns are touched: a link recorded in state, the
//     ownership marker on the target object, or an explicit adoption policy;
//     an existing target object with the same address is otherwise reported
//     and left alone;
//   - a suspension done outside the sync is never undone by it;
//   - members the sync does not manage stay in managed groups unless the
//     operator opts in to removing them;
//   - an adopted account (one that existed before the sync and was taken
//     over by address) keeps its org unit, its address and any name or
//     field AD has no value for, unless the policy says otherwise; a
//     disabled AD user never adopts an account; an adopted group loses no
//     member by default.
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
)

// OpKind is the type of one planned operation.
type OpKind string

// Operation kinds. Relink and unlink only change local state (no target
// write); every other kind writes to the target.
const (
	UserRelink    OpKind = "user.relink"
	UserUnlink    OpKind = "user.unlink"
	UserAdopt     OpKind = "user.adopt"
	UserRename    OpKind = "user.rename"
	UserUpdate    OpKind = "user.update"
	UserUnsuspend OpKind = "user.unsuspend"
	UserCreate    OpKind = "user.create"
	UserSuspend   OpKind = "user.suspend"
	GroupRelink   OpKind = "group.relink"
	GroupUnlink   OpKind = "group.unlink"
	GroupAdopt    OpKind = "group.adopt"
	GroupCreate   OpKind = "group.create"
	GroupUpdate   OpKind = "group.update"
	MemberAdd     OpKind = "member.add"
	MemberRemove  OpKind = "member.remove"
)

// phase orders operations: local relinks first, then renames (so an
// address freed by a rename can be taken by a create), updates, creates,
// groups, memberships, and suspensions last (an interrupted run leaves the
// fewest surprise suspensions).
var phase = map[OpKind]int{
	UserRelink: 0, UserUnlink: 0, GroupRelink: 0, GroupUnlink: 0,
	UserRename: 1, UserAdopt: 2, UserUpdate: 2, UserUnsuspend: 3, UserCreate: 4,
	GroupAdopt: 5, GroupUpdate: 5, GroupCreate: 6,
	MemberAdd: 7, MemberRemove: 8, UserSuspend: 9,
}

// WritesTarget reports whether the operation changes the target.
func (k OpKind) WritesTarget() bool {
	switch k {
	case UserRelink, UserUnlink, GroupRelink, GroupUnlink:
		return false
	}
	return true
}

// Change is one field difference.
type Change struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// GroupSpec is the desired state of a target group.
type GroupSpec struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// MemberSpec identifies one membership. Target IDs may be empty when the
// object is created in the same run; they are resolved from the links at
// apply time.
type MemberSpec struct {
	GroupSourceID  string     `json:"group_source_id,omitempty"`
	GroupTargetID  string     `json:"group_target_id,omitempty"`
	GroupEmail     string     `json:"group_email"`
	Kind           model.Kind `json:"member_kind,omitempty"`
	MemberSourceID string     `json:"member_source_id,omitempty"`
	MemberTargetID string     `json:"member_target_id,omitempty"`
	MemberEmail    string     `json:"member_email"`
}

// Op is one planned operation.
type Op struct {
	Kind     OpKind `json:"kind"`
	SourceID string `json:"source_id,omitempty"`
	TargetID string `json:"target_id,omitempty"`
	// Key is the target address the operation is about (display, sort).
	Key     string   `json:"key"`
	Reason  string   `json:"reason,omitempty"`
	Changes []Change `json:"changes,omitempty"`
	// Attrs is the full desired user (managed fields) for create, adopt,
	// update and rename; the connector writes the changed ones.
	Attrs model.UserAttrs `json:"attrs,omitempty"`
	// Suspend creates the account suspended.
	Suspend bool `json:"suspend,omitempty"`
	// Adopted marks a relink of an account that carries the adoption mark
	// (state lost after an adoption), so the link keeps the adopted rules.
	Adopted bool        `json:"adopted,omitempty"`
	Group   *GroupSpec  `json:"group,omitempty"`
	Member  *MemberSpec `json:"member,omitempty"`
}

// String renders an operation for humans.
func (o Op) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-15s %s", o.Kind, o.Key)
	if o.Member != nil {
		fmt.Fprintf(&sb, " (%s %s)", o.Member.Kind, o.Member.MemberEmail)
	}
	if o.Reason != "" {
		fmt.Fprintf(&sb, "  [%s]", o.Reason)
	}
	for _, c := range o.Changes {
		fmt.Fprintf(&sb, "\n      %s: %q -> %q", c.Field, c.Old, c.New)
	}
	if o.Kind == UserCreate {
		for _, f := range model.SortedFields(o.Attrs) {
			fmt.Fprintf(&sb, "\n      %s = %q", f, o.Attrs[f])
		}
		if o.Suspend {
			sb.WriteString("\n      suspended = true")
		}
	}
	if o.Group != nil && o.Kind == GroupCreate {
		fmt.Fprintf(&sb, "\n      name = %q, description = %q", o.Group.Name, o.Group.Description)
	}
	return sb.String()
}

func hasChange(cs []Change, field string) bool {
	for _, c := range cs {
		if c.Field == field {
			return true
		}
	}
	return false
}

// Warning is something the operator should look at; it never causes a
// write.
type Warning struct {
	Code    string `json:"code"`
	Key     string `json:"key"`
	Message string `json:"message"`
}

// Warning codes.
const (
	WarnDuplicateAddress  = "duplicate-address"
	WarnUnmanagedExists   = "unmanaged-exists"
	WarnOwnedByOther      = "owned-by-other-source"
	WarnAliasCollision    = "alias-collision"
	WarnSuspendedOutside  = "suspended-outside-sync"
	WarnGroupOutOfScope   = "group-out-of-scope"
	WarnInvalidSource     = "invalid-source-object"
	WarnTargetMissing     = "target-missing"
	WarnUnmanagedMember   = "unmanaged-member-kept"
	WarnDisabledNotCreate = "disabled-not-created"
	WarnProtected         = "protected-account"
	// WarnAdoptedAddress: AD renders another address for an adopted
	// account or group; the address is kept (no rename) by default.
	WarnAdoptedAddress = "adopted-address-kept"
	// WarnAdoptDisabled: an existing account matches a disabled AD user;
	// it is not adopted (and so not suspended) until the user is enabled.
	WarnAdoptDisabled = "disabled-not-adopted"
	// WarnAdoptedMemberKept: a member of an adopted group is not in the AD
	// group; kept because adopted groups are add-only by default.
	WarnAdoptedMemberKept = "adopted-member-kept"
)

// Plan error codes: a per-object problem the operator must fix; the object
// is left untouched (not created, changed, suspended or removed from
// groups) until then.
const (
	ErrOrgUnitAmbiguous = "org-unit-ambiguous"
)

// SkippedObject is a source object that could not be mapped.
type SkippedObject struct {
	DN     string `json:"dn"`
	Reason string `json:"reason"`
}

// Plan is the outcome of Compute.
type Plan struct {
	Connector string    `json:"connector"`
	Ops       []Op      `json:"ops"`
	Warnings  []Warning `json:"warnings,omitempty"`
	// Errors are per-object plan errors (the object is left untouched).
	Errors       []Warning `json:"errors,omitempty"`
	SourceUsers  int       `json:"source_users"`
	SourceGroups int       `json:"source_groups"`
	// ManagedUsers counts links to existing target users before the run.
	ManagedUsers  int    `json:"managed_users"`
	ManagedGroups int    `json:"managed_groups"`
	Digest        string `json:"digest"`

	// Display only (not in the digest): the referenced groups as
	// resolved, users left out by the include and exclude groups, and
	// source objects that could not be mapped. Set by the engine.
	Scope       []model.ScopeGroup `json:"scope,omitempty"`
	NotIncluded int                `json:"not_included,omitempty"`
	Excluded    int                `json:"excluded,omitempty"`
	Skipped     []SkippedObject    `json:"skipped,omitempty"`
}

// Counts returns how many operations of each kind the plan holds.
func (p *Plan) Counts() map[OpKind]int {
	out := map[OpKind]int{}
	for _, o := range p.Ops {
		out[o.Kind]++
	}
	return out
}

// Writes counts operations that change the target.
func (p *Plan) Writes() int {
	n := 0
	for _, o := range p.Ops {
		if o.Kind.WritesTarget() {
			n++
		}
	}
	return n
}

// Empty reports a plan with nothing to do.
func (p *Plan) Empty() bool { return len(p.Ops) == 0 }

// ComputeDigest is SHA-256 over the canonical JSON of the operations: two
// plans with the same digest perform exactly the same changes.
func ComputeDigest(ops []Op) string {
	b, _ := json.Marshal(ops)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Link is a recorded source-to-target association.
type Link struct {
	Kind     model.Kind
	SourceID string
	TargetID string
	Key      string
	// SuspendedBySync is set when the sync suspended the target object; only
	// then may the sync unsuspend it.
	SuspendedBySync bool
	// Adopted is set when the target object existed before the sync and was
	// adopted by address (not created by the sync). The adopted rules of
	// the policy apply to it on every run.
	Adopted bool
}

// InFlight is a create that an interrupted run started but never
// confirmed; a target object with that address is the result of it.
type InFlight struct {
	Kind     OpKind
	SourceID string
	Key      string
}

// AdoptMode decides what happens to an existing, unmanaged target object
// whose address equals a desired one.
type AdoptMode string

// Adoption modes.
const (
	AdoptNever AdoptMode = "never"
	AdoptEmail AdoptMode = "email"
)

// AdoptedMode decides how one aspect of an adopted account or group is
// treated.
type AdoptedMode string

// Adopted modes. Not every aspect accepts every mode (see Policy).
const (
	// AdoptedKeep never changes the value on the target.
	AdoptedKeep AdoptedMode = "keep"
	// AdoptedIfSet writes the AD value only when AD has one of its own
	// (not empty, not rendered by a fallback template).
	AdoptedIfSet AdoptedMode = "if-set"
	// AdoptedManage treats the adopted object like one the sync created.
	AdoptedManage AdoptedMode = "manage"
	// AdoptedAddOnly adds members to an adopted group but never removes one.
	AdoptedAddOnly AdoptedMode = "add-only"
)

// Policy holds the behaviour switches of a plan.
type Policy struct {
	// Optional lists the optional user fields that are mapped (managed).
	Optional map[model.UserField]bool
	// SuspendDisabled suspends target accounts of disabled source users.
	SuspendDisabled bool
	// CreateDisabled also creates (suspended) accounts for disabled users.
	CreateDisabled bool
	Adopt          AdoptMode
	// ManageGroups turns group and membership sync on.
	ManageGroups bool
	// RemoveUnmanagedMembers removes members of managed groups that the
	// sync does not manage (external addresses, manual additions). It does
	// not apply to adopted groups unless AdoptedGroupMembers is manage.
	RemoveUnmanagedMembers bool

	// Rules for adopted accounts and groups (Link.Adopted), on the
	// adoption run and on every later run. Empty values take the safe
	// defaults (Defaults).
	//
	// AdoptedOrgUnit: keep (default) or manage.
	AdoptedOrgUnit AdoptedMode
	// AdoptedEmail: keep (default: an adopted account or group is never
	// renamed; a different AD address is a warning) or manage.
	AdoptedEmail AdoptedMode
	// AdoptedNames (given and family name; group name and description):
	// if-set (default), keep or manage.
	AdoptedNames AdoptedMode
	// AdoptedAttributes (the mapped optional fields): if-set (default:
	// an empty AD value never clears the Google value), keep or manage.
	AdoptedAttributes AdoptedMode
	// AdoptedGroupMembers: add-only (default) or manage.
	AdoptedGroupMembers AdoptedMode
}

// Defaults fills the empty adopted rules with the safe defaults.
func (p *Policy) Defaults() {
	if p.Adopt == "" {
		p.Adopt = AdoptNever
	}
	if p.AdoptedOrgUnit == "" {
		p.AdoptedOrgUnit = AdoptedKeep
	}
	if p.AdoptedEmail == "" {
		p.AdoptedEmail = AdoptedKeep
	}
	if p.AdoptedNames == "" {
		p.AdoptedNames = AdoptedIfSet
	}
	if p.AdoptedAttributes == "" {
		p.AdoptedAttributes = AdoptedIfSet
	}
	if p.AdoptedGroupMembers == "" {
		p.AdoptedGroupMembers = AdoptedAddOnly
	}
}

// AdoptedChoices lists the accepted modes of each adopted rule, by its
// configuration key (policy.<key>).
var AdoptedChoices = map[string][]AdoptedMode{
	"adopted_org_unit":      {AdoptedKeep, AdoptedManage},
	"adopted_email":         {AdoptedKeep, AdoptedManage},
	"adopted_names":         {AdoptedIfSet, AdoptedKeep, AdoptedManage},
	"adopted_attributes":    {AdoptedIfSet, AdoptedKeep, AdoptedManage},
	"adopted_group_members": {AdoptedAddOnly, AdoptedManage},
}

// ValidAdopted reports whether v is accepted for the rule key ("" means
// the default and is accepted).
func ValidAdopted(key string, v AdoptedMode) bool {
	if v == "" {
		return true
	}
	for _, c := range AdoptedChoices[key] {
		if c == v {
			return true
		}
	}
	return false
}

// Input is everything Compute needs.
type Input struct {
	Connector    string
	Users        []model.SourceUser
	Groups       []model.SourceGroup
	TargetUsers  []model.TargetUser
	TargetGroups []model.TargetGroup
	Links        []Link
	InFlight     []InFlight
	Policy       Policy
}

type planner struct {
	in   Input
	ops  []Op
	warn []Warning
	errs []Warning
	// frozen source users are left untouched (plan error or duplicate
	// address): no suspension, no membership removal.
	frozen map[string]bool

	tUserByID    map[string]*model.TargetUser
	tUserByEmail map[string]*model.TargetUser // primary and aliases
	tUserByOwner map[string]*model.TargetUser
	tGroupByID   map[string]*model.TargetGroup
	tGroupByMail map[string]*model.TargetGroup

	userLinkBySrc  map[string]Link
	userLinkByTgt  map[string]Link
	groupLinkBySrc map[string]Link
	groupLinkByTgt map[string]Link

	// managedUser maps a source user ID to the target ID it will have after
	// this run ("" when created in this run) for users that are managed.
	managedUser  map[string]string
	managedGroup map[string]string
	// userAddr is the address a managed user has after this run (an
	// adopted account keeps its own by default).
	userAddr map[string]string
	srcUser  map[string]*model.SourceUser
	srcGroup map[string]*model.SourceGroup
	inflight map[string]InFlight // kind|key
}

// Compute builds the plan. It is deterministic: the same input yields the
// same operations in the same order, so the digest identifies the plan.
func Compute(in Input) *Plan {
	p := &planner{in: in,
		tUserByID: map[string]*model.TargetUser{}, tUserByEmail: map[string]*model.TargetUser{}, tUserByOwner: map[string]*model.TargetUser{},
		tGroupByID: map[string]*model.TargetGroup{}, tGroupByMail: map[string]*model.TargetGroup{},
		userLinkBySrc: map[string]Link{}, userLinkByTgt: map[string]Link{}, groupLinkBySrc: map[string]Link{}, groupLinkByTgt: map[string]Link{},
		managedUser: map[string]string{}, managedGroup: map[string]string{},
		srcUser: map[string]*model.SourceUser{}, srcGroup: map[string]*model.SourceGroup{}, inflight: map[string]InFlight{},
		frozen: map[string]bool{}, userAddr: map[string]string{},
	}
	p.in.Policy.Defaults()
	p.index()
	p.users()
	if in.Policy.ManageGroups {
		p.groups()
	}
	sort.SliceStable(p.ops, func(i, j int) bool {
		a, b := p.ops[i], p.ops[j]
		if phase[a.Kind] != phase[b.Kind] {
			return phase[a.Kind] < phase[b.Kind]
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		ma, mb := "", ""
		if a.Member != nil {
			ma = a.Member.MemberEmail
		}
		if b.Member != nil {
			mb = b.Member.MemberEmail
		}
		if ma != mb {
			return ma < mb
		}
		return a.Kind < b.Kind
	})
	sort.SliceStable(p.warn, func(i, j int) bool {
		if p.warn[i].Code != p.warn[j].Code {
			return p.warn[i].Code < p.warn[j].Code
		}
		return p.warn[i].Key < p.warn[j].Key
	})
	sort.SliceStable(p.errs, func(i, j int) bool { return p.errs[i].Key < p.errs[j].Key })
	out := &Plan{Connector: in.Connector, Ops: p.ops, Warnings: p.warn, Errors: p.errs,
		SourceUsers: len(in.Users), SourceGroups: len(in.Groups)}
	for _, l := range in.Links {
		switch l.Kind {
		case model.KindUser:
			if _, ok := p.tUserByID[l.TargetID]; ok {
				out.ManagedUsers++
			}
		case model.KindGroup:
			if _, ok := p.tGroupByID[l.TargetID]; ok {
				out.ManagedGroups++
			}
		}
	}
	if out.Ops == nil {
		out.Ops = []Op{}
	}
	out.Digest = ComputeDigest(out.Ops)
	return out
}

func (p *planner) index() {
	for i := range p.in.TargetUsers {
		u := &p.in.TargetUsers[i]
		p.tUserByID[u.ID] = u
		for _, a := range u.Aliases {
			p.tUserByEmail[model.NormalizeEmail(a)] = u
		}
		p.tUserByEmail[model.NormalizeEmail(u.Attrs[model.FieldPrimaryEmail])] = u
		if u.Owner != "" {
			p.tUserByOwner[u.Owner] = u
		}
	}
	for i := range p.in.TargetGroups {
		g := &p.in.TargetGroups[i]
		p.tGroupByID[g.ID] = g
		for _, a := range g.Aliases {
			p.tGroupByMail[model.NormalizeEmail(a)] = g
		}
		p.tGroupByMail[model.NormalizeEmail(g.Email)] = g
	}
	for _, l := range p.in.Links {
		switch l.Kind {
		case model.KindUser:
			p.userLinkBySrc[l.SourceID] = l
			p.userLinkByTgt[l.TargetID] = l
		case model.KindGroup:
			p.groupLinkBySrc[l.SourceID] = l
			p.groupLinkByTgt[l.TargetID] = l
		}
	}
	for _, f := range p.in.InFlight {
		p.inflight[string(f.Kind)+"|"+model.NormalizeEmail(f.Key)] = f
	}
}

func (p *planner) add(o Op) { p.ops = append(p.ops, o) }

func (p *planner) warnf(code, key, format string, args ...any) {
	p.warn = append(p.warn, Warning{Code: code, Key: key, Message: fmt.Sprintf(format, args...)})
}

// managedFields lists the user fields compared on a managed account.
func (p *planner) managedFields() []model.UserField {
	out := append([]model.UserField(nil), model.AlwaysManagedUserFields...)
	for _, f := range model.OptionalUserFields {
		if p.in.Policy.Optional[f] {
			out = append(out, f)
		}
	}
	return out
}

func (p *planner) desiredAttrs(su *model.SourceUser) model.UserAttrs {
	out := model.UserAttrs{}
	for _, f := range p.managedFields() {
		out[f] = su.Attrs[f]
	}
	return out
}

// desiredFor returns the desired managed fields of a user's account. For
// an adopted account the adopted rules replace AD values by the account's
// own where the policy keeps them; kept lists the fields whose AD value
// differs but is not written (shown in the adoption's reason).
func (p *planner) desiredFor(su *model.SourceUser, tu *model.TargetUser, adopted bool) (desired model.UserAttrs, kept []string) {
	desired = p.desiredAttrs(su)
	if !adopted || tu == nil {
		return desired, nil
	}
	pol := p.in.Policy
	keep := func(f model.UserField) {
		if len(diffUser(tu.Attrs, desired, []model.UserField{f})) > 0 {
			kept = append(kept, string(f))
		}
		desired[f] = tu.Attrs[f]
	}
	if pol.AdoptedOrgUnit != AdoptedManage {
		keep(model.FieldOrgUnit)
	}
	if pol.AdoptedEmail != AdoptedManage && len(diffUser(tu.Attrs, desired, []model.UserField{model.FieldPrimaryEmail})) > 0 {
		p.warnf(WarnAdoptedAddress, model.NormalizeEmail(tu.Attrs[model.FieldPrimaryEmail]),
			"AD renders %s for this adopted account; its address is kept (policy.adopted_email = \"manage\" renames it)",
			model.NormalizeEmail(desired[model.FieldPrimaryEmail]))
		keep(model.FieldPrimaryEmail)
	}
	for _, f := range []model.UserField{model.FieldGivenName, model.FieldFamilyName} {
		switch pol.AdoptedNames {
		case AdoptedKeep:
			keep(f)
		case AdoptedIfSet:
			if strings.TrimSpace(su.Attrs[f]) == "" || su.Fallback[f] {
				keep(f)
			}
		}
	}
	for _, f := range model.OptionalUserFields {
		if !pol.Optional[f] {
			continue
		}
		switch pol.AdoptedAttributes {
		case AdoptedKeep:
			keep(f)
		case AdoptedIfSet:
			if strings.TrimSpace(su.Attrs[f]) == "" {
				keep(f)
			}
		}
	}
	return desired, kept
}

func (p *planner) users() {
	users := append([]model.SourceUser(nil), p.in.Users...)
	sort.Slice(users, func(i, j int) bool {
		return model.NormalizeEmail(users[i].Attrs[model.FieldPrimaryEmail]) < model.NormalizeEmail(users[j].Attrs[model.FieldPrimaryEmail])
	})
	// Duplicate desired addresses: none of the colliding users is touched.
	byEmail := map[string][]string{}
	for i := range users {
		su := &users[i]
		email := model.NormalizeEmail(su.Attrs[model.FieldPrimaryEmail])
		if su.ID == "" || email == "" {
			p.warnf(WarnInvalidSource, su.DN, "source user has no ID or no target address; skipped")
			continue
		}
		byEmail[email] = append(byEmail[email], su.ID)
	}
	groupEmails := map[string]bool{}
	if p.in.Policy.ManageGroups {
		for _, g := range p.in.Groups {
			groupEmails[model.NormalizeEmail(g.Email)] = true
		}
	}
	seenSource := map[string]bool{}
	for i := range users {
		su := &users[i]
		email := model.NormalizeEmail(su.Attrs[model.FieldPrimaryEmail])
		if su.ID == "" || email == "" {
			continue
		}
		seenSource[su.ID] = true
		if su.Error != "" {
			// A per-user mapping error (an ambiguous org unit) is never
			// resolved by a silent pick: report it and leave the user,
			// its account and its memberships as they are.
			p.frozen[su.ID] = true
			p.errs = append(p.errs, Warning{Code: ErrOrgUnitAmbiguous, Key: email, Message: su.Account + ": " + su.Error})
			continue
		}
		if len(byEmail[email]) > 1 {
			p.warnf(WarnDuplicateAddress, email, "%d source users map to this address (%s); none of them is synced until fixed", len(byEmail[email]), su.Account)
			// Keep an existing link from being suspended as "out of scope".
			p.frozen[su.ID] = true
			continue
		}
		if groupEmails[email] {
			p.warnf(WarnDuplicateAddress, email, "user %s maps to the address of a group; skipped", su.Account)
			continue
		}
		p.srcUser[su.ID] = su
		p.user(su, email)
	}
	// Linked users that are no longer in scope: suspend (never delete).
	links := make([]Link, 0, len(p.userLinkBySrc))
	for _, l := range p.userLinkBySrc {
		links = append(links, l)
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Key < links[j].Key })
	for _, l := range links {
		if seenSource[l.SourceID] {
			continue
		}
		tu, ok := p.tUserByID[l.TargetID]
		if !ok {
			p.add(Op{Kind: UserUnlink, SourceID: l.SourceID, TargetID: l.TargetID, Key: l.Key,
				Reason: "out of scope and the target account no longer exists"})
			continue
		}
		if !tu.Suspended {
			if tu.Protected {
				p.warnf(WarnProtected, l.Key, "administrator account left the scope; not suspended by the sync")
				continue
			}
			p.add(Op{Kind: UserSuspend, SourceID: l.SourceID, TargetID: tu.ID, Key: tu.Attrs[model.FieldPrimaryEmail],
				Reason: "no longer in the sync scope (moved, filtered or removed from AD)"})
		}
	}
	// Accounts carrying the ownership marker without a link (state lost or
	// a create whose confirmation was interrupted) and no source: relink
	// them so they are tracked, and suspend them like any out-of-scope user.
	owners := make([]string, 0, len(p.tUserByOwner))
	for o := range p.tUserByOwner {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		tu := p.tUserByOwner[owner]
		if seenSource[owner] {
			continue
		}
		if _, linked := p.userLinkBySrc[owner]; linked {
			continue
		}
		if _, linked := p.userLinkByTgt[tu.ID]; linked {
			continue
		}
		key := tu.Attrs[model.FieldPrimaryEmail]
		p.add(Op{Kind: UserRelink, SourceID: owner, TargetID: tu.ID, Key: key, Reason: "carries the ownership marker"})
		if !tu.Suspended && !tu.Protected {
			p.add(Op{Kind: UserSuspend, SourceID: owner, TargetID: tu.ID, Key: key,
				Reason: "owned by the sync but its source is not in scope"})
		}
	}
}

func (p *planner) user(su *model.SourceUser, email string) {
	var tu *model.TargetUser
	var link Link
	linked := false
	adopted := false
	if l, ok := p.userLinkBySrc[su.ID]; ok {
		if t, ok := p.tUserByID[l.TargetID]; ok {
			tu, link, linked = t, l, true
			adopted = l.Adopted || t.Adopted
		} else {
			p.add(Op{Kind: UserUnlink, SourceID: su.ID, TargetID: l.TargetID, Key: l.Key,
				Reason: "the linked target account no longer exists"})
			p.warnf(WarnTargetMissing, l.Key, "target account %s was removed outside the sync; it will be created again", l.TargetID)
		}
	}
	if tu == nil {
		if t, ok := p.tUserByOwner[su.ID]; ok {
			if other, taken := p.userLinkByTgt[t.ID]; taken && other.SourceID != su.ID {
				p.warnf(WarnOwnedByOther, email, "target account is linked to another source object; skipped")
				return
			}
			tu = t
			adopted = t.Adopted
			p.add(Op{Kind: UserRelink, SourceID: su.ID, TargetID: t.ID, Key: t.Attrs[model.FieldPrimaryEmail],
				Reason: "carries the ownership marker", Adopted: t.Adopted})
		}
	}
	wantSuspended := !su.Enabled && p.in.Policy.SuspendDisabled
	if tu == nil {
		t, exists := p.tUserByEmail[email]
		if exists {
			switch {
			case model.NormalizeEmail(t.Attrs[model.FieldPrimaryEmail]) != email:
				p.warnf(WarnAliasCollision, email, "address is an alias of %s; skipped", t.Attrs[model.FieldPrimaryEmail])
				return
			case p.userLinkByTgt[t.ID].SourceID != "":
				p.warnf(WarnOwnedByOther, email, "target account is linked to another source object; skipped")
				return
			case t.Owner != "" && t.Owner != su.ID:
				p.warnf(WarnOwnedByOther, email, "target account carries the marker of another source object (%s); skipped", t.Owner)
				return
			case p.in.Policy.Adopt != AdoptEmail:
				p.warnf(WarnUnmanagedExists, email, "an account with this address exists and is not managed by the sync; left alone (adopt = \"email\" to take it over)")
				return
			case !su.Enabled:
				// Adopting would suspend a working account only because AD
				// has it disabled: wait until it is enabled in AD.
				p.warnf(WarnAdoptDisabled, email, "an account with this address exists but the AD user is disabled; not adopted (and not suspended) until it is enabled in AD")
				return
			}
			desired, kept := p.desiredFor(su, t, true)
			reason := "adopt existing account by address"
			if len(kept) > 0 {
				reason += "; kept on the account: " + strings.Join(kept, ", ")
			}
			p.managedUser[su.ID] = t.ID
			p.userAddr[su.ID] = model.NormalizeEmail(desired[model.FieldPrimaryEmail])
			p.add(Op{Kind: UserAdopt, SourceID: su.ID, TargetID: t.ID, Key: email, Attrs: desired,
				Changes: diffUser(t.Attrs, desired, p.managedFields()), Reason: reason})
			p.suspension(su, t, email, Link{}, false, false)
			return
		}
		if !su.Enabled && !p.in.Policy.CreateDisabled {
			p.warnf(WarnDisabledNotCreate, email, "disabled in AD and not on the target; not created")
			return
		}
		attrs := p.desiredAttrs(su)
		reason := ""
		if wantSuspended {
			reason = "created suspended (disabled in AD)"
		}
		p.managedUser[su.ID] = ""
		p.userAddr[su.ID] = email
		p.add(Op{Kind: UserCreate, SourceID: su.ID, Key: email, Attrs: attrs, Reason: reason, Suspend: wantSuspended})
		return
	}
	desired, _ := p.desiredFor(su, tu, adopted)
	key := model.NormalizeEmail(desired[model.FieldPrimaryEmail])
	p.managedUser[su.ID] = tu.ID
	p.userAddr[su.ID] = key
	if changes := diffUser(tu.Attrs, desired, p.managedFields()); len(changes) > 0 {
		reason := ""
		if hasChange(changes, string(model.FieldOrgUnit)) && su.Placement != "" {
			reason = "org unit from " + su.Placement
		}
		kind := UserUpdate
		if hasChange(changes, string(model.FieldPrimaryEmail)) {
			kind = UserRename
			if tu.Protected {
				p.warnf(WarnProtected, key, "administrator account %s would be renamed; left alone", tu.Attrs[model.FieldPrimaryEmail])
				p.suspension(su, tu, key, link, linked, wantSuspended)
				return
			}
		}
		p.add(Op{Kind: kind, SourceID: su.ID, TargetID: tu.ID, Key: key, Changes: changes, Attrs: desired, Reason: reason})
	}
	p.suspension(su, tu, key, link, linked, wantSuspended)
}

func (p *planner) suspension(su *model.SourceUser, tu *model.TargetUser, email string, link Link, linked, want bool) {
	switch {
	case want && !tu.Suspended && tu.Protected:
		p.warnf(WarnProtected, email, "administrator account is disabled in AD; not suspended by the sync")
	case want && !tu.Suspended:
		p.add(Op{Kind: UserSuspend, SourceID: su.ID, TargetID: tu.ID, Key: email, Reason: "disabled in AD"})
	case !want && tu.Suspended:
		if linked && link.SuspendedBySync {
			p.add(Op{Kind: UserUnsuspend, SourceID: su.ID, TargetID: tu.ID, Key: email, Reason: "enabled and in scope again"})
		} else {
			p.warnf(WarnSuspendedOutside, email, "suspended on the target by someone else; the sync does not unsuspend it")
		}
	}
}

// diffUser compares the managed fields. Addresses compare case-insensitively.
func diffUser(cur, want model.UserAttrs, fields []model.UserField) []Change {
	var out []Change
	for _, f := range fields {
		c, w := strings.TrimSpace(cur[f]), strings.TrimSpace(want[f])
		if f == model.FieldPrimaryEmail {
			if model.NormalizeEmail(c) == model.NormalizeEmail(w) {
				continue
			}
			w = model.NormalizeEmail(w)
		} else if f == model.FieldOrgUnit {
			if strings.EqualFold(c, w) {
				continue
			}
		} else if c == w {
			continue
		}
		out = append(out, Change{Field: string(f), Old: c, New: w})
	}
	return out
}

func (p *planner) groups() {
	groups := append([]model.SourceGroup(nil), p.in.Groups...)
	sort.Slice(groups, func(i, j int) bool {
		return model.NormalizeEmail(groups[i].Email) < model.NormalizeEmail(groups[j].Email)
	})
	byEmail := map[string]int{}
	for _, g := range groups {
		byEmail[model.NormalizeEmail(g.Email)]++
	}
	seen := map[string]bool{}
	// First pass: decide which groups are managed (and their target IDs) so
	// nested group memberships can be resolved in the second pass.
	type pending struct {
		sg      *model.SourceGroup
		tg      *model.TargetGroup
		adopted bool
	}
	var managed []pending
	for i := range groups {
		sg := &groups[i]
		email := model.NormalizeEmail(sg.Email)
		if sg.ID == "" || email == "" {
			p.warnf(WarnInvalidSource, sg.DN, "source group has no ID or no target address; skipped")
			continue
		}
		seen[sg.ID] = true
		if byEmail[email] > 1 {
			p.warnf(WarnDuplicateAddress, email, "%d source groups map to this address; none of them is synced until fixed", byEmail[email])
			continue
		}
		if t, ok := p.tUserByEmail[email]; ok {
			p.warnf(WarnDuplicateAddress, email, "group address is taken by user %s; skipped", t.Attrs[model.FieldPrimaryEmail])
			continue
		}
		var tg *model.TargetGroup
		adopted, adopting := false, false
		if l, ok := p.groupLinkBySrc[sg.ID]; ok {
			if t, ok := p.tGroupByID[l.TargetID]; ok {
				tg = t
				adopted = l.Adopted
			} else {
				p.add(Op{Kind: GroupUnlink, SourceID: sg.ID, TargetID: l.TargetID, Key: l.Key,
					Reason: "the linked target group no longer exists"})
				p.warnf(WarnTargetMissing, l.Key, "target group %s was removed outside the sync; it will be created again", l.TargetID)
			}
		}
		if tg == nil {
			if t, ok := p.tGroupByMail[email]; ok {
				_, inflight := p.inflight[string(GroupCreate)+"|"+email]
				switch {
				case model.NormalizeEmail(t.Email) != email:
					p.warnf(WarnAliasCollision, email, "address is an alias of group %s; skipped", t.Email)
					continue
				case p.groupLinkByTgt[t.ID].SourceID != "":
					p.warnf(WarnOwnedByOther, email, "target group is linked to another source group; skipped")
					continue
				case inflight:
					tg = t
					p.add(Op{Kind: GroupRelink, SourceID: sg.ID, TargetID: t.ID, Key: email,
						Reason: "created by an interrupted run"})
				case p.in.Policy.Adopt == AdoptEmail:
					tg = t
					adopted, adopting = true, true
				default:
					p.warnf(WarnUnmanagedExists, email, "a group with this address exists and is not managed by the sync; left alone (adopt = \"email\" to take it over)")
					continue
				}
			}
		}
		p.srcGroup[sg.ID] = sg
		spec := GroupSpec{Email: email, Name: sg.Name, Description: sg.Description}
		if tg == nil {
			p.managedGroup[sg.ID] = ""
			p.add(Op{Kind: GroupCreate, SourceID: sg.ID, Key: email, Group: &spec})
		} else {
			p.managedGroup[sg.ID] = tg.ID
			if adopted {
				spec = p.adoptedGroupSpec(sg, tg, spec)
			}
			var changes []Change
			if model.NormalizeEmail(tg.Email) != spec.Email {
				changes = append(changes, Change{Field: "email", Old: tg.Email, New: spec.Email})
			}
			if tg.Name != spec.Name {
				changes = append(changes, Change{Field: "name", Old: tg.Name, New: spec.Name})
			}
			if tg.Description != spec.Description {
				changes = append(changes, Change{Field: "description", Old: tg.Description, New: spec.Description})
			}
			switch {
			case adopting:
				p.add(Op{Kind: GroupAdopt, SourceID: sg.ID, TargetID: tg.ID, Key: email, Changes: changes, Group: &spec,
					Reason: "adopt existing group by address"})
			case len(changes) > 0:
				p.add(Op{Kind: GroupUpdate, SourceID: sg.ID, TargetID: tg.ID, Key: email, Changes: changes, Group: &spec})
			}
		}
		managed = append(managed, pending{sg, tg, adopted})
	}
	for _, m := range managed {
		p.members(m.sg, m.tg, m.adopted)
	}
	// Linked groups out of scope are kept: groups are never deleted, and
	// their members are left as they are.
	links := make([]Link, 0, len(p.groupLinkBySrc))
	for _, l := range p.groupLinkBySrc {
		links = append(links, l)
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Key < links[j].Key })
	for _, l := range links {
		if seen[l.SourceID] {
			continue
		}
		if _, ok := p.tGroupByID[l.TargetID]; !ok {
			p.add(Op{Kind: GroupUnlink, SourceID: l.SourceID, TargetID: l.TargetID, Key: l.Key,
				Reason: "out of scope and the target group no longer exists"})
			continue
		}
		p.warnf(WarnGroupOutOfScope, l.Key, "group left the sync scope; kept unchanged (delete it manually if intended)")
	}
}

// memberKey identifies a member: its target ID when known, else its
// address.
func memberKey(id, email string) string {
	if id != "" {
		return "id:" + id
	}
	return "mail:" + model.NormalizeEmail(email)
}

// adoptedGroupSpec applies the adopted rules to an adopted group's desired
// state: its address is kept unless adopted_email is manage, and its name
// and description follow adopted_names.
func (p *planner) adoptedGroupSpec(sg *model.SourceGroup, tg *model.TargetGroup, spec GroupSpec) GroupSpec {
	pol := p.in.Policy
	if pol.AdoptedEmail != AdoptedManage && model.NormalizeEmail(tg.Email) != spec.Email {
		p.warnf(WarnAdoptedAddress, model.NormalizeEmail(tg.Email),
			"AD renders %s for this adopted group; its address is kept (policy.adopted_email = \"manage\" renames it)", spec.Email)
		spec.Email = model.NormalizeEmail(tg.Email)
	}
	switch pol.AdoptedNames {
	case AdoptedKeep:
		spec.Name, spec.Description = tg.Name, tg.Description
	case AdoptedIfSet:
		if strings.TrimSpace(sg.Name) == "" {
			spec.Name = tg.Name
		}
		if strings.TrimSpace(sg.Description) == "" {
			spec.Description = tg.Description
		}
	}
	return spec
}

func (p *planner) members(sg *model.SourceGroup, tg *model.TargetGroup, adopted bool) {
	email := model.NormalizeEmail(sg.Email)
	type want struct {
		kind     model.Kind
		srcID    string
		targetID string
		email    string
	}
	desired := map[string]want{}
	var order []string
	for _, m := range sg.Members {
		var w want
		switch m.Kind {
		case model.KindUser:
			su, ok := p.srcUser[m.ID]
			if !ok {
				continue
			}
			tid, managed := p.managedUser[m.ID]
			if !managed {
				continue
			}
			addr := p.userAddr[m.ID]
			if addr == "" {
				addr = model.NormalizeEmail(su.Attrs[model.FieldPrimaryEmail])
			}
			w = want{model.KindUser, m.ID, tid, addr}
		case model.KindGroup:
			g, ok := p.srcGroup[m.ID]
			if !ok || m.ID == sg.ID {
				continue
			}
			tid, managed := p.managedGroup[m.ID]
			if !managed {
				continue
			}
			w = want{model.KindGroup, m.ID, tid, model.NormalizeEmail(g.Email)}
		default:
			continue
		}
		k := memberKey(w.targetID, w.email)
		if _, dup := desired[k]; !dup {
			desired[k] = w
			order = append(order, k)
		}
	}
	current := map[string]model.TargetMember{}
	if tg != nil {
		for _, m := range tg.Members {
			if m.ID != "" {
				current[memberKey(m.ID, "")] = m
			}
			if m.Email != "" {
				current[memberKey("", m.Email)] = m
			}
		}
	}
	gid := ""
	if tg != nil {
		gid = tg.ID
	}
	for _, k := range order {
		w := desired[k]
		if _, ok := current[k]; ok {
			continue
		}
		if w.targetID != "" {
			if _, ok := current[memberKey("", w.email)]; ok {
				continue
			}
		}
		p.add(Op{Kind: MemberAdd, Key: email, Member: &MemberSpec{GroupSourceID: sg.ID, GroupTargetID: gid,
			GroupEmail: email, Kind: w.kind, MemberSourceID: w.srcID, MemberTargetID: w.targetID, MemberEmail: w.email}})
	}
	if tg == nil {
		return
	}
	desiredByID := map[string]bool{}
	desiredByMail := map[string]bool{}
	for _, w := range desired {
		if w.targetID != "" {
			desiredByID[w.targetID] = true
		}
		desiredByMail[w.email] = true
	}
	for _, m := range tg.Members {
		if (m.ID != "" && desiredByID[m.ID]) || desiredByMail[model.NormalizeEmail(m.Email)] {
			continue
		}
		managedObj := false
		var srcID string
		var kind model.Kind
		if l, ok := p.userLinkByTgt[m.ID]; ok && m.ID != "" {
			if p.frozen[l.SourceID] {
				// A user left untouched by a plan error keeps its groups.
				continue
			}
			managedObj, srcID, kind = true, l.SourceID, model.KindUser
		} else if l, ok := p.groupLinkByTgt[m.ID]; ok && m.ID != "" {
			managedObj, srcID, kind = true, l.SourceID, model.KindGroup
		}
		if adopted && p.in.Policy.AdoptedGroupMembers != AdoptedManage {
			// An adopted group is add-only: nobody is removed, managed or not.
			if managedObj {
				p.warnf(WarnAdoptedMemberKept, email, "member %s is not in the AD group; kept (adopted group, policy.adopted_group_members = \"add-only\")", m.Email)
			} else {
				p.warnf(WarnUnmanagedMember, email, "member %s is not managed by the sync; kept", m.Email)
			}
			continue
		}
		if !managedObj && !p.in.Policy.RemoveUnmanagedMembers {
			p.warnf(WarnUnmanagedMember, email, "member %s is not managed by the sync; kept", m.Email)
			continue
		}
		if kind == "" {
			kind = m.Kind
		}
		p.add(Op{Kind: MemberRemove, Key: email, Member: &MemberSpec{GroupSourceID: sg.ID, GroupTargetID: tg.ID,
			GroupEmail: email, Kind: kind, MemberSourceID: srcID, MemberTargetID: m.ID, MemberEmail: model.NormalizeEmail(m.Email)}})
	}
}
