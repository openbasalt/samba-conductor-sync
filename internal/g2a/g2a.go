// Package g2a builds the plan of the Google-first mode: Google Workspace
// is the source of truth for the people of a scope, and AD follows. The
// plan is a list of typed AD operations (create, update, rename, disable,
// re-enable) computed from a read of Google (read-only Directory API
// scopes) and a read of AD (conductor-sync's read-only account).
//
// conductor-sync never writes to Google or to AD: conductor applies the
// plan through conductor-provisioner and reports back what it applied.
//
// Product rules (normative premises of the mode):
//   - P1: nothing from Google grants or touches a privileged AD account. A
//     privileged account is skipped (privileged-object) whatever Google
//     says about it; Google administrator flags never map to anything in
//     AD (super administrators and the admin subject are not created).
//   - P2: Google wins on the fields it owns. An AD-side change of such a
//     field is reverted on the next plan (ad.user.update, reason ad-drift).
//   - Never delete: a suspended, deleted or deselected Google account is
//     disabled and moved to the quarantine OU.
//   - Identity is the immutable Google user ID, carried on the AD object as
//     the marker "google-first:<id>" in msDS-cloudExtensionAttribute1 and
//     in the g2a_links table. A Google account deleted and recreated has a
//     new ID: it is a new person, never a takeover of the old AD account.
//
// Build is deterministic: the same input gives the same plan and digest.
package g2a

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-sync/internal/gimport"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// Unlimited disables one limit (0 means none allowed).
const Unlimited = -1

// Limits bound what one plan may change in a scope.
type Limits struct {
	MaxCreates           int     `toml:"max_creates"`
	MaxDisables          int     `toml:"max_disables"`
	MaxReenables         int     `toml:"max_reenables"`
	MaxUpdates           int     `toml:"max_updates"`
	MaxRenames           int     `toml:"max_renames"`
	MaxTouchedPercent    float64 `toml:"max_touched_percent"`
	MinSourceSize        int     `toml:"min_source_size"`
	MaxSourceDropPercent float64 `toml:"max_source_drop_percent"`
}

// DefaultLimits are small on purpose: day-to-day changes pass, anything
// bigger is reviewed (and the limits raised) by an administrator.
func DefaultLimits() Limits {
	return Limits{MaxCreates: 20, MaxDisables: 5, MaxReenables: 20, MaxUpdates: 50, MaxRenames: 5,
		MaxTouchedPercent: 20, MinSourceSize: 1, MaxSourceDropPercent: 20}
}

// Validate checks the ranges (-1 unlimited, 0 none; percentages 0-100).
func (l Limits) Validate(prefix string) []error {
	var errs []error
	for _, c := range []struct {
		name string
		v    int
	}{{"max_creates", l.MaxCreates}, {"max_disables", l.MaxDisables}, {"max_reenables", l.MaxReenables},
		{"max_updates", l.MaxUpdates}, {"max_renames", l.MaxRenames}, {"min_source_size", l.MinSourceSize}} {
		if c.v < Unlimited || c.v > 1000000 {
			errs = append(errs, fmt.Errorf("%s.%s: %d (0-1000000, or -1 for no limit)", prefix, c.name, c.v))
		}
	}
	for _, c := range []struct {
		name string
		v    float64
	}{{"max_touched_percent", l.MaxTouchedPercent}, {"max_source_drop_percent", l.MaxSourceDropPercent}} {
		if c.v != Unlimited && (c.v < 0 || c.v > 100) {
			errs = append(errs, fmt.Errorf("%s.%s: %g (0-100, or -1 for no limit)", prefix, c.name, c.v))
		}
	}
	return errs
}

// Scope is one Google-first scope as the plan needs it.
type Scope struct {
	Name         string
	Mode         string
	ManagedOU    string
	GroupsOU     string
	QuarantineOU string
	OrgUnits     []string
	SubOrgUnits  bool
	MemberOf     []string
	// Fields are the optional fields Google owns in this scope.
	Fields        []model.UserField
	LogonTemplate string
	Limits        Limits
}

// ---- Google side ----

// GoogleUser is one Google account of the snapshot.
type GoogleUser struct {
	ID, Email, Given, Family, OrgUnit string
	Suspended                         bool
	// Admin: a super administrator or the sync's admin subject (never
	// created in AD).
	Admin bool
	// ADFirst: the account carries the AD-to-Google ownership marker.
	ADFirst bool
	Fields  model.UserAttrs
}

// FromTarget converts the snapshot's accounts; adminSubject is the
// account the service account acts as.
func FromTarget(users []model.TargetUser, adminSubject string) []GoogleUser {
	out := make([]GoogleUser, 0, len(users))
	for _, u := range users {
		email := model.NormalizeEmail(u.Attrs[model.FieldPrimaryEmail])
		ou := u.Attrs[model.FieldOrgUnit]
		if ou == "" {
			ou = "/"
		}
		out = append(out, GoogleUser{ID: u.ID, Email: email, Given: strings.TrimSpace(u.Attrs[model.FieldGivenName]),
			Family: strings.TrimSpace(u.Attrs[model.FieldFamilyName]), OrgUnit: ou, Suspended: u.Suspended,
			Admin: u.Admin || (adminSubject != "" && email == model.NormalizeEmail(adminSubject)), ADFirst: u.Owner != "",
			Fields: u.Attrs.Clone()})
	}
	return out
}

// SelectionError stops a read: a selection that resolves to nothing must
// never look like everybody left. The message names the scope and the org
// unit or group, never a person.
type SelectionError struct {
	Scope string
	// Code is empty-selection, missing-org-unit or missing-group.
	Code    string
	Message string
}

func (e *SelectionError) Error() string { return fmt.Sprintf("scope %s: %s", e.Scope, e.Message) }

// Selection codes.
const (
	ErrCodeEmptySelection = "empty-selection"
	ErrCodeMissingOrgUnit = "missing-org-unit"
	ErrCodeMissingGroup   = "missing-group"
)

// ErrNoMarkerAttribute: the AD schema lacks the marker attribute.
var ErrNoMarkerAttribute = errors.New("the AD schema has no " + syncapi.G2AMarkerAttribute +
	" attribute: the Google-first mode needs it to mark the accounts it manages (no other attribute is used)")

// ScopeSelection is what one scope selects in Google.
type ScopeSelection struct {
	// Selected are the accounts the scope manages (in the domain, not
	// administrators, not AD-first), by Google ID.
	Selected map[string]bool
	// Admins passed the filters but are administrators: never created;
	// an account already linked keeps being managed (the flag changes
	// nothing in AD).
	Admins map[string]bool
	// ADFirst passed the filters but carry the AD-to-Google marker.
	ADFirst map[string]bool
}

// Selection is the Google side of a plan.
type Selection struct {
	Users  map[string]GoogleUser // by Google ID (every account read)
	Scopes map[string]*ScopeSelection
	// TwoScopes are accounts selected by more than one scope.
	TwoScopes map[string]bool
}

// Select applies each scope's filters. Every scope is evaluated (an
// account selected by two scopes is left alone by both), but selection
// errors stop only the scopes in plan (plan nil: all).
func Select(users []GoogleUser, groups []model.TargetGroup, scopes []Scope, domain string, plan map[string]bool) (*Selection, error) {
	sel := &Selection{Users: map[string]GoogleUser{}, Scopes: map[string]*ScopeSelection{}, TwoScopes: map[string]bool{}}
	for _, u := range users {
		sel.Users[u.ID] = u
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	seen := map[string]string{}
	for _, sc := range scopes {
		inPlan := plan == nil || plan[sc.Name]
		ss := &ScopeSelection{Selected: map[string]bool{}, Admins: map[string]bool{}, ADFirst: map[string]bool{}}
		sel.Scopes[sc.Name] = ss
		members, missing := gimport.MembersOf(groups, sc.MemberOf)
		if len(missing) > 0 && inPlan {
			return nil, &SelectionError{Scope: sc.Name, Code: ErrCodeMissingGroup,
				Message: "member_of names Google groups that do not exist: " + strings.Join(missing, ", ")}
		}
		perOU := map[string]int{}
		for _, u := range users {
			for _, ou := range sc.OrgUnits {
				if gimport.InOrgUnits(u.OrgUnit, []string{ou}, sc.SubOrgUnits) {
					perOU[ou]++
				}
			}
			if !gimport.InOrgUnits(u.OrgUnit, sc.OrgUnits, sc.SubOrgUnits) || (members != nil && !members[u.Email]) {
				continue
			}
			if !inDomain(u.Email, domain) {
				continue
			}
			switch {
			case u.ADFirst:
				ss.ADFirst[u.ID] = true
			case u.Admin:
				ss.Admins[u.ID] = true
			default:
				ss.Selected[u.ID] = true
			}
			if other, ok := seen[u.ID]; ok && other != sc.Name {
				sel.TwoScopes[u.ID] = true
			}
			seen[u.ID] = sc.Name
		}
		if !inPlan {
			continue
		}
		for _, ou := range sc.OrgUnits {
			if perOU[ou] == 0 {
				return nil, &SelectionError{Scope: sc.Name, Code: ErrCodeMissingOrgUnit,
					Message: fmt.Sprintf("the Google org unit %s has no account (missing or empty)", ou)}
			}
		}
		if len(ss.Selected) == 0 {
			return nil, &SelectionError{Scope: sc.Name, Code: ErrCodeEmptySelection,
				Message: "the selection resolves to no Google account (the read stops: it must never look like everybody left)"}
		}
	}
	return sel, nil
}

func inDomain(email, domain string) bool {
	at := strings.LastIndexByte(email, '@')
	return at > 0 && domain != "" && strings.EqualFold(email[at+1:], domain)
}

// ---- AD side ----

// ADUser is one AD object as the plan needs it (users below a managed OU,
// and any object that conflicts with a candidate).
type ADUser struct {
	DN, SAM, SID, GUID, UPN, CN string
	Mail                        string
	ProxyAddresses              []string
	// Marker is the raw value of the marker attribute.
	Marker string
	// Attrs are the Google-owned AD attributes (givenName, sn,
	// displayName, title, department, employeeID, telephoneNumber, mobile).
	Attrs      map[string]string
	Enabled    bool
	PwdLastSet bool // false: pwdLastSet is 0 (no password set yet)
	AdminCount bool
}

// MarkerID returns the Google ID of a Google-first marker ("" when the
// value is not one).
func MarkerID(marker string) (string, bool) {
	if !strings.HasPrefix(marker, syncapi.G2AMarkerPrefix) {
		return "", false
	}
	id := strings.TrimPrefix(marker, syncapi.G2AMarkerPrefix)
	return id, id != ""
}

// ADRequest is what the AD read needs: the managed OUs and the candidates
// of the creates (addresses, markers, logon names, common names).
type ADRequest struct {
	// ManagedOUs by scope name.
	ManagedOUs map[string]string
	Mails      []string
	Markers    []string
	SAMs       []string
	UPNs       []string
	// CNs by parent DN.
	CNs           map[string][]string
	RoleGroupSIDs []string
}

// ADState is the AD side of a plan, read through the read-only account.
type ADState struct {
	SchemaHasMarker bool
	// Managed holds every user below each scope's managed OU.
	Managed map[string][]ADUser
	// Others are objects anywhere with a candidate address (mail,
	// userPrincipalName, an SMTP proxyAddresses entry) or marker.
	Others []ADUser
	// TakenSAM and TakenUPN hold lower-case values used by any object;
	// TakenCN holds CNKey(parent, cn) of the names used in the OUs.
	TakenSAM map[string]bool
	TakenUPN map[string]bool
	TakenCN  map[string]bool
	// Privileged maps an object SID to the reasons it is privileged
	// (privilege index: nested membership of the administrative and role
	// groups, adminCount, rights on protected objects).
	Privileged map[string][]string
}

// Request computes the AD read of a selection: the managed OUs and the
// candidates of every possible create. realm is the AD DNS domain.
func Request(sel *Selection, scopes []Scope, realm string, roleGroupSIDs []string) ADRequest {
	req := ADRequest{ManagedOUs: map[string]string{}, CNs: map[string][]string{}, RoleGroupSIDs: slices.Clone(roleGroupSIDs)}
	realm = strings.ToLower(realm)
	mails, markers, sams, upns := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	cns := map[string]map[string]bool{}
	for _, sc := range scopes {
		ss := sel.Scopes[sc.Name]
		if ss == nil {
			continue
		}
		req.ManagedOUs[sc.Name] = sc.ManagedOU
		ids := keys(ss.Selected)
		for _, id := range ids {
			u := sel.Users[id]
			mails[u.Email] = true
			markers[syncapi.G2AMarker(id)] = true
			for _, c := range LogonCandidates(sc.LogonTemplate, u.Given, u.Family, u.Email) {
				sams[c] = true
				upns[c+"@"+realm] = true
				if cns[sc.ManagedOU] == nil {
					cns[sc.ManagedOU] = map[string]bool{}
				}
				cns[sc.ManagedOU][cutRunes(cn(u, c), maxCN)] = true
				cns[sc.ManagedOU][cnVariant(cn(u, c), c)] = true
			}
		}
	}
	req.Mails, req.Markers, req.SAMs, req.UPNs = keys(mails), keys(markers), keys(sams), keys(upns)
	for p, set := range cns {
		req.CNs[p] = keys(set)
	}
	return req
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// displayName is the AD displayName of a Google account.
func displayName(u GoogleUser) string { return strings.TrimSpace(u.Given + " " + u.Family) }

// cn is the preferred common name of a new account (as the import: the
// display name, else the logon name).
func cn(u GoogleUser, sam string) string {
	c := cutRunes(displayName(u), maxCN)
	if c == "" {
		c = sam
	}
	return c
}

// cnVariant is the common name used when the preferred one is taken.
func cnVariant(c, sam string) string {
	suffix := " (" + sam + ")"
	return cutRunes(c, maxCN-len([]rune(suffix))) + suffix
}

// ---- links ----

// Link is the stored association of a Google account with an AD account.
type Link struct {
	Scope, GoogleID, ObjectGUID, SID, SAM string
	// DisabledBySync: the sync disabled the account (only then may it
	// re-enable it).
	DisabledBySync bool
	// Snapshot holds the Google values last applied, by AD attribute.
	Snapshot map[string]string
}

// ---- plan ----

// Input is everything Build needs.
type Input struct {
	Now          time.Time
	GoogleDomain string
	Realm        string
	// Scopes to plan, in any order (the plan sorts them by name).
	Scopes    []Scope
	Selection *Selection
	AD        *ADState
	Links     []Link
	// PreviousSourceSize is each scope's source size at its last applied
	// plan (absent: no drop check).
	PreviousSourceSize map[string]int
}

// Google-owned attributes, in display order, with their model field and
// their length bound in AD.
type ownedAttr struct {
	attr  string
	field model.UserField
	max   int
}

var optionalAttrs = []ownedAttr{
	{"title", model.FieldTitle, 128},
	{"department", model.FieldDepartment, 64},
	{"employeeID", model.FieldEmployeeID, 16},
	{"telephoneNumber", model.FieldPhoneWork, 64},
	{"mobile", model.FieldPhoneMobile, 64},
}

// googleValues renders the AD values Google owns for an account (mail
// included).
func googleValues(u GoogleUser, fields []model.UserField) map[string]string {
	out := map[string]string{
		"givenName":   cutRunes(u.Given, 64),
		"sn":          cutRunes(u.Family, 64),
		"displayName": cutRunes(displayName(u), 256),
		"mail":        u.Email,
	}
	for _, a := range optionalAttrs {
		if slices.Contains(fields, a.field) {
			out[a.attr] = cutRunes(strings.TrimSpace(u.Fields[a.field]), a.max)
		}
	}
	return out
}

// ownedOrder is the order of the attributes in a change list.
func ownedOrder(fields []model.UserField) []string {
	out := []string{"givenName", "sn", "displayName"}
	for _, a := range optionalAttrs {
		if slices.Contains(fields, a.field) {
			out = append(out, a.attr)
		}
	}
	return out
}

// Account is an AD account the plan accounts for, with the Google values
// it holds once the plan's operations for it are applied (the link
// snapshot). It is stored with the plan, not returned by the API.
type Account struct {
	Scope    string            `json:"scope"`
	GoogleID string            `json:"google_id"`
	GUID     string            `json:"object_guid,omitempty"`
	SID      string            `json:"sid,omitempty"`
	SAM      string            `json:"sam,omitempty"`
	Snapshot map[string]string `json:"snapshot,omitempty"`
}

// Result is a built plan with its accounts.
type Result struct {
	Plan     *syncapi.G2APlan
	Accounts []Account
}

// Build computes the plan of the scopes in in.Scopes.
func Build(in Input) (*Result, error) {
	if in.AD == nil || in.Selection == nil {
		return nil, errors.New("g2a: incomplete input")
	}
	if !in.AD.SchemaHasMarker {
		return nil, ErrNoMarkerAttribute
	}
	scopes := slices.Clone(in.Scopes)
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Name < scopes[j].Name })
	links := map[string]map[string]Link{}
	for _, l := range in.Links {
		if links[l.Scope] == nil {
			links[l.Scope] = map[string]Link{}
		}
		links[l.Scope][l.GoogleID] = l
	}
	res := &Result{Plan: &syncapi.G2APlan{ReadAt: in.Now.UTC(), GoogleDomain: in.GoogleDomain, Scopes: []syncapi.G2AScopePlan{}}}
	seq := 0
	for _, sc := range scopes {
		sp, accounts := buildScope(in, sc, links[sc.Name])
		for i := range sp.Ops {
			sp.Ops[i].Seq = seq
			seq++
		}
		res.Plan.Scopes = append(res.Plan.Scopes, sp)
		res.Accounts = append(res.Accounts, accounts...)
	}
	res.Plan.Digest = Digest(res.Plan)
	return res, nil
}

// Digest is SHA-256 over the canonical JSON of the operations of every
// scope (scope names included): two plans with the same digest perform
// exactly the same changes.
func Digest(p *syncapi.G2APlan) string {
	type scopeOps struct {
		Name string          `json:"name"`
		Ops  []syncapi.G2AOp `json:"ops"`
	}
	all := make([]scopeOps, 0, len(p.Scopes))
	for _, s := range p.Scopes {
		all = append(all, scopeOps{Name: s.Name, Ops: s.Ops})
	}
	b, _ := json.Marshal(all)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// scopeBuild carries the state of one scope's plan.
type scopeBuild struct {
	in    Input
	sc    Scope
	links map[string]Link
	sp    syncapi.G2AScopePlan
	// accounts are the accounts with their Google values (link snapshots).
	accounts []Account
}

func (b *scopeBuild) account(u GoogleUser, guid, sid, sam string) {
	b.accounts = append(b.accounts, Account{Scope: b.sc.Name, GoogleID: u.ID, GUID: guid, SID: sid, SAM: sam,
		Snapshot: googleValues(u, b.sc.Fields)})
}

func (b *scopeBuild) skip(googleID string, o *ADUser, reason string, detail ...string) {
	s := syncapi.G2ASkipped{GoogleID: googleID, Reason: reason, Detail: detail}
	if o != nil {
		s.SAM, s.DN = o.SAM, o.DN
	}
	b.sp.Skipped = append(b.sp.Skipped, s)
}

func (b *scopeBuild) warn(code, key, msg string) {
	b.sp.Warnings = append(b.sp.Warnings, syncapi.Warning{Code: code, Key: key, Message: msg})
}

// maxPrivilegeDetail bounds the privilege reasons kept in a skip: a
// member of Domain Admins inherits one reason per protected object, so the
// full list can run to dozens of ACL entries. The group reasons come first
// (they explain the rest).
const maxPrivilegeDetail = 8

// privileged returns the privilege reasons of an AD object (nil when it is
// not privileged), at most maxPrivilegeDetail of them plus a count of the
// others.
func (b *scopeBuild) privileged(o ADUser) []string {
	var out []string
	if o.AdminCount {
		out = append(out, "adminCount is 1")
	}
	if o.SID != "" {
		reasons := slices.Clone(b.in.AD.Privileged[o.SID])
		sort.SliceStable(reasons, func(i, j int) bool {
			return strings.HasPrefix(reasons[i], "group:") && !strings.HasPrefix(reasons[j], "group:")
		})
		out = append(out, reasons...)
	}
	if len(out) > maxPrivilegeDetail {
		out = append(out[:maxPrivilegeDetail], fmt.Sprintf("and %d more", len(out)-maxPrivilegeDetail))
	}
	return out
}

func buildScope(in Input, sc Scope, links map[string]Link) (syncapi.G2AScopePlan, []Account) {
	b := &scopeBuild{in: in, sc: sc, links: links, sp: syncapi.G2AScopePlan{Name: sc.Name, Mode: sc.Mode, Ops: []syncapi.G2AOp{}}}
	ss := in.Selection.Scopes[sc.Name]
	if ss == nil {
		ss = &ScopeSelection{}
	}
	b.sp.SourceSize = len(ss.Selected)

	// AD objects below the managed OU, by the Google ID of their marker.
	marked := map[string][]ADUser{}
	var unmarked []ADUser
	for _, o := range in.AD.Managed[sc.Name] {
		if id, ok := MarkerID(o.Marker); ok {
			marked[id] = append(marked[id], o)
		} else {
			unmarked = append(unmarked, o)
		}
	}
	for _, objs := range marked {
		b.sp.Managed += len(objs)
	}

	// Accounts AD already holds for the scope.
	for _, id := range sortedKeys(marked) {
		b.existing(id, marked[id], ss)
	}

	// Creates: selected accounts without an AD object in the scope.
	type create struct {
		u   GoogleUser
		sam string
	}
	var creates []create
	for _, id := range keys(ss.ADFirst) {
		if _, ok := marked[id]; !ok {
			b.skip(id, nil, syncapi.G2ASkipManagedByADFirst)
		}
	}
	for _, id := range keys(ss.Selected) {
		if _, ok := marked[id]; ok {
			continue
		}
		u := in.Selection.Users[id]
		if in.Selection.TwoScopes[id] {
			b.skip(id, nil, syncapi.G2ASkipInTwoScopes)
			continue
		}
		if u.Suspended {
			continue
		}
		if reason, o, detail := b.conflict(u, unmarked); reason != "" {
			b.skip(id, o, reason, detail...)
			continue
		}
		cands := LogonCandidates(sc.LogonTemplate, u.Given, u.Family, u.Email)
		sam := ""
		for _, c := range cands {
			if !in.AD.TakenSAM[strings.ToLower(c)] && !in.AD.TakenUPN[strings.ToLower(c+"@"+in.Realm)] {
				sam = c
				break
			}
		}
		if sam == "" {
			b.skip(id, nil, syncapi.G2ASkipNoFreeLogon, "tried: "+strings.Join(cands, ", "))
			continue
		}
		creates = append(creates, create{u: u, sam: sam})
	}
	// Two accounts that map to the same logon name: neither is created
	// until one is fixed in Google.
	bySAM := map[string]int{}
	for _, c := range creates {
		bySAM[strings.ToLower(c.sam)]++
	}
	cnUsed := map[string]bool{}
	for _, c := range creates {
		if bySAM[strings.ToLower(c.sam)] > 1 {
			b.skip(c.u.ID, nil, syncapi.G2ASkipDuplicateLogon, "logon name "+c.sam)
			continue
		}
		name := cn(c.u, c.sam)
		taken := func(n string) bool { return in.AD.TakenCN[CNKey(sc.ManagedOU, n)] || cnUsed[CNKey(sc.ManagedOU, n)] }
		if taken(name) {
			name = cnVariant(name, c.sam)
			if taken(name) {
				b.skip(c.u.ID, nil, syncapi.G2ASkipNoFreeLogon, "the name and its (logon name) variant are taken in the managed OU")
				continue
			}
		}
		cnUsed[CNKey(sc.ManagedOU, name)] = true
		dn, err := escape.ChildDN("CN", name, sc.ManagedOU)
		if err != nil {
			b.skip(c.u.ID, nil, syncapi.G2ASkipNoFreeLogon, "the name cannot be a DN: "+err.Error())
			continue
		}
		vals := googleValues(c.u, sc.Fields)
		changes := []syncapi.G2AChange{
			{Field: "sAMAccountName", After: c.sam},
			{Field: "userPrincipalName", After: c.sam + "@" + in.Realm},
			{Field: "cn", After: name},
			{Field: "mail", After: vals["mail"]},
		}
		for _, a := range ownedOrder(sc.Fields) {
			if vals[a] != "" {
				changes = append(changes, syncapi.G2AChange{Field: a, After: vals[a]})
			}
		}
		b.sp.Ops = append(b.sp.Ops, syncapi.G2AOp{Kind: syncapi.G2AUserCreate, GoogleID: c.u.ID, SAM: c.sam, DN: dn,
			Reason: syncapi.G2AReasonNew, Marker: syncapi.G2AMarker(c.u.ID), Changes: changes, ParentOU: sc.ManagedOU, Invite: true})
		b.account(c.u, "", "", c.sam)
	}

	sortOps(b.sp.Ops)
	sort.SliceStable(b.sp.Skipped, func(i, j int) bool {
		x, y := b.sp.Skipped[i], b.sp.Skipped[j]
		if x.GoogleID != y.GoogleID {
			return x.GoogleID < y.GoogleID
		}
		if x.DN != y.DN {
			return x.DN < y.DN
		}
		return x.Reason < y.Reason
	})
	sort.SliceStable(b.sp.Warnings, func(i, j int) bool {
		if b.sp.Warnings[i].Key != b.sp.Warnings[j].Key {
			return b.sp.Warnings[i].Key < b.sp.Warnings[j].Key
		}
		return b.sp.Warnings[i].Code < b.sp.Warnings[j].Code
	})
	b.sp.Limits = limitRows(sc.Limits, b.sp, in.PreviousSourceSize)
	for _, r := range b.sp.Limits {
		if r.Exceeded {
			b.sp.Blocked = true
		}
	}
	sort.Slice(b.accounts, func(i, j int) bool { return b.accounts[i].GoogleID < b.accounts[j].GoogleID })
	return b.sp, b.accounts
}

// existing plans the account(s) AD holds with the marker of Google ID id.
func (b *scopeBuild) existing(id string, objs []ADUser, ss *ScopeSelection) {
	if len(objs) > 1 {
		for i := range objs {
			b.skip(id, &objs[i], syncapi.G2ASkipMarkerMismatch, fmt.Sprintf("%d AD accounts carry this marker", len(objs)))
		}
		return
	}
	o := objs[0]
	if reasons := b.privileged(o); len(reasons) > 0 {
		b.skip(id, &o, syncapi.G2ASkipPrivileged, reasons...)
		return
	}
	link, linked := b.links[id]
	if linked && link.ObjectGUID != "" && o.GUID != "" && !strings.EqualFold(link.ObjectGUID, o.GUID) {
		b.skip(id, &o, syncapi.G2ASkipMarkerMismatch, "the marker is on another AD account than the linked one")
		return
	}
	if !linked {
		b.warn("unlinked", id, "the AD account carries the marker but no link is recorded (the state database was replaced?); the link is written on the next confirmed apply")
	}
	u, inGoogle := b.in.Selection.Users[id]
	if b.in.Selection.TwoScopes[id] {
		b.skip(id, &o, syncapi.G2ASkipInTwoScopes)
		return
	}
	if inGoogle && u.ADFirst {
		b.skip(id, &o, syncapi.G2ASkipManagedByADFirst)
		return
	}
	selected := inGoogle && (ss.Selected[id] || ss.Admins[id])
	base := syncapi.G2AOp{GoogleID: id, SAM: o.SAM, DN: o.DN, SID: o.SID, ObjectGUID: o.GUID, Marker: syncapi.G2AMarker(id)}
	if selected {
		b.fields(base, u, o, link)
		b.account(u, o.GUID, o.SID, o.SAM)
	}
	inQuarantine := parentIs(o.DN, b.sc.QuarantineOU)
	switch {
	case selected && !u.Suspended:
		if o.Enabled {
			return
		}
		switch {
		case linked && link.DisabledBySync:
			op := base
			op.Kind, op.Reason, op.Enable = syncapi.G2AUserReenable, syncapi.G2AReasonActive, true
			op.Changes = []syncapi.G2AChange{{Field: "enabled", Before: "false", After: "true"}}
			if !parentIs(o.DN, b.sc.ManagedOU) {
				op.MoveTo = b.sc.ManagedOU
				op.Changes = append(op.Changes, syncapi.G2AChange{Field: "parent", Before: parentOf(o.DN), After: b.sc.ManagedOU})
			}
			b.sp.Ops = append(b.sp.Ops, op)
		case linked && !o.PwdLastSet:
			// Created by the sync, waiting for the invitation to complete:
			// the account is enabled at the end of that flow.
		default:
			b.skip(id, &o, syncapi.G2ASkipDisabledOutsideSync)
		}
	default:
		reason := syncapi.G2AReasonOutOfSelection
		switch {
		case !inGoogle:
			reason = syncapi.G2AReasonDeleted
		case u.Suspended:
			reason = syncapi.G2AReasonSuspended
		}
		if !o.Enabled && inQuarantine {
			return
		}
		op := base
		op.Kind, op.Reason, op.Disable = syncapi.G2AUserDisable, reason, o.Enabled
		if o.Enabled {
			op.Changes = append(op.Changes, syncapi.G2AChange{Field: "enabled", Before: "true", After: "false"})
		}
		if !inQuarantine {
			op.MoveTo = b.sc.QuarantineOU
			op.Changes = append(op.Changes, syncapi.G2AChange{Field: "parent", Before: parentOf(o.DN), After: b.sc.QuarantineOU})
		}
		b.sp.Ops = append(b.sp.Ops, op)
	}
}

// fields plans the update and rename of a selected account (P2: every
// Google-owned field equals Google's value after the apply).
func (b *scopeBuild) fields(base syncapi.G2AOp, u GoogleUser, o ADUser, link Link) {
	want := googleValues(u, b.sc.Fields)
	// reason of one difference: google-change when the stored snapshot
	// holds the AD value (AD still has what was last applied), else
	// ad-drift.
	drifted := func(attr, adValue string) bool {
		old, ok := link.Snapshot[attr]
		return !ok || old != adValue
	}
	var changes []syncapi.G2AChange
	drift := false
	for _, a := range ownedOrder(b.sc.Fields) {
		if o.Attrs[a] != want[a] {
			changes = append(changes, syncapi.G2AChange{Field: a, Before: o.Attrs[a], After: want[a]})
			drift = drift || drifted(a, o.Attrs[a])
		}
	}
	adMail := model.NormalizeEmail(o.Mail)
	rename := false
	if o.Mail != want["mail"] {
		switch {
		case adMail != "" && adMail != want["mail"] && !drifted("mail", o.Mail):
			// Google's primary address changed: a rename (the old address
			// stays reachable as an smtp: proxy address).
			rename = true
		default:
			changes = append(changes, syncapi.G2AChange{Field: "mail", Before: o.Mail, After: want["mail"]})
			drift = drift || drifted("mail", o.Mail)
		}
	}
	if len(changes) > 0 {
		op := base
		op.Kind, op.Changes, op.Reason = syncapi.G2AUserUpdate, changes, syncapi.G2AReasonGoogleChange
		if drift {
			op.Reason = syncapi.G2AReasonADDrift
		}
		b.sp.Ops = append(b.sp.Ops, op)
	}
	if rename {
		before := sortedProxies(o.ProxyAddresses)
		var after []string
		for _, p := range o.ProxyAddresses {
			addr := strings.ToLower(proxyAddress(p))
			if addr == adMail || addr == want["mail"] {
				continue
			}
			after = append(after, p)
		}
		after = append(after, "smtp:"+adMail)
		op := base
		op.Kind, op.Reason = syncapi.G2AUserRename, syncapi.G2AReasonPrimaryAddress
		op.Changes = []syncapi.G2AChange{
			{Field: "mail", Before: o.Mail, After: want["mail"]},
			{Field: "proxyAddresses", Before: strings.Join(before, "\n"), After: strings.Join(sortedProxies(after), "\n")},
		}
		b.sp.Ops = append(b.sp.Ops, op)
	}
}

// conflict checks a create against AD: an object with the account's
// marker outside the managed OU, an object with the address carrying
// another Google ID's marker, or any other object with the address.
func (b *scopeBuild) conflict(u GoogleUser, unmarked []ADUser) (string, *ADUser, []string) {
	marker := syncapi.G2AMarker(u.ID)
	cands := append(slices.Clone(unmarked), b.in.AD.Others...)
	sort.SliceStable(cands, func(i, j int) bool { return escape.NormalizeDN(cands[i].DN) < escape.NormalizeDN(cands[j].DN) })
	var hit *ADUser
	for i := range cands {
		o := &cands[i]
		if o.Marker == marker {
			return syncapi.G2ASkipUnmanagedExists, o, []string{"an AD object outside the managed OU carries this account's marker"}
		}
		if !hasAddress(*o, u.Email) {
			continue
		}
		if _, ok := MarkerID(o.Marker); ok {
			return syncapi.G2ASkipMarkerMismatch, o, []string{"an AD account with this address carries the marker of another Google account"}
		}
		if hit == nil {
			hit = o
		}
	}
	if hit != nil {
		return syncapi.G2ASkipUnmanagedExists, hit, []string{"an AD object already has this address"}
	}
	return "", nil, nil
}

// hasAddress reports whether an AD object has the address as mail,
// userPrincipalName or an SMTP proxy address.
func hasAddress(o ADUser, email string) bool {
	if model.NormalizeEmail(o.Mail) == email || model.NormalizeEmail(o.UPN) == email {
		return true
	}
	for _, p := range o.ProxyAddresses {
		if strings.HasPrefix(strings.ToLower(p), "smtp:") && strings.ToLower(proxyAddress(p)) == email {
			return true
		}
	}
	return false
}

func proxyAddress(p string) string {
	if i := strings.IndexByte(p, ':'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func sortedProxies(in []string) []string {
	out := slices.Clone(in)
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

func parentOf(dn string) string {
	p, _, err := escape.ParentDN(dn)
	if err != nil {
		return ""
	}
	return p
}

func parentIs(dn, parent string) bool {
	p := parentOf(dn)
	return p != "" && escape.EqualDN(p, parent)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortOps orders operations by kind (apply order), then Google ID.
func sortOps(ops []syncapi.G2AOp) {
	rank := map[string]int{}
	for i, k := range syncapi.G2AKinds {
		rank[k] = i
	}
	sort.SliceStable(ops, func(i, j int) bool {
		if rank[ops[i].Kind] != rank[ops[j].Kind] {
			return rank[ops[i].Kind] < rank[ops[j].Kind]
		}
		return ops[i].GoogleID < ops[j].GoogleID
	})
}

// Counts counts a scope's operations by kind.
func Counts(sp syncapi.G2AScopePlan) map[string]int {
	out := map[string]int{}
	for _, o := range sp.Ops {
		out[o.Kind]++
	}
	return out
}

// limitRows compares each limit with a scope's plan, like plan.Limits.
func limitRows(l Limits, sp syncapi.G2AScopePlan, previous map[string]int) []syncapi.LimitRow {
	c := Counts(sp)
	var out []syncapi.LimitRow
	count := func(name string, value, max int) {
		out = append(out, syncapi.LimitRow{Limit: name, Value: float64(value), Max: float64(max), Exceeded: max != Unlimited && value > max})
	}
	count("max_creates", c[syncapi.G2AUserCreate], l.MaxCreates)
	count("max_disables", c[syncapi.G2AUserDisable], l.MaxDisables)
	count("max_reenables", c[syncapi.G2AUserReenable], l.MaxReenables)
	count("max_updates", c[syncapi.G2AUserUpdate], l.MaxUpdates)
	count("max_renames", c[syncapi.G2AUserRename], l.MaxRenames)
	touched := map[string]bool{}
	for _, o := range sp.Ops {
		if o.Kind != syncapi.G2AUserCreate {
			touched[o.GoogleID] = true
		}
	}
	pct := 0.0
	if sp.Managed > 0 {
		pct = round1(100 * float64(len(touched)) / float64(sp.Managed))
	}
	out = append(out, syncapi.LimitRow{Limit: "max_touched_percent", Value: pct, Max: l.MaxTouchedPercent,
		Exceeded: l.MaxTouchedPercent != Unlimited && sp.Managed > 0 && pct > l.MaxTouchedPercent})
	out = append(out, syncapi.LimitRow{Limit: "min_source_size", Value: float64(sp.SourceSize), Max: float64(l.MinSourceSize),
		Exceeded: l.MinSourceSize != Unlimited && sp.SourceSize < l.MinSourceSize})
	drop := 0.0
	if prev := previous[sp.Name]; prev > 0 && sp.SourceSize < prev {
		drop = round1(100 * float64(prev-sp.SourceSize) / float64(prev))
	}
	out = append(out, syncapi.LimitRow{Limit: "max_source_drop_percent", Value: drop, Max: l.MaxSourceDropPercent,
		Exceeded: l.MaxSourceDropPercent != Unlimited && drop > l.MaxSourceDropPercent})
	return out
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
