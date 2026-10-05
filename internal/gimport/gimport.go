// Package gimport builds the plan of a one-time import from Google
// Workspace into AD: the Google accounts (and, optionally, groups) an
// administrator may create in AD before the AD -> Google sync starts.
//
// conductor-sync only reads: the plan is computed from a snapshot taken
// with the read-only Directory API scopes, and nothing is written to Google
// or to AD. The AD objects are created by conductor, which holds the AD
// write rights, checks conflicts and audits every creation. Passwords are
// never part of the plan (Google does not return them).
package gimport

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/connector"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// Default bounds of a plan when the request leaves them at 0.
const (
	DefaultMaxUsers  = 500
	DefaultMaxGroups = 200
)

// ErrGroupNotFound: a group named by a filter does not exist in Google.
var ErrGroupNotFound = errors.New("no such Google group")

// Options are the request plus what the plan needs from the configuration.
type Options struct {
	syncapi.ImportPlanParams
	// AllowedDomains and GroupAllowedDomains are the sync's: an address
	// outside them is reported (the sync would not adopt it).
	AllowedDomains      []string
	GroupAllowedDomains []string
	Now                 time.Time
}

// NeedsGroups reports whether the plan needs the groups of the snapshot
// (groups requested, or a group membership filter).
func NeedsGroups(p syncapi.ImportPlanParams) bool { return p.Groups || len(p.MemberOf) > 0 }

// Build computes the plan from a snapshot of the Google directory (with
// groups when NeedsGroups). A group named by a filter that does not exist
// is an error: a filter must never silently select nobody or everybody.
func Build(snap *connector.Snapshot, opt Options) (*syncapi.ImportPlan, error) {
	maxUsers, maxGroups := opt.MaxUsers, opt.MaxGroups
	if maxUsers == 0 {
		maxUsers = DefaultMaxUsers
	}
	if maxGroups == 0 {
		maxGroups = DefaultMaxGroups
	}
	groupDomains := opt.GroupAllowedDomains
	if len(groupDomains) == 0 {
		groupDomains = opt.AllowedDomains
	}
	out := &syncapi.ImportPlan{ReadAt: opt.Now.UTC(), AllowedDomains: nonNil(opt.AllowedDomains), GroupAllowedDomains: nonNil(groupDomains),
		Users: []syncapi.ImportUser{}, Groups: []syncapi.ImportGroup{}, SkippedCounts: map[string]int{},
		UsersRead: len(snap.Users), GroupsRead: len(snap.Groups)}
	skip := func(kind, email, reason string) {
		out.SkippedCounts[reason]++
		if reason != syncapi.ImportSkipFiltered && len(out.Skipped) < syncapi.MaxImportSkipped {
			out.Skipped = append(out.Skipped, syncapi.ImportSkip{Kind: kind, Email: email, Reason: reason})
		}
	}

	groups := map[string]*model.TargetGroup{}
	for i := range snap.Groups {
		g := &snap.Groups[i]
		groups[model.NormalizeEmail(g.Email)] = g
	}
	if err := requireGroups(groups, opt.MemberOf, "member_of"); err != nil {
		return nil, err
	}
	if err := requireGroups(groups, opt.GroupEmails, "group_emails"); err != nil {
		return nil, err
	}

	// Users that pass the org unit and group filters.
	ouCount := map[string]int{}
	members := transitiveUsers(groups, opt.MemberOf)
	var candidates []model.TargetUser
	for _, u := range snap.Users {
		ou := orgUnitOf(u)
		ouCount[ou]++
		email := u.Attrs[model.FieldPrimaryEmail]
		if !inOrgUnits(ou, opt.OrgUnits, opt.SubOrgUnits) || (members != nil && !members[email]) {
			skip("user", email, syncapi.ImportSkipFiltered)
			continue
		}
		candidates = append(candidates, u)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Attrs[model.FieldPrimaryEmail] < candidates[j].Attrs[model.FieldPrimaryEmail]
	})
	inPlan := map[string]bool{}
	for _, u := range candidates {
		email := u.Attrs[model.FieldPrimaryEmail]
		switch {
		case u.Owner != "":
			skip("user", email, syncapi.ImportSkipManaged)
			continue
		case u.Suspended && !opt.IncludeSuspended:
			skip("user", email, syncapi.ImportSkipSuspended)
			continue
		case u.Protected && !opt.IncludeAdmins:
			skip("user", email, syncapi.ImportSkipAdmin)
			continue
		case len(out.Users) >= maxUsers:
			skip("user", email, syncapi.ImportSkipLimit)
			continue
		}
		iu := syncapi.ImportUser{Email: email, GivenName: u.Attrs[model.FieldGivenName], FamilyName: u.Attrs[model.FieldFamilyName],
			OrgUnit: orgUnitOf(u), Suspended: u.Suspended, Admin: u.Protected, Aliases: lowerAll(u.Aliases),
			Title: u.Attrs[model.FieldTitle], Department: u.Attrs[model.FieldDepartment], EmployeeID: u.Attrs[model.FieldEmployeeID],
			PhoneWork: u.Attrs[model.FieldPhoneWork], PhoneMobile: u.Attrs[model.FieldPhoneMobile]}
		if !inDomains(email, opt.AllowedDomains) {
			iu.Warnings = append(iu.Warnings, syncapi.ImportWarnDomain)
		}
		inPlan[email] = true
		out.Users = append(out.Users, iu)
	}
	for path, n := range ouCount {
		out.OrgUnits = append(out.OrgUnits, syncapi.ImportOrgUnit{Path: path, Users: n})
	}
	sort.Slice(out.OrgUnits, func(i, j int) bool { return out.OrgUnits[i].Path < out.OrgUnits[j].Path })

	// Groups: every group (or the ones named), members limited to the plan.
	if NeedsGroups(opt.ImportPlanParams) {
		refs := make([]syncapi.ImportGroupRef, 0, len(snap.Groups))
		for _, g := range snap.Groups {
			refs = append(refs, syncapi.ImportGroupRef{Email: model.NormalizeEmail(g.Email), Name: g.Name, Members: len(g.Members)})
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].Email < refs[j].Email })
		if len(refs) > syncapi.MaxImportGroupRefs {
			refs = refs[:syncapi.MaxImportGroupRefs]
		}
		out.AllGroups = refs
	}
	if opt.Groups {
		buildGroups(out, groups, opt, inPlan, maxGroups, groupDomains, skip)
	}
	if len(out.SkippedCounts) == 0 {
		out.SkippedCounts = nil
	}
	return out, nil
}

// buildGroups adds the selected groups to the plan.
func buildGroups(out *syncapi.ImportPlan, groups map[string]*model.TargetGroup, opt Options, users map[string]bool, maxGroups int,
	domains []string, skip func(kind, email, reason string)) {
	var emails []string
	if len(opt.GroupEmails) > 0 {
		seen := map[string]bool{}
		for _, e := range opt.GroupEmails {
			if e = model.NormalizeEmail(e); !seen[e] {
				seen[e] = true
				emails = append(emails, e)
			}
		}
	} else {
		for e := range groups {
			emails = append(emails, e)
		}
	}
	sort.Strings(emails)
	// Which groups are in the plan decides the nested members, so the
	// selection is made first.
	selected := map[string]bool{}
	var order []string
	for _, e := range emails {
		g := groups[e]
		if opt.SkipEmptyGroups && !hasPlanMember(g, groups, users, map[string]bool{}) {
			skip("group", e, syncapi.ImportSkipEmpty)
			continue
		}
		if len(order) >= maxGroups {
			skip("group", e, syncapi.ImportSkipLimit)
			continue
		}
		selected[e] = true
		order = append(order, e)
	}
	for _, e := range order {
		g := groups[e]
		ig := syncapi.ImportGroup{Email: e, Name: g.Name, Description: g.Description, Aliases: lowerAll(g.Aliases)}
		for _, m := range g.Members {
			addr := model.NormalizeEmail(m.Email)
			switch {
			case m.Kind == model.KindUser && users[addr]:
				ig.Users = append(ig.Users, addr)
			case m.Kind == model.KindGroup && selected[addr] && addr != e:
				ig.Groups = append(ig.Groups, addr)
			default:
				ig.LeftOut++
			}
		}
		sort.Strings(ig.Users)
		sort.Strings(ig.Groups)
		if !inDomains(e, domains) {
			ig.Warnings = append(ig.Warnings, syncapi.ImportWarnDomain)
		}
		out.Groups = append(out.Groups, ig)
	}
}

// hasPlanMember reports whether a group has, directly or through nested
// groups, a user member that is in the plan.
func hasPlanMember(g *model.TargetGroup, groups map[string]*model.TargetGroup, users map[string]bool, seen map[string]bool) bool {
	if g == nil || seen[g.Email] {
		return false
	}
	seen[g.Email] = true
	for _, m := range g.Members {
		addr := model.NormalizeEmail(m.Email)
		if m.Kind == model.KindUser && users[addr] {
			return true
		}
		if m.Kind == model.KindGroup && hasPlanMember(groups[addr], groups, users, seen) {
			return true
		}
	}
	return false
}

// transitiveUsers returns the user addresses that are members of any of
// the groups, nested membership included (nil when there is no filter).
func transitiveUsers(groups map[string]*model.TargetGroup, roots []string) map[string]bool {
	if len(roots) == 0 {
		return nil
	}
	out := map[string]bool{}
	seen := map[string]bool{}
	var walk func(email string)
	walk = func(email string) {
		if seen[email] {
			return
		}
		seen[email] = true
		g := groups[email]
		if g == nil {
			return
		}
		for _, m := range g.Members {
			addr := model.NormalizeEmail(m.Email)
			switch m.Kind {
			case model.KindUser:
				out[addr] = true
			case model.KindGroup:
				walk(addr)
			}
		}
	}
	for _, r := range roots {
		walk(model.NormalizeEmail(r))
	}
	return out
}

func requireGroups(groups map[string]*model.TargetGroup, emails []string, field string) error {
	var missing []string
	for _, e := range emails {
		if groups[model.NormalizeEmail(e)] == nil {
			missing = append(missing, e)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w (%s): %s", ErrGroupNotFound, field, strings.Join(missing, ", "))
	}
	return nil
}

func orgUnitOf(u model.TargetUser) string {
	if ou := u.Attrs[model.FieldOrgUnit]; ou != "" {
		return ou
	}
	return "/"
}

// inOrgUnits reports whether an org unit path is selected: equal to one of
// the filters, or below one with sub. No filter selects everything.
func inOrgUnits(ou string, filters []string, sub bool) bool {
	if len(filters) == 0 {
		return true
	}
	lou := strings.ToLower(ou)
	for _, f := range filters {
		lf := strings.ToLower(strings.TrimRight(f, "/"))
		if lf == "" {
			// The root org unit: itself, or everything with sub.
			if sub || lou == "/" {
				return true
			}
			continue
		}
		if lou == lf || (sub && strings.HasPrefix(lou, lf+"/")) {
			return true
		}
	}
	return false
}

func inDomains(email string, domains []string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	d := strings.ToLower(email[at+1:])
	for _, x := range domains {
		if strings.ToLower(x) == d {
			return true
		}
	}
	return false
}

func lowerAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, model.NormalizeEmail(s))
	}
	sort.Strings(out)
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
