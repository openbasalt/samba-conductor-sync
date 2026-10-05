package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/openbasalt/samba-conductor-sync/internal/app"
	"github.com/openbasalt/samba-conductor-sync/internal/config"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// listFlag is a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// importFlags are the flags of import-plan (the filters of import.plan).
type importFlags struct {
	orgUnits, memberOf, groupEmails                 listFlag
	sub, suspended, admins, groups, skipEmptyGroups bool
	maxUsers, maxGroups                             int
}

func (f *importFlags) register(fs *flag.FlagSet) {
	fs.Var(&f.orgUnits, "org-unit", "only users in this Google org unit path (repeatable)")
	fs.BoolVar(&f.sub, "sub-org-units", false, "with --org-unit: also the org units below")
	fs.Var(&f.memberOf, "member-of", "only users that are members (nested) of this Google group address (repeatable)")
	fs.BoolVar(&f.suspended, "include-suspended", false, "include suspended accounts (left out by default)")
	fs.BoolVar(&f.admins, "include-admins", false, "include Google administrators (left out by default)")
	fs.BoolVar(&f.groups, "groups", false, "also list Google groups, with their members in the plan")
	fs.Var(&f.groupEmails, "group", "with --groups: only this group address (repeatable)")
	fs.BoolVar(&f.skipEmptyGroups, "skip-empty-groups", false, "with --groups: leave out groups without members in the plan")
	fs.IntVar(&f.maxUsers, "max-users", 0, "most users in the plan (default 500)")
	fs.IntVar(&f.maxGroups, "max-groups", 0, "most groups in the plan (default 200)")
}

func (f *importFlags) params() syncapi.ImportPlanParams {
	return syncapi.ImportPlanParams{OrgUnits: f.orgUnits, SubOrgUnits: f.sub, MemberOf: f.memberOf, IncludeSuspended: f.suspended,
		IncludeAdmins: f.admins, Groups: f.groups, GroupEmails: f.groupEmails, SkipEmptyGroups: f.skipEmptyGroups,
		MaxUsers: f.maxUsers, MaxGroups: f.maxGroups}
}

// importPlanCmd prints the import plan. It only reads Google (read-only
// scopes) and records the read in the audit log.
func importPlanCmd(ctx context.Context, rt *app.Runtime, cfg *config.Config, p syncapi.ImportPlanParams, asJSON bool, stdout, stderr io.Writer) int {
	if err := p.Validate(); err != nil {
		fmt.Fprintln(stderr, "import-plan:", err)
		return exitUsage
	}
	pl, err := rt.ImportPlan(ctx, cfg, p)
	result, detail := store.ResultInfo, app.ImportSummary(p, pl)
	if err != nil {
		result, detail = store.ResultFailed, detail+"; "+err.Error()
	}
	_, _ = rt.Store.AppendAudit(ctx, store.AuditEvent{Actor: cliActor(), Action: "import.plan", Target: "google", Detail: detail, Result: result})
	if err != nil {
		fmt.Fprintln(stderr, "import-plan:", err)
		return exitError
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(pl)
		return exitOK
	}
	printImportPlan(stdout, pl)
	return exitOK
}

func printImportPlan(w io.Writer, pl *syncapi.ImportPlan) {
	fmt.Fprintf(w, "Import plan (read-only; nothing was written): read %d users and %d groups from Google.\n", pl.UsersRead, pl.GroupsRead)
	fmt.Fprintf(w, "Users to create in AD: %d. Groups: %d.\n", len(pl.Users), len(pl.Groups))
	if len(pl.SkippedCounts) > 0 {
		reasons := make([]string, 0, len(pl.SkippedCounts))
		for r, n := range pl.SkippedCounts {
			reasons = append(reasons, fmt.Sprintf("%s %d", r, n))
		}
		sort.Strings(reasons)
		fmt.Fprintf(w, "Left out: %s.\n", strings.Join(reasons, ", "))
	}
	if len(pl.Users) > 0 {
		fmt.Fprintln(w, "\nUsers:")
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  ADDRESS\tGIVEN NAME\tFAMILY NAME\tORG UNIT\tNOTES")
		for _, u := range pl.Users {
			var notes []string
			if u.Suspended {
				notes = append(notes, "suspended")
			}
			if u.Admin {
				notes = append(notes, "administrator")
			}
			if len(u.Aliases) > 0 {
				notes = append(notes, fmt.Sprintf("%d alias(es)", len(u.Aliases)))
			}
			notes = append(notes, u.Warnings...)
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", u.Email, u.GivenName, u.FamilyName, u.OrgUnit, strings.Join(notes, ", "))
		}
		_ = tw.Flush()
	}
	if len(pl.Groups) > 0 {
		fmt.Fprintln(w, "\nGroups:")
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  ADDRESS\tNAME\tUSERS\tGROUPS\tOTHER MEMBERS\tNOTES")
		for _, g := range pl.Groups {
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\t%d\t%s\n", g.Email, g.Name, len(g.Users), len(g.Groups), g.LeftOut, strings.Join(g.Warnings, ", "))
		}
		_ = tw.Flush()
	}
	if len(pl.Skipped) > 0 {
		fmt.Fprintln(w, "\nLeft out:")
		for _, s := range pl.Skipped {
			fmt.Fprintf(w, "  %s %s: %s\n", s.Kind, s.Email, s.Reason)
		}
	}
	fmt.Fprintln(w, "\nThe AD objects are created by conductor (Google Workspace sync > Import from Google), never by conductor-sync.")
}
