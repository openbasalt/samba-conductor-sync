package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/openbasalt/samba-conductor-sync/internal/app"
	"github.com/openbasalt/samba-conductor-sync/internal/config"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// g2aFlags are the flags of g2a-plan.
type g2aFlags struct {
	scope      string
	roleGroups listFlag
}

func (f *g2aFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.scope, "scope", "", "plan only this Google-first scope (default: every scope)")
	fs.Var(&f.roleGroups, "role-group", "SID of a group whose members are privileged, like conductor's role groups (repeatable)")
}

func (f *g2aFlags) params() syncapi.G2APlanParams {
	return syncapi.G2APlanParams{Scope: f.scope, RoleGroupSIDs: f.roleGroups}
}

// g2aPlanCmd records and prints the Google-first plan. It only reads
// Google (read-only scopes) and AD (the read-only account); the plan is
// recorded as a run of action g2a and the read is audited (g2a.plan).
func g2aPlanCmd(ctx context.Context, rt *app.Runtime, cfg *config.Config, p syncapi.G2APlanParams, asJSON bool, stdout, stderr io.Writer) int {
	if err := p.Validate(); err != nil {
		fmt.Fprintln(stderr, "g2a-plan:", err)
		return exitUsage
	}
	pl, runID, err := rt.G2APlan(ctx, cfg, p, cliActor(), "manual")
	result, detail := store.ResultInfo, app.G2APlanSummary(p, pl, runID)
	if err != nil {
		result, detail = store.ResultFailed, detail+"; "+app.G2AErrorSummary(err)
	}
	_, _ = rt.Store.AppendAudit(ctx, store.AuditEvent{Actor: cliActor(), Action: "g2a.plan", Target: "google-first", Detail: detail, Result: result})
	if err != nil {
		fmt.Fprintln(stderr, "g2a-plan:", err)
		return exitError
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(pl)
		return exitOK
	}
	printG2APlan(stdout, pl)
	return exitOK
}

func printG2APlan(w io.Writer, pl *syncapi.G2APlan) {
	fmt.Fprintf(w, "Google-first plan, run %d, digest %s (domain %s)\n", pl.RunID, pl.Digest, pl.GoogleDomain)
	for _, sc := range pl.Scopes {
		state := "within its limits"
		if sc.Blocked {
			state = "BLOCKED by its limits"
		}
		fmt.Fprintf(w, "\nScope %s (%s): %d selected in Google, %d managed in AD, %d operations, %s\n", sc.Name, sc.Mode,
			sc.SourceSize, sc.Managed, len(sc.Ops), state)
		if len(sc.Ops) > 0 {
			tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "  SEQ\tKIND\tLOGON\tREASON\tCHANGES")
			for _, o := range sc.Ops {
				var ch []string
				for _, c := range o.Changes {
					ch = append(ch, fmt.Sprintf("%s: %q -> %q", c.Field, c.Before, c.After))
				}
				fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s\n", o.Seq, o.Kind, o.SAM, o.Reason, strings.Join(ch, "; "))
			}
			_ = tw.Flush()
		}
		for _, s := range sc.Skipped {
			who := s.SAM
			if who == "" {
				who = "google:" + s.GoogleID
			}
			fmt.Fprintf(w, "  skipped %s: %s %s\n", who, s.Reason, strings.Join(s.Detail, "; "))
		}
		for _, wn := range sc.Warnings {
			fmt.Fprintf(w, "  warning %s (%s): %s\n", wn.Code, wn.Key, wn.Message)
		}
		for _, r := range sc.Limits {
			if r.Exceeded {
				fmt.Fprintf(w, "  limit %s: %g exceeds %g\n", r.Limit, r.Value, r.Max)
			}
		}
	}
	fmt.Fprintln(w, "\nconductor-sync writes nothing to AD or Google: conductor applies the plan through conductor-provisioner.")
}
