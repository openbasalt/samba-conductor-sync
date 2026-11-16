package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/engine"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
)

const adoptUsage = `usage: conductor-sync adopt list
       conductor-sync adopt approve --kind user|group --source GUID --target ID [--comment TEXT]
       conductor-sync adopt revoke  --kind user|group --source GUID`

// adoptCmd lists the adoption candidates of the latest plan and the
// recorded approvals, or approves or revokes one adoption. An approval names
// one AD object and one existing target object; it is checked, audited, and
// applied by the next apply (manual or scheduled) if it still matches.
func adoptCmd(ctx context.Context, eng *engine.Engine, args []string, kind model.Kind, src, target, comment string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, adoptUsage)
		return exitUsage
	}
	switch args[0] {
	case "list":
		runID, cands, approvals, err := eng.Adoptions(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		if runID == 0 {
			fmt.Fprintln(stdout, "No recorded plan: run conductor-sync plan first.")
		} else {
			fmt.Fprintf(stdout, "Adoption candidates of plan run %d (%d):\n", runID, len(cands))
			tw := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "  KIND\tADDRESS\tSTATUS\tREASON\tAD objectGUID\tTARGET ID\tAD ACCOUNT\tAD DN")
			for _, c := range cands {
				reason := c.Reason
				if c.Detail != "" {
					reason += ": " + c.Detail
				}
				fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.Kind, c.Address, c.Status, reason, c.SourceID, c.TargetID, c.Account, c.SourceDN)
			}
			_ = tw.Flush()
		}
		fmt.Fprintf(stdout, "Approvals (%d):\n", len(approvals))
		tw := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  KIND\tADDRESS\tAD objectGUID\tTARGET ID\tAPPROVED BY\tAT\tCOMMENT")
		for _, a := range approvals {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.Kind, a.Address, a.SourceID, a.TargetID, a.By, a.At.Local().Format(time.DateTime), a.Comment)
		}
		_ = tw.Flush()
		return exitOK
	case "approve":
		if src == "" || target == "" {
			fmt.Fprintln(stderr, adoptUsage)
			return exitUsage
		}
		ap, err := eng.ApproveAdoption(ctx, engine.ApproveRequest{Kind: kind, SourceID: src, TargetID: target, Comment: comment})
		if err != nil {
			fmt.Fprintln(stderr, err)
			if errors.Is(err, engine.ErrApprovalRefused) {
				return exitNotApplied
			}
			return exitError
		}
		fmt.Fprintf(stdout, "Approved: %s %s (target %s) for AD object %s. The next apply adopts it if it still matches.\n",
			ap.Kind, ap.Address, ap.TargetID, ap.SourceID)
		return exitOK
	case "revoke":
		if src == "" {
			fmt.Fprintln(stderr, adoptUsage)
			return exitUsage
		}
		ok, err := eng.RevokeAdoption(ctx, kind, src)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		if !ok {
			fmt.Fprintf(stderr, "no approval for %s %s\n", kind, src)
			return exitError
		}
		fmt.Fprintln(stdout, "Approval removed (an object already adopted stays linked).")
		return exitOK
	}
	fmt.Fprintln(stderr, adoptUsage)
	return exitUsage
}
