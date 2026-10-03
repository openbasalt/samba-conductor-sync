// Command conductor-sync provisions users and groups from Samba AD to
// Google Workspace: plan, then apply; never delete (out of scope means
// suspended); scheduled runs stay inside safety limits.
//
//	conductor-sync plan     [--all] [--json]
//	conductor-sync apply    [--plan RUN | --digest SHA256] [--yes] [--override-limits] [--scheduled]
//	conductor-sync status
//	conductor-sync history  [--limit N] [--run RUN]
//	conductor-sync map      [--kind user|group] [KEY]
//	conductor-sync delete-user KEY [--confirm ADDRESS]
//	conductor-sync audit    verify | export
//	conductor-sync check-config
//	conductor-sync version
//
// Every command takes --config (default /etc/conductor-sync/conductor-sync.toml).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/samba-conductor/conductor-sync/internal/alert"
	"github.com/samba-conductor/conductor-sync/internal/config"
	"github.com/samba-conductor/conductor-sync/internal/connector"
	"github.com/samba-conductor/conductor-sync/internal/connector/google"
	"github.com/samba-conductor/conductor-sync/internal/engine"
	"github.com/samba-conductor/conductor-sync/internal/model"
	"github.com/samba-conductor/conductor-sync/internal/plan"
	"github.com/samba-conductor/conductor-sync/internal/secret"
	"github.com/samba-conductor/conductor-sync/internal/source"
	"github.com/samba-conductor/conductor-sync/internal/source/adsource"
	"github.com/samba-conductor/conductor-sync/internal/store"
)

var version = "dev"

// Exit codes (documented in docs/usage-p5.md).
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitBlocked     = 3
	exitPartial     = 4
	exitNotApplied  = 5
	exitDryRunApply = 6
)

const defaultConfig = "/etc/conductor-sync/conductor-sync.toml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: conductor-sync <command> [flags]

commands:
  plan           compute and record a plan (read-only on both sides)
  apply          compute a fresh plan and apply it (confirmation, limits)
  status         mode, last runs, links, unfinished operations, audit chain
  history        recent runs, or one run's plan and journal (--run)
  map            the AD object <-> target object links
  delete-user    permanently delete one suspended, sync-owned account
  audit          verify | export the hash-chained audit log
  check-config   validate the configuration and the credentials
  version
`)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(stdout, "conductor-sync", version)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfig, "configuration file")
	var (
		all, asJSON, yes, override, scheduled bool
		planRun                               int64
		digest, kind, confirm                 string
		limit                                 int
		runID                                 int64
	)
	switch cmd {
	case "plan":
		fs.BoolVar(&all, "all", false, "print every operation (default: the first 200)")
		fs.BoolVar(&asJSON, "json", false, "print the plan as JSON")
	case "apply":
		fs.Int64Var(&planRun, "plan", 0, "apply only if the fresh plan equals the plan recorded by run RUN")
		fs.StringVar(&digest, "digest", "", "apply only if the fresh plan has this digest")
		fs.BoolVar(&yes, "yes", false, "do not ask for confirmation")
		fs.BoolVar(&override, "override-limits", false, "apply a manual plan that exceeds the safety limits")
		fs.BoolVar(&scheduled, "scheduled", false, "scheduled run (the systemd timer): binding limits, no prompt")
		fs.BoolVar(&all, "all", false, "print every operation before confirming")
	case "history":
		fs.IntVar(&limit, "limit", 20, "runs to list")
		fs.Int64Var(&runID, "run", 0, "show one run: its plan and journal")
	case "map":
		fs.StringVar(&kind, "kind", "", "user or group")
	case "delete-user":
		fs.StringVar(&confirm, "confirm", "", "the account's exact address (non-interactive confirmation)")
	case "status", "audit", "check-config":
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", cmd)
		usage(stderr)
		return exitUsage
	}
	// Flags may follow positional arguments (delete-user KEY --confirm X).
	var positional []string
	for {
		if err := fs.Parse(rest); err != nil {
			return exitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	secret.FallbackDir = cfg.CredentialsDir
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cmd == "check-config" {
		return checkConfig(ctx, cfg, stdout, stderr)
	}
	if err := cfg.EnsureStateDir(); err != nil {
		fmt.Fprintln(stderr, "state directory:", err)
		return exitError
	}
	st, err := store.Open(ctx, cfg.StatePath())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	defer func() { _ = st.Close() }()

	switch cmd {
	case "status":
		return status(ctx, cfg, st, stdout, stderr)
	case "history":
		return history(ctx, cfg, st, limit, runID, stdout, stderr)
	case "map":
		key := ""
		if len(positional) > 0 {
			key = positional[0]
		}
		return mapCmd(ctx, cfg, st, kind, key, stdout, stderr)
	case "audit":
		if len(positional) != 1 {
			fmt.Fprintln(stderr, "usage: conductor-sync audit verify|export")
			return exitUsage
		}
		return auditCmd(ctx, st, positional[0], stdout, stderr)
	}

	eng, err := buildEngine(cfg, st, scheduled, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	switch cmd {
	case "plan":
		c, err := eng.Plan(ctx, "manual")
		if err != nil {
			fmt.Fprintln(stderr, "plan:", err)
			return exitError
		}
		if asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(struct {
				Run        int64            `json:"run"`
				Plan       *plan.Plan       `json:"plan"`
				Violations []plan.Violation `json:"violations"`
				Skipped    any              `json:"skipped_source_objects"`
			}{c.RunID, c.Plan, c.Violations, c.Skipped})
			return exitOK
		}
		printPlan(stdout, c, all, cfg.Mode)
		fmt.Fprintf(stdout, "\nTo apply exactly this plan: conductor-sync apply --plan %d\n", c.RunID)
		return exitOK
	case "apply":
		return apply(ctx, cfg, st, eng, applyArgs{planRun: planRun, digest: digest, yes: yes, override: override, scheduled: scheduled, all: all}, stdin, stdout, stderr)
	case "delete-user":
		if len(positional) != 1 {
			fmt.Fprintln(stderr, "usage: conductor-sync delete-user KEY [--confirm ADDRESS]")
			return exitUsage
		}
		return deleteUser(ctx, cfg, eng, positional[0], confirm, stdin, stdout, stderr)
	}
	return exitUsage
}

func actor(scheduled bool) string {
	if scheduled {
		return "timer"
	}
	name := "unknown"
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	if s := os.Getenv("SUDO_USER"); s != "" {
		name = s + " (as " + name + ")"
	}
	return name
}

func buildEngine(cfg *config.Config, st *store.Store, scheduled bool, stderr io.Writer) (*engine.Engine, error) {
	var senders alert.Multi
	senders = append(senders, alert.Log{W: stderr})
	if cfg.Alert.WebhookURL != "" {
		wh := alert.Webhook{URL: cfg.Alert.WebhookURL}
		if cfg.Alert.WebhookSecretCredential != "" {
			b, err := secret.Load(cfg.Alert.WebhookSecretCredential)
			if err != nil {
				return nil, err
			}
			wh.Secret = []byte(strings.TrimSpace(string(b)))
		}
		senders = append(senders, wh)
	}
	src := &lazySource{cfg: cfg}
	var keyCache *google.ServiceAccountKey
	connect := func(write bool) (connector.Connector, error) {
		if keyCache == nil {
			b, err := secret.Load(cfg.Google.KeyCredential)
			if err != nil {
				return nil, err
			}
			k, err := google.ParseServiceAccountKey(b)
			if err != nil {
				return nil, err
			}
			keyCache = k
		}
		return google.New(cfg.Google, keyCache, write, google.Options{})
	}
	return &engine.Engine{
		Store:         st,
		Source:        src,
		Connect:       connect,
		ConnectorName: cfg.Connector,
		Policy:        cfg.PlanPolicy(),
		Limits:        cfg.Limits,
		Mode:          cfg.Mode,
		MaxFailures:   cfg.MaxFailures,
		Alert:         senders,
		MetricsPath:   cfg.MetricsFile,
		LockPath:      cfg.LockPath(),
		Actor:         actor(scheduled),
		Host:          engine.Hostname(),
		Out:           stderr,
	}, nil
}

// lazySource loads the bind password only when the source is read.
type lazySource struct {
	cfg *config.Config
	r   *adsource.Reader
}

func (l *lazySource) Read(ctx context.Context) (*source.Result, error) {
	if l.r == nil {
		pw, err := secret.LoadString(l.cfg.Source.PasswordCredential)
		if err != nil {
			return nil, err
		}
		r, err := adsource.NewReader(l.cfg.Source, l.cfg.Rules, pw)
		if err != nil {
			return nil, err
		}
		l.r = r
	}
	return l.r.Read(ctx)
}

func checkConfig(ctx context.Context, cfg *config.Config, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "configuration: ok (mode %s, connector %s, state %s)\n", cfg.Mode, cfg.Connector, cfg.StateDir)
	failed := false
	if _, err := secret.LoadString(cfg.Source.PasswordCredential); err != nil {
		fmt.Fprintln(stderr, "AD bind password:", err)
		failed = true
	} else {
		fmt.Fprintln(stdout, "AD bind password: readable")
	}
	b, err := secret.Load(cfg.Google.KeyCredential)
	if err == nil {
		_, err = google.ParseServiceAccountKey(b)
	}
	if err != nil {
		fmt.Fprintln(stderr, "Google service account key:", err)
		failed = true
	} else {
		fmt.Fprintln(stdout, "Google service account key: valid")
	}
	if failed {
		return exitError
	}
	src := &lazySource{cfg: cfg}
	r, err := src.Read(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "AD read:", err)
		return exitError
	}
	fmt.Fprintf(stdout, "AD: %d users, %d groups in scope, %d skipped\n", len(r.Users), len(r.Groups), len(r.Skipped))
	for i, s := range r.Skipped {
		if i == 20 {
			fmt.Fprintf(stdout, "  ... %d more\n", len(r.Skipped)-20)
			break
		}
		fmt.Fprintf(stdout, "  skipped %s: %s\n", s.DN, s.Reason)
	}
	return exitOK
}

func printPlan(w io.Writer, c *engine.Computed, all bool, mode string) {
	p := c.Plan
	fmt.Fprintf(w, "Plan (run %d) for %s, digest %s\n", c.RunID, p.Connector, p.Digest)
	fmt.Fprintf(w, "Source: %d users, %d groups in scope (%d skipped). Managed on the target: %d users, %d groups.\n",
		p.SourceUsers, p.SourceGroups, len(c.Skipped), p.ManagedUsers, p.ManagedGroups)
	counts := p.Counts()
	if len(counts) == 0 {
		fmt.Fprintln(w, "No changes.")
	} else {
		kinds := make([]string, 0, len(counts))
		for k := range counts {
			kinds = append(kinds, string(k))
		}
		sort.Strings(kinds)
		fmt.Fprint(w, "Changes:")
		for _, k := range kinds {
			fmt.Fprintf(w, " %s=%d", k, counts[plan.OpKind(k)])
		}
		fmt.Fprintln(w)
	}
	max := 200
	if all {
		max = len(p.Ops)
	}
	for i, o := range p.Ops {
		if i == max {
			fmt.Fprintf(w, "  ... %d more operations (--all to list them)\n", len(p.Ops)-max)
			break
		}
		fmt.Fprintf(w, "  %s\n", o.String())
	}
	if len(p.Warnings) > 0 {
		fmt.Fprintf(w, "Warnings (%d):\n", len(p.Warnings))
		for i, x := range p.Warnings {
			if i == 50 && !all {
				fmt.Fprintf(w, "  ... %d more\n", len(p.Warnings)-50)
				break
			}
			fmt.Fprintf(w, "  [%s] %s: %s\n", x.Code, x.Key, x.Message)
		}
	}
	if len(c.Skipped) > 0 {
		fmt.Fprintf(w, "Skipped source objects (%d):\n", len(c.Skipped))
		for i, s := range c.Skipped {
			if i == 20 && !all {
				fmt.Fprintf(w, "  ... %d more\n", len(c.Skipped)-20)
				break
			}
			fmt.Fprintf(w, "  %s: %s\n", s.DN, s.Reason)
		}
	}
	if len(c.Violations) > 0 {
		fmt.Fprintln(w, "SAFETY LIMITS EXCEEDED (a scheduled run would stop here):")
		for _, v := range c.Violations {
			fmt.Fprintf(w, "  %s\n", v)
		}
	} else {
		fmt.Fprintln(w, "Within the safety limits.")
	}
	if mode != engine.ModeApply {
		fmt.Fprintln(w, "Mode is dry-run: nothing is applied until mode = \"apply\".")
	}
}

type applyArgs struct {
	planRun                       int64
	digest                        string
	yes, override, scheduled, all bool
}

func apply(ctx context.Context, cfg *config.Config, st *store.Store, eng *engine.Engine, a applyArgs, stdin io.Reader, stdout, stderr io.Writer) int {
	opt := engine.ApplyOptions{Scheduled: a.scheduled, ExpectDigest: a.digest, OverrideLimits: a.override, Yes: a.yes}
	if a.planRun != 0 {
		p, err := st.LoadPlan(ctx, a.planRun)
		if err != nil || p == nil {
			fmt.Fprintf(stderr, "no recorded plan for run %d\n", a.planRun)
			return exitError
		}
		if opt.ExpectDigest != "" && opt.ExpectDigest != p.Digest {
			fmt.Fprintln(stderr, "--plan and --digest disagree")
			return exitUsage
		}
		opt.ExpectDigest = p.Digest
	}
	if a.scheduled && (a.override || a.yes) {
		fmt.Fprintln(stderr, "--scheduled cannot be combined with --override-limits or --yes")
		return exitUsage
	}
	if !a.scheduled && !a.yes {
		in := bufio.NewReader(stdin)
		opt.Confirm = func(c *engine.Computed) bool {
			printPlan(stdout, c, a.all, cfg.Mode)
			word := "apply"
			if len(c.Violations) > 0 {
				word = "override"
			}
			fmt.Fprintf(stdout, "\n%d operations (%d target writes). Type %q to apply: ", len(c.Plan.Ops), c.Plan.Writes(), word)
			line, _ := in.ReadString('\n')
			return strings.TrimSpace(line) == word
		}
	}
	res, err := eng.Apply(ctx, opt)
	if res != nil && res.Computed != nil && (a.scheduled || a.yes) && !errors.Is(err, engine.ErrNotConfirmed) {
		// Non-interactive runs print the plan they acted on (journald).
		printPlan(stdout, res.Computed, a.all, cfg.Mode)
	}
	if res != nil {
		if res.Computed != nil {
			fmt.Fprintf(stdout, "\nRun %d: %s", res.RunID, res.Status)
		} else {
			fmt.Fprintf(stdout, "\nRun: %s", res.Status)
		}
		if res.Done+res.Failed+res.Skipped > 0 {
			fmt.Fprintf(stdout, " (%d done, %d failed, %d skipped)", res.Done, res.Failed, res.Skipped)
		}
		fmt.Fprintln(stdout)
	}
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, engine.ErrDryRun):
		fmt.Fprintln(stderr, err)
		if a.scheduled {
			return exitOK
		}
		return exitDryRunApply
	case errors.Is(err, engine.ErrBlocked), errors.Is(err, engine.ErrFirstManual):
		fmt.Fprintln(stderr, err)
		if !a.scheduled && errors.Is(err, engine.ErrBlocked) {
			fmt.Fprintln(stderr, "Review the plan; apply it by hand with --override-limits if it is intended.")
		}
		return exitBlocked
	case errors.Is(err, engine.ErrNotConfirmed), errors.Is(err, engine.ErrPlanChanged):
		fmt.Fprintln(stderr, err)
		return exitNotApplied
	case errors.Is(err, engine.ErrPartial):
		fmt.Fprintln(stderr, err)
		for _, f := range res.Failures {
			fmt.Fprintln(stderr, "  ", f)
		}
		return exitPartial
	case errors.Is(err, store.ErrLocked):
		fmt.Fprintln(stderr, err)
		return exitError
	default:
		fmt.Fprintln(stderr, "apply:", err)
		if res != nil && res.Status == store.StatusPartial {
			return exitPartial
		}
		return exitError
	}
}

func status(ctx context.Context, cfg *config.Config, st *store.Store, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "mode: %s   connector: %s   state: %s\n", cfg.Mode, cfg.Connector, cfg.StatePath())
	first, _ := st.Meta(ctx, "first_manual_apply")
	if first == "" {
		fmt.Fprintln(stdout, "first manual apply: not yet (scheduled runs stay blocked until one is done)")
	} else {
		fmt.Fprintln(stdout, "first manual apply:", first)
	}
	links, err := st.Links(ctx, cfg.Connector)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	users, groups, susp := 0, 0, 0
	for _, l := range links {
		if l.Kind == model.KindUser {
			users++
			if l.SuspendedBySync {
				susp++
			}
		} else {
			groups++
		}
	}
	fmt.Fprintf(stdout, "links: %d users (%d suspended by the sync), %d groups\n", users, susp, groups)
	runs, err := st.Runs(ctx, cfg.Connector, 5)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	fmt.Fprintln(stdout, "last runs:")
	printRuns(stdout, runs)
	inflight, _ := st.InFlight(ctx, cfg.Connector)
	if len(inflight) > 0 {
		fmt.Fprintf(stdout, "unconfirmed operations from interrupted runs: %d (the next apply resolves them)\n", len(inflight))
	}
	v, err := st.VerifyAudit(ctx)
	switch {
	case err != nil:
		fmt.Fprintln(stderr, "audit:", err)
		return exitError
	case v.BrokenAt != 0:
		fmt.Fprintf(stdout, "audit chain: BROKEN at row %d (%s)\n", v.BrokenAt, v.Reason)
		return exitError
	default:
		fmt.Fprintf(stdout, "audit chain: intact (%d rows)\n", v.Rows)
	}
	return exitOK
}

func printRuns(w io.Writer, runs []store.Run) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  RUN\tACTION\tTRIGGER\tSTARTED\tSTATUS\tOPS\tDONE\tFAILED\tACTOR\tNOTE")
	for _, r := range runs {
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", r.ID, r.Action, r.Trigger, r.StartedAt.Local().Format(time.DateTime),
			r.Status, r.OpsTotal, r.OpsDone, r.OpsFailed, r.Actor, clip(r.Error, 80))
	}
	_ = tw.Flush()
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func history(ctx context.Context, cfg *config.Config, st *store.Store, limit int, runID int64, stdout, stderr io.Writer) int {
	if runID == 0 {
		runs, err := st.Runs(ctx, cfg.Connector, limit)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		printRuns(stdout, runs)
		return exitOK
	}
	r, err := st.GetRun(ctx, runID)
	if err != nil || r == nil {
		fmt.Fprintf(stderr, "no run %d\n", runID)
		return exitError
	}
	printRuns(stdout, []store.Run{*r})
	fmt.Fprintf(stdout, "digest: %s\nsummary: %s\n", r.PlanDigest, string(r.Summary))
	journal, err := st.Journal(ctx, runID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if len(journal) > 0 {
		fmt.Fprintln(stdout, "journal:")
		for _, j := range journal {
			fmt.Fprintf(stdout, "  %4d %-10s %-15s %s %s\n", j.Seq, j.Status, j.Kind, j.Key, j.Error)
		}
	} else if p, _ := st.LoadPlan(ctx, runID); p != nil {
		fmt.Fprintln(stdout, "plan (not applied):")
		for _, o := range p.Ops {
			fmt.Fprintf(stdout, "  %s\n", o.String())
		}
	}
	return exitOK
}

func mapCmd(ctx context.Context, cfg *config.Config, st *store.Store, kind, key string, stdout, stderr io.Writer) int {
	links, err := st.Links(ctx, cfg.Connector)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	tw := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tADDRESS\tTARGET ID\tAD objectGUID\tSUSPENDED BY SYNC\tAD DN")
	n := 0
	for _, l := range links {
		if kind != "" && string(l.Kind) != kind {
			continue
		}
		if key != "" && l.SourceID != key && l.TargetID != key && l.Key != model.NormalizeEmail(key) {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", l.Kind, l.Key, l.TargetID, l.SourceID, strconv.FormatBool(l.SuspendedBySync), l.SourceDN)
		n++
	}
	_ = tw.Flush()
	if key != "" && n == 0 {
		fmt.Fprintf(stderr, "no link for %q\n", key)
		return exitError
	}
	return exitOK
}

func auditCmd(ctx context.Context, st *store.Store, sub string, stdout, stderr io.Writer) int {
	switch sub {
	case "verify":
		v, err := st.VerifyAudit(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		if v.BrokenAt != 0 {
			fmt.Fprintf(stdout, "BROKEN at row %d: %s\n", v.BrokenAt, v.Reason)
			return exitError
		}
		fmt.Fprintf(stdout, "intact: %d rows, last hash %s\n", v.Rows, v.LastHash)
		return exitOK
	case "export":
		if _, err := st.ExportAudit(ctx, stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		return exitOK
	}
	fmt.Fprintln(stderr, "usage: conductor-sync audit verify|export")
	return exitUsage
}

func deleteUser(ctx context.Context, cfg *config.Config, eng *engine.Engine, key, confirm string, stdin io.Reader, stdout, stderr io.Writer) int {
	minSusp := time.Duration(cfg.Delete.MinSuspendedDays) * 24 * time.Hour
	p, err := eng.PreviewDelete(ctx, key, minSusp)
	if p != nil {
		fmt.Fprintf(stdout, "Account: %s (target ID %s)\nAD object: %s %s\nSuspended by the sync for: %s\n",
			p.Email, p.TargetID, p.SourceID, p.SourceDN, p.SuspendedFor.Round(time.Minute))
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitNotApplied
	}
	fmt.Fprintln(stdout, "This PERMANENTLY deletes the account and its data on the target (Google keeps a deleted user restorable for about 20 days).")
	if confirm == "" {
		fmt.Fprintf(stdout, "Type the address %q to delete it: ", p.Email)
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		confirm = strings.TrimSpace(line)
	}
	if _, err := eng.DeleteUser(ctx, engine.DeleteRequest{Key: key, Confirm: confirm, MinSuspended: minSusp}); err != nil {
		fmt.Fprintln(stderr, err)
		return exitNotApplied
	}
	fmt.Fprintf(stdout, "Deleted %s.\n", p.Email)
	return exitOK
}
