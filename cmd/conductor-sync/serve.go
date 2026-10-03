package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/openbasalt/samba-conductor-sync/internal/api"
	"github.com/openbasalt/samba-conductor-sync/internal/app"
	"github.com/openbasalt/samba-conductor-sync/internal/config"
	"github.com/openbasalt/samba-conductor-sync/internal/store"
	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// serve runs the management API (and the in-process scheduler when
// schedule.in_process is set) until SIGINT/SIGTERM.
func serve(ctx context.Context, rt *app.Runtime, cfg *config.Config, stderr io.Writer) int {
	log := slog.New(slog.NewTextHandler(stderr, nil))
	srv, err := api.New(rt, api.Options{Logger: log, Version: version})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if err := srv.Listen(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if cfg.Schedule.InProcess {
		log.Info("in-process scheduler on", "interval", cfg.Schedule.Interval.Duration.String())
		go srv.RunScheduler(ctx)
	}
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	return exitOK
}

func cliActor() string { return "cli:" + actor(false) }

// configCmd: export | import [FILE] | history.
func configCmd(ctx context.Context, rt *app.Runtime, cfg *config.Config, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: conductor-sync config export | import [FILE] | history")
		return exitUsage
	}
	switch args[0] {
	case "export":
		out, err := config.Export(cfg)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		fmt.Fprint(stdout, out)
		return exitOK
	case "import":
		// The sync settings of FILE (default: the configuration file)
		// become the newest stored version; host settings are not taken
		// from FILE.
		path := rt.File.Path
		if len(args) > 1 {
			path = args[1]
		}
		src, err := config.Load(path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		id, changes, err := rt.SaveSettings(ctx, cfg.SettingsVersion, config.SettingsOf(src), cliActor(), app.OriginCLI, "imported from "+path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		if len(changes) == 0 {
			fmt.Fprintln(stdout, "no change")
			return exitOK
		}
		var lines []string
		for _, c := range changes {
			lines = append(lines, c.String())
			fmt.Fprintln(stdout, " ", c.String())
		}
		b, _ := json.Marshal(map[string]string{"detail": "imported from " + path + "\n" + strings.Join(lines, "\n")})
		_, _ = rt.Store.AppendAudit(ctx, store.AuditEvent{Actor: cliActor(), Action: "config.update", Target: fmt.Sprintf("version %d", id),
			Detail: string(b), Result: store.ResultOK})
		fmt.Fprintf(stdout, "stored as version %d\n", id)
		return exitOK
	case "history":
		rows, err := rt.Store.ConfigHistory(ctx, 50)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		if len(rows) == 0 {
			fmt.Fprintln(stdout, "no stored version: the sync settings come from", rt.File.Path)
			return exitOK
		}
		tw := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "VERSION\tAT\tACTOR\tORIGIN\tCHANGES")
		for _, r := range rows {
			var ch []json.RawMessage
			_ = json.Unmarshal(r.Changes, &ch)
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\n", r.ID, r.At.Local().Format("2006-01-02 15:04:05"), r.Actor, r.Origin, len(ch))
		}
		_ = tw.Flush()
		return exitOK
	}
	fmt.Fprintln(stderr, "usage: conductor-sync config export | import [FILE] | history")
	return exitUsage
}

// keyCmd: set FILE | show.
func keyCmd(ctx context.Context, rt *app.Runtime, cfg *config.Config, args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 2 && args[0] == "set":
		b, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		info, err := rt.SetKey(ctx, b, cliActor())
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		d, _ := json.Marshal(map[string]string{"detail": fmt.Sprintf("client_email %s, key_id %s", info.ClientEmail, info.KeyID)})
		_, _ = rt.Store.AppendAudit(ctx, store.AuditEvent{Actor: cliActor(), Action: "key.set", Target: "google service account",
			Detail: string(d), Result: store.ResultOK})
		fmt.Fprintf(stdout, "stored (encrypted): %s, key %s. Shred the file now.\n", info.ClientEmail, info.KeyID)
		return exitOK
	case len(args) == 1 && args[0] == "show":
		info, err := rt.KeyInfo(ctx, cfg)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		if info == nil {
			fmt.Fprintln(stdout, "no key configured")
			return exitError
		}
		fmt.Fprintf(stdout, "%s, key %s, from the %s", info.ClientEmail, info.KeyID, info.Source)
		if !info.SetAt.IsZero() {
			fmt.Fprintf(stdout, " (set %s by %s)", info.SetAt.Local().Format("2006-01-02 15:04"), info.SetBy)
		}
		fmt.Fprintln(stdout)
		return exitOK
	}
	fmt.Fprintln(stderr, "usage: conductor-sync key set FILE | show")
	return exitUsage
}

// secretNames maps the CLI secret names to the API names.
var secretNames = map[string]string{
	"ad-bind-password":     syncapi.SecretADBindPassword,
	"alert-webhook-secret": syncapi.SecretWebhookSecret,
	"google-key":           syncapi.SecretGoogleKey,
}

// secretCmd: status | set NAME | remove NAME. A value is read from stdin
// (one line), never from the command line.
func secretCmd(ctx context.Context, rt *app.Runtime, cfg *config.Config, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	const use = "usage: conductor-sync secret status | set ad-bind-password|alert-webhook-secret | remove ad-bind-password|alert-webhook-secret|google-key"
	switch {
	case len(args) == 1 && args[0] == "status":
		infos, err := rt.Secrets(ctx, cfg)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		tw := tabwriter.NewWriter(stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SECRET\tSTATE\tSOURCE\tSET\tBY")
		for _, i := range infos {
			state := "not configured"
			if i.Configured {
				state = "configured"
			} else if i.Error != "" {
				state = "unreadable credential"
			}
			at := ""
			if !i.SetAt.IsZero() {
				at = i.SetAt.Local().Format("2006-01-02 15:04")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", i.Name, state, i.Source, at, i.SetBy)
		}
		_ = tw.Flush()
		return exitOK
	case len(args) == 2 && args[0] == "set":
		name := secretNames[args[1]]
		if name == "" || name == syncapi.SecretGoogleKey {
			fmt.Fprintln(stderr, use+" (the Google key: conductor-sync key set FILE)")
			return exitUsage
		}
		line, err := bufio.NewReader(io.LimitReader(stdin, 8<<10)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		value := strings.TrimRight(line, "\r\n")
		if err := rt.SetSecret(ctx, name, []byte(value), cliActor()); err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		d, _ := json.Marshal(map[string]string{"detail": "secret " + name + ": replaced"})
		_, _ = rt.Store.AppendAudit(ctx, store.AuditEvent{Actor: cliActor(), Action: "secret.set", Target: name, Detail: string(d), Result: store.ResultOK})
		fmt.Fprintf(stdout, "stored (encrypted): %s\n", name)
		return exitOK
	case len(args) == 2 && args[0] == "remove":
		name := secretNames[args[1]]
		if name == "" {
			fmt.Fprintln(stderr, use)
			return exitUsage
		}
		existed, err := rt.RemoveSecret(ctx, name)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		if !existed {
			fmt.Fprintln(stdout, "nothing stored for", name)
			return exitOK
		}
		d, _ := json.Marshal(map[string]string{"detail": "secret " + name + ": removed"})
		_, _ = rt.Store.AppendAudit(ctx, store.AuditEvent{Actor: cliActor(), Action: "secret.remove", Target: name, Detail: string(d), Result: store.ResultOK})
		fmt.Fprintf(stdout, "removed: %s (the credential file named in the configuration, if any, is used again)\n", name)
		return exitOK
	}
	fmt.Fprintln(stderr, use)
	return exitUsage
}
