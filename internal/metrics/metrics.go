// Package metrics writes conductor-sync's metrics in the Prometheus text
// format to a file (for node_exporter's textfile collector), replaced
// atomically after every run. No listener is opened.
package metrics

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Run is what one run reports.
type Run struct {
	Connector    string
	Action       string // plan | apply
	Status       string
	Started      time.Time
	Finished     time.Time
	SourceUsers  int
	SourceGroups int
	ManagedUsers int
	Ops          map[string]int // by kind
	OpsDone      int
	OpsFailed    int
	Violations   int
	Warnings     int
	Requests     int
	Retries      int
}

// Write renders r to path (no-op when path is empty).
func Write(path string, r Run, lastSuccess time.Time) error {
	if path == "" {
		return nil
	}
	var sb strings.Builder
	l := fmt.Sprintf(`connector=%q`, r.Connector)
	gauge := func(name, help string, labels string, v float64) {
		fmt.Fprintf(&sb, "# HELP %s %s\n# TYPE %s gauge\n%s{%s} %g\n", name, help, name, name, labels, v)
	}
	gauge("conductor_sync_last_run_timestamp_seconds", "End of the last run.", l+fmt.Sprintf(`,action=%q,status=%q`, r.Action, r.Status), float64(r.Finished.Unix()))
	gauge("conductor_sync_last_run_duration_seconds", "Duration of the last run.", l, r.Finished.Sub(r.Started).Seconds())
	if !lastSuccess.IsZero() {
		gauge("conductor_sync_last_success_timestamp_seconds", "End of the last run that applied or had nothing to do.", l, float64(lastSuccess.Unix()))
	}
	blocked := 0.0
	if r.Status == "blocked" {
		blocked = 1
	}
	gauge("conductor_sync_blocked", "1 when the last run stopped at the safety limits.", l, blocked)
	gauge("conductor_sync_source_users", "Users in the source scope.", l, float64(r.SourceUsers))
	gauge("conductor_sync_source_groups", "Groups in the source scope.", l, float64(r.SourceGroups))
	gauge("conductor_sync_managed_users", "Target accounts linked to the source.", l, float64(r.ManagedUsers))
	gauge("conductor_sync_ops_done", "Operations applied in the last run.", l, float64(r.OpsDone))
	gauge("conductor_sync_ops_failed", "Operations that failed in the last run.", l, float64(r.OpsFailed))
	gauge("conductor_sync_limit_violations", "Safety limits exceeded by the last plan.", l, float64(r.Violations))
	gauge("conductor_sync_warnings", "Warnings in the last plan.", l, float64(r.Warnings))
	gauge("conductor_sync_api_requests", "Target API requests in the last run.", l, float64(r.Requests))
	gauge("conductor_sync_api_retries", "Target API retries in the last run.", l, float64(r.Retries))
	kinds := make([]string, 0, len(r.Ops))
	for k := range r.Ops {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	sb.WriteString("# HELP conductor_sync_planned_ops Operations in the last plan by kind.\n# TYPE conductor_sync_planned_ops gauge\n")
	for _, k := range kinds {
		fmt.Fprintf(&sb, "conductor_sync_planned_ops{%s,kind=%q} %d\n", l, k, r.Ops[k])
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".conductor-sync-metrics-*")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(sb.String()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
