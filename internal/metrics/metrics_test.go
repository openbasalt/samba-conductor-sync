package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sync.prom")
	now := time.Now()
	r := Run{Connector: "google", Action: "apply", Status: "blocked", Started: now.Add(-time.Second), Finished: now,
		SourceUsers: 10, Ops: map[string]int{"user.create": 3}}
	if err := Write(p, r, now); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	for _, want := range []string{`conductor_sync_blocked{connector="google"} 1`, `conductor_sync_planned_ops{connector="google",kind="user.create"} 3`,
		`conductor_sync_source_users{connector="google"} 10`, "# TYPE conductor_sync_last_success_timestamp_seconds gauge"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in\n%s", want, b)
		}
	}
	if err := Write("", r, now); err != nil {
		t.Fatal(err)
	}
}
