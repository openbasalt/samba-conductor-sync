// Package store is conductor-sync's local state in SQLite (pure Go driver,
// CGO off, WAL, synchronous=FULL): source-to-target links, runs with their
// plans, the per-operation journal that makes an interrupted apply
// resumable, and the hash-chained audit log. No copy of the directory is
// kept beyond the link of each synced object.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store wraps the database.
type Store struct {
	db      *sql.DB
	auditMu sync.Mutex
	now     func() time.Time
}

// Open opens (creating if needed) the database and applies migrations. The
// files are made private to the process user.
func Open(ctx context.Context, p string) (*Store, error) {
	if p == "" {
		return nil, errors.New("store: empty path")
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + p + "?" + q.Encode()
	if p == ":memory:" {
		dsn = "file::memory:?" + q.Encode()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if p != ":memory:" {
		for _, f := range []string{p, p + "-wal", p + "-shm"} {
			if _, err := os.Stat(f); err == nil {
				_ = os.Chmod(f, 0o600)
			}
		}
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SetClock replaces the clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		v, err := strconv.Atoi(strings.SplitN(path.Base(name), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("store: migration %s: bad name", name)
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, v).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, v, ts(s.now())); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// ---- lock ----

// Lock is an exclusive run lock (flock on a file next to the database):
// a scheduled run and a manual one never overlap.
type Lock struct{ f *os.File }

// ErrLocked means another run holds the lock.
var ErrLocked = errors.New("another conductor-sync run is in progress")

// AcquireLock takes the lock without waiting.
func AcquireLock(p string) (*Lock, error) {
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	return &Lock{f: f}, nil
}

// Release drops the lock.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}

// ---- meta ----

// Meta reads a value ("" when absent).
func (s *Store) Meta(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetMeta writes a value.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// ---- links ----

// LinkRow is a stored link with its bookkeeping.
type LinkRow struct {
	plan.Link
	Connector string
	SourceDN  string
	// SuspendedAt is when the sync suspended the target object (zero when
	// it is not suspended by the sync).
	SuspendedAt time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Links returns every link of a connector.
func (s *Store) Links(ctx context.Context, connector string) ([]LinkRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT connector, kind, source_id, target_id, key, source_dn, suspended_by_sync, suspended_at, adopted, created_at, updated_at
		FROM links WHERE connector = ? ORDER BY kind, key`, connector)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []LinkRow
	for rows.Next() {
		var l LinkRow
		var kind, suspAt, created, updated string
		var susp, adopted int
		if err := rows.Scan(&l.Connector, &kind, &l.SourceID, &l.TargetID, &l.Key, &l.SourceDN, &susp, &suspAt, &adopted, &created, &updated); err != nil {
			return nil, err
		}
		l.Kind = model.Kind(kind)
		l.SuspendedBySync = susp != 0
		l.Adopted = adopted != 0
		if suspAt != "" {
			l.SuspendedAt = parseTS(suspAt)
		}
		l.CreatedAt, l.UpdatedAt = parseTS(created), parseTS(updated)
		out = append(out, l)
	}
	return out, rows.Err()
}

// PutLink inserts or updates a link (by source). A link to the same target
// held by another source is replaced: the target object has one owner.
func (s *Store) PutLink(ctx context.Context, connector string, l plan.Link, sourceDN string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := ts(s.now())
	if _, err := tx.ExecContext(ctx, `DELETE FROM links WHERE connector = ? AND kind = ? AND target_id = ? AND source_id <> ?`,
		connector, string(l.Kind), l.TargetID, l.SourceID); err != nil {
		return err
	}
	suspAt := ""
	if l.SuspendedBySync {
		suspAt = now
	}
	// adopted is sticky for the same target: once adopted, an update that
	// does not repeat the flag never turns the account into a created one.
	if _, err := tx.ExecContext(ctx, `INSERT INTO links(connector, kind, source_id, target_id, key, source_dn, suspended_by_sync, suspended_at, adopted, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(connector, kind, source_id) DO UPDATE SET target_id = excluded.target_id, key = excluded.key,
			source_dn = CASE WHEN excluded.source_dn <> '' THEN excluded.source_dn ELSE links.source_dn END,
			suspended_at = CASE WHEN excluded.suspended_by_sync = 0 THEN ''
				WHEN links.suspended_by_sync = 1 AND links.target_id = excluded.target_id THEN links.suspended_at
				ELSE excluded.suspended_at END,
			adopted = CASE WHEN links.target_id = excluded.target_id THEN MAX(links.adopted, excluded.adopted) ELSE excluded.adopted END,
			suspended_by_sync = excluded.suspended_by_sync, updated_at = excluded.updated_at`,
		connector, string(l.Kind), l.SourceID, l.TargetID, model.NormalizeEmail(l.Key), sourceDN, boolInt(l.SuspendedBySync), suspAt, boolInt(l.Adopted), now, now); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteLink forgets a link (the target object is gone).
func (s *Store) DeleteLink(ctx context.Context, connector string, kind model.Kind, sourceID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM links WHERE connector = ? AND kind = ? AND source_id = ?`, connector, string(kind), sourceID)
	return err
}

// RefreshSourceDNs records the current DN of linked source objects
// (display only; links are keyed by objectGUID).
func (s *Store) RefreshSourceDNs(ctx context.Context, connector string, dns map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `UPDATE links SET source_dn = ? WHERE connector = ? AND source_id = ? AND source_dn <> ?`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()
	for id, dn := range dns {
		if _, err := stmt.ExecContext(ctx, dn, connector, id, dn); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FindLink looks a link up by source ID, target ID or address.
func (s *Store) FindLink(ctx context.Context, connector, key string) (*LinkRow, error) {
	links, err := s.Links(ctx, connector)
	if err != nil {
		return nil, err
	}
	k := model.NormalizeEmail(key)
	for i := range links {
		l := &links[i]
		if l.SourceID == key || l.TargetID == key || l.Key == k {
			return l, nil
		}
	}
	return nil, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- runs ----

// Run statuses.
const (
	StatusRunning     = "running"
	StatusPlanned     = "planned"
	StatusApplied     = "applied"
	StatusPartial     = "partial"
	StatusBlocked     = "blocked"
	StatusFailed      = "failed"
	StatusInterrupted = "interrupted"
	StatusDryRun      = "dry-run"
	StatusNothing     = "nothing-to-do"
)

// Run is one stored run.
type Run struct {
	ID           int64
	Connector    string
	Action       string
	Trigger      string
	Actor        string
	StartedAt    time.Time
	FinishedAt   time.Time
	Status       string
	PlanDigest   string
	SourceUsers  int
	SourceGroups int
	OpsTotal     int
	OpsDone      int
	OpsFailed    int
	Summary      json.RawMessage
	Error        string
}

// StartRun records a new run in status running.
func (s *Store) StartRun(ctx context.Context, connector, action, trigger, actor string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO runs(connector, action, trigger, actor, started_at, status) VALUES (?, ?, ?, ?, ?, ?)`,
		connector, action, trigger, actor, ts(s.now()), StatusRunning)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// MarkInterrupted turns runs left "running" (a crash; the caller holds the
// lock, so none is really running) into "interrupted" and returns them.
func (s *Store) MarkInterrupted(ctx context.Context, connector string) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM runs WHERE connector = ? AND status = ?`, connector, StatusRunning)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	for _, id := range ids {
		// The journal tells how far it got.
		if _, err := s.db.ExecContext(ctx, `UPDATE runs SET status = ?, finished_at = ?, error = 'process ended before the run finished',
			ops_done = (SELECT COUNT(*) FROM ops WHERE run_id = runs.id AND status = 'done'),
			ops_failed = (SELECT COUNT(*) FROM ops WHERE run_id = runs.id AND status = 'failed') WHERE id = ?`,
			StatusInterrupted, ts(s.now()), id); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// RunResult is what FinishRun records.
type RunResult struct {
	Status       string
	PlanDigest   string
	SourceUsers  int
	SourceGroups int
	OpsTotal     int
	OpsDone      int
	OpsFailed    int
	Summary      any
	Error        string
}

// FinishRun records the outcome.
func (s *Store) FinishRun(ctx context.Context, id int64, r RunResult) error {
	sum, err := json.Marshal(r.Summary)
	if err != nil || r.Summary == nil {
		sum = []byte("{}")
	}
	_, err = s.db.ExecContext(ctx, `UPDATE runs SET finished_at = ?, status = ?, plan_digest = ?, source_users = ?, source_groups = ?,
		ops_total = ?, ops_done = ?, ops_failed = ?, summary = ?, error = ? WHERE id = ?`,
		ts(s.now()), r.Status, r.PlanDigest, r.SourceUsers, r.SourceGroups, r.OpsTotal, r.OpsDone, r.OpsFailed, string(sum), clip(r.Error, 4096), id)
	return err
}

const runCols = `id, connector, action, trigger, actor, started_at, finished_at, status, plan_digest, source_users, source_groups, ops_total, ops_done, ops_failed, summary, error`

func scanRun(sc interface{ Scan(...any) error }) (Run, error) {
	var r Run
	var started, finished, summary string
	err := sc.Scan(&r.ID, &r.Connector, &r.Action, &r.Trigger, &r.Actor, &started, &finished, &r.Status, &r.PlanDigest,
		&r.SourceUsers, &r.SourceGroups, &r.OpsTotal, &r.OpsDone, &r.OpsFailed, &summary, &r.Error)
	r.StartedAt, r.FinishedAt = parseTS(started), parseTS(finished)
	r.Summary = json.RawMessage(summary)
	return r, err
}

// Runs returns the newest runs first.
func (s *Store) Runs(ctx context.Context, connector string, limit int) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+runCols+` FROM runs WHERE connector = ? ORDER BY id DESC LIMIT ?`, connector, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRun returns one run (nil when absent).
func (s *Store) GetRun(ctx context.Context, id int64) (*Run, error) {
	r, err := scanRun(s.db.QueryRowContext(ctx, `SELECT `+runCols+` FROM runs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// LastRunWithStatus returns the newest run of an action with one of the
// statuses (nil when none).
func (s *Store) LastRunWithStatus(ctx context.Context, connector, action string, statuses ...string) (*Run, error) {
	if len(statuses) == 0 {
		return nil, errors.New("store: no status")
	}
	q := `SELECT ` + runCols + ` FROM runs WHERE connector = ? AND action = ? AND status IN (?` + strings.Repeat(",?", len(statuses)-1) + `) ORDER BY id DESC LIMIT 1`
	args := []any{connector, action}
	for _, st := range statuses {
		args = append(args, st)
	}
	r, err := scanRun(s.db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// SavePlan stores the plan of a run.
func (s *Store) SavePlan(ctx context.Context, runID int64, p *plan.Plan) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO plans(run_id, plan_json) VALUES (?, ?) ON CONFLICT(run_id) DO UPDATE SET plan_json = excluded.plan_json`, runID, string(b))
	return err
}

// LoadPlan returns the stored plan of a run (nil when absent).
func (s *Store) LoadPlan(ctx context.Context, runID int64) (*plan.Plan, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT plan_json FROM plans WHERE run_id = ?`, runID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p plan.Plan
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ---- operation journal ----

// Op statuses.
const (
	OpPending    = "pending"
	OpStarted    = "started"
	OpDone       = "done"
	OpFailed     = "failed"
	OpSkipped    = "skipped"
	OpSuperseded = "superseded"
)

// JournalOps records the operations of a run as pending.
func (s *Store) JournalOps(ctx context.Context, runID int64, ops []plan.Op) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := ts(s.now())
	for i, o := range ops {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ops(run_id, seq, kind, key, source_id, target_id, status, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			runID, i, string(o.Kind), o.Key, o.SourceID, o.TargetID, OpPending, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE runs SET ops_total = ? WHERE id = ?`, len(ops), runID); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkOp updates one journal entry.
func (s *Store) MarkOp(ctx context.Context, runID int64, seq int, status, targetID, errText string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE ops SET status = ?, target_id = CASE WHEN ? <> '' THEN ? ELSE target_id END, error = ?, updated_at = ? WHERE run_id = ? AND seq = ?`,
		status, targetID, targetID, clip(errText, 2048), ts(s.now()), runID, seq)
	return err
}

// JournalEntry is one journal row.
type JournalEntry struct {
	RunID    int64
	Seq      int
	Kind     plan.OpKind
	Key      string
	SourceID string
	TargetID string
	Status   string
	Error    string
}

// InFlight returns operations that were started but never confirmed (the
// process ended in between): their effect on the target is unknown.
func (s *Store) InFlight(ctx context.Context, connector string) ([]JournalEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT o.run_id, o.seq, o.kind, o.key, o.source_id, o.target_id, o.status, o.error
		FROM ops o JOIN runs r ON r.id = o.run_id WHERE r.connector = ? AND o.status = ? ORDER BY o.run_id, o.seq`, connector, OpStarted)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []JournalEntry
	for rows.Next() {
		var e JournalEntry
		var kind string
		if err := rows.Scan(&e.RunID, &e.Seq, &kind, &e.Key, &e.SourceID, &e.TargetID, &e.Status, &e.Error); err != nil {
			return nil, err
		}
		e.Kind = plan.OpKind(kind)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Supersede marks unconfirmed operations of earlier runs as handled by a
// later run (its plan accounted for their unknown outcome).
func (s *Store) Supersede(ctx context.Context, connector string, beforeRun int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE ops SET status = ?, updated_at = ? WHERE status = ? AND run_id < ?
		AND run_id IN (SELECT id FROM runs WHERE connector = ?)`, OpSuperseded, ts(s.now()), OpStarted, beforeRun, connector)
	return err
}

// Journal returns the journal of one run.
func (s *Store) Journal(ctx context.Context, runID int64) ([]JournalEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT run_id, seq, kind, key, source_id, target_id, status, error FROM ops WHERE run_id = ? ORDER BY seq`, runID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []JournalEntry
	for rows.Next() {
		var e JournalEntry
		var kind string
		if err := rows.Scan(&e.RunID, &e.Seq, &kind, &e.Key, &e.SourceID, &e.TargetID, &e.Status, &e.Error); err != nil {
			return nil, err
		}
		e.Kind = plan.OpKind(kind)
		out = append(out, e)
	}
	return out, rows.Err()
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
