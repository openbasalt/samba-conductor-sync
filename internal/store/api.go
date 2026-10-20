package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ---- configuration versions ----

// ConfigVersion is one stored version of the sync settings.
type ConfigVersion struct {
	ID       int64
	At       time.Time
	Actor    string
	Origin   string
	Comment  string
	Settings json.RawMessage
	Changes  json.RawMessage
	SHA256   string
}

// ErrStaleVersion is returned when a configuration update was based on a
// version that is no longer the newest.
var ErrStaleVersion = errors.New("store: the configuration changed since it was read")

const cfgCols = `id, created_at, actor, origin, comment, settings_json, changes_json, sha256`

func scanConfig(sc interface{ Scan(...any) error }) (ConfigVersion, error) {
	var v ConfigVersion
	var at, settings, changes string
	err := sc.Scan(&v.ID, &at, &v.Actor, &v.Origin, &v.Comment, &settings, &changes, &v.SHA256)
	v.At, v.Settings, v.Changes = parseTS(at), json.RawMessage(settings), json.RawMessage(changes)
	return v, err
}

// LatestConfig returns the newest stored version (nil when none).
func (s *Store) LatestConfig(ctx context.Context) (*ConfigVersion, error) {
	v, err := scanConfig(s.db.QueryRowContext(ctx, `SELECT `+cfgCols+` FROM config_versions ORDER BY id DESC LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// SaveConfig stores a new version. base must be the newest version's ID
// (0 when none is stored): a concurrent edit makes it ErrStaleVersion.
// Secrets given are stored (replaced) in the same transaction.
func (s *Store) SaveConfig(ctx context.Context, base int64, actor, origin, comment string, settings, changes []byte, secrets ...SecretRow) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var latest int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM config_versions`).Scan(&latest); err != nil {
		return 0, err
	}
	if latest != base {
		return 0, ErrStaleVersion
	}
	sum := sha256.Sum256(settings)
	if changes == nil {
		changes = []byte("[]")
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO config_versions(created_at, actor, origin, comment, settings_json, changes_json, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ts(s.now()), clip(actor, 256), origin, clip(comment, 500), string(settings), string(changes), hex.EncodeToString(sum[:]))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, r := range secrets {
		if err := putSecret(ctx, tx, r, s.now()); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

// GetConfig returns one stored version (nil when absent).
func (s *Store) GetConfig(ctx context.Context, id int64) (*ConfigVersion, error) {
	v, err := scanConfig(s.db.QueryRowContext(ctx, `SELECT `+cfgCols+` FROM config_versions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// ConfigHistory returns the newest versions first.
func (s *Store) ConfigHistory(ctx context.Context, limit int) ([]ConfigVersion, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+cfgCols+` FROM config_versions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ConfigVersion
	for rows.Next() {
		v, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- encrypted secrets ----

// SecretRow is a stored secret: ciphertext and non-secret metadata.
type SecretRow struct {
	Name       string
	Nonce      []byte
	Ciphertext []byte
	Meta       json.RawMessage
	UpdatedAt  time.Time
	Actor      string
}

// PutSecret stores (or replaces) an encrypted secret.
func (s *Store) PutSecret(ctx context.Context, r SecretRow) error {
	return putSecret(ctx, s.db, r, s.now())
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func putSecret(ctx context.Context, db execer, r SecretRow, now time.Time) error {
	meta := string(r.Meta)
	if meta == "" {
		meta = "{}"
	}
	_, err := db.ExecContext(ctx, `INSERT INTO secrets(name, nonce, ciphertext, meta_json, updated_at, actor) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET nonce = excluded.nonce, ciphertext = excluded.ciphertext, meta_json = excluded.meta_json,
			updated_at = excluded.updated_at, actor = excluded.actor`,
		r.Name, r.Nonce, r.Ciphertext, meta, ts(now), clip(r.Actor, 256))
	return err
}

// DeleteSecret removes a stored secret; it reports whether one existed.
func (s *Store) DeleteSecret(ctx context.Context, name string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE name = ?`, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// GetSecret returns a stored secret (nil when absent).
func (s *Store) GetSecret(ctx context.Context, name string) (*SecretRow, error) {
	var r SecretRow
	var meta, at string
	err := s.db.QueryRowContext(ctx, `SELECT name, nonce, ciphertext, meta_json, updated_at, actor FROM secrets WHERE name = ?`, name).
		Scan(&r.Name, &r.Nonce, &r.Ciphertext, &meta, &at, &r.Actor)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Meta, r.UpdatedAt = json.RawMessage(meta), parseTS(at)
	return &r, nil
}

// ---- run queries for the API ----

// ListRuns returns a page of runs (newest first), optionally of one
// status, and the total count of the selection.
func (s *Store) ListRuns(ctx context.Context, connector, status string, offset, limit int) ([]Run, int, error) {
	where, args := `connector = ?`, []any{connector}
	if status != "" {
		where += ` AND status = ?`
		args = append(args, status)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+runCols+` FROM runs WHERE `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// BlockedSince returns blocked runs with an ID above after, newest first.
func (s *Store) BlockedSince(ctx context.Context, connector string, after int64) ([]Run, error) {
	// Google-first runs are reported with their own plan, not as blocked
	// AD to Google runs.
	rows, err := s.db.QueryContext(ctx, `SELECT `+runCols+` FROM runs WHERE connector = ? AND status = ? AND id > ? AND action <> ? ORDER BY id DESC LIMIT 20`,
		connector, StatusBlocked, after, RunActionG2A)
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

// LastRun returns the newest run of an action ("" = any AD to Google run:
// Google-first runs only when asked by their action) and trigger ("" =
// any), or nil.
func (s *Store) LastRun(ctx context.Context, connector, action, trigger string) (*Run, error) {
	where, args := `connector = ?`, []any{connector}
	if action != "" {
		where += ` AND action = ?`
		args = append(args, action)
	} else {
		where += ` AND action <> ?`
		args = append(args, RunActionG2A)
	}
	if trigger != "" {
		where += ` AND trigger = ?`
		args = append(args, trigger)
	}
	r, err := scanRun(s.db.QueryRowContext(ctx, `SELECT `+runCols+` FROM runs WHERE `+where+` ORDER BY id DESC LIMIT 1`, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// LatestPlanRun returns the newest run that recorded a plan (0 when none).
// Self-service activations ("activate" runs) record the plan of one user's
// create; they do not supersede a plan under review (that plan has no
// operation for a user waiting for activation, so its digest stays the
// same after the activation).
func (s *Store) LatestPlanRun(ctx context.Context, connector string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(r.id), 0) FROM runs r JOIN plans p ON p.run_id = r.id
		WHERE r.connector = ? AND r.action <> 'activate'`, connector).Scan(&id)
	return id, err
}

// OpCounts counts a run's journal entries by status (apply progress).
func (s *Store) OpCounts(ctx context.Context, runID int64) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM ops WHERE run_id = ? GROUP BY status`, runID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// JournalStatus returns status and error of a run's journal by sequence.
func (s *Store) JournalStatus(ctx context.Context, runID int64) (map[int][2]string, error) {
	entries, err := s.Journal(ctx, runID)
	if err != nil {
		return nil, err
	}
	out := make(map[int][2]string, len(entries))
	for _, e := range entries {
		out[e.Seq] = [2]string{e.Status, e.Error}
	}
	return out, nil
}

// HasPlan reports whether a run recorded a plan (an AD to Google plan, or
// the plan of a g2a run).
func (s *Store) HasPlan(ctx context.Context, runID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM plans WHERE run_id = ?) + (SELECT COUNT(*) FROM g2a_plans WHERE run_id = ?)`,
		runID, runID).Scan(&n)
	return n > 0, err
}

// LinkCounts counts links of a connector.
func (s *Store) LinkCounts(ctx context.Context, connector string) (users, suspended, groups int, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(CASE WHEN kind = 'user' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN kind = 'user' AND suspended_by_sync = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN kind = 'group' THEN 1 ELSE 0 END), 0) FROM links WHERE connector = ?`, connector).Scan(&users, &suspended, &groups)
	return
}
