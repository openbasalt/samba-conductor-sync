package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// RunActionG2A is the action of the runs that record a Google-first plan.
const RunActionG2A = "g2a"

// G2ALink is one stored Google-first link.
type G2ALink struct {
	Scope          string
	GoogleID       string
	ObjectGUID     string
	SID            string
	SAM            string
	DisabledBySync bool
	Snapshot       map[string]string
	UpdatedAt      time.Time
}

// G2ALinks returns every Google-first link, by scope and Google ID.
func (s *Store) G2ALinks(ctx context.Context) ([]G2ALink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT scope, google_id, object_guid, sid, sam, disabled_by_sync, google_snapshot, updated_at
		FROM g2a_links ORDER BY scope, google_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []G2ALink
	for rows.Next() {
		var l G2ALink
		var disabled int
		var snap, updated string
		if err := rows.Scan(&l.Scope, &l.GoogleID, &l.ObjectGUID, &l.SID, &l.SAM, &disabled, &snap, &updated); err != nil {
			return nil, err
		}
		l.DisabledBySync = disabled != 0
		_ = json.Unmarshal([]byte(snap), &l.Snapshot)
		l.UpdatedAt = parseTS(updated)
		out = append(out, l)
	}
	return out, rows.Err()
}

// G2ALinkCount counts the Google-first links.
func (s *Store) G2ALinkCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM g2a_links`).Scan(&n)
	return n, err
}

// G2ARun is a finished g2a plan run to record.
type G2ARun struct {
	Connector, Trigger, Actor string
	StartedAt                 time.Time
	Status                    string
	Digest                    string
	SourceUsers               int
	OpsTotal                  int
	Summary                   any
	Error                     string
	// Plan is the stored plan (nil for a failed read).
	Plan []byte
}

// SaveG2ARun records a g2a run, already finished (a plan is computed
// before anything is recorded, so a g2a run is never left running), with
// its plan.
func (s *Store) SaveG2ARun(ctx context.Context, r G2ARun) (int64, error) {
	sum, err := json.Marshal(r.Summary)
	if err != nil || r.Summary == nil {
		sum = []byte("{}")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO runs(connector, action, trigger, actor, started_at, finished_at, status, plan_digest, source_users, ops_total, summary, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, r.Connector, RunActionG2A, r.Trigger, clip(r.Actor, 256), ts(r.StartedAt), ts(s.now()),
		r.Status, r.Digest, r.SourceUsers, r.OpsTotal, string(sum), clip(r.Error, 4096))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if r.Plan != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO g2a_plans(run_id, plan_json) VALUES (?, ?)`, id, string(r.Plan)); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

// LoadG2APlan returns the stored plan of a g2a run and the results
// conductor reported (nil plan when the run has none).
func (s *Store) LoadG2APlan(ctx context.Context, runID int64) (plan, results []byte, err error) {
	var p, r string
	err = s.db.QueryRowContext(ctx, `SELECT plan_json, results_json FROM g2a_plans WHERE run_id = ?`, runID).Scan(&p, &r)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return []byte(p), []byte(r), nil
}

// ErrG2AClosed: the g2a run was already confirmed (or is not a plan).
var ErrG2AClosed = errors.New("store: the g2a run is not waiting for a confirmation")

// ConfirmG2A closes a g2a run in one transaction: its status and counts,
// the results conductor reported, and the links (inserted or replaced by
// scope and Google ID). Only a run in status planned can be confirmed.
func (s *Store) ConfirmG2A(ctx context.Context, runID int64, status string, done, failed int, results []byte, links []G2ALink) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := ts(s.now())
	res, err := tx.ExecContext(ctx, `UPDATE runs SET status = ?, ops_done = ?, ops_failed = ?, finished_at = ? WHERE id = ? AND action = ? AND status = ?`,
		status, done, failed, now, runID, RunActionG2A, StatusPlanned)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrG2AClosed
	}
	if _, err := tx.ExecContext(ctx, `UPDATE g2a_plans SET results_json = ? WHERE run_id = ?`, string(results), runID); err != nil {
		return err
	}
	for _, l := range links {
		snap, err := json.Marshal(l.Snapshot)
		if err != nil || l.Snapshot == nil {
			snap = []byte("{}")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO g2a_links(scope, google_id, object_guid, sid, sam, disabled_by_sync, google_snapshot, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(scope, google_id) DO UPDATE SET object_guid = excluded.object_guid, sid = excluded.sid, sam = excluded.sam,
				disabled_by_sync = excluded.disabled_by_sync, google_snapshot = excluded.google_snapshot, updated_at = excluded.updated_at`,
			l.Scope, l.GoogleID, l.ObjectGUID, l.SID, l.SAM, boolInt(l.DisabledBySync), string(snap), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
