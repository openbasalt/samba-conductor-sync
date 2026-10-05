package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ---- self-service: activations and the action log ----

// tsFixed renders action times with a fixed width, so that comparing them
// as text (the rate limit window) orders them like times.
func tsFixed(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

// Activate records that a user activated their account on a connector
// (idempotent).
func (s *Store) Activate(ctx context.Context, connector, sourceID, actor string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO activations(connector, source_id, activated_at, actor) VALUES (?, ?, ?, ?)
		ON CONFLICT(connector, source_id) DO NOTHING`, connector, sourceID, ts(s.now()), clip(actor, 256))
	return err
}

// Activated returns the source IDs that activated their account.
func (s *Store) Activated(ctx context.Context, connector string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source_id FROM activations WHERE connector = ?`, connector)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ErrRateLimited is returned by TakeSelfServiceSlot when a limit is reached.
var ErrRateLimited = errors.New("store: too many self-service actions in the last hour")

// SelfServiceLimit is one rate limit check.
type SelfServiceLimit struct {
	PerUser, PerTarget int
	Window             time.Duration
}

// TakeSelfServiceSlot records the start of a self-service action when the
// user and the target are both below their limits in the window, in one
// transaction (two requests cannot both take the last slot). It returns the
// action's ID, to be finished with FinishSelfService.
func (s *Store) TakeSelfServiceSlot(ctx context.Context, connector, actorSID, sourceID, action string, lim SelfServiceLimit) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	since := tsFixed(s.now().Add(-lim.Window))
	var user, target int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM selfservice_actions WHERE connector = ? AND actor_sid = ? AND at > ?`,
		connector, actorSID, since).Scan(&user); err != nil {
		return 0, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM selfservice_actions WHERE connector = ? AND at > ?`, connector, since).Scan(&target); err != nil {
		return 0, err
	}
	if user >= lim.PerUser || target >= lim.PerTarget {
		return 0, ErrRateLimited
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO selfservice_actions(connector, actor_sid, source_id, action, at) VALUES (?, ?, ?, ?, ?)`,
		connector, actorSID, sourceID, action, tsFixed(s.now()))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// FinishSelfService records the result of an action ("ok", "failed").
func (s *Store) FinishSelfService(ctx context.Context, id int64, result string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE selfservice_actions SET result = ? WHERE id = ?`, clip(result, 64), id)
	return err
}

// SelfServiceLeft returns how many actions the user has left in the window
// (the lower of the user's and the target's remainder, never negative).
func (s *Store) SelfServiceLeft(ctx context.Context, connector, actorSID string, lim SelfServiceLimit) (int, error) {
	since := tsFixed(s.now().Add(-lim.Window))
	var user, target int
	err := s.db.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(CASE WHEN actor_sid = ? THEN 1 ELSE 0 END), 0), COUNT(*)
		FROM selfservice_actions WHERE connector = ? AND at > ?`, actorSID, connector, since).Scan(&user, &target)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return 0, err
	}
	return max(0, min(lim.PerUser-user, lim.PerTarget-target)), nil
}
