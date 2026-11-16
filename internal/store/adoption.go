package store

import (
	"context"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
)

// ---- adoption approvals ----

// ApprovalRow is one recorded adoption approval.
type ApprovalRow struct {
	plan.Approval
	At      time.Time
	Comment string
}

// PutApproval records (or replaces) the approval of one adoption.
func (s *Store) PutApproval(ctx context.Context, connector string, a plan.Approval, comment string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO adoption_approvals(connector, kind, source_id, target_id, address, approved_by, approved_at, comment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(connector, kind, source_id) DO UPDATE SET target_id = excluded.target_id, address = excluded.address,
			approved_by = excluded.approved_by, approved_at = excluded.approved_at, comment = excluded.comment`,
		connector, string(a.Kind), a.SourceID, a.TargetID, model.NormalizeEmail(a.Address), clip(a.By, 256), ts(s.now()), clip(comment, 1024))
	return err
}

// DeleteApproval removes an approval; it reports whether one existed.
func (s *Store) DeleteApproval(ctx context.Context, connector string, kind model.Kind, sourceID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM adoption_approvals WHERE connector = ? AND kind = ? AND source_id = ?`,
		connector, string(kind), sourceID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Approvals returns the approvals of a connector.
func (s *Store) Approvals(ctx context.Context, connector string) ([]ApprovalRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind, source_id, target_id, address, approved_by, approved_at, comment
		FROM adoption_approvals WHERE connector = ? ORDER BY kind DESC, address`, connector)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ApprovalRow
	for rows.Next() {
		var r ApprovalRow
		var kind, at string
		if err := rows.Scan(&kind, &r.SourceID, &r.TargetID, &r.Address, &r.By, &at, &r.Comment); err != nil {
			return nil, err
		}
		r.Kind, r.At = model.Kind(kind), parseTS(at)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ApprovalMap returns the approvals by plan.AdoptionKey (the plan's input).
func (s *Store) ApprovalMap(ctx context.Context, connector string) (map[string]plan.Approval, error) {
	rows, err := s.Approvals(ctx, connector)
	if err != nil {
		return nil, err
	}
	out := make(map[string]plan.Approval, len(rows))
	for _, r := range rows {
		out[plan.AdoptionKey(r.Kind, r.SourceID)] = r.Approval
	}
	return out, nil
}
