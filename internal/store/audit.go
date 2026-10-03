package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// GenesisHash is the prev_hash of the first audit row.
var GenesisHash = strings.Repeat("0", 64)

// Audit results.
const (
	ResultOK      = "ok"
	ResultFailed  = "failed"
	ResultBlocked = "blocked"
	ResultInfo    = "info"
)

// AuditEvent is one audit row. Detail never holds a secret (passwords are
// generated and sent without being recorded anywhere).
type AuditEvent struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"ts"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Target   string    `json:"target"`
	Detail   string    `json:"detail"`
	Result   string    `json:"result"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// chainHash is SHA-256 over the previous hash and the canonical JSON of
// every other field.
func chainHash(e AuditEvent) string {
	b, _ := json.Marshal(struct {
		ID     int64  `json:"id"`
		Time   string `json:"ts"`
		Actor  string `json:"actor"`
		Action string `json:"action"`
		Target string `json:"target"`
		Detail string `json:"detail"`
		Result string `json:"result"`
	}{e.ID, ts(e.Time), e.Actor, e.Action, e.Target, e.Detail, e.Result})
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write([]byte{'\n'})
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// AppendAudit adds an event at the end of the chain.
func (s *Store) AppendAudit(ctx context.Context, e AuditEvent) (AuditEvent, error) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	e.Time = s.now().Truncate(time.Microsecond)
	e.Actor, e.Action, e.Target, e.Result = clip(e.Actor, 256), clip(e.Action, 64), clip(e.Target, 1024), clip(e.Result, 32)
	e.Detail = clip(e.Detail, 16<<10)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return e, err
	}
	defer func() { _ = tx.Rollback() }()
	var lastID int64
	var lastHash string
	err = tx.QueryRowContext(ctx, `SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&lastID, &lastHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		lastID, lastHash = 0, GenesisHash
	case err != nil:
		return e, err
	}
	e.ID, e.PrevHash = lastID+1, lastHash
	e.Hash = chainHash(e)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit(id, ts, actor, action, target, detail, result, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, ts(e.Time), e.Actor, e.Action, e.Target, e.Detail, e.Result, e.PrevHash, e.Hash); err != nil {
		return e, err
	}
	return e, tx.Commit()
}

const auditCols = `id, ts, actor, action, target, detail, result, prev_hash, hash`

func scanAudit(sc interface{ Scan(...any) error }) (AuditEvent, error) {
	var e AuditEvent
	var t string
	err := sc.Scan(&e.ID, &t, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.Result, &e.PrevHash, &e.Hash)
	e.Time = parseTS(t)
	return e, err
}

// ListAudit returns the newest events first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExportAudit writes every event as JSON lines, oldest first.
func (s *Store) ExportAudit(ctx context.Context, w io.Writer) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit ORDER BY id ASC`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	enc := json.NewEncoder(w)
	n := 0
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return n, err
		}
		if err := enc.Encode(e); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// VerifyResult is the outcome of a chain check.
type VerifyResult struct {
	Rows     int
	LastHash string
	BrokenAt int64
	Reason   string
}

// VerifyAudit walks the chain from the genesis hash.
func (s *Store) VerifyAudit(ctx context.Context) (VerifyResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit ORDER BY id ASC`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer func() { _ = rows.Close() }()
	res := VerifyResult{LastHash: GenesisHash}
	var expect int64 = 1
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return res, err
		}
		switch {
		case e.ID != expect:
			res.BrokenAt, res.Reason = expect, fmt.Sprintf("row %d missing (found %d)", expect, e.ID)
		case e.PrevHash != res.LastHash:
			res.BrokenAt, res.Reason = e.ID, "prev_hash does not match the previous row"
		case chainHash(e) != e.Hash:
			res.BrokenAt, res.Reason = e.ID, "row content does not match its hash"
		}
		if res.BrokenAt != 0 {
			return res, nil
		}
		res.Rows++
		res.LastHash = e.Hash
		expect++
	}
	return res, rows.Err()
}

// TamperForTest rewrites one audit row's detail without fixing the chain
// (tests of VerifyAudit only).
func (s *Store) TamperForTest(ctx context.Context, id int64, detail string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE audit SET detail = ? WHERE id = ?`, detail, id)
	return err
}
