package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(context.Background(), filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func TestLinks(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	l := plan.Link{Kind: model.KindUser, SourceID: "g1", TargetID: "t1", Key: "A@x.com"}
	if err := s.PutLink(ctx, "google", l, "CN=a"); err != nil {
		t.Fatal(err)
	}
	l.SuspendedBySync = true
	if err := s.PutLink(ctx, "google", l, ""); err != nil {
		t.Fatal(err)
	}
	// The same target claimed by another source replaces the old link.
	if err := s.PutLink(ctx, "google", plan.Link{Kind: model.KindUser, SourceID: "g2", TargetID: "t1", Key: "a@x.com"}, ""); err != nil {
		t.Fatal(err)
	}
	links, _ := s.Links(ctx, "google")
	if len(links) != 1 || links[0].SourceID != "g2" {
		t.Fatalf("links %+v", links)
	}
	if err := s.RefreshSourceDNs(ctx, "google", map[string]string{"g2": "CN=b"}); err != nil {
		t.Fatal(err)
	}
	f, _ := s.FindLink(ctx, "google", "a@x.com")
	if f == nil || f.SourceDN != "CN=b" || f.Key != "a@x.com" {
		t.Fatalf("find %+v", f)
	}
	if err := s.DeleteLink(ctx, "google", model.KindUser, "g2"); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.FindLink(ctx, "google", "t1"); f != nil {
		t.Fatal("not deleted")
	}
}

func TestRunsJournalAndInFlight(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	id, _ := s.StartRun(ctx, "google", "apply", "manual", "me")
	ops := []plan.Op{{Kind: plan.GroupCreate, Key: "g@x.com", SourceID: "s1"}, {Kind: plan.UserSuspend, Key: "u@x.com"}}
	if err := s.JournalOps(ctx, id, ops); err != nil {
		t.Fatal(err)
	}
	_ = s.MarkOp(ctx, id, 0, OpStarted, "", "")
	_ = s.MarkOp(ctx, id, 1, OpDone, "", "")
	inflight, _ := s.InFlight(ctx, "google")
	if len(inflight) != 1 || inflight[0].Kind != plan.GroupCreate {
		t.Fatalf("in-flight %+v", inflight)
	}
	ids, _ := s.MarkInterrupted(ctx, "google")
	if len(ids) != 1 || ids[0] != id {
		t.Fatalf("interrupted %v", ids)
	}
	if r, _ := s.GetRun(ctx, id); r.Status != StatusInterrupted || r.OpsTotal != 2 || r.OpsDone != 1 {
		t.Fatalf("interrupted run %+v", r)
	}
	id2, _ := s.StartRun(ctx, "google", "apply", "manual", "me")
	_ = s.Supersede(ctx, "google", id2)
	if inflight, _ := s.InFlight(ctx, "google"); len(inflight) != 0 {
		t.Fatalf("still in flight %+v", inflight)
	}
	_ = s.FinishRun(ctx, id2, RunResult{Status: StatusApplied, SourceUsers: 42})
	last, _ := s.LastRunWithStatus(ctx, "google", "apply", StatusApplied)
	if last == nil || last.SourceUsers != 42 {
		t.Fatalf("last %+v", last)
	}
	p := &plan.Plan{Connector: "google", Ops: ops, Digest: "d"}
	_ = s.SavePlan(ctx, id2, p)
	if got, _ := s.LoadPlan(ctx, id2); got == nil || got.Digest != "d" || len(got.Ops) != 2 {
		t.Fatalf("plan %+v", got)
	}
}

func TestAuditChain(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := s.AppendAudit(ctx, AuditEvent{Actor: "a", Action: "x", Target: "t", Detail: "d", Result: ResultOK}); err != nil {
			t.Fatal(err)
		}
	}
	v, _ := s.VerifyAudit(ctx)
	if v.Rows != 5 || v.BrokenAt != 0 {
		t.Fatalf("verify %+v", v)
	}
	_ = s.TamperForTest(ctx, 3, "edited")
	v, _ = s.VerifyAudit(ctx)
	if v.BrokenAt != 3 {
		t.Fatalf("tamper not detected: %+v", v)
	}
}

func TestLock(t *testing.T) {
	_, dir := open(t)
	p := filepath.Join(dir, "lock")
	a, err := AcquireLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	a.Release()
	b, err := AcquireLock(p)
	if err != nil {
		t.Fatal(err)
	}
	b.Release()
}

func TestSuspendedAtKeptAcrossUpdates(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := t0
	s.SetClock(func() time.Time { return now })
	l := plan.Link{Kind: model.KindUser, SourceID: "g", TargetID: "t", Key: "a@x.com", SuspendedBySync: true}
	_ = s.PutLink(ctx, "google", l, "")
	now = t0.Add(48 * time.Hour)
	l.Key = "renamed@x.com" // an update while suspended keeps the date
	_ = s.PutLink(ctx, "google", l, "")
	got, _ := s.FindLink(ctx, "google", "g")
	if !got.SuspendedAt.Equal(t0) {
		t.Fatalf("suspended_at %v", got.SuspendedAt)
	}
	l.SuspendedBySync = false
	_ = s.PutLink(ctx, "google", l, "")
	if got, _ := s.FindLink(ctx, "google", "g"); !got.SuspendedAt.IsZero() {
		t.Fatalf("not cleared: %v", got.SuspendedAt)
	}
}
