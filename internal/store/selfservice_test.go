package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSelfServiceSlotsAndActivations(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 5, 12, 0, 0, 500_000_000, time.UTC)
	s.SetClock(func() time.Time { return now })
	lim := SelfServiceLimit{PerUser: 2, PerTarget: 3, Window: time.Hour}
	for i := range 2 {
		id, err := s.TakeSelfServiceSlot(ctx, "google", "S-1-5-21-1-2-3-1001", "g1", "self.set_password", lim)
		if err != nil || id == 0 {
			t.Fatalf("slot %d: %v", i, err)
		}
		_ = s.FinishSelfService(ctx, id, "ok")
		now = now.Add(time.Second / 3)
	}
	if _, err := s.TakeSelfServiceSlot(ctx, "google", "S-1-5-21-1-2-3-1001", "g1", "self.set_password", lim); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("per user: %v", err)
	}
	if left, _ := s.SelfServiceLeft(ctx, "google", "S-1-5-21-1-2-3-1001", lim); left != 0 {
		t.Fatalf("left %d", left)
	}
	if _, err := s.TakeSelfServiceSlot(ctx, "google", "S-1-5-21-1-2-3-1002", "g2", "self.activate", lim); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeSelfServiceSlot(ctx, "google", "S-1-5-21-1-2-3-1003", "g3", "self.activate", lim); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("per target: %v", err)
	}
	// Another target has its own count.
	if _, err := s.TakeSelfServiceSlot(ctx, "entra", "S-1-5-21-1-2-3-1003", "g3", "self.activate", lim); err != nil {
		t.Fatal(err)
	}
	// One hour after the first action (sub-second precision), one slot frees.
	now = time.Date(2026, 10, 5, 13, 0, 0, 600_000_000, time.UTC)
	if left, _ := s.SelfServiceLeft(ctx, "google", "S-1-5-21-1-2-3-1001", lim); left != 1 {
		t.Fatalf("left after the window: %d", left)
	}
	if err := s.Activate(ctx, "google", "g2", "conductor:u"); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(ctx, "google", "g2", "conductor:u"); err != nil {
		t.Fatal("activation is idempotent")
	}
	if a, _ := s.Activated(ctx, "google"); len(a) != 1 || !a["g2"] {
		t.Fatalf("activated %v", a)
	}
}
