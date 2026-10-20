package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestG2ARuns(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	apply, err := s.StartRun(ctx, "google", "apply", "manual", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, apply, RunResult{Status: StatusBlocked}); err != nil {
		t.Fatal(err)
	}
	id, err := s.SaveG2ARun(ctx, G2ARun{Connector: "google", Trigger: "manual", Actor: "admin", StartedAt: time.Now(), Status: StatusPlanned,
		Digest: "d", OpsTotal: 2, Summary: map[string]int{"x": 1}, Plan: []byte(`{"plan":{}}`)})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := s.SaveG2ARun(ctx, G2ARun{Connector: "google", Status: StatusFailed, Error: "empty selection", StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	// g2a runs are not AD to Google runs.
	if r, _ := s.LastRun(ctx, "google", "", ""); r == nil || r.ID != apply {
		t.Fatalf("last run %+v", r)
	}
	if r, _ := s.LastRun(ctx, "google", RunActionG2A, ""); r == nil || r.ID != failed {
		t.Fatalf("last g2a run %+v", r)
	}
	if blocked, _ := s.BlockedSince(ctx, "google", 0); len(blocked) != 1 || blocked[0].ID != apply {
		t.Fatalf("blocked %+v", blocked)
	}
	if has, _ := s.HasPlan(ctx, id); !has {
		t.Fatal("the g2a plan is not seen")
	}
	if has, _ := s.HasPlan(ctx, failed); has {
		t.Fatal("a failed read has no plan")
	}
	links := []G2ALink{{Scope: "people", GoogleID: "1", ObjectGUID: "g", SID: "S-1-5-21-1-2-3-1100", SAM: "ana", Snapshot: map[string]string{"mail": "a@x"}}}
	if err := s.ConfirmG2A(ctx, id, StatusApplied, 1, 0, []byte(`[{"seq":0,"status":"done"}]`), links); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmG2A(ctx, id, StatusApplied, 1, 0, nil, nil); !errors.Is(err, ErrG2AClosed) {
		t.Fatalf("second confirm: %v", err)
	}
	if err := s.ConfirmG2A(ctx, apply, StatusApplied, 0, 0, nil, nil); !errors.Is(err, ErrG2AClosed) {
		t.Fatalf("an AD to Google run: %v", err)
	}
	got, _ := s.G2ALinks(ctx)
	if len(got) != 1 || got[0].Snapshot["mail"] != "a@x" || got[0].DisabledBySync {
		t.Fatalf("links %+v", got)
	}
	links[0].DisabledBySync = true
	id2, _ := s.SaveG2ARun(ctx, G2ARun{Connector: "google", Status: StatusPlanned, StartedAt: time.Now(), Plan: []byte(`{}`)})
	if err := s.ConfirmG2A(ctx, id2, StatusPartial, 1, 1, []byte(`[]`), links); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.G2ALinks(ctx); len(got) != 1 || !got[0].DisabledBySync {
		t.Fatalf("upsert %+v", got)
	}
	r, _ := s.GetRun(ctx, id2)
	if r.Status != StatusPartial || r.OpsDone != 1 || r.OpsFailed != 1 || r.Action != RunActionG2A {
		t.Fatalf("run %+v", r)
	}
	plan, results, _ := s.LoadG2APlan(ctx, id)
	if string(plan) != `{"plan":{}}` || string(results) != `[{"seq":0,"status":"done"}]` {
		t.Fatalf("%s %s", plan, results)
	}
}
