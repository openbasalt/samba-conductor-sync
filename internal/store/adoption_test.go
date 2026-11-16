package store

import (
	"context"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
)

func TestApprovals(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	a := plan.Approval{Kind: model.KindUser, SourceID: "g1", TargetID: "t1", Address: "Ana@X.com", By: "root"}
	if err := s.PutApproval(ctx, "google", a, "ticket 1"); err != nil {
		t.Fatal(err)
	}
	// Replacing keeps one row per AD object.
	a.TargetID = "t2"
	if err := s.PutApproval(ctx, "google", a, "ticket 2"); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Approvals(ctx, "google")
	if err != nil || len(rows) != 1 || rows[0].TargetID != "t2" || rows[0].Address != "ana@x.com" || rows[0].Comment != "ticket 2" || rows[0].At.IsZero() {
		t.Fatalf("rows %+v %v", rows, err)
	}
	m, err := s.ApprovalMap(ctx, "google")
	if err != nil || m[plan.AdoptionKey(model.KindUser, "g1")].TargetID != "t2" {
		t.Fatalf("map %+v %v", m, err)
	}
	if other, _ := s.Approvals(ctx, "entra"); len(other) != 0 {
		t.Fatalf("other connector sees %+v", other)
	}
	if ok, err := s.DeleteApproval(ctx, "google", model.KindUser, "g1"); err != nil || !ok {
		t.Fatalf("delete %v %v", ok, err)
	}
	if ok, _ := s.DeleteApproval(ctx, "google", model.KindUser, "g1"); ok {
		t.Fatal("deleted twice")
	}
}
