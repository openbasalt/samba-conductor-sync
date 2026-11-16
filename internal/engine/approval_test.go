package engine_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/engine"
	"github.com/openbasalt/samba-conductor-sync/internal/fakegoogle"
	"github.com/openbasalt/samba-conductor-sync/internal/model"
	"github.com/openbasalt/samba-conductor-sync/internal/plan"
	"github.com/openbasalt/samba-conductor-sync/internal/source"
)

func candidate(c *engine.Computed, address string) *plan.Candidate {
	for i := range c.Plan.Candidates {
		if c.Plan.Candidates[i].Address == address {
			return &c.Plan.Candidates[i]
		}
	}
	return nil
}

// TestAttributeWriterCannotTakeOverAnAccount is the SYNC-1 attack: someone
// who can edit an AD user's mail points it at an existing Google account.
// Nothing happens until an administrator approves that exact pair, and an
// approval is bound to the address it was given for.
func TestAttributeWriterCannotTakeOverAnAccount(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.eng.Policy.Adopt = plan.AdoptEmail
	e.eng.Limits.MaxTouchedPercent = -1
	boss := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "boss@example.com", Name: map[string]any{"givenName": "The", "familyName": "Boss"}})
	mallory := user(1, "/Staff", true)
	mallory.Attrs[model.FieldPrimaryEmail] = "boss@example.com"
	e.src.Users = []model.SourceUser{mallory}

	// Scheduled or manual, the run adopts nothing: a pending candidate.
	c := e.plan()
	cand := candidate(c, "boss@example.com")
	if c.Plan.Counts()[plan.UserAdopt] != 0 || cand == nil || cand.Status != plan.CandidatePending || cand.TargetID != boss.ID {
		t.Fatalf("plan %v candidates %+v", c.Plan.Counts(), c.Plan.Candidates)
	}
	e.mustApply(engine.ApplyOptions{})
	if ownerOf(e.userByEmail("boss@example.com")) != "" {
		t.Fatal("adopted without approval")
	}

	// The approval is refused when the AD object is privileged, or when
	// another AD object carries the address too.
	key := plan.AdoptionKey(model.KindUser, guid(1))
	req := engine.ApproveRequest{Kind: model.KindUser, SourceID: guid(1), TargetID: boss.ID}
	e.checks = map[string]plan.AdoptionCheck{key: {Privileged: []string{"adminCount: CN=user0001"}}}
	if _, err := e.eng.ApproveAdoption(ctx, req); !errors.Is(err, engine.ErrApprovalRefused) || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("privileged: %v", err)
	}
	e.checks = map[string]plan.AdoptionCheck{key: {Duplicates: []string{"CN=boss,OU=People,DC=lab"}}}
	if _, err := e.eng.ApproveAdoption(ctx, req); !errors.Is(err, engine.ErrApprovalRefused) || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("duplicate address: %v", err)
	}
	// A wrong target is refused.
	if _, err := e.eng.ApproveAdoption(ctx, engine.ApproveRequest{Kind: model.KindUser, SourceID: guid(1), TargetID: "other"}); !errors.Is(err, engine.ErrApprovalRefused) {
		t.Fatalf("wrong target: %v", err)
	}
	e.checks = nil
	ap, err := e.eng.ApproveAdoption(ctx, engine.ApproveRequest{Kind: model.KindUser, SourceID: guid(1), TargetID: boss.ID, Comment: "ticket 42"})
	if err != nil || ap.Address != "boss@example.com" || ap.By != "tester" {
		t.Fatalf("approve: %+v %v", ap, err)
	}

	// The checks run again at plan time: a duplicate found now refuses.
	e.checks = map[string]plan.AdoptionCheck{key: {Duplicates: []string{"CN=boss,OU=People,DC=lab"}}}
	c = e.plan()
	if cand := candidate(c, "boss@example.com"); c.Plan.Counts()[plan.UserAdopt] != 0 || cand == nil || cand.Reason != plan.RefuseNotUnique {
		t.Fatalf("duplicate at plan time: %v %+v", c.Plan.Counts(), cand)
	}
	e.checks = nil

	// The AD address changes after the approval: the approval no longer
	// applies to the new address.
	e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "cfo@example.com", Name: map[string]any{"givenName": "C", "familyName": "FO"}})
	e.src.Users[0].Attrs[model.FieldPrimaryEmail] = "cfo@example.com"
	c = e.plan()
	if cand := candidate(c, "cfo@example.com"); c.Plan.Counts()[plan.UserAdopt] != 0 || cand == nil || cand.Reason != plan.ReasonApprovalStale {
		t.Fatalf("stale approval: %v %+v", c.Plan.Counts(), cand)
	}

	// Back to the approved address: adopted, with the approver in the
	// operation's reason; the approval and the adoption are audited.
	e.src.Users[0].Attrs[model.FieldPrimaryEmail] = "boss@example.com"
	c = e.plan()
	if c.Plan.Counts()[plan.UserAdopt] != 1 || !strings.Contains(c.Plan.Ops[0].Reason, "approved by tester") {
		t.Fatalf("approved plan %v", c.Plan.Ops)
	}
	e.mustApply(engine.ApplyOptions{})
	if ownerOf(e.userByEmail("boss@example.com")) != guid(1) {
		t.Fatal("approved adoption not applied")
	}
	ev, _ := e.st.ListAudit(ctx, 100)
	var approved, refused, adopted bool
	for _, a := range ev {
		switch {
		case a.Action == "adoption.approve" && a.Result == "ok" && strings.Contains(a.Detail, "ticket 42"):
			approved = true
		case a.Action == "adoption.approve" && a.Result == "blocked":
			refused = true
		case a.Action == "user.adopt" && strings.Contains(a.Detail, "approved by tester"):
			adopted = true
		}
	}
	if !approved || !refused || !adopted {
		t.Fatalf("audit approved=%v refused=%v adopted=%v: %+v", approved, refused, adopted, ev)
	}
}

// noCheckSource is a source that can not check adoption candidates.
type noCheckSource struct{ e *env }

func (s noCheckSource) Read(ctx context.Context) (*source.Result, error) {
	return mutableSource(s).Read(ctx)
}

// TestAdoptionFailsClosedWithoutChecks: a source that can not run the AD
// checks adopts nothing and accepts no approval.
func TestAdoptionFailsClosedWithoutChecks(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.eng.Policy.Adopt = plan.AdoptEmail
	u := e.fake.SeedUser(fakegoogle.User{PrimaryEmail: "user0001@example.com", Name: map[string]any{"givenName": "A", "familyName": "B"}})
	e.src.Users = []model.SourceUser{user(1, "/Staff", true)}
	e.approveAll()
	e.eng.Source = noCheckSource{e}
	c := e.plan()
	if cand := candidate(c, "user0001@example.com"); c.Plan.Counts()[plan.UserAdopt] != 0 || cand == nil || cand.Reason != plan.RefuseNotChecked {
		t.Fatalf("plan %v %+v", c.Plan.Counts(), cand)
	}
	if _, err := e.eng.ApproveAdoption(ctx, engine.ApproveRequest{Kind: model.KindUser, SourceID: guid(1), TargetID: u.ID}); !errors.Is(err, engine.ErrApprovalRefused) {
		t.Fatalf("approval without checks: %v", err)
	}
}

// TestGroupWithAdminRoleNeverAdopted: an approved group that holds an
// administrator role on the target is refused.
func TestGroupWithAdminRoleNeverAdopted(t *testing.T) {
	e := newEnv(t)
	e.eng.Policy.Adopt = plan.AdoptEmail
	e.fake.RoleScopes[fakegoogle.ScopeRoleReadonly] = true
	g := e.fake.SeedGroup(fakegoogle.Group{Email: "admins@groups.example.com", Name: "Admins"})
	e.fake.RoleAssignments = []fakegoogle.RoleAssignment{{RoleID: "1", AssignedTo: g.ID, AssigneeType: "group"}}
	e.src.Users = []model.SourceUser{user(1, "/Staff", true)}
	e.src.Groups = []model.SourceGroup{group(1, "Admins", uref(1))}
	e.approveAll()
	c := e.plan()
	cand := candidate(c, "admins@groups.example.com")
	if c.Plan.Counts()[plan.GroupAdopt] != 0 || cand == nil || cand.Reason != plan.RefuseGroupAdminRole {
		t.Fatalf("plan %v %+v", c.Plan.Counts(), c.Plan.Candidates)
	}
	for _, op := range c.Plan.Ops {
		if op.Kind == plan.MemberAdd && op.Key == "admins@groups.example.com" {
			t.Fatalf("member added to a refused group: %+v", op)
		}
	}
	// Once refused, it can not be approved again.
	if _, err := e.eng.ApproveAdoption(context.Background(), engine.ApproveRequest{Kind: model.KindGroup, SourceID: guid(900001), TargetID: g.ID}); !errors.Is(err, engine.ErrApprovalRefused) {
		t.Fatalf("approval of an admin group: %v", err)
	}
}
