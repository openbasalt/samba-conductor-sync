package plan

import (
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
)

func candidateOf(p *Plan, kind model.Kind, sourceID string) *Candidate {
	for i := range p.Candidates {
		if p.Candidates[i].Kind == kind && p.Candidates[i].SourceID == sourceID {
			return &p.Candidates[i]
		}
	}
	return nil
}

// TestAdoptionNeedsApproval: adopt = "email" alone adopts nothing; the
// match is a pending candidate and the AD user is left alone (no create,
// no membership), until an administrator approves that exact pair.
func TestAdoptionNeedsApproval(t *testing.T) {
	in := adoptIn()
	in.Approvals, in.AdoptChecks = nil, nil
	p := Compute(in)
	c := candidateOf(p, model.KindUser, "a")
	if len(p.Ops) != 0 || c == nil || c.Status != CandidatePending || c.Reason != ReasonAwaitingApproval || c.TargetID != "1" ||
		!warned(p, WarnAdoptionPending) {
		t.Fatalf("ops %s candidates %+v warnings %v", kinds(p), p.Candidates, p.Warnings)
	}
	// The candidates are display only: not part of the digest.
	if p.Digest != ComputeDigest([]Op{}) {
		t.Fatal("candidates changed the digest")
	}
	// adopt = never: no candidate at all.
	in.Policy.Adopt = AdoptNever
	if p := Compute(in); len(p.Candidates) != 0 || !warned(p, WarnUnmanagedExists) {
		t.Fatalf("never: %+v %v", p.Candidates, p.Warnings)
	}
}

// TestApprovalIsBoundToTargetAndAddress: an approval for another target
// object or another address (the AD attribute was changed afterwards) does
// not apply.
func TestApprovalIsBoundToTargetAndAddress(t *testing.T) {
	for name, edit := range map[string]func(*Input){
		"other target":  func(in *Input) { a := in.Approvals["user|a"]; a.TargetID = "999"; in.Approvals["user|a"] = a },
		"other address": func(in *Input) { a := in.Approvals["user|a"]; a.Address = "boss@x.com"; in.Approvals["user|a"] = a },
	} {
		in := adoptIn()
		edit(&in)
		p := Compute(in)
		c := candidateOf(p, model.KindUser, "a")
		if len(p.Ops) != 0 || c == nil || c.Status != CandidatePending || c.Reason != ReasonApprovalStale {
			t.Fatalf("%s: ops %s candidate %+v", name, kinds(p), c)
		}
	}
	// The matching approval adopts, and the operation names the approver
	// (the digest and the audit carry it).
	p := Compute(adoptIn())
	if len(p.Ops) != 1 || p.Ops[0].Kind != UserAdopt || !strings.Contains(p.Ops[0].Reason, "approved by admin") {
		t.Fatalf("approved: %+v", p.Ops)
	}
	if c := candidateOf(p, model.KindUser, "a"); c == nil || c.Status != CandidateApproved || c.ApprovedBy != "admin" {
		t.Fatalf("candidate %+v", c)
	}
}

// TestNeverAdoptable: a target administrator, a privileged AD object, an
// address another AD object carries and an unchecked candidate are never
// adopted, approved or not.
func TestNeverAdoptable(t *testing.T) {
	cases := map[string]struct {
		edit   func(*Input)
		reason string
	}{
		"target admin": {func(in *Input) { in.TargetUsers[0].Protected = true }, RefuseTargetAdmin},
		"ad privileged": {func(in *Input) {
			in.AdoptChecks["user|a"] = AdoptionCheck{Privileged: []string{"group: S-1-5-21-1-512"}}
		}, RefuseADPrivileged},
		"not unique": {func(in *Input) {
			in.AdoptChecks["user|a"] = AdoptionCheck{Duplicates: []string{"CN=mallory,OU=People,DC=x"}}
		}, RefuseNotUnique},
		"not checked": {func(in *Input) { delete(in.AdoptChecks, "user|a") }, RefuseNotChecked},
	}
	for name, tc := range cases {
		in := adoptIn()
		tc.edit(&in)
		p := Compute(in)
		c := candidateOf(p, model.KindUser, "a")
		if len(p.Ops) != 0 || c == nil || c.Status != CandidateRefused || c.Reason != tc.reason || !warned(p, WarnAdoptionRefused) {
			t.Fatalf("%s: ops %s candidate %+v", name, kinds(p), c)
		}
	}
	// A target administrator is refused even without an approval.
	in := adoptIn()
	in.Approvals = nil
	in.TargetUsers[0].Protected = true
	if c := candidateOf(Compute(in), model.KindUser, "a"); c == nil || c.Reason != RefuseTargetAdmin {
		t.Fatalf("unapproved admin: %+v", c)
	}
	// NeedsChecks lists only the approved, unchecked candidates.
	in = adoptIn()
	in.AdoptChecks = nil
	if need := Compute(in).NeedsChecks(); len(need) != 1 || need[0].SourceID != "a" {
		t.Fatalf("needs checks %+v", need)
	}
}

// TestGroupAdoptionNeedsKnownRoles: an approved group is adopted only when
// the target's role assignments were read and none names it.
func TestGroupAdoptionNeedsKnownRoles(t *testing.T) {
	in := groupIn()
	in.GroupRolesKnown = false
	p := Compute(in)
	if c := candidateOf(p, model.KindGroup, "g"); len(p.Ops) != 0 || c == nil || c.Reason != RefuseGroupRolesUnknown {
		t.Fatalf("roles unknown: %s %+v", kinds(p), c)
	}
	in = groupIn()
	in.AdminRoleGroups = map[string]bool{"G": true}
	p = Compute(in)
	if c := candidateOf(p, model.KindGroup, "g"); len(p.Ops) != 0 || c == nil || c.Reason != RefuseGroupAdminRole {
		t.Fatalf("admin role: %s %+v", kinds(p), c)
	}
	// Not approved: pending, and no member is added to it.
	in = groupIn()
	delete(in.Approvals, "group|g")
	p = Compute(in)
	if c := candidateOf(p, model.KindGroup, "g"); len(p.Ops) != 0 || c == nil || c.Status != CandidatePending {
		t.Fatalf("unapproved group: %s %+v", kinds(p), c)
	}
}
