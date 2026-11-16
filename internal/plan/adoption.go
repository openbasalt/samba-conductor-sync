package plan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openbasalt/samba-conductor-sync/internal/model"
)

// Adoption by address is never automatic. With adopt = "email" an existing,
// unmanaged target object whose address equals the one AD renders for an
// in-scope object is only a candidate: it is adopted when an administrator
// approved that exact pair (the AD object, the target object and the
// address) and every check below passes; otherwise the plan lists it as a
// pending or refused candidate and leaves it alone.
//
// Never adoptable, approved or not:
//   - a target administrator (Google super or delegated administrator, or
//     the admin subject of the delegated mode): Protected;
//   - an AD object that is privileged in the domain (administrative groups,
//     adminCount, rights on protected objects);
//   - an address that another AD object also carries (mail, proxyAddresses
//     or userPrincipalName): the attribute feeding the address must be
//     unique in the whole directory, not only in the sync scope;
//   - a target group that holds an administrator role assignment, or any
//     group when the role assignments could not be read (fail closed);
//   - a candidate the checks did not answer for (fail closed).

// Candidate statuses.
const (
	// CandidatePending waits for an administrator's approval.
	CandidatePending = "pending"
	// CandidateApproved is approved and adopted by this plan.
	CandidateApproved = "approved"
	// CandidateRefused can not be adopted (Reason says why), even when
	// approved.
	CandidateRefused = "refused"
)

// Refusal reasons of a candidate.
const (
	RefuseTargetAdmin       = "target-administrator"
	RefuseADPrivileged      = "ad-privileged"
	RefuseNotUnique         = "address-not-unique"
	RefuseNotChecked        = "not-checked"
	RefuseGroupAdminRole    = "group-holds-admin-role"
	RefuseGroupRolesUnknown = "group-roles-unknown"
	// ReasonAwaitingApproval: no approval recorded for this pair.
	ReasonAwaitingApproval = "awaiting-approval"
	// ReasonApprovalStale: the recorded approval names another target
	// object or another address (the AD attribute or the target changed
	// since it was approved); it must be approved again.
	ReasonApprovalStale = "approval-stale"
)

// Warning codes of adoption candidates.
const (
	// WarnAdoptionPending: an existing object could be adopted once an
	// administrator approves it (conductor-sync adopt approve).
	WarnAdoptionPending = "adoption-pending"
	// WarnAdoptionRefused: an existing object matches but can never be
	// adopted (a target administrator, a privileged AD object, an address
	// that is not unique, a group with an administrator role).
	WarnAdoptionRefused = "adoption-refused"
)

// Approval is an administrator's explicit approval to adopt one existing
// target object for one AD object. It is bound to the target ID and to the
// address: if either changes, the approval no longer applies.
type Approval struct {
	Kind     model.Kind `json:"kind"`
	SourceID string     `json:"source_id"`
	TargetID string     `json:"target_id"`
	Address  string     `json:"address"`
	By       string     `json:"by"`
}

// AdoptionCheck is what the source directory says about one candidate.
type AdoptionCheck struct {
	// Privileged lists why the AD object is privileged (empty: it is not).
	Privileged []string `json:"privileged,omitempty"`
	// Duplicates lists other AD objects that carry the same address.
	Duplicates []string `json:"duplicates,omitempty"`
}

// AdoptionKey identifies an approval or a check: the kind and the source ID.
func AdoptionKey(kind model.Kind, sourceID string) string {
	return string(kind) + "|" + sourceID
}

// Candidate is an existing target object that matches an in-scope AD object
// by address (display, not part of the digest).
type Candidate struct {
	Kind     model.Kind `json:"kind"`
	SourceID string     `json:"source_id"`
	SourceDN string     `json:"source_dn,omitempty"`
	Account  string     `json:"account,omitempty"`
	TargetID string     `json:"target_id"`
	Address  string     `json:"address"`
	Status   string     `json:"status"`
	Reason   string     `json:"reason,omitempty"`
	// Detail explains a refusal (privilege reasons, the other objects with
	// the address).
	Detail string `json:"detail,omitempty"`
	// ApprovedBy is the approver of an approved candidate.
	ApprovedBy string `json:"approved_by,omitempty"`
}

// candidate decides one adoption candidate. It returns the approval when
// the object is adopted now, or records the candidate as pending or
// refused (with a warning) and returns nil.
func (p *planner) candidate(c Candidate, protected bool, groupRole bool) *Approval {
	key := AdoptionKey(c.Kind, c.SourceID)
	refuse := func(reason, detail string) *Approval {
		c.Status, c.Reason, c.Detail = CandidateRefused, reason, detail
		p.cands = append(p.cands, c)
		p.warnf(WarnAdoptionRefused, c.Address, "an existing %s with this address can not be adopted (%s%s); left alone",
			c.Kind, reason, suffix(detail))
		return nil
	}
	if protected {
		return refuse(RefuseTargetAdmin, "")
	}
	if c.Kind == model.KindGroup && p.in.GroupRolesKnown && groupRole {
		return refuse(RefuseGroupAdminRole, "")
	}
	ap, approved := p.in.Approvals[key]
	stale := approved && (ap.TargetID != c.TargetID || model.NormalizeEmail(ap.Address) != c.Address)
	if !approved || stale {
		c.Status, c.Reason = CandidatePending, ReasonAwaitingApproval
		msg := "an existing %s with this address is not managed by the sync; it is adopted only after an administrator approves it (conductor-sync adopt approve)"
		if stale {
			c.Reason = ReasonApprovalStale
			msg = "the approval recorded for this %s names another target object or address; approve it again to adopt it"
		}
		p.cands = append(p.cands, c)
		p.warnf(WarnAdoptionPending, c.Address, msg, c.Kind)
		return nil
	}
	chk, checked := p.in.AdoptChecks[key]
	switch {
	case !checked:
		return refuse(RefuseNotChecked, "the AD checks did not answer for this object")
	case len(chk.Privileged) > 0:
		return refuse(RefuseADPrivileged, strings.Join(chk.Privileged, "; "))
	case len(chk.Duplicates) > 0:
		return refuse(RefuseNotUnique, "also on "+strings.Join(chk.Duplicates, "; "))
	case c.Kind == model.KindGroup && !p.in.GroupRolesKnown:
		return refuse(RefuseGroupRolesUnknown, "the target's administrator role assignments could not be read")
	}
	c.Status, c.ApprovedBy = CandidateApproved, ap.By
	p.cands = append(p.cands, c)
	return &ap
}

func suffix(detail string) string {
	if detail == "" {
		return ""
	}
	return ": " + detail
}

func sortCandidates(cs []Candidate) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Kind != cs[j].Kind {
			return cs[i].Kind > cs[j].Kind // users first
		}
		return cs[i].Address < cs[j].Address
	})
}

// approvedReason is the reason of an adoption operation: it names the
// approver, so the digest (and the audit of the operation) carries who
// approved it.
func approvedReason(what string, ap *Approval) string {
	return fmt.Sprintf("adopt existing %s by address, approved by %s", what, ap.By)
}

// NeedsChecks lists the candidates of a plan that are approved but were
// not checked yet (status refused, reason not-checked): the engine runs
// the source checks for them and computes the plan again.
func (p *Plan) NeedsChecks() []Candidate {
	var out []Candidate
	for _, c := range p.Candidates {
		if c.Status == CandidateRefused && c.Reason == RefuseNotChecked {
			out = append(out, c)
		}
	}
	return out
}

// HasGroupCandidates reports whether any group matched by address (the
// engine reads the target's role assignments only then).
func (p *Plan) HasGroupCandidates() bool {
	for _, c := range p.Candidates {
		if c.Kind == model.KindGroup {
			return true
		}
	}
	return false
}
