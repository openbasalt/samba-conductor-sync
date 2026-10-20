package g2a

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

// Outcome is what a confirmation records: the links to write and how the
// run closes.
type Outcome struct {
	// Status is applied, partial, blocked or dry-run.
	Status                string
	Done, Failed, Skipped int
	// Links are the links to insert or replace (by scope and Google ID).
	Links []Link
}

// ConfirmError refuses a confirmation that does not match the plan.
type ConfirmError struct{ Message string }

func (e *ConfirmError) Error() string { return e.Message }

// Confirm checks what conductor reports applying against the stored plan
// and computes the links and the run's status:
//   - only operations of scopes in apply mode whose limits hold can have
//     been applied (anything else is refused, nothing is recorded);
//   - a done create links the new account (its SID and objectGUID come
//     with the result); a done update or rename records the Google values
//     in the link snapshot, except the fields of the account's operations
//     that were not done; a done disable records that the sync disabled the
//     account when it did; a done re-enable clears it;
//   - accounts that carry the marker but had no link get one;
//   - the run is blocked when nothing was applied and a scope exceeded its
//     limits, dry-run when no scope is in apply mode within its limits,
//     applied when every operation of those scopes is done and no scope
//     was blocked, partial otherwise.
func Confirm(res *Result, links []Link, results []syncapi.G2AOpResult) (*Outcome, error) {
	type opRef struct {
		scope *syncapi.G2AScopePlan
		op    syncapi.G2AOp
	}
	bySeq := map[int]opRef{}
	applicable := map[int]bool{}
	anyBlocked, anyApply := false, false
	for i := range res.Plan.Scopes {
		sp := &res.Plan.Scopes[i]
		if sp.Blocked {
			anyBlocked = true
		}
		if sp.Mode == syncapi.G2AModeApply && !sp.Blocked {
			anyApply = true
		}
		for _, o := range sp.Ops {
			bySeq[o.Seq] = opRef{scope: sp, op: o}
			if sp.Mode == syncapi.G2AModeApply && !sp.Blocked {
				applicable[o.Seq] = true
			}
		}
	}
	status := map[int]syncapi.G2AOpResult{}
	out := &Outcome{}
	for _, r := range results {
		ref, ok := bySeq[r.Seq]
		if !ok {
			return nil, &ConfirmError{Message: fmt.Sprintf("operation %d is not in the plan", r.Seq)}
		}
		if r.Status == syncapi.G2AOpDone && !applicable[r.Seq] {
			why := "is in dry-run mode"
			if ref.scope.Blocked {
				why = "exceeds its limits"
			}
			return nil, &ConfirmError{Message: fmt.Sprintf("operation %d: scope %s %s, so it cannot have been applied", r.Seq, ref.scope.Name, why)}
		}
		if r.Status == syncapi.G2AOpDone && ref.op.Kind == syncapi.G2AUserCreate && (r.SID == "" || r.ObjectGUID == "") {
			return nil, &ConfirmError{Message: fmt.Sprintf("operation %d: a done create needs the new account's SID and objectGUID", r.Seq)}
		}
		status[r.Seq] = r
		switch r.Status {
		case syncapi.G2AOpDone:
			out.Done++
		case syncapi.G2AOpFailed:
			out.Failed++
		default:
			out.Skipped++
		}
	}

	key := func(scope, id string) string { return scope + "\x00" + id }
	current := map[string]Link{}
	for _, l := range links {
		current[key(l.Scope, l.GoogleID)] = l
	}
	accounts := map[string]Account{}
	for _, a := range res.Accounts {
		accounts[key(a.Scope, a.GoogleID)] = a
	}
	// Operations of each account, to keep the fields of undone ones out of
	// the snapshot.
	opsOf := map[string][]syncapi.G2AOp{}
	for _, ref := range bySeq {
		k := key(ref.scope.Name, ref.op.GoogleID)
		opsOf[k] = append(opsOf[k], ref.op)
	}
	changed := map[string]Link{}
	for _, k := range sortedKeys(opsOf) {
		ops := opsOf[k]
		sort.Slice(ops, func(i, j int) bool { return ops[i].Seq < ops[j].Seq })
		scope, id, _ := strings.Cut(k, "\x00")
		l, had := current[k]
		if !had {
			l = Link{Scope: scope, GoogleID: id}
		}
		l.Snapshot = maps.Clone(l.Snapshot)
		touched := false
		var undoneFields []string
		for _, o := range ops {
			r, reported := status[o.Seq]
			if !reported || r.Status != syncapi.G2AOpDone {
				for _, c := range o.Changes {
					undoneFields = append(undoneFields, c.Field)
				}
				continue
			}
			touched = true
			switch o.Kind {
			case syncapi.G2AUserCreate:
				l.ObjectGUID, l.SID, l.SAM, l.DisabledBySync = strings.ToLower(r.ObjectGUID), r.SID, o.SAM, false
				l.Snapshot = nil
			case syncapi.G2AUserDisable:
				l.DisabledBySync = l.DisabledBySync || o.Disable
			case syncapi.G2AUserReenable:
				l.DisabledBySync = false
			}
			if o.Kind != syncapi.G2AUserCreate {
				if o.ObjectGUID != "" {
					l.ObjectGUID = strings.ToLower(o.ObjectGUID)
				}
				if o.SID != "" {
					l.SID = o.SID
				}
				if o.SAM != "" {
					l.SAM = o.SAM
				}
			}
		}
		if !touched {
			continue
		}
		if a, ok := accounts[k]; ok {
			snap := maps.Clone(a.Snapshot)
			for _, f := range undoneFields {
				if old, ok := l.Snapshot[f]; ok {
					snap[f] = old
				} else {
					delete(snap, f)
				}
			}
			l.Snapshot = snap
		}
		changed[k] = l
	}
	// Accounts carrying the marker without a link: link them as they are
	// (their fields equal Google's, or an operation above handled them).
	for _, k := range sortedKeys(accounts) {
		a := accounts[k]
		if _, ok := current[k]; ok {
			continue
		}
		if _, ok := changed[k]; ok || a.GUID == "" {
			continue
		}
		if len(opsOf[k]) > 0 {
			continue
		}
		changed[k] = Link{Scope: a.Scope, GoogleID: a.GoogleID, ObjectGUID: strings.ToLower(a.GUID), SID: a.SID, SAM: a.SAM,
			Snapshot: maps.Clone(a.Snapshot)}
	}
	for _, k := range sortedKeys(changed) {
		out.Links = append(out.Links, changed[k])
	}

	allDone := true
	for _, seq := range slices.Sorted(maps.Keys(applicable)) {
		if r, ok := status[seq]; !ok || r.Status != syncapi.G2AOpDone {
			allDone = false
			break
		}
	}
	switch {
	case out.Done == 0 && anyBlocked:
		out.Status = syncapi.StatusBlocked
	case !anyApply:
		out.Status = syncapi.StatusDryRun
	case allDone && out.Failed == 0 && !anyBlocked:
		out.Status = syncapi.StatusApplied
	default:
		out.Status = syncapi.StatusPartial
	}
	return out, nil
}
