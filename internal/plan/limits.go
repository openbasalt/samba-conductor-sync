package plan

import (
	"fmt"
	"sort"
)

// Unlimited disables one limit. Zero means "none allowed", so a limit can
// forbid a kind of change in scheduled runs altogether.
const Unlimited = -1

// Limits bound what a scheduled run may change. A plan outside them is not
// applied: the run stops, records the plan as blocked and alerts. A manual
// apply can override them explicitly.
type Limits struct {
	MaxCreates           int `toml:"max_creates"`
	MaxSuspends          int `toml:"max_suspends"`
	MaxUnsuspends        int `toml:"max_unsuspends"`
	MaxRenames           int `toml:"max_renames"`
	MaxUpdates           int `toml:"max_updates"`
	MaxGroupChanges      int `toml:"max_group_changes"`
	MaxMembershipChanges int `toml:"max_membership_changes"`
	// MaxTouchedPercent bounds the share of managed users whose existing
	// account changes (update, rename, suspend, unsuspend); creates are
	// bounded by MaxCreates. Unlimited (-1) disables it.
	MaxTouchedPercent float64 `toml:"max_touched_percent"`
	// MinSourceUsers refuses a source that returned fewer users (an empty
	// or broken scope must never look like "everybody left").
	MinSourceUsers int `toml:"min_source_users"`
	// MaxSourceDropPercent refuses a source that shrank by more than this
	// since the last applied run.
	MaxSourceDropPercent float64 `toml:"max_source_drop_percent"`
}

// DefaultLimits are conservative: a scheduled run handles day-to-day
// changes; anything bigger (the first sync, a reorganization) is applied
// by hand after review.
func DefaultLimits() Limits {
	return Limits{
		MaxCreates:           50,
		MaxSuspends:          10,
		MaxUnsuspends:        50,
		MaxRenames:           10,
		MaxUpdates:           500,
		MaxGroupChanges:      20,
		MaxMembershipChanges: 1000,
		MaxTouchedPercent:    10,
		MinSourceUsers:       1,
		MaxSourceDropPercent: 10,
	}
}

// Violation is one limit a plan exceeds.
type Violation struct {
	Limit string  `json:"limit"`
	Value float64 `json:"value"`
	Max   float64 `json:"max"`
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %g exceeds %g", v.Limit, v.Value, v.Max)
}

// Check returns the limits the plan exceeds. previousSourceUsers is the
// source size of the last applied run (0 when there is none).
func (l Limits) Check(p *Plan, previousSourceUsers int) []Violation {
	c := p.Counts()
	var out []Violation
	check := func(name string, value, max int) {
		if max != Unlimited && value > max {
			out = append(out, Violation{Limit: name, Value: float64(value), Max: float64(max)})
		}
	}
	check("max_creates", c[UserCreate], l.MaxCreates)
	check("max_suspends", c[UserSuspend], l.MaxSuspends)
	check("max_unsuspends", c[UserUnsuspend], l.MaxUnsuspends)
	check("max_renames", c[UserRename], l.MaxRenames)
	check("max_updates", c[UserUpdate]+c[UserAdopt], l.MaxUpdates)
	check("max_group_changes", c[GroupCreate]+c[GroupUpdate]+c[GroupAdopt], l.MaxGroupChanges)
	check("max_membership_changes", c[MemberAdd]+c[MemberRemove], l.MaxMembershipChanges)

	if l.MaxTouchedPercent != Unlimited && l.MaxTouchedPercent >= 0 && p.ManagedUsers > 0 {
		touched := map[string]bool{}
		for _, o := range p.Ops {
			switch o.Kind {
			case UserUpdate, UserRename, UserSuspend, UserUnsuspend, UserAdopt:
				touched[o.TargetID] = true
			}
		}
		pct := 100 * float64(len(touched)) / float64(p.ManagedUsers)
		if pct > l.MaxTouchedPercent {
			out = append(out, Violation{Limit: "max_touched_percent", Value: round1(pct), Max: l.MaxTouchedPercent})
		}
	}
	if l.MinSourceUsers != Unlimited && p.SourceUsers < l.MinSourceUsers {
		out = append(out, Violation{Limit: "min_source_users", Value: float64(p.SourceUsers), Max: float64(l.MinSourceUsers)})
	}
	if l.MaxSourceDropPercent != Unlimited && l.MaxSourceDropPercent >= 0 && previousSourceUsers > 0 && p.SourceUsers < previousSourceUsers {
		drop := 100 * float64(previousSourceUsers-p.SourceUsers) / float64(previousSourceUsers)
		if drop > l.MaxSourceDropPercent {
			out = append(out, Violation{Limit: "max_source_drop_percent", Value: round1(drop), Max: l.MaxSourceDropPercent})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Limit < out[j].Limit })
	return out
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
