package fakegoogle

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
)

// The fake normally lives in memory. tools/fakegws can keep its key and
// its directory across restarts (the persistent test environment), with
// SetKey and MarshalState / LoadState.

// SetKey replaces the service account key (to keep the key of an earlier
// run, so a key already uploaded to conductor-sync stays valid).
func (s *Server) SetKey(k *rsa.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = k
}

type groupState struct {
	Group
	Members map[string]*Member `json:"members"`
}

type state struct {
	Users    map[string]*User       `json:"users"`
	Groups   map[string]*groupState `json:"groups"`
	OrgUnits map[string]bool        `json:"org_units"`
	NextID   int                    `json:"next_id"`
}

// MarshalState returns users, groups (with members), org units and the ID
// counter as JSON. Faults, recorded writes and tokens are not kept.
func (s *Server) MarshalState() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := state{Users: s.users, Groups: map[string]*groupState{}, OrgUnits: s.orgUnits, NextID: s.nextID}
	for id, g := range s.groups {
		st.Groups[id] = &groupState{Group: *g, Members: g.members}
	}
	return json.Marshal(st)
}

// LoadState replaces the directory with a MarshalState result.
func (s *Server) LoadState(b []byte) error {
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if st.Users == nil || st.Groups == nil {
		return errors.New("fakegoogle: not a state file")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = st.Users
	s.groups = map[string]*Group{}
	for id, g := range st.Groups {
		c := g.Group
		c.members = g.Members
		if c.members == nil {
			c.members = map[string]*Member{}
		}
		s.groups[id] = &c
	}
	for ou := range st.OrgUnits {
		s.orgUnits[ou] = true
	}
	if st.NextID > s.nextID {
		s.nextID = st.NextID
	}
	return nil
}
