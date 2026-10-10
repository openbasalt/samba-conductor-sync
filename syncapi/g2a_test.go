package syncapi

import (
	"strings"
	"testing"
)

func TestG2AParams(t *testing.T) {
	actor := Actor{User: "lab.admin", SID: "S-1-5-21-1-2-3-1104", Session: "sess1234"}
	digest := strings.Repeat("a", 64)
	good := []Params{
		G2APlanParams{},
		G2APlanParams{Scope: "people", RoleGroupSIDs: []string{"S-1-5-21-1-2-3-1600"}},
		G2AConfirmParams{RunID: 1, Digest: digest, Actor: "lab.admin", Results: []G2AOpResult{{Seq: 0, Status: G2AOpDone,
			SID: "S-1-5-21-1-2-3-2000", ObjectGUID: "00000000-0000-4000-8000-000000000001"}, {Seq: 1, Status: G2AOpFailed, Error: "conflict"}}},
	}
	for _, p := range good {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := []Params{
		G2APlanParams{Scope: "People!"},
		G2APlanParams{RoleGroupSIDs: []string{"Domain Admins"}},
		G2AConfirmParams{RunID: 0, Digest: digest, Actor: "a"},
		G2AConfirmParams{RunID: 1, Digest: "short", Actor: "a"},
		G2AConfirmParams{RunID: 1, Digest: digest},
		G2AConfirmParams{RunID: 1, Digest: digest, Actor: "a", Results: []G2AOpResult{{Seq: 0, Status: G2AOpDone}, {Seq: 0, Status: G2AOpDone}}},
		G2AConfirmParams{RunID: 1, Digest: digest, Actor: "a", Results: []G2AOpResult{{Seq: 0, Status: "maybe"}}},
		G2AConfirmParams{RunID: 1, Digest: digest, Actor: "a", Results: []G2AOpResult{{Seq: 0, Status: G2AOpDone, ObjectGUID: "x"}}},
	}
	for _, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("accepted %+v", p)
		}
	}
	if !OpG2APlan.Mutating() || !OpG2AConfirm.Mutating() {
		t.Fatal("g2a operations record runs and links: they are mutations")
	}
	if _, err := NewRequest("req-00000001", OpG2APlan, actor, G2APlanParams{Scope: "people"}); err != nil {
		t.Fatal(err)
	}
	if G2AMarker("123") != "google-first:123" {
		t.Fatal("marker")
	}
}
