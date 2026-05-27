// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"testing"
)

// TestAliasesExports exercises the package's Validate and IsGateEvent
// wrapper re-exports.
func TestAliasesExports(t *testing.T) {
	t.Parallel()
	good := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:    "r",
				On:      EventConnect,
				Match:   "true",
				Actions: []Action{{Type: ActionAllow}},
			},
		},
	}
	if err := Validate(good); err != nil {
		t.Errorf("Validate(good): %v", err)
	}

	bad := &PolicyDocument{Version: 99}
	if err := Validate(bad); err == nil {
		t.Error("Validate(bad): want error")
	}

	if !IsGateEvent(EventConnect) {
		t.Error("IsGateEvent(connect): want true")
	}
	if IsGateEvent(EventLeave) {
		t.Error("IsGateEvent(leave): want false")
	}
}

// TestPolicyRunner_PolicyAndPolicyJSON exercises the Policy and
// PolicyJSON accessors.
func TestPolicyRunner_PolicyAndPolicyJSON(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := &PolicyRunner{netID: 5, compiled: cp}

	if got := pr.Policy(); got != cp {
		t.Errorf("Policy() = %v, want %v", got, cp)
	}

	body, err := pr.PolicyJSON()
	if err != nil {
		t.Fatalf("PolicyJSON: %v", err)
	}
	if len(body) == 0 {
		t.Error("PolicyJSON returned empty")
	}

	// nil compiled → returns (nil, nil).
	pr2 := &PolicyRunner{}
	body, err = pr2.PolicyJSON()
	if err != nil || body != nil {
		t.Errorf("PolicyJSON on nil compiled: (%v, %v); want (nil, nil)", body, err)
	}
}

// TestPolicyRunner_NetworkIDAndHasMember exercises the accessor + peer
// lookup.
func TestPolicyRunner_NetworkIDAndHasMember(t *testing.T) {
	t.Parallel()
	pr := &PolicyRunner{
		netID: 7,
		peers: map[uint32]*managedPeer{0xCAFE: {NodeID: 0xCAFE}},
	}
	if got := pr.NetworkID(); got != 7 {
		t.Errorf("NetworkID = %d, want 7", got)
	}
	if !pr.HasMember(0xCAFE) {
		t.Error("HasMember(0xCAFE): want true")
	}
	if pr.HasMember(0xDEAD) {
		t.Error("HasMember(0xDEAD): want false")
	}
}

// TestMergeTags drives every branch in mergeTags.
func TestMergeTags(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		a, b   []string
		want   []string
	}{
		{"both empty", nil, nil, []string{}},
		{"only a", []string{"x", "y"}, nil, []string{"x", "y"}},
		{"only b", nil, []string{"x"}, []string{"x"}},
		{"dedup", []string{"x", "y"}, []string{"y", "z"}, []string{"x", "y", "z"}},
		{"dups within a", []string{"x", "x"}, nil, []string{"x"}},
	}
	for _, tc := range cases {
		got := mergeTags(tc.a, tc.b)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}

// TestPolicyRunner_EvaluatePortGate_DriveCtxBuilders exercises the
// per-event ctx population (peer_age_s, members, size, direction).
func TestPolicyRunner_EvaluatePortGate_AllEvents(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			0x1234: {NodeID: 0x1234},
		},
	}

	// EventConnect — port 80 hits the allow rule → true.
	if !pr.EvaluatePortGate(EventConnect, 80, 0x1234, 0, "in", []string{"a"}, []string{"b"}) {
		t.Error("EventConnect port=80: want allow")
	}
	// EventConnect — port 99 hits deny-all → false.
	if pr.EvaluatePortGate(EventConnect, 99, 0x1234, 0, "out", nil, nil) {
		t.Error("EventConnect port=99: want deny")
	}
	// EventDial — no rules for dial in the test policy → default allow.
	if !pr.EvaluatePortGate(EventDial, 99, 0x1234, 0, "out", nil, nil) {
		t.Error("EventDial: no matching rule → want default allow")
	}
	// EventDatagram — sets size + direction in ctx; just verify no panic.
	_ = pr.EvaluatePortGate(EventDatagram, 80, 0x1234, 1024, "in", nil, nil)
}
