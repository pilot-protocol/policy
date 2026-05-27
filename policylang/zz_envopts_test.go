// SPDX-License-Identifier: AGPL-3.0-or-later

package policylang

import "testing"

// TestEnvOptions_CoversEveryEventType verifies that every EventType
// produces a valid expr.Option slice — exercises every case in the
// switch.
func TestEnvOptions_CoversEveryEventType(t *testing.T) {
	t.Parallel()
	for _, ev := range []EventType{
		EventConnect, EventDial, EventDatagram,
		EventCycle, EventJoin, EventLeave,
		EventType("unknown"),
	} {
		opts := envOptions(ev)
		if len(opts) == 0 {
			t.Errorf("envOptions(%q) returned empty slice", ev)
		}
	}
}

// TestEnvOptions_CompileForDial drives the EventDial branch
// through a real Compile so the env vars are validated.
func TestEnvOptions_CompileForDial(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:    "dial-rule",
				On:      EventDial,
				Match:   "port == 443 && sender_rating > 0.5",
				Actions: []Action{{Type: ActionAllow}},
			},
		},
	}
	if _, err := Compile(doc); err != nil {
		t.Errorf("Compile dial: %v", err)
	}
}

// TestEnvOptions_CompileForDatagram drives the EventDatagram branch.
func TestEnvOptions_CompileForDatagram(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:    "datagram-rule",
				On:      EventDatagram,
				Match:   `direction == "in" && size > 0`,
				Actions: []Action{{Type: ActionAllow}},
			},
		},
	}
	if _, err := Compile(doc); err != nil {
		t.Errorf("Compile datagram: %v", err)
	}
}

// TestEnvOptions_CompileForJoinAndLeave drives EventJoin/EventLeave.
func TestEnvOptions_CompileForJoinAndLeave(t *testing.T) {
	t.Parallel()
	for _, ev := range []EventType{EventJoin, EventLeave} {
		doc := &PolicyDocument{
			Version: 1,
			Rules: []Rule{
				{
					Name:    "rule",
					On:      ev,
					Match:   "peer_id > 0",
					Actions: []Action{{Type: ActionLog, Params: map[string]interface{}{"message": "x"}}},
				},
			},
		}
		if _, err := Compile(doc); err != nil {
			t.Errorf("Compile %q: %v", ev, err)
		}
	}
}

// TestEnvOptions_CompileForCycleUsesCycleVars drives EventCycle vars.
func TestEnvOptions_CompileForCycleUsesCycleVars(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:    "cycle-rule",
				On:      EventCycle,
				Match:   "cycle_num > 0 && trusted_count >= 0",
				Actions: []Action{{Type: ActionLog, Params: map[string]interface{}{"message": "tick"}}},
			},
		},
	}
	if _, err := Compile(doc); err != nil {
		t.Errorf("Compile cycle: %v", err)
	}
}

// TestBaseEnv covers the helper.
func TestBaseEnv(t *testing.T) {
	t.Parallel()
	env := baseEnv()
	if _, ok := env["local_tags"]; !ok {
		t.Error("local_tags missing from baseEnv")
	}
}
