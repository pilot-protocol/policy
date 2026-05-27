// SPDX-License-Identifier: AGPL-3.0-or-later

package policylang

import (
	"strings"
	"testing"
)

// Helper: minimal valid policy doc with one allow-on-connect rule.
func minimalDoc() *PolicyDocument {
	return &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:    "allow-all",
				On:      EventConnect,
				Match:   "true",
				Actions: []Action{{Type: ActionAllow}},
			},
		},
	}
}

// TestIsGateEvent covers the gate-vs-action lookup.
func TestIsGateEvent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   EventType
		want bool
	}{
		{EventConnect, true},
		{EventDial, true},
		{EventDatagram, true},
		{EventCycle, false},
		{EventJoin, false},
		{EventLeave, false},
		{EventType("unknown"), false},
	}
	for _, tc := range cases {
		if got := IsGateEvent(tc.in); got != tc.want {
			t.Errorf("IsGateEvent(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestValidate_Branches drives every error branch of Validate.
func TestValidate_Branches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		mutate  func(*PolicyDocument)
		wantErr string
	}{
		{
			name:    "bad_version",
			mutate:  func(d *PolicyDocument) { d.Version = 99 },
			wantErr: "unsupported version",
		},
		{
			name:    "bad_default_verdict",
			mutate:  func(d *PolicyDocument) { d.DefaultVerdict = "maybe" },
			wantErr: "default_verdict must be",
		},
		{
			name:    "empty_rules",
			mutate:  func(d *PolicyDocument) { d.Rules = nil },
			wantErr: "at least one rule",
		},
		{
			name:    "missing_name",
			mutate:  func(d *PolicyDocument) { d.Rules[0].Name = "" },
			wantErr: "name is required",
		},
		{
			name: "duplicate_name",
			mutate: func(d *PolicyDocument) {
				d.Rules = append(d.Rules, d.Rules[0])
			},
			wantErr: "duplicate rule name",
		},
		{
			name:    "unknown_event",
			mutate:  func(d *PolicyDocument) { d.Rules[0].On = EventType("explode") },
			wantErr: "unknown event type",
		},
		{
			name:    "missing_match",
			mutate:  func(d *PolicyDocument) { d.Rules[0].Match = "" },
			wantErr: "match expression is required",
		},
		{
			name:    "no_actions",
			mutate:  func(d *PolicyDocument) { d.Rules[0].Actions = nil },
			wantErr: "at least one action",
		},
		{
			name: "bad_cycle_type",
			mutate: func(d *PolicyDocument) {
				d.Config = map[string]interface{}{"cycle": 42}
			},
			wantErr: "config.cycle must be a string",
		},
		{
			name: "bad_cycle_duration",
			mutate: func(d *PolicyDocument) {
				d.Config = map[string]interface{}{"cycle": "not-a-duration"}
			},
			wantErr: "config.cycle",
		},
		{
			name: "cycle_too_short",
			mutate: func(d *PolicyDocument) {
				d.Config = map[string]interface{}{"cycle": "100ms"}
			},
			wantErr: ">= 1s",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := minimalDoc()
			tc.mutate(doc)
			err := Validate(doc)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestValidate_AllowedDefaultVerdicts covers the empty/"allow"/"deny"
// cases that should pass.
func TestValidate_AllowedDefaultVerdicts(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"", "allow", "deny"} {
		doc := minimalDoc()
		doc.DefaultVerdict = v
		if err := Validate(doc); err != nil {
			t.Errorf("default_verdict=%q should validate: %v", v, err)
		}
	}
}

// TestParse_HappyAndErrors exercises both branches of Parse.
func TestParse_HappyAndErrors(t *testing.T) {
	t.Parallel()

	good := `{"version":1,"rules":[{"name":"r","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if _, err := Parse([]byte("{not json")); err == nil {
		t.Error("expected JSON parse error")
	}

	// Valid JSON but fails validation (wrong version).
	bad := `{"version":99,"rules":[]}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Error("expected validation error")
	}
}

// TestCompile_HappyAndErrors covers the compile path.
func TestCompile_HappyAndErrors(t *testing.T) {
	t.Parallel()

	cp, err := Compile(minimalDoc())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if cp.RuleCount() != 1 {
		t.Errorf("RuleCount = %d, want 1", cp.RuleCount())
	}
	if cp.PeerProgramCount() != 0 {
		t.Errorf("PeerProgramCount = %d, want 0", cp.PeerProgramCount())
	}
	if !cp.HasRulesFor(EventConnect) {
		t.Error("HasRulesFor(connect): want true")
	}
	if cp.HasRulesFor(EventLeave) {
		t.Error("HasRulesFor(leave): want false")
	}

	// Bad expr → Compile error.
	doc := minimalDoc()
	doc.Rules[0].Match = "not a valid && expr ||"
	if _, err := Compile(doc); err == nil {
		t.Error("expected compile error on bad expression")
	}

	// Bad config → Validate error propagated from Compile.
	doc2 := minimalDoc()
	doc2.Version = 99
	if _, err := Compile(doc2); err == nil {
		t.Error("expected validation error from Compile")
	}
}

// TestCompile_EvictWherePeerProgram exercises the per-action peer
// sub-expression compilation path.
func TestCompile_EvictWherePeerProgram(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:  "evict-stale",
				On:    EventCycle,
				Match: "true",
				Actions: []Action{
					{Type: ActionEvictWhere, Params: map[string]interface{}{"match": "true"}},
				},
			},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if cp.PeerProgramCount() != 1 {
		t.Errorf("PeerProgramCount = %d, want 1", cp.PeerProgramCount())
	}

	// Evaluate the per-peer expression.
	matched, err := cp.EvaluatePeerExpr("evict-stale", 0, map[string]interface{}{})
	if err != nil {
		t.Fatalf("EvaluatePeerExpr: %v", err)
	}
	if !matched {
		t.Error("expected true verdict")
	}

	// Unknown rule/action lookup must error.
	if _, err := cp.EvaluatePeerExpr("nope", 0, nil); err == nil {
		t.Error("expected error for unknown peer expression")
	}
}

// TestCompile_EvictWhereInvalidPeerExpr exercises the per-action
// compilation-error branch.
func TestCompile_EvictWhereInvalidPeerExpr(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:  "bad-peer",
				On:    EventCycle,
				Match: "true",
				Actions: []Action{
					{Type: ActionEvictWhere, Params: map[string]interface{}{"match": "&&&"}},
				},
			},
		},
	}
	if _, err := Compile(doc); err == nil {
		t.Error("expected compile error from bad peer expression")
	}
}

// TestCompile_EvictWhereMatchNotString exercises the type-assertion
// error path inside Compile.
func TestCompile_EvictWhereMatchNotString(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:  "bad",
				On:    EventCycle,
				Match: "true",
				Actions: []Action{
					{Type: ActionEvictWhere, Params: map[string]interface{}{"match": 42}},
				},
			},
		},
	}
	_, err := Compile(doc)
	if err == nil {
		t.Error("expected error when match is not a string")
	}
}

// TestEvaluate_GateAllowDenyAndDefault exercises evaluateGate's branches.
func TestEvaluate_GateAllowDenyAndDefault(t *testing.T) {
	t.Parallel()

	// Rule denies; verdict returned.
	doc := minimalDoc()
	doc.Rules[0].Actions = []Action{{Type: ActionDeny}}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	dirs, err := cp.Evaluate(EventConnect, map[string]interface{}{"port": uint16(80)})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Should contain a Deny directive.
	foundDeny := false
	for _, d := range dirs {
		if d.Type == DirectiveDeny {
			foundDeny = true
		}
	}
	if !foundDeny {
		t.Errorf("expected Deny directive, got %+v", dirs)
	}

	// No matching rule → default allow.
	doc = minimalDoc()
	doc.Rules[0].Match = "false"
	cp, err = Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	dirs, err = cp.Evaluate(EventConnect, map[string]interface{}{"port": uint16(80)})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(dirs) == 0 || dirs[len(dirs)-1].Type != DirectiveAllow {
		t.Errorf("expected default Allow tail directive, got %+v", dirs)
	}

	// default_verdict deny.
	doc = minimalDoc()
	doc.DefaultVerdict = "deny"
	doc.Rules[0].Match = "false"
	cp, err = Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	dirs, _ = cp.Evaluate(EventConnect, map[string]interface{}{"port": uint16(80)})
	if len(dirs) == 0 || dirs[len(dirs)-1].Type != DirectiveDeny {
		t.Errorf("expected default Deny, got %+v", dirs)
	}
}

// TestEvaluate_ActionEventAggregates exercises evaluateActions.
func TestEvaluate_ActionEventAggregates(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:    "log-cycle",
				On:      EventCycle,
				Match:   "true",
				Actions: []Action{{Type: ActionLog, Params: map[string]interface{}{"message": "tick"}}},
			},
			{
				Name:    "noop-cycle",
				On:      EventCycle,
				Match:   "false",
				Actions: []Action{{Type: ActionLog, Params: map[string]interface{}{"message": "skip"}}},
			},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	dirs, err := cp.Evaluate(EventCycle, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(dirs) != 1 {
		t.Errorf("expected 1 directive (only matching rule), got %d", len(dirs))
	}
	if dirs[0].Rule != "log-cycle" {
		t.Errorf("rule = %q, want log-cycle", dirs[0].Rule)
	}
}


// TestCycleDuration_AllBranches drives CycleDuration's two-key path.
func TestCycleDuration_AllBranches(t *testing.T) {
	t.Parallel()
	cp := &CompiledPolicy{Doc: PolicyDocument{Config: nil}}
	if dur, grace := cp.CycleDuration(); dur != "" || grace != "" {
		t.Errorf("nil config: got (%q, %q), want empty", dur, grace)
	}

	cp = &CompiledPolicy{Doc: PolicyDocument{Config: map[string]interface{}{
		"cycle": "1m",
		"grace": "10s",
	}}}
	if dur, grace := cp.CycleDuration(); dur != "1m" || grace != "10s" {
		t.Errorf("got (%q, %q), want (1m, 10s)", dur, grace)
	}
}

// TestToDirectives_UnknownActionSkipped exercises the unknown-action
// branch (no panic, just skipped).
func TestToDirectives_UnknownActionSkipped(t *testing.T) {
	t.Parallel()
	r := Rule{
		Name: "mixed",
		Actions: []Action{
			{Type: ActionAllow},
			{Type: ActionType("unknown-action")},
			{Type: ActionLog, Params: map[string]interface{}{"message": "hi"}},
		},
	}
	got := toDirectives(r)
	if len(got) != 2 {
		t.Errorf("got %d directives, want 2 (unknown skipped): %+v", len(got), got)
	}
}
