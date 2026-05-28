// SPDX-License-Identifier: AGPL-3.0-or-later

package policylang

import (
	"testing"
	"time"

	"github.com/expr-lang/expr"
)

// TestEvaluateGate_RuleOnMismatchSkipped covers engine.go:101 — when a
// rule's On doesn't match the event, the loop continues.
func TestEvaluateGate_RuleOnMismatchSkipped(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "connect-only", On: EventConnect, Match: "true", Actions: []Action{
				{Type: ActionDeny},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Dial event — connect-only rule skipped → fall-through to default allow.
	dirs, err := cp.Evaluate(EventDial, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(dirs) != 1 || dirs[0].Type != DirectiveAllow {
		t.Errorf("dirs = %v, want default allow", dirs)
	}
}

// TestEvaluateGate_EvalErrorPropagates covers engine.go:106 — runProgram
// error bubbles up.
func TestEvaluateGate_EvalErrorPropagates(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "boom", On: EventConnect, Match: `duration("nope") > 0`, Actions: []Action{
				{Type: ActionDeny},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, err := cp.Evaluate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	}); err == nil {
		t.Fatal("expected eval error, got nil")
	}
}

// TestEvaluateGate_SideEffectsAccumulate covers engine.go:128 — a rule with
// only side effects (tag) is accumulated, then the next matching rule's
// verdict + accumulated side effects are returned.
func TestEvaluateGate_SideEffectsAccumulate(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "tag-first", On: EventConnect, Match: "true", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"side"}}},
			}},
			{Name: "deny-second", On: EventConnect, Match: "port == 80", Actions: []Action{
				{Type: ActionDeny},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	dirs, err := cp.Evaluate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	hasTag, hasDeny := false, false
	for _, d := range dirs {
		if d.Type == DirectiveTag {
			hasTag = true
		}
		if d.Type == DirectiveDeny {
			hasDeny = true
		}
	}
	if !hasTag || !hasDeny {
		t.Errorf("dirs = %v, want tag + deny", dirs)
	}
}

// TestEvaluateActions_RuleOnMismatchSkipped covers engine.go:149.
func TestEvaluateActions_RuleOnMismatchSkipped(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "join-only", On: EventJoin, Match: "true", Actions: []Action{
				{Type: ActionLog, Params: map[string]interface{}{"message": "x"}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	dirs, err := cp.Evaluate(EventLeave, map[string]interface{}{
		"peer_id": 1, "network_id": 1,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(dirs) != 0 {
		t.Errorf("dirs = %v, want empty", dirs)
	}
}

// TestEvaluateActions_EvalErrorPropagates covers engine.go:154.
func TestEvaluateActions_EvalErrorPropagates(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "boom", On: EventCycle, Match: `duration("nope") > 0`, Actions: []Action{
				{Type: ActionLog, Params: map[string]interface{}{"message": "x"}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, err := cp.Evaluate(EventCycle, map[string]interface{}{
		"network_id": 1, "members": 0, "peer_count": 0,
		"cycle_num": 0, "trusted_count": 0,
		"peer_id": 0, "peer_tags": []string{}, "peer_age_s": 0.0,
	}); err == nil {
		t.Fatal("expected eval error, got nil")
	}
}

// TestRunProgram_NonBoolResult covers engine.go:246. expr.AsBool() option
// in envOptions forces bool, but a program compiled WITHOUT AsBool can
// return non-bool. Compile bypassing the public Compile() to drive this.
func TestRunProgram_NonBoolResult(t *testing.T) {
	t.Parallel()
	// Compile without AsBool — program returns an int.
	prog, err := expr.Compile(`1 + 1`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ok, err := runProgram(prog, map[string]interface{}{})
	if err == nil {
		t.Fatalf("expected non-bool error, got ok=%v", ok)
	}
}

// TestRunProgram_PanicRecovered drives the defer-recover branch
// (engine.go:233). We construct an expr program that's likely to panic
// at runtime — index past end of a typed slice. If it doesn't panic in
// this expr version we still confirm no crash.
func TestRunProgram_PanicRecovered(t *testing.T) {
	t.Parallel()
	prog, err := expr.Compile(`Foo[10]`,
		expr.Env(map[string]interface{}{"Foo": []int{}}),
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BUG: runProgram propagated panic: %v", r)
		}
	}()
	_, _ = runProgram(prog, map[string]interface{}{"Foo": []int{}})
}

// TestValidate_PropagatesValidateActionError covers policy.go:170 — the
// only path where validateAction's error is returned up the call stack.
func TestValidate_PropagatesValidateActionError(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "bad", On: EventConnect, Match: "true", Actions: []Action{
				{Type: ActionTag}, // missing add/remove
			}},
		},
	}
	if err := Validate(doc); err == nil {
		t.Fatal("expected validateAction error propagation")
	}
}

// TestRunProgram_HappyPath covers the normal expr.Run path end-to-end for
// determinism (also a sanity net for the runProgram time.After case).
func TestRunProgram_HappyPath(t *testing.T) {
	t.Parallel()
	prog, err := expr.Compile(`x > 0`,
		expr.AsBool(),
		expr.Env(map[string]interface{}{"x": 0}),
	)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	start := time.Now()
	ok, err := runProgram(prog, map[string]interface{}{"x": 5})
	if err != nil {
		t.Fatalf("runProgram: %v", err)
	}
	if !ok {
		t.Error("want true")
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Errorf("runProgram took %v, expected <50ms", time.Since(start))
	}
}
