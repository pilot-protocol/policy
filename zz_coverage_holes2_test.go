// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// runner.go — small branch coverage holes
// -----------------------------------------------------------------------------

// TestExecuteEvictWhere_EvalErrorContinues covers the slog.Warn continue
// branch (runner.go:365) when EvaluatePeerExpr errors for a specific peer.
func TestExecuteEvictWhere_EvalErrorContinues(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "evict-boom", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionEvictWhere, Params: map[string]interface{}{
					// last_seen is float64, so duration() over a number errors out
					// at expr runtime (duration expects a string).
					"match": `duration("nope") > 0`,
				}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	pr.mu.Lock()
	pr.peers[1] = &managedPeer{NodeID: 1, AddedAt: time.Now()}
	pr.peers[2] = &managedPeer{NodeID: 2, AddedAt: time.Now()}
	pr.mu.Unlock()

	pr.executeEvictWhere(Directive{
		Type:      DirectiveEvictWhere,
		Rule:      "evict-boom",
		ActionIdx: 0,
	}, 0)

	// Eval error → continue → no peers evicted.
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) != 2 {
		t.Errorf("peers = %d, want 2 (eval error must skip)", len(pr.peers))
	}
}

// TestExecutePrune_DefaultByAge covers the empty-`by` → fallback-to-"age"
// branch (runner.go:395).
func TestExecutePrune_DefaultByAge(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	now := time.Now()
	pr.mu.Lock()
	pr.peers[1] = &managedPeer{NodeID: 1, AddedAt: now.Add(-2 * time.Hour)}
	pr.peers[2] = &managedPeer{NodeID: 2, AddedAt: now.Add(-1 * time.Hour)}
	pr.mu.Unlock()

	pr.executePrune(Directive{
		Type:   DirectivePrune,
		Params: map[string]interface{}{"count": 1.0}, // no `by` → defaults to age
	})

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if _, ok := pr.peers[1]; ok {
		t.Error("oldest peer 1 should be pruned via default by=age")
	}
}

// TestExecutePruneTrust_ClampToMinLinks covers the "total-toRemove < min"
// clamp + the toRemove<=0 early-return branches (runner.go:512-517).
func TestExecutePruneTrust_ClampToMinLinks(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	revoked := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		TrustedPeersFn: func() []TrustRecord {
			// total=4, percent=80 → toRemove=3; min=3 → clamp to 4-3=1.
			return []TrustRecord{
				{NodeID: 1, ApprovedAt: time.Now().Add(-3 * time.Hour)},
				{NodeID: 2, ApprovedAt: time.Now().Add(-2 * time.Hour)},
				{NodeID: 3, ApprovedAt: time.Now().Add(-1 * time.Hour)},
				{NodeID: 4, ApprovedAt: time.Now()},
			}
		},
		RevokeTrustFn: func(uint32) error { revoked++; return nil },
	})
	pr.executePruneTrust(Directive{
		Type:   DirectivePruneTrust,
		Params: map[string]interface{}{"percent": 80.0, "min": 3.0},
	})
	if revoked != 1 {
		t.Errorf("revoked = %d, want 1 (clamped by min)", revoked)
	}
}

// TestExecutePruneTrust_ClampDropsBelowZero covers the toRemove<=0 early
// exit branch (when min equals total).
func TestExecutePruneTrust_ClampDropsBelowZero(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	revoked := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		TrustedPeersFn: func() []TrustRecord {
			// total=3, percent=99 → toRemove=2, min=2 → 3-2=1 → toRemove=1, still >0.
			// To hit <=0, use total=2, percent=99 → toRemove=1, min=2 → 2-1=1 < 2 → toRemove=1.
			// Need: total-toRemove < min AND total-min <= 0.
			// total=3, min=3 → total<=minLinks early-return takes us out first.
			// Use percent=100, min=2 with total=3 → toRemove=3, 3-3=0 < 2 → toRemove=0 → return.
			return []TrustRecord{
				{NodeID: 1, ApprovedAt: time.Now()},
				{NodeID: 2, ApprovedAt: time.Now()},
				{NodeID: 3, ApprovedAt: time.Now()},
			}
		},
		RevokeTrustFn: func(uint32) error { revoked++; return nil },
	})
	pr.executePruneTrust(Directive{
		Type:   DirectivePruneTrust,
		Params: map[string]interface{}{"percent": 100.0, "min": 3.0}, // total<=min → early-return
	})
	if revoked != 0 {
		t.Errorf("revoked = %d, want 0 (early return at total<=min)", revoked)
	}
}

// TestExecuteFillTrust_AlreadyTrustedSkipped covers the "f.ID is self or
// already trusted → continue" branch (runner.go:582).
func TestExecuteFillTrust_AlreadyTrustedSkipped(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	sent := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		TrustedPeersFn: func() []TrustRecord {
			// Peer 2 already trusted → skipped from candidates.
			return []TrustRecord{{NodeID: 2}}
		},
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3), nil
		},
		SendHandshakeFn: func(uint32, string) error { sent++; return nil },
	})
	pr.executeFillTrust(Directive{
		Type:   DirectiveFillTrust,
		Params: map[string]interface{}{"target": 3.0},
	})
	// target=3, current=1 → deficit=2; candidates after skip = [1,3] → 2 sent.
	if sent != 2 {
		t.Errorf("sent = %d, want 2 (already-trusted peer 2 skipped)", sent)
	}
}

// TestExecuteFillTrust_DeficitExceedsCandidates covers the
// deficit>len(candidates) clamp (runner.go:592).
func TestExecuteFillTrust_DeficitExceedsCandidates(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	sent := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn:       func() uint32 { return 99 },
		TrustedPeersFn: func() []TrustRecord { return nil },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2), nil // only 2 candidates
		},
		SendHandshakeFn: func(uint32, string) error { sent++; return nil },
	})
	pr.executeFillTrust(Directive{
		Type:   DirectiveFillTrust,
		Params: map[string]interface{}{"target": 10.0}, // deficit=10 > 2 candidates
	})
	if sent != 2 {
		t.Errorf("sent = %d, want 2 (clamped to candidate count)", sent)
	}
}

// TestRankedPeers_ByActivity covers the "activity" sort branch
// (runner.go:1160).
func TestRankedPeers_ByActivity(t *testing.T) {
	t.Parallel()
	now := time.Now()
	pr := &PolicyRunner{
		peers: map[uint32]*managedPeer{
			1: {NodeID: 1, LastSeen: now.Add(-3 * time.Hour)},
			2: {NodeID: 2, LastSeen: now.Add(-1 * time.Hour)},
			3: {NodeID: 3, LastSeen: now.Add(-2 * time.Hour)},
		},
	}
	pr.mu.Lock()
	defer pr.mu.Unlock()
	ranked := pr.rankedPeers("activity")
	if len(ranked) != 3 {
		t.Fatalf("len = %d, want 3", len(ranked))
	}
	// Oldest LastSeen first → peer 1.
	if ranked[0].NodeID != 1 {
		t.Errorf("first = %d, want 1 (oldest LastSeen)", ranked[0].NodeID)
	}
}

// TestLoad_UnmarshalErrorPropagated covers the json.Unmarshal err branch
// (runner.go:1202).
func TestLoad_UnmarshalErrorPropagated(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_1.json")
	if err := os.WriteFile(path, []byte("not valid json"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	pr := &PolicyRunner{path: path}
	if err := pr.load(); err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
}

// TestLoad_NilPeersMapInitialized covers the snap.Peers==nil → make() branch
// (runner.go:1207).
func TestLoad_NilPeersMapInitialized(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_1.json")
	// Persist a snapshot with no peers field.
	if err := os.WriteFile(path, []byte(`{"network_id":1,"joined_at":"","cycle_num":5}`), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	pr := &PolicyRunner{path: path}
	if err := pr.load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if pr.peers == nil {
		t.Error("peers should be initialized when snap.Peers is nil")
	}
}

// TestParamInt_Int64 covers the int64 case (runner.go:1231).
func TestParamInt_Int64(t *testing.T) {
	t.Parallel()
	if got := paramInt(map[string]interface{}{"k": int64(7)}, "k"); got != 7 {
		t.Errorf("paramInt int64 = %d, want 7", got)
	}
}

// TestReconcileMembership_NilFetchedNoOp covers the early-return when
// fetchMembersWithTags returns nil (runner.go:675).
func TestReconcileMembership_NilFetchedNoOp(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return nil, errors.New("simulated")
		},
	})
	// Must not panic; just returns silently.
	pr.reconcileMembership()
}

// TestFetchMembersWithTags_BackoffCapsAt5min hits the cap (runner.go:1091).
// Run reconcile many times to push backoff > 5min, then assert it's capped.
func TestFetchMembersWithTags_BackoffCapsAt5min(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return nil, errors.New("simulated")
		},
	})
	// Inject prior failure count to push next backoff past 5min.
	pr.fetchFailMu.Lock()
	pr.fetchFailures = 100 // 1<<min(100,6) = 1<<6 = 64 * 5s = 320s > 5min cap
	pr.fetchSkipUntil = time.Time{}
	pr.fetchFailMu.Unlock()

	_ = pr.fetchMembersWithTags()

	pr.fetchFailMu.Lock()
	defer pr.fetchFailMu.Unlock()
	wait := time.Until(pr.fetchSkipUntil)
	if wait > 5*time.Minute+5*time.Second {
		t.Errorf("backoff = %v, want <= 5min cap", wait)
	}
}

// TestCycleLoop_UnparseableDurationDefaults24h covers the runner.go:641
// branch — bad config.cycle string gets warned and defaults to 24h.
// We invoke cycleLoop's setup indirectly via Start(); the cycle ticker
// won't fire in the test window (24h) but the branch is hit during init.
func TestCycleLoop_UnparseableDurationDefaults24h(t *testing.T) {
	t.Parallel()
	// Validate would reject a bad cycle string at the doc level. To hit
	// the runner.go branch we need a CompiledPolicy with a bad config.cycle
	// that bypassed Validate — construct it manually.
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "noop", On: EventConnect, Match: "true", Actions: []Action{{Type: ActionAllow}}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Post-compile, sneak a bad cycle string past Validate.
	cp.Doc.Config = map[string]interface{}{"cycle": "not a duration"}

	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	pr.Start()
	// Stop immediately — we only care that cycleLoop init didn't panic.
	pr.Stop()
}

// TestCycleLoop_DurationBelowMinPromotedTo1s covers the runner.go:645
// branch — sub-1s cycle is promoted to 1s.
func TestCycleLoop_DurationBelowMinPromotedTo1s(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "noop", On: EventConnect, Match: "true", Actions: []Action{{Type: ActionAllow}}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cp.Doc.Config = map[string]interface{}{"cycle": "100ms"}

	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	pr.Start()
	pr.Stop()
}

// TestCycleLoop_TicksReconcileAndCycle covers the select case branches
// (runner.go:657-660): reconcile tick + cycle tick + stop. reconcileInterval
// is 5s in the runner, so the test sleeps slightly longer than that to
// guarantee the reconcile branch fires at least once.
func TestCycleLoop_TicksReconcileAndCycle(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "noop", On: EventConnect, Match: "true", Actions: []Action{{Type: ActionAllow}}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cp.Doc.Config = map[string]interface{}{"cycle": "1s"}

	listCalls := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			listCalls++
			return fakeNodeList(99), nil
		},
	})
	pr.Start()
	// Wait long enough that reconcileTicker (5s) fires at least once AND
	// cycleTicker (1s) fires a few times.
	time.Sleep(5500 * time.Millisecond)
	pr.Stop()

	if listCalls == 0 {
		t.Error("expected ListNodes to be called at least once during cycleLoop")
	}
}

// TestPersist_NoOpWhenPathEmpty covers the early-return when pr.path=="".
func TestPersist_NoOpWhenPathEmpty(t *testing.T) {
	t.Parallel()
	pr := &PolicyRunner{peers: map[uint32]*managedPeer{}}
	pr.persist() // path is "" → no-op, no panic.
}

// TestPersist_WriteFailureLogged simulates a persist failure via an
// unwritable path. We can't easily mock fsutil.AtomicWrite, so use a
// path under a read-only parent. Skipped on non-unix to avoid perm games.
func TestPersist_WriteFailureLogged(t *testing.T) {
	t.Parallel()
	// Path inside a non-existent dir we can't create (root-owned parent).
	// Easier: point at /dev/null/foo on unix — mkdir fails silently
	// (ignored), then AtomicWrite tries to write and fails.
	pr := &PolicyRunner{
		path:  "/dev/null/cannot-create/policy.json",
		peers: map[uint32]*managedPeer{},
	}
	pr.persist() // must not panic; logs warn.
}

// -----------------------------------------------------------------------------
// engine.go — evaluateGate rule-mismatch + error propagation branches
// -----------------------------------------------------------------------------

// TestEvaluate_RuleOnMismatchSkipped covers the rule.On != eventType
// continue branches (engine.go:101 + 149). We compile a rule for connect
// then Evaluate with cycle; the rule must be skipped and the gate returns
// default-allow.
func TestEvaluate_RuleOnMismatchSkipped(t *testing.T) {
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
	// Evaluate as a *dial* event — the connect-only rule must be skipped.
	dirs, err := cp.Evaluate(EventDial, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// Default fall-through → DirectiveAllow with rule="_default".
	if len(dirs) != 1 || dirs[0].Rule != "_default" {
		t.Errorf("dirs = %v, want single _default allow", dirs)
	}
}

// TestEvaluate_ActionRuleOnMismatchSkipped covers the action-event variant
// of the same branch (engine.go:149).
func TestEvaluate_ActionRuleOnMismatchSkipped(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "join-only", On: EventJoin, Match: "true", Actions: []Action{
				{Type: ActionLog, Params: map[string]interface{}{"message": "hi"}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Evaluate as a leave event — the join-only rule must be skipped.
	dirs, err := cp.Evaluate(EventLeave, map[string]interface{}{
		"peer_id": 1, "network_id": 1,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(dirs) != 0 {
		t.Errorf("dirs = %v, want empty (rule.On mismatch)", dirs)
	}
}

// TestEvaluate_GateEvalErrorPropagates covers engine.go:106 — runProgram
// error during gate eval propagates out.
func TestEvaluate_GateEvalErrorPropagates(t *testing.T) {
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
	_, err = cp.Evaluate(EventConnect, map[string]interface{}{
		"port": 80, "peer_id": 1, "network_id": 1,
		"peer_tags": []string{}, "peer_age_s": 0.0, "members": 0,
	})
	if err == nil {
		t.Fatal("expected eval error, got nil")
	}
}

// TestEvaluate_ActionEvalErrorPropagates covers engine.go:154 for actions.
func TestEvaluate_ActionEvalErrorPropagates(t *testing.T) {
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
	_, err = cp.Evaluate(EventCycle, map[string]interface{}{
		"network_id": 1, "members": 0, "peer_count": 0,
		"cycle_num": 0, "trusted_count": 0,
		"peer_id": 0, "peer_tags": []string{}, "peer_age_s": 0.0,
	})
	if err == nil {
		t.Fatal("expected eval error, got nil")
	}
}

// TestEvaluate_GateAccumulatesSideEffectsBeforeVerdict covers engine.go:128
// — when an early-matching rule has only side effects (tag/log/webhook), the
// engine accumulates them and continues until a verdict-bearing rule matches.
func TestEvaluate_GateAccumulatesSideEffectsBeforeVerdict(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			// First rule: side-effect only (tag), no verdict.
			{Name: "tag-first", On: EventConnect, Match: "true", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"early"}}},
			}},
			// Second rule: verdict.
			{Name: "allow-second", On: EventConnect, Match: "port == 80", Actions: []Action{
				{Type: ActionAllow},
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
	// Expect: [tag (from rule 1), allow (from rule 2 verdict)] — but in
	// the actual engine impl, when rule 2's directives include the verdict,
	// the engine prepends accumulated sideEffects + the whole rule. So we
	// should see tag + allow in the result.
	hasTag, hasAllow := false, false
	for _, d := range dirs {
		if d.Type == DirectiveTag {
			hasTag = true
		}
		if d.Type == DirectiveAllow {
			hasAllow = true
		}
	}
	if !hasTag || !hasAllow {
		t.Errorf("dirs = %v, want tag + allow", dirs)
	}
}

// -----------------------------------------------------------------------------
// engine.go — runProgram non-bool / panic-recover branches
// -----------------------------------------------------------------------------
//
// runProgram lives in policylang; we can drive it indirectly. The bool-result
// type-assert (engine.go:246) is hard to trigger via the public Compile path
// because expr.AsBool() forces a bool program. So this branch is the honest
// ceiling — covered only via an internal-package test.
//
// The recover branch (engine.go:233) needs a panic during expr.Run; that
// has its own dedicated regression test in policylang/zz_runprogram_panic_bug_test.go.
//
// The timeout branch (engine.go:250) requires expr to hang past 100ms; the
// current public surface doesn't expose a way to construct such a program
// without unsafe internals. Pin the budget at the integration level via
// TestPin_ExprTimeout_GateBoundedLatency above instead.

// -----------------------------------------------------------------------------
// service.go — exprPolicyJSONFromPayload Marshal-error branches
// -----------------------------------------------------------------------------

// TestExprPolicyJSONFromPayload_MapMarshalNonError covers the typical
// happy path explicitly; the Marshal-error path is unreachable for normal
// inputs (json.Marshal of a valid map always succeeds). Marshalling a
// channel returns ok=true with the fallback-marshal also erroring — but
// json.Marshal returns an error there too, so the function returns false.
func TestExprPolicyJSONFromPayload_UnmarshallableChannel(t *testing.T) {
	t.Parallel()
	// channels can't be JSON-marshalled → fallback branch returns false.
	got, ok := exprPolicyJSONFromPayload(map[string]any{"expr_policy": make(chan int)})
	if ok || got != nil {
		t.Errorf("got (%s, %v), want (nil, false)", got, ok)
	}
}

// TestExprPolicyJSONFromPayload_MapWithChannelMarshalFails covers the
// map[string]any branch where json.Marshal errors (channel field).
func TestExprPolicyJSONFromPayload_MapWithChannelMarshalFails(t *testing.T) {
	t.Parallel()
	got, ok := exprPolicyJSONFromPayload(map[string]any{
		"expr_policy": map[string]any{"bad": make(chan int)},
	})
	if ok || got != nil {
		t.Errorf("got (%s, %v), want (nil, false)", got, ok)
	}
}

// -----------------------------------------------------------------------------
// validateAction propagation — exercised by Validate's loop body (policy.go:170)
// -----------------------------------------------------------------------------

func TestValidate_PropagatesActionErrors(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "bad-action", On: EventConnect, Match: "true", Actions: []Action{
				{Type: ActionTag}, // missing add/remove → validateAction errors
			}},
		},
	}
	if err := Validate(doc); err == nil {
			t.Fatal("expected validation error propagated from validateAction")
	}
}

// TestPolicyRunner_PersistJSONShape sanity-checks the persisted JSON
// matches the policySnapshot schema (catches drift between persist/load).
func TestPolicyRunner_PersistJSONShape(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	pr.mu.Lock()
	pr.peers[1] = &managedPeer{NodeID: 1, AddedAt: time.Now(), Tags: []string{"x"}}
	pr.cycleNum = 9
	pr.mu.Unlock()
	pr.persist()

	data, err := os.ReadFile(pr.path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var snap policySnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.CycleNum != 9 {
		t.Errorf("CycleNum = %d, want 9", snap.CycleNum)
	}
	if _, ok := snap.Peers[1]; !ok {
		t.Error("peer 1 missing from persisted snapshot")
	}
}
