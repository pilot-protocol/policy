// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
)

// -----------------------------------------------------------------------------
// runner.go — evaluatePerPeerCycle (0% → drive direct + via runCycle)
// -----------------------------------------------------------------------------

// TestEvaluatePerPeerCycle_TagDirectiveApplies covers the per-peer cycle
// pass that the public runCycle uses internally. evaluatePerPeerCycle
// scopes EventCycle to a single peer's ctx and applies only DirectiveTag —
// fleet directives are skipped. This pins the per-peer pass works in
// isolation; pairing with TestRunCycle_FiresPerPeerThenFleet below ensures
// runCycle drives it.
func TestEvaluatePerPeerCycle_TagDirectiveApplies(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "tag-on-cycle", On: EventCycle, Match: "peer_id == 42", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"per-peer"}}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	pr.mu.Lock()
	pr.peers[42] = &managedPeer{NodeID: 42, AddedAt: time.Now()}
	pr.mu.Unlock()

	pr.evaluatePerPeerCycle(map[string]interface{}{
		"peer_id": 42, "network_id": 1, "members": 1,
		"peer_count": 1, "cycle_num": 1, "trusted_count": 0,
		"peer_tags": []string{}, "peer_age_s": 0.0,
	})
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	tags := pr.peers[42].tags()
	if len(tags) != 1 || tags[0] != "per-peer" {
		t.Errorf("tags = %v, want [per-peer]", tags)
	}
}

// TestEvaluatePerPeerCycle_EvalErrorIsSwallowed covers the early return on
// compiled.Evaluate error.
func TestEvaluatePerPeerCycle_EvalErrorIsSwallowed(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "boom", On: EventCycle, Match: `duration("nope") > 0`, Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"x"}}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})

	// Must not panic and must not mutate.
	pr.evaluatePerPeerCycle(map[string]interface{}{
		"peer_id": 1, "network_id": 1, "members": 0,
		"peer_count": 0, "cycle_num": 0, "trusted_count": 0,
		"peer_tags": []string{}, "peer_age_s": 0.0,
	})
}

// TestRunCycle_FiresPerPeerThenFleet drives runCycle through the public
// entry against a policy with a per-peer tag rule that fires for every
// peer (peer_id != 0 → ctx populated by the per-peer pass) plus a fleet
// evict_where rule. Asserts the cycle result map is shaped correctly and
// per-peer + fleet passes both ran. Covers the per-peer ctx-build branch
// (~runner.go:842) and the cycle result-build branches.
func TestRunCycle_FiresPerPeerThenFleet(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			// Per-peer pass: tag every peer (peer_id is always >0 in per-peer ctx).
			// Note: this rule ALSO fires in the fleet pass where peer_id=0; the
			// match is intentionally written so a 0/nil peer_id is non-matching
			// (`peer_id != nil and peer_id > 0`). expr renders `peer_id != nil`
			// as `peer_id` so we use the simpler `peer_count > 0` proxy: peer_count
			// is always populated in the cycle ctx.
			{Name: "tag-on-cycle", On: EventCycle, Match: `peer_count > 0`, Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"seen"}}},
			}},
			// Fleet pass: prune one (oldest). Different rule from the per-peer one.
			{Name: "prune-old", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionPrune, Params: map[string]interface{}{"count": 1.0, "by": "age"}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	now := time.Now()
	pr.mu.Lock()
	pr.peers[10] = &managedPeer{NodeID: 10, AddedAt: now.Add(-2 * time.Hour)}
	pr.peers[20] = &managedPeer{NodeID: 20, AddedAt: now.Add(-1 * time.Hour)}
	pr.mu.Unlock()

	result := pr.runCycle()
	if result["pruned"].(int) != 1 {
		t.Errorf("pruned = %v, want 1", result["pruned"])
	}
	if result["cycle_num"].(int) != 1 {
		t.Errorf("cycle_num = %v, want 1", result["cycle_num"])
	}
	// Per-peer pass must have tagged the remaining peer.
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) != 1 {
		t.Fatalf("peers after = %d, want 1", len(pr.peers))
	}
	for _, p := range pr.peers {
		if len(p.tags()) == 0 || p.tags()[0] != "seen" {
			t.Errorf("survivor tags = %v, want [seen]", p.tags())
		}
	}
}

// -----------------------------------------------------------------------------
// runner.go — EvaluateActions dispatch branches (Evict, EvictWhere,
// PruneTrust, FillTrust) that the existing tests don't reach via the
// public EvaluateActions entrypoint.
// -----------------------------------------------------------------------------

func TestEvaluateActions_DispatchEvictDirective(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{{Type: ActionEvict}})
	pr := runnerWithPeers(t, cp, 11, 22)
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 11, "network_id": 1, "members": 2,
		"peer_tags": []string{}, "peer_age_s": 0.0,
	})
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if _, ok := pr.peers[11]; ok {
		t.Error("peer 11 should be evicted via DirectiveEvict")
	}
}

func TestEvaluateActions_DispatchEvictWhereDirective(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "evict-all", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionEvictWhere, Params: map[string]interface{}{"match": "true"}},
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
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 2,
	})
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) != 0 {
		t.Errorf("peers = %d, want 0 (all evicted via DirectiveEvictWhere)", len(pr.peers))
	}
}

func TestEvaluateActions_DispatchFillDirective(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "fill", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionFill, Params: map[string]interface{}{"count": 1.0}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3), nil
		},
	})
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 0,
	})
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) != 1 {
		t.Errorf("peers after fill = %d, want 1", len(pr.peers))
	}
}

func TestEvaluateActions_DispatchPruneTrustDirective(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "prune-trust", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionPruneTrust, Params: map[string]interface{}{
					"percent": 50.0, "min": 1.0,
				}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	revoked := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		TrustedPeersFn: func() []TrustRecord {
			return []TrustRecord{
				{NodeID: 1, ApprovedAt: time.Now().Add(-2 * time.Hour)},
				{NodeID: 2, ApprovedAt: time.Now()},
			}
		},
		RevokeTrustFn: func(uint32) error { revoked++; return nil },
	})
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 0,
	})
	if revoked != 1 {
		t.Errorf("revoked = %d, want 1", revoked)
	}
}

func TestEvaluateActions_DispatchFillTrustDirective(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "fill-trust", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionFillTrust, Params: map[string]interface{}{"target": 2.0}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	sent := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn:       func() uint32 { return 99 },
		TrustedPeersFn: func() []TrustRecord { return nil },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3, 4), nil
		},
		SendHandshakeFn: func(uint32, string) error { sent++; return nil },
	})
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 0,
	})
	if sent != 2 {
		t.Errorf("sent handshakes = %d, want 2", sent)
	}
}

// TestEvaluateActions_EvalErrorIsSwallowed covers the slog.Warn early return.
func TestEvaluateActions_EvalErrorIsSwallowed(t *testing.T) {
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
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	// Must not panic.
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id": 0, "network_id": 1, "members": 0,
	})
}

// -----------------------------------------------------------------------------
// runner.go — executeFill maxPeers clamp branches, executePruneTrust clamps,
// executeFillTrust handshake error path
// -----------------------------------------------------------------------------

// TestExecuteFill_MaxPeersClamps confirms a fill that would exceed max_peers
// is clamped to the available headroom.
func TestExecuteFill_MaxPeersClamps(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"max_peers": 3.0},
		Rules: []Rule{
			{Name: "fill", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionFill, Params: map[string]interface{}{"count": 10.0}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3, 4, 5, 6), nil
		},
	})
	// Pre-seed one peer so available = 3 - 1 = 2.
	pr.mu.Lock()
	pr.peers[1] = &managedPeer{NodeID: 1, AddedAt: time.Now()}
	pr.mu.Unlock()

	pr.executeFill(Directive{
		Type:   DirectiveFill,
		Params: map[string]interface{}{"count": 10.0},
	})

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	// Capped at max_peers=3 total.
	if len(pr.peers) != 3 {
		t.Errorf("peers = %d, want 3 (clamped to max_peers)", len(pr.peers))
	}
}

// TestExecuteFill_MaxPeersAlreadyFullNoop confirms a fill is a no-op when
// pr.peers is already at max_peers (available = 0 < 0 branch hit).
func TestExecuteFill_MaxPeersAlreadyFullNoop(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"max_peers": 2.0},
		Rules: []Rule{
			{Name: "fill", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionFill, Params: map[string]interface{}{"count": 5.0}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3, 4, 5), nil
		},
	})
	// Over capacity — pre-seed 3 peers; max_peers=2; available = -1 → 0.
	pr.mu.Lock()
	pr.peers[10] = &managedPeer{NodeID: 10, AddedAt: time.Now()}
	pr.peers[11] = &managedPeer{NodeID: 11, AddedAt: time.Now()}
	pr.peers[12] = &managedPeer{NodeID: 12, AddedAt: time.Now()}
	pr.mu.Unlock()

	pr.executeFill(Directive{
		Type:   DirectiveFill,
		Params: map[string]interface{}{"count": 5.0},
	})

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	// No new peers added (still has the original 3, none of 1..5 added).
	if len(pr.peers) != 3 {
		t.Errorf("peers = %d, want 3 (no-op when over capacity)", len(pr.peers))
	}
}

// TestExecutePruneTrust_ToRemoveClampedToMin covers the toRemove == 0
// promotion-to-1 branch AND the total-toRemove < min clamp.
func TestExecutePruneTrust_ToRemoveZeroPromoted(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "prune-trust", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionPruneTrust, Params: map[string]interface{}{
					"percent": 10.0, // 10% of 3 = 0 → promoted to 1
					"min":     1.0,
				}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	revoked := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		TrustedPeersFn: func() []TrustRecord {
			return []TrustRecord{
				{NodeID: 1, ApprovedAt: time.Now().Add(-3 * time.Hour)},
				{NodeID: 2, ApprovedAt: time.Now().Add(-2 * time.Hour)},
				{NodeID: 3, ApprovedAt: time.Now().Add(-1 * time.Hour)},
			}
		},
		RevokeTrustFn: func(uint32) error { revoked++; return nil },
	})
	pr.executePruneTrust(Directive{
		Type: DirectivePruneTrust,
		Params: map[string]interface{}{
			"percent": 10.0, "min": 1.0,
		},
	})
	if revoked != 1 {
		t.Errorf("revoked = %d, want 1 (toRemove promoted from 0 → 1)", revoked)
	}
}

// TestExecuteFillTrust_HandshakeErrorSkipped covers the SendHandshakeRequest
// error continue branch.
func TestExecuteFillTrust_HandshakeErrorSkipped(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "fill-trust", On: EventCycle, Match: "true", Actions: []Action{
				{Type: ActionFillTrust, Params: map[string]interface{}{"target": 3.0}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	calls := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn:       func() uint32 { return 99 },
		TrustedPeersFn: func() []TrustRecord { return nil },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3, 4), nil
		},
		SendHandshakeFn: func(uint32, string) error {
			calls++
			return errors.New("simulated")
		},
	})
	pr.executeFillTrust(Directive{
		Type:   DirectiveFillTrust,
		Params: map[string]interface{}{"target": 3.0},
	})
	// All 3 attempts errored — sent counter stays 0 (no PublishEvent), but
	// the SendHandshakeFn was still invoked 3 times.
	if calls != 3 {
		t.Errorf("handshake calls = %d, want 3", calls)
	}
}

// -----------------------------------------------------------------------------
// runner.go — rankTrustLinks "random" branch
// -----------------------------------------------------------------------------

func TestRankTrustLinks_RandomBranch(t *testing.T) {
	t.Parallel()
	records := []TrustRecord{
		{NodeID: 1}, {NodeID: 2}, {NodeID: 3}, {NodeID: 4},
	}
	pr := &PolicyRunner{}
	ranked := pr.rankTrustLinks(records, "random")
	if len(ranked) != 4 {
		t.Fatalf("len = %d, want 4", len(ranked))
	}
	// Random can technically return identical order — we only assert the
	// IDs are preserved.
	seen := map[uint32]bool{}
	for _, r := range ranked {
		seen[r.NodeID] = true
	}
	for _, want := range []uint32{1, 2, 3, 4} {
		if !seen[want] {
			t.Errorf("missing node %d in random ranking", want)
		}
	}
}

// -----------------------------------------------------------------------------
// runner.go — bootstrap branches: maxPeers cap, deny-on-join recently-evicted,
// log/webhook on join.
// -----------------------------------------------------------------------------

func TestBootstrap_MaxPeersClampsCandidates(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"max_peers": 2.0},
		Rules: []Rule{
			{Name: "noop", On: EventConnect, Match: "true", Actions: []Action{{Type: ActionAllow}}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3, 4, 5), nil
		},
	})
	if err := pr.bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) != 2 {
		t.Errorf("peers = %d, want 2 (capped by max_peers)", len(pr.peers))
	}
}

// TestBootstrap_DenyJoinSetsCooldown pins that bootstrap's deny path also
// marks the peer in recentlyEvicted (matches applyMembershipDiff behaviour).
func TestBootstrap_DenyJoinSetsCooldown(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "deny-join", On: EventJoin, Match: "true", Actions: []Action{
				{Type: ActionDeny},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2), nil
		},
	})
	if err := pr.bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	for _, id := range []uint32{1, 2} {
		if _, blocked := pr.recentlyEvicted[id]; !blocked {
			t.Errorf("peer %d should be in recentlyEvicted after bootstrap deny", id)
		}
	}
}

// TestBootstrap_JoinDispatchesLogAndWebhook drives the bootstrap → EventJoin
// log + webhook directive branches.
func TestBootstrap_JoinDispatchesLogAndWebhook(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "log-join", On: EventJoin, Match: "true", Actions: []Action{
				{Type: ActionLog, Params: map[string]interface{}{"message": "join"}},
				{Type: ActionWebhook, Params: map[string]interface{}{"event": "joined"}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	publishes := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn:       func() uint32 { return 99 },
		PublishEventFn: func(string, map[string]any) { publishes++ },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(7), nil
		},
	})
	if err := pr.bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if publishes == 0 {
		t.Error("ActionWebhook should have called PublishEvent at least once")
	}
}

// -----------------------------------------------------------------------------
// runner.go — applyMembershipDiff branches: leave dispatches log + webhook +
// tag side-effects.
// -----------------------------------------------------------------------------

func TestApplyMembershipDiff_LeaveDispatchesLogTagWebhook(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "leave-actions", On: EventLeave, Match: "true", Actions: []Action{
				{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"gone"}}},
				{Type: ActionLog, Params: map[string]interface{}{"message": "bye"}},
				{Type: ActionWebhook, Params: map[string]interface{}{"event": "left"}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	publishes := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn:       func() uint32 { return 99 },
		PublishEventFn: func(string, map[string]any) { publishes++ },
	})
	pr.mu.Lock()
	pr.peers[42] = &managedPeer{NodeID: 42, AddedAt: time.Now()}
	pr.mu.Unlock()

	// fetched omits 42 → triggers leave.
	pr.applyMembershipDiff([]fetchedMember{{ID: 99}}, 99)

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if _, ok := pr.peers[42]; ok {
		t.Error("peer 42 should have left")
	}
	if publishes == 0 {
		t.Error("leave-webhook should fire PublishEvent")
	}
}

// TestApplyMembershipDiff_JoinDispatchesLogAndWebhook covers join's
// DirectiveLog + DirectiveWebhook branches inside the loop body.
func TestApplyMembershipDiff_JoinDispatchesLogAndWebhook(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "join-actions", On: EventJoin, Match: "true", Actions: []Action{
				{Type: ActionLog, Params: map[string]interface{}{"message": "hi"}},
				{Type: ActionWebhook, Params: map[string]interface{}{"event": "joined"}},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	publishes := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn:       func() uint32 { return 99 },
		PublishEventFn: func(string, map[string]any) { publishes++ },
	})
	pr.applyMembershipDiff([]fetchedMember{
		{ID: 99}, {ID: 11},
	}, 99)
	if publishes == 0 {
		t.Error("join-webhook should fire PublishEvent")
	}
}

// TestApplyMembershipDiff_JoinEvalErrorSkips covers the slog.Warn continue
// branch when Evaluate returns err during join dispatch.
func TestApplyMembershipDiff_JoinEvalErrorSkips(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{Name: "boom-join", On: EventJoin, Match: `duration("bad") > 0`, Actions: []Action{
				{Type: ActionDeny},
			}},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{NodeIDFn: func() uint32 { return 99 }})
	pr.applyMembershipDiff([]fetchedMember{{ID: 99}, {ID: 5}}, 99)
	// Peer 5 should still join (eval error treated as no-deny — runner just
	// warns and continues).
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if _, ok := pr.peers[5]; !ok {
		t.Error("peer 5 should be added despite join-rule eval error")
	}
}

// -----------------------------------------------------------------------------
// runner.go — fetchMembersWithTags failure / recover / backoff branches
// -----------------------------------------------------------------------------

// TestFetchMembersWithTags_BackoffSkipsTick covers the
// "skip if recent failures put us in backoff" branch.
func TestFetchMembersWithTags_BackoffSkipsTick(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	calls := 0
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			calls++
			return fakeNodeList(1), nil
		},
	})
	// Manually push the skip-until into the future.
	pr.fetchFailMu.Lock()
	pr.fetchSkipUntil = time.Now().Add(1 * time.Hour)
	pr.fetchFailMu.Unlock()

	if got := pr.fetchMembersWithTags(); got != nil {
		t.Errorf("expected nil during backoff, got %v", got)
	}
	if calls != 0 {
		t.Errorf("calls = %d, want 0 (backoff should skip)", calls)
	}
}

// TestFetchMembersWithTags_RecoveryResetsFailures covers the "Reset failure
// count on success" branch.
func TestFetchMembersWithTags_RecoveryResetsFailures(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2), nil
		},
	})
	// Simulate a prior failure streak.
	pr.fetchFailMu.Lock()
	pr.fetchFailures = 3
	pr.fetchSkipUntil = time.Time{} // already eligible
	pr.fetchFailMu.Unlock()

	got := pr.fetchMembersWithTags()
	if got == nil {
		t.Fatal("expected members, got nil")
	}
	pr.fetchFailMu.Lock()
	defer pr.fetchFailMu.Unlock()
	if pr.fetchFailures != 0 {
		t.Errorf("fetchFailures = %d, want 0 after recovery", pr.fetchFailures)
	}
}

// TestFetchMembersWithTags_FailureIncrementsBackoff covers the err path.
func TestFetchMembersWithTags_FailureIncrementsBackoff(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return nil, errors.New("simulated")
		},
	})
	if got := pr.fetchMembersWithTags(); got != nil {
		t.Error("expected nil on error")
	}
	pr.fetchFailMu.Lock()
	defer pr.fetchFailMu.Unlock()
	if pr.fetchFailures != 1 {
		t.Errorf("fetchFailures = %d, want 1", pr.fetchFailures)
	}
	if pr.fetchSkipUntil.IsZero() {
		t.Error("fetchSkipUntil should be set after failure")
	}
}

// TestFetchMembersWithTags_NodesFieldMissing covers the "nodes" type-assert
// failure path (returns nil).
func TestFetchMembersWithTags_NodesFieldMissing(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return map[string]any{}, nil
		},
	})
	if got := pr.fetchMembersWithTags(); got != nil {
		t.Errorf("expected nil on missing 'nodes' field, got %v", got)
	}
}

// TestFetchMembersWithTags_NonMapEntrySkipped covers the per-entry
// type-assert continue branch.
func TestFetchMembersWithTags_NonMapEntrySkipped(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return map[string]any{
				"nodes": []interface{}{
					"not a map", // skipped
					map[string]any{"node_id": float64(42)},
					map[string]any{"no_id_here": "x"}, // skipped (no node_id)
				},
			}, nil
		},
	})
	got := pr.fetchMembersWithTags()
	if len(got) != 1 || got[0].ID != 42 {
		t.Errorf("got = %v, want [{ID:42}]", got)
	}
}

// -----------------------------------------------------------------------------
// runner.go — Stop idempotency + NewPolicyRunner load-from-disk branch
// -----------------------------------------------------------------------------

// TestPolicyRunner_StopIdempotent covers the first select-case in Stop
// where stopCh is already closed.
func TestPolicyRunner_StopIdempotent(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	pr.Start()
	pr.Stop()
	pr.Stop() // must not panic; covers the `case <-pr.stopCh:` branch
}

// TestNewPolicyRunner_LoadsPriorState pre-populates the JSON file so
// NewPolicyRunner's `if err := pr.load(); err != nil` branch returns
// nil (success), exercising the success leg of load().
func TestNewPolicyRunner_LoadsPriorState(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	netID := uniqueNetID()

	// Persist a snapshot via a first runner.
	pr1 := NewPolicyRunner(netID, cp, &fakeRuntime{})
	pr1.mu.Lock()
	pr1.peers[123] = &managedPeer{NodeID: 123, AddedAt: time.Now(), Tags: []string{"preserved"}}
	pr1.cycleNum = 42
	pr1.mu.Unlock()
	pr1.persist()

	// Re-create — load() should populate peers + cycleNum.
	pr2 := NewPolicyRunner(netID, cp, &fakeRuntime{})
	pr2.mu.RLock()
	defer pr2.mu.RUnlock()
	if _, ok := pr2.peers[123]; !ok {
		t.Errorf("peer 123 not loaded from disk")
	}
	if pr2.cycleNum != 42 {
		t.Errorf("cycleNum = %d, want 42", pr2.cycleNum)
	}
}

// TestNewPolicyRunner_PilotHomeOverride pins that PILOT_HOME env wins over
// $HOME — covers the env-set branch in NewPolicyRunner.
func TestNewPolicyRunner_PilotHomeOverride(t *testing.T) {
	// Cannot t.Parallel — uses t.Setenv.
	dir := t.TempDir()
	t.Setenv("PILOT_HOME", dir)
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	if !filepath.HasPrefix(pr.path, dir) {
		t.Errorf("pr.path = %s, want prefix %s", pr.path, dir)
	}
}

// -----------------------------------------------------------------------------
// service.go — handleNetworkJoined / handleNetworkLeft skip branches
// -----------------------------------------------------------------------------

func TestHandleNetworkJoined_SkipsWhenNetIDMissing(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	t.Cleanup(s.StopAll)
	// Missing network_id — must early-return without panic.
	s.handleNetworkJoined(map[string]any{
		"expr_policy": `{"version":1,"rules":[{"name":"r","on":"connect","match":"true","actions":[{"type":"allow"}]}]}`,
	})
	// Map should remain empty.
	if got := s.Manager().All(); len(got) != 0 {
		t.Errorf("runners = %d, want 0 after missing-netID join", len(got))
	}
}

func TestHandleNetworkJoined_SkipsWhenAlreadyRunning(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	t.Cleanup(s.StopAll)

	if _, err := s.startInternal(7, []byte(minimalPolicyJSON)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := len(s.Manager().All())

	s.handleNetworkJoined(map[string]any{
		"network_id":  uint16(7),
		"expr_policy": minimalPolicyJSON,
	})
	after := len(s.Manager().All())
	if before != after {
		t.Errorf("runner count changed: %d → %d (should skip if already running)", before, after)
	}
}

func TestHandleNetworkJoined_BadPolicyJSONLogsAndContinues(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	t.Cleanup(s.StopAll)
	s.handleNetworkJoined(map[string]any{
		"network_id":  uint16(8),
		"expr_policy": `not valid json`,
	})
	if got := s.Manager().Get(8); got != nil {
		t.Error("runner should NOT exist after bad JSON parse")
	}
}

func TestHandleNetworkLeft_NoOpWhenNetIDMissing(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	t.Cleanup(s.StopAll)
	// Should not panic.
	s.handleNetworkLeft(map[string]any{})
}

// TestDispatchNetworkEvents_TagsChangedNoOp covers the network.tags_changed
// case in the dispatcher loop (currently reserved for future use).
func TestDispatchNetworkEvents_TagsChangedNoOp(t *testing.T) {
	t.Parallel()
	bus := newStubBus()
	svc := NewService(&fakeRuntime{})
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	if err := svc.Start(context.Background(), coreapi.Deps{Events: bus}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	bus.Publish("network.tags_changed", map[string]any{
		"network_id": uint16(99),
	})
	// Give dispatcher a tick to drain.
	time.Sleep(50 * time.Millisecond)
	// Must not have started a runner.
	if svc.Manager().Get(99) != nil {
		t.Error("tags_changed must NOT start a runner")
	}
}

// -----------------------------------------------------------------------------
// service.go — startInternal Compile error + LoadPersisted edge branches
// -----------------------------------------------------------------------------

func TestStartInternal_CompileError(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	// Valid JSON, but rule references an unknown event type → Validate fails
	// at the Parse step. Construct a doc that *parses* but fails Compile —
	// match expression with type error.
	doc := `{"version":1,"rules":[{"name":"r","on":"connect","match":"port + true","actions":[{"type":"allow"}]}]}`
	_, err := s.startInternal(1, []byte(doc))
	if err == nil {
		t.Fatal("expected compile error, got nil")
	}
}

func TestLoadPersisted_EmptyHomeNoError(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	s := NewService(&fakeRuntime{})
	if err := s.LoadPersisted(); err != nil {
		t.Errorf("LoadPersisted on empty HOME = %v", err)
	}
}

// TestLoadPersisted_ReaddirError covers the os.ReadDir error path that isn't
// IsNotExist. We can simulate by pointing HOME at a *file* — ReadDir on a
// non-directory returns ENOTDIR.
func TestLoadPersisted_ReaddirError(t *testing.T) {
	tmp := t.TempDir()
	// Make ~/.pilot exist as a regular file → ReadDir errors with ENOTDIR.
	pilotPath := filepath.Join(tmp, ".pilot")
	if err := os.WriteFile(pilotPath, []byte("not a dir"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Setenv("HOME", tmp)
	s := NewService(&fakeRuntime{})
	if err := s.LoadPersisted(); err == nil {
		t.Error("expected ReadDir error on file-instead-of-dir, got nil")
	}
}
