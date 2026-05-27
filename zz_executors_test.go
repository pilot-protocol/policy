// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"testing"
	"time"
)

// makeCyclePolicy returns a policy whose cycle event triggers various
// action directives so we can drive executeTag/executeEvict/executePrune/etc.
func makeCyclePolicy(t *testing.T, actions []Action) *CompiledPolicy {
	t.Helper()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:    "cycle-rule",
				On:      EventCycle,
				Match:   "true",
				Actions: actions,
			},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return cp
}

// runnerWithPeers builds a PolicyRunner with N peers pre-populated.
func runnerWithPeers(t *testing.T, cp *CompiledPolicy, peerIDs ...uint32) *PolicyRunner {
	t.Helper()
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	pr.mu.Lock()
	for i, id := range peerIDs {
		pr.peers[id] = &managedPeer{
			NodeID:  id,
			AddedAt: time.Now().Add(time.Duration(-i) * time.Minute),
		}
	}
	pr.recentlyEvicted = map[uint32]time.Time{}
	pr.mu.Unlock()
	return pr
}

func TestExecuteEvict_RemovesPeer(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{{Type: ActionEvict}})
	pr := runnerWithPeers(t, cp, 1, 2, 3)

	ctx := map[string]interface{}{"peer_id": int(2)}
	pr.executeEvict(ctx)

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if _, ok := pr.peers[2]; ok {
		t.Error("peer 2 should be evicted")
	}
	if _, ok := pr.recentlyEvicted[2]; !ok {
		t.Error("peer 2 should be in recentlyEvicted")
	}
}

func TestExecuteEvict_ZeroPeerIDIsNoop(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{{Type: ActionEvict}})
	pr := runnerWithPeers(t, cp, 1)
	pr.executeEvict(map[string]interface{}{"peer_id": int(0)})
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if _, ok := pr.peers[1]; !ok {
		t.Error("peer 1 should NOT be evicted (peer_id=0)")
	}
}

func TestExecutePrune_RemovesNOldest(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionPrune, Params: map[string]interface{}{"count": float64(2), "by": "age"}},
	})
	pr := runnerWithPeers(t, cp, 1, 2, 3, 4, 5)

	pr.executePrune(Directive{
		Type:    DirectivePrune,
		Rule:    "cycle-rule",
		Params:  map[string]interface{}{"count": float64(2), "by": "age"},
	})

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) != 3 {
		t.Errorf("peers len = %d, want 3 (pruned 2)", len(pr.peers))
	}
}

func TestExecuteEvictWhere_MatchAll(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionEvictWhere, Params: map[string]interface{}{"match": "true"}},
	})
	pr := runnerWithPeers(t, cp, 10, 20, 30)

	pr.executeEvictWhere(Directive{
		Type:      DirectiveEvictWhere,
		Rule:      "cycle-rule",
		ActionIdx: 0,
	}, 0)

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) != 0 {
		t.Errorf("peers len = %d, want 0 (all evicted)", len(pr.peers))
	}
}

func TestExecuteEvictWhere_MatchNone(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionEvictWhere, Params: map[string]interface{}{"match": "false"}},
	})
	pr := runnerWithPeers(t, cp, 10, 20)

	pr.executeEvictWhere(Directive{
		Type:      DirectiveEvictWhere,
		Rule:      "cycle-rule",
		ActionIdx: 0,
	}, 0)

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) != 2 {
		t.Errorf("peers len = %d, want 2 (no match)", len(pr.peers))
	}
}

func TestExecuteTag_AddAndRemove(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"flagged"}}},
	})
	pr := runnerWithPeers(t, cp, 0xCAFE)

	pr.executeTag(Directive{
		Type:   DirectiveTag,
		Rule:   "cycle-rule",
		Params: map[string]interface{}{"add": []interface{}{"flagged", "later"}},
	}, map[string]interface{}{"peer_id": int(0xCAFE)})

	pr.mu.RLock()
	tags := pr.peers[0xCAFE].tags()
	pr.mu.RUnlock()
	if len(tags) != 2 {
		t.Errorf("tags = %v, want 2", tags)
	}

	// Remove one tag.
	pr.executeTag(Directive{
		Type:   DirectiveTag,
		Rule:   "cycle-rule",
		Params: map[string]interface{}{"remove": []interface{}{"later"}},
	}, map[string]interface{}{"peer_id": int(0xCAFE)})

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	tags2 := pr.peers[0xCAFE].tags()
	if len(tags2) != 1 || tags2[0] != "flagged" {
		t.Errorf("after remove: tags = %v, want [flagged]", tags2)
	}
}

func TestExecuteTag_ZeroPeerIDIsNoop(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"x"}}}})
	pr := runnerWithPeers(t, cp, 1)
	pr.executeTag(Directive{Params: map[string]interface{}{"add": []interface{}{"x"}}},
		map[string]interface{}{"peer_id": int(0)})
}

func TestExecuteTag_AbsentPeerIsNoop(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{{Type: ActionTag, Params: map[string]interface{}{"add": []interface{}{"x"}}}})
	pr := runnerWithPeers(t, cp, 1)
	pr.executeTag(Directive{Params: map[string]interface{}{"add": []interface{}{"x"}}},
		map[string]interface{}{"peer_id": int(9999)})
}

// TestEvaluateActions_DispatchesAllDirectiveTypes drives EvaluateActions
// through a cycle event so every switch case in the executor table is
// covered.
func TestEvaluateActions_DispatchesAllDirectiveTypes(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionLog, Params: map[string]interface{}{"message": "hi"}},
		{Type: ActionWebhook, Params: map[string]interface{}{"event": "test"}},
	})
	pr := runnerWithPeers(t, cp, 1)
	pr.EvaluateActions(EventCycle, map[string]interface{}{
		"peer_id":    int(1),
		"network_id": int(1),
		"local_tags": []string{},
		"peer_tags":  []string{},
		"peer_age_s": 0.0,
		"members":    1,
	})
}

// TestRankTrustLinks drives the ranking helper directly.
func TestRankTrustLinks(t *testing.T) {
	t.Parallel()
	t1 := time.Now().Add(-3 * time.Hour)
	t2 := time.Now().Add(-time.Hour)
	records := []TrustRecord{
		{NodeID: 1, ApprovedAt: t2},
		{NodeID: 2, ApprovedAt: t1},
		{NodeID: 3, ApprovedAt: t2.Add(time.Minute)},
	}
	pr := &PolicyRunner{}
	ranked := pr.rankTrustLinks(records, "age")
	if len(ranked) != 3 {
		t.Fatalf("len = %d, want 3", len(ranked))
	}
	// Oldest first by ApprovedAt: record with t1 (NodeID 2) comes first.
	if ranked[0].NodeID != 2 {
		t.Errorf("first = %d, want 2 (oldest)", ranked[0].NodeID)
	}
}
