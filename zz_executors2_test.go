// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"errors"
	"testing"
	"time"
)

// fakeNodeList returns a ListNodes response with the given node IDs.
func fakeNodeList(ids ...uint32) map[string]any {
	nodes := make([]interface{}, len(ids))
	for i, id := range ids {
		nodes[i] = map[string]any{
			"node_id":     float64(id),
			"member_tags": []interface{}{"tag1"},
		}
	}
	return map[string]any{"nodes": nodes}
}

func TestExecuteFill_AddsNewPeers(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionFill, Params: map[string]interface{}{"count": float64(2)}},
	})
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3), nil
		},
	})

	pr.executeFill(Directive{
		Type:   DirectiveFill,
		Rule:   "cycle-rule",
		Params: map[string]interface{}{"count": float64(2)},
	})

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if got := len(pr.peers); got != 2 {
		t.Errorf("peers len = %d, want 2", got)
	}
}

func TestExecuteFill_FetchFailureIsNoop(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionFill, Params: map[string]interface{}{"count": float64(2)}},
	})
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return nil, errors.New("simulated")
		},
	})
	pr.executeFill(Directive{Params: map[string]interface{}{"count": float64(2)}})
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) != 0 {
		t.Errorf("peers should remain empty after fetch failure")
	}
}

func TestExecuteFill_SkipsSelfAndExistingPeer(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionFill, Params: map[string]interface{}{"count": float64(10)}},
	})
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 1 }, // skip self
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3), nil
		},
	})
	// Pre-add node 2 — Fill should refresh tags, not double-add.
	pr.mu.Lock()
	pr.peers[2] = &managedPeer{NodeID: 2, AddedAt: time.Now()}
	pr.mu.Unlock()

	pr.executeFill(Directive{Params: map[string]interface{}{"count": float64(10)}})

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	// Self (1) skipped, existing peer (2) refreshed; only node 3 added.
	if len(pr.peers) != 2 {
		t.Errorf("peers len = %d, want 2 (self skipped, existing refreshed, 3 added)", len(pr.peers))
	}
}

func TestExecutePruneTrust_BelowMinIsNoop(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionPruneTrust, Params: map[string]interface{}{
			"percent": float64(50), "min": float64(5),
		}},
	})
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		TrustedPeersFn: func() []TrustRecord {
			return []TrustRecord{
				{NodeID: 1, ApprovedAt: time.Now()},
				{NodeID: 2, ApprovedAt: time.Now()},
			}
		},
	})
	pr.executePruneTrust(Directive{
		Type: DirectivePruneTrust,
		Params: map[string]interface{}{
			"percent": float64(50), "min": float64(5),
		},
	})
	// total=2 <= min=5 → no revoke called.
}

func TestExecutePruneTrust_HappyPath(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionPruneTrust, Params: map[string]interface{}{
			"percent": float64(50), "min": float64(2),
		}},
	})
	revoked := []uint32{}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		TrustedPeersFn: func() []TrustRecord {
			now := time.Now()
			return []TrustRecord{
				{NodeID: 1, ApprovedAt: now.Add(-3 * time.Hour)},
				{NodeID: 2, ApprovedAt: now.Add(-2 * time.Hour)},
				{NodeID: 3, ApprovedAt: now.Add(-time.Hour)},
				{NodeID: 4, ApprovedAt: now},
			}
		},
		RevokeTrustFn: func(id uint32) error {
			revoked = append(revoked, id)
			return nil
		},
	})
	pr.executePruneTrust(Directive{
		Type: DirectivePruneTrust,
		Rule: "prune-rule",
		Params: map[string]interface{}{
			"percent": float64(50), "min": float64(2),
		},
	})
	// total=4, percent=50 → toRemove=2; clamped by min=2 → 4-2=2 stays.
	if len(revoked) != 2 {
		t.Errorf("revoked = %v, want 2 (oldest)", revoked)
	}
	// Oldest first by age.
	if revoked[0] != 1 || revoked[1] != 2 {
		t.Errorf("revoked order = %v, want [1, 2]", revoked)
	}
}

func TestExecutePruneTrust_RevokeErrorSkipped(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionPruneTrust, Params: map[string]interface{}{
			"percent": float64(50), "min": float64(0),
		}},
	})
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		TrustedPeersFn: func() []TrustRecord {
			return []TrustRecord{
				{NodeID: 1, ApprovedAt: time.Now()},
				{NodeID: 2, ApprovedAt: time.Now()},
			}
		},
		RevokeTrustFn: func(uint32) error { return errors.New("simulated") },
	})
	pr.executePruneTrust(Directive{
		Type: DirectivePruneTrust,
		Params: map[string]interface{}{
			"percent": float64(50), "min": float64(0),
		},
	})
}

func TestExecuteFillTrust_DeficitNeg(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionFillTrust, Params: map[string]interface{}{"target": float64(2)}},
	})
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		TrustedPeersFn: func() []TrustRecord {
			return []TrustRecord{
				{NodeID: 1}, {NodeID: 2}, {NodeID: 3},
			}
		},
	})
	pr.executeFillTrust(Directive{
		Type:   DirectiveFillTrust,
		Params: map[string]interface{}{"target": float64(2)},
	})
	// target=2, current=3 → deficit=-1 → no-op.
}

func TestExecuteFillTrust_FetchFailureIsNoop(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionFillTrust, Params: map[string]interface{}{"target": float64(5)}},
	})
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		TrustedPeersFn: func() []TrustRecord { return nil },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return nil, errors.New("simulated")
		},
	})
	pr.executeFillTrust(Directive{
		Type:   DirectiveFillTrust,
		Params: map[string]interface{}{"target": float64(5)},
	})
}

func TestExecuteFillTrust_SendsHandshakes(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{
		{Type: ActionFillTrust, Params: map[string]interface{}{"target": float64(3)}},
	})
	sent := []uint32{}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn:       func() uint32 { return 99 },
		TrustedPeersFn: func() []TrustRecord { return nil },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3, 4, 5), nil
		},
		SendHandshakeFn: func(id uint32, _ string) error {
			sent = append(sent, id)
			return nil
		},
	})
	pr.executeFillTrust(Directive{
		Type:   DirectiveFillTrust,
		Rule:   "fill-rule",
		Params: map[string]interface{}{"target": float64(3)},
	})
	// Target=3, current=0 → deficit=3 → 3 handshakes sent.
	if len(sent) != 3 {
		t.Errorf("sent = %v, want 3 handshakes", sent)
	}
}

func TestFetchMembers_PropagatesIDs(t *testing.T) {
	t.Parallel()
	cp := makeCyclePolicy(t, []Action{{Type: ActionAllow}})
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(10, 20, 30), nil
		},
	})
	ids, err := pr.fetchMembers()
	if err != nil {
		t.Fatalf("fetchMembers: %v", err)
	}
	if len(ids) != 3 {
		t.Errorf("ids = %v, want 3", ids)
	}
}

func TestService_ManagerView_StartManagerAndStartUnderscore(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	t.Cleanup(s.StopAll)
	// Start_ alias.
	if _, err := s.Start_(1, []byte(minimalPolicyJSON)); err != nil {
		t.Errorf("Start_: %v", err)
	}
	// StartManager alias.
	if _, err := s.StartManager(2, []byte(minimalPolicyJSON)); err != nil {
		t.Errorf("StartManager: %v", err)
	}
}

func TestManagerView_LoadPersisted(t *testing.T) {
	// Cannot t.Parallel — uses t.Setenv.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	s := NewService(&fakeRuntime{})
	mv := s.Manager()
	if err := mv.LoadPersisted(); err != nil {
		t.Errorf("LoadPersisted: %v", err)
	}
}
