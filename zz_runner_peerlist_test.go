// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"testing"
	"time"
)

// TestPolicyRunner_PeerList_OrderedAndShaped exercises the list builder.
func TestPolicyRunner_PeerList_OrderedAndShaped(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	t1 := time.Now().Add(-2 * time.Hour)
	t2 := time.Now().Add(-1 * time.Hour)

	pr := &PolicyRunner{
		netID:    1,
		compiled: cp,
		peers: map[uint32]*managedPeer{
			0xCAFE: {NodeID: 0xCAFE, AddedAt: t2, Tags: []string{"web"}, RegistryTags: []string{"prod"}},
			0xBEEF: {NodeID: 0xBEEF, AddedAt: t1, LastSeen: t2},
		},
	}
	list := pr.PeerList()
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	// Sorted by AddedAt — oldest first: BEEF then CAFE.
	if list[0]["node_id"] != uint32(0xBEEF) {
		t.Errorf("first node_id = %v, want 0xBEEF", list[0]["node_id"])
	}
	if list[1]["node_id"] != uint32(0xCAFE) {
		t.Errorf("second node_id = %v, want 0xCAFE", list[1]["node_id"])
	}
	// BEEF has LastSeen set.
	if _, ok := list[0]["last_seen"]; !ok {
		t.Error("BEEF missing last_seen")
	}
	// CAFE has tags merged from policy + registry.
	tags, _ := list[1]["tags"].([]string)
	if len(tags) != 2 {
		t.Errorf("CAFE tags = %v, want 2", tags)
	}
}

// TestPolicyRunner_PeerList_EmptyMap drives the empty-peers branch.
func TestPolicyRunner_PeerList_EmptyMap(t *testing.T) {
	t.Parallel()
	pr := &PolicyRunner{peers: map[uint32]*managedPeer{}}
	if got := pr.PeerList(); len(got) != 0 {
		t.Errorf("empty peers: got %v", got)
	}
}

// TestPolicyRunner_ForceCycle drives runCycle through the public entry.
// fetchMembers fails (fakeRuntime returns no nodes), so the cycle exits
// gracefully without doing reconciliation but still produces a status map.
func TestPolicyRunner_ForceCycle(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(7, cp, &fakeRuntime{})
	pr.Start()
	t.Cleanup(pr.Stop)

	status := pr.ForceCycle()
	if status == nil {
		t.Error("ForceCycle returned nil status")
	}
}

// TestPolicyRunner_ReconcileNow runs the membership reconciler once.
func TestPolicyRunner_ReconcileNow(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(7, cp, &fakeRuntime{
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return map[string]any{
				"nodes": []interface{}{
					map[string]any{"node_id": float64(0x42)},
				},
			}, nil
		},
	})
	pr.Start()
	t.Cleanup(pr.Stop)
	pr.ReconcileNow() // must not panic
}

// TestClonePeersLocked covers the deep-copy helper.
func TestClonePeersLocked(t *testing.T) {
	t.Parallel()
	src := map[uint32]*managedPeer{
		1: {NodeID: 1, Tags: []string{"a"}, RegistryTags: []string{"r1"}},
	}
	dst := clonePeersLocked(src)
	if len(dst) != 1 {
		t.Fatalf("len = %d, want 1", len(dst))
	}
	// Mutating src must not affect dst.
	src[1].Tags[0] = "MUTATED"
	if dst[1].Tags[0] != "a" {
		t.Error("clone is shallow — Tags slice shared")
	}
}
