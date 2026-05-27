// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"testing"
	"time"
)

// TestApplyMembershipDiff_JoinAndLeave drives the diff loop with both
// new joins and departed peers.
func TestApplyMembershipDiff_JoinAndLeave(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{NodeIDFn: func() uint32 { return 99 }})

	// Pre-seed peer 5 (will leave).
	pr.mu.Lock()
	pr.peers[5] = &managedPeer{NodeID: 5, AddedAt: time.Now()}
	pr.mu.Unlock()

	// Fetched membership: peer 5 absent, peers 1+2 new (join).
	fetched := []fetchedMember{
		{ID: 1, Tags: []string{"a"}},
		{ID: 2, Tags: []string{"b"}},
		{ID: 99, Tags: []string{"self"}}, // self skipped
	}
	pr.applyMembershipDiff(fetched, 99)

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if _, ok := pr.peers[1]; !ok {
		t.Error("peer 1 should have joined")
	}
	if _, ok := pr.peers[2]; !ok {
		t.Error("peer 2 should have joined")
	}
	if _, ok := pr.peers[5]; ok {
		t.Error("peer 5 should have left")
	}
}

// TestApplyMembershipDiff_TagRefreshOnExistingPeer covers the
// already-tracked branch where RegistryTags is updated in-place.
func TestApplyMembershipDiff_TagRefreshOnExistingPeer(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{NodeIDFn: func() uint32 { return 99 }})

	// Pre-seed peer 7 with old tags.
	pr.mu.Lock()
	pr.peers[7] = &managedPeer{NodeID: 7, AddedAt: time.Now(), RegistryTags: []string{"old"}}
	pr.mu.Unlock()

	pr.applyMembershipDiff([]fetchedMember{{ID: 7, Tags: []string{"new"}}}, 99)

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	tags := pr.peers[7].RegistryTags
	if len(tags) != 1 || tags[0] != "new" {
		t.Errorf("RegistryTags = %v, want [new]", tags)
	}
}

// TestApplyMembershipDiff_RecentlyEvictedCooldownBlocks covers the
// cooldown-prevents-rejoin branch.
func TestApplyMembershipDiff_RecentlyEvictedCooldownBlocks(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{NodeIDFn: func() uint32 { return 99 }})

	pr.mu.Lock()
	pr.recentlyEvicted[3] = time.Now()
	pr.mu.Unlock()

	pr.applyMembershipDiff([]fetchedMember{{ID: 3}}, 99)

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if _, ok := pr.peers[3]; ok {
		t.Error("peer 3 should be blocked by cooldown")
	}
}

// TestApplyMembershipDiff_ExpiredCooldownSwept exercises the cooldown
// sweep branch.
func TestApplyMembershipDiff_ExpiredCooldownSwept(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{NodeIDFn: func() uint32 { return 99 }})

	pr.mu.Lock()
	pr.recentlyEvicted[3] = time.Now().Add(-2 * evictCooldown)
	pr.mu.Unlock()

	pr.applyMembershipDiff([]fetchedMember{{ID: 3}}, 99)

	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if _, ok := pr.recentlyEvicted[3]; ok {
		t.Error("expired cooldown should be swept")
	}
	if _, ok := pr.peers[3]; !ok {
		t.Error("peer 3 should be joined (expired cooldown)")
	}
}
