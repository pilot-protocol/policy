// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"testing"
)

// TestBootstrap_SuccessfulFetchAddsCandidates drives bootstrap on a
// policy with no join rules so it just registers candidates from
// ListNodes.
func TestBootstrap_SuccessfulFetchAddsCandidates(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 3, 99), nil
		},
	})

	if err := pr.bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	// Self (99) skipped, 1+2+3 added.
	if len(pr.peers) != 3 {
		t.Errorf("peers len = %d, want 3", len(pr.peers))
	}
}

// TestBootstrap_DenyOnJoinEvictsPeer drives the bootstrap → EventJoin
// → DirectiveDeny path.
func TestBootstrap_DenyOnJoinEvictsPeer(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:    "join-deny",
				On:      EventJoin,
				Match:   "true",
				Actions: []Action{{Type: ActionDeny}},
			},
			// Always need at least one rule for Validate to pass.
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{
		NodeIDFn: func() uint32 { return 99 },
		ListNodesFn: func(uint16, string) (map[string]any, error) {
			return fakeNodeList(1, 2, 99), nil
		},
	})

	if err := pr.bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	// All candidates denied on join → evicted from peers map.
	if len(pr.peers) != 0 {
		t.Errorf("peers len = %d, want 0 (all denied on join)", len(pr.peers))
	}
}
