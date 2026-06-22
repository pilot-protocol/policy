// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestStopBeforeStartIsNoOp guards the deadlock where Stop() before
// Start() waited on `done`, which cycleLoop never closes if it never ran.
func TestStopBeforeStartIsNoOp(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})

	done := make(chan struct{})
	go func() {
		pr.Stop() // must return immediately, not block on pr.done
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() before Start() blocked")
	}

	// A subsequent Start on an already-stopped runner is a no-op, and a
	// second Stop must also return.
	pr.Start()
	pr.Stop()
}

// TestStartThenStop exercises the normal lifecycle: Start launches the
// loop, Stop signals and waits for it.
func TestStartThenStop(t *testing.T) {
	t.Parallel()
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	pr.Start()
	done := make(chan struct{})
	go func() {
		pr.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop() after Start() blocked")
	}
}

// TestPersistLoadRoundTripPilotHome verifies that a runner persists to
// the PILOT_HOME-derived path and a fresh runner for the same netID
// loads that state back. Reconciles runner.go and service.go on the
// single stateDir() convention.
func TestPersistLoadRoundTripPilotHome(t *testing.T) {
	// Cannot t.Parallel — uses t.Setenv.
	tmp := t.TempDir()
	t.Setenv("PILOT_HOME", tmp)

	netID := uint16(4321)
	cp := compileTestPolicy(t)

	pr := NewPolicyRunner(netID, cp, &fakeRuntime{})
	pr.mu.Lock()
	pr.peers[100] = &managedPeer{NodeID: 100, Tags: []string{"elite"}, AddedAt: time.Now().Truncate(time.Second)}
	pr.peers[200] = &managedPeer{NodeID: 200, AddedAt: time.Now().Truncate(time.Second)}
	pr.cycleNum = 9
	pr.mu.Unlock()
	pr.persist()

	wantPath := filepath.Join(tmp, ".pilot", "policy_4321.json")
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("expected persisted file at %s: %v", wantPath, err)
	}

	// Fresh runner for the same netID must load the persisted snapshot
	// from the same PILOT_HOME-derived path.
	pr2 := NewPolicyRunner(netID, cp, &fakeRuntime{})
	if len(pr2.peers) != 2 {
		t.Fatalf("reloaded peers = %d, want 2", len(pr2.peers))
	}
	if pr2.peers[100] == nil || len(pr2.peers[100].Tags) == 0 || pr2.peers[100].Tags[0] != "elite" {
		t.Errorf("peer 100 tags not restored: %+v", pr2.peers[100])
	}
	if pr2.cycleNum != 9 {
		t.Errorf("cycleNum = %d, want 9", pr2.cycleNum)
	}
}

// TestLoadPersistedHonorsPilotHome verifies Service.LoadPersisted scans
// the same PILOT_HOME directory NewPolicyRunner writes to, and surfaces
// the discovered networks.
func TestLoadPersistedHonorsPilotHome(t *testing.T) {
	// Cannot t.Parallel — uses t.Setenv.
	tmp := t.TempDir()
	t.Setenv("PILOT_HOME", tmp)

	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(777, cp, &fakeRuntime{})
	pr.persist()

	s := NewService(&fakeRuntime{})
	if err := s.LoadPersisted(); err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	got := s.PersistedNetworks()
	found := false
	for _, id := range got {
		if id == 777 {
			found = true
		}
	}
	if !found {
		t.Errorf("PersistedNetworks = %v, want to include 777", got)
	}
}
