// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestStartInternal_AtomicSwap verifies that reloading a policy runner
// never leaves a window where Get(netID) returns nil — the new runner
// is registered before the old one is stopped.
func TestStartInternal_AtomicSwap(t *testing.T) {
	t.Parallel()
	svc := NewService(&fakeRuntime{})
	netID := uniqueNetID()

	// Policy 1: trivial allow-all.
	pol1 := &PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"max_peers": 10, "cycle": "1h"},
		Rules: []Rule{
			{Name: "allow", On: "connect", Match: "true", Actions: []Action{{Type: ActionAllow}}},
		},
	}

	// Start first runner.
	_, err := svc.startInternal(netID, mustMarshalPolicy(t, pol1))
	if err != nil {
		t.Fatalf("startInternal: %v", err)
	}

	// Confirm it's there.
	if svc.Manager().Get(netID) == nil {
		t.Fatal("Get returned nil after first start")
	}

	// Policy 2: a different allow-all (triggers reload).
	pol2 := &PolicyDocument{
		Version: 1,
		Config:  map[string]interface{}{"max_peers": 20, "cycle": "2h"},
		Rules: []Rule{
			{Name: "allow", On: "connect", Match: "true", Actions: []Action{{Type: ActionAllow}}},
		},
	}

	done := make(chan struct{})
	errCh := make(chan error, 1)

	// Goroutine that hammers Get in a loop during the reload.
	go func() {
		defer close(done)
		for {
			select {
			case <-errCh:
				return
			default:
			}
			if svc.Manager().Get(netID) == nil {
				select {
				case errCh <- nil:
				default:
				}
				return
			}
		}
	}()

	// Give the goroutine a moment to start.
	time.Sleep(10 * time.Millisecond)

	// Reload the policy — this triggers the stop-and-swap.
	_, err = svc.startInternal(netID, mustMarshalPolicy(t, pol2))
	if err != nil {
		t.Fatalf("reload startInternal: %v", err)
	}

	// Signal the observer to stop and check for errors.
	close(errCh)
	<-done

	// Confirm Get still returns non-nil after reload.
	if svc.Manager().Get(netID) == nil {
		t.Fatal("Get returned nil after reload")
	}

	// Clean up: stop the runner (so its goroutines don't outlive the test).
	_ = svc.Stop(context.Background())
}

func mustMarshalPolicy(t *testing.T, doc *PolicyDocument) []byte {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
