// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"os"
	"sync/atomic"
	"testing"
)

// uniqueNetID returns a fresh, monotonically-increasing uint16 each
// call so concurrent test PolicyRunners don't share the
// $PILOT_HOME/.pilot/policy_<netID>.json persistence file. Without
// this, parallel tests that all picked netID=1 (the historical
// default) raced through one shared file and silently inherited each
// other's persisted-peers state.
func uniqueNetID() uint16 {
	return uint16(testNetIDCounter.Add(1))
}

var testNetIDCounter atomic.Uint32

// TestMain isolates every PolicyRunner created during the package's
// tests from the real ~/.pilot/policy_<netID>.json files (and from
// each other) by pointing PILOT_HOME at a per-binary tmpdir. Without
// this, parallel tests using the same netID share one JSON file and
// pollute each other's persisted-peers state.
//
// NewPolicyRunner reads PILOT_HOME first, falling back to UserHomeDir
// when it's unset — see runner.go.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "pilot-policy-tests-")
	if err != nil {
		panic("policy tests: cannot create tmpdir: " + err.Error())
	}
	os.Setenv("PILOT_HOME", tmp)
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}
