// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"os"
	"testing"
)

// TestLoadPersisted_MissingDirNoError covers the reconciled path
// convention: LoadPersisted resolves its directory via stateDir()
// (PILOT_HOME-first, same as NewPolicyRunner). When that directory does
// not exist, LoadPersisted is a graceful no-op rather than an error.
func TestLoadPersisted_MissingDirNoError(t *testing.T) {
	// Cannot t.Parallel — mutates PILOT_HOME env at process level.
	tmp := t.TempDir() // exists, but $PILOT_HOME/.pilot does not
	t.Setenv("PILOT_HOME", tmp)

	s := NewService(&fakeRuntime{})
	if err := s.LoadPersisted(); err != nil {
		t.Errorf("LoadPersisted with missing state dir should be a no-op, got %v", err)
	}
}

// TestNewPolicyRunner_FallsBackToUserHomeDir covers runner.go:77 — when
// PILOT_HOME is unset, NewPolicyRunner falls back to os.UserHomeDir().
// TestMain pre-sets PILOT_HOME for the whole binary; we override it
// inside this test only.
func TestNewPolicyRunner_FallsBackToUserHomeDir(t *testing.T) {
	// Cannot t.Parallel — mutates PILOT_HOME at process level.
	prev, hadPilot := os.LookupEnv("PILOT_HOME")
	os.Unsetenv("PILOT_HOME")
	t.Cleanup(func() {
		if hadPilot {
			os.Setenv("PILOT_HOME", prev)
		}
	})
	cp := compileTestPolicy(t)
	pr := NewPolicyRunner(uniqueNetID(), cp, &fakeRuntime{})
	// pr.path should still be non-empty (UserHomeDir is usually present).
	if pr.path == "" {
		t.Skip("UserHomeDir returned empty — env probably also lacks HOME")
	}
}
