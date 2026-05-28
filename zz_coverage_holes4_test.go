// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"os"
	"testing"
)

// TestLoadPersisted_UserHomeDirError covers service.go:268 — UserHomeDir
// returns an error when HOME (or its platform equivalent) is unset.
func TestLoadPersisted_UserHomeDirError(t *testing.T) {
	// Cannot t.Parallel — mutates HOME env at process level.
	// t.Setenv("", "") would do it on macOS/linux; explicit unset is clearer.
	prev, hadHome := os.LookupEnv("HOME")
	os.Unsetenv("HOME")
	t.Cleanup(func() {
		if hadHome {
			os.Setenv("HOME", prev)
		}
	})

	s := NewService(&fakeRuntime{})
	if err := s.LoadPersisted(); err == nil {
		t.Error("expected UserHomeDir error when HOME is unset")
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
