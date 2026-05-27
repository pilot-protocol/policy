// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_policy
// +build !no_policy

package policy

import (
	"context"
	"os"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

const minimalPolicyJSON = `{
  "version": 1,
  "rules": [
    {"name": "allow-all", "on": "connect", "match": "true", "actions": [{"type": "allow"}]}
  ]
}`

func TestService_NameOrder(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	if s.Name() != "policy" {
		t.Errorf("Name = %q", s.Name())
	}
	if s.Order() != 140 {
		t.Errorf("Order = %d, want 140", s.Order())
	}
}

func TestService_StartNoEvents(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	if err := s.Start(context.Background(), coreapi.Deps{}); err != nil {
		t.Errorf("Start: %v", err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestService_StartInternalNoRuntime(t *testing.T) {
	t.Parallel()
	s := &Service{runners: map[uint16]*PolicyRunner{}}
	if _, err := s.startInternal(1, []byte(minimalPolicyJSON)); err == nil {
		t.Error("expected error when runtime is nil")
	}
}

func TestService_StartInternalBadJSON(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	if _, err := s.startInternal(1, []byte("not json")); err == nil {
		t.Error("expected parse error")
	}
}

func TestService_StartInternalHappyAndRestart(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	pr, err := s.startInternal(1, []byte(minimalPolicyJSON))
	if err != nil {
		t.Fatalf("startInternal: %v", err)
	}
	if pr == nil {
		t.Fatal("nil runner")
	}
	t.Cleanup(func() { s.StopAll() })

	// Second call replaces the existing runner.
	pr2, err := s.startInternal(1, []byte(minimalPolicyJSON))
	if err != nil {
		t.Fatalf("re-startInternal: %v", err)
	}
	if pr2 == nil {
		t.Fatal("second nil")
	}
}

func TestService_ManagerView_StartStopGetAll(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	t.Cleanup(s.StopAll)
	mv := s.Manager()

	// All() empty.
	if got := mv.All(); len(got) != 0 {
		t.Errorf("All empty = %v", got)
	}

	pr, err := mv.Start(7, []byte(minimalPolicyJSON))
	if err != nil {
		t.Fatalf("mv.Start: %v", err)
	}
	if pr == nil {
		t.Fatal("nil pr")
	}

	// Get returns the same runner.
	if got := mv.Get(7); got == nil {
		t.Error("Get(7) = nil")
	}
	// Get unknown returns nil.
	if got := mv.Get(9999); got != nil {
		t.Errorf("Get(unknown) = %v, want nil", got)
	}

	// All() returns one.
	if got := mv.All(); len(got) != 1 {
		t.Errorf("All len = %d, want 1", len(got))
	}

	// Stop removes.
	mv.Stop(7)
	if got := mv.Get(7); got != nil {
		t.Error("Get(7) after Stop = non-nil")
	}

	// StopAll on already-empty is safe.
	mv.StopAll()
}

func TestService_ManagerView_StartBadJSON(t *testing.T) {
	t.Parallel()
	s := NewService(&fakeRuntime{})
	mv := s.Manager()
	if _, err := mv.Start(1, []byte("nope")); err == nil {
		t.Error("expected parse error from Start")
	}
}

func TestService_LoadPersisted_NoOpWhenDirMissing(t *testing.T) {
	// Cannot t.Parallel — uses t.Setenv.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	s := NewService(&fakeRuntime{})
	if err := s.LoadPersisted(); err != nil {
		t.Errorf("LoadPersisted missing dir: %v", err)
	}
}

func TestService_LoadPersisted_ScansPolicyFiles(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	// Pre-create ~/.pilot with some files (policy and non-policy).
	dir := tmp + "/.pilot"
	if err := makeDir(dir); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range []string{"policy_7.json", "policy_8.json", "not-a-policy.txt"} {
		if err := writeEmptyFile(dir + "/" + name); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	s := NewService(&fakeRuntime{})
	if err := s.LoadPersisted(); err != nil {
		t.Errorf("LoadPersisted: %v", err)
	}
}

func makeDir(p string) error {
	return os.MkdirAll(p, 0700)
}
func writeEmptyFile(p string) error {
	return os.WriteFile(p, nil, 0600)
}
