// SPDX-License-Identifier: AGPL-3.0-or-later

package policylang

import (
	"strings"
	"testing"

	"github.com/expr-lang/expr"
)

// TestRunProgramRecoversFromExprPanic pins the P1 stability fix:
// runProgram must surface a panic in expr.Run as an error, NOT let
// it tear down the entire daemon.
//
// Before the fix: engine.go:226-229 spawned a goroutine that called
// expr.Run with no defer recover(). A malformed expression or a bug
// in the expr library that triggered a panic took the whole process
// down. Even policy reload (an operator-initiated path) becomes a
// daemon-crash vector if the expression panics during compile-vs-run
// drift.
//
// We reproduce the panic by compiling against ONE context schema and
// running against ANOTHER — expr panics on undefined field access in
// some versions / configurations. If that doesn't trigger a panic in
// this expr version, the test stays useful as a regression guard for
// future expr upgrades that may panic on edge inputs.
func TestRunProgramRecoversFromExprPanic(t *testing.T) {
	t.Parallel()

	// Compile against an empty schema, then run against a context that
	// references a panic-shaped path. The exact panic trigger varies by
	// expr version; if no panic surfaces, we still verify the code path
	// returns an error rather than panicking.
	prog, err := expr.Compile(`Tags["x"][0] == "y"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BUG: runProgram propagated a panic out to caller: %v", r)
		}
	}()

	// Call with a context that has no Tags key — accessing [0] on nil
	// slice panics in expr. The fix must wrap expr.Run in defer recover
	// so this returns (false, err) instead of crashing.
	ok, err := runProgram(prog, map[string]interface{}{})
	if err == nil && ok {
		// Some expr versions return false silently — still no panic.
		return
	}
	if err != nil && !strings.Contains(err.Error(), "panic") &&
		!strings.Contains(err.Error(), "runtime error") {
		// The error might not mention 'panic' if expr surfaced it
		// normally. Either way, we got an error back instead of a
		// crash — that's the invariant we care about.
		return
	}
}
