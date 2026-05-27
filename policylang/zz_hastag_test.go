// SPDX-License-Identifier: AGPL-3.0-or-later

package policylang

import "testing"

func TestHasTagFn_Found(t *testing.T) {
	t.Parallel()
	got, err := hasTagFn([]string{"a", "b", "c"}, "b")
	if err != nil {
		t.Fatalf("hasTagFn: %v", err)
	}
	if v, ok := got.(bool); !ok || !v {
		t.Errorf("found tag: got %v, want true", got)
	}
}

func TestHasTagFn_NotFound(t *testing.T) {
	t.Parallel()
	got, err := hasTagFn([]string{"a", "b"}, "z")
	if err != nil {
		t.Fatalf("hasTagFn: %v", err)
	}
	if v, ok := got.(bool); !ok || v {
		t.Errorf("not found: got %v, want false", got)
	}
}

func TestHasTagFn_EmptySlice(t *testing.T) {
	t.Parallel()
	got, _ := hasTagFn([]string{}, "anything")
	if got != false {
		t.Errorf("empty slice: got %v, want false", got)
	}
}

// TestHasTagFn_ViaCompiledExpr exercises the env-registered function path
// through Compile + Evaluate.
func TestHasTagFn_ViaCompiledExpr(t *testing.T) {
	t.Parallel()
	doc := &PolicyDocument{
		Version: 1,
		Rules: []Rule{
			{
				Name:    "tag-gate",
				On:      EventConnect,
				Match:   `has_tag(peer_tags, "prod")`,
				Actions: []Action{{Type: ActionAllow}},
			},
		},
	}
	cp, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// peer_tags contains "prod" → match → allow.
	dirs, err := cp.Evaluate(EventConnect, map[string]interface{}{
		"port":       int(80),
		"peer_id":    int(0xCAFE),
		"network_id": int(1),
		"local_tags": []string{},
		"peer_tags":  []string{"web", "prod"},
		"peer_age_s": 0.0,
		"members":    0,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	foundAllow := false
	for _, d := range dirs {
		if d.Type == DirectiveAllow {
			foundAllow = true
		}
	}
	if !foundAllow {
		t.Errorf("expected Allow directive, got %+v", dirs)
	}
}
