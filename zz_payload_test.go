// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"encoding/json"
	"testing"
)

func TestNetworkIDFromPayload_AllBranches(t *testing.T) {
	t.Parallel()
	if _, ok := networkIDFromPayload(nil); ok {
		t.Error("nil payload: ok = true")
	}
	cases := []struct {
		name    string
		payload map[string]any
		want    uint16
		wantOK  bool
	}{
		{"uint16", map[string]any{"network_id": uint16(7)}, 7, true},
		{"int", map[string]any{"network_id": 8}, 8, true},
		{"int64", map[string]any{"network_id": int64(9)}, 9, true},
		{"float64", map[string]any{"network_id": float64(10)}, 10, true},
		{"missing", map[string]any{}, 0, false},
		{"string-not-supported", map[string]any{"network_id": "11"}, 0, false},
	}
	for _, tc := range cases {
		got, ok := networkIDFromPayload(tc.payload)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestExprPolicyJSONFromPayload_AllBranches(t *testing.T) {
	t.Parallel()
	if _, ok := exprPolicyJSONFromPayload(nil); ok {
		t.Error("nil payload: ok = true")
	}
	if _, ok := exprPolicyJSONFromPayload(map[string]any{}); ok {
		t.Error("missing field: ok = true")
	}
	if _, ok := exprPolicyJSONFromPayload(map[string]any{"expr_policy": nil}); ok {
		t.Error("nil value: ok = true")
	}

	// String → RawMessage.
	got, ok := exprPolicyJSONFromPayload(map[string]any{"expr_policy": `{"version":1}`})
	if !ok || string(got) != `{"version":1}` {
		t.Errorf("string: got (%s, %v)", got, ok)
	}

	// []byte → RawMessage.
	got, ok = exprPolicyJSONFromPayload(map[string]any{"expr_policy": []byte(`{"x":1}`)})
	if !ok || string(got) != `{"x":1}` {
		t.Errorf("[]byte: got (%s, %v)", got, ok)
	}

	// json.RawMessage passthrough.
	raw := json.RawMessage(`{"k":1}`)
	got, ok = exprPolicyJSONFromPayload(map[string]any{"expr_policy": raw})
	if !ok || string(got) != string(raw) {
		t.Errorf("RawMessage: got (%s, %v)", got, ok)
	}

	// map[string]any → marshaled.
	got, ok = exprPolicyJSONFromPayload(map[string]any{
		"expr_policy": map[string]any{"version": float64(2)},
	})
	if !ok || len(got) == 0 {
		t.Errorf("map: got (%s, %v)", got, ok)
	}

	// Fallback marshal for any other type (int).
	got, ok = exprPolicyJSONFromPayload(map[string]any{"expr_policy": 42})
	if !ok || string(got) != "42" {
		t.Errorf("int fallback: got (%s, %v)", got, ok)
	}
}
