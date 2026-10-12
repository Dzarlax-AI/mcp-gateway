package policy

import (
	"encoding/json"
	"testing"

	"mcp-gateway/internal/config"
)

func TestArguments(t *testing.T) {
	g := config.Grant{AllowedArguments: []string{"scope", "n"}, RequiredArguments: []string{"scope"}, ArgumentEquals: map[string]any{"scope": map[string]any{"value": "safe"}, "n": json.Number("1")}}
	for _, tc := range []struct {
		a  map[string]any
		ok bool
	}{{map[string]any{"scope": map[string]any{"value": "safe"}, "n": json.Number("1.0")}, true}, {map[string]any{"scope": map[string]any{"value": "unsafe"}, "n": json.Number("1")}, false}, {map[string]any{"scope": map[string]any{"value": "safe"}, "n": json.Number("1.0000000000000000001")}, false}, {nil, false}, {map[string]any{"n": json.Number("1")}, false}, {map[string]any{"scope": nil, "n": json.Number("1")}, false}, {map[string]any{"scope": map[string]any{"value": "safe"}, "n": json.Number("1"), "extra": true}, false}} {
		if (Arguments(g, tc.a) == nil) != tc.ok {
			t.Fatalf("args=%v", tc.a)
		}
	}
}
