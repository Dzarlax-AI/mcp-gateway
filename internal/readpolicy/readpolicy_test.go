package readpolicy

import (
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"testing"
)

func TestReviewedContractsAndFailClosedChanges(t *testing.T) {
	for _, profile := range []string{"calendar-mcp-v1", "home-assistant-v1"} {
		tools := ReviewedTools(profile)
		if len(tools) == 0 {
			t.Fatal("missing contracts")
		}
		for _, tool := range tools {
			if ok, r := Classify(profile, tool); !ok {
				t.Fatalf("%s: %s", tool.Name, r)
			}
			for _, change := range []string{"description", "title", "input", "output", "annotations", "name"} {
				b, _ := json.Marshal(tool)
				var changed mcp.Tool
				json.Unmarshal(b, &changed)
				switch change {
				case "description":
					changed.Description += " changed"
				case "title":
					changed.Title += " changed"
				case "input":
					changed.InputSchema = map[string]any{"type": "object", "properties": map[string]any{"set": map[string]any{"type": "string"}}}
				case "output":
					changed.OutputSchema = map[string]any{"type": "object"}
				case "annotations":
					changed.Annotations = nil
				case "name":
					changed.Name = "get_mutate"
				}
				if ok, _ := Classify(profile, &changed); ok {
					t.Fatalf("accepted changed %s/%s", tool.Name, change)
				}
			}
		}
	}
	if ok, _ := Classify("unknown", ReviewedTools("home-assistant-v1")[0]); ok {
		t.Fatal("unknown profile")
	}
	if ok, _ := Classify("home-assistant-v1", nil); ok {
		t.Fatal("nil tool")
	}
	// Returned fixtures cannot mutate the embedded rule set.
	tools := ReviewedTools("home-assistant-v1")
	tools[0].Description = "spoof"
	if ok, _ := Classify("home-assistant-v1", tools[0]); ok {
		t.Fatal("mutable policy")
	}
}
func TestCanonicalSchemaObjectOrder(t *testing.T) {
	x := ReviewedTools("home-assistant-v1")[0]
	b, _ := json.Marshal(x.InputSchema)
	x.InputSchema = json.RawMessage(b)
	if ok, r := Classify("home-assistant-v1", x); !ok {
		t.Fatal(r)
	}
}

func TestUndeclaredArgumentsDenied(t *testing.T) {
	dt := ReviewedTools("home-assistant-v1")[1]
	if !Arguments(dt, map[string]any{}) || Arguments(dt, map[string]any{"action": "turn_on"}) {
		t.Fatal("datetime args")
	}
	live := ReviewedTools("home-assistant-v1")[0]
	if !Arguments(live, map[string]any{"domain": "light"}) || Arguments(live, map[string]any{"domain": "light", "action": "turn_on"}) {
		t.Fatal("live args")
	}
}

func BenchmarkClassification(b *testing.B) {
	for _, profile := range []string{"calendar-mcp-v1", "home-assistant-v1"} {
		b.Run(profile, func(b *testing.B) {
			t := ReviewedTools(profile)[0]
			b.ReportAllocs()
			for b.Loop() {
				ok, _ := Classify(profile, t)
				if !ok {
					b.Fatal("reviewed read denied")
				}
			}
		})
	}
}
