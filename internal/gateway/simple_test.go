package gateway

import (
	"mcp-gateway/internal/config"
	"testing"
)

func TestSharedFullScenarioAndSchema(t *testing.T) {
	f := newFixtureAuth(t, "", "x-api-key")
	config.SimplifyAccess(&f.config)
	srv := f.config.Servers["demo"]
	srv.Tools["hidden"] = config.Tool{AccessMode: "shared"}
	f.config.Servers["demo"] = srv
	f.write()
	f.call("discover_server", map[string]any{"query": "echo"}, false)
	f.call("discover_tools", map[string]any{"server_id": "demo"}, false)
	f.call("get_tool_schema", map[string]any{"server_id": "demo", "tool_name": "echo"}, false)
	f.call("invoke_tool", invocation("without fixed restrictions"), false)
	before := f.calls.Load()
	for _, args := range []map[string]any{{"text": 42}, {}, {"text": "valid", "extra": true}} {
		f.call("invoke_tool", map[string]any{"server_id": "demo", "tool_name": "echo", "arguments": args}, true)
	}
	if f.calls.Load() != before {
		t.Fatal("schema failures invoked upstream")
	}
	f.call("get_tool_schema", map[string]any{"server_id": "demo", "tool_name": "hidden"}, true)
	srv.Tools["echo"] = config.Tool{AccessMode: "shared"}
	f.config.Servers["demo"] = srv
	f.write()
	f.call("invoke_tool", invocation("disabled"), true)
	if f.calls.Load() != before {
		t.Fatal("disabled tool invoked")
	}
	srv.Enabled = false
	f.config.Servers["demo"] = srv
	f.write()
	f.call("discover_tools", map[string]any{"server_id": "demo"}, true)
}
