package policy

import (
	"mcp-gateway/internal/config"
	"testing"
)

func TestSharedEnablement(t *testing.T) {
	c := &config.Config{Servers: map[string]config.Server{"s": {Enabled: true, Tools: map[string]config.Tool{"t": {Enabled: true, AccessMode: "shared"}}}}, Principals: map[string]config.Principal{"one": {}, "two": {}}}
	for _, p := range []string{"one", "two"} {
		g, err := Grant(c, p, "s", "t")
		if err != nil || !Visible(c, p, "s") || !g.SchemaOnly || Arguments(g, map[string]any{"nested": map[string]any{"value": true}}) != nil {
			t.Fatal("shared access", p, err)
		}
		if Arguments(g, nil) == nil {
			t.Fatal("nil arguments accepted")
		}
	}
	if _, err := Grant(c, "unknown", "s", "t"); err == nil || Visible(c, "unknown", "s") {
		t.Fatal("unknown principal")
	}
	srv := c.Servers["s"]
	srv.Tools["t"] = config.Tool{AccessMode: "shared"}
	c.Servers["s"] = srv
	if Visible(c, "one", "s") {
		t.Fatal("disabled tool visible")
	}
	srv.Tools["t"] = config.Tool{Enabled: true, AccessMode: "shared"}
	srv.Enabled = false
	c.Servers["s"] = srv
	if Visible(c, "one", "s") {
		t.Fatal("disabled server visible")
	}
}
