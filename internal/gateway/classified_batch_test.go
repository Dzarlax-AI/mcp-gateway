package gateway

import (
	"context"
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/readpolicy"
	"path/filepath"
	"testing"
)

func classifiedFixture(t *testing.T) *connectorFixture {
	f := newConnectorFixture(t, "sqlite", filepath.Join(t.TempDir(), "classified.db"))
	f.g.ReadBatch = NewReadBatchExecutor(&ReadBatchPolicy{Classified: true})
	f.change(t, func(c *config.Config) {
		c.Servers["ha"] = config.Server{Enabled: true, URL: f.url, Tools: map[string]config.Tool{}}
	})
	return f
}
func addClassifiedTool(t *testing.T, f *connectorFixture, name string, read bool) *mcp.Tool {
	tool := &mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object", "additionalProperties": true}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: read}}
	f.upstream.AddTool(tool, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.calls.Add(1)
		return result(map[string]any{"ok": true}), nil
	})
	f.change(t, func(c *config.Config) {
		srv := c.Servers["ha"]
		srv.Tools[name] = config.Tool{Enabled: true, AccessMode: "shared"}
		c.Servers["ha"] = srv
	})
	return tool
}
func TestClassifiedBatchEligibilityAndRevocation(t *testing.T) {
	f := classifiedFixture(t)
	read := addClassifiedTool(t, f, "arbitrary_reader", true)
	unknown := addClassifiedTool(t, f, "arbitrary_operation", false)
	f.publish(t)
	if !f.batch(t, read.Name, 2) || f.calls.Load() != 2 {
		t.Fatal("annotated read not batched")
	}
	if f.batch(t, unknown.Name, 1) || f.calls.Load() != 2 {
		t.Fatal("unknown dispatched")
	}
	f.change(t, func(c *config.Config) {
		srv := c.Servers["ha"]
		x := srv.Tools[read.Name]
		x.OperationKind = "write"
		srv.Tools[read.Name] = x
		c.Servers["ha"] = srv
	})
	if f.batch(t, read.Name, 1) {
		t.Fatal("manual write did not override annotation")
	}
	snapshot, _ := f.db.ReadSnapshot(context.Background())
	connection, _ := catalog.FromSnapshot(snapshot, "ha")
	hash, _ := readpolicy.OperationFingerprint(unknown, catalog.ConnectionBinding(connection))
	f.change(t, func(c *config.Config) {
		srv := c.Servers["ha"]
		x := srv.Tools[unknown.Name]
		x.OperationKind = "read"
		x.OperationContractHash = hash
		srv.Tools[unknown.Name] = x
		c.Servers["ha"] = srv
	})
	if !f.batch(t, unknown.Name, 1) {
		t.Fatal("manual read denied")
	}
	changed := *unknown
	changed.InputSchema = map[string]any{"type": "object", "properties": map[string]any{"new": map[string]any{"type": "string"}}}
	f.upstream.AddTool(&changed, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.calls.Add(1)
		return result(nil), nil
	})
	f.publish(t)
	before := f.calls.Load()
	if f.batch(t, unknown.Name, 1) || f.calls.Load() != before {
		t.Fatal("stale manual read dispatched")
	}
}
func TestClassifiedBatchRechecksTypeAfterInitialize(t *testing.T) {
	for _, kind := range []string{"type", "tool", "server", "principal"} {
		t.Run(kind, func(t *testing.T) {
			f := classifiedFixture(t)
			tool := addClassifiedTool(t, f, "read_then_revoked", true)
			f.publish(t)
			f.initializeHook.Store(&initializeHook{fn: func() {
				f.change(t, func(c *config.Config) {
					srv := c.Servers["ha"]
					x := srv.Tools[tool.Name]
					switch kind {
					case "type":
						x.OperationKind = "write"
					case "tool":
						x.Enabled = false
					case "server":
						srv.Enabled = false
					case "principal":
						p := c.Principals["client"]
						p.AccessPolicy = config.Restricted
						p.ToolAllowlist = map[string][]string{}
						c.Principals["client"] = p
					}
					srv.Tools[tool.Name] = x
					c.Servers["ha"] = srv
				})
			}})
			if f.batch(t, tool.Name, 1) || f.calls.Load() != 0 {
				t.Fatal("revocation during initialize dispatched", kind)
			}
		})
	}
}
func TestClassifiedBatchUsesStandardInputSchemaAndMetadata(t *testing.T) {
	f := classifiedFixture(t)
	tool := addClassifiedTool(t, f, "dynamic_read", true)
	f.publish(t)
	r := f.call(t, "invoke_read_batch", map[string]any{"operations": []map[string]any{{"id": "one", "server_id": "ha", "tool_name": tool.Name, "arguments": map[string]any{"additional": "permitted"}}}})
	b, _ := json.Marshal(r.StructuredContent)
	var v struct{ Complete bool }
	json.Unmarshal(b, &v)
	if !v.Complete {
		t.Fatalf("standard schema rejected declared additional properties: %s", b)
	}
	r = f.call(t, "discover_tools", map[string]any{"server_id": "ha"})
	b, _ = json.Marshal(r.StructuredContent)
	var listing struct {
		Tools []struct {
			OperationKind string `json:"operation_kind"`
			Allowed       bool   `json:"batch_read_allowed"`
		}
	}
	if json.Unmarshal(b, &listing) != nil || len(listing.Tools) != 1 {
		t.Fatalf("metadata %s", b)
	}
	found := false
	for _, x := range listing.Tools {
		if x.OperationKind == "read" && x.Allowed {
			found = true
		}
	}
	if !found {
		t.Fatalf("classified metadata missing: %s", b)
	}
}
