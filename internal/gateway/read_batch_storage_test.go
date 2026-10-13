package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
)

func TestReadBatchStorageParity(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { testReadBatchStorage(t, "sqlite", filepath.Join(t.TempDir(), "batch.db")) })
	if dsn := os.Getenv("TEST_READ_BATCH_POSTGRES_DSN"); dsn != "" {
		t.Run("postgres", func(t *testing.T) { testReadBatchStorage(t, "postgres", dsn) })
	}
}
func testReadBatchStorage(t *testing.T, kind, location string) {
	f := newFixture(t)
	ctx := context.Background()
	if err := store.Migrate(ctx, kind, location); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(kind, location, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg, err := config.Clone(&f.config)
	if err != nil {
		t.Fatal(err)
	}
	server := cfg.Servers["demo"]
	server.TokenEnv = ""
	server.TokenRef = "demo"
	tool := server.Tools["echo"]
	tool.AccessMode = "shared"
	server.Tools["echo"] = tool
	cfg.Servers["demo"] = server
	managed := "mgw_" + strings.Repeat("b", 43)
	cfg.Principals["managed"] = config.Principal{TokenHash: config.TokenDigest(managed), Key: &config.ClientKey{Name: "Batch test", Prefix: managed[:12], CreatedAt: "2026-10-13T12:00:00Z"}, Grants: map[string]map[string]config.Grant{}}
	upstreamToken := backendToken
	snap, err := db.CompareAndSwap(ctx, 0, cfg, map[string]*string{"demo": &upstreamToken})
	if err != nil {
		t.Fatal("requires empty disposable database", err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	b, _ := json.Marshal(map[string]any{"version": 1, "operations": []map[string]string{{"server_id": "demo", "tool_name": "echo", "endpoint": server.URL}}})
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	cache := catalog.New()
	defer cache.Close()
	handler, err := (&Gateway{Store: db, Catalog: cache, ReadBatch: NewReadBatchExecutor(&ReadBatchPolicy{Path: path}), Timeout: time.Second}).Handler()
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(handler)
	defer web.Close()
	client := clientHeaderHTTPClient(managed, "X-API-Key")
	defer client.CloseIdleConnections()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "storage-batch-check", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: web.URL + "/mcp", HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	ops := map[string]any{"operations": []map[string]any{{"id": "first", "server_id": "demo", "tool_name": "echo", "arguments": map[string]any{"text": "first"}}, {"id": "second", "server_id": "demo", "tool_name": "echo", "arguments": map[string]any{"text": "second"}}}}
	before := f.calls.Load()
	r, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_read_batch", Arguments: ops})
	if err != nil || r.IsError {
		t.Fatalf("batch %v %+v", err, r)
	}
	encoded, _ := json.Marshal(r.StructuredContent)
	var out struct {
		Complete bool `json:"complete"`
		Results  []struct {
			ID, Status string
			ToolResult *mcp.CallToolResult `json:"tool_result"`
		} `json:"results"`
	}
	if err = json.Unmarshal(encoded, &out); err != nil || !out.Complete || len(out.Results) != 2 || f.calls.Load()-before != 2 {
		t.Fatalf("invalid envelope %s %v", encoded, err)
	}
	for i, id := range []string{"first", "second"} {
		item := out.Results[i]
		if item.ID != id || item.Status != "ok" || item.ToolResult == nil || len(item.ToolResult.Content) != 2 || item.ToolResult.Content[0].(*mcp.TextContent).Text != id {
			t.Fatal("ordered MCP parity failure")
		}
	}
	tool.Enabled = false
	server.Tools["echo"] = tool
	cfg.Servers["demo"] = server
	snap, err = db.CompareAndSwap(ctx, snap.Revision, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	before = f.calls.Load()
	r, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_read_batch", Arguments: ops})
	if err != nil || r.IsError {
		t.Fatal("valid batch should return per-item denial", err)
	}
	encoded, _ = json.Marshal(r.StructuredContent)
	if !bytes.Contains(encoded, []byte(`"status":"denied"`)) || f.calls.Load() != before {
		t.Fatal("disabled batch invoked upstream")
	}
	delete(cfg.Principals, "managed")
	if _, err = db.CompareAndSwap(ctx, snap.Revision, cfg, nil); err != nil {
		t.Fatal(err)
	}
	r, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_read_batch", Arguments: ops})
	if err == nil && (r == nil || !r.IsError) {
		t.Fatal("revoked managed key admitted")
	}
	if f.calls.Load() != before {
		t.Fatal("revoked client invoked upstream")
	}
}
