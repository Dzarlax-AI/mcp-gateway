package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"mcp-gateway/internal/upstream"
)

func cachedFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	p := catalog.New()
	t.Cleanup(p.Close)
	handler, err := (&Gateway{Path: f.path, Catalog: p, Timeout: time.Second}).Handler()
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(handler)
	t.Cleanup(web.Close)
	h := upstream.HTTPClient(clientToken, 3*time.Second)
	t.Cleanup(h.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "search-client", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: web.URL + "/mcp", HTTPClient: h, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.session.Close()
	f.session = session
	return f
}

func searchResponse(t *testing.T, r *mcp.CallToolResult) searchResult {
	t.Helper()
	b, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out searchResult
	if err = json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSearchVisibilityValidationAndPartialFailure(t *testing.T) {
	f := cachedFixture(t)
	out := searchResponse(t, f.call("search_tools", map[string]any{"query": "echo"}, false))
	if !out.Complete || len(out.Tools) != 2 || out.Tools[0].ToolName != "echo" || out.Tools[0].Definition == nil || !out.Tools[0].SchemaIncluded {
		t.Fatal("ranking/schema", out)
	}
	for _, item := range out.Tools {
		if item.ToolName == "hidden" {
			t.Fatal("unauthorized metadata leak")
		}
	}
	warm := f.requests.Load()
	f.call("get_tool_schema", map[string]any{"server_id": "demo", "tool_name": "echo"}, false)
	f.call("discover_tools", map[string]any{"server_id": "demo"}, false)
	if f.requests.Load() != warm {
		t.Fatal("warm metadata contacted upstream")
	}
	for _, args := range []map[string]any{{"query": " "}, {"query": strings.Repeat("я", 257)}, {"query": "echo", "limit": 11}, {"query": "echo", "unknown": true}, {"query": "echo", "server_id": "secret"}} {
		f.call("search_tools", args, true)
	}
	if f.requests.Load() != warm {
		t.Fatal("invalid search contacted upstream")
	}
	f.config.Servers["offline"] = config.Server{URL: "http://127.0.0.1:1/mcp", Enabled: true, Tools: map[string]config.Tool{"read": {Enabled: true, AccessMode: "shared"}}}
	f.config.Servers["private"] = config.Server{URL: "http://127.0.0.1:1/mcp", Enabled: true, Tools: map[string]config.Tool{"read": {Enabled: true}}}
	f.write()
	out = searchResponse(t, f.call("search_tools", map[string]any{"query": "echo"}, false))
	if out.Complete || len(out.Unavailable) != 1 || out.Unavailable[0] != "offline" || len(out.Tools) == 0 {
		t.Fatal("partial status leaked private server or hid failure", out)
	}
	f.call("search_tools", map[string]any{"query": "read", "server_id": "offline"}, true)
	f.call("invoke_tool", invocation("cached"), false)
	s := f.config.Servers["demo"]
	v := s.Tools["echo"]
	v.Enabled = false
	s.Tools["echo"] = v
	f.config.Servers["demo"] = s
	f.write()
	before := f.calls.Load()
	f.call("invoke_tool", invocation("disabled"), true)
	if f.calls.Load() != before {
		t.Fatal("cached schema bypassed live disable")
	}
}

func TestSearchSchemaBudgetAndStableTie(t *testing.T) {
	f := newFixture(t)
	p := catalog.New()
	defer p.Close()
	cfg, err := config.Clone(&f.config)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot{Config: cfg}
	connection, err := catalog.FromSnapshot(snapshot, "demo")
	if err != nil {
		t.Fatal(err)
	}
	huge := &mcp.Tool{Name: "echo", Description: "Huge echo definition", InputSchema: map[string]any{"type": "object", "description": strings.Repeat("x", 100000)}}
	if err = p.Publish(connection, 0, time.Now(), []*mcp.Tool{huge}); err != nil {
		t.Fatal(err)
	}
	g := Gateway{Catalog: p, Path: f.path}
	res := g.search(context.Background(), snapshot, "local", input{Query: "echo"}, http.Header{"Authorization": {"Bearer " + clientToken}})
	out := searchResponse(t, res)
	b, _ := json.Marshal(res)
	if len(b) > searchBudget || len(out.Tools) != 1 || out.Tools[0].SchemaIncluded || out.Tools[0].Definition != nil || out.Tools[0].OmittedReason != "response_budget" {
		t.Fatal("schema was truncated or response exceeds budget")
	}
	// Ranking ties use names, never the randomized registry map order.
	cfg.Servers["aaa"] = cfg.Servers["demo"]
	cfg.Principals["local"] = config.Principal{ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
		TokenEnv: "TEST_CLIENT_TOKEN", Grants: map[string]map[string]config.Grant{"demo": cfg.Principals["local"].Grants["demo"], "aaa": cfg.Principals["local"].Grants["demo"]}}
	conn, _ := catalog.FromSnapshot(snapshot, "aaa")
	if err = p.Publish(conn, 0, time.Now(), []*mcp.Tool{huge}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	os.WriteFile(f.path, raw, 0600)
	out = searchResponse(t, g.search(context.Background(), snapshot, "local", input{Query: "echo"}, http.Header{"Authorization": {"Bearer " + clientToken}}))
	if len(out.Tools) != 2 || out.Tools[0].ServerID != "aaa" || out.Tools[1].ServerID != "demo" {
		t.Fatal("tie order", out)
	}
}

func TestCachedMissingToolRefreshesOnlyOnce(t *testing.T) {
	f := cachedFixture(t)
	f.call("search_tools", map[string]any{"query": "echo"}, false)
	s := f.config.Servers["demo"]
	s.Tools["missing"] = config.Tool{Enabled: true, AccessMode: "shared"}
	f.config.Servers["demo"] = s
	f.write()
	before := f.requests.Load()
	f.call("get_tool_schema", map[string]any{"server_id": "demo", "tool_name": "missing"}, true)
	delta := f.requests.Load() - before
	// This stateless SDK transport sends initialize + tools/list, with no DELETE.
	if delta != 2 {
		t.Fatal("missing tool should perform one catalog refresh", delta)
	}
	before = f.calls.Load()
	f.call("invoke_tool", map[string]any{"server_id": "demo", "tool_name": "missing", "arguments": map[string]any{}}, true)
	if f.calls.Load() != before {
		t.Fatal("missing tool invoked upstream")
	}
}
