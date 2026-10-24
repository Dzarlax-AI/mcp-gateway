package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/readpolicy"
	"mcp-gateway/internal/store"

	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type initializeHook struct{ fn func() }
type connectorFixture struct {
	initializeHook atomic.Pointer[initializeHook]
	db             store.Store
	cache          *catalog.Provider
	upstream       *mcp.Server
	g              *Gateway
	session        *mcp.ClientSession
	calls          atomic.Int64
	url            string
}

func newConnectorFixture(t *testing.T, kind, location string) *connectorFixture {
	t.Helper()
	ctx := context.Background()
	t.Setenv("CONNECTOR_CLIENT", "synthetic-connector-client-token")
	if e := store.Migrate(ctx, kind, location); e != nil {
		t.Fatal(e)
	}
	db, e := store.Open(kind, location, bytes.Repeat([]byte{13}, 32))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	cfg := &config.Config{RegistryVersion: 2,
		Servers: map[string]config.Server{}, Principals: map[string]config.Principal{"client": {ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
			TokenEnv: "CONNECTOR_CLIENT", Grants: map[string]map[string]config.Grant{}}}}
	if _, e = db.CompareAndSwap(ctx, 0, cfg, nil); e != nil {
		t.Fatal("requires empty test DB", e)
	}
	f := &connectorFixture{db: db, cache: catalog.New(), upstream: mcp.NewServer(&mcp.Implementation{Name: "synthetic-home-assistant", Version: "1"}, nil)}
	t.Cleanup(f.cache.Close)
	add := func(tool *mcp.Tool) {
		f.upstream.AddTool(tool, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.calls.Add(1)
			time.Sleep(10 * time.Millisecond)
			return result(map[string]any{"synthetic": true}), nil
		})
	}
	add(readpolicy.ReviewedTools("home-assistant-v1")[1])
	baseHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return f.upstream }, nil)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var v struct{ Method string }
			json.Unmarshal(body, &v)
			if v.Method == "initialize" {
				if hook := f.initializeHook.Swap(nil); hook != nil {
					hook.fn()
				}
			}
		}
		baseHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(web.Close)
	f.url = web.URL
	f.g = &Gateway{Store: db, Catalog: f.cache, ReadBatch: NewReadBatchExecutor(&ReadBatchPolicy{Registry: true}), Timeout: time.Second}
	h, e := f.g.Handler()
	if e != nil {
		t.Fatal(e)
	}
	gw := httptest.NewServer(h)
	t.Cleanup(gw.Close)
	client := clientHeaderHTTPClient("synthetic-connector-client-token", "X-API-Key")
	t.Cleanup(client.CloseIdleConnections)
	f.session, e = mcp.NewClient(&mcp.Implementation{Name: "same-session-test", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: gw.URL + "/mcp", HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.session.Close() })
	return f
}
func (f *connectorFixture) change(t *testing.T, fn func(*config.Config)) {
	t.Helper()
	s, e := f.db.ReadSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	fn(s.Config)
	if _, e = f.db.CompareAndSwap(context.Background(), s.Revision, s.Config, nil); e != nil {
		t.Fatal(e)
	}
}
func (f *connectorFixture) publish(t *testing.T) {
	t.Helper()
	s, _ := f.db.ReadSnapshot(context.Background())
	c, e := catalog.FromSnapshot(s, "ha")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.cache.Get(context.Background(), c, true); e != nil {
		t.Fatal(e)
	}
}
func (f *connectorFixture) call(t *testing.T, name string, args any) *mcp.CallToolResult {
	t.Helper()
	r, e := f.session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func (f *connectorFixture) batch(t *testing.T, name string, n int) bool {
	t.Helper()
	ops := []map[string]any{}
	for i := 0; i < n; i++ {
		ops = append(ops, map[string]any{"id": fmt.Sprint(i), "server_id": "ha", "tool_name": name, "arguments": map[string]any{}})
	}
	r := f.call(t, "invoke_read_batch", map[string]any{"operations": ops})
	b, _ := json.Marshal(r.StructuredContent)
	var v struct {
		Complete bool
		Results  []struct {
			Status     string
			Dispatched bool
		}
	}
	json.Unmarshal(b, &v)
	if v.Complete {
		if len(v.Results) != n {
			t.Fatal("missing items")
		}
		for _, x := range v.Results {
			if x.Status != "ok" || !x.Dispatched {
				t.Fatal("bad item")
			}
		}
	}
	return !r.IsError && v.Complete
}
func (f *connectorFixture) enable(t *testing.T) {
	f.change(t, func(c *config.Config) {
		c.Servers["ha"] = config.Server{Enabled: true, URL: f.url, BatchReadEnabled: true, BatchReadEndpoint: f.url, BatchReadProfile: "home-assistant-v1", Tools: map[string]config.Tool{"llm__GetDateTime": {Enabled: true, AccessMode: "shared"}}}
	})
}
func TestConnectorBatchSameSDKSession(t *testing.T) {
	run := func(t *testing.T, kind, location string) {
		f := newConnectorFixture(t, kind, location)
		r := f.call(t, "discover_server", map[string]any{})
		b, _ := json.Marshal(r.StructuredContent)
		if string(b) != "{\"servers\":[]}" {
			t.Fatal(string(b))
		}
		f.enable(t)
		f.publish(t)
		if !f.batch(t, "llm__GetDateTime", 1) {
			t.Fatal("new connector not admitted")
		}
		if e := f.db.Close(); e != nil {
			t.Fatal(e)
		}
		reopened, e := store.Open(kind, location, bytes.Repeat([]byte{13}, 32))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { reopened.Close() })
		f.db = reopened
		f.g.Store = reopened
		persisted, e := reopened.ReadSnapshot(context.Background())
		if e != nil || !persisted.Config.Servers["ha"].BatchReadEnabled {
			t.Fatal("batch settings not persistent", e)
		}
		if !f.batch(t, "llm__GetDateTime", 1) {
			t.Fatal("existing MCP session after store reopen")
		}

		// Upstream adds both a reviewed read and an unknown misleading readOnly tool.
		read := readpolicy.ReviewedTools("home-assistant-v1")[0]
		unknown := &mcp.Tool{Name: "get_mutate", Description: "unknown", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
		for _, tool := range []*mcp.Tool{read, unknown} {
			f.upstream.AddTool(tool, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.calls.Add(1)
				return result(map[string]any{"synthetic": true}), nil
			})
		}
		f.change(t, func(c *config.Config) {
			s := c.Servers["ha"]
			for _, tool := range []*mcp.Tool{read, unknown} {
				s.Tools[tool.Name] = config.Tool{Enabled: true, AccessMode: "shared"}
			}
			c.Servers["ha"] = s
		})
		f.publish(t)
		if !f.batch(t, read.Name, 3) {
			t.Fatal("new known tool not admitted")
		}
		before := f.calls.Load()
		if f.batch(t, unknown.Name, 1) || f.calls.Load() != before {
			t.Fatal("unknown dispatched")
		}
		changed := *read
		changed.Description += " modified"
		f.upstream.AddTool(&changed, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.calls.Add(1)
			return result(nil), nil
		})
		f.publish(t)
		if f.batch(t, read.Name, 1) || f.calls.Load() != before {
			t.Fatal("changed contract dispatched")
		}
		f.change(t, func(c *config.Config) {
			s := c.Servers["ha"]
			s.BatchReadEnabled = false
			s.BatchReadEndpoint = ""
			c.Servers["ha"] = s
		})
		if f.batch(t, "llm__GetDateTime", 1) || f.calls.Load() != before {
			t.Fatal("revoked batch dispatched")
		}
	}
	t.Run("sqlite", func(t *testing.T) { run(t, "sqlite", filepath.Join(t.TempDir(), "registry.db")) })
	if dsn := os.Getenv("TEST_CONNECTOR_POSTGRES_DSN"); dsn != "" {
		t.Run("postgres", func(t *testing.T) { run(t, "postgres", dsn) })
	}
}
func TestConnectorBatchWarmBenchmark(t *testing.T) {
	f := newConnectorFixture(t, "sqlite", filepath.Join(t.TempDir(), "registry.db"))
	f.enable(t)
	f.publish(t)
	path := filepath.Join(t.TempDir(), "allowlist.json")
	b, _ := json.Marshal(map[string]any{"version": 1, "operations": []map[string]string{{"server_id": "ha", "tool_name": "llm__GetDateTime", "endpoint": f.url}}})
	os.WriteFile(path, b, 0600)
	rows := []map[string]any{}
	summary := map[string]map[string]float64{}
	for cycle := 0; cycle < 20; cycle++ {
		modes := []string{"file", "registry"}
		if cycle%2 == 1 {
			modes = []string{"registry", "file"}
		}
		for _, mode := range modes {
			for _, n := range []int{1, 3} {
				f.g.ReadBatch.policy = &ReadBatchPolicy{Registry: mode == "registry"}
				if mode == "file" {
					f.g.ReadBatch.policy.Path = path
				}
				start := time.Now()
				if !f.batch(t, "llm__GetDateTime", n) {
					t.Fatal("benchmark failed")
				}
				rows = append(rows, map[string]any{"cycle": cycle + 1, "mode": mode, "items": n, "ms": float64(time.Since(start).Microseconds()) / 1000})
			}
		}
	}
	for _, mode := range []string{"file", "registry"} {
		for _, n := range []int{1, 3} {
			vs := []float64{}
			for _, r := range rows {
				if r["mode"] == mode && r["items"] == n {
					vs = append(vs, r["ms"].(float64))
				}
			}
			sort.Float64s(vs)
			summary[fmt.Sprintf("%s_%d", mode, n)] = map[string]float64{"median_ms": (vs[9] + vs[10]) / 2, "p95_ms": vs[18]}
		}
	}
	if f.calls.Load() != 160 {
		t.Fatalf("unexpected retries/call count %d", f.calls.Load())
	}
	output, _ := json.MarshalIndent(map[string]any{"rows": rows, "summary": summary, "upstream_calls": f.calls.Load(), "scope": "synthetic 10ms read; persistent SDK session; 20 alternating cycles"}, "", "  ")
	os.WriteFile("/tmp/connector-batch-benchmark.json", output, 0600)
	t.Log(string(mustJSON(summary)))
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestConnectorBatchRevocationWhileInitializeIsBlocked(t *testing.T) {
	f := newConnectorFixture(t, "sqlite", filepath.Join(t.TempDir(), "registry.db"))
	f.enable(t)
	f.publish(t)
	arrived := make(chan struct{})
	release := make(chan struct{})
	f.initializeHook.Store(&initializeHook{fn: func() { close(arrived); <-release }})
	done := make(chan bool)
	go func() { done <- f.batch(t, "llm__GetDateTime", 1) }()
	<-arrived
	f.change(t, func(c *config.Config) {
		s := c.Servers["ha"]
		s.BatchReadEnabled = false
		s.BatchReadEndpoint = ""
		c.Servers["ha"] = s
	})
	close(release)
	if <-done || f.calls.Load() != 0 {
		t.Fatal("revocation after initialize failed")
	}
}

func TestConnectorBatchTTLExistingSession(t *testing.T) {
	if testing.Short() {
		t.Skip("real 60-second TTL acceptance")
	}
	f := newConnectorFixture(t, "sqlite", filepath.Join(t.TempDir(), "registry.db"))
	f.enable(t)
	f.publish(t)
	// Keep an existing contract present so absence-triggered refresh cannot mask TTL.
	tool := readpolicy.ReviewedTools("home-assistant-v1")[1]
	changed := *tool
	changed.Description += " upstream update"
	f.upstream.AddTool(&changed, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.calls.Add(1)
		return result(map[string]any{"synthetic": true}), nil
	})
	r := f.call(t, "search_tools", map[string]any{"server_id": "ha", "query": "llm__GetDateTime"})
	b, _ := json.Marshal(r.StructuredContent)
	if bytes.Contains(b, []byte("upstream update")) {
		t.Fatal("fixture was not warm")
	}
	newRead := readpolicy.ReviewedTools("home-assistant-v1")[0]
	f.upstream.AddTool(newRead, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		f.calls.Add(1)
		return result(map[string]any{"synthetic": true}), nil
	})
	f.change(t, func(c *config.Config) {
		s := c.Servers["ha"]
		s.Tools[newRead.Name] = config.Tool{Enabled: true, AccessMode: "shared"}
		c.Servers["ha"] = s
	})
	unseen := f.call(t, "search_tools", map[string]any{"server_id": "ha", "query": newRead.Name})
	unseenJSON, _ := json.Marshal(unseen.StructuredContent)
	if bytes.Contains(unseenJSON, []byte(newRead.Name)) {
		t.Fatal("new tool was visible before TTL")
	}
	time.Sleep(61 * time.Second)
	r = f.call(t, "search_tools", map[string]any{"server_id": "ha", "query": "llm__GetDateTime"})
	b, _ = json.Marshal(r.StructuredContent)
	if !bytes.Contains(b, []byte("upstream update")) || !bytes.Contains(b, []byte("contract_changed")) {
		t.Fatalf("TTL did not refresh/revoke %s", b)
	}
	if f.batch(t, tool.Name, 1) || f.calls.Load() != 0 {
		t.Fatal("stale metadata allowed dispatch")
	}
	found := f.call(t, "search_tools", map[string]any{"server_id": "ha", "query": newRead.Name})
	foundJSON, _ := json.Marshal(found.StructuredContent)
	if !bytes.Contains(foundJSON, []byte(newRead.Name)) || !bytes.Contains(foundJSON, []byte(`"batch_read_allowed":true`)) {
		t.Fatalf("TTL did not discover eligible new read: %s", foundJSON)
	}
	if !f.batch(t, newRead.Name, 1) || f.calls.Load() != 1 {
		t.Fatal("new read not callable after TTL in existing session")
	}

}

func TestConnectorBatchFreshRegistryDenials(t *testing.T) {
	for _, name := range []string{"server_disabled", "tool_disabled", "profile_changed", "client_revoked"} {
		t.Run(name, func(t *testing.T) {
			f := newConnectorFixture(t, "sqlite", filepath.Join(t.TempDir(), "registry.db"))
			f.enable(t)
			f.publish(t)
			if !f.batch(t, "llm__GetDateTime", 1) {
				t.Fatal("initial read failed")
			}
			before := f.calls.Load()
			t.Setenv("CONNECTOR_OTHER", "synthetic-replacement-client-token")
			f.change(t, func(c *config.Config) {
				s := c.Servers["ha"]
				switch name {
				case "server_disabled":
					s.Enabled = false
				case "tool_disabled":
					x := s.Tools["llm__GetDateTime"]
					x.Enabled = false
					s.Tools["llm__GetDateTime"] = x
				case "profile_changed":
					s.BatchReadProfile = "calendar-mcp-v1"
				case "client_revoked":
					p := c.Principals["client"]
					p.TokenEnv = "CONNECTOR_OTHER"
					c.Principals["client"] = p
				}
				c.Servers["ha"] = s
			})
			if name == "client_revoked" {
				_, err := f.session.CallTool(context.Background(), &mcp.CallToolParams{Name: "invoke_read_batch", Arguments: map[string]any{"operations": []map[string]any{{"id": "x", "server_id": "ha", "tool_name": "llm__GetDateTime", "arguments": map[string]any{}}}}})
				if err == nil || !strings.Contains(err.Error(), "Unauthorized") || f.calls.Load() != before {
					t.Fatal("revoked client passed HTTP admission", err)
				}
			} else if f.batch(t, "llm__GetDateTime", 1) || f.calls.Load() != before {
				t.Fatal("fresh admission failed")
			}
		})
	}
}

func TestConnectorBatchRestrictedACLRevocationAfterInitialize(t *testing.T) {
	f := newConnectorFixture(t, "sqlite", filepath.Join(t.TempDir(), "registry.db"))
	f.enable(t)
	f.publish(t)
	f.change(t, func(c *config.Config) {
		p := c.Principals["client"]
		p.AccessPolicy = config.Restricted
		p.ToolAllowlist = map[string][]string{"ha": {"llm__GetDateTime"}}
		c.Principals["client"] = p
	})
	if !f.batch(t, "llm__GetDateTime", 1) {
		t.Fatal("restricted positive control")
	}
	before := f.calls.Load()
	arrived, release := make(chan struct{}), make(chan struct{})
	f.initializeHook.Store(&initializeHook{fn: func() { close(arrived); <-release }})
	done := make(chan bool)
	go func() { done <- f.batch(t, "llm__GetDateTime", 1) }()
	<-arrived
	f.change(t, func(c *config.Config) {
		p := c.Principals["client"]
		p.ToolAllowlist = map[string][]string{}
		c.Principals["client"] = p
	})
	close(release)
	if <-done || f.calls.Load() != before {
		t.Fatal("revoked ACL dispatched registry batch")
	}
}
