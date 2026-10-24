package gateway

import (
	"context"
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/accessauth"
	"mcp-gateway/internal/audit"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentACLAllEntryPointsAndIdentityPaths(t *testing.T) {
	f := newFixture(t)
	srv := f.config.Servers["demo"]
	for name, tool := range srv.Tools {
		tool.AccessMode = "shared"
		srv.Tools[name] = tool
	}
	f.config.Servers["demo"] = srv
	p := f.config.Principals["local"]
	p.AccessPolicy = config.Restricted
	p.ToolAllowlist = map[string][]string{"demo": {"echo"}}
	f.config.Principals["local"] = p
	t.Setenv("ACL_SECOND_TOKEN", "synthetic-second-client-token")
	f.config.Principals["second"] = config.Principal{TokenEnv: "ACL_SECOND_TOKEN", AccessPolicy: config.Restricted, ToolAllowlist: map[string][]string{"demo": {"hidden"}}}
	f.write()
	cache := catalog.New()
	defer cache.Close()
	policyPath := filepath.Join(t.TempDir(), "batch.json")
	b, _ := json.Marshal(map[string]any{"version": 1, "operations": []map[string]string{{"server_id": "demo", "tool_name": "echo", "endpoint": srv.URL}, {"server_id": "demo", "tool_name": "hidden", "endpoint": srv.URL}}})
	os.WriteFile(policyPath, b, 0600)
	g := &Gateway{Path: f.path, Catalog: cache, ReadBatch: NewReadBatchExecutor(&ReadBatchPolicy{Path: policyPath}), Timeout: time.Second}
	verifier, assertions := accessFixture(t, map[string]string{"local@example.net": "local", "second@example.net": "second"})
	g.PublicOrigin = "https://mcp.example.org"
	g.AccessOAuth = verifier
	handler, e := g.Handler()
	if e != nil {
		t.Fatal(e)
	}
	web := httptest.NewServer(handler)
	defer web.Close()

	for _, auth := range []string{"bearer", "apikey", "oauth"} {
		for _, id := range []string{"local", "second"} {
			t.Run(auth+"/"+id, func(t *testing.T) {
				ctx := context.Background()
				headers := http.Header{}
				token := clientToken
				allowed, denied := "echo", "hidden"
				if id == "second" {
					token = "synthetic-second-client-token"
					allowed, denied = "hidden", "echo"
				}
				switch auth {
				case "bearer":
					headers.Set("Authorization", "Bearer "+token)
				case "apikey":
					headers.Set("X-API-Key", token)
				case "oauth":
					ctx = withAccessIdentity(ctx, accessauth.Identity{Principal: id, ExpiresAt: time.Now().Add(time.Minute)})
					headers.Set("Authorization", "Bearer oauth:synthetic")
				}
				client := &http.Client{Transport: accessRoundTrip(func(r *http.Request) (*http.Response, error) {
					r.Host = "mcp.example.org"
					for key, values := range headers {
						r.Header[key] = append([]string{}, values...)
					}
					if auth == "oauth" {
						r.Header.Set("Cf-Access-Jwt-Assertion", assertions(id+"@example.net"))
					}
					return http.DefaultTransport.RoundTrip(r)
				})}
				endpoint := web.URL + "/mcp"
				if auth == "oauth" {
					endpoint += "/oauth"
				}
				session, e := mcp.NewClient(&mcp.Implementation{Name: "acl-matrix", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
				if e != nil {
					t.Fatal(e)
				}
				defer session.Close()
				call := func(name string, args any) *mcp.CallToolResult {
					t.Helper()
					res, e := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
					if e != nil {
						t.Fatal(e)
					}
					return res
				}

				if call("discover_server", map[string]any{"query": ""}).IsError {
					t.Fatal("discovery")
				}
				for _, name := range []string{"discover_tools", "search_tools"} {
					args := map[string]any{"server_id": "demo"}
					if name == "search_tools" {
						args = map[string]any{"query": "echo hidden"}
					}
					res := call(name, args)
					raw, _ := json.Marshal(res.StructuredContent)
					if res.IsError || !strings.Contains(string(raw), `"`+allowed+`"`) || strings.Contains(string(raw), `"`+denied+`"`) {
						t.Fatalf("catalog leak %s: %s", name, raw)
					}
				}
				for _, name := range []string{"get_tool_schema", "invoke_tool"} {
					for _, tool := range []string{allowed, denied} {
						args := map[string]any{"server_id": "demo", "tool_name": tool}
						if name == "invoke_tool" {
							args["arguments"] = map[string]any{"text": "synthetic"}
						}
						res := call(name, args)
						if res.IsError != (tool == denied) {
							t.Fatal("direct known name bypass", name, tool)
						}
					}
				}
				res := call("invoke_read_batch", map[string]any{"operations": []map[string]any{{"id": "yes", "server_id": "demo", "tool_name": allowed, "arguments": map[string]any{"text": "synthetic"}}, {"id": "no", "server_id": "demo", "tool_name": denied, "arguments": map[string]any{"text": "synthetic"}}}})
				if res.IsError {
					t.Fatal("batch")
				}
				var decoded struct {
					Results []readBatchItemResult `json:"results"`
				}
				raw, _ := json.Marshal(res.StructuredContent)
				if e := json.Unmarshal(raw, &decoded); e != nil {
					t.Fatal(e)
				}
				items := decoded.Results
				if items[0].Status != "ok" || items[1].Status != "denied" || items[1].Dispatched {
					t.Fatal(items)
				}
			})
		}
	}
}
func TestOrdinaryACLRechecksAfterInitialize(t *testing.T) {
	for _, warm := range []bool{false, true} {
		for _, change := range []string{"acl", "principal", "switch", "endpoint", "secret", "unrelated"} {
			t.Run(change+map[bool]string{true: "/cache", false: "/no-cache"}[warm], func(t *testing.T) {
				back := &controlledBatchBackend{initEntered: make(chan struct{}, 4), initRelease: make(chan struct{}), entered: make(chan string, 4), activeByGroup: map[string]int{}, maxByGroup: map[string]int{}}
				g, headers, path := newControlledBatchGateway(t, back)
				cfg, e := config.Load(path)
				if e != nil {
					t.Fatal(e)
				}
				p := cfg.Principals["local"]
				p.AccessPolicy = config.Restricted
				p.ToolAllowlist = map[string][]string{"demo": {"read"}}
				cfg.Principals["local"] = p
				write := func() { b, _ := json.Marshal(cfg); os.WriteFile(path+".tmp", b, 0600); os.Rename(path+".tmp", path) }
				write()
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				if warm {
					conn, _ := catalog.FromSnapshot(store.Snapshot{Config: cfg}, "demo")
					if _, e = g.Catalog.Get(ctx, conn, false); e != nil {
						t.Fatal(e)
					}
				} else {
					g.Catalog = nil
				}
				back.blockInit.Store(true)
				raw := json.RawMessage(`{"server_id":"demo","tool_name":"read","arguments":{"group":"test"}}`)
				done := make(chan *mcp.CallToolResult, 1)
				go func() {
					res, _ := g.call(ctx, &mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: headers}, Params: &mcp.CallToolParamsRaw{Name: "invoke_tool", Arguments: raw}})
					done <- res
				}()
				select {
				case <-back.initEntered:
				case <-ctx.Done():
					close(back.initRelease)
					t.Fatal("initialize did not block")
				}
				switch change {
				case "acl":
					p.ToolAllowlist = map[string][]string{}
					cfg.Principals["local"] = p
				case "principal":
					delete(cfg.Principals, "local")
					cfg.Principals["other"] = p
				case "switch":
					s := cfg.Servers["demo"]
					s.Enabled = false
					cfg.Servers["demo"] = s
				case "endpoint":
					s := cfg.Servers["demo"]
					s.URL = "http://127.0.0.1:1/mcp"
					cfg.Servers["demo"] = s
				case "secret":
					t.Setenv("ACL_REPLACEMENT_SECRET", "synthetic-replacement-secret")
					s := cfg.Servers["demo"]
					s.TokenEnv = "ACL_REPLACEMENT_SECRET"
					cfg.Servers["demo"] = s
				case "unrelated":
					s := cfg.Servers["demo"]
					s.Description = "Unrelated display edit"
					cfg.Servers["demo"] = s
				}
				write()
				close(back.initRelease)
				select {
				case res := <-done:
					if res.IsError != (change != "unrelated") {
						t.Fatal("unexpected outcome", res)
					}
				case <-ctx.Done():
					t.Fatal("call blocked")
				}
				want := int32(0)
				if change == "unrelated" {
					want = 1
				}
				if back.calls.Load() != want {
					t.Fatal("unexpected dispatch", back.calls.Load(), want)
				}
			})
		}
	}
}

func TestAgentACLMetadataRevokedDuringFetch(t *testing.T) {
	for _, operation := range []string{"discover_tools", "get_tool_schema", "search_tools"} {
		t.Run(operation, func(t *testing.T) {
			back := &controlledBatchBackend{initEntered: make(chan struct{}, 4), initRelease: make(chan struct{}), entered: make(chan string, 4), activeByGroup: map[string]int{}, maxByGroup: map[string]int{}}
			g, headers, path := newControlledBatchGateway(t, back)
			cfg, e := config.Load(path)
			if e != nil {
				t.Fatal(e)
			}
			p := cfg.Principals["local"]
			p.AccessPolicy = config.Restricted
			p.ToolAllowlist = map[string][]string{"demo": {"read"}}
			cfg.Principals["local"] = p
			write := func() {
				b, _ := json.Marshal(cfg)
				if e := os.WriteFile(path+".tmp", b, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Rename(path+".tmp", path); e != nil {
					t.Fatal(e)
				}
			}
			write()
			back.blockInit.Store(true)
			args := map[string]any{"server_id": "demo", "tool_name": "read"}
			if operation == "search_tools" {
				args = map[string]any{"query": "read"}
			}
			raw, _ := json.Marshal(args)
			done := make(chan *mcp.CallToolResult, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			go func() {
				r, _ := g.call(ctx, &mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: headers}, Params: &mcp.CallToolParamsRaw{Name: operation, Arguments: raw}})
				done <- r
			}()
			select {
			case <-back.initEntered:
			case <-ctx.Done():
				close(back.initRelease)
				t.Fatal("no blocked fetch")
			}
			p.ToolAllowlist = map[string][]string{}
			cfg.Principals["local"] = p
			write()
			close(back.initRelease)
			select {
			case res := <-done:
				b, _ := json.Marshal(res.StructuredContent)
				if !res.IsError && (strings.Contains(string(b), `"tool_name":"read"`) || strings.Contains(string(b), `"name":"read"`) || strings.Contains(string(b), `"server_id":"demo"`)) {
					t.Fatal("revoked metadata leaked", string(b))
				}
			case <-ctx.Done():
				t.Fatal("blocked")
			}
			if back.calls.Load() != 0 {
				t.Fatal("metadata invoked a tool")
			}
		})
	}
}

func TestAgentACLAuditRedactionAndSinkLoss(t *testing.T) {
	f := newFixture(t)
	p := f.config.Principals["local"]
	p.AccessPolicy = config.Restricted
	p.ToolAllowlist = map[string][]string{"demo": {"echo"}}
	f.config.Principals["local"] = p
	f.write()
	dir := filepath.Join(t.TempDir(), "audit")
	sink, e := audit.New(dir)
	if e != nil {
		t.Fatal(e)
	}
	g := &Gateway{Path: f.path, Audit: sink, Timeout: time.Second}
	invoke := func(tool string) *mcp.CallToolResult {
		raw, _ := json.Marshal(map[string]any{"server_id": "demo", "tool_name": tool, "arguments": map[string]any{"text": "synthetic-private-payload"}})
		r, _ := g.call(context.Background(), &mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: http.Header{"Authorization": {"Bearer " + clientToken}}}, Params: &mcp.CallToolParamsRaw{Name: "invoke_tool", Arguments: raw}})
		return r
	}
	if invoke("echo").IsError || !invoke("hidden").IsError {
		t.Fatal("decision")
	}
	files, _ := os.ReadDir(dir)
	text := ""
	for _, entry := range files {
		b, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
		text += string(b)
	}
	for _, private := range []string{clientToken, "synthetic-private-payload", f.config.Servers["demo"].URL, "arguments", "ciphertext", "token_hash"} {
		if strings.Contains(text, private) {
			t.Fatal("audit leaked private material")
		}
	}
	if !strings.Contains(text, `"principal":"local"`) || !strings.Contains(text, `"dispatched":true`) || !strings.Contains(text, `"outcome":"denied"`) {
		t.Fatal("missing decision evidence", text)
	}
	os.Rename(dir, dir+"-gone")
	if invoke("echo").IsError || sink.State() != "degraded" {
		t.Fatal("sink failure changed business result")
	}
	h, e := g.Handler()
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/healthz", nil))
	if w.Code != 200 || w.Header().Get("X-Gateway-Audit-Status") != "degraded" {
		t.Fatal("health status")
	}
}
