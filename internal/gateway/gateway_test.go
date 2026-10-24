package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcp-gateway/internal/config"
	"mcp-gateway/internal/upstream"
)

const clientToken = "synthetic-client-token-123456"
const backendToken = "synthetic-backend-token-123456"

type fixture struct {
	t               *testing.T
	path            string
	config          config.Config
	server          *httptest.Server
	session         *mcp.ClientSession
	calls, requests atomic.Int32
}

func newFixture(t *testing.T) *fixture                        { return newFixtureVersion(t, "") }
func newFixtureVersion(t *testing.T, version string) *fixture { return newFixtureAuth(t, version, "") }
func newFixtureAuth(t *testing.T, version, authHeader string) *fixture {
	t.Helper()
	t.Setenv("TEST_CLIENT_TOKEN", clientToken)
	t.Setenv("TEST_BACKEND_TOKEN", backendToken)
	f := &fixture{t: t, path: filepath.Join(t.TempDir(), "config.json")}
	s := mcp.NewServer(&mcp.Implementation{Name: "synthetic", Version: "0.1.0"}, nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}, "required": []string{"text"}, "additionalProperties": false}
	for _, name := range []string{"echo", "error", "hidden"} {
		s.AddTool(&mcp.Tool{Name: name, Description: name, InputSchema: schema, OutputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.calls.Add(1)
			var a map[string]any
			json.Unmarshal(r.Params.Arguments, &a)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: a["text"].(string)}, &mcp.ImageContent{MIMEType: "image/png", Data: []byte{1, 2, 3}}}, StructuredContent: a, IsError: r.Params.Name == "error"}, nil
		})
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		valid := r.Header.Get("Authorization") == "Bearer "+backendToken
		if authHeader != "" {
			valid = r.Header.Get(authHeader) == backendToken && r.Header.Get("Authorization") == ""
		}
		if authHeader != "x-api-key" && r.Header.Get("X-API-Key") != "" {
			t.Error("upstream received client API key")
		}
		if !valid {
			t.Error("upstream received wrong credential")
			http.Error(w, "unauthorized", 401)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(back.Close)
	grant := config.Grant{AllowedArguments: []string{"text"}, RequiredArguments: []string{"text"}}
	f.config = config.Config{RegistryVersion: 2,
		Servers: map[string]config.Server{"demo": {Enabled: true, Description: "Synthetic echo", Keywords: []string{"test"}, URL: back.URL + "/mcp", TokenEnv: "TEST_BACKEND_TOKEN", AuthHeader: authHeader, Tools: map[string]config.Tool{"echo": {Enabled: true}, "error": {Enabled: true}, "hidden": {Enabled: true}}}}, Principals: map[string]config.Principal{"local": {ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
			TokenEnv: "TEST_CLIENT_TOKEN", Grants: map[string]map[string]config.Grant{"demo": {"echo": grant, "error": grant}}}}}
	f.write()
	handler, e := (&Gateway{Path: f.path, Timeout: 300 * time.Millisecond}).Handler()
	if e != nil {
		t.Fatal(e)
	}
	f.server = httptest.NewServer(handler)
	t.Cleanup(f.server.Close)
	httpClient := upstream.HTTPClient(clientToken, time.Second)
	t.Cleanup(httpClient.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.session, e = mcp.NewClient(&mcp.Implementation{Name: "integration", Version: "0.1.0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: f.server.URL + "/mcp", HTTPClient: httpClient, MaxRetries: -1, DisableStandaloneSSE: true}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.session.Close() })
	return f
}
func (f *fixture) write() {
	f.t.Helper()
	b, e := json.Marshal(f.config)
	if e != nil {
		f.t.Fatal(e)
	}
	if e = os.WriteFile(f.path+".tmp", b, 0600); e != nil {
		f.t.Fatal(e)
	}
	if e = os.Rename(f.path+".tmp", f.path); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fixture) call(name string, args any, wantError bool) *mcp.CallToolResult {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r, e := f.session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if e != nil {
		f.t.Fatal(e)
	}
	if r.IsError != wantError {
		b, _ := json.Marshal(r)
		f.t.Fatalf("%s: %s", name, b)
	}
	return r
}
func invocation(text any) map[string]any {
	return map[string]any{"server_id": "demo", "tool_name": "echo", "arguments": map[string]any{"text": text}}
}
func TestEndToEndAndReload(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tools, e := f.session.ListTools(ctx, nil)
	if e != nil || len(tools.Tools) != 4 {
		t.Fatalf("tools: %v %v", tools, e)
	}
	r := f.call("discover_server", map[string]any{"query": "echo"}, false)
	b, _ := json.Marshal(r.StructuredContent)
	if !strings.Contains(string(b), "demo") || strings.Contains(string(b), "token") || strings.Contains(string(b), "http") {
		t.Fatal(string(b))
	}
	r = f.call("discover_tools", map[string]any{"server_id": "demo"}, false)
	b, _ = json.Marshal(r.StructuredContent)
	if strings.Contains(string(b), "hidden") {
		t.Fatal(string(b))
	}
	r = f.call("get_tool_schema", map[string]any{"server_id": "demo", "tool_name": "echo"}, false)
	b, _ = json.Marshal(r.StructuredContent)
	if !strings.Contains(string(b), "outputSchema") || !strings.Contains(string(b), "annotations") {
		t.Fatal(string(b))
	}
	r = f.call("invoke_tool", invocation("hello"), false)
	if len(r.Content) != 2 {
		t.Fatal(r)
	}
	if _, ok := r.Content[1].(*mcp.ImageContent); !ok {
		t.Fatal("image type lost")
	}
	if r.StructuredContent.(map[string]any)["text"] != "hello" {
		t.Fatal(r)
	}
	a := invocation("failure")
	a["tool_name"] = "error"
	f.call("invoke_tool", a, true)
	if f.calls.Load() != 2 {
		t.Fatal("unexpected invoke count")
	}
	before := f.requests.Load()
	f.call("invoke_tool", invocation(42), true)
	f.call("invoke_tool", map[string]any{"server_id": "demo", "tool_name": "hidden", "arguments": map[string]any{"text": "x"}}, true)
	bad := invocation("x")
	bad["arguments"].(map[string]any)["extra"] = "x"
	f.call("invoke_tool", bad, true)
	f.call("invoke_tool", map[string]any{"server_id": "demo", "tool_name": "echo", "arguments": map[string]any{}}, true)
	if f.calls.Load() != 2 {
		t.Fatal("denied call executed")
	}
	if f.requests.Load() <= before {
		t.Fatal("schema check did not fetch upstream")
	}
	before = f.requests.Load()
	s := f.config.Servers["demo"]
	s.Tools["echo"] = config.Tool{}
	f.config.Servers["demo"] = s
	f.write()
	f.call("invoke_tool", invocation("x"), true)
	if f.requests.Load() != before {
		t.Fatal("disabled tool reached upstream")
	}
	s.Enabled = false
	f.config.Servers["demo"] = s
	f.write()
	r = f.call("discover_server", map[string]any{}, false)
	b, _ = json.Marshal(r.StructuredContent)
	if strings.Contains(string(b), "demo") {
		t.Fatal(string(b))
	}
	f.call("get_tool_schema", map[string]any{"server_id": "demo", "tool_name": "echo"}, true)
	s.Enabled = true
	s.Tools["echo"] = config.Tool{Enabled: true}
	f.config.Servers["demo"] = s
	f.write()
	f.call("invoke_tool", invocation("again"), false)
	p := f.config.Principals["local"]
	delete(p.Grants["demo"], "echo")
	f.config.Principals["local"] = p
	f.write()
	before = f.requests.Load()
	f.call("invoke_tool", invocation("revoked"), true)
	if f.requests.Load() != before {
		t.Fatal("revocation reached upstream")
	}
	f.config.Servers["new"] = s
	p.Grants["new"] = map[string]config.Grant{"echo": {AllowedArguments: []string{"text"}}}
	f.config.Principals["local"] = p
	f.write()
	r = f.call("discover_server", map[string]any{"query": "new", "limit": 1}, false)
	b, _ = json.Marshal(r.StructuredContent)
	if !strings.Contains(string(b), "new") {
		t.Fatal(string(b))
	}
	r = f.call("discover_server", map[string]any{"query": "no-match"}, false)
	b, _ = json.Marshal(r.StructuredContent)
	if string(b) != "{\"servers\":[]}" {
		t.Fatal(string(b))
	}
}
func TestFailClosedAndHTTPGuards(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		body, token, origin string
		status              int
	}{{"{}", "", "", 401}, {"{}", "wrong", "", 401}, {"{}", clientToken, "https://evil.test", 403}, {strings.Repeat("x", MaxBody+1), clientToken, "", 413}} {
		r, _ := http.NewRequest("POST", f.server.URL+"/mcp", strings.NewReader(tc.body))
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		res, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("status=%d want=%d", res.StatusCode, tc.status)
		}
	}
	if e := os.WriteFile(f.path, []byte(`{"bad":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	r, _ := http.NewRequest("POST", f.server.URL+"/mcp", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer "+clientToken)
	res, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 503 {
		t.Fatal(res.Status)
	}
	res, e = http.Get(f.server.URL + "/healthz")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 503 {
		t.Fatal(res.Status)
	}
	f.write()
	f.call("discover_server", map[string]any{}, false)
}
func TestEqualsAndDeniedDoNotContactUpstream(t *testing.T) {
	f := newFixture(t)
	p := f.config.Principals["local"]
	g := p.Grants["demo"]["echo"]
	g.ArgumentEquals = map[string]any{"text": "allowed"}
	p.Grants["demo"]["echo"] = g
	f.config.Principals["local"] = p
	f.write()
	before := f.requests.Load()
	f.call("invoke_tool", invocation("wrong"), true)
	f.call("discover_tools", map[string]any{"server_id": "unknown"}, true)
	f.call("discover_server", map[string]any{"limit": 0}, true)
	f.call("invoke_tool", map[string]any{"server_id": "demo", "tool_name": "echo", "arguments": nil}, true)
	if before != f.requests.Load() {
		t.Fatal("denial made an upstream request")
	}
	f.call("invoke_tool", invocation("allowed"), false)
}
func TestUpstreamTimeoutAndUnavailable(t *testing.T) {
	f := newFixture(t)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer slow.Close()
	s := f.config.Servers["demo"]
	s.URL = slow.URL + "/mcp"
	f.config.Servers["demo"] = s
	f.write()
	start := time.Now()
	f.call("discover_tools", map[string]any{"server_id": "demo"}, true)
	if time.Since(start) > 800*time.Millisecond {
		t.Fatal("timeout not bounded")
	}
	slow.Close()
	f.call("discover_tools", map[string]any{"server_id": "demo"}, true)
}
func TestLegacySessionReload(t *testing.T) {
	f := newFixtureVersion(t, "2025-11-25")
	f.call("invoke_tool", invocation("legacy"), false)
	s := f.config.Servers["demo"]
	s.Enabled = false
	f.config.Servers["demo"] = s
	f.write()
	before := f.requests.Load()
	f.call("invoke_tool", invocation("revoked"), true)
	if f.requests.Load() != before {
		t.Fatal("legacy session retained revoked access")
	}
}
func TestServerIsolation(t *testing.T) {
	f := newFixture(t)
	f.config.Servers["private"] = f.config.Servers["demo"]
	f.write()
	r := f.call("discover_server", map[string]any{}, false)
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "private") {
		t.Fatal("private server disclosed")
	}
	a := invocation("private")
	a["server_id"] = "private"
	before := f.requests.Load()
	f.call("invoke_tool", a, true)
	if f.requests.Load() != before {
		t.Fatal("private server contacted")
	}
}
