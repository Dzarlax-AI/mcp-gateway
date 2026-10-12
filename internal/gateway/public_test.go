package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPublicOriginValidation(t *testing.T) {
	for _, v := range []string{"", "https://mcp.example.com", "https://localhost:8443", "https://[::1]:8443"} {
		if e := ValidatePublicOrigin(v); e != nil {
			t.Errorf("%q: %v", v, e)
		}
	}
	for _, v := range []string{"http://mcp.example.com", "https://mcp.example.com/", "https://user@mcp.example.com", "https://mcp.example.com?", "https://mcp.example.com#", "https://*.example.com", "https://MCP.example.com", "https://mcp.example.com:", "https://mcp.example.com:0", "https://mcp.example.com:65536", "https://mcp.example.com:0443", "https://-bad.test", "https://bad..test"} {
		if ValidatePublicOrigin(v) == nil {
			t.Errorf("accepted %q", v)
		}
	}
}

func TestPublicHTTPGuards(t *testing.T) {
	f := newFixture(t)
	g := &Gateway{Path: f.path, PublicOrigin: "https://mcp.example.com"}
	h, e := g.Handler()
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, host, token, body string
		origins                 []string
		want                    int
	}{
		{"no origin", "mcp.example.com", clientToken, "", nil, 200},
		{"https origin", "mcp.example.com", clientToken, "", []string{g.PublicOrigin}, 200},
		{"missing token", "mcp.example.com", "", "", nil, 401},
		{"wrong token", "mcp.example.com", "wrong", "", nil, 401},
		{"http origin", "mcp.example.com", clientToken, "", []string{"http://mcp.example.com"}, 403},
		{"foreign origin", "mcp.example.com", clientToken, "", []string{"https://evil.test"}, 403},
		{"null origin", "mcp.example.com", clientToken, "", []string{"null"}, 403},
		{"empty origin", "mcp.example.com", clientToken, "", []string{""}, 403},
		{"duplicate origin", "mcp.example.com", clientToken, "", []string{g.PublicOrigin, g.PublicOrigin}, 403},
		{"wrong host", "evil.test", clientToken, "", []string{g.PublicOrigin}, 403},
		{"wrong host no origin", "evil.test", clientToken, "", nil, 403},
		{"body limit", "mcp.example.com", clientToken, strings.Repeat("x", MaxBody+1), nil, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if body == "" {
				body = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
			}
			r := httptest.NewRequest("POST", "http://127.0.0.1/mcp", strings.NewReader(body))
			r.Host = tc.host
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			r.Header.Set("MCP-Protocol-Version", "2025-11-25")
			r.Header.Set("X-Forwarded-Host", "mcp.example.com")
			r.Header.Set("X-Forwarded-Proto", "https")
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.origins != nil {
				r.Header["Origin"] = tc.origins
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
	if f.requests.Load() != 0 {
		t.Fatal("HTTP guards or tools/list contacted upstream")
	}
	if e := os.WriteFile(f.path, []byte(`{"invalid":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "http://mcp.example.com/mcp", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer "+clientToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}

type publicTransport struct{ base http.RoundTripper }

func (p publicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	c.Host = "mcp.example.com"
	c.Header.Set("Origin", "https://mcp.example.com")
	c.Header.Set("Authorization", "Bearer "+clientToken)
	return p.base.RoundTrip(c)
}

func TestPublicSessionPolicyAndReload(t *testing.T) {
	f := newFixture(t)
	h, e := (&Gateway{Path: f.path, PublicOrigin: "https://mcp.example.com"}).Handler()
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewServer(h)
	defer s.Close()
	client := &http.Client{Transport: publicTransport{http.DefaultTransport}, Timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, e := mcp.NewClient(&mcp.Implementation{Name: "public-test", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: s.URL + "/mcp", HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"discover_server", map[string]any{}},
		{"discover_tools", map[string]any{"server_id": "demo"}},
		{"get_tool_schema", map[string]any{"server_id": "demo", "tool_name": "echo"}},
		{"invoke_tool", invocation("public-path")},
	} {
		r, e := session.CallTool(ctx, &mcp.CallToolParams{Name: tc.name, Arguments: tc.args})
		if e != nil || r.IsError {
			t.Fatalf("%s: %v %v", tc.name, r, e)
		}
	}
	before := f.requests.Load()
	for _, args := range []map[string]any{
		{"server_id": "demo", "tool_name": "hidden", "arguments": map[string]any{"text": "x"}},
		{"server_id": "demo", "tool_name": "echo", "arguments": map[string]any{"text": "x", "extra": true}},
	} {
		r, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_tool", Arguments: args})
		if e != nil || !r.IsError {
			t.Fatalf("denial: %v %v", r, e)
		}
	}
	if before != f.requests.Load() {
		t.Fatal("denial contacted upstream")
	}
	server := f.config.Servers["demo"]
	server.Enabled = false
	f.config.Servers["demo"] = server
	f.write()
	r, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_tool", Arguments: invocation("revoked")})
	if e != nil || !r.IsError || f.requests.Load() != before {
		t.Fatalf("reload: %v %v", r, e)
	}
}
