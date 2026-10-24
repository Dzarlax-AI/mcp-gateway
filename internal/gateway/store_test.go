package gateway

import (
	"bytes"
	"context"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDatabaseRegistryRuntime(t *testing.T) {
	for _, header := range []string{"", "x-api-key", "X-Access-Key"} {
		for _, clientHeader := range []string{"Authorization", "X-API-Key"} {
			for _, recoverable := range []bool{false, true} {
				t.Run(fmt.Sprintf("upstream=%s/client=%s/recoverable=%t", header, clientHeader, recoverable), func(t *testing.T) { testDatabaseRegistryRuntime(t, header, clientHeader, recoverable) })
			}
		}
	}
}
func testDatabaseRegistryRuntime(t *testing.T, header, clientHeader string, recoverable bool) {
	f := newFixtureAuth(t, "", header)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "gateway.db")
	if e := store.Migrate(ctx, "sqlite", path); e != nil {
		t.Fatal(e)
	}
	db, e := store.Open("sqlite", path, bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	c, e := config.Clone(&f.config)
	if e != nil {
		t.Fatal(e)
	}
	server := c.Servers["demo"]
	server.TokenEnv = ""
	server.TokenRef = "demo"
	c.Servers["demo"] = server
	token := backendToken
	snap, e := db.CompareAndSwap(ctx, 0, c, map[string]*string{"demo": &token})
	if e != nil {
		t.Fatal(e)
	}
	h, e := (&Gateway{Store: db, Timeout: time.Second}).Handler()
	if e != nil {
		t.Fatal(e)
	}
	web := httptest.NewServer(h)
	defer web.Close()
	client := clientHeaderHTTPClient(clientToken, clientHeader)
	defer client.CloseIdleConnections()
	session, e := mcp.NewClient(&mcp.Implementation{Name: "db-check", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: web.URL + "/mcp", HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	for _, name := range []string{"discover_server", "discover_tools", "get_tool_schema", "invoke_tool"} {
		args := any(map[string]any{"query": "echo"})
		if name != "discover_server" {
			args = invocation("snapshot")
		}
		if name == "discover_tools" {
			args = map[string]any{"server_id": "demo"}
		}
		if name == "get_tool_schema" {
			args = map[string]any{"server_id": "demo", "tool_name": "echo"}
		}
		result, e := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if e != nil || result.IsError {
			t.Fatalf("%s %v %+v", name, e, result)
		}
	}
	// A separately issued hash-backed key completes the same real protocol path.
	managedToken := "mgw_" + strings.Repeat("m", 43)
	c.Principals["key_new"] = config.Principal{ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
		TokenHash: config.TokenDigest(managedToken), Key: &config.ClientKey{Name: "Laptop", Prefix: managedToken[:12], CreatedAt: "2026-10-12T12:00:00Z", Recoverable: recoverable}}
	tool := server.Tools["echo"]
	tool.AccessMode = "shared"
	server.Tools["echo"] = tool
	c.Servers["demo"] = server
	changes := map[string]*string{}
	if recoverable {
		changes["key_new"] = &managedToken
	}
	snap, e = db.CompareAndSwapClientKeys(ctx, snap.Revision, c, changes)
	if e != nil {
		t.Fatal(e)
	}
	managedClient := clientHeaderHTTPClient(managedToken, clientHeader)
	defer managedClient.CloseIdleConnections()
	managedSession, e := mcp.NewClient(&mcp.Implementation{Name: "managed-check", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: web.URL + "/mcp", HTTPClient: managedClient, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer managedSession.Close()
	for _, entry := range []struct {
		name string
		args map[string]any
	}{
		{"discover_server", map[string]any{"query": "echo"}},
		{"discover_tools", map[string]any{"server_id": "demo"}},
		{"get_tool_schema", map[string]any{"server_id": "demo", "tool_name": "echo"}},
		{"invoke_tool", invocation("managed read")},
	} {
		result, e := managedSession.CallTool(ctx, &mcp.CallToolParams{Name: entry.name, Arguments: entry.args})
		if e != nil || result.IsError {
			t.Fatal("managed scenario", entry.name, e)
		}
	}
	beforeRevoke := f.requests.Load()
	delete(c.Principals, "key_new")
	snap, e = db.CompareAndSwap(ctx, snap.Revision, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	if result, e := managedSession.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_tool", Arguments: invocation("revoked")}); e == nil && !result.IsError {
		t.Fatal("existing managed session not revoked")
	}
	response, e := managedClient.Get(web.URL + "/mcp")
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("new request not revoked", response.StatusCode)
	}
	if f.requests.Load() != beforeRevoke {
		t.Fatal("revoked client contacted upstream")
	}
	if result, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_tool", Arguments: invocation("legacy retained")}); e != nil || result.IsError {
		t.Fatal("legacy session lost", e)
	}
	before := f.calls.Load()
	server.Enabled = false
	c.Servers["demo"] = server
	if _, e = db.CompareAndSwap(ctx, snap.Revision, c, nil); e != nil {
		t.Fatal(e)
	}
	result, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_tool", Arguments: invocation("revoked")})
	if e != nil || !result.IsError || f.calls.Load() != before {
		t.Fatal("revoked DB policy was not observed")
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	response, e = client.Get(web.URL + "/healthz")
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatal("closed DB fell back")
	}
}
func TestFileRegistryRejectsSecretRefs(t *testing.T) {
	f := newFixture(t)
	s := f.config.Servers["demo"]
	s.TokenEnv = ""
	s.TokenRef = "demo"
	f.config.Servers["demo"] = s
	f.write()
	if _, e := config.Load(f.path); e == nil {
		t.Fatal("file mode accepted unresolved secret")
	}
	if !strings.Contains(config.ErrConfig.Error(), "configuration") {
		t.Fatal("unexpected error")
	}
}

// This client changes only the credential sent to the gateway, never the upstream.
type clientCredentialTransport struct {
	token, header string
	base          http.RoundTripper
}

func (tr clientCredentialTransport) CloseIdleConnections() {
	if closer, ok := tr.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
func (tr clientCredentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	value := tr.token
	if tr.header == "Authorization" {
		value = "Bearer " + value
	}
	r.Header.Set(tr.header, value)
	return tr.base.RoundTrip(r)
}
func clientHeaderHTTPClient(token, header string) *http.Client {
	return &http.Client{Transport: clientCredentialTransport{token, header, http.DefaultTransport.(*http.Transport).Clone()}, Timeout: time.Second}
}
