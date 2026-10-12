package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCustomHeaderWorkflow(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	ctx := context.Background()
	key := "key with spaces"
	server := mcp.NewServer(&mcp.Implementation{Name: "key-test", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "echo", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Error("probe invoked a tool")
		return nil, nil
	})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != key || r.Header.Get("Authorization") != "" {
			http.Error(w, "wrong credential", 401)
			return
		}
		mcpHandler.ServeHTTP(w, r)
	}))
	defer upstream.Close()
	post := func(path string, form url.Values, want int) {
		t.Helper()
		snap, e := s.ReadSnapshot(ctx)
		if e != nil {
			t.Fatal(e)
		}
		form.Set("csrf", csrf)
		form.Set("revision", fmt.Sprint(snap.Revision))
		w := request(h, "POST", path, form, cookie)
		if w.Code != want {
			t.Fatalf("%s status=%d want=%d", path, w.Code, want)
		}
	}
	endpoint := upstream.URL + "/mcp"
	post("/admin/servers/create", url.Values{"id": {"key"}, "url": {endpoint}, "auth_mode": {"header"}, "auth_header": {"x-api-key"}, "secret": {key}}, 303)
	post("/admin/servers/key/check", url.Values{}, 303)
	snap, _ := s.ReadSnapshot(ctx)
	if _, ok := h.probe("key", snap.Revision); !ok {
		t.Fatal("custom probe failed")
	}
	body := request(h, "GET", "/admin/servers", nil, cookie).Body.String()
	if strings.Contains(body, key) || !strings.Contains(body, "custom header X-Api-Key") || !strings.Contains(body, `name="auth_header"`) {
		t.Fatal("header UI or redaction")
	}
	post("/admin/servers/key/tool-enable", url.Values{"tool": {"echo"}, "principal": {"codex"}, "enabled": {"yes"}, "grant": {"yes"}}, 303)
	post("/admin/servers/key/enable", url.Values{}, 303)
	// Case-only normalization preserves a valid check and the saved value.
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"header"}, "auth_header": {"X-API-KEY"}}, 303)
	snap, _ = s.ReadSnapshot(ctx)
	if !snap.Config.Servers["key"].Enabled {
		t.Fatal("case-only header change disabled server")
	}
	for _, bad := range []string{"Host", "Authorization", "MCP-Session-Id", "X-authentik-username", "Bad Header"} {
		post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"header"}, "auth_header": {bad}}, 400)
	}
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"header"}, "auth_header": {"x-api-key"}, "secret": {"key\r\nHost: evil"}}, 400)
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"bearer"}}, 400)
	// Changing only the header keeps the encrypted value but disables access.
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"header"}, "auth_header": {"X-Access-Key"}}, 303)
	snap, _ = s.ReadSnapshot(ctx)
	if snap.Config.Servers["key"].Enabled {
		t.Fatal("header change left server enabled")
	}
	if _, ok := h.probe("key", snap.Revision); ok {
		t.Fatal("header change retained probe")
	}
	post("/admin/servers/key/enable", url.Values{}, 502)
	post("/admin/servers/key/check", url.Values{}, 502)
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"header"}, "auth_header": {"x-api-key"}, "secret": {"replacement key"}}, 303)
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"bearer"}, "secret": {"synthetic-bearer-token-long-enough"}}, 303)
	snap, _ = s.ReadSnapshot(ctx)
	if snap.Config.Servers["key"].AuthHeader != "" || snap.Config.Servers["key"].Enabled {
		t.Fatal("Bearer mode change failed")
	}
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"none"}, "secret": {"unexpected"}}, 400)
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"none"}}, 303)
	snap, _ = s.ReadSnapshot(ctx)
	v := snap.Config.Servers["key"]
	if v.TokenRef != "" || v.AuthHeader != "" || v.Enabled {
		t.Fatal("authentication removal failed")
	}
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"header"}, "auth_header": {"x-api-key"}}, 400)
	// Editing a server already using None must preserve its valid check/access.
	noAuth := httptest.NewServer(mcpHandler)
	defer noAuth.Close()
	endpoint = noAuth.URL + "/mcp"
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"none"}}, 303)
	post("/admin/servers/key/check", url.Values{}, 303)
	post("/admin/servers/key/tool-enable", url.Values{"tool": {"echo"}, "principal": {"codex"}, "enabled": {"yes"}, "grant": {"yes"}}, 303)
	post("/admin/servers/key/enable", url.Values{}, 303)
	post("/admin/servers/key/update", url.Values{"url": {endpoint}, "auth_mode": {"none"}, "description": {"updated"}}, 303)
	snap, _ = s.ReadSnapshot(ctx)
	if !snap.Config.Servers["key"].Enabled {
		t.Fatal("None metadata edit disabled server")
	}
	if _, ok := h.probe("key", snap.Revision); !ok {
		t.Fatal("None metadata edit lost probe")
	}
}
