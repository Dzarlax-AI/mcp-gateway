package admin

import (
	"context"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSimpleTogglesRefreshRestartAndErrors(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	var invokes, requests atomic.Int32
	up := mcp.NewServer(&mcp.Implementation{Name: "simple", Version: "1"}, nil)
	up.AddTool(&mcp.Tool{Name: "read", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		invokes.Add(1)
		return &mcp.CallToolResult{}, nil
	})
	mh := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return up }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); mh.ServeHTTP(w, r) }))
	defer srv.Close()
	post := func(path string, f url.Values, want int) {
		t.Helper()
		snap, err := s.ReadSnapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		f.Set("csrf", csrf)
		f.Set("revision", fmt.Sprint(snap.Revision))
		w := request(h, "POST", path, f, cookie)
		if w.Code != want {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	post("/admin/servers/create", url.Values{"id": {"simple"}, "url": {srv.URL + "/mcp"}, "auth_mode": {"none"}}, 303)
	post("/admin/servers/simple/enable", url.Values{}, 303)
	snap, _ := s.ReadSnapshot(context.Background())
	if !snap.Config.Servers["simple"].Enabled || snap.Config.Servers["simple"].Tools["read"].Enabled {
		t.Fatal("server enable changed tool switches")
	}
	post("/admin/servers/simple/tool-enable", url.Values{"tool": {"read"}}, 303)
	before := requests.Load()
	h.mu.Lock()
	p := h.probes["simple"]
	p.at = time.Now().Add(-time.Hour)
	h.probes["simple"] = p
	h.mu.Unlock()
	body := request(h, "GET", "/admin/servers", nil, cookie).Body.String()
	if !strings.Contains(body, `aria-checked="true" aria-label="Enable tool read on server simple"`) || strings.Contains(body, "Allowed argument names") || strings.Contains(body, "Grant this tool") {
		t.Fatal("simple UI or expired catalog")
	}
	post("/admin/servers/simple/tool-disable", url.Values{"tool": {"read"}}, 303)
	if requests.Load() != before {
		t.Fatal("disable contacted upstream")
	}
	post("/admin/servers/simple/tool-enable", url.Values{"tool": {"read"}}, 303)
	if requests.Load() == before {
		t.Fatal("enable did not refresh expired probe")
	}
	post("/admin/servers/simple/disable", url.Values{}, 303)
	snap, _ = s.ReadSnapshot(context.Background())
	if snap.Config.Servers["simple"].Enabled || !snap.Config.Servers["simple"].Tools["read"].Enabled {
		t.Fatal("server disable lost tools")
	}
	raw, err := New(s, Options{Token: adminToken, Origin: "http://127.0.0.1:8081"})
	if err != nil {
		t.Fatal(err)
	}
	restarted := raw.(*handler)
	c, _ := login(t, restarted)
	if !strings.Contains(request(restarted, "GET", "/admin/servers", nil, c).Body.String(), `aria-checked="true" aria-label="Enable tool read on server simple"`) {
		t.Fatal("restart hid tools")
	}
	// New upstream tools remain disabled; disappeared tools cannot stay enabled.
	up.RemoveTools("read")
	up.AddTool(&mcp.Tool{Name: "new", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("refresh invoked tool")
		return nil, nil
	})
	post("/admin/servers/simple/check", url.Values{}, 303)
	snap, _ = s.ReadSnapshot(context.Background())
	if snap.Config.Servers["simple"].Tools["read"].Enabled || snap.Config.Servers["simple"].Tools["new"].Enabled || invokes.Load() != 0 {
		t.Fatal("unsafe catalog refresh")
	}
	post("/admin/servers/simple/tool-enable", url.Values{"tool": {"read"}}, 400)
	// A failed create keeps nonsecret data while the secret is never redisplayed.
	snap, _ = s.ReadSnapshot(context.Background())
	w := request(h, "POST", "/admin/servers/create", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "id": {"retry"}, "url": {"https://example.com/mcp"}, "auth_mode": {"header"}, "auth_header": {"x-api-key"}, "secret": {"synthetic-secret-do-not-display"}}, cookie)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `value="retry"`) || strings.Contains(w.Body.String(), "synthetic-secret-do-not-display") {
		t.Fatal("unsafe create error")
	}
	srv.Close()
	post("/admin/servers/simple/check", url.Values{}, 502)
	snap, _ = s.ReadSnapshot(context.Background())
	if snap.Config.Servers["simple"].Enabled {
		t.Fatal("failed check enabled server")
	}
	post("/admin/servers/simple/disable", url.Values{}, 303)
}
