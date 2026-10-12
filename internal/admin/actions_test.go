package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/config"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestActionJSONAndProbeInputs(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	snap, _ := s.ReadSnapshot(context.Background())
	c := clone(snap.Config)
	c.Servers["one"] = config.Server{URL: "http://127.0.0.1:9999/mcp", Tools: map[string]config.Tool{"read": {Enabled: true, AccessMode: "shared"}}, Enabled: true}
	c.Servers["two"] = config.Server{URL: "http://127.0.0.1:9998/mcp", Tools: map[string]config.Tool{}}
	snap, e := s.CompareAndSwap(context.Background(), snap.Revision, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := connectionKey(snap, "one")
	at := time.Now()
	h.probes["one"] = probe{revision: snap.Revision, key: key, at: at, tools: map[string]*mcp.Tool{"read": {Name: "read", InputSchema: map[string]any{"type": "object"}}}}
	do := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:8081"+path, strings.NewReader(form.Encode()))
		r.AddCookie(cookie)
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if method == "POST" {
			r.Header.Set("Origin", "http://127.0.0.1:8081")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do("POST", "/admin/servers/one/tool-disable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tool": {"read"}})
	if w.Code != 200 || w.Header().Get("Location") != "" || !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		t.Fatal(w.Code, w.Body.String())
	}
	var response struct {
		Revision int64
		Servers  []struct {
			ID    string
			Tools []toolView
		}
	}
	if e := json.Unmarshal(w.Body.Bytes(), &response); e != nil {
		t.Fatal(e)
	}
	if response.Revision != snap.Revision+1 || strings.Contains(w.Body.String(), "csrf") || strings.Contains(w.Body.String(), "TokenEnv") {
		t.Fatal("unsafe response")
	}
	snap, _ = s.ReadSnapshot(context.Background())
	c = clone(snap.Config)
	other := c.Servers["two"]
	other.Description = "unrelated"
	c.Servers["two"] = other
	snap, e = s.CompareAndSwap(context.Background(), snap.Revision, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	p, ok := h.currentProbe("one", snap)
	if !ok || !p.at.Equal(at) {
		t.Fatal("unrelated change invalidated or extended cache")
	}
	w = do("POST", "/admin/servers/one/tool-enable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tool": {"read"}})
	if w.Code != 200 {
		t.Fatal("unrelated revision triggered upstream", w.Code, w.Body.String())
	}
	snap, _ = s.ReadSnapshot(context.Background())
	for _, modify := range []func(*config.Config){func(c *config.Config) {
		x := c.Servers["one"]
		x.URL = "http://127.0.0.1:9997/mcp"
		c.Servers["one"] = x
	}, func(c *config.Config) { c.HTTPSAllowlist = []string{"https://example.com/mcp"} }, func(c *config.Config) { x := c.Servers["one"]; x.AuthHeader = "X-Api-Key"; c.Servers["one"] = x }} {
		original := snap.Config
		snap.Config = clone(original)
		modify(snap.Config)
		if _, ok := h.currentProbe("one", snap); ok {
			t.Fatal("connection change kept cache")
		}
		snap.Config = original
	}
	h.mu.Lock()
	p = h.probes["one"]
	p.at = time.Now().Add(-time.Hour)
	h.probes["one"] = p
	h.mu.Unlock()
	if _, ok := h.currentProbe("one", snap); ok {
		t.Fatal("expired cache accepted")
	}
	w = do("POST", "/admin/servers/one/disable", url.Values{"csrf": {csrf}, "revision": {"1"}})
	if w.Code != 409 {
		t.Fatal("stale CAS", w.Code)
	}
	w = do("POST", "/admin/servers/one/disable", url.Values{"csrf": {"bad"}, "revision": {fmt.Sprint(snap.Revision)}})
	if w.Code != 403 {
		t.Fatal("csrf", w.Code)
	}
	w = do("GET", "/admin/actions.js", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "fetch(") || !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatal("asset/CSP")
	}
}

func TestConnectionKeyCredentialRotation(t *testing.T) {
	h, s := adminFixture(t)
	ctx := context.Background()
	snap, _ := s.ReadSnapshot(ctx)
	c := clone(snap.Config)
	c.Servers["key"] = config.Server{URL: "http://127.0.0.1:9999/mcp", AuthHeader: "X-Api-Key", TokenRef: "key", Tools: map[string]config.Tool{}}
	secret := "synthetic-secret-one"
	snap, e := s.CompareAndSwap(ctx, snap.Revision, c, map[string]*string{"key": &secret})
	if e != nil {
		t.Fatal(e)
	}
	key, _ := connectionKey(snap, "key")
	h.probes["key"] = probe{key: key, at: time.Now()}
	if _, ok := h.currentProbe("key", snap); !ok {
		t.Fatal("fresh key")
	}
	secret = "synthetic-secret-two"
	snap, e = s.CompareAndSwap(ctx, snap.Revision, c, map[string]*string{"key": &secret})
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := h.currentProbe("key", snap); ok {
		t.Fatal("encrypted rotation kept probe")
	}
	c = clone(snap.Config)
	v := c.Servers["key"]
	v.TokenRef = ""
	v.TokenEnv = "QA_PROBE_KEY"
	c.Servers["key"] = v
	t.Setenv("QA_PROBE_KEY", "synthetic-env-secret-one")
	snap, e = s.CompareAndSwap(ctx, snap.Revision, c, map[string]*string{"key": nil})
	if e != nil {
		t.Fatal(e)
	}
	key, _ = connectionKey(snap, "key")
	h.probes["key"] = probe{key: key, at: time.Now()}
	t.Setenv("QA_PROBE_KEY", "synthetic-env-secret-two")
	if _, ok := h.currentProbe("key", snap); ok {
		t.Fatal("env rotation kept probe")
	}
}

func TestJSONFailureAndLoginFallback(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	snap, _ := s.ReadSnapshot(context.Background())
	c := clone(snap.Config)
	c.Servers["offline"] = config.Server{URL: "http://127.0.0.1:1/mcp", Tools: map[string]config.Tool{}}
	snap, e := s.CompareAndSwap(context.Background(), snap.Revision, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8081/admin/servers/offline/enable", strings.NewReader(url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}}.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "http://127.0.0.1:8081")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 502 || strings.Contains(w.Body.String(), "<html") {
		t.Fatal("JSON failure", w.Code)
	}
	after, _ := s.ReadSnapshot(context.Background())
	if after.Revision != snap.Revision || after.Config.Servers["offline"].Enabled {
		t.Fatal("failed action persisted")
	}
	w = request(h, "GET", "/admin/login", nil)
	if strings.Contains(w.Body.String(), "actions.js") {
		t.Fatal("login must not request authenticated asset")
	}
	w = request(h, "POST", "/admin/servers/offline/disable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}}, cookie)
	if w.Code != 303 {
		t.Fatal("no-JS fallback")
	}
}
