package admin

import (
	"bytes"
	"context"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const adminToken = "synthetic-admin-token-123456"

func adminFixture(t *testing.T) (*handler, store.Store) {
	t.Helper()
	t.Setenv("ADMIN_TEST_CLIENT", "synthetic-client-token-123456")
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "admin.db")
	if e := store.Migrate(ctx, "sqlite", path); e != nil {
		t.Fatal(e)
	}
	s, e := store.Open("sqlite", path, bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	c := &config.Config{RegistryVersion: 2,
		Servers: map[string]config.Server{}, Principals: map[string]config.Principal{"codex": {ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
			TokenEnv: "ADMIN_TEST_CLIENT", Grants: map[string]map[string]config.Grant{}}}}
	if _, e = s.CompareAndSwap(ctx, 0, c, nil); e != nil {
		t.Fatal(e)
	}
	h, e := New(s, Options{Token: adminToken, Origin: "http://127.0.0.1:8081"})
	if e != nil {
		t.Fatal(e)
	}
	return h.(*handler), s
}
func request(h http.Handler, method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8081"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if method == "POST" {
		r.Header.Set("Origin", "http://127.0.0.1:8081")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func login(t *testing.T, h *handler) (*http.Cookie, string) {
	t.Helper()
	w := request(h, "GET", "/admin/login", nil)
	var nonce *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "gateway_login_csrf" {
			nonce = c
		}
	}
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("HTML POST Origin requires same-origin referrer policy")
	}
	if nonce == nil {
		t.Fatal("missing login csrf")
	}
	w = request(h, "POST", "/admin/login", url.Values{"csrf": {nonce.Value}, "token": {adminToken}}, nonce)
	if w.Code != 303 {
		t.Fatal("login", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "gateway_admin" {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure {
				t.Fatal("cookie flags")
			}
			return c, h.a.sessions[c.Value].csrf
		}
	}
	t.Fatal("missing session")
	return nil, ""
}
func TestAuthBoundaries(t *testing.T) {
	h, _ := adminFixture(t)
	cookie, csrf := login(t, h)
	for _, tc := range []struct {
		name  string
		alter func(*http.Request)
		want  int
	}{{"missing csrf", func(r *http.Request) {}, 403}, {"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403}, {"duplicate origin", func(r *http.Request) { r.Header.Add("Origin", "http://127.0.0.1:8081") }, 403}, {"wrong host", func(r *http.Request) { r.Host = "evil.example" }, 403}, {"principal token cannot sign in", func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic-client-token-123456") }, 403}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://127.0.0.1:8081/admin/servers/create", strings.NewReader("revision=1"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "http://127.0.0.1:8081")
			r.AddCookie(cookie)
			tc.alter(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatal(w.Code)
			}
		})
	}
	w := request(h, "POST", "/admin/logout", url.Values{"csrf": {csrf}}, cookie)
	if w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w = request(h, "POST", "/admin/servers/create", url.Values{"csrf": {csrf}}, cookie); w.Code != 401 {
		t.Fatal("revoked session", w.Code)
	}
	h.a.sessions["expired"] = session{csrf: csrf, expires: time.Now().Add(-time.Second)}
	if w = request(h, "GET", "/admin/servers", nil, &http.Cookie{Name: "gateway_admin", Value: "expired"}); w.Code != 303 {
		t.Fatal("expired session", w.Code)
	}
}
func TestRegistryWorkflowAndRedaction(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	var calls atomic.Int32
	up := mcp.NewServer(&mcp.Implementation{Name: "synthetic", Version: "1"}, nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}, "required": []string{"text"}, "additionalProperties": false}
	up.AddTool(&mcp.Tool{Name: "echo", Description: "<script>alert(1)</script>", InputSchema: schema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		return &mcp.CallToolResult{}, nil
	})
	srv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return up }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	defer srv.Close()
	post := func(path string, f url.Values, want int) {
		t.Helper()
		snap, e := s.ReadSnapshot(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		f.Set("csrf", csrf)
		f.Set("revision", fmt.Sprint(snap.Revision))
		w := request(h, "POST", path, f, cookie)
		if w.Code != want {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	secret := "synthetic-upstream-secret-123456"
	post("/admin/servers/create", url.Values{"id": {"test"}, "url": {srv.URL + "/mcp"}, "description": {"<script>alert(2)</script>"}, "secret": {secret}}, 303)
	snap, _ := s.ReadSnapshot(context.Background())
	if snap.Config.Servers["test"].Enabled || len(snap.Config.Servers["test"].Tools) != 0 {
		t.Fatal("create granted access")
	}
	post("/admin/servers/test/enable", url.Values{}, 303)
	post("/admin/servers/test/check", url.Values{}, 303)
	if calls.Load() != 0 {
		t.Fatal("probe invoked tool")
	}
	w := request(h, "GET", "/admin/servers", nil, cookie)
	if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatal("secret or unescaped upstream content")
	}
	post("/admin/servers/test/access", url.Values{"tool": {"echo"}}, 404)
	post("/admin/servers/test/tool-enable", url.Values{"tool": {"echo"}}, 303)
	post("/admin/servers/test/enable", url.Values{}, 303)
	snap, _ = s.ReadSnapshot(context.Background())
	if !snap.Config.Servers["test"].Enabled || snap.Config.Servers["test"].Tools["echo"].AccessMode != "shared" || len(snap.Config.Principals["codex"].Grants) != 0 {
		t.Fatal("access missing")
	}
	stale := request(h, "POST", "/admin/servers/test/disable", url.Values{"csrf": {csrf}, "revision": {"1"}}, cookie)
	if stale.Code != 409 {
		t.Fatal("stale revision", stale.Code)
	}
	post("/admin/servers/test/update", url.Values{"url": {"http://127.0.0.1:9000/mcp"}}, 303)
	snap, _ = s.ReadSnapshot(context.Background())
	if snap.Config.Servers["test"].Enabled || len(snap.Config.Servers["test"].Tools) > 0 || len(snap.Config.Principals["codex"].Grants["test"]) > 0 {
		t.Fatal("URL change did not clear access")
	}
	post("/admin/servers/test/delete", url.Values{"confirm": {"wrong"}}, 400)
	post("/admin/servers/test/delete", url.Values{"confirm": {"test"}}, 303)
	snap, _ = s.ReadSnapshot(context.Background())
	if len(snap.Config.Servers) != 0 {
		t.Fatal("delete failed")
	}
}
func TestLoginRateLimitsAndSeparateToken(t *testing.T) {
	h, s := adminFixture(t)
	if _, e := New(s, Options{Token: "synthetic-client-token-123456", Origin: "http://127.0.0.1:8081"}); e == nil {
		t.Fatal("principal token accepted")
	}
	for i := 0; i < 5; i++ {
		if !h.a.loginAllowed(fmt.Sprintf("127.0.0.1:%d", 1000+i)) {
			t.Fatal("unexpected rejection")
		}
	}
	if h.a.loginAllowed("127.0.0.1:2000") {
		t.Fatal("source port bypass")
	}
	secure, e := newAuth(adminToken, "https://mcp.example")
	if e != nil || !secure.secure {
		t.Fatal("HTTPS cookies")
	}
}

func TestExternalPrefix(t *testing.T) {
	_, s := adminFixture(t)
	raw, err := New(s, Options{Token: adminToken, Origin: "https://mcp.example", BasePath: "/gateway"})
	if err != nil {
		t.Fatal(err)
	}
	h := raw.(*handler)
	r := httptest.NewRequest("GET", "https://mcp.example/admin/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), `action="/gateway/admin/login"`) {
		t.Fatal("missing external form prefix", w.Body.String())
	}
	nonce := w.Result().Cookies()[0]
	if nonce.Path != "/gateway/admin/" || !nonce.Secure {
		t.Fatal("external cookie path", nonce)
	}
	form := url.Values{"csrf": {nonce.Value}, "token": {adminToken}}
	r = httptest.NewRequest("POST", "https://mcp.example/admin/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://mcp.example")
	r.AddCookie(nonce)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Location") != "/gateway/admin/servers" {
		t.Fatal("redirect prefix")
	}
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "gateway_admin" {
			sessionCookie = c
		}
	}
	r = httptest.NewRequest("GET", "https://mcp.example/admin/servers", nil)
	r.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), `action="/admin/`) || !strings.Contains(w.Body.String(), `action="/gateway/admin/logout"`) {
		t.Fatal("nested external form prefix")
	}
	if _, err = New(s, Options{Token: adminToken, Origin: "https://mcp.example", BasePath: "/../evil"}); err == nil {
		t.Fatal("unsafe prefix")
	}
}
