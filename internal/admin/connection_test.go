package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"mcp-gateway/internal/config"
)

func TestClientKeysLifecycleAndGuards(t *testing.T) {
	h, s := adminFixture(t)
	h.mcpEndpoint = "https://mcp.example.com/gateway/mcp"
	cookie, csrf := login(t, h)
	do := func(method, path string, f url.Values, jsonResponse bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:8081"+path, strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://127.0.0.1:8081")
		r.AddCookie(cookie)
		if jsonResponse {
			r.Header.Set("Accept", "application/json")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do("GET", "/admin/connection", nil, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Managed by environment") || !strings.Contains(w.Body.String(), h.mcpEndpoint) || !strings.Contains(w.Body.String(), "X-API-Key: &lt;key&gt;") || !strings.Contains(w.Body.String(), "Choose one header") {
		t.Fatal("page", w.Code)
	}
	if !strings.Contains(do("GET", "/admin/servers", nil, false).Body.String(), `href="/admin/connection"`) {
		t.Fatal("navigation")
	}
	for _, f := range []url.Values{{"csrf": {"bad"}, "revision": {"1"}, "name": {"Laptop"}}, {"csrf": {csrf}, "revision": {"0"}, "name": {"Laptop"}}, {"csrf": {csrf}, "revision": {"1"}, "name": {""}}, {"csrf": {csrf, csrf}, "revision": {"1"}, "name": {"Laptop"}}} {
		if do("POST", "/admin/connection/keys/create", f, true).Code < 400 {
			t.Fatal("bad request accepted")
		}
	}
	if request(h, "POST", "/admin/connection/keys/create", url.Values{"csrf": {csrf}, "revision": {"1"}, "name": {"Laptop"}}).Code != 401 {
		t.Fatal("unauthenticated create")
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8081/admin/connection/keys/create", strings.NewReader(url.Values{"csrf": {csrf}, "revision": {"1"}, "name": {"Laptop"}}.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://attacker.example")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("origin")
	}
	w = do("POST", "/admin/connection/keys/create", url.Values{"csrf": {csrf}, "revision": {"1"}, "name": {"<Laptop>"}}, true)
	var issued connectionView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Token != "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("issue", w.Code)
	}
	snap, err := s.ReadSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for pid, p := range snap.Config.Principals {
		if p.Key != nil {
			id = pid
		}
	}
	revealPath := "/admin/connection/keys/" + id + "/reveal"
	for _, bad := range []url.Values{{"csrf": {"bad"}, "revision": {"2"}}, {"csrf": {csrf}, "revision": {"1"}}, {"csrf": {csrf, csrf}, "revision": {"2"}}} {
		if do("POST", revealPath, bad, true).Code < 400 {
			t.Fatal("reveal guard")
		}
	}
	for _, path := range []string{revealPath, "/admin/connection/keys/codex/reveal", "/admin/connection/keys/missing/reveal"} {
		if do("GET", path, nil, true).Code < 400 {
			t.Fatal("GET reveal")
		}
	}
	if request(h, "POST", revealPath, url.Values{"csrf": {csrf}, "revision": {"2"}}).Code != 401 {
		t.Fatal("unauthenticated reveal")
	}
	r = httptest.NewRequest("POST", "http://127.0.0.1:8081"+revealPath, strings.NewReader(url.Values{"csrf": {csrf}, "revision": {"2"}}.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://attacker.example")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("reveal Origin")
	}
	for i := 0; i < 2; i++ {
		w = do("POST", revealPath, url.Values{"csrf": {csrf}, "revision": {"2"}}, true)
		var shown struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &shown) != nil || shown.ID != id || len(shown.Token) != 47 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("reveal", w.Code)
		}
		if issued.Token != "" && issued.Token != shown.Token {
			t.Fatal("key changed")
		}
		issued.Token = shown.Token
	}
	for _, path := range []string{"/admin/connection/keys/codex/reveal", "/admin/connection/keys/missing/reveal"} {
		if do("POST", path, url.Values{"csrf": {csrf}, "revision": {"2"}}, true).Code < 400 {
			t.Fatal("unavailable reveal")
		}
	}
	authenticatedID, err := snap.Config.Authenticate("Bearer " + issued.Token)
	if authenticatedID != id {
		t.Fatal("principal mismatch")
	}
	if err != nil {
		t.Fatal("new auth")
	}
	if _, err = snap.Config.Authenticate("Bearer synthetic-client-token-123456"); err != nil {
		t.Fatal("legacy lost")
	}
	encoded, _ := json.Marshal(snap.Config)
	if strings.Contains(string(encoded), issued.Token) {
		t.Fatal("stored raw key")
	}
	w = do("POST", "/admin/servers/create", url.Values{"csrf": {csrf}, "revision": {"2"}, "id": {"collision"}, "url": {"http://127.0.0.1:9000/mcp"}, "auth_mode": {"bearer"}, "secret": {issued.Token}}, true)
	if w.Code != 400 {
		t.Fatal("managed key reused for upstream", w.Code)
	}
	for _, jsonResponse := range []bool{false, true} {
		w = do("GET", "/admin/connection", nil, jsonResponse)
		if strings.Contains(w.Body.String(), issued.Token) || strings.Contains(w.Body.String(), config.TokenDigest(issued.Token)) || strings.Contains(w.Body.String(), "ADMIN_TEST_CLIENT") {
			t.Fatal("list leak")
		}
		if !jsonResponse && (!strings.Contains(w.Body.String(), "&lt;Laptop&gt;") || strings.Contains(w.Body.String(), "<Laptop>")) {
			t.Fatal("name escaping")
		}
	}
	if do("POST", "/admin/connection/keys/codex/delete", url.Values{"csrf": {csrf}, "revision": {"2"}, "confirm": {"codex"}}, true).Code != 400 {
		t.Fatal("environment deletion")
	}
	if do("POST", "/admin/connection/keys/"+id+"/delete", url.Values{"csrf": {csrf}, "revision": {"1"}, "confirm": {"<Laptop>"}}, true).Code != 409 {
		t.Fatal("stale delete")
	}
	if do("POST", "/admin/connection/keys/"+id+"/delete", url.Values{"csrf": {csrf}, "revision": {"2"}, "confirm": {"wrong"}}, true).Code != 400 {
		t.Fatal("confirmation")
	}
	w = do("POST", "/admin/connection/keys/"+id+"/delete", url.Values{"csrf": {csrf}, "revision": {"2"}, "confirm": {"<Laptop>"}}, true)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatal("delete")
	}
	snap, _ = s.ReadSnapshot(context.Background())
	if do("POST", revealPath, url.Values{"csrf": {csrf}, "revision": {"3"}}, true).Code < 400 {
		t.Fatal("deleted key reveal")
	}
	if _, err = snap.Config.Authenticate("Bearer " + issued.Token); err == nil {
		t.Fatal("revocation")
	}
	if _, err = snap.Config.Authenticate("Bearer synthetic-client-token-123456"); err != nil {
		t.Fatal("legacy revoked")
	}
	// Ordinary forms create hidden keys, reveal explicitly, then delete with a redirect.
	w = do("POST", "/admin/connection/keys/create", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "name": {"No JS"}}, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `id="issued-key" readonly value=""`) {
		t.Fatal("no JS issue")
	}
	snap, _ = s.ReadSnapshot(context.Background())
	for pid, p := range snap.Config.Principals {
		if p.Key != nil {
			id = pid
		}
	}
	w = do("POST", "/admin/connection/keys/"+id+"/reveal", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}}, false)
	if w.Code != 200 || strings.Contains(w.Body.String(), `id="issued-key" readonly value=""`) || !strings.Contains(w.Body.String(), "automatic hiding is unavailable") {
		t.Fatal("no JS reveal")
	}
	w = do("POST", "/admin/connection/keys/"+id+"/delete", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "confirm": {"No JS"}}, false)
	if w.Code != 303 || w.Header().Get("Location") != "/admin/connection" {
		t.Fatal("no JS delete")
	}
	if do("GET", "/admin/connection.js", nil, false).Code != 200 {
		t.Fatal("asset")
	}
}

func TestConnectionProxyPrefix(t *testing.T) {
	h, s := adminFixture(t)
	raw, err := New(s, Options{Token: adminToken, Origin: h.a.origin, BasePath: "/gateway", MCPEndpoint: "https://mcp.example.com/gateway/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	proxied := raw.(*handler)
	cookie, _ := login(t, proxied)
	r := httptest.NewRequest("GET", "http://127.0.0.1:8081/gateway/admin/connection", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	http.StripPrefix("/gateway", proxied).ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `src="/gateway/admin/connection.js"`) || !strings.Contains(w.Body.String(), `action="/gateway/admin/connection/keys/create"`) || !strings.Contains(w.Body.String(), `href="/gateway/admin/servers"`) {
		t.Fatal("proxy prefix", w.Code)
	}
	for _, example := range []struct{ id, header, value string }{
		{"claude-bearer", "Authorization", "Bearer ${MCP_GATEWAY_TOKEN}"},
		{"claude-api-key", "X-API-Key", "${MCP_GATEWAY_TOKEN}"},
	} {
		_, block, ok := strings.Cut(w.Body.String(), `<pre id="`+example.id+`">`)
		if !ok || !strings.Contains(w.Body.String(), `data-copy="`+example.id+`"`) {
			t.Fatal("missing Claude example or copy button", example.id)
		}
		block, _, _ = strings.Cut(block, "</pre>")
		var parsed struct {
			Servers map[string]struct {
				Type    string            `json:"type"`
				URL     string            `json:"url"`
				Headers map[string]string `json:"headers"`
			} `json:"mcpServers"`
		}
		if err := json.Unmarshal([]byte(html.UnescapeString(block)), &parsed); err != nil {
			t.Fatal("invalid rendered Claude JSON", err)
		}
		server := parsed.Servers["gateway"]
		if server.Type != "http" || server.URL != proxied.mcpEndpoint || len(server.Headers) != 1 || server.Headers[example.header] != example.value {
			t.Fatal("Claude endpoint or credential placeholder incorrect", example.id)
		}
	}
}

func TestConnectionURLAndAdminTokenSeparation(t *testing.T) {
	h, s := adminFixture(t)
	for _, endpoint := range []string{"http://evil.example/mcp", "https://user:pass@example.com/mcp", "https://example.com/mcp?q=1", "https://example.com/mcp#frag"} {
		if _, err := New(s, Options{Token: adminToken, Origin: h.a.origin, MCPEndpoint: endpoint}); err == nil {
			t.Fatal("bad URL accepted")
		}
	}
	for _, endpoint := range []string{"https://example.com/gateway/mcp", "http://127.0.0.1:8080/mcp", "http://[::1]:8080/mcp"} {
		if _, err := New(s, Options{Token: adminToken, Origin: h.a.origin, MCPEndpoint: endpoint}); err != nil {
			t.Fatal("valid URL", err)
		}
	}
	snap, _ := s.ReadSnapshot(context.Background())
	c := clone(snap.Config)
	c.Principals["managed"] = config.Principal{ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
		TokenHash: config.TokenDigest(adminToken), Key: &config.ClientKey{Name: "bad", Prefix: "mgw_abcdefgh", CreatedAt: "2026-10-12T12:00:00Z"}}
	if _, err := s.CompareAndSwap(context.Background(), snap.Revision, c, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := New(s, Options{Token: adminToken, Origin: h.a.origin}); err == nil {
		t.Fatal("admin/client separation")
	}
}
