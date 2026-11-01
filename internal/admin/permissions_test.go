package admin

import (
	"context"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/audit"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPermissionsCASAndAuditLoss(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	ctx := context.Background()
	snap, _ := s.ReadSnapshot(ctx)
	c := clone(snap.Config)
	c.Servers["demo"] = config.Server{URL: "http://127.0.0.1:9999/mcp", Enabled: true, Tools: map[string]config.Tool{"read": {Enabled: true, AccessMode: "shared"}, "off": {AccessMode: "shared"}}}
	snap, e := s.CompareAndSwap(ctx, snap.Revision, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(t.TempDir(), "audit")
	h.audit, e = audit.New(dir)
	if e != nil {
		t.Fatal(e)
	}
	post := func(f url.Values, json bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://127.0.0.1:8081/admin/connection/permissions/codex", strings.NewReader(f.Encode()))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://127.0.0.1:8081")
		if json {
			req.Header.Set("Accept", "application/json")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	fields := url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "policy": {"restricted"}, permissionField("demo", "read"): {"1"}, permissionField("demo", "off"): {"1"}}
	wrong := fields.Encode()
	bad, _ := url.ParseQuery(wrong)
	bad.Set("csrf", "bad")
	if post(bad, true).Code != 403 {
		t.Fatal("csrf")
	}
	if e := os.Rename(dir, dir+"-removed"); e != nil {
		t.Fatal(e)
	}
	w := post(fields, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"audit_status":"degraded"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := s.ReadSnapshot(ctx)
	p := after.Config.Principals["codex"]
	if p.AccessPolicy != config.Restricted || len(p.ToolAllowlist["demo"]) != 2 || after.Revision != snap.Revision+1 {
		t.Fatal("ACL not atomically saved")
	}
	if post(fields, true).Code != 409 {
		t.Fatal("stale save")
	}
	latest, _ := s.ReadSnapshot(ctx)
	if latest.Revision != after.Revision {
		t.Fatal("stale save wrote")
	}
	fields.Set("revision", fmt.Sprint(after.Revision))
	fields.Set("policy", "legacy_shared")
	if post(fields, true).Code != 400 {
		t.Fatal("restricted broadening accepted")
	}
	page := request(h, "GET", "/admin/connection/permissions/codex", nil, cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Disabled") || !strings.Contains(page.Body.String(), "degraded") {
		t.Fatal("configured/effective page")
	}
	fields.Set("policy", "restricted")
	fields.Del(permissionField("demo", "read"))
	fields.Del(permissionField("demo", "off"))
	if post(fields, false).Code != 303 {
		t.Fatal("no-JS save")
	}
	latest, _ = s.ReadSnapshot(ctx)
	if len(latest.Config.Principals["codex"].ToolAllowlist) != 0 {
		t.Fatal("empty ACL not saved")
	}
}
func TestLifecyclePreservesLegacyAndClearsACL(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	ctx := context.Background()
	snap, _ := s.ReadSnapshot(ctx)
	c := clone(snap.Config)
	c.Servers["demo"] = config.Server{URL: "http://127.0.0.1:9999/mcp", Enabled: true, Tools: map[string]config.Tool{"read": {}}}
	p := c.Principals["codex"]
	p.AccessPolicy = config.Restricted
	p.ToolAllowlist = map[string][]string{"demo": {"read"}}
	p.Grants = map[string]map[string]config.Grant{"demo": {"read": {AllowedArguments: []string{"scope"}, ArgumentEquals: map[string]any{"scope": "safe"}}}}
	c.Principals["codex"] = p
	snap, e := s.CompareAndSwap(ctx, snap.Revision, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := connectionKey(snap, "demo")
	h.probes["demo"] = probe{key: key, revision: snap.Revision, at: time.Now(), tools: map[string]*mcp.Tool{"read": {Name: "read", InputSchema: map[string]any{"type": "object"}}}}
	w := request(h, "POST", "/admin/servers/demo/tool-enable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tool": {"read"}}, cookie)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	snap, _ = s.ReadSnapshot(ctx)
	if snap.Config.Servers["demo"].Tools["read"].AccessMode != "" || len(snap.Config.Principals["codex"].Grants["demo"]) != 1 {
		t.Fatal("enable widened legacy access")
	}
	w = request(h, "POST", "/admin/servers/demo/update", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "url": {"http://127.0.0.1:9998/mcp"}, "auth_mode": {"none"}}, cookie)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	snap, _ = s.ReadSnapshot(ctx)
	if len(snap.Config.Principals["codex"].ToolAllowlist) != 0 || len(snap.Config.Principals["codex"].Grants) != 0 || snap.Config.Servers["demo"].Enabled {
		t.Fatal("endpoint retained rights")
	}
}

type permissionUnknownStore struct {
	store.Store
	calls int
}

func (s *permissionUnknownStore) CompareAndSwap(ctx context.Context, rev int64, c *config.Config, secrets map[string]*string) (store.Snapshot, error) {
	s.calls++
	out, e := s.Store.CompareAndSwap(ctx, rev, c, secrets)
	if e != nil {
		return out, e
	}
	return store.Snapshot{}, fmt.Errorf("synthetic lost acknowledgement")
}
func TestPermissionsUnknownOutcomeReadBack(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	snap, _ := s.ReadSnapshot(context.Background())
	fault := &permissionUnknownStore{Store: s}
	h.s = fault
	w := request(h, "POST", "/admin/connection/permissions/codex", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "policy": {"restricted"}}, cookie)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "could not be confirmed") || fault.calls != 1 {
		t.Fatal(w.Code, w.Body.String(), fault.calls)
	}
	after, e := s.ReadSnapshot(context.Background())
	if e != nil || after.Revision != snap.Revision+1 || after.Config.Principals["codex"].AccessPolicy != config.Restricted {
		t.Fatal("committed once", e)
	}
}

func TestVerifiedCatalogRemovalClearsOnlyMissingACL(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	ctx := context.Background()
	syn := mcp.NewServer(&mcp.Implementation{Name: "acl-catalog", Version: "1"}, nil)
	add := func(name string) {
		syn.AddTool(&mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			t.Error("check invoked a tool")
			return nil, nil
		})
	}
	add("keep")
	backend := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return syn }, nil))
	defer backend.Close()
	snap, _ := s.ReadSnapshot(ctx)
	c := clone(snap.Config)
	c.Servers["demo"] = config.Server{URL: backend.URL, Enabled: true, Tools: map[string]config.Tool{"keep": {Enabled: true, AccessMode: "shared"}, "gone": {Enabled: true, AccessMode: "shared"}}}
	p := c.Principals["codex"]
	p.AccessPolicy = config.Restricted
	p.ToolAllowlist = map[string][]string{"demo": {"keep", "gone"}}
	c.Principals["codex"] = p
	snap, e := s.CompareAndSwap(ctx, snap.Revision, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	check := func() {
		w := request(h, "POST", "/admin/servers/demo/check", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}}, cookie)
		if w.Code != 303 {
			t.Fatal(w.Code, w.Body.String())
		}
		snap, _ = s.ReadSnapshot(ctx)
	}
	check()
	if snap.Config.Servers["demo"].Tools["gone"].Enabled || strings.Join(snap.Config.Principals["codex"].ToolAllowlist["demo"], ",") != "keep" {
		t.Fatal("missing tool ACL retained")
	}
	add("gone")
	check()
	if snap.Config.Servers["demo"].Tools["gone"].Enabled || len(snap.Config.Principals["codex"].ToolAllowlist["demo"]) != 1 {
		t.Fatal("reappearance silently restored permission")
	}
	// Batch-enable publishes a verified probe through the same reconciler.
	c = clone(snap.Config)
	server := c.Servers["demo"]
	x := server.Tools["gone"]
	x.Enabled = true
	server.Tools["gone"] = x
	p = c.Principals["codex"]
	p.ToolAllowlist["demo"] = []string{"keep", "gone"}
	c.Principals["codex"] = p
	reconcileCatalogACL(c, "demo", &server, map[string]*mcp.Tool{"keep": {Name: "keep"}})
	if server.Tools["gone"].Enabled || len(c.Principals["codex"].ToolAllowlist["demo"]) != 1 {
		t.Fatal("probe reconciliation")
	}
}

func TestClientWorkspaceGuidesAndMultiServerPermissions(t *testing.T) {
	h, s := adminFixture(t)
	h.mcpEndpoint = "http://127.0.0.1:8080/mcp"
	cookie, csrf := login(t, h)
	ctx := context.Background()
	snap, _ := s.ReadSnapshot(ctx)
	c := clone(snap.Config)
	c.Servers["alpha"] = config.Server{URL: "http://127.0.0.1:9999/mcp", Enabled: true, Tools: map[string]config.Tool{"read": {Enabled: true, AccessMode: "shared"}, "other": {AccessMode: "shared"}}}
	c.Servers["beta"] = config.Server{URL: "http://127.0.0.1:9998/mcp", Tools: map[string]config.Tool{"off": {Enabled: true, AccessMode: "shared"}}}
	t.Setenv("SECOND_CLIENT_TOKEN", "second-client-token-123456789")
	c.Principals["second"] = config.Principal{TokenEnv: "SECOND_CLIENT_TOKEN", AccessPolicy: config.Restricted, ToolAllowlist: map[string][]string{}, Grants: map[string]map[string]config.Grant{}}
	snap, e := s.CompareAndSwap(ctx, snap.Revision, c, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/admin/connection", "/admin/connection/permissions/codex"} {
		w := request(h, "GET", path, nil, cookie)
		body := w.Body.String()
		for _, want := range []string{"Connect Codex", "codex mcp add", "MCP_GATEWAY_TOKEN", "Connect Claude Code", "claude-bearer", "claude-api-key", "data-client-workspace", "data-client-link"} {
			if w.Code != 200 || !strings.Contains(body, want) {
				t.Fatalf("%s missing %s", path, want)
			}
		}
	}
	form := url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "policy": {"restricted"}, permissionField("alpha", "read"): {"1"}, permissionField("beta", "off"): {"1"}}
	w := request(h, "POST", "/admin/connection/permissions/codex", form, cookie)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := s.ReadSnapshot(ctx)
	if after.Revision != snap.Revision+1 || len(after.Config.Principals["codex"].ToolAllowlist) != 2 || len(after.Config.Principals["second"].ToolAllowlist) != 0 || after.Config.Servers["beta"].Enabled {
		t.Fatal("multi-server ACL not isolated")
	}
	page := request(h, "GET", "/admin/connection/permissions/codex", nil, cookie).Body.String()
	for _, want := range []string{`data-server="alpha"`, `data-server="beta"`, `data-permission-group-select`, `data-allow-visible`, `data-deny-visible`, `Client settings`} {
		if !strings.Contains(page, want) {
			t.Fatal("missing workspace control", want)
		}
	}
	// A stale HTML submission preserves the submitted draft and marks it uncertain.
	stale := request(h, "POST", "/admin/connection/permissions/codex", form, cookie)
	if stale.Code != 409 || !strings.Contains(stale.Body.String(), `data-uncertain="true"`) {
		t.Fatal("stale draft unlocked", stale.Code)
	}
}
