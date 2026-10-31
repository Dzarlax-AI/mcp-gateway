package admin

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/readpolicy"
	"mcp-gateway/internal/store"
)

func managementFixture(t *testing.T) (*handler, store.Store, []*mcp.Tool) {
	h, s := adminFixture(t)
	h.batchClassified = true
	h.catalog = catalog.New()
	t.Cleanup(h.catalog.Close)
	defs := []*mcp.Tool{{Name: "read_a", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, {Name: "read_b", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, {Name: "write_x", InputSchema: map[string]any{"type": "object"}}}
	snap, err := s.ReadSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := snap.Config
	c.Servers["test"] = config.Server{Enabled: true, URL: "http://127.0.0.1:9/mcp", Tools: map[string]config.Tool{"read_a": {AccessMode: "shared"}, "read_b": {AccessMode: "shared"}, "write_x": {AccessMode: "shared", OperationKind: "write"}}}
	snap, err = s.CompareAndSwap(context.Background(), snap.Revision, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	publishManagement(t, h, snap, defs)
	return h, s, defs
}
func publishManagement(t *testing.T, h *handler, snap store.Snapshot, defs []*mcp.Tool) {
	t.Helper()
	conn, err := catalog.FromSnapshot(snap, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = h.catalog.Publish(conn, snap.Revision, time.Now(), defs); err != nil {
		t.Fatal(err)
	}
}
func TestBulkToolEnableAtomicAndDisableOffline(t *testing.T) {
	h, s, _ := managementFixture(t)
	cookie, csrf := login(t, h)
	snap, _ := s.ReadSnapshot(context.Background())
	form := url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tools": {"read_a", "read_b"}, "selection_kind": {"read"}}
	w := request(h, "POST", "/admin/servers/test/bulk-enable", form, cookie)
	if w.Code != 303 || w.Header().Get("Location") != "/admin/servers/test" {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := s.ReadSnapshot(context.Background())
	if after.Revision != snap.Revision+1 || !after.Config.Servers["test"].Tools["read_a"].Enabled || !after.Config.Servers["test"].Tools["read_b"].Enabled || after.Config.Servers["test"].Tools["write_x"].Enabled {
		t.Fatal("not one isolated bulk commit")
	}
	h.catalog.Invalidate("test", after.Revision)
	form.Set("revision", fmt.Sprint(after.Revision))
	form.Del("selection_kind")
	w = request(h, "POST", "/admin/servers/test/bulk-disable", form, cookie)
	if w.Code != 303 {
		t.Fatal("disable contacted offline upstream", w.Code)
	}
	end, _ := s.ReadSnapshot(context.Background())
	if end.Revision != after.Revision+1 || end.Config.Servers["test"].Tools["read_a"].Enabled {
		t.Fatal("bulk disable")
	}
}
func TestBulkSelectionFailuresDoNotCommit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
		group string
		want  int
	}{{"empty", nil, "", 400}, {"repeated", []string{"read_a", "read_a"}, "", 400}, {"missing", []string{"read_a", "missing"}, "", 409}, {"changed group", []string{"read_a", "write_x"}, "read", 409}, {"invalid group", []string{"read_a"}, "other", 400}, {"too many", make([]string, 501), "", 400}} {
		t.Run(tc.name, func(t *testing.T) {
			h, s, _ := managementFixture(t)
			cookie, csrf := login(t, h)
			before, _ := s.ReadSnapshot(context.Background())
			w := request(h, "POST", "/admin/servers/test/bulk-enable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(before.Revision)}, "tools": tc.names, "selection_kind": {tc.group}}, cookie)
			after, _ := s.ReadSnapshot(context.Background())
			if w.Code != tc.want || after.Revision != before.Revision || after.Config.Servers["test"].Tools["read_a"].Enabled {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
func TestManualOperationClassification(t *testing.T) {
	h, s, defs := managementFixture(t)
	cookie, csrf := login(t, h)
	bindingSnapshot, _ := s.ReadSnapshot(context.Background())
	bindingConnection, _ := catalog.FromSnapshot(bindingSnapshot, "test")
	hash, _ := readpolicy.OperationFingerprint(defs[2], catalog.ConnectionBinding(bindingConnection))
	for _, tc := range []struct {
		kind, hash string
		want       int
	}{{"read", "", 409}, {"read", strings.Repeat("a", 64), 409}, {"read", hash, 303}, {"write", "", 303}, {"", "", 303}, {"other", "", 400}} {
		snap, _ := s.ReadSnapshot(context.Background())
		w := request(h, "POST", "/admin/servers/test/tool-operation", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tool": {"write_x"}, "operation_kind": {tc.kind}, "contract_hash": {tc.hash}}, cookie)
		if w.Code != tc.want {
			t.Fatal(tc.kind, w.Code, w.Body.String())
		}
		after, _ := s.ReadSnapshot(context.Background())
		setting := after.Config.Servers["test"].Tools["write_x"]
		if tc.want == 303 && (setting.OperationKind != tc.kind || (tc.kind == "read" && setting.OperationContractHash != hash)) {
			t.Fatal("classification not persisted")
		}
		if tc.want != 303 && after.Revision != snap.Revision {
			t.Fatal("rejected classification committed")
		}
	}
}
func TestBulkUnknownOutcomeCommitsOnce(t *testing.T) {
	h, s, _ := managementFixture(t)
	cookie, csrf := login(t, h)
	snap, _ := s.ReadSnapshot(context.Background())
	fault := &permissionUnknownStore{Store: s}
	h.s = fault
	w := request(h, "POST", "/admin/servers/test/bulk-enable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tools": {"read_a", "read_b"}}, cookie)
	after, _ := s.ReadSnapshot(context.Background())
	if w.Code != 503 || fault.calls != 1 || after.Revision != snap.Revision+1 || !strings.Contains(w.Body.String(), "could not be confirmed") {
		t.Fatal("unknown outcome", w.Code, fault.calls)
	}
}
func TestClassifiedViewUsesSharedMetadata(t *testing.T) {
	h, s, _ := managementFixture(t)
	snap, _ := s.ReadSnapshot(context.Background())
	v := h.view(snap, "")
	if len(v.Servers) != 1 || !v.Servers[0].CatalogFresh || v.Servers[0].Tools[0].OperationKind != "read" || v.Servers[0].Tools[2].OperationKind != "write" {
		t.Fatalf("view %+v", v.Servers)
	}
	h.catalog.Invalidate("test", snap.Revision)
	v = h.view(snap, "")
	if v.Servers[0].CatalogKnown || v.Servers[0].CatalogFresh || v.Servers[0].Tools[0].OperationKind != "unknown" {
		t.Fatal("stale data presented as current")
	}
}

func TestBulkGroupDisableRevalidatesWithoutNetwork(t *testing.T) {
	h, s, defs := managementFixture(t)
	cookie, csrf := login(t, h)
	snap, _ := s.ReadSnapshot(context.Background())
	changed := *defs[0]
	changed.Annotations = nil
	publishManagement(t, h, snap, []*mcp.Tool{&changed, defs[1], defs[2]})
	w := request(h, "POST", "/admin/servers/test/bulk-disable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tools": {"read_a", "read_b"}, "selection_kind": {"read"}}, cookie)
	after, _ := s.ReadSnapshot(context.Background())
	if w.Code != 409 || after.Revision != snap.Revision {
		t.Fatal("changed group disabled", w.Code)
	}
}
func TestBulkToolSelectionLimit(t *testing.T) {
	for _, n := range []int{500, 501} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			h, s, _ := managementFixture(t)
			cookie, csrf := login(t, h)
			snap, _ := s.ReadSnapshot(context.Background())
			srv := snap.Config.Servers["test"]
			names := []string{}
			defs := []*mcp.Tool{}
			srv.Tools = map[string]config.Tool{}
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("tool_%03d", i)
				names = append(names, name)
				srv.Tools[name] = config.Tool{AccessMode: "shared"}
				if i < 500 {
					defs = append(defs, &mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}})
				}
			}
			snap.Config.Servers["test"] = srv
			snap, err := s.CompareAndSwap(context.Background(), snap.Revision, snap.Config, nil)
			if err != nil {
				t.Fatal(err)
			}
			publishManagement(t, h, snap, defs)
			w := request(h, "POST", "/admin/servers/test/bulk-enable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tools": names}, cookie)
			want := 303
			if n == 501 {
				want = 400
			}
			if w.Code != want {
				t.Fatal(n, w.Code, w.Body.String())
			}
			after, _ := s.ReadSnapshot(context.Background())
			if n == 500 && after.Revision != snap.Revision+1 {
				t.Fatal("500 not atomic")
			}
			if n == 501 && after.Revision != snap.Revision {
				t.Fatal("501 committed")
			}
		})
	}
}
func TestWorkspaceErrorPreservesSafeDraftAndLocksUnknown(t *testing.T) {
	h, s, _ := managementFixture(t)
	cookie, csrf := login(t, h)
	snap, _ := s.ReadSnapshot(context.Background())
	w := request(h, "POST", "/admin/servers/test/update", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "description": {"Draft title"}, "url": {"not-an-endpoint"}, "auth_mode": {"none"}, "secret": {"never-return-this-secret"}}, cookie)
	body := w.Body.String()
	if w.Code != 400 || !strings.Contains(body, "Draft title") || strings.Contains(body, "never-return-this-secret") || !strings.Contains(body, `role="alert"`) {
		t.Fatal("draft/error response", w.Code)
	}
	fault := &permissionUnknownStore{Store: s}
	h.s = fault
	w = request(h, "POST", "/admin/servers/test/bulk-enable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tools": {"read_a"}}, cookie)
	if w.Code != 503 || !strings.Contains(w.Body.String(), `data-uncertain="true"`) || !strings.Contains(w.Body.String(), `checked`) {
		t.Fatal("unknown outcome not locked")
	}
}

func TestClassifiedManagementPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_MANAGEMENT_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires empty disposable PostgreSQL")
	}
	ctx := context.Background()
	t.Setenv("MANAGEMENT_PG_CLIENT", "synthetic-management-pg-client-token")
	if err := store.Migrate(ctx, "postgres", dsn); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	db, err := store.Open("postgres", dsn, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := &config.Config{RegistryVersion: config.RegistryVersion, Servers: map[string]config.Server{"test": {Enabled: true, URL: "http://127.0.0.1:9/mcp", Tools: map[string]config.Tool{"read_a": {AccessMode: "shared"}, "read_b": {AccessMode: "shared"}, "write_x": {AccessMode: "shared"}}}}, Principals: map[string]config.Principal{"codex": {AccessPolicy: config.LegacyShared, ToolAllowlist: map[string][]string{}, TokenEnv: "MANAGEMENT_PG_CLIENT"}}}
	snap, err := db.CompareAndSwap(ctx, 0, cfg, nil)
	if err != nil {
		t.Fatal("requires empty disposable management DB", err)
	}
	cache := catalog.New()
	defer cache.Close()
	web, err := New(db, Options{Token: adminToken, Origin: "http://127.0.0.1:8081", Catalog: cache, BatchClassified: true})
	if err != nil {
		t.Fatal(err)
	}
	h := web.(*handler)
	defs := []*mcp.Tool{{Name: "read_a", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, {Name: "read_b", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, {Name: "write_x", InputSchema: map[string]any{"type": "object"}}}
	publishManagement(t, h, snap, defs)
	cookie, csrf := login(t, h)
	w := request(h, "POST", "/admin/servers/test/bulk-enable", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "tools": {"read_a", "read_b"}, "selection_kind": {"read"}}, cookie)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := db.ReadSnapshot(ctx)
	if after.Revision != snap.Revision+1 || !after.Config.Servers["test"].Tools["read_a"].Enabled || after.Config.Servers["test"].Tools["write_x"].Enabled {
		t.Fatal("postgres bulk atomicity")
	}
	conn, _ := catalog.FromSnapshot(after, "test")
	hash, _ := readpolicy.OperationFingerprint(defs[2], catalog.ConnectionBinding(conn))
	w = request(h, "POST", "/admin/servers/test/tool-operation", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(after.Revision)}, "tool": {"write_x"}, "operation_kind": {"read"}, "contract_hash": {hash}}, cookie)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	reopened, err := store.Open("postgres", dsn, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted, err := reopened.ReadSnapshot(ctx)
	if err != nil || persisted.Config.Servers["test"].Tools["write_x"].OperationContractHash != hash {
		t.Fatal("postgres classification reopen", err)
	}
}
