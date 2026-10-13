package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/gateway"
	"mcp-gateway/internal/store"
	"mcp-gateway/internal/upstream"
)

func TestCatalogNewToolInExistingClientSession(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { testCatalogExistingSession(t, "") })
	if dsn := os.Getenv("TEST_CATALOG_POSTGRES_DSN"); dsn != "" {
		t.Run("postgres", func(t *testing.T) { testCatalogExistingSession(t, dsn) })
	}
}

func catalogAdminFixture(t *testing.T, dsn string) (*handler, store.Store) {
	if dsn == "" {
		return adminFixture(t)
	}
	t.Setenv("ADMIN_TEST_CLIENT", "synthetic-client-token-123456")
	ctx := context.Background()
	if err := store.Migrate(ctx, "postgres", dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open("postgres", dsn, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cfg := &config.Config{Servers: map[string]config.Server{}, Principals: map[string]config.Principal{"codex": {TokenEnv: "ADMIN_TEST_CLIENT", Grants: map[string]map[string]config.Grant{}}}}
	if _, err = db.CompareAndSwap(ctx, 0, cfg, nil); err != nil {
		t.Fatal("requires empty disposable PostgreSQL database", err)
	}
	h, err := New(db, Options{Token: adminToken, Origin: "http://127.0.0.1:8081"})
	if err != nil {
		t.Fatal(err)
	}
	return h.(*handler), db
}

func testCatalogExistingSession(t *testing.T, dsn string) {
	h, db := catalogAdminFixture(t, dsn)
	cache := catalog.New()
	defer cache.Close()
	h.catalog = cache
	var listings, calls atomic.Int32
	var failList atomic.Bool
	syn := mcp.NewServer(&mcp.Implementation{Name: "catalog-fixture", Version: "1"}, nil)
	add := func(name string) {
		syn.AddTool(&mcp.Tool{Name: name, Description: "Synthetic " + name, InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, OutputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			calls.Add(1)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "synthetic value"}}, StructuredContent: map[string]any{"ok": true}}, nil
		})
	}
	add("old_read")
	backHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return syn }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		var msg struct{ Method string }
		json.Unmarshal(b, &msg)
		if msg.Method == "tools/list" {
			listings.Add(1)
			if failList.Load() {
				http.Error(w, "synthetic failure", 503)
				return
			}
		}
		backHandler.ServeHTTP(w, r)
	}))
	defer back.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	snap, err := db.ReadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := clone(snap.Config)
	c.Servers["one"] = config.Server{URL: back.URL + "/mcp", Enabled: true, Tools: map[string]config.Tool{"old_read": {Enabled: true, AccessMode: "shared"}}}
	snap, err = db.CompareAndSwap(ctx, snap.Revision, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	gh, err := (&gateway.Gateway{Store: db, Catalog: cache}).Handler()
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(gh)
	defer web.Close()
	hc := upstream.HTTPClient("synthetic-client-token-123456", 5*time.Second)
	defer hc.CloseIdleConnections()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "same-session", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: web.URL + "/mcp", HTTPClient: hc, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	fixed, err := session.ListTools(ctx, nil)
	if err != nil || len(fixed.Tools) != 5 {
		t.Fatal("expected five fixed tools", err)
	}
	call := func(name string, args map[string]any, wantError bool) *mcp.CallToolResult {
		t.Helper()
		r, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil || r.IsError != wantError {
			t.Fatalf("%s: %v %+v", name, err, r)
		}
		return r
	}
	search := func(query string) []struct {
		ToolName   string    `json:"tool_name"`
		Definition *mcp.Tool `json:"tool_definition"`
	} {
		t.Helper()
		r := call("search_tools", map[string]any{"query": query}, false)
		b, _ := json.Marshal(r.StructuredContent)
		var got struct {
			Tools []struct {
				ToolName   string    `json:"tool_name"`
				Definition *mcp.Tool `json:"tool_definition"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		return got.Tools
	}
	if ts := search("old_read"); len(ts) != 1 || ts[0].Definition == nil || ts[0].Definition.OutputSchema == nil || !ts[0].Definition.Annotations.ReadOnlyHint {
		t.Fatal("missing schema/annotations")
	}
	if listings.Load() != 1 {
		t.Fatal("cold search", listings.Load())
	}
	add("new_read")
	if len(search("new_read")) != 0 || listings.Load() != 1 {
		t.Fatal("warm search unexpectedly refreshed or exposed unregistered tool")
	}
	cookie, csrf := login(t, h)
	post := func(action string, form url.Values, jsonResponse bool, want int) {
		t.Helper()
		snap, err := db.ReadSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if form == nil {
			form = url.Values{}
		}
		form.Set("csrf", csrf)
		form.Set("revision", fmt.Sprint(snap.Revision))
		r := httptest.NewRequest("POST", "http://127.0.0.1:8081/admin/servers/one/"+action, strings.NewReader(form.Encode()))
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://127.0.0.1:8081")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if jsonResponse {
			r.Header.Set("Accept", "application/json")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal(action, w.Code, w.Body.String())
		}
	}
	post("check", nil, false, 303)
	if listings.Load() != 2 || calls.Load() != 0 {
		t.Fatal("check must list once and never invoke")
	}
	if len(search("new_read")) != 0 || listings.Load() != 2 {
		t.Fatal("new tool exposed before enable or publication missed")
	}
	post("tool-enable", url.Values{"tool": {"new_read"}}, true, 200)
	if ts := search("new_read"); len(ts) != 1 || ts[0].ToolName != "new_read" || ts[0].Definition == nil {
		t.Fatal("new schema not visible in existing session")
	}
	call("get_tool_schema", map[string]any{"server_id": "one", "tool_name": "new_read"}, false)
	invoke := map[string]any{"server_id": "one", "tool_name": "new_read", "arguments": map[string]any{}}
	call("invoke_tool", invoke, false)
	if listings.Load() != 2 || calls.Load() != 1 {
		t.Fatal("cached schema/invoke fetched extra catalog or repeated call", listings.Load(), calls.Load())
	}
	// Failed checks leave both committed registry and the still-fresh catalog intact.
	before, _ := db.ReadSnapshot(ctx)
	failList.Store(true)
	post("check", nil, false, 502)
	after, _ := db.ReadSnapshot(ctx)
	failList.Store(false)
	if before.Revision != after.Revision || len(search("new_read")) != 1 {
		t.Fatal("failed check altered registry/catalog")
	}
	post("tool-disable", url.Values{"tool": {"new_read"}}, true, 200)
	if len(search("new_read")) != 0 {
		t.Fatal("cached tool ignored disable")
	}
	beforeCalls, beforeLists := calls.Load(), listings.Load()
	call("invoke_tool", invoke, true)
	if calls.Load() != beforeCalls || listings.Load() != beforeLists {
		t.Fatal("disabled invocation contacted upstream")
	}
	// Existing SDK session must reauthenticate even though its metadata is warm.
	t.Setenv("ADMIN_TEST_CLIENT", "synthetic-rotated-client-token-123456")
	if r, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "search_tools", Arguments: map[string]any{"query": "old_read"}}); err == nil && !r.IsError {
		t.Fatal("revoked credential retained access")
	}
	if calls.Load() != beforeCalls || listings.Load() != beforeLists {
		t.Fatal("revoked session contacted upstream")
	}
	t.Logf("same session: old catalog → admin check → enable → new schema → one invoke; tools/list=2 before failed-check QA, CallTool=1")
}

func TestCatalogPublicationRejectsRotatedCheckCredential(t *testing.T) {
	h, db := adminFixture(t)
	cache := catalog.New()
	defer cache.Close()
	h.catalog = cache
	syn := mcp.NewServer(&mcp.Implementation{Name: "rotation", Version: "1"}, nil)
	schema := map[string]any{"type": "object"}
	syn.AddTool(&mcp.Tool{Name: "current_metadata", InputSchema: schema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("check invoked tool")
		return nil, nil
	})
	back := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return syn }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	defer back.Close()
	t.Setenv("CHECK_ROTATION_TOKEN", "synthetic-before-rotation")
	ctx := context.Background()
	snap, _ := db.ReadSnapshot(ctx)
	c := clone(snap.Config)
	c.Servers["rotate"] = config.Server{URL: back.URL + "/mcp", TokenEnv: "CHECK_ROTATION_TOKEN", AuthHeader: "X-API-Key", Tools: map[string]config.Tool{}}
	saved, err := db.CompareAndSwap(ctx, snap.Revision, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := connectionKey(saved, "rotate")
	if err != nil {
		t.Fatal(err)
	}
	checked := probe{key: key, at: time.Now(), tools: map[string]*mcp.Tool{"old_metadata": {Name: "old_metadata", InputSchema: schema}}}
	t.Setenv("CHECK_ROTATION_TOKEN", "synthetic-after-rotation")
	h.updateCatalog(snap, saved, "rotate", &checked, true)
	conn, err := catalog.FromSnapshot(saved, "rotate")
	if err != nil {
		t.Fatal(err)
	}
	tools, err := cache.Get(ctx, conn, false)
	if err != nil || len(tools) != 1 || tools[0].Name != "current_metadata" {
		t.Fatal("old check published under rotated credential", err)
	}
}

type conflictCatalogStore struct {
	store.Store
	beforeCommit func()
}

func (s *conflictCatalogStore) CompareAndSwap(ctx context.Context, revision int64, c *config.Config, changes map[string]*string) (store.Snapshot, error) {
	s.beforeCommit()
	return s.Store.CompareAndSwap(ctx, revision, c, changes)
}

func TestCatalogCASConflictNeverPublishesCheckedTools(t *testing.T) {
	h, db := adminFixture(t)
	p := catalog.New()
	defer p.Close()
	h.catalog = p
	ctx := context.Background()
	syn := mcp.NewServer(&mcp.Implementation{Name: "conflict", Version: "1"}, nil)
	add := func(name string) {
		syn.AddTool(&mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			t.Fatal("check invoked tool")
			return nil, nil
		})
	}
	add("old_read")
	back := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return syn }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	defer back.Close()
	snap, _ := db.ReadSnapshot(ctx)
	c := clone(snap.Config)
	c.Servers["one"] = config.Server{URL: back.URL + "/mcp", Enabled: true, Tools: map[string]config.Tool{"old_read": {Enabled: true, AccessMode: "shared"}}}
	snap, err := db.CompareAndSwap(ctx, snap.Revision, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := catalog.FromSnapshot(snap, "one")
	if _, err = p.Get(ctx, conn, false); err != nil {
		t.Fatal(err)
	}
	add("unsaved_read")
	cookie, csrf := login(t, h)
	h.s = &conflictCatalogStore{Store: db, beforeCommit: func() {
		latest, err := db.ReadSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c := clone(latest.Config)
		server := c.Servers["one"]
		server.Description = "Concurrent edit"
		c.Servers["one"] = server
		if _, err = db.CompareAndSwap(ctx, latest.Revision, c, nil); err != nil {
			t.Fatal(err)
		}
	}}
	w := request(h, "POST", "/admin/servers/one/check", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}}, cookie)
	if w.Code != 409 {
		t.Fatal("expected CAS conflict", w.Code)
	}
	latest, _ := db.ReadSnapshot(ctx)
	if _, ok := latest.Config.Servers["one"].Tools["unsaved_read"]; ok {
		t.Fatal("failed CAS registered tool")
	}
	conn, _ = catalog.FromSnapshot(latest, "one")
	tools, refreshed, err := p.GetWithStatus(ctx, conn, false)
	if err != nil || refreshed || len(tools) != 1 || tools[0].Name != "old_read" {
		t.Fatal("failed CAS published new catalog", refreshed, err)
	}
}
