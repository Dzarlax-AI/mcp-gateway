//go:build ignore

// Synthetic local browser fixture. It never contacts real providers.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/admin"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/gateway"
	"mcp-gateway/internal/readpolicy"
	"mcp-gateway/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dir, err := os.MkdirTemp("", "gateway-workspace-fixture-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "registry.db")
	if err = store.Migrate(ctx, "sqlite", path); err != nil {
		return err
	}
	db, err := store.Open("sqlite", path, bytes.Repeat([]byte{14}, 32))
	if err != nil {
		return err
	}
	defer db.Close()
	if err = os.Setenv("WORKSPACE_FIXTURE_CLIENT_TOKEN", "synthetic-workspace-client-token-123456"); err != nil {
		return err
	}

	upstream := mcp.NewServer(&mcp.Implementation{Name: "synthetic-inventory", Version: "1"}, nil)
	var definitions []*mcp.Tool
	reads := []string{"list_items", "get_item", "search_items", "get_stock", "list_locations", "get_location"}
	writes := []string{"add_item", "update_item", "remove_item", "move_item", "add_location", "remove_location"}
	for _, name := range reads {
		definitions = append(definitions, &mcp.Tool{Name: name, Description: "Synthetic read operation", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}})
	}
	for _, name := range writes {
		definitions = append(definitions, &mcp.Tool{Name: name, Description: "Synthetic write operation", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}})
	}
	definitions = append(definitions, &mcp.Tool{Name: "preview_import", Description: "Synthetic unclassified operation", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}})
	for _, tool := range definitions {
		upstream.AddTool(tool, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"synthetic":true}`}}}, nil
		})
	}
	backend := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upstream }, nil))
	defer backend.Close()
	hash, err := readpolicy.OperationFingerprint(definitions[0])
	if err != nil {
		return err
	}
	names := []string{"demo-inventory", "demo-recipes", "demo-library", "demo-workshop", "demo-weather"}
	cfg := &config.Config{RegistryVersion: config.RegistryVersion, Servers: map[string]config.Server{}, Principals: map[string]config.Principal{"demo-cli": {AccessPolicy: config.LegacyShared, ToolAllowlist: map[string][]string{}, TokenEnv: "WORKSPACE_FIXTURE_CLIENT_TOKEN", Grants: map[string]map[string]config.Grant{}}}}
	for i, name := range names {
		server := config.Server{URL: backend.URL, Description: "Synthetic " + name + " connector", Enabled: i != 4, Tools: map[string]config.Tool{}}
		for j, tool := range definitions {
			v := config.Tool{Enabled: j%3 != 2, AccessMode: "shared"}
			if j == 0 {
				v.OperationKind = "read"
				v.OperationContractHash = hash
			}
			if j >= len(reads) && j < len(reads)+len(writes) {
				v.OperationKind = "write"
			}
			server.Tools[tool.Name] = v
		}
		cfg.Servers[name] = server
		conn, e := catalog.FromSnapshot(store.Snapshot{Config: cfg}, name)
		if e != nil {
			return e
		}
		setting := server.Tools[definitions[0].Name]
		setting.OperationContractHash, e = readpolicy.OperationFingerprint(definitions[0], catalog.ConnectionBinding(conn))
		if e != nil {
			return e
		}
		server.Tools[definitions[0].Name] = setting
		cfg.Servers[name] = server
	}
	snap, err := db.CompareAndSwap(ctx, 0, cfg, nil)
	if err != nil {
		return err
	}
	cache := catalog.New()
	defer cache.Close()
	for _, name := range names {
		conn, e := catalog.FromSnapshot(snap, name)
		if e != nil {
			return e
		}
		if e = cache.Publish(conn, snap.Revision, time.Now(), definitions); e != nil {
			return e
		}
	}
	handler, err := (&gateway.Gateway{Store: db, Catalog: cache, ReadBatch: gateway.NewReadBatchExecutor(&gateway.ReadBatchPolicy{Classified: true}), Timeout: time.Second}).Handler()
	if err != nil {
		return err
	}
	web := httptest.NewServer(handler)
	defer web.Close()
	aw := httptest.NewUnstartedServer(nil)
	origin := "http://" + aw.Listener.Addr().String()
	a, err := admin.New(db, admin.Options{Origin: origin, Token: "synthetic-workspace-admin-token-123456", Catalog: cache, BatchClassified: true, MCPEndpoint: web.URL + "/mcp"})
	if err != nil {
		aw.Listener.Close()
		return err
	}
	aw.Config.Handler = a
	aw.Start()
	defer aw.Close()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]string{"admin_origin": origin, "mcp_endpoint": web.URL + "/mcp"}); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
