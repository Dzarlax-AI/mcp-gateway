//go:build ignore

// Synthetic local admin/MCP fixture. No real providers or credentials are used.
//
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/admin"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/gateway"
	"mcp-gateway/internal/readpolicy"
	"mcp-gateway/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	work, e := os.MkdirTemp("", "connector-batch-local-")
	if e != nil {
		panic(e)
	}
	defer os.RemoveAll(work)
	path := filepath.Join(work, "registry.db")
	if e = store.Migrate(ctx, "sqlite", path); e != nil {
		panic(e)
	}
	db, e := store.Open("sqlite", path, bytes.Repeat([]byte{14}, 32))
	if e != nil {
		panic(e)
	}
	defer db.Close()
	os.Setenv("CONNECTOR_FIXTURE_CLIENT", "synthetic-connector-fixture-client-token")
	s := mcp.NewServer(&mcp.Implementation{Name: "synthetic-home-assistant", Version: "1"}, nil)
	for _, t := range readpolicy.ReviewedTools("home-assistant-v1") {
		s.AddTool(t, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			time.Sleep(10 * time.Millisecond)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"synthetic":true}`}}}, nil
		})
	}
	s.AddTool(&mcp.Tool{Name: "intent__HassTurnOn", Description: "Synthetic control, never invoked", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return nil, fmt.Errorf("control must not run")
	})
	backend := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil))
	defer backend.Close()
	cfg := &config.Config{Servers: map[string]config.Server{"homeassistant": {Enabled: true, URL: backend.URL, BatchReadProfile: "home-assistant-v1", Description: "Synthetic read fixture", Tools: map[string]config.Tool{}}}, Principals: map[string]config.Principal{"client": {TokenEnv: "CONNECTOR_FIXTURE_CLIENT", Grants: map[string]map[string]config.Grant{}}}}
	srv := cfg.Servers["homeassistant"]
	for _, t := range readpolicy.ReviewedTools("home-assistant-v1") {
		srv.Tools[t.Name] = config.Tool{Enabled: true, AccessMode: "shared"}
	}
	srv.Tools["intent__HassTurnOn"] = config.Tool{Enabled: true, AccessMode: "shared"}
	cfg.Servers["homeassistant"] = srv
	if _, e = db.CompareAndSwap(ctx, 0, cfg, nil); e != nil {
		panic(e)
	}
	cat := catalog.New()
	defer cat.Close()
	h, e := (&gateway.Gateway{Store: db, Catalog: cat, ReadBatch: gateway.NewReadBatchExecutor(&gateway.ReadBatchPolicy{Registry: true}), Timeout: time.Second}).Handler()
	if e != nil {
		panic(e)
	}
	web := httptest.NewServer(h)
	defer web.Close()
	aw := httptest.NewUnstartedServer(nil)
	origin := "http://" + aw.Listener.Addr().String()
	a, e := admin.New(db, admin.Options{Origin: origin, Token: "synthetic-connector-admin-token", Catalog: cat, BatchRegistry: true, MCPEndpoint: web.URL + "/mcp"})
	if e != nil {
		panic(e)
	}
	aw.Config.Handler = a
	aw.Start()
	defer aw.Close()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"admin_origin": origin, "gateway_endpoint": web.URL + "/mcp", "admin_token": "synthetic-connector-admin-token", "registry_path": path})
	<-ctx.Done()
}
