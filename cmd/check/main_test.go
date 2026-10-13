package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCheckExpectedToolsAreFeatureScoped(t *testing.T) {
	legacy := []*mcp.Tool{
		{Name: "discover_server"},
		{Name: "discover_tools"},
		{Name: "get_tool_schema"},
		{Name: "invoke_tool"},
	}
	if err := checkExpectedTools(legacy, false); err != nil {
		t.Fatalf("legacy tool set rejected: %v", err)
	}
	if err := checkExpectedTools(legacy, true); err == nil {
		t.Fatal("feature-enabled check accepted a missing search_tools")
	}
	withSearch := append(append([]*mcp.Tool(nil), legacy...), &mcp.Tool{Name: "search_tools"})
	if err := checkExpectedTools(withSearch, true); err != nil {
		t.Fatalf("feature-enabled tool set rejected: %v", err)
	}
	withUnexpected := append(append([]*mcp.Tool(nil), withSearch...), &mcp.Tool{Name: "unexpected"})
	if err := checkExpectedTools(withUnexpected, true); err == nil {
		t.Fatal("accepted an unexpected tool in the feature-enabled catalog")
	}
}

func TestToolSearchEnabledParsing(t *testing.T) {
	for raw, want := range map[string]bool{"": false, "false": false, "true": true, "1": true} {
		got, err := toolSearchEnabled(raw)
		if err != nil || got != want {
			t.Errorf("toolSearchEnabled(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	if _, err := toolSearchEnabled("sometimes"); err == nil {
		t.Fatal("accepted invalid feature flag")
	}
}

func TestCheckConnectsThroughHTTPSWithTrustedCertificate(t *testing.T) {
	const token = "synthetic-public-check-token-123456"
	t.Setenv("GATEWAY_CODEX_TOKEN", token)
	server := mcp.NewServer(&mcp.Implementation{Name: "check-fixture", Version: "1"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("endpoint or credential mismatch")
			http.Error(w, "unauthorized", 401)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer tlsServer.Close()
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	session, cleanup, err := connectGateway(ctx, tlsServer.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err = session.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

func TestExpectedBatchToolSet(t *testing.T) {
	tools := []*mcp.Tool{{Name: "discover_server"}, {Name: "discover_tools"}, {Name: "get_tool_schema"}, {Name: "invoke_tool"}, {Name: "search_tools"}, {Name: "invoke_read_batch"}}
	if err := checkExpectedTools(tools, true, true); err != nil {
		t.Fatal(err)
	}
	if err := checkExpectedTools(tools, true, false); err == nil {
		t.Fatal("unexpected batch accepted")
	}
	if err := checkExpectedTools(tools, false, true); err == nil {
		t.Fatal("batch without search accepted")
	}
}
