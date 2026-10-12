package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
