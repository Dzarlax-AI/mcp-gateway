package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectionEndpoint(t *testing.T) {
	t.Setenv("GATEWAY_MCP_EXTERNAL_URL", "")
	if got := connectionEndpoint("127.0.0.1:8090", ""); got != "http://127.0.0.1:8090/mcp" {
		t.Fatal("local MCP port", got)
	}
	if got := connectionEndpoint("0.0.0.0:8080", "https://example.com"); got != "" {
		t.Fatal("proxy must use explicit endpoint", got)
	}
	t.Setenv("GATEWAY_MCP_EXTERNAL_URL", "https://example.com/gateway/mcp")
	if got := connectionEndpoint("0.0.0.0:8080", "https://example.com"); got != "https://example.com/gateway/mcp" {
		t.Fatal(got)
	}
}

func TestListenRequiresExplicitPublicOrigin(t *testing.T) {
	for _, tc := range []struct {
		addr, origin string
		ok           bool
	}{
		{"127.0.0.1:8080", "", true}, {"[::1]:8080", "", true},
		{"0.0.0.0:8080", "", false}, {"192.0.2.1:8080", "", false},
		{"0.0.0.0:8080", "https://mcp.example.com", true},
		{"0.0.0.0:8080", "http://mcp.example.com", false},
		{"localhost:8080", "https://mcp.example.com", false},
		{":8080", "https://mcp.example.com", false},
		{"127.0.0.1:0", "", false}, {"127.0.0.1:65536", "", false},
		{"127.0.0.1:8080", "https://mcp.example.com/", false},
	} {
		if (validateListen(tc.addr, tc.origin) == nil) != tc.ok {
			t.Errorf("unexpected listen validation for %q %q", tc.addr, tc.origin)
		}
	}
}

func TestHealthcheck(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" || r.Header.Get("Authorization") != "" {
			t.Error("wrong healthcheck request")
		}
		w.Write([]byte("ok\n"))
	}))
	defer s.Close()
	addr := strings.TrimPrefix(s.URL, "http://")
	t.Setenv("GATEWAY_LISTEN_ADDR", addr)
	if e := healthCheck(); e != nil {
		t.Fatal(e)
	}
	t.Setenv("GATEWAY_LISTEN_ADDR", "0.0.0.0:"+strings.Split(addr, ":")[1])
	if e := healthCheck(); e != nil {
		t.Fatal(e)
	}
	t.Setenv("GATEWAY_LISTEN_ADDR", "invalid")
	if healthCheck() == nil {
		t.Fatal("invalid health address accepted")
	}
}
