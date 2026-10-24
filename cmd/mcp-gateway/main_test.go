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

func TestAccessOAuthEnvironmentValidation(t *testing.T) {
	for _, name := range []string{"GATEWAY_MCP_ACCESS_ENABLED", "GATEWAY_MCP_ACCESS_ISSUER", "GATEWAY_MCP_ACCESS_AUD", "GATEWAY_MCP_ACCESS_USER_MAP"} {
		t.Setenv(name, "")
	}
	if v, err := accessOAuthOptions(""); err != nil || v != nil {
		t.Fatalf("default profile should be off: %v %v", v, err)
	}
	t.Setenv("GATEWAY_MCP_ACCESS_ISSUER", "https://issuer.example.org")
	if _, err := accessOAuthOptions(""); err == nil {
		t.Fatal("settings accepted while profile is disabled")
	}
	t.Setenv("GATEWAY_MCP_ACCESS_ENABLED", "true")
	t.Setenv("GATEWAY_MCP_ACCESS_AUD", "synthetic-audience")
	t.Setenv("GATEWAY_MCP_ACCESS_USER_MAP", `{"alice@example.net":"principal-a"}`)
	if _, err := accessOAuthOptions(""); err == nil {
		t.Fatal("enabled profile accepted without public origin")
	}
	v, err := accessOAuthOptions("https://gateway.example.org")
	if err != nil || v == nil {
		t.Fatalf("valid synthetic settings rejected: %v", err)
	}
	t.Setenv("GATEWAY_MCP_ACCESS_USER_MAP", `{"alice@example.net":"a","alice@example.net":"b"}`)
	if _, err := accessOAuthOptions("https://gateway.example.org"); err == nil {
		t.Fatal("duplicate user-map key accepted")
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
