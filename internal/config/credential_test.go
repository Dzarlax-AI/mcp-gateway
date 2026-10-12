package config

import (
	"strings"
	"testing"
)

func TestCredentialHeaders(t *testing.T) {
	for _, name := range []string{"x-api-key", "X-API-Key", "X-Access-Key", "api_key"} {
		if !ValidAuthHeader(name) {
			t.Fatal("allowed header rejected", name)
		}
	}
	for _, name := range []string{"", "Host", "AUTHORIZATION", "Cookie", "Connection", "Content-Length", "Transfer-Encoding", "Content-Type", "Accept", "Forwarded", "x-forwarded-host", "X-authentik-username", "Mcp-Session-Id", "MCP-Protocol-Version", "Proxy-Authorization", "Sec-Fetch-Site", "Last-Event-ID", "bad header", "bad:header", "x\r\nname", strings.Repeat("x", 129)} {
		if ValidAuthHeader(name) {
			t.Fatal("reserved or invalid header accepted", name)
		}
	}
	for _, value := range []string{"k", "key with spaces"} {
		if !ValidCredential("x-api-key", value) {
			t.Fatal("custom value rejected")
		}
		if ValidCredential("", value) {
			t.Fatal("Bearer constraints relaxed")
		}
	}
	for _, value := range []string{"", "key\r\nHost: evil", "a\tb", "a\x00b", "a\x7fb", " leading", "trailing ", strings.Repeat("x", 4097)} {
		if ValidCredential("x-api-key", value) {
			t.Fatal("invalid value accepted")
		}
	}
}
