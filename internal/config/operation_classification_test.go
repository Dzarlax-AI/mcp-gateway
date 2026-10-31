package config

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/readpolicy"
)

func TestOperationValidation(t *testing.T) {
	t.Setenv("OPERATION_TEST_TOKEN", "synthetic-client-token-123456")
	c := Config{RegistryVersion: RegistryVersion, Servers: map[string]Server{"demo": {URL: "http://127.0.0.1:8081/mcp", Tools: map[string]Tool{}}}, Principals: map[string]Principal{"local": {AccessPolicy: LegacyShared, ToolAllowlist: map[string][]string{}, TokenEnv: "OPERATION_TEST_TOKEN"}}}
	h := strings.Repeat("a", 64)
	for _, tc := range []struct {
		kind, hash string
		valid      bool
	}{
		{"", "", true}, {"write", "", true}, {"read", h, true}, {"read", "", false}, {"read", strings.ToUpper(h), false}, {"read", strings.Repeat("g", 64), false}, {"read", h + "a", false}, {"write", h, false}, {"", h, false}, {"unknown", "", false},
	} {
		srv := c.Servers["demo"]
		srv.Tools["find"] = Tool{OperationKind: tc.kind, OperationContractHash: tc.hash}
		c.Servers["demo"] = srv
		if got := c.Validate() == nil; got != tc.valid {
			t.Errorf("%q %q: %v", tc.kind, tc.hash, got)
		}
	}
}

func TestClassifiedReadDecisionAndClear(t *testing.T) {
	tool := &mcp.Tool{Name: "find", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
	hash, err := readpolicy.OperationFingerprint(tool)
	if err != nil {
		t.Fatal(err)
	}
	s := Server{Enabled: true, Tools: map[string]Tool{"find": {Enabled: true, OperationKind: "read", OperationContractHash: hash}, "change": {OperationKind: "write"}}}
	if ok, reason := s.ClassifiedReadDecision(tool); !ok || reason != "manual_read" {
		t.Fatal(ok, reason)
	}
	s.Enabled = false
	if ok, reason := s.ClassifiedReadDecision(tool); ok || reason != "server_disabled" {
		t.Fatal(ok, reason)
	}
	s.Enabled = true
	if ok, reason := s.ClassifiedReadDecision(nil); ok || reason != "catalog_unavailable" {
		t.Fatal(ok, reason)
	}
	if ok, reason := s.ClassifiedReadDecision(&mcp.Tool{Name: "missing"}); ok || reason != "tool_disabled" {
		t.Fatal(ok, reason)
	}
	s.ClearManualReadOperations()
	if s.Tools["find"].OperationKind != "" || s.Tools["find"].OperationContractHash != "" || s.Tools["change"].OperationKind != "write" {
		t.Fatal(s.Tools)
	}
}

func TestClassifiedReadDecisionConnectionBinding(t *testing.T) {
	tool := &mcp.Tool{Name: "find", InputSchema: map[string]any{"type": "object"}}
	hash, err := readpolicy.OperationFingerprint(tool, "old-connection")
	if err != nil {
		t.Fatal(err)
	}
	s := Server{Enabled: true, Tools: map[string]Tool{"find": {Enabled: true, OperationKind: "read", OperationContractHash: hash}}}
	if ok, reason := s.ClassifiedReadDecision(tool, "old-connection"); !ok || reason != "manual_read" {
		t.Fatal(ok, reason)
	}
	if ok, reason := s.ClassifiedReadDecision(tool, "new-connection"); ok || reason != "manual_read_stale" {
		t.Fatal(ok, reason)
	}
}
