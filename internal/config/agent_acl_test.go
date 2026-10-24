package config

import (
	"strings"
	"testing"
)

func TestAgentACLDocument(t *testing.T) {
	t.Setenv("ACL_CLIENT_TOKEN", "synthetic-acl-client-token")
	raw := `{"registry_version":2,"servers":{"s":{"url":"http://127.0.0.1:8081/mcp","tools":{"read":{"enabled":true,"access_mode":"shared"}}}},"principals":{"a":{"token_env":"ACL_CLIENT_TOKEN","access_policy":"restricted","tool_allowlist":{"s":["read"]},"grants":{}}}}`
	if _, e := Decode([]byte(raw)); e != nil {
		t.Fatalf("valid v2 ACL rejected: %v", e)
	}
	for _, bad := range []string{strings.Replace(raw, `"registry_version":2,`, "", 1), strings.Replace(raw, `"restricted"`, `"unknown"`, 1), strings.Replace(raw, `["read"]`, `["read","read"]`, 1), strings.Replace(raw, `["read"]`, `["*"]`, 1), strings.Replace(raw, `["read"]`, `["unknown"]`, 1), strings.Replace(raw, `"tool_allowlist":{"s":["read"]}`, `"tool_allowlist":null`, 1), strings.Replace(raw, `"restricted"`, `"legacy_shared"`, 1)} {
		if _, e := Decode([]byte(bad)); e == nil {
			t.Fatal("invalid ACL accepted")
		}
	}
}
