package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExplicitAgentACLMigrationPreservesNumbersAndGrants(t *testing.T) {
	t.Setenv("LEGACY_CLIENT", "synthetic-legacy-client-token")
	raw := []byte(`{"servers":{"s":{"url":"http://127.0.0.1:9999/mcp","enabled":true,"tools":{"read":{"enabled":true}}}},"principals":{"p":{"token_env":"LEGACY_CLIENT","grants":{"s":{"read":{"allowed_arguments":["n"],"argument_equals":{"n":123456789123456789123456789}}}}}}}`)
	if _, e := Decode(raw); e != ErrRegistryVersion {
		t.Fatal("runtime accepted v1", e)
	}
	b, changed, e := UpgradeAgentACLDocument(raw)
	if e != nil || !changed || !bytes.Contains(b, []byte("123456789123456789123456789")) {
		t.Fatal("migration", e)
	}
	c, e := Decode(b)
	if e != nil || c.Principals["p"].AccessPolicy != LegacyShared || len(c.Principals["p"].ToolAllowlist) != 0 {
		t.Fatal(e)
	}
	var before, after map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.Decode(&before)
	d = json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	d.Decode(&after)
	delete(after, "registry_version")
	for _, v := range after["principals"].(map[string]any) {
		p := v.(map[string]any)
		delete(p, "access_policy")
		delete(p, "tool_allowlist")
	}
	a, _ := json.Marshal(before)
	z, _ := json.Marshal(after)
	if !bytes.Equal(a, z) {
		t.Fatal("legacy content changed")
	}
	again, changed, e := UpgradeAgentACLDocument(b)
	if e != nil || changed || !bytes.Equal(again, b) {
		t.Fatal("not idempotent")
	}
	for _, bad := range []string{strings.Replace(string(raw), `"grants":`, `"access_policy":"restricted","grants":`, 1), strings.Replace(string(raw), `"servers":`, `"unknown":true,"servers":`, 1)} {
		if _, _, e := UpgradeAgentACLDocument([]byte(bad)); e == nil {
			t.Fatal("partial/unknown accepted")
		}
	}
}
