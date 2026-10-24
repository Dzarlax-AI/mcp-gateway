package policy

import (
	"encoding/json"
	"mcp-gateway/internal/config"
	"testing"
)

func TestRestrictedSharedDoesNotBypassACL(t *testing.T) {
	var c config.Config
	json.Unmarshal([]byte(`{"registry_version":2,"servers":{"s":{"enabled":true,"tools":{"read":{"enabled":true,"access_mode":"shared"},"write":{"enabled":true,"access_mode":"shared"}}}},"principals":{"a":{"access_policy":"restricted","tool_allowlist":{"s":["read"]}},"b":{"access_policy":"restricted","tool_allowlist":{}}}}`), &c)
	for _, tc := range []struct {
		p, tool string
		allow   bool
	}{{"a", "read", true}, {"a", "write", false}, {"b", "read", false}, {"unknown", "read", false}, {"a", "unknown", false}} {
		_, e := Grant(&c, tc.p, "s", tc.tool)
		if (e == nil) != tc.allow {
			t.Fatalf("%s/%s allowed=%v", tc.p, tc.tool, e == nil)
		}
	}
}

func TestRestrictedLegacyConstraintsIntersection(t *testing.T) {
	c := &config.Config{RegistryVersion: 2, Servers: map[string]config.Server{"s": {Enabled: true, Tools: map[string]config.Tool{"read": {Enabled: true}}}}, Principals: map[string]config.Principal{"p": {AccessPolicy: config.Restricted, ToolAllowlist: map[string][]string{"s": {"read"}}, Grants: map[string]map[string]config.Grant{"s": {"read": {AllowedArguments: []string{"scope"}, RequiredArguments: []string{"scope"}, ArgumentEquals: map[string]any{"scope": "safe"}}}}}}}
	g, e := Grant(c, "p", "s", "read")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		args  map[string]any
		allow bool
	}{{map[string]any{"scope": "safe"}, true}, {map[string]any{"scope": "other"}, false}, {map[string]any{}, false}, {map[string]any{"scope": "safe", "extra": true}, false}} {
		if (Arguments(g, tc.args) == nil) != tc.allow {
			t.Fatal(tc)
		}
	}
	delete(c.Principals["p"].Grants["s"], "read")
	if _, e = Grant(c, "p", "s", "read"); e == nil {
		t.Fatal("ACL bypassed missing legacy grant")
	}
}
