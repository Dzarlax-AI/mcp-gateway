package config

import (
	"encoding/json"
	"testing"
)

func TestConnectorBatchSettingsFailClosed(t *testing.T) {
	t.Setenv("CONNECTOR_CONFIG_TOKEN", "synthetic-config-client-token")
	base := `{"principals":{"p":{"access_policy":"legacy_shared","grants":{},"token_env":"CONNECTOR_CONFIG_TOKEN","tool_allowlist":{}}},"registry_version":2,"servers":{"s":{"enabled":true,"tools":{},"url":"http://127.0.0.1:18081/mcp"}}}`
	var c Config
	json.Unmarshal([]byte(base), &c)
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		profile, endpoint string
		enabled, valid    bool
	}{{"home-assistant-v1", "http://127.0.0.1:18081/mcp", true, true}, {"unknown", "", false, false}, {"", "http://127.0.0.1:18081/mcp", true, false}, {"home-assistant-v1", "http://127.0.0.1:18082/mcp", true, false}, {"home-assistant-v1", "http://127.0.0.1:18081/mcp", false, false}, {"home-assistant-v1", "", false, true}} {
		s := c.Servers["s"]
		s.BatchReadProfile = tc.profile
		s.BatchReadEndpoint = tc.endpoint
		s.BatchReadEnabled = tc.enabled
		c.Servers["s"] = s
		if (c.Validate() == nil) != tc.valid {
			t.Fatalf("accepted/rejected %+v", tc)
		}
	}
}
