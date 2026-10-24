package config

import "testing"

func TestSimplifyPreservesSwitchesAndResetsPolicy(t *testing.T) {
	t.Setenv("SIMPLE_TOKEN", "synthetic-client-token-12345")
	c := &Config{RegistryVersion: 2,
		Servers: map[string]Server{"s": {URL: "http://127.0.0.1:9876/mcp", Enabled: false, Tools: map[string]Tool{"read": {Enabled: true}, "write": {Enabled: false}}}}, Principals: map[string]Principal{"codex": {ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
			TokenEnv: "SIMPLE_TOKEN", Grants: map[string]map[string]Grant{"s": {"read": {AllowedArguments: []string{"scope"}, ArgumentEquals: map[string]any{"scope": "safe"}}}}}}}
	before, err := Clone(c)
	if err != nil {
		t.Fatal(err)
	}
	if !SimplifyAccess(c) || SimplifyAccess(c) {
		t.Fatal("conversion idempotence")
	}
	if c.Servers["s"].Enabled || !c.Servers["s"].Tools["read"].Enabled || c.Servers["s"].Tools["write"].Enabled || len(c.Principals["codex"].Grants) != 0 {
		t.Fatal("conversion lost switches or retained grants")
	}
	if len(before.Principals["codex"].Grants) != 1 || before.Servers["s"].Tools["read"].AccessMode != "" {
		t.Fatal("old snapshot changed")
	}
	if c.Validate() != nil {
		t.Fatal("invalid simple config")
	}
	srv := c.Servers["s"]
	srv.Tools["read"] = Tool{AccessMode: "wildcard"}
	c.Servers["s"] = srv
	if c.Validate() == nil {
		t.Fatal("unknown access mode accepted")
	}
}
