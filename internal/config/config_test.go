package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictConfig(t *testing.T) {
	t.Setenv("TEST_CLIENT_TOKEN", "client-token-long-enough")
	base := `{"servers":{"demo":{"url":"http://127.0.0.1:8081/mcp","tools":{"echo":{}}}},"principals":{"local":{"token_env":"TEST_CLIENT_TOKEN","grants":{"demo":{"echo":{"allowed_arguments":["text"]}}}}}}`
	path := filepath.Join(t.TempDir(), "config.json")
	cases := []struct {
		name, raw string
		ok        bool
	}{{"valid", base, true}, {"unknown", strings.Replace(base, `"url":`, `"oops":1,"url":`, 1), false}, {"duplicate", strings.Replace(base, `"url":`, `"url":"http://127.0.0.1:9000","url":`, 1), false}, {"external", strings.Replace(base, "127.0.0.1", "example.com", 1), false}, {"wildcard", strings.Replace(base, `["text"]`, `["*"]`, 1), false}, {"unknown grant", strings.Replace(base, `"grants":{"demo"`, `"grants":{"absent"`, 1), false}, {"trailing", base + ` {}`, false}, {"oversize", strings.Repeat(" ", 1<<20) + base, false}, {"null", "null", false}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.WriteFile(path, []byte(tc.raw), 0600)
			c, e := Load(path)
			if (e == nil) != tc.ok {
				t.Fatalf("valid=%v err=%v", tc.ok, e)
			}
			if tc.ok {
				if c.Servers["demo"].Enabled || c.Servers["demo"].Tools["echo"].Enabled {
					t.Fatal("enabled by default")
				}
				if _, e := c.Authenticate("Bearer client-token-long-enough"); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
func TestInvalidPolicyAndCredentials(t *testing.T) {
	t.Setenv("TEST_CLIENT_TOKEN", "client-token-long-enough")
	t.Setenv("TEST_OTHER_TOKEN", "other-token-long-enough")
	base := Config{Servers: map[string]Server{"demo": {URL: "http://127.0.0.1:8081/mcp", Tools: map[string]Tool{"echo": {}}}}, Principals: map[string]Principal{"local": {TokenEnv: "TEST_CLIENT_TOKEN", Grants: map[string]map[string]Grant{"demo": {"echo": {AllowedArguments: []string{"text"}}}}}}}
	for _, tc := range []string{"missing-secret", "duplicate-token", "shared-upstream-token", "bad-required", "bad-equals", "unknown-tool"} {
		t.Run(tc, func(t *testing.T) {
			b, _ := json.Marshal(base)
			var c Config
			json.Unmarshal(b, &c)
			p := c.Principals["local"]
			g := p.Grants["demo"]["echo"]
			switch tc {
			case "missing-secret":
				p.TokenEnv = "MISSING_TEST_TOKEN"
				t.Setenv(p.TokenEnv, "")
			case "duplicate-token":
				c.Principals["other"] = p
			case "shared-upstream-token":
				s := c.Servers["demo"]
				s.TokenEnv = p.TokenEnv
				c.Servers["demo"] = s
			case "bad-required":
				g.RequiredArguments = []string{"bad"}
			case "bad-equals":
				g.ArgumentEquals = map[string]any{"bad": "x"}
			case "unknown-tool":
				p.Grants["demo"]["bad"] = g
			}
			p.Grants["demo"]["echo"] = g
			c.Principals["local"] = p
			if c.Validate() == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
func TestURLRestriction(t *testing.T) {
	for _, url := range []string{"http://localhost/mcp", "https://127.0.0.1/mcp", "http://user:pass@127.0.0.1/mcp", "http://127.0.0.1/mcp?token=x", "http://example.com/mcp", "http://127.0.0.1/mcp#x"} {
		if ValidURL(url) {
			t.Fatal(url)
		}
	}
	for _, url := range []string{"http://127.0.0.1:1234/mcp", "http://[::1]:1234/mcp"} {
		if !ValidURL(url) {
			t.Fatal(url)
		}
	}
}

func TestHTTPSAllowlist(t *testing.T) {
	t.Setenv("TEST_CLIENT_TOKEN", "client-token-long-enough")
	endpoint := "https://developers.openai.com/mcp"
	c := Config{Servers: map[string]Server{"docs": {URL: endpoint, Tools: map[string]Tool{}}}, Principals: map[string]Principal{"test": {TokenEnv: "TEST_CLIENT_TOKEN"}}}
	if c.Validate() == nil {
		t.Fatal("remote allowed by default")
	}
	c.HTTPSAllowlist = []string{endpoint}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	if c.AllowsEndpoint("https://example.com/mcp") || c.AllowsEndpoint(endpoint+"/extra") {
		t.Fatal("allowlist is not exact")
	}
	for _, list := range [][]string{{endpoint, endpoint}, {"http://example.com/mcp"}, {"https://user:pass@example.com/mcp"}, {endpoint + "?token=x"}, {endpoint + "#x"}, {"https://developers.openai.com:8443/mcp"}, {"https://*.example.com/mcp"}} {
		c.HTTPSAllowlist = list
		if c.Validate() == nil {
			t.Fatal("invalid allowlist accepted")
		}
	}
}

func TestPolicyObjectRejectsDuplicateKeys(t *testing.T) {
	for _, raw := range []string{`{"text":"first","text":"last"}`, `{"x":{"same":1,"same":2}}`, `{"x":1} {"x":2}`, `null`, `[]`} {
		if _, e := DecodeObject([]byte(raw)); e == nil {
			t.Fatalf("ambiguous policy accepted: %s", raw)
		}
	}
	if object, e := DecodeObject([]byte(`{"limit":3,"query":"fixed"}`)); e != nil || object["limit"] != json.Number("3") {
		t.Fatal("valid fixed values rejected", object, e)
	}
}
