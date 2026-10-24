package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientKeyValidationAndAuthentication(t *testing.T) {
	t.Setenv("KEYS_ENV", "synthetic-preserved-codex-token")
	t.Setenv("KEYS_UPSTREAM", "synthetic-upstream-token")
	token := "mgw_abcdefghABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	p := Principal{ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
		TokenHash: TokenDigest(token), Key: &ClientKey{Name: "Laptop", Prefix: token[:12], CreatedAt: "2026-10-12T12:00:00Z"}}
	c := &Config{RegistryVersion: 2,
		Servers: map[string]Server{}, Principals: map[string]Principal{"codex": {ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
			TokenEnv: "KEYS_ENV"}, "key_new": p}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{token, "key_new"}, {"synthetic-preserved-codex-token", "codex"}} {
		if id, err := c.Authenticate("Bearer " + pair[0]); err != nil || id != pair[1] {
			t.Fatal("authentication", err)
		}
	}
	for _, header := range []string{"", "Bearer ", "bearer " + token, "Bearer wrong", "Bearer " + token + " "} {
		if _, err := c.Authenticate(header); err == nil {
			t.Fatal("bad credential accepted")
		}
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), token) || strings.Contains(string(b), "synthetic-preserved-codex-token") {
		t.Fatal("plaintext export")
	}
	if _, err := Decode(b); err != nil {
		t.Fatal("round trip", err)
	}
	for name, change := range map[string]func(*Principal){
		"both sources":     func(p *Principal) { p.TokenEnv = "KEYS_ENV" },
		"missing metadata": func(p *Principal) { p.Key = nil },
		"bad hash":         func(p *Principal) { p.TokenHash = "abc" },
		"upper hash":       func(p *Principal) { p.TokenHash = strings.ToUpper(p.TokenHash) },
		"control name":     func(p *Principal) { p.Key.Name = "bad\nname" },
		"bad prefix":       func(p *Principal) { p.Key.Prefix = token },
		"bad date":         func(p *Principal) { p.Key.CreatedAt = "yesterday" },
		"non UTC":          func(p *Principal) { p.Key.CreatedAt = "2026-10-12T12:00:00+02:00" },
		"grants":           func(p *Principal) { p.Grants = map[string]map[string]Grant{"any": {}} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			meta := *p.Key
			bad.Key = &meta
			change(&bad)
			c.Principals["key_new"] = bad
			if c.Validate() == nil {
				t.Fatal("invalid principal accepted")
			}
			c.Principals["key_new"] = p
		})
	}
	c.Principals["key_duplicate"] = p
	if c.Validate() == nil {
		t.Fatal("duplicate digest")
	}
	delete(c.Principals, "key_duplicate")
	t.Setenv("KEYS_ENV", token)
	if c.Validate() == nil {
		t.Fatal("env/hash duplicate")
	}
	t.Setenv("KEYS_ENV", "synthetic-preserved-codex-token")
	t.Setenv("KEYS_UPSTREAM", token)
	c.Servers["test"] = Server{URL: "http://127.0.0.1:9000/mcp", TokenEnv: "KEYS_UPSTREAM", Tools: map[string]Tool{}}
	if c.Validate() == nil {
		t.Fatal("upstream/hash duplicate")
	}
}

func TestRecoverableClientKeysRequireDatabase(t *testing.T) {
	token := "mgw_" + strings.Repeat("a", 43)
	c := Config{RegistryVersion: 2,
		Servers: map[string]Server{}, Principals: map[string]Principal{"key": {ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
			TokenHash: TokenDigest(token), Key: &ClientKey{Name: "Laptop", Prefix: token[:12], CreatedAt: "2026-10-12T12:00:00Z", Recoverable: true}}}}
	b, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("file/import accepted recoverable key without ciphertext")
	}
	if _, err := Decode(b); err != nil {
		t.Fatal("SQL document", err)
	}
}
