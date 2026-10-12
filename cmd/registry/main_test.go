package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitMigrationImportExport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	t.Setenv("GATEWAY_STORAGE", "sqlite")
	t.Setenv("GATEWAY_SQLITE_PATH", path)
	t.Setenv("GATEWAY_SECRET_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv("CLI_CLIENT_TOKEN", "synthetic-client-123456789")
	t.Setenv("CLI_API_KEY", "short key")
	c := config.Config{Servers: map[string]config.Server{"custom": {URL: "http://127.0.0.1:9000/mcp", AuthHeader: "x-api-key", TokenEnv: "CLI_API_KEY", Tools: map[string]config.Tool{"read": {Enabled: true}, "write": {Enabled: false}}}}, Principals: map[string]config.Principal{"codex": {TokenEnv: "CLI_CLIENT_TOKEN", Grants: map[string]map[string]config.Grant{"custom": {"read": {AllowedArguments: []string{"scope"}, ArgumentEquals: map[string]any{"scope": "safe"}}}}}}}
	b, _ := json.Marshal(c)
	file := filepath.Join(t.TempDir(), "config.json")
	if os.WriteFile(file, b, 0600) != nil {
		t.Fatal("fixture")
	}
	if err := run([]string{"import", "--file", file}); err == nil {
		t.Fatal("must explicitly migrate")
	}
	if err := run([]string{"migrate"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"import"}); err == nil {
		t.Fatal("explicit input file required")
	}
	if err := run([]string{"import", "--file", file}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"import", "--file", file}); err == nil {
		t.Fatal("cannot overwrite existing registry")
	}
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	err = run([]string{"export"})
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = config.Decode(out); err != nil {
		t.Fatal("export valid JSON", err)
	}
	if !bytes.Contains(out, []byte(`"auth_header": "x-api-key"`)) || bytes.Contains(out, []byte(os.Getenv("CLI_API_KEY"))) {
		t.Fatal("custom auth import/export")
	}
	if bytes.Contains(out, []byte(os.Getenv("CLI_CLIENT_TOKEN"))) {
		t.Fatal("export included credential")
	}

	if err := run([]string{"simplify"}); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open("sqlite", path, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := db.ReadSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision != 2 || len(snap.Config.Principals["codex"].Grants) != 0 || !snap.Config.Servers["custom"].Tools["read"].Enabled || snap.Config.Servers["custom"].Tools["write"].Enabled || snap.Config.Servers["custom"].AuthHeader != "x-api-key" {
		t.Fatal("simplify did not preserve switches/credentials")
	}
	if err := run([]string{"simplify"}); err != nil {
		t.Fatal(err)
	}
	again, err := db.ReadSnapshot(context.Background())
	db.Close()
	if err != nil || again.Revision != snap.Revision {
		t.Fatal("simplify not idempotent")
	}
	t.Setenv("GATEWAY_SECRET_KEY", "invalid")
	if err := run([]string{"export"}); err == nil {
		t.Fatal("reject malformed key")
	}
	if err := run([]string{"migrate"}); err != nil {
		t.Fatal("migration does not require secret key", err)
	}
}
