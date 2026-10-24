package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"mcp-gateway/internal/config"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func fixture(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("STORE_CLIENT_TOKEN", "synthetic-client-token-123456")
	return &config.Config{RegistryVersion: 2,
		Servers: map[string]config.Server{"demo": {URL: "http://127.0.0.1:9876/mcp", Tools: map[string]config.Tool{"hello": {Enabled: true}}}}, Principals: map[string]config.Principal{"codex": {ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
			TokenEnv: "STORE_CLIENT_TOKEN", Grants: map[string]map[string]config.Grant{"demo": {"hello": {AllowedArguments: []string{"name"}, RequiredArguments: []string{"name"}, ArgumentEquals: map[string]any{"name": "test"}}}}}}}
}
func TestContract(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { contract(t, "sqlite", filepath.Join(t.TempDir(), "registry.db")) })
	if dsn := os.Getenv("TEST_POSTGRES_DSN"); dsn != "" {
		t.Run("postgres", func(t *testing.T) { contract(t, "postgres", dsn) })
	}
}
func contract(t *testing.T, kind, location string) {
	ctx := context.Background()
	c := fixture(t)
	key := bytes.Repeat([]byte{42}, 32)
	if err := Migrate(ctx, kind, location); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, kind, location); err != nil {
		t.Fatal("migration idempotency", err)
	}
	si, err := Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	s := si.(*DB)
	defer s.Close()
	if _, err = s.ReadSnapshot(ctx); !errors.Is(err, ErrEmpty) {
		t.Fatal("expected empty", err)
	}
	first, err := s.CompareAndSwap(ctx, 0, c, nil)
	if err != nil || first.Revision != 1 {
		t.Fatal(first, err)
	}
	if _, err = s.CompareAndSwap(ctx, 0, c, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate import", err)
	}
	srv := c.Servers["demo"]
	srv.TokenRef = "demo"
	c.Servers["demo"] = srv
	if _, err = s.CompareAndSwap(ctx, 1, c, nil); !errors.Is(err, ErrSecret) {
		t.Fatal("missing credential", err)
	}
	if snap, e := s.ReadSnapshot(ctx); e != nil || snap.Revision != 1 {
		t.Fatal("rollback", snap, e)
	}
	token := "synthetic-upstream-token-12345"
	second, err := s.CompareAndSwap(ctx, 1, c, map[string]*string{"demo": &token})
	if err != nil || second.Revision != 2 {
		t.Fatal(second, err)
	}
	if got, e := ResolveSnapshotSecret(second, "demo"); e != nil || got != token {
		t.Fatal("resolve", e)
	}
	var ciphertext []byte
	if err = s.db.QueryRow("SELECT ciphertext FROM " + s.table("upstream_secrets") + " WHERE server_id='demo'").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(token)) {
		t.Fatal("plaintext stored")
	}
	replacement := "new-synthetic-upstream-token-12345"
	third, err := s.CompareAndSwap(ctx, 2, c, map[string]*string{"demo": &replacement})
	if err != nil {
		t.Fatal(err)
	}
	if got, e := ResolveSnapshotSecret(second, "demo"); e != nil || got != token {
		t.Fatal("admitted snapshot lost its credential", e)
	}
	if got, e := ResolveSnapshotSecret(third, "demo"); e != nil || got != replacement {
		t.Fatal("new credential", e)
	}
	same := os.Getenv("STORE_CLIENT_TOKEN")
	if _, err = s.CompareAndSwap(ctx, 3, c, map[string]*string{"demo": &same}); !errors.Is(err, ErrSecret) {
		t.Fatal("principal token separation", err)
	}
	short := "short"
	if _, err = s.CompareAndSwap(ctx, 3, c, map[string]*string{"demo": &short}); !errors.Is(err, ErrSecret) {
		t.Fatal("short credential", err)
	}
	if _, err = s.CompareAndSwap(ctx, 2, c, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("stale writer", err)
	}
	// Exactly one concurrent writer can advance the same revision.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.CompareAndSwap(ctx, 3, c, nil); results <- e }()
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal(success, conflicts)
	}
	// Reopen with the same key preserves the validated state.
	other, err := Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := other.ReadSnapshot(ctx)
	other.Close()
	if err != nil || snap.Revision != 4 {
		t.Fatal("restart", snap, err)
	}
	wrong, err := Open(kind, location, bytes.Repeat([]byte{43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrong.ReadSnapshot(ctx)
	wrong.Close()
	if !errors.Is(err, ErrSecret) {
		t.Fatal("wrong key", err)
	}
	// Delete the server and grant together; credentials are automatically removed.
	delete(c.Servers, "demo")
	p := c.Principals["codex"]
	delete(p.Grants, "demo")
	c.Principals["codex"] = p
	if _, err = s.CompareAndSwap(ctx, 4, c, nil); err != nil {
		t.Fatal(err)
	}
	var count int
	if s.db.QueryRow("SELECT count(*) FROM "+s.table("upstream_secrets")).Scan(&count) != nil || count != 0 {
		t.Fatal("orphan credential")
	}
	// Custom headers share the encrypted storage contract on both backends.
	c.Servers["custom"] = config.Server{URL: "http://127.0.0.1:9876/mcp", AuthHeader: "x-api-key", TokenRef: "custom", Tools: map[string]config.Tool{}}
	customKey := "short key"
	custom, err := s.CompareAndSwap(ctx, 5, c, map[string]*string{"custom": &customKey})
	if err != nil {
		t.Fatal("custom credential", err)
	}
	if err = s.db.QueryRow("SELECT ciphertext FROM " + s.table("upstream_secrets") + " WHERE server_id='custom'").Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte(customKey)) {
		t.Fatal("custom plaintext stored")
	}
	other, err = Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := other.ReadSnapshot(ctx)
	other.Close()
	if err != nil || persisted.Config.Servers["custom"].AuthHeader != "x-api-key" {
		t.Fatal("custom header persistence", err)
	}
	if got, e := ResolveSnapshotSecret(persisted, "custom"); e != nil || got != customKey {
		t.Fatal("custom secret persistence", e)
	}
	exported, err := json.Marshal(persisted.Config)
	if err != nil || bytes.Contains(exported, []byte(customKey)) {
		t.Fatal("export leaked credential")
	}
	srv = c.Servers["custom"]
	srv.AuthHeader = "X-Access-Key"
	c.Servers["custom"] = srv
	if _, err = s.CompareAndSwap(ctx, 5, c, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("custom stale writer", err)
	}
	if _, err = s.CompareAndSwap(ctx, 6, c, nil); err != nil {
		t.Fatal(err)
	}
	if custom.Config.Servers["custom"].AuthHeader != "x-api-key" {
		t.Fatal("admitted header mutated")
	}
	if got, e := ResolveSnapshotSecret(custom, "custom"); e != nil || got != customKey {
		t.Fatal("admitted custom key mutated")
	}
	srv.AuthHeader = ""
	c.Servers["custom"] = srv
	if _, err = s.CompareAndSwap(ctx, 7, c, nil); !errors.Is(err, ErrSecret) {
		t.Fatal("invalid Bearer conversion", err)
	}
	srv.AuthHeader = "X-Access-Key"
	c.Servers["custom"] = srv
	for _, bad := range []string{"a\r\nb", "a\x00b", os.Getenv("STORE_CLIENT_TOKEN")} {
		if _, err = s.CompareAndSwap(ctx, 7, c, map[string]*string{"custom": &bad}); !errors.Is(err, ErrSecret) {
			t.Fatal("invalid custom secret", err)
		}
	}
	srv.TokenRef = "duplicate"
	c.Servers["duplicate"] = srv
	if _, err = s.CompareAndSwap(ctx, 7, c, map[string]*string{"duplicate": &customKey}); !errors.Is(err, ErrSecret) {
		t.Fatal("duplicate custom credential", err)
	}

	delete(c.Servers, "duplicate")
	beforeSimple, err := s.ReadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	simple, err := config.Clone(beforeSimple.Config)
	if err != nil {
		t.Fatal(err)
	}
	v := simple.Servers["custom"]
	v.Tools = map[string]config.Tool{"read": {Enabled: true}, "write": {Enabled: false}}
	simple.Servers["custom"] = v
	client := simple.Principals["codex"]
	client.Grants = map[string]map[string]config.Grant{"custom": {"read": {AllowedArguments: []string{"scope"}, ArgumentEquals: map[string]any{"scope": "fixed"}}}}
	simple.Principals["codex"] = client
	if !config.SimplifyAccess(simple) {
		t.Fatal("no simplification")
	}
	converted, err := s.CompareAndSwap(ctx, 7, simple, nil)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err = reopened.ReadSnapshot(ctx)
	reopened.Close()
	if err != nil || persisted.Config.Servers["custom"].Tools["read"].AccessMode != "shared" || !persisted.Config.Servers["custom"].Tools["read"].Enabled || persisted.Config.Servers["custom"].Tools["write"].Enabled || len(persisted.Config.Principals["codex"].Grants) != 0 {
		t.Fatal("simple persistence", err)
	}
	if value, err := ResolveSnapshotSecret(converted, "custom"); err != nil || value != customKey {
		t.Fatal("simplify changed encrypted secret")
	}
	if len(beforeSimple.Config.Servers["custom"].Tools) != 0 {
		t.Fatal("simple conversion mutated old snapshot")
	}
	if _, err = s.CompareAndSwap(ctx, 7, simple, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("simple stale write")
	}
	delete(c.Servers, "duplicate")
	delete(c.Servers, "custom")
	if _, err = s.CompareAndSwap(ctx, 8, c, map[string]*string{"custom": nil}); err != nil {
		t.Fatal("custom removal", err)
	}
	// Managed client keys persist as hashes on both backends; old credentials remain intact.
	keySnapshot, err := s.ReadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := config.Clone(keySnapshot.Config)
	if err != nil {
		t.Fatal(err)
	}
	managedToken := "mgw_abcdefghABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	keys.Principals["key_laptop"] = config.Principal{ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
		TokenHash: config.TokenDigest(managedToken), Key: &config.ClientKey{Name: "Laptop", Prefix: managedToken[:12], CreatedAt: "2026-10-12T12:00:00Z"}}
	if _, err = s.CompareAndSwap(ctx, keySnapshot.Revision, keys, nil); err != nil {
		t.Fatal(err)
	}
	other, err = Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	keySnapshot, err = other.ReadSnapshot(ctx)
	other.Close()
	if err != nil {
		t.Fatal(err)
	}
	if id, e := keySnapshot.Config.Authenticate("Bearer " + managedToken); e != nil || id != "key_laptop" {
		t.Fatal("managed restart", e)
	}
	exported, err = json.Marshal(keySnapshot.Config)
	if err != nil || bytes.Contains(exported, []byte(managedToken)) {
		t.Fatal("managed export leak")
	}
	// Encrypted upstream credentials must also stay distinct from hashed client keys.
	keys.Servers["collision"] = config.Server{URL: "http://127.0.0.1:9876/mcp", TokenRef: "collision", Tools: map[string]config.Tool{}}
	if _, err = s.CompareAndSwap(ctx, keySnapshot.Revision, keys, map[string]*string{"collision": &managedToken}); !errors.Is(err, ErrSecret) {
		t.Fatal("managed/upstream separation", err)
	}
	delete(keys.Servers, "collision")
	delete(keys.Principals, "key_laptop")
	if _, err = s.CompareAndSwap(ctx, keySnapshot.Revision, keys, nil); err != nil {
		t.Fatal(err)
	}
	keySnapshot, err = s.ReadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, e := keySnapshot.Config.Authenticate("Bearer " + managedToken); e == nil {
		t.Fatal("managed revocation")
	}
	if _, e := keySnapshot.Config.Authenticate("Bearer " + os.Getenv("STORE_CLIENT_TOKEN")); e != nil {
		t.Fatal("legacy client lost")
	}
	if _, err = s.db.Exec("UPDATE " + s.table("registry_state") + " SET document='{bad}'"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadSnapshot(ctx); !errors.Is(err, ErrStore) {
		t.Fatal("corrupt snapshot", err)
	}
}
func TestFailClosed(t *testing.T) {
	ctx := context.Background()
	location := filepath.Join(t.TempDir(), "empty.db")
	s, err := Open("sqlite", location, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadSnapshot(ctx); !errors.Is(err, ErrStore) {
		t.Fatal("unmigrated", err)
	}
	s.Close()
	if _, err = s.ReadSnapshot(ctx); !errors.Is(err, ErrStore) {
		t.Fatal("closed", err)
	}
	if _, err = Open("unknown", location, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrStore) {
		t.Fatal(err)
	}
	if _, err = Open("sqlite", location, nil); !errors.Is(err, ErrSecret) {
		t.Fatal(err)
	}
}
func TestSQLDriverErrorsAreRedacted(t *testing.T) {
	d, err := sql.Open("pgx", "postgres://invalid:very-secret-password@localhost:1/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	s := &DB{db: d, kind: "postgres"}
	defer s.Close()
	_, err = s.ReadSnapshot(context.Background())
	if err != ErrStore {
		t.Fatal("driver error was not redacted")
	}
}

func TestSchemaVersionAndSQLitePermissions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "gateway.db")
	if err := Migrate(ctx, "sqlite", path); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("database permissions", info.Mode())
	}
	dir, _ := os.Stat(filepath.Dir(path))
	if dir.Mode().Perm() != 0700 {
		t.Fatal("directory permissions", dir.Mode())
	}
	s0, err := Open("sqlite", path, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := s0.(*DB)
	defer s.Close()
	if _, err = s.db.Exec("UPDATE schema_version SET version=99"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadSnapshot(ctx); err != ErrStore {
		t.Fatal("unknown schema read", err)
	}
	if _, err = s.CompareAndSwap(ctx, 0, fixture(t), nil); err != ErrStore {
		t.Fatal("unknown schema write", err)
	}
	if err = Migrate(ctx, "sqlite", path); err != ErrStore {
		t.Fatal("unknown schema migration", err)
	}
	link := filepath.Join(t.TempDir(), "link.db")
	if os.Symlink(path, link) != nil {
		t.Fatal("symlink")
	}
	if _, err = Open("sqlite", link, bytes.Repeat([]byte{1}, 32)); err != ErrStore {
		t.Fatal("symlink accepted", err)
	}
	if _, err = Open("sqlite", "file:"+path, bytes.Repeat([]byte{1}, 32)); err != ErrStore {
		t.Fatal("URI accepted", err)
	}
}
func TestCredentialIntegrityAndAtomicRollback(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db")
	if err := Migrate(ctx, "sqlite", path); err != nil {
		t.Fatal(err)
	}
	s0, _ := Open("sqlite", path, bytes.Repeat([]byte{1}, 32))
	s := s0.(*DB)
	defer s.Close()
	c := fixture(t)
	srv := c.Servers["demo"]
	srv.TokenRef = "demo"
	c.Servers["demo"] = srv
	token := "synthetic-upstream-token-12345"
	if _, err := s.CompareAndSwap(ctx, 0, c, map[string]*string{"demo": &token}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompareAndSwap(ctx, 1, c, map[string]*string{"demo": nil}); err != ErrSecret {
		t.Fatal("delete referenced token must rollback", err)
	}
	snap, err := s.ReadSnapshot(ctx)
	if err != nil || snap.Revision != 1 {
		t.Fatal("credential rollback", err)
	}
	unicodeToken := "synthetic-token-with\u00a0space"
	if _, err = s.CompareAndSwap(ctx, 1, c, map[string]*string{"demo": &unicodeToken}); err != ErrSecret {
		t.Fatal("unicode whitespace accepted", err)
	}
	var ciphertext []byte
	if err = s.db.QueryRow("SELECT ciphertext FROM upstream_secrets WHERE server_id='demo'").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	// Ciphertext cannot be moved to another server ID because ID is authenticated.
	if _, err = s.db.Exec("UPDATE upstream_secrets SET server_id='other'"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadSnapshot(ctx); err != ErrSecret {
		t.Fatal("unbound ciphertext", err)
	}
}
