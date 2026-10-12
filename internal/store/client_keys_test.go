package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mcp-gateway/internal/config"
)

func TestRecoverableKeyContract(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { recoverableContract(t, "sqlite", filepath.Join(t.TempDir(), "keys.db")) })
	if dsn := os.Getenv("TEST_CLIENT_KEYS_POSTGRES_DSN"); dsn != "" {
		t.Run("postgres", func(t *testing.T) { recoverableContract(t, "postgres", dsn) })
	}
}
func recoverableContract(t *testing.T, kind, location string) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{8}, 32)
	if err := Migrate(ctx, kind, location); err != nil {
		t.Fatal(err)
	}
	raw, err := Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	s := raw.(*DB)
	defer func() { s.Close() }()
	c := fixture(t)
	upstreamToken := "synthetic-preserved-upstream-token"
	server := c.Servers["demo"]
	server.TokenRef = "demo"
	server.Enabled = true
	c.Servers["demo"] = server
	if _, err = s.CompareAndSwap(ctx, 0, c, map[string]*string{"demo": &upstreamToken}); err != nil {
		t.Fatal(err)
	}
	var upstreamCipher []byte
	s.db.QueryRow("SELECT ciphertext FROM " + s.table("upstream_secrets")).Scan(&upstreamCipher)
	// Construct the preceding schema, preserving live registry and ciphertext.
	if _, err = s.db.Exec("DROP TABLE " + s.table("client_key_secrets")); err != nil {
		t.Fatal(err)
	}
	s.db.Exec("UPDATE " + s.table("schema_version") + " SET version=1")
	if _, err = s.ReadSnapshot(ctx); err == nil {
		t.Fatal("runtime migrated automatically")
	}
	if err = Migrate(ctx, kind, location); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, kind, location); err != nil {
		t.Fatal("repeat migration", err)
	}
	snap, err := s.ReadSnapshot(ctx)
	if err != nil || snap.Revision != 1 {
		t.Fatal("migration altered registry", err)
	}
	var afterCipher []byte
	s.db.QueryRow("SELECT ciphertext FROM " + s.table("upstream_secrets")).Scan(&afterCipher)
	if !bytes.Equal(upstreamCipher, afterCipher) {
		t.Fatal("migration altered upstream")
	}
	token := "mgw_" + strings.Repeat("a", 43)
	c.Principals["key_new"] = config.Principal{TokenHash: config.TokenDigest(token), Key: &config.ClientKey{Name: "Laptop", Prefix: token[:12], CreatedAt: "2026-10-12T12:00:00Z", Recoverable: true}}
	if _, err = s.CompareAndSwap(ctx, 1, c, nil); !errors.Is(err, ErrSecret) {
		t.Fatal("missing ciphertext admitted", err)
	}
	wrong := token + "x"
	if _, err = s.CompareAndSwapClientKeys(ctx, 1, c, map[string]*string{"key_new": &wrong}); !errors.Is(err, ErrSecret) {
		t.Fatal("invalid secret committed")
	}
	snap, err = s.CompareAndSwapClientKeys(ctx, 1, c, map[string]*string{"key_new": &token})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CompareAndSwapClientKeys(ctx, 1, c, map[string]*string{"key_new": &token}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale write")
	}
	var ciphertext []byte
	s.db.QueryRow("SELECT ciphertext FROM " + s.table("client_key_secrets")).Scan(&ciphertext)
	if bytes.Contains(ciphertext, []byte(token)) {
		t.Fatal("plaintext stored")
	}
	encoded, _ := json.Marshal(snap)
	if bytes.Contains(encoded, []byte(token)) {
		t.Fatal("snapshot plaintext")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err = Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	s = raw.(*DB)
	for i := 0; i < 2; i++ {
		got, e := s.RevealClientKey(ctx, 2, "key_new")
		if e != nil || got != token {
			t.Fatal("repeat reveal", e)
		}
	}
	if _, err = s.RevealClientKey(ctx, 1, "key_new"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale reveal")
	}
	if _, err = s.RevealClientKey(ctx, 2, "codex"); err == nil {
		t.Fatal("env reveal")
	}
	other, err := Open(kind, location, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.RevealClientKey(ctx, 2, "key_new"); err == nil {
		t.Fatal("wrong encryption key")
	}
	other.Close()
	// Same ciphertext moved to another key fails its associated-data check.
	c.Principals["key_second"] = config.Principal{TokenHash: config.TokenDigest("mgw_" + strings.Repeat("b", 43)), Key: &config.ClientKey{Name: "Phone", Prefix: "mgw_bbbbbbbb", CreatedAt: "2026-10-12T12:00:00Z", Recoverable: true}}
	secondToken := "mgw_" + strings.Repeat("b", 43)
	if _, err = s.CompareAndSwapClientKeys(ctx, 2, c, map[string]*string{"key_second": &secondToken}); err != nil {
		t.Fatal(err)
	}
	s.db.ExecContext(ctx, s.query("UPDATE "+s.table("client_key_secrets")+" SET ciphertext=? WHERE principal_id=?"), ciphertext, "key_second")
	if _, err = s.RevealClientKey(ctx, 3, "key_second"); err == nil {
		t.Fatal("ciphertext substitution")
	}
	if _, err = s.CompareAndSwapClientKeys(ctx, 3, c, map[string]*string{"key_second": &secondToken}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CompareAndSwap(ctx, 4, c, nil); err != nil {
		t.Fatal("ordinary CAS", err)
	}
	var retained []byte
	s.db.QueryRowContext(ctx, s.query("SELECT ciphertext FROM "+s.table("client_key_secrets")+" WHERE principal_id=?"), "key_new").Scan(&retained)
	if !bytes.Equal(retained, ciphertext) {
		t.Fatal("ordinary CAS rewrote secret")
	}
	broken := append([]byte(nil), ciphertext...)
	broken[len(broken)-1] ^= 1
	s.db.ExecContext(ctx, s.query("UPDATE "+s.table("client_key_secrets")+" SET ciphertext=? WHERE principal_id=?"), broken, "key_new")
	if _, err = s.RevealClientKey(ctx, 5, "key_new"); err == nil {
		t.Fatal("corruption")
	}
	if _, err = s.CompareAndSwapClientKeys(ctx, 5, c, map[string]*string{"key_new": &token}); err != nil {
		t.Fatal(err)
	}
	// Ciphertext with the upstream associated-data domain cannot be revealed as a client key.
	nonce := make([]byte, s.aead.NonceSize())
	upstreamDomain := s.aead.Seal(nonce, nonce, []byte(token), []byte("key_new"))
	s.db.ExecContext(ctx, s.query("UPDATE "+s.table("client_key_secrets")+" SET ciphertext=? WHERE principal_id=?"), upstreamDomain, "key_new")
	if _, err = s.RevealClientKey(ctx, 6, "key_new"); err == nil {
		t.Fatal("upstream domain substitution")
	}
	s.db.ExecContext(ctx, s.query("UPDATE "+s.table("client_key_secrets")+" SET ciphertext=? WHERE principal_id=?"), ciphertext, "key_new")
	var originalDocument string
	s.db.QueryRow("SELECT document FROM " + s.table("registry_state")).Scan(&originalDocument)
	changed := strings.Replace(originalDocument, token[:12], "mgw_cccccccc", 1)
	s.db.ExecContext(ctx, s.query("UPDATE "+s.table("registry_state")+" SET document=? WHERE id=1"), changed)
	if _, err = s.RevealClientKey(ctx, 6, "key_new"); err == nil {
		t.Fatal("prefix mismatch")
	}
	s.db.ExecContext(ctx, s.query("UPDATE "+s.table("registry_state")+" SET document=? WHERE id=1"), originalDocument)
	changed = strings.Replace(originalDocument, config.TokenDigest(token), config.TokenDigest("mgw_"+strings.Repeat("c", 43)), 1)
	s.db.ExecContext(ctx, s.query("UPDATE "+s.table("registry_state")+" SET document=? WHERE id=1"), changed)
	if _, err = s.RevealClientKey(ctx, 6, "key_new"); err == nil {
		t.Fatal("digest mismatch")
	}
	s.db.ExecContext(ctx, s.query("UPDATE "+s.table("registry_state")+" SET document=? WHERE id=1"), originalDocument)
	// Authentication stays hash based; downgrade discards only recoverability.
	if err = s.DowngradeClientKeys(ctx); err != nil {
		t.Fatal("downgrade", err)
	}
	var document string
	var revision int64
	if err = s.db.QueryRow("SELECT document,revision FROM "+s.table("registry_state")).Scan(&document, &revision); err != nil {
		t.Fatal(err)
	}
	decoded, err := config.Decode([]byte(document))
	if err != nil || strings.Contains(document, "recoverable") || revision != 7 {
		t.Fatal("downgrade state", err)
	}
	if _, err = decoded.Authenticate("Bearer " + token); err != nil {
		t.Fatal("downgrade revoked key")
	}
	if !decoded.Servers["demo"].Enabled {
		t.Fatal("switch lost")
	}
	if err = Migrate(ctx, kind, location); err != nil {
		t.Fatal(err)
	}
	snap, err = s.ReadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevealClientKey(ctx, snap.Revision, "key_new"); err == nil {
		t.Fatal("hash-only revealed")
	}
	delete(decoded.Principals, "key_new")
	if _, err = s.CompareAndSwapClientKeys(ctx, snap.Revision, decoded, nil); err != nil {
		t.Fatal(err)
	}
}
