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
	"testing"
)

func TestAgentACLMigrationParity(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { aclMigrationContract(t, "sqlite", filepath.Join(t.TempDir(), "acl.db")) })
	if dsn := os.Getenv("TEST_ACL_POSTGRES_DSN"); dsn != "" {
		t.Run("postgres", func(t *testing.T) { aclMigrationContract(t, "postgres", dsn) })
	}
}
func aclMigrationContract(t *testing.T, kind, path string) {
	ctx := context.Background()
	if e := Migrate(ctx, kind, path); e != nil {
		t.Fatal(e)
	}
	si, e := Open(kind, path, bytes.Repeat([]byte{8}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer si.Close()
	s := si.(*DB)
	c := fixture(t)
	server := c.Servers["demo"]
	server.TokenRef = "demo"
	c.Servers["demo"] = server
	token := "synthetic-preserved-upstream-token"
	client := "mgw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	c.Principals["managed"] = config.Principal{AccessPolicy: config.LegacyShared, ToolAllowlist: map[string][]string{}, TokenHash: config.TokenDigest(client), Key: &config.ClientKey{Name: "Synthetic", Prefix: client[:12], CreatedAt: "2026-10-24T00:00:00Z", Recoverable: true}}
	snap, e := s.CompareAndSwapClientKeys(ctx, 0, c, map[string]*string{"managed": &client})
	if e == nil {
		t.Fatal("missing upstream secret should fail")
	}
	snap, e = s.compareAndSwap(ctx, 0, c, map[string]*string{"demo": &token}, map[string]*string{"managed": &client})
	if e != nil {
		t.Fatal(e)
	}
	before := map[string][]byte{}
	for _, table := range []string{"upstream_secrets", "client_key_secrets"} {
		var b []byte
		if e := s.db.QueryRow("SELECT ciphertext FROM " + s.table(table)).Scan(&b); e != nil {
			t.Fatal(e)
		}
		before[table] = b
	}
	raw, _ := json.Marshal(c)
	var obj map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.Decode(&obj)
	delete(obj, "registry_version")
	for _, v := range obj["principals"].(map[string]any) {
		p := v.(map[string]any)
		delete(p, "access_policy")
		delete(p, "tool_allowlist")
	}
	legacy, _ := json.Marshal(obj)
	if _, e := s.db.Exec(s.query("UPDATE "+s.table("registry_state")+" SET document=? WHERE id=1"), string(legacy)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadSnapshot(ctx); !errors.Is(e, config.ErrRegistryVersion) {
		t.Fatal("runtime version error", e)
	}
	report, e := MigrateAgentACL(ctx, kind, path, ACLMigrationOptions{})
	if e != nil || !report.Changed || report.Committed || report.Revision != snap.Revision {
		t.Fatal("dry run", report, e)
	}
	if _, e = MigrateAgentACL(ctx, kind, path, ACLMigrationOptions{Apply: true, ExpectedRevision: 100}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale CAS", e)
	}
	report, e = migrateAgentACL(ctx, kind, path, ACLMigrationOptions{Apply: true, ExpectedRevision: snap.Revision}, func(tx *sql.Tx) error {
		if e := tx.Commit(); e != nil {
			return e
		}
		return errors.New("synthetic lost acknowledgement")
	})
	if !errors.Is(e, ErrACLCommitUnknown) {
		t.Fatal("unknown commit", e)
	}
	latest, e := s.ReadSnapshot(ctx)
	if e != nil || latest.Revision != snap.Revision+1 {
		t.Fatal("committed once", e)
	}
	again, e := MigrateAgentACL(ctx, kind, path, ACLMigrationOptions{Apply: true, ExpectedRevision: latest.Revision})
	if e != nil || again.Changed || again.Committed || again.Revision != latest.Revision {
		t.Fatal("idempotency", again, e)
	}
	for table, want := range before {
		var got []byte
		s.db.QueryRow("SELECT ciphertext FROM " + s.table(table)).Scan(&got)
		if !bytes.Equal(got, want) {
			t.Fatal("ciphertext changed", table)
		}
	}
	if got, e := s.RevealClientKey(ctx, latest.Revision, "managed"); e != nil || got != client {
		t.Fatal("managed key changed", e)
	}
}

func TestAgentACLMigrationDoesNotCreateSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "registry.db")
	if _, e := MigrateAgentACL(context.Background(), "sqlite", path, ACLMigrationOptions{}); e == nil {
		t.Fatal("missing registry accepted")
	}
	if _, e := os.Stat(filepath.Dir(path)); !os.IsNotExist(e) {
		t.Fatal("dry-run created a database directory")
	}
}
