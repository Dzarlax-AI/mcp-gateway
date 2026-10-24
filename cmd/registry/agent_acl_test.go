package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"mcp-gateway/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineFileACLMigration(t *testing.T) {
	t.Setenv("FILE_ACL_CLIENT", "synthetic-file-acl-client-token")
	path := filepath.Join(t.TempDir(), "registry.json")
	raw := []byte(`{"servers":{},"principals":{"p":{"token_env":"FILE_ACL_CLIENT","grants":{}}}}`)
	os.WriteFile(path, raw, 0600)
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	report, e := migrateACLFile(path, "", false, false)
	if e != nil || !report.Changed || report.Committed {
		t.Fatal("dry-run", e)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, raw) {
		t.Fatal("dry-run writes")
	}
	if _, e = migrateACLFile(path, digest, true, false); e == nil {
		t.Fatal("online apply")
	}
	if _, e = migrateACLFile(path, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, true); e == nil {
		t.Fatal("stale digest")
	}
	report, e = migrateACLFile(path, digest, true, true)
	if e != nil || !report.Committed {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if _, e = config.Load(path); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("file permissions")
	}
	report, e = migrateACLFile(path, "", false, false)
	if e != nil || report.Changed {
		t.Fatal("idempotent dry run")
	}
	link := path + ".link"
	os.Symlink(path, link)
	if _, e = migrateACLFile(link, "", false, false); e == nil {
		t.Fatal("symlink accepted")
	}
	if !bytes.Contains(b, []byte(`"legacy_shared"`)) {
		t.Fatal("mode")
	}
}
