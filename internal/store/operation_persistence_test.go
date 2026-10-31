package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mcp-gateway/internal/config"
)

func TestOperationPersistence(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { operationPersistence(t, "sqlite", filepath.Join(t.TempDir(), "registry.db")) })
	if dsn := os.Getenv("TEST_OPERATION_POSTGRES_DSN"); dsn != "" {
		t.Run("postgres", func(t *testing.T) { operationPersistence(t, "postgres", dsn) })
	}
}
func operationPersistence(t *testing.T, kind, location string) {
	t.Helper()
	ctx := context.Background()
	c := fixture(t)
	srv := c.Servers["demo"]
	srv.Tools["hello"] = config.Tool{Enabled: true, OperationKind: "read", OperationContractHash: strings.Repeat("a", 64)}
	srv.Tools["change"] = config.Tool{OperationKind: "write"}
	c.Servers["demo"] = srv
	if err := Migrate(ctx, kind, location); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{42}, 32)
	db, err := Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CompareAndSwap(ctx, 0, c, nil); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	snap, err := db.ReadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := snap.Config.Servers["demo"].Tools
	if got["hello"].OperationKind != "read" || got["hello"].OperationContractHash != strings.Repeat("a", 64) || got["change"].OperationKind != "write" {
		t.Fatal(got)
	}
}
