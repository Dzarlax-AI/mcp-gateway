package store

import (
	"bytes"
	"context"
	"errors"
	"mcp-gateway/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedUpstreamCredentials(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { sharedCredentials(t, "sqlite", filepath.Join(t.TempDir(), "shared.db")) })
	if dsn := os.Getenv("TEST_SHARED_CREDENTIALS_POSTGRES_DSN"); dsn != "" {
		t.Run("postgres", func(t *testing.T) { sharedCredentials(t, "postgres", dsn) })
	}
}

func sharedCredentials(t *testing.T, kind, location string) {
	ctx := context.Background()
	c := fixture(t)
	token := "synthetic-shared-upstream-token"
	t.Setenv("STORE_SHARED_UPSTREAM_TOKEN", token)
	c.Principals["hashed"] = config.Principal{TokenHash: config.TokenDigest("mgw_abcdefghABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"), AccessPolicy: config.Restricted, ToolAllowlist: map[string][]string{}, Key: &config.ClientKey{Name: "Hashed", Prefix: "mgw_abcdefgh", CreatedAt: "2026-10-31T12:00:00Z"}}
	changes := map[string]*string{}
	for _, id := range []string{"bearer_one", "bearer_two", "header_one", "header_two", "env_bearer", "env_header"} {
		srv := config.Server{URL: "http://127.0.0.1:9876/mcp", Tools: map[string]config.Tool{}}
		if id == "header_one" || id == "header_two" || id == "env_header" {
			srv.AuthHeader = "X-Api-Key"
		}
		if id == "env_bearer" || id == "env_header" {
			srv.TokenEnv = "STORE_SHARED_UPSTREAM_TOKEN"
		} else {
			srv.TokenRef = id
			changes[id] = &token
		}
		c.Servers[id] = srv
	}
	key := bytes.Repeat([]byte{42}, 32)
	if err := Migrate(ctx, kind, location); err != nil {
		t.Fatal(err)
	}
	si, err := Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	defer si.Close()
	snap, err := si.CompareAndSwap(ctx, 0, c, changes)
	if err != nil {
		t.Fatal("shared credential save", err)
	}
	reopened, err := Open(kind, location, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snap, err = reopened.ReadSnapshot(ctx)
	if err != nil {
		t.Fatal("shared credential reopen", err)
	}
	for id := range changes {
		if got, err := ResolveSnapshotSecret(snap, id); err != nil || got != token {
			t.Fatal("shared credential read", id, err)
		}
	}
	replacement := "synthetic-independent-replacement-token"
	snap, err = si.CompareAndSwap(ctx, snap.Revision, snap.Config, map[string]*string{"bearer_one": &replacement})
	if err != nil {
		t.Fatal("independent replacement", err)
	}
	for id := range changes {
		want := token
		if id == "bearer_one" {
			want = replacement
		}
		if got, err := ResolveSnapshotSecret(snap, id); err != nil || got != want {
			t.Fatal("replacement changed another server", id, err)
		}
	}
	for _, bad := range []string{os.Getenv("STORE_CLIENT_TOKEN"), "mgw_abcdefghABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", "bad\r\ncredential"} {
		if _, err := si.CompareAndSwap(ctx, snap.Revision, snap.Config, map[string]*string{"bearer_one": &bad}); !errors.Is(err, ErrSecret) {
			t.Fatal("invalid credential accepted", err)
		}
		after, err := si.ReadSnapshot(ctx)
		if err != nil || after.Revision != snap.Revision {
			t.Fatal("rejected save changed revision", err)
		}
		if got, err := ResolveSnapshotSecret(after, "bearer_one"); err != nil || got != replacement {
			t.Fatal("rejected save changed secret", err)
		}
	}
}
