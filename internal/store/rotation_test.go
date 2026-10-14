package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"mcp-gateway/internal/config"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func rotationFixture(t *testing.T, kind, location string) (*DB, string) {
	t.Helper()
	ctx := context.Background()
	if e := Migrate(ctx, kind, location); e != nil {
		t.Fatal(e)
	}
	raw, e := Open(kind, location, bytes.Repeat([]byte{71}, 32))
	if e != nil {
		t.Fatal(e)
	}
	s := raw.(*DB)
	c := fixture(t)
	for _, id := range []string{"demo", "second"} {
		srv := c.Servers["demo"]
		srv.Enabled = true
		srv.TokenRef = id
		if id == "second" {
			srv.AuthHeader = "X-API-Key"
		}
		c.Servers[id] = srv
	}
	a, b := "synthetic-rotation-upstream-first", "synthetic-rotation-upstream-second"
	if _, e = s.CompareAndSwap(ctx, 0, c, map[string]*string{"demo": &a, "second": &b}); e != nil {
		t.Fatal(e)
	}
	token := "mgw_" + strings.Repeat("r", 43)
	hashOnly := "mgw_" + strings.Repeat("h", 43)
	c.Principals["recoverable"] = config.Principal{TokenHash: config.TokenDigest(token), Key: &config.ClientKey{Name: "Synthetic", Prefix: token[:12], CreatedAt: "2026-10-14T12:00:00Z", Recoverable: true}}
	c.Principals["hashonly"] = config.Principal{TokenHash: config.TokenDigest(hashOnly), Key: &config.ClientKey{Name: "Hash only", Prefix: hashOnly[:12], CreatedAt: "2026-10-14T12:00:00Z"}}
	if _, e = s.CompareAndSwapClientKeys(ctx, 1, c, map[string]*string{"recoverable": &token}); e != nil {
		t.Fatal(e)
	}
	return s, token
}
func TestRotationPreservation(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { rotationContract(t, "sqlite", filepath.Join(t.TempDir(), "r.db")) })
	if dsn := os.Getenv("TEST_ROTATION_POSTGRES_DSN"); dsn != "" {
		u, e := url.Parse(dsn)
		if e != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || !strings.HasPrefix(u.Path, "/rotation_") {
			t.Fatal("rotation tests require an isolated loopback rotation_ database")
		}
		t.Run("postgres", func(t *testing.T) { rotationContract(t, "postgres", dsn) })
	}
}
func rotationContract(t *testing.T, kind, location string) {
	s, token := rotationFixture(t, kind, location)
	defer s.Close()
	ctx := context.Background()
	next := bytes.Repeat([]byte{72}, 32)
	var before string
	s.db.QueryRow("SELECT document FROM " + s.table("registry_state")).Scan(&before)
	opts := RotationOptions{ExpectedRevision: 2, NewKey: next, VerifyOnly: true}
	out, e := s.RotateSecretKey(ctx, opts)
	if e != nil || out.Committed || out.Upstreams != 2 || out.Clients != 1 {
		t.Fatal("verify-only", e, out)
	}
	opts.VerifyOnly = false
	if _, e = s.RotateSecretKey(ctx, RotationOptions{ExpectedRevision: 1, NewKey: next}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale", e)
	}
	// Late failures must roll back earlier rows and the password too.
	for _, stage := range []string{"row", "before_commit"} {
		_, e = s.rotateSecretKey(ctx, opts, func(at string) error {
			if at == stage {
				return ErrStore
			}
			return nil
		})
		if e == nil {
			t.Fatal("injected fault ignored")
		}
		snap, e := s.ReadSnapshot(ctx)
		if e != nil || snap.Revision != 2 {
			t.Fatal("partial rotation", e)
		}
		if got, e := s.RevealClientKey(ctx, 2, "recoverable"); e != nil || got != token {
			t.Fatal("lost client", e)
		}
	}
	var clientCipher []byte
	s.db.QueryRow("SELECT ciphertext FROM " + s.table("client_key_secrets")).Scan(&clientCipher)
	broken := append([]byte(nil), clientCipher...)
	broken[len(broken)-1] ^= 1
	s.db.Exec(s.query("UPDATE "+s.table("client_key_secrets")+" SET ciphertext=?"), broken)
	if _, e = s.RotateSecretKey(ctx, opts); !errors.Is(e, ErrSecret) {
		t.Fatal("corrupt late row", e)
	}
	s.db.Exec(s.query("UPDATE "+s.table("client_key_secrets")+" SET ciphertext=?"), clientCipher)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.RotateSecretKey(ctx, opts); errs <- e }()
	}
	wg.Wait()
	close(errs)
	wins, conflicts := 0, 0
	for e := range errs {
		if e == nil {
			wins++
		} else if errors.Is(e, ErrConflict) {
			conflicts++
		} else {
			t.Fatal("concurrent rotate", e)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("concurrent rotation was not CAS protected")
	}
	var after string
	s.db.QueryRow("SELECT document FROM " + s.table("registry_state")).Scan(&after)
	if before != after {
		t.Fatal("document rewritten")
	}
	if _, e = s.ReadSnapshot(ctx); !errors.Is(e, ErrSecret) {
		t.Fatal("old key works", e)
	}
	raw, e := Open(kind, location, next)
	if e != nil {
		t.Fatal(e)
	}
	n := raw.(*DB)
	defer n.Close()
	snap, e := n.ReadSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for id, want := range map[string]string{"demo": "synthetic-rotation-upstream-first", "second": "synthetic-rotation-upstream-second"} {
		got, e := ResolveSnapshotSecret(snap, id)
		if e != nil || got != want {
			t.Fatal("upstream changed", e)
		}
	}
	got, e := n.RevealClientKey(ctx, 3, "recoverable")
	if e != nil || got != token {
		t.Fatal("client changed", e)
	}
	for id, v := range map[string]string{"codex": os.Getenv("STORE_CLIENT_TOKEN"), "recoverable": token, "hashonly": "mgw_" + strings.Repeat("h", 43)} {
		if !snap.Config.Principals[id].MatchesToken(v) {
			t.Fatal("client auth changed")
		}
	}
	if _, e = n.RotateSecretKey(ctx, opts); !errors.Is(e, ErrConflict) {
		t.Fatal("retry admitted", e)
	}
	if kind == "postgres" {
		passwordContract(t, n, location)
	}
}
func passwordContract(t *testing.T, s *DB, location string) {
	ctx := context.Background()
	role := "rotation_runtime"
	old := strings.Repeat("o", 48)
	next := strings.Repeat("n", 48)
	// This contract runs only in the dedicated empty synthetic PostgreSQL database.
	s.db.Exec(`DROP ROLE IF EXISTS rotation_runtime`)
	if _, e := s.db.Exec(`CREATE ROLE rotation_runtime LOGIN PASSWORD '` + old + `'`); e != nil {
		t.Fatal("create test role failed")
	}
	defer s.db.Exec(`DROP ROLE rotation_runtime`)
	auth := func(password string) bool {
		u, _ := url.Parse(location)
		u.User = url.UserPassword(role, password)
		db, e := sql.Open("pgx", u.String())
		if e != nil {
			return false
		}
		defer db.Close()
		return db.PingContext(ctx) == nil
	}
	if !auth(old) {
		t.Fatal("baseline SCRAM failed")
	}
	var originalLogging string
	s.db.QueryRow("SHOW log_statement").Scan(&originalLogging)
	o := RotationOptions{ExpectedRevision: 3, NewKey: bytes.Repeat([]byte{73}, 32), Role: role, Password: []byte(next)}
	if _, e := s.rotateSecretKey(ctx, o, func(stage string) error {
		if stage == "password" {
			return ErrStore
		}
		return nil
	}); e == nil {
		t.Fatal("password fault")
	}
	if !auth(old) || auth(next) {
		t.Fatal("password rollback failed")
	}
	// Simulate an ambiguous response after a successful database commit.
	if _, e := s.rotateSecretKey(ctx, o, func(stage string) error {
		if stage == "after_commit" {
			return ErrStore
		}
		return nil
	}); !errors.Is(e, ErrRotationCommitUnknown) {
		t.Fatal("unknown commit")
	}
	if auth(old) || !auth(next) {
		t.Fatal("password not rotated")
	}
	var currentLogging string
	s.db.QueryRow("SHOW log_statement").Scan(&currentLogging)
	if originalLogging != currentLogging {
		t.Fatal("global logging altered")
	}
	raw, e := Open("postgres", location, o.NewKey)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	snap, e := raw.ReadSnapshot(ctx)
	if e != nil || snap.Revision != 4 {
		t.Fatal("ambiguous commit recovery failed", e)
	}
}
