// Package store persists atomic registry snapshots and encrypted upstream credentials.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	_ "github.com/jackc/pgx/v5/stdlib"
	"mcp-gateway/internal/config"
	_ "modernc.org/sqlite"
)

var (
	ErrEmpty    = errors.New("registry is empty")
	ErrConflict = errors.New("registry revision conflict")
	ErrStore    = errors.New("registry storage unavailable or invalid")
	ErrSecret   = errors.New("upstream credential unavailable or invalid")
)

const maxDocument = 1 << 20

type Snapshot struct {
	Revision int64
	Config   *config.Config
	secrets  map[string]string
}
type Store interface {
	ReadSnapshot(context.Context) (Snapshot, error)
	CompareAndSwap(context.Context, int64, *config.Config, map[string]*string) (Snapshot, error)
	ResolveSecret(context.Context, string) (string, error)
	CompareAndSwapClientKeys(context.Context, int64, *config.Config, map[string]*string) (Snapshot, error)
	RevealClientKey(context.Context, int64, string) (string, error)
	DowngradeClientKeys(context.Context) error
	Close() error
}
type DB struct {
	db   *sql.DB
	kind string
	aead cipher.AEAD
}

// Open does not apply migrations or select another backend on failure.
func Open(kind, location string, key []byte) (Store, error) {
	if len(key) != 32 {
		return nil, ErrSecret
	}
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrSecret
	}
	ae, err := cipher.NewGCM(a)
	if err != nil {
		return nil, ErrSecret
	}
	d, err := openDB(kind, location)
	if err != nil {
		return nil, err
	}
	return &DB{db: d, kind: kind, aead: ae}, nil
}
func openDB(kind, location string) (*sql.DB, error) {
	if location == "" {
		return nil, ErrStore
	}
	driver := "sqlite"
	if kind == "sqlite" {
		if err := prepareSQLite(location); err != nil {
			return nil, err
		}
	}
	if kind == "postgres" {
		driver = "pgx"
	} else if kind != "sqlite" {
		return nil, ErrStore
	}
	d, err := sql.Open(driver, location)
	if err != nil {
		return nil, ErrStore
	}
	if kind == "sqlite" {
		d.SetMaxOpenConns(1)
		for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON"} {
			if _, err = d.Exec(q); err != nil {
				d.Close()
				return nil, ErrStore
			}
		}
	}
	return d, nil
}

// SQLite paths are local regular files; URI DSNs cannot bypass file checks.
func prepareSQLite(path string) error {
	if path == ":memory:" {
		return nil
	}
	if strings.Contains(path, "?") || strings.HasPrefix(path, "file:") {
		return ErrStore
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ErrStore
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		if f.Close() != nil {
			return ErrStore
		}
	} else if !os.IsExist(err) {
		return ErrStore
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return ErrStore
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return ErrStore
	}
	return nil
}
func (s *DB) checkVersion(ctx context.Context, tx *sql.Tx) error {
	var version int
	if tx.QueryRowContext(ctx, "SELECT version FROM "+s.table("schema_version")+" WHERE id=1").Scan(&version) != nil || version != 2 {
		return ErrStore
	}
	return nil
}
func (s *DB) Close() error {
	if s.db.Close() != nil {
		return ErrStore
	}
	return nil
}
func (s *DB) table(name string) string {
	if s.kind == "postgres" {
		return "mcp_gateway." + name
	}
	return name
}
func (s *DB) query(q string) string {
	if s.kind != "postgres" {
		return q
	}
	n := 0
	return replaceParams(q, &n)
}
func replaceParams(q string, n *int) string {
	var b strings.Builder
	for _, r := range q {
		if r == '?' {
			*n++
			b.WriteString("$")
			b.WriteString(strconv.Itoa(*n))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Migrate is an explicit administrative operation, separate from runtime Open.
func Migrate(ctx context.Context, kind, location string) error {
	d, err := openDB(kind, location)
	if err != nil {
		return err
	}
	defer d.Close()
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return ErrStore
	}
	defer tx.Rollback()
	prefix := ""
	blob := "BLOB"
	if kind == "postgres" {
		prefix = "mcp_gateway."
		blob = "BYTEA"
		if _, err = tx.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS mcp_gateway"); err != nil {
			return ErrStore
		}
	}
	queries := []string{
		"CREATE TABLE IF NOT EXISTS " + prefix + "schema_version (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)",
		"CREATE TABLE IF NOT EXISTS " + prefix + "registry_state (id INTEGER PRIMARY KEY CHECK(id=1), revision BIGINT NOT NULL CHECK(revision>0), document TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS " + prefix + "upstream_secrets (server_id TEXT PRIMARY KEY, ciphertext " + blob + " NOT NULL)",
		"INSERT INTO " + prefix + "schema_version (id,version) VALUES(1,1) ON CONFLICT(id) DO NOTHING",
	}
	for _, q := range queries {
		if _, err = tx.ExecContext(ctx, q); err != nil {
			return ErrStore
		}
	}
	var v int
	if tx.QueryRowContext(ctx, "SELECT version FROM "+prefix+"schema_version WHERE id=1").Scan(&v) != nil || (v != 1 && v != 2) {
		return ErrStore
	}
	if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+prefix+"client_key_secrets (principal_id TEXT PRIMARY KEY, ciphertext "+blob+" NOT NULL CHECK(length(ciphertext)=75))"); err != nil {
		return ErrStore
	}
	if _, err = tx.ExecContext(ctx, "UPDATE "+prefix+"schema_version SET version=2 WHERE id=1"); err != nil {
		return ErrStore
	}
	if tx.Commit() != nil {
		return ErrStore
	}
	return nil
}
func (s *DB) ReadSnapshot(ctx context.Context) (Snapshot, error) {
	opts := &sql.TxOptions{ReadOnly: true}
	if s.kind == "postgres" {
		opts.Isolation = sql.LevelRepeatableRead
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return Snapshot{}, ErrStore
	}
	defer tx.Rollback()
	out, err := s.read(ctx, tx)
	if err != nil {
		return Snapshot{}, err
	}
	if tx.Commit() != nil {
		return Snapshot{}, ErrStore
	}
	return out, nil
}
func (s *DB) read(ctx context.Context, tx *sql.Tx) (Snapshot, error) {
	if err := s.checkVersion(ctx, tx); err != nil {
		return Snapshot{}, err
	}
	var rev, size int64
	length := "length(CAST(document AS BLOB))"
	if s.kind == "postgres" {
		length = "octet_length(document)"
	}
	err := tx.QueryRowContext(ctx, "SELECT revision,"+length+" FROM "+s.table("registry_state")+" WHERE id=1").Scan(&rev, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrEmpty
	}
	if err != nil || rev < 1 || size > maxDocument || size < 0 {
		return Snapshot{}, ErrStore
	}
	var raw string
	if tx.QueryRowContext(ctx, "SELECT document FROM "+s.table("registry_state")+" WHERE id=1").Scan(&raw) != nil {
		return Snapshot{}, ErrStore
	}
	c, err := config.Decode([]byte(raw))
	if err != nil {
		if errors.Is(err, config.ErrRegistryVersion) {
			return Snapshot{}, err
		}
		return Snapshot{}, ErrStore
	}
	secrets, err := s.readSecrets(ctx, tx)
	if err != nil {
		return Snapshot{}, err
	}
	if validateSecrets(c, secrets) != nil {
		return Snapshot{}, ErrSecret
	}
	if err := s.validateClientKeys(ctx, tx, c); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Revision: rev, Config: c, secrets: secrets}, nil
}
func (s *DB) readSecrets(ctx context.Context, tx *sql.Tx) (map[string]string, error) {
	var oversized int
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM "+s.table("upstream_secrets")+" WHERE length(server_id)>128 OR length(ciphertext)>16412").Scan(&oversized) != nil {
		return nil, ErrStore
	}
	if oversized > 0 {
		return nil, ErrSecret
	}
	rows, err := tx.QueryContext(ctx, "SELECT server_id,ciphertext FROM "+s.table("upstream_secrets")+" LIMIT 4097")
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id string
		var b []byte
		if rows.Scan(&id, &b) != nil || len(id) > 128 || len(b) > (16<<10)+s.aead.NonceSize()+s.aead.Overhead() || len(out) >= 4096 {
			return nil, ErrStore
		}
		if len(b) < s.aead.NonceSize()+s.aead.Overhead() {
			return nil, ErrSecret
		}
		p, e := s.aead.Open(nil, b[:s.aead.NonceSize()], b[s.aead.NonceSize():], []byte(id))
		if e != nil {
			return nil, ErrSecret
		}
		out[id] = string(p)
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return out, nil
}
func validateSecrets(c *config.Config, secrets map[string]string) error {
	used := map[string]bool{}
	for _, p := range c.Principals {
		if p.TokenHash != "" {
			used[p.TokenHash] = true
		} else {
			used[config.TokenDigest(os.Getenv(p.TokenEnv))] = true
		}
	}
	for _, srv := range c.Servers {
		if srv.TokenEnv != "" {
			used[config.TokenDigest(os.Getenv(srv.TokenEnv))] = true
		}
	}
	for id, srv := range c.Servers {
		if srv.TokenRef == "" {
			continue
		}
		token, ok := secrets[id]
		if srv.TokenRef != id || !ok || !config.ValidCredential(srv.AuthHeader, token) || used[config.TokenDigest(token)] {
			return ErrSecret
		}
		used[config.TokenDigest(token)] = true
	}
	return nil
}
func (s *DB) CompareAndSwap(ctx context.Context, expected int64, c *config.Config, changes map[string]*string) (Snapshot, error) {
	return s.compareAndSwap(ctx, expected, c, changes, nil)
}
func (s *DB) CompareAndSwapClientKeys(ctx context.Context, expected int64, c *config.Config, changes map[string]*string) (Snapshot, error) {
	return s.compareAndSwap(ctx, expected, c, nil, changes)
}
func (s *DB) compareAndSwap(ctx context.Context, expected int64, c *config.Config, changes, clientChanges map[string]*string) (Snapshot, error) {
	if expected < 0 || c == nil || c.Validate() != nil {
		return Snapshot{}, ErrStore
	}
	b, err := json.Marshal(c)
	if err != nil || len(b) > maxDocument {
		return Snapshot{}, ErrStore
	}
	// Detach from caller-owned maps and preserve JSON numbers consistently.
	c, err = config.Decode(b)
	if err != nil {
		return Snapshot{}, ErrStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, ErrStore
	}
	defer tx.Rollback()
	if err := s.checkVersion(ctx, tx); err != nil {
		return Snapshot{}, err
	}
	// Claim the revision before touching credentials; concurrent writers cannot overwrite each other.
	var result sql.Result
	if expected == 0 {
		result, err = tx.ExecContext(ctx, s.query("INSERT INTO "+s.table("registry_state")+" (id,revision,document) VALUES(1,1,?) ON CONFLICT(id) DO NOTHING"), string(b))
	} else {
		result, err = tx.ExecContext(ctx, s.query("UPDATE "+s.table("registry_state")+" SET revision=revision+1,document=? WHERE id=1 AND revision=?"), string(b), expected)
	}
	if err != nil {
		return Snapshot{}, ErrStore
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Snapshot{}, ErrStore
	}
	if count != 1 {
		return Snapshot{}, ErrConflict
	}
	secrets, err := s.readSecrets(ctx, tx)
	if err != nil {
		return Snapshot{}, err
	}
	for id, token := range changes {
		if token == nil {
			delete(secrets, id)
			if _, err = tx.ExecContext(ctx, s.query("DELETE FROM "+s.table("upstream_secrets")+" WHERE server_id=?"), id); err != nil {
				return Snapshot{}, ErrStore
			}
			continue
		}
		srv, exists := c.Servers[id]
		if !exists || srv.TokenRef != id || !config.ValidCredential(srv.AuthHeader, *token) {
			return Snapshot{}, ErrSecret
		}
		nonce := make([]byte, s.aead.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return Snapshot{}, ErrSecret
		}
		encrypted := s.aead.Seal(nonce, nonce, []byte(*token), []byte(id))
		if _, err = tx.ExecContext(ctx, s.query("INSERT INTO "+s.table("upstream_secrets")+" (server_id,ciphertext) VALUES(?,?) ON CONFLICT(server_id) DO UPDATE SET ciphertext=excluded.ciphertext"), id, encrypted); err != nil {
			return Snapshot{}, ErrStore
		}
		secrets[id] = *token
	}
	// Delete orphaned credentials within the same transaction.
	for id := range secrets {
		srv, ok := c.Servers[id]
		if !ok || srv.TokenRef != id {
			delete(secrets, id)
			if _, err = tx.ExecContext(ctx, s.query("DELETE FROM "+s.table("upstream_secrets")+" WHERE server_id=?"), id); err != nil {
				return Snapshot{}, ErrStore
			}
		}
	}
	if validateSecrets(c, secrets) != nil {
		return Snapshot{}, ErrSecret
	}
	if err := s.writeClientKeys(ctx, tx, c, clientChanges); err != nil {
		return Snapshot{}, err
	}
	if tx.Commit() != nil {
		return Snapshot{}, ErrStore
	}
	return Snapshot{Revision: expected + 1, Config: c, secrets: secrets}, nil
}
func ResolveSnapshotSecret(snapshot Snapshot, id string) (string, error) {
	if snapshot.Config == nil {
		return "", ErrSecret
	}
	srv, ok := snapshot.Config.Servers[id]
	if !ok || srv.TokenRef != id {
		return "", ErrSecret
	}
	value, ok := snapshot.secrets[id]
	if !ok {
		return "", ErrSecret
	}
	return value, nil
}
func (s *DB) ResolveSecret(ctx context.Context, id string) (string, error) {
	snap, err := s.ReadSnapshot(ctx)
	if err != nil {
		return "", err
	}
	return ResolveSnapshotSecret(snap, id)
}
