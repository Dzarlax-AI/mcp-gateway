package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"mcp-gateway/internal/config"
	"regexp"
)

var clientTokenPattern = regexp.MustCompile(`^mgw_[A-Za-z0-9_-]{43}$`)

func matchesClientKey(p config.Principal, token string) bool {
	return p.Key != nil && p.Key.Recoverable && clientTokenPattern.MatchString(token) && p.MatchesToken(token) && p.Key.Prefix == token[:12]
}

// Client plaintext is never part of an admitted MCP snapshot.
func (s *DB) clientKeyIDs(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT principal_id,length(ciphertext) FROM "+s.table("client_key_secrets")+" LIMIT 4097")
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()
	ids := map[string]bool{}
	for rows.Next() {
		var id string
		var size int
		if rows.Scan(&id, &size) != nil || !config.ValidIdentifier(id) || size != 75 || len(ids) >= 4096 {
			return nil, ErrSecret
		}
		ids[id] = true
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return ids, nil
}
func (s *DB) validateClientKeys(ctx context.Context, tx *sql.Tx, c *config.Config) error {
	ids, err := s.clientKeyIDs(ctx, tx)
	if err != nil {
		return err
	}
	for id, p := range c.Principals {
		if p.Key != nil && p.Key.Recoverable {
			if !ids[id] {
				return ErrSecret
			}
			delete(ids, id)
		}
	}
	if len(ids) != 0 {
		return ErrSecret
	}
	return nil
}
func (s *DB) writeClientKeys(ctx context.Context, tx *sql.Tx, c *config.Config, changes map[string]*string) error {
	for id, token := range changes {
		if token == nil {
			if _, err := tx.ExecContext(ctx, s.query("DELETE FROM "+s.table("client_key_secrets")+" WHERE principal_id=?"), id); err != nil {
				return ErrStore
			}
			continue
		}
		p, ok := c.Principals[id]
		if !ok || !matchesClientKey(p, *token) {
			return ErrSecret
		}
		nonce := make([]byte, s.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return ErrSecret
		}
		encrypted := s.aead.Seal(nonce, nonce, []byte(*token), []byte("client-key:"+id))
		if _, err := tx.ExecContext(ctx, s.query("INSERT INTO "+s.table("client_key_secrets")+" (principal_id,ciphertext) VALUES(?,?) ON CONFLICT(principal_id) DO UPDATE SET ciphertext=excluded.ciphertext"), id, encrypted); err != nil {
			return ErrStore
		}
	}
	ids, err := s.clientKeyIDs(ctx, tx)
	if err != nil {
		return err
	}
	for id := range ids {
		p, ok := c.Principals[id]
		if !ok || p.Key == nil || !p.Key.Recoverable {
			if _, err := tx.ExecContext(ctx, s.query("DELETE FROM "+s.table("client_key_secrets")+" WHERE principal_id=?"), id); err != nil {
				return ErrStore
			}
		}
	}
	return s.validateClientKeys(ctx, tx, c)
}
func (s *DB) RevealClientKey(ctx context.Context, expected int64, id string) (string, error) {
	if !config.ValidIdentifier(id) {
		return "", ErrSecret
	}
	opts := &sql.TxOptions{ReadOnly: true}
	if s.kind == "postgres" {
		opts.Isolation = sql.LevelRepeatableRead
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return "", ErrStore
	}
	defer tx.Rollback()
	snap, err := s.read(ctx, tx)
	if err != nil {
		return "", err
	}
	if snap.Revision != expected {
		return "", ErrConflict
	}
	p, ok := snap.Config.Principals[id]
	if !ok || p.Key == nil || !p.Key.Recoverable {
		return "", ErrSecret
	}
	var encrypted []byte
	if tx.QueryRowContext(ctx, s.query("SELECT ciphertext FROM "+s.table("client_key_secrets")+" WHERE principal_id=?"), id).Scan(&encrypted) != nil || len(encrypted) != 75 {
		return "", ErrSecret
	}
	plaintext, err := s.aead.Open(nil, encrypted[:s.aead.NonceSize()], encrypted[s.aead.NonceSize():], []byte("client-key:"+id))
	if err != nil || !matchesClientKey(p, string(plaintext)) {
		return "", ErrSecret
	}
	token := string(plaintext)
	if tx.Commit() != nil {
		return "", ErrStore
	}
	return token, nil
}

// DowngradeClientKeys preserves authentication hashes and current server state.
// Only explicit administrative use may discard recoverable encrypted values.
func (s *DB) DowngradeClientKeys(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStore
	}
	defer tx.Rollback()
	if s.kind == "postgres" {
		var id int
		if tx.QueryRowContext(ctx, "SELECT id FROM "+s.table("registry_state")+" WHERE id=1 FOR UPDATE").Scan(&id) != nil {
			return ErrStore
		}
	}
	snap, err := s.read(ctx, tx)
	if err != nil {
		return err
	}
	for _, p := range snap.Config.Principals {
		if p.Key != nil {
			p.Key.Recoverable = false
		}
	}
	b, err := json.Marshal(snap.Config)
	if err != nil {
		return ErrStore
	}
	result, err := tx.ExecContext(ctx, s.query("UPDATE "+s.table("registry_state")+" SET document=?,revision=revision+1 WHERE id=1 AND revision=?"), string(b), snap.Revision)
	if err != nil {
		return ErrStore
	}
	n, err := result.RowsAffected()
	if err != nil {
		return ErrStore
	}
	if n != 1 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "DROP TABLE "+s.table("client_key_secrets")); err != nil {
		return ErrStore
	}
	if _, err = tx.ExecContext(ctx, "UPDATE "+s.table("schema_version")+" SET version=1 WHERE id=1"); err != nil {
		return ErrStore
	}
	if tx.Commit() != nil {
		return ErrStore
	}
	return nil
}
