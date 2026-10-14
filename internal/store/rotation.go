package store

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
)

var ErrRotationCommitUnknown = errors.New("rotation commit outcome unknown; inspect before recovery")

type RotationOptions struct {
	ExpectedRevision int64
	NewKey           []byte
	VerifyOnly       bool
	// Password rotation requires a privileged maintenance connection, not the runtime role.
	Role     string
	Password []byte
}
type RotationReport struct {
	Revision        int64 `json:"revision"`
	Upstreams       int   `json:"upstreams"`
	Clients         int   `json:"clients"`
	Committed       bool  `json:"committed"`
	PasswordRotated bool  `json:"password_rotated"`
}
type rotationRow struct {
	table, column, id string
	ciphertext        []byte
}

// RotateSecretKey is an explicit offline operator operation. Runtime AEAD is never changed
// in place: callers must close this store and reopen with the new key after commit.
func (s *DB) RotateSecretKey(ctx context.Context, o RotationOptions) (RotationReport, error) {
	return s.rotateSecretKey(ctx, o, nil)
}
func (s *DB) rotateSecretKey(ctx context.Context, o RotationOptions, fault func(string) error) (out RotationReport, err error) {
	if o.ExpectedRevision < 1 || len(o.NewKey) != 32 {
		return out, ErrSecret
	}
	if o.ExpectedRevision == int64(^uint64(0)>>1) {
		return out, ErrConflict
	}
	block, e := aes.NewCipher(o.NewKey)
	if e != nil {
		return out, ErrSecret
	}
	next, e := cipher.NewGCM(block)
	if e != nil {
		return out, ErrSecret
	}
	if (o.Role == "") != (len(o.Password) == 0) || (o.Role != "" && (s.kind != "postgres" || !regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`).MatchString(o.Role))) {
		return out, ErrSecret
	}
	if len(o.Password) > 0 {
		if len(o.Password) < 32 || len(o.Password) > 256 {
			return out, ErrSecret
		}
		for _, b := range o.Password {
			if b < 33 || b > 126 {
				return out, ErrSecret
			}
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, ErrStore
	}
	defer tx.Rollback()
	if s.kind == "postgres" {
		// Lock ordering matches ordinary CAS writers. Offline operation also excludes direct DML.
		var rev int64
		if tx.QueryRowContext(ctx, "SELECT revision FROM "+s.table("registry_state")+" WHERE id=1 FOR UPDATE").Scan(&rev) != nil {
			return out, ErrStore
		}
		if rev != o.ExpectedRevision {
			return out, ErrConflict
		}
		if _, e = tx.ExecContext(ctx, "LOCK TABLE "+s.table("upstream_secrets")+", "+s.table("client_key_secrets")+" IN EXCLUSIVE MODE"); e != nil {
			return out, ErrStore
		}
	} else {
		// Acquire the SQLite writer before reading to prevent a stale read-to-write upgrade.
		r, e := tx.ExecContext(ctx, s.query("UPDATE "+s.table("registry_state")+" SET revision=revision WHERE id=1 AND revision=?"), o.ExpectedRevision)
		if e != nil {
			return out, ErrStore
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return out, ErrConflict
		}
	}
	snap, e := s.read(ctx, tx)
	if e != nil {
		return out, e
	}
	if snap.Revision != o.ExpectedRevision {
		return out, ErrConflict
	}
	out.Revision = snap.Revision
	references := 0
	for _, srv := range snap.Config.Servers {
		if srv.TokenRef != "" {
			references++
		}
	}
	if references != len(snap.secrets) {
		return out, ErrSecret
	}
	var all []rotationRow
	for _, spec := range []struct{ table, column, prefix string }{{"upstream_secrets", "server_id", ""}, {"client_key_secrets", "principal_id", "client-key:"}} {
		rows, e := tx.QueryContext(ctx, "SELECT "+spec.column+",ciphertext FROM "+s.table(spec.table)+" ORDER BY "+spec.column+" LIMIT 4097")
		if e != nil {
			return out, ErrStore
		}
		count := 0
		for rows.Next() {
			var id string
			var enc []byte
			if rows.Scan(&id, &enc) != nil || len(enc) < s.aead.NonceSize()+s.aead.Overhead() || count >= 4096 {
				rows.Close()
				return out, ErrSecret
			}
			aad := []byte(spec.prefix + id)
			plain, e := s.aead.Open(nil, enc[:s.aead.NonceSize()], enc[s.aead.NonceSize():], aad)
			if e != nil {
				rows.Close()
				return out, ErrSecret
			}
			if spec.prefix != "" && !matchesClientKey(snap.Config.Principals[id], string(plain)) {
				clear(plain)
				rows.Close()
				return out, ErrSecret
			}
			// Reject reuse of the same encryption key by testing the existing authentication tag.
			if _, e = next.Open(nil, enc[:next.NonceSize()], enc[next.NonceSize():], aad); e == nil {
				clear(plain)
				rows.Close()
				return out, ErrSecret
			}
			nonce := make([]byte, next.NonceSize())
			if _, e = rand.Read(nonce); e != nil {
				clear(plain)
				rows.Close()
				return out, ErrSecret
			}
			sealed := next.Seal(nonce, nonce, plain, aad)
			check, e := next.Open(nil, sealed[:next.NonceSize()], sealed[next.NonceSize():], aad)
			equal := e == nil && bytes.Equal(plain, check)
			clear(plain)
			clear(check)
			if !equal {
				rows.Close()
				return out, ErrSecret
			}
			all = append(all, rotationRow{spec.table, spec.column, id, sealed})
			count++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, ErrStore
		}
		if spec.prefix == "" {
			out.Upstreams = count
		} else {
			out.Clients = count
		}
	}
	if o.Role != "" {
		var super string
		var exists bool
		if tx.QueryRowContext(ctx, "SHOW is_superuser").Scan(&super) != nil || super != "on" {
			return out, ErrStore
		}
		if tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", o.Role).Scan(&exists) != nil || !exists {
			return out, ErrStore
		}
		// Refuse audit extensions rather than assuming local statement settings suppress them.
		var audit bool
		if tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pgaudit') OR current_setting('shared_preload_libraries') LIKE '%pgaudit%'").Scan(&audit) != nil || audit {
			return out, ErrStore
		}
	}
	if o.VerifyOnly {
		return out, nil
	}
	hit := func(stage string) error {
		if fault != nil {
			return fault(stage)
		}
		return nil
	}
	for _, r := range all {
		if _, e = tx.ExecContext(ctx, s.query("UPDATE "+s.table(r.table)+" SET ciphertext=? WHERE "+r.column+"=?"), r.ciphertext, r.id); e != nil {
			return out, ErrStore
		}
		if e = hit("row"); e != nil {
			return out, e
		}
	}
	if o.Role != "" {
		// These settings are confined to the maintenance transaction and revert on commit/rollback.
		// Never transmit a plaintext password in SQL, even when logging is suppressed.
		for _, q := range []string{"SET LOCAL log_statement='none'", "SET LOCAL log_min_error_statement='panic'", "SET LOCAL log_min_duration_statement=-1", "SET LOCAL log_min_duration_sample=-1", "SET LOCAL log_duration=off"} {
			if _, e = tx.ExecContext(ctx, q); e != nil {
				return out, ErrStore
			}
		}
		verifier, e := scramVerifier(o.Password)
		if e != nil {
			return out, ErrSecret
		}
		if _, e = tx.ExecContext(ctx, `ALTER ROLE "`+o.Role+`" PASSWORD '`+verifier+`'`); e != nil {
			return out, ErrStore
		}
		out.PasswordRotated = true
		if e = hit("password"); e != nil {
			return out, e
		}
	}
	verified := &DB{db: s.db, kind: s.kind, aead: next}
	if _, e = verified.read(ctx, tx); e != nil {
		return out, ErrSecret
	}
	r, e := tx.ExecContext(ctx, s.query("UPDATE "+s.table("registry_state")+" SET revision=revision+1 WHERE id=1 AND revision=?"), snap.Revision)
	if e != nil {
		return out, ErrStore
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return out, ErrConflict
	}
	if e = hit("before_commit"); e != nil {
		return out, e
	}
	if tx.Commit() != nil {
		return out, ErrRotationCommitUnknown
	}
	out.Revision++
	out.Committed = true
	if e = hit("after_commit"); e != nil {
		return out, ErrRotationCommitUnknown
	}
	return out, nil
}

func scramVerifier(password []byte) (string, error) {
	// Generated passwords are ASCII, avoiding SASLprep ambiguity and SQL quoting entirely.
	if len(password) < 32 || len(password) > 256 {
		return "", ErrSecret
	}
	for _, b := range password {
		if b < 33 || b > 126 {
			return "", ErrSecret
		}
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", ErrSecret
	}
	salted, e := pbkdf2.Key(sha256.New, string(password), salt, 4096, 32)
	if e != nil {
		return "", ErrSecret
	}
	defer clear(salted)
	mac := hmac.New(sha256.New, salted)
	mac.Write([]byte("Client Key"))
	client := mac.Sum(nil)
	defer clear(client)
	stored := sha256.Sum256(client)
	mac = hmac.New(sha256.New, salted)
	mac.Write([]byte("Server Key"))
	server := mac.Sum(nil)
	defer clear(server)
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$4096:%s$%s:%s", b64(salt), b64(stored[:]), b64(server)), nil
}
