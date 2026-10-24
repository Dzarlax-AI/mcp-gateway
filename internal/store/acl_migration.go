package store

import (
	"context"
	"database/sql"
	"errors"
	"mcp-gateway/internal/config"
	"os"
)

var ErrACLCommitUnknown = errors.New("ACL migration commit outcome unknown; inspect registry before retrying")

type ACLMigrationOptions struct {
	Apply            bool
	ExpectedRevision int64
}
type ACLMigrationReport struct {
	Revision        int64 `json:"revision"`
	DocumentVersion int   `json:"document_version"`
	Principals      int   `json:"principals"`
	Changed         bool  `json:"changed"`
	Committed       bool  `json:"committed"`
}

// MigrateAgentACL changes only registry_state in an explicit maintenance transaction.
func MigrateAgentACL(ctx context.Context, kind, location string, o ACLMigrationOptions) (ACLMigrationReport, error) {
	return migrateAgentACL(ctx, kind, location, o, nil)
}
func migrateAgentACL(ctx context.Context, kind, location string, o ACLMigrationOptions, finish func(*sql.Tx) error) (out ACLMigrationReport, err error) {
	if o.Apply && o.ExpectedRevision < 1 {
		return out, ErrConflict
	}
	// Maintenance never bootstraps a missing SQLite database, including dry-run.
	if kind == "sqlite" {
		info, e := os.Lstat(location)
		if e != nil || !info.Mode().IsRegular() {
			return out, ErrStore
		}
	}
	db, err := openDB(kind, location)
	if err != nil {
		return out, ErrStore
	}
	defer db.Close()
	s := &DB{db: db, kind: kind}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return out, ErrStore
	}
	defer tx.Rollback()
	if err = s.checkVersion(ctx, tx); err != nil {
		return out, err
	}
	var raw string
	var revision int64
	q := "SELECT revision,document FROM " + s.table("registry_state") + " WHERE id=1"
	if kind == "postgres" {
		q += " FOR UPDATE"
	}
	if tx.QueryRowContext(ctx, q).Scan(&revision, &raw) != nil || len(raw) > maxDocument {
		return out, ErrStore
	}
	if o.ExpectedRevision != 0 && o.ExpectedRevision != revision {
		return out, ErrConflict
	}
	b, changed, err := config.UpgradeAgentACLDocument([]byte(raw))
	if err != nil {
		return out, err
	}
	c, err := config.Decode(b)
	if err != nil {
		return out, err
	}
	out = ACLMigrationReport{Revision: revision, DocumentVersion: config.RegistryVersion, Principals: len(c.Principals), Changed: changed}
	if !o.Apply || !changed {
		return out, nil
	}
	if revision == int64(^uint64(0)>>1) {
		return out, ErrConflict
	}
	res, err := tx.ExecContext(ctx, s.query("UPDATE "+s.table("registry_state")+" SET document=?,revision=revision+1 WHERE id=1 AND revision=?"), string(b), revision)
	if err != nil {
		return out, ErrStore
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return out, ErrConflict
	}
	if finish == nil {
		finish = func(tx *sql.Tx) error { return tx.Commit() }
	}
	if finish(tx) != nil {
		return out, ErrACLCommitUnknown
	}
	out.Revision++
	out.Committed = true
	return out, nil
}
