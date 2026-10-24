package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"mcp-gateway/internal/audit"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func runAgentACL(args []string) error {
	fs := flag.NewFlagSet("migrate-agent-acl", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "apply explicit document migration")
	dry := fs.Bool("dry-run", false, "inspect without writing (default)")
	file := fs.String("file", "", "offline file registry")
	offline := fs.Bool("offline", false, "confirm all file writers are stopped")
	digest := fs.String("expect-sha256", "", "expected file digest")
	rev := fs.Int64("expect-revision", 0, "expected SQL revision")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || (*apply && *dry) {
		return errors.New("invalid migration options")
	}
	sink, err := audit.FromEnv()
	if err != nil {
		return err
	}
	var report store.ACLMigrationReport
	if *file != "" {
		if *rev != 0 {
			return errors.New("file migration does not use SQL revision")
		}
		report, err = migrateACLFile(*file, *digest, *apply, *offline)
	} else {
		if *offline || *digest != "" {
			return errors.New("file options require --file")
		}
		kind := os.Getenv("GATEWAY_STORAGE")
		location := ""
		switch kind {
		case "sqlite":
			location = os.Getenv("GATEWAY_SQLITE_PATH")
			if location == "" {
				location = "/var/lib/gateway/gateway.db"
			}
		case "postgres":
			location = os.Getenv("GATEWAY_DATABASE_URL")
		default:
			return errors.New("SQL migration requires sqlite or postgres")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		report, err = store.MigrateAgentACL(ctx, kind, location, store.ACLMigrationOptions{Apply: *apply, ExpectedRevision: *rev})
	}
	event := audit.Event{Kind: "acl_migration", Actor: "operator", RequestID: audit.RequestID(), Outcome: "dry_run", Revision: report.Revision}
	if report.Committed {
		event.Outcome = "committed"
	} else if *apply && err == nil {
		event.Outcome = "no_op"
	}
	if err != nil {
		event.Outcome = "rejected"
		if errors.Is(err, store.ErrConflict) {
			event.Outcome = "conflict"
		}
		if errors.Is(err, store.ErrACLCommitUnknown) {
			event.Outcome = "unknown"
		}
	}
	_ = sink.Record(event)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		store.ACLMigrationReport
		Audit string `json:"audit_status"`
	}{report, sink.State()})
}
func ownedRegular(f *os.File) bool {
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && sys.Uid == uint32(os.Geteuid())
}
func readACLFile(path string) ([]byte, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, config.ErrConfig
	}
	defer f.Close()
	if !ownedRegular(f) {
		return nil, config.ErrConfig
	}
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return nil, config.ErrConfig
	}
	return b, nil
}
func migrateACLFile(path, want string, apply, offline bool) (out store.ACLMigrationReport, err error) {
	if apply && (!offline || len(want) != 64 || want != strings.ToLower(want)) {
		return out, errors.New("file apply requires --offline and expected SHA-256")
	}
	if want != "" {
		if _, e := hex.DecodeString(want); e != nil {
			return out, config.ErrConfig
		}
	}
	var lock *os.File
	if apply {
		lock, err = os.OpenFile(path+".agent-acl.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		if err != nil {
			return out, config.ErrConfig
		}
		defer lock.Close()
		if !ownedRegular(lock) {
			return out, config.ErrConfig
		}
		if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return out, store.ErrConflict
		}
		defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	}
	raw, err := readACLFile(path)
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256(raw)
	actual := hex.EncodeToString(sum[:])
	if want != "" && actual != want {
		return out, store.ErrConflict
	}
	b, changed, err := config.UpgradeAgentACLDocument(raw)
	if err != nil {
		return out, err
	}
	c, err := config.Decode(b)
	if err != nil {
		return out, err
	}
	out = store.ACLMigrationReport{DocumentVersion: 2, Principals: len(c.Principals), Changed: changed}
	if !apply || !changed {
		return out, nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent-acl-*")
	if err != nil {
		return out, config.ErrConfig
	}
	name := tmp.Name()
	defer os.Remove(name)
	defer tmp.Close()
	if err = tmp.Chmod(0600); err != nil {
		return out, config.ErrConfig
	}
	if _, err = tmp.Write(b); err != nil {
		return out, config.ErrConfig
	}
	if err = tmp.Sync(); err != nil {
		return out, config.ErrConfig
	}
	if err = tmp.Close(); err != nil {
		return out, config.ErrConfig
	}
	current, err := readACLFile(path)
	if err != nil || sha256.Sum256(current) != sum {
		return out, store.ErrConflict
	}
	if os.Rename(name, path) != nil {
		return out, config.ErrConfig
	}
	out.Committed = true
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return out, store.ErrACLCommitUnknown
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return out, store.ErrACLCommitUnknown
	}
	return out, nil
}
