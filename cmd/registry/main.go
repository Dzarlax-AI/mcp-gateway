// registry applies explicit migrations and imports or exports credential-free registry configuration.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"os"
	"time"
)

func run(args []string) error {
	if len(args) > 0 && args[0] == "rotate-secret-key" {
		return runRotation(args[1:])
	}
	if len(args) > 0 && args[0] == "seal-recovery" {
		return runRecovery(args[1:])
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: registry migrate|import --file PATH|export|simplify|downgrade-client-keys")
	}
	fs := flag.NewFlagSet("registry", flag.ContinueOnError)
	file := fs.String("file", "", "JSON registry to import")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
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
		return fmt.Errorf("GATEWAY_STORAGE must be sqlite or postgres")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if args[0] == "migrate" {
		if *file != "" {
			return fmt.Errorf("--file is only valid for import")
		}
		return store.Migrate(ctx, kind, location)
	}
	if args[0] != "import" && args[0] != "export" && args[0] != "simplify" && args[0] != "downgrade-client-keys" {
		return fmt.Errorf("unknown registry command")
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("GATEWAY_SECRET_KEY"))
	if err != nil || len(key) != 32 {
		return fmt.Errorf("GATEWAY_SECRET_KEY must be base64 encoding of 32 bytes")
	}
	s, err := store.Open(kind, location, key)
	if err != nil {
		return err
	}
	defer s.Close()
	if args[0] == "downgrade-client-keys" {
		if *file != "" {
			return fmt.Errorf("--file is only valid for import")
		}
		return s.DowngradeClientKeys(ctx)
	}
	if args[0] == "simplify" {
		if *file != "" {
			return fmt.Errorf("--file is only valid for import")
		}
		snap, err := s.ReadSnapshot(ctx)
		if err != nil {
			return err
		}
		c, err := config.Clone(snap.Config)
		if err != nil {
			return err
		}
		if !config.SimplifyAccess(c) {
			return nil
		}
		_, err = s.CompareAndSwap(ctx, snap.Revision, c, nil)
		return err
	}

	if args[0] == "export" {
		if *file != "" {
			return fmt.Errorf("--file is only valid for import")
		}
		snap, err := s.ReadSnapshot(ctx)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap.Config)
	}
	if *file == "" {
		return fmt.Errorf("import requires --file")
	}
	c, err := config.Load(*file)
	if err != nil {
		return err
	}
	if _, err = s.ReadSnapshot(ctx); err != store.ErrEmpty {
		if err == nil {
			return fmt.Errorf("import requires an empty registry")
		}
		return err
	}
	_, err = s.CompareAndSwap(ctx, 0, c, nil)
	return err
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
