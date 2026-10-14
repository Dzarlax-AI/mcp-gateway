//go:build ignore

// Synthetic rotation fixture. It never reads production configuration.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"net/url"
	"os"
	"strings"
)

func work() error {
	mode := flag.String("mode", "seed", "seed or verify")
	locationPath := flag.String("location-file", "", "private test DSN file")
	keyPath := flag.String("key-file", "", "private test key file")
	fixturePath := flag.String("fixture-file", "", "synthetic fixture JSON")
	flag.Parse()
	location, e := os.ReadFile(*locationPath)
	if e != nil {
		return fmt.Errorf("fixture input failed")
	}
	u, e := url.Parse(string(location))
	if e != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || !strings.HasPrefix(u.Path, "/rotation_") {
		return fmt.Errorf("fixture requires isolated loopback database")
	}
	kb, e := os.ReadFile(*keyPath)
	if e != nil {
		return fmt.Errorf("fixture input failed")
	}
	key, e := base64.StdEncoding.DecodeString(string(kb))
	if e != nil {
		return fmt.Errorf("fixture key failed")
	}
	ctx := context.Background()
	if *mode == "seed" {
		if e = store.Migrate(ctx, "postgres", string(location)); e != nil {
			return fmt.Errorf("fixture migration failed")
		}
	}
	db, e := store.Open("postgres", string(location), key)
	if e != nil {
		return fmt.Errorf("fixture store failed")
	}
	defer db.Close()
	token := "mgw_" + strings.Repeat("r", 43)
	hash := "mgw_" + strings.Repeat("h", 43)
	if *mode == "seed" {
		b, e := os.ReadFile(*fixturePath)
		if e != nil {
			return fmt.Errorf("fixture config failed")
		}
		var c config.Config
		if json.Unmarshal(b, &c) != nil {
			return fmt.Errorf("fixture config failed")
		}
		a, btoken := os.Getenv("ROTATION_UPSTREAM_A"), os.Getenv("ROTATION_UPSTREAM_B")
		if _, e = db.CompareAndSwap(ctx, 0, &c, map[string]*string{"demo": &a, "second": &btoken}); e != nil {
			return fmt.Errorf("fixture seed failed")
		}
		c.Principals["recoverable"] = config.Principal{TokenHash: config.TokenDigest(token), Key: &config.ClientKey{Name: "Synthetic", Prefix: token[:12], CreatedAt: "2026-10-14T12:00:00Z", Recoverable: true}}
		c.Principals["hashonly"] = config.Principal{TokenHash: config.TokenDigest(hash), Key: &config.ClientKey{Name: "Synthetic hash", Prefix: hash[:12], CreatedAt: "2026-10-14T12:00:00Z"}}
		if _, e = db.CompareAndSwapClientKeys(ctx, 1, &c, map[string]*string{"recoverable": &token}); e != nil {
			return fmt.Errorf("fixture seed failed")
		}
	} else {
		snap, e := db.ReadSnapshot(ctx)
		if e != nil {
			return fmt.Errorf("fixture verify failed")
		}
		for id, want := range map[string]string{"demo": os.Getenv("ROTATION_UPSTREAM_A"), "second": os.Getenv("ROTATION_UPSTREAM_B")} {
			v, e := store.ResolveSnapshotSecret(snap, id)
			if e != nil || v != want {
				return fmt.Errorf("fixture upstream changed")
			}
		}
		got, e := db.RevealClientKey(ctx, snap.Revision, "recoverable")
		if e != nil || got != token {
			return fmt.Errorf("fixture client changed")
		}
		for id, v := range map[string]string{"codex": os.Getenv("ROTATION_CLIENT_TOKEN"), "recoverable": token, "hashonly": hash} {
			if !snap.Config.Principals[id].MatchesToken(v) {
				return fmt.Errorf("fixture authentication changed")
			}
		}
	}
	fmt.Println(`{"fixture_verified":true}`)
	return nil
}
func main() {
	if e := work(); e != nil {
		fmt.Fprintln(os.Stderr, "synthetic fixture failed")
		os.Exit(1)
	}
}
