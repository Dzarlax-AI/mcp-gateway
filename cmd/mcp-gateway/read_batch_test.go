package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadBatchStartupOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"operations":[{"server_id":"demo","tool_name":"read","endpoint":"http://127.0.0.1:18081/mcp"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, flag, path string
		search, want     bool
		fail             bool
	}{
		{"unset", "", "", false, false, false}, {"off", "false", "", false, false, false}, {"invalid flag", "sometimes", path, true, false, true}, {"needs search", "true", path, false, false, true}, {"missing policy", "true", "", true, false, true}, {"valid", "true", path, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GATEWAY_READ_BATCH_ENABLED", tc.flag)
			t.Setenv("GATEWAY_READ_BATCH_ALLOWLIST", tc.path)
			batch, err := readBatchOptions(tc.search)
			if (err != nil) != tc.fail || (batch != nil) != tc.want {
				t.Fatalf("got enabled=%v err=%v", batch != nil, err)
			}
		})
	}
}

func TestRegistryReadBatchStartupMode(t *testing.T) {
	t.Setenv("GATEWAY_READ_BATCH_ENABLED", "true")
	t.Setenv("GATEWAY_READ_BATCH_POLICY_MODE", "registry")
	t.Setenv("GATEWAY_READ_BATCH_ALLOWLIST", "")
	b, e := readBatchOptions(true)
	if e != nil || !b.RegistryMode() {
		t.Fatalf("registry mode: %v", e)
	}
	t.Setenv("GATEWAY_READ_BATCH_ALLOWLIST", "unexpected.json")
	if _, e = readBatchOptions(true); e == nil {
		t.Fatal("mixed mode accepted")
	}
	t.Setenv("GATEWAY_READ_BATCH_POLICY_MODE", "unknown")
	if _, e = readBatchOptions(true); e == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestClassifiedReadBatchStartupMode(t *testing.T) {
	t.Setenv("GATEWAY_READ_BATCH_ENABLED", "true")
	t.Setenv("GATEWAY_READ_BATCH_POLICY_MODE", "classified")
	t.Setenv("GATEWAY_READ_BATCH_ALLOWLIST", "")
	b, err := readBatchOptions(true)
	if err != nil || !b.ClassifiedMode() || b.RegistryMode() {
		t.Fatalf("classified mode: %v", err)
	}
	t.Setenv("GATEWAY_READ_BATCH_ALLOWLIST", "unexpected.json")
	if _, err = readBatchOptions(true); err == nil {
		t.Fatal("mixed policy accepted")
	}
}
