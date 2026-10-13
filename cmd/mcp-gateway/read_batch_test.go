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
