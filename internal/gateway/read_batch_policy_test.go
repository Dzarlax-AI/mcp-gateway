package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

const readBatchTestPolicy = `{"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp"},{"server_id":"demo","tool_name":"read_beta","endpoint":"http://127.0.0.1:8081/mcp"}]}`

func writeReadBatchPolicy(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReadBatchPolicyAllowsExactOperations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	writeReadBatchPolicy(t, path, readBatchTestPolicy)
	policy := &ReadBatchPolicy{Path: path}
	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	for _, tool := range []string{"read_alpha", "read_beta"} {
		if err := policy.Allows("demo", tool, "http://127.0.0.1:8081/mcp"); err != nil {
			t.Errorf("Allows(%q) error = %v", tool, err)
		}
	}
	for _, tc := range []struct{ server, tool, endpoint string }{
		{"other", "read_alpha", "http://127.0.0.1:8081/mcp"},
		{"demo", "write_alpha", "http://127.0.0.1:8081/mcp"},
		{"demo", "read_alpha", "http://127.0.0.1:8082/mcp"},
		{"*", "read_alpha", "http://127.0.0.1:8081/mcp"},
	} {
		if err := policy.Allows(tc.server, tc.tool, tc.endpoint); err == nil {
			t.Errorf("Allows(%q, %q, %q) unexpectedly succeeded", tc.server, tc.tool, tc.endpoint)
		}
	}
}

func TestReadBatchPolicyRejectsInvalidFiles(t *testing.T) {
	duplicate := `{"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp"},{"server_id":"demo","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8082/mcp"}]}`
	tooMany := `{"version":1,"operations":[` + strings.TrimSuffix(strings.Repeat(`{"server_id":"demo","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp"},`, 257), ",") + `]}`
	tooLarge := `{"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp"}],"padding":"` + strings.Repeat("x", readBatchPolicyMaxBytes) + `"}`
	tests := []struct {
		name string
		body string
	}{
		{"malformed", `{`},
		{"unknown field", strings.Replace(readBatchTestPolicy, `"version":1`, `"version":1,"extra":true`, 1)},
		{"trailing json", readBatchTestPolicy + `{}`},
		{"wrong version", strings.Replace(readBatchTestPolicy, `"version":1`, `"version":2`, 1)},
		{"empty operations", `{"version":1,"operations":[]}`},
		{"duplicate server tool", duplicate},
		{"duplicate version key", `{"version":2,"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp"}]}`},
		{"duplicate endpoint key", `{"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp","endpoint":"http://127.0.0.1:8082/mcp"}]}`},
		{"duplicate server key", `{"version":1,"operations":[{"server_id":"demo","server_id":"other","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp"}]}`},
		{"duplicate tool key", `{"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","tool_name":"read_beta","endpoint":"http://127.0.0.1:8081/mcp"}]}`},
		{"trimmed identifier", strings.Replace(readBatchTestPolicy, `"demo"`, `" demo "`, 1)},
		{"wildcard endpoint", `{"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","endpoint":"https://*.example.com"}]}`},
		{"too many operations", tooMany},
		{"oversized", tooLarge},
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	policy := &ReadBatchPolicy{Path: path}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writeReadBatchPolicy(t, path, tc.body)
			if err := policy.Validate(); err == nil {
				t.Fatal("Validate() succeeded for invalid policy")
			}
			if err := policy.Allows("demo", "read_alpha", "http://127.0.0.1:8081/mcp"); err == nil {
				t.Fatal("Allows() succeeded for invalid policy")
			}
		})
	}
}

func TestReadBatchPolicyReloadsForReplacementAndRemoval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writeReadBatchPolicy(t, path, readBatchTestPolicy)
	policy := &ReadBatchPolicy{Path: path}
	if err := policy.Allows("demo", "read_alpha", "http://127.0.0.1:8081/mcp"); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.json")
	writeReadBatchPolicy(t, replacement, `{"version":1,"operations":[{"server_id":"demo","tool_name":"read_beta","endpoint":"http://127.0.0.1:8081/mcp"}]}`)
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := policy.Allows("demo", "read_alpha", "http://127.0.0.1:8081/mcp"); err == nil {
		t.Fatal("old grant remained after atomic replacement")
	}
	if err := policy.Allows("demo", "read_beta", "http://127.0.0.1:8081/mcp"); err != nil {
		t.Fatalf("replacement grant denied: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := policy.Allows("demo", "read_beta", "http://127.0.0.1:8081/mcp"); err == nil {
		t.Fatal("grant allowed after policy removal")
	}
}

func TestReadBatchPolicyRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Skipf("named pipes unavailable: %v", err)
	}
	policy := &ReadBatchPolicy{Path: path}
	if err := policy.Validate(); err == nil {
		t.Fatal("Validate() accepted a named pipe")
	}
}

func TestReadBatchPolicyParallelReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	writeReadBatchPolicy(t, path, readBatchTestPolicy)
	policy := &ReadBatchPolicy{Path: path}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tool := "read_alpha"
			if i%2 == 1 {
				tool = "read_beta"
			}
			if err := policy.Allows("demo", tool, "http://127.0.0.1:8081/mcp"); err != nil {
				t.Errorf("parallel authorization failed: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestReadBatchPolicyErrorsDoNotExposePathOrContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret-policy.json")
	policy := &ReadBatchPolicy{Path: path}
	err := policy.Validate()
	if err == nil || strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe error: %v", err)
	}
	writeReadBatchPolicy(t, path, fmt.Sprintf(`{"version":%d}`, 2))
	err = policy.Validate()
	if err == nil || strings.Contains(err.Error(), "version") {
		t.Fatalf("unsafe validation error: %v", err)
	}
}
