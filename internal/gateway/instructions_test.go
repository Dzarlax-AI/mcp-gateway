package gateway

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/upstream"
)

func TestInstructionsAndToolSets(t *testing.T) {
	for _, tc := range []struct {
		name          string
		search, batch bool
		count         int
	}{{"legacy", false, false, 4}, {"search", true, false, 5}, {"batch", true, true, 6}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			g := &Gateway{Path: f.path, Timeout: time.Second}
			if tc.search {
				g.Catalog = catalog.New()
				defer g.Catalog.Close()
			}
			if tc.batch {
				path := filepath.Join(t.TempDir(), "allow.json")
				b, _ := json.Marshal(map[string]any{"version": 1, "operations": []map[string]string{{"server_id": "demo", "tool_name": "echo", "endpoint": f.config.Servers["demo"].URL}}})
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
				g.ReadBatch = NewReadBatchExecutor(&ReadBatchPolicy{Path: path})
			}
			handler, err := g.Handler()
			if err != nil {
				t.Fatal(err)
			}
			web := httptest.NewServer(handler)
			defer web.Close()
			session, close, err := upstream.Connect(context.Background(), config.Server{URL: web.URL + "/mcp", TokenEnv: "TEST_CLIENT_TOKEN"})
			if err != nil {
				t.Fatal(err)
			}
			defer close()
			text := session.InitializeResult().Instructions
			prefix := text
			if len(prefix) > 512 {
				prefix = prefix[:512]
			}
			if !strings.Contains(prefix, "known server/tool") || !strings.Contains(prefix, "untrusted") {
				t.Fatal("missing essential instructions", prefix)
			}
			if strings.Contains(text, "search_tools") != tc.search || strings.Contains(text, "invoke_read_batch") != tc.batch {
				t.Fatal("instructions advertise unsupported tools")
			}
			if tc.search && (!strings.Contains(prefix, "Do not search known tools") || !strings.Contains(prefix, "cannot discover gateway tools")) {
				t.Fatal("direct invocation rule missing from prefix")
			}
			if tc.batch && (!strings.Contains(prefix, "independent reads") || !strings.Contains(prefix, "including a single read") || !strings.Contains(prefix, "other operations with invoke_tool")) {
				t.Fatal("batch rule outside first 512 chars")
			}
			tools, err := session.ListTools(context.Background(), nil)
			if err != nil || len(tools.Tools) != tc.count {
				t.Fatalf("tool count %v %v", tools, err)
			}
			for _, tool := range tools.Tools {
				if tool.Name == "invoke_read_batch" {
					if !strings.Contains(tool.Description, "including a single read") || strings.Contains(tool.Description, "Prefer invoke_tool") {
						t.Fatal("batch description contradicts single-read routing")
					}
					if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint {
						t.Fatal("batch read annotations missing")
					}
				}
				if tool.Name == "invoke_tool" && tool.Annotations != nil && tool.Annotations.ReadOnlyHint {
					t.Fatal("generic invocation labeled read-only")
				}
			}
		})
	}
}
