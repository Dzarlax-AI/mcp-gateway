//go:build ignore

// Synthetic loopback benchmark: no real data or credentials are used.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/gateway"
	"mcp-gateway/internal/upstream"
)

const benchmarkToken = "synthetic-read-batch-client-123456"

type row struct {
	Cache    string  `json:"cache"`
	Mode     string  `json:"mode"`
	Run      int     `json:"run"`
	MS       float64 `json:"ms"`
	External int     `json:"external_calls"`
	Upstream int64   `json:"upstream_calls"`
	Metadata int64   `json:"upstream_http_requests"`
	Parity   bool    `json:"result_parity"`
}

func main() {
	runs := flag.Int("runs", 10, "cycles per mode and cache state, 1-20")
	serve := flag.Bool("serve", false, "serve synthetic upstream for isolated CLI acceptance")
	flag.Parse()
	if *runs < 1 || *runs > 20 {
		panic("invalid runs")
	}
	var calls, metadata atomic.Int64
	s := mcp.NewServer(&mcp.Implementation{Name: "synthetic-read-benchmark", Version: "1"}, nil)
	names := []string{"read_alpha", "read_beta", "read_gamma"}
	for _, name := range names {
		s.AddTool(&mcp.Tool{Name: name, Description: "Read synthetic " + name, InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			calls.Add(1)
			select {
			case <-time.After(120 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: r.Params.Name}}, StructuredContent: map[string]any{"name": r.Params.Name}}, nil
		})
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata.Add(1)
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}).ServeHTTP(w, r)
	}))
	defer backend.Close()
	dir, err := os.MkdirTemp("", "read-batch-benchmark-")
	must(err)
	defer os.RemoveAll(dir)
	cfg := config.Config{Servers: map[string]config.Server{"demo": {Description: "Synthetic independent read operations", URL: backend.URL + "/mcp", Enabled: true, Tools: map[string]config.Tool{}}}, Principals: map[string]config.Principal{"benchmark": {TokenEnv: "READ_BATCH_BENCH_TOKEN", Grants: map[string]map[string]config.Grant{}}}}
	policyOps := []map[string]string{}
	server := cfg.Servers["demo"]
	for _, n := range names {
		server.Tools[n] = config.Tool{Enabled: true, AccessMode: "shared"}
		policyOps = append(policyOps, map[string]string{"server_id": "demo", "tool_name": n, "endpoint": server.URL})
	}
	cfg.Servers["demo"] = server
	path := filepath.Join(dir, "registry.json")
	write(path, cfg)
	policyPath := filepath.Join(dir, "policy.json")
	write(policyPath, map[string]any{"version": 1, "operations": policyOps})
	if *serve {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"endpoint": server.URL, "registry_path": path, "allowlist_path": policyPath, "client_token_env": "READ_BATCH_BENCH_TOKEN"})
		select {}
	}
	must(os.Setenv("READ_BATCH_BENCH_TOKEN", benchmarkToken))
	provider := catalog.New()
	defer provider.Close()
	g := &gateway.Gateway{Path: path, Catalog: provider, ReadBatch: gateway.NewReadBatchExecutor(&gateway.ReadBatchPolicy{Path: policyPath}), Timeout: 10 * time.Second}
	handler, err := g.Handler()
	must(err)
	front := httptest.NewServer(handler)
	defer front.Close()
	session, close, err := upstream.Connect(context.Background(), config.Server{URL: front.URL + "/mcp", TokenEnv: "READ_BATCH_BENCH_TOKEN"})
	must(err)
	defer close()
	rows := []row{}
	for _, cache := range []string{"warm", "cold"} {
		for _, mode := range []string{"sequential", "parallel", "batch"} {
			for run := 1; run <= *runs; run++ {
				provider.Invalidate("demo", 0)
				if cache == "warm" {
					r, e := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_tool_schema", Arguments: map[string]any{"server_id": "demo", "tool_name": names[0]}})
					must(e)
					if r.IsError {
						panic("warmup failed")
					}
				}
				before, requests := calls.Load(), metadata.Load()
				start := time.Now()
				results := make([]*mcp.CallToolResult, len(names))
				external := 3
				if mode == "batch" {
					ops := []map[string]any{}
					for _, name := range names {
						ops = append(ops, map[string]any{"id": name, "server_id": "demo", "tool_name": name, "arguments": map[string]any{}})
					}
					r, e := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "invoke_read_batch", Arguments: map[string]any{"operations": ops}})
					must(e)
					if r.IsError {
						panic("batch failed")
					}
					b, _ := json.Marshal(r.StructuredContent)
					var envelope struct {
						Complete bool `json:"complete"`
						Results  []struct {
							ID     string              `json:"id"`
							Status string              `json:"status"`
							Result *mcp.CallToolResult `json:"tool_result"`
						} `json:"results"`
					}
					must(json.Unmarshal(b, &envelope))
					if !envelope.Complete || len(envelope.Results) != 3 {
						panic("incomplete batch")
					}
					for i, v := range envelope.Results {
						if v.ID != names[i] || v.Status != "ok" {
							panic("batch order/status")
						}
						results[i] = v.Result
					}
					external = 1
				} else {
					invoke := func(i int) {
						r, e := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "invoke_tool", Arguments: map[string]any{"server_id": "demo", "tool_name": names[i], "arguments": map[string]any{}}})
						must(e)
						if r.IsError {
							panic("single failed")
						}
						results[i] = r
					}
					if mode == "parallel" {
						var wg sync.WaitGroup
						for i := range names {
							wg.Add(1)
							go func() { defer wg.Done(); invoke(i) }()
						}
						wg.Wait()
					} else {
						for i := range names {
							invoke(i)
						}
					}
				}
				ms := float64(time.Since(start).Microseconds()) / 1000
				for i, r := range results {
					if r == nil || r.IsError || len(r.Content) != 1 || r.Content[0].(*mcp.TextContent).Text != names[i] {
						panic("result parity failed")
					}
					b, _ := json.Marshal(r.StructuredContent)
					if string(b) != "{\"name\":\""+names[i]+"\"}" {
						panic("structured parity failed")
					}
				}
				delta := calls.Load() - before
				if delta != 3 {
					panic("upstream count mismatch")
				}
				rows = append(rows, row{cache, mode, run, ms, external, delta, metadata.Load() - requests, true})
			}
		}
	}
	summaries := []map[string]any{}
	for _, cache := range []string{"warm", "cold"} {
		for _, mode := range []string{"sequential", "parallel", "batch"} {
			values := []float64{}
			for _, r := range rows {
				if r.Cache == cache && r.Mode == mode {
					values = append(values, r.MS)
				}
			}
			sort.Float64s(values)
			median := values[len(values)/2]
			if len(values)%2 == 0 {
				median = (values[len(values)/2-1] + median) / 2
			}
			summaries = append(summaries, map[string]any{"cache": cache, "mode": mode, "median_ms": median})
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(map[string]any{"measured_at": time.Now().UTC().Format(time.RFC3339), "synthetic_read_delay_ms": 120, "runs_per_variant": *runs, "rows": rows, "summaries": summaries, "notes": "Loopback SDK; same client session; 3 known independent reads; native transport no retries; no model or Codex overhead; upstream_http_requests includes initialize and tool HTTP requests. No real calendar data."}))
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func write(path string, v any) { b, e := json.Marshal(v); must(e); must(os.WriteFile(path, b, 0600)) }
