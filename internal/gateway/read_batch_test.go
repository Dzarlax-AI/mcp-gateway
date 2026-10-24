package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
)

func TestDecodeReadBatchStrictContract(t *testing.T) {
	valid := `{"operations":[{"id":"a_1-Z","server_id":"docs","tool_name":"search","arguments":{"query":"x"}}]}`
	if _, ok := decodeReadBatch(json.RawMessage(valid)); !ok {
		t.Fatal("valid batch rejected")
	}
	invalid := []string{
		`null`, `[]`, `{}`, `{"operations":[]}`,
		`{"operations":[{"id":"x","server_id":"s","tool_name":"t","arguments":{}}],"extra":1}`,
		`{"operations":[{"id":"x","server_id":"s","tool_name":"t","arguments":{},"extra":1}]}`,
		`{"operations":[{"id":"bad id","server_id":"s","tool_name":"t","arguments":{}}]}`,
		`{"operations":[{"id":"x","server_id":"s","tool_name":"t","arguments":null}]}`,
		`{"operations":[{"id":"x","server_id":"s","tool_name":"t","arguments":[]}]}`,
		`{"operations":[{"id":"x","server_id":"s","tool_name":"t","arguments":{}}],"operations":[]}`,
		`{"operations":[{"id":"x","server_id":"s","tool_name":"t","arguments":{}}]} {}`,
		`{"operations":[{"id":"x","id":"y","server_id":"s","tool_name":"t","arguments":{}}]}`,
		`{"operations":[{"id":"x","server_id":"s","tool_name":"t","arguments":{"a":1,"a":2}}]}`,
	}
	for _, raw := range invalid {
		t.Run(strings.ReplaceAll(raw, "/", "_"), func(t *testing.T) {
			if _, ok := decodeReadBatch(json.RawMessage(raw)); ok {
				t.Fatalf("accepted malformed batch: %s", raw)
			}
		})
	}
	dupe := `{"operations":[{"id":"x","server_id":"s","tool_name":"a","arguments":{}},{"id":"x","server_id":"s","tool_name":"b","arguments":{}}]}`
	if _, ok := decodeReadBatch(json.RawMessage(dupe)); ok {
		t.Fatal("accepted duplicate IDs")
	}
}

func TestReadBatchMixedResultsKeepOrderAndAuthorizeEveryItem(t *testing.T) {
	f := newFixture(t)
	policyPath := filepath.Join(t.TempDir(), "read-batch.json")
	policyData := map[string]any{"version": 1, "operations": []map[string]string{
		{"server_id": "demo", "tool_name": "echo", "endpoint": f.config.Servers["demo"].URL},
		{"server_id": "demo", "tool_name": "error", "endpoint": f.config.Servers["demo"].URL},
		{"server_id": "demo", "tool_name": "hidden", "endpoint": f.config.Servers["demo"].URL},
	}}
	b, err := json.Marshal(policyData)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(policyPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	cat := catalog.New()
	t.Cleanup(cat.Close)
	g := &Gateway{Path: f.path, Catalog: cat, ReadBatch: NewReadBatchExecutor(&ReadBatchPolicy{Path: policyPath}), Timeout: time.Second}
	raw := json.RawMessage(`{"operations":[{"id":"first","server_id":"demo","tool_name":"echo","arguments":{"text":"ok"}},{"id":"denied","server_id":"demo","tool_name":"hidden","arguments":{"text":"secret"}},{"id":"schema","server_id":"demo","tool_name":"echo","arguments":{"text":123}},{"id":"upstream-error","server_id":"demo","tool_name":"error","arguments":{"text":"failure"}}]}`)
	headers := http.Header{"Authorization": []string{"Bearer " + clientToken}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	malformed := g.readBatch(ctx, headers, json.RawMessage(`{"operations":[{"id":"bad","server_id":"demo","tool_name":"echo","arguments":{"text":"first","text":"second"}}]}`))
	if !malformed.IsError || f.calls.Load() != 0 {
		t.Fatalf("duplicate argument keys must reject the whole batch before dispatch: result=%#v calls=%d", malformed, f.calls.Load())
	}
	got := g.readBatch(ctx, headers, raw)
	items := got.StructuredContent.(map[string]any)["results"].([]readBatchItemResult)
	if len(items) != 4 || items[0].ID != "first" || items[1].ID != "denied" || items[2].ID != "schema" || items[3].ID != "upstream-error" {
		t.Fatalf("input order lost: %#v", items)
	}
	if items[0].Status != "ok" || !items[0].Dispatched || items[0].ToolResult == nil {
		t.Fatalf("first item: %#v", items[0])
	}
	if items[1].Status != "denied" || items[1].Dispatched {
		t.Fatalf("denied item dispatched: %#v", items[1])
	}
	if items[2].Status != "invalid_arguments" || items[2].Dispatched {
		t.Fatalf("bad schema item dispatched: %#v", items[2])
	}
	if items[3].Status != "upstream_error" || !items[3].Dispatched || items[3].UpstreamIsError == nil || !*items[3].UpstreamIsError || items[3].ToolResult == nil || !items[3].ToolResult.IsError {
		t.Fatalf("upstream error outcome was lost: %#v", items[3])
	}
	if items[0].UpstreamIsError == nil || *items[0].UpstreamIsError {
		t.Fatal("successful result must emit known upstream_is_error=false")
	}
	if f.calls.Load() != 2 {
		t.Fatalf("expected two upstream invocations, got %d", f.calls.Load())
	}
	if _, ok := items[0].ToolResult.Content[1].(*mcp.ImageContent); !ok {
		t.Fatalf("upstream content was not preserved: %T", items[0].ToolResult.Content[1])
	}
}

type controlledBatchBackend struct {
	blockCalls    atomic.Bool
	blockInit     atomic.Bool
	failCall      atomic.Bool
	callRelease   chan struct{}
	initEntered   chan struct{}
	initRelease   chan struct{}
	entered       chan string
	mu            sync.Mutex
	active        int
	maxActive     int
	activeByGroup map[string]int
	maxByGroup    map[string]int
	calls         atomic.Int32
	callRequests  atomic.Int32
	initRequests  atomic.Int32
	methods       []string
}

func newControlledBatchGateway(t *testing.T, backend *controlledBatchBackend) (*Gateway, http.Header, string) {
	t.Helper()
	t.Setenv("TEST_CLIENT_TOKEN", clientToken)
	t.Setenv("TEST_BACKEND_TOKEN", backendToken)
	server := mcp.NewServer(&mcp.Implementation{Name: "batch-test", Version: "1"}, nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{"group": map[string]any{"type": "string"}}, "required": []string{"group"}, "additionalProperties": false}
	server.AddTool(&mcp.Tool{Name: "read", InputSchema: schema}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		backend.calls.Add(1)
		var args map[string]any
		_ = json.Unmarshal(r.Params.Arguments, &args)
		group, _ := args["group"].(string)
		backend.mu.Lock()
		backend.active++
		if backend.active > backend.maxActive {
			backend.maxActive = backend.active
		}
		backend.activeByGroup[group]++
		if backend.activeByGroup[group] > backend.maxByGroup[group] {
			backend.maxByGroup[group] = backend.activeByGroup[group]
		}
		backend.mu.Unlock()
		backend.entered <- group
		if backend.blockCalls.Load() {
			select {
			case <-backend.callRelease:
			case <-ctx.Done():
			}
		}
		backend.mu.Lock()
		backend.active--
		backend.activeByGroup[group]--
		backend.mu.Unlock()
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: group}}, StructuredContent: map[string]any{"group": group}}, nil
	})
	protocol := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	path := filepath.Join(t.TempDir(), "registry.json")
	var connURL string
	backendHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		var envelope struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &envelope)
		backend.mu.Lock()
		backend.methods = append(backend.methods, envelope.Method)
		backend.mu.Unlock()
		// This SDK version starts the stateless Streamable HTTP session with server/discover.
		if (envelope.Method == "initialize" || envelope.Method == "server/discover") && backend.blockInit.Load() {
			backend.initRequests.Add(1)
			backend.initEntered <- struct{}{}
			<-backend.initRelease
		}
		if envelope.Method == "tools/call" {
			backend.callRequests.Add(1)
			if backend.failCall.Load() {
				http.Error(w, "failed", http.StatusBadGateway)
				return
			}
		}
		protocol.ServeHTTP(w, r)
	}))
	t.Cleanup(backendHTTP.Close)
	connURL = backendHTTP.URL + "/mcp"
	grant := config.Grant{AllowedArguments: []string{"group"}, RequiredArguments: []string{"group"}}
	cfg := config.Config{RegistryVersion: 2,
		Servers: map[string]config.Server{"demo": {Enabled: true, URL: connURL, TokenEnv: "TEST_BACKEND_TOKEN", Tools: map[string]config.Tool{"read": {Enabled: true}}}}, Principals: map[string]config.Principal{"local": {ToolAllowlist: map[string][]string{}, AccessPolicy: "legacy_shared",
			TokenEnv: "TEST_CLIENT_TOKEN", Grants: map[string]map[string]config.Grant{"demo": {"read": grant}}}}}
	write := func() {
		b, e := json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write()
	policyPath := filepath.Join(t.TempDir(), "batch-policy.json")
	writePolicy := func(allow bool) {
		entries := []map[string]string{}
		if allow {
			entries = append(entries, map[string]string{"server_id": "demo", "tool_name": "read", "endpoint": connURL})
		}
		b, e := json.Marshal(map[string]any{"version": 1, "operations": entries})
		if e != nil {
			t.Fatal(e)
		}
		if !allow {
			b = []byte(`{"version":1,"operations":[{"server_id":"elsewhere","tool_name":"read","endpoint":"http://127.0.0.1:1234/mcp"}]}`)
		}
		if e = os.WriteFile(policyPath, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writePolicy(true)
	cat := catalog.New()
	t.Cleanup(cat.Close)
	g := &Gateway{Path: path, Catalog: cat, ReadBatch: NewReadBatchExecutor(&ReadBatchPolicy{Path: policyPath}), Timeout: 5 * time.Second}
	return g, http.Header{"Authorization": []string{"Bearer " + clientToken}}, path
}

func batchRaw(group string, n int) json.RawMessage {
	ops := make([]map[string]any, n)
	for i := range ops {
		ops[i] = map[string]any{"id": group + "-" + string(rune('a'+i)), "server_id": "demo", "tool_name": "read", "arguments": map[string]any{"group": group}}
	}
	b, _ := json.Marshal(map[string]any{"operations": ops})
	return b
}

func TestReadBatchBoundsConcurrentDispatchAndBusyAdmission(t *testing.T) {
	backend := &controlledBatchBackend{callRelease: make(chan struct{}), entered: make(chan string, 64), activeByGroup: map[string]int{}, maxByGroup: map[string]int{}}
	backend.blockCalls.Store(true)
	g, headers, _ := newControlledBatchGateway(t, backend)
	var wg sync.WaitGroup
	results := make(chan *mcp.CallToolResult, 4)
	for i := 0; i < 4; i++ {
		group := string(rune('A' + i))
		wg.Add(1)
		go func() { defer wg.Done(); results <- g.readBatch(context.Background(), headers, batchRaw(group, 3)) }()
	}
	for i := 0; i < readBatchGlobalWorkers; i++ {
		select {
		case <-backend.entered:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d global dispatches entered", i)
		}
	}
	if backend.calls.Load() != readBatchGlobalWorkers {
		t.Fatalf("global cap not filled: %d", backend.calls.Load())
	}
	busy := g.readBatch(context.Background(), headers, batchRaw("busy", 1))
	if !busy.IsError {
		t.Fatal("fifth concurrent batch was not rejected busy")
	}
	if backend.calls.Load() != readBatchGlobalWorkers {
		t.Fatal("busy batch reached upstream")
	}
	backend.mu.Lock()
	if backend.maxActive > readBatchGlobalWorkers {
		t.Fatalf("global concurrency %d", backend.maxActive)
	}
	for group, n := range backend.maxByGroup {
		if n > readBatchItemWorkers {
			t.Fatalf("per-batch group %s had %d active", group, n)
		}
	}
	backend.mu.Unlock()
	close(backend.callRelease)
	wg.Wait()
	close(results)
	for result := range results {
		if result == nil || result.IsError {
			t.Fatalf("batch failed: %#v", result)
		}
	}
}

func replaceReadBatchPolicy(t *testing.T, path string) {
	t.Helper()
	b := []byte(`{"version":1,"operations":[{"server_id":"other","tool_name":"read","endpoint":"http://127.0.0.1:1234/mcp"}]}`)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func waitForBatchActive(t *testing.T, b *ReadBatchExecutor, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		active := b.active
		b.mu.Unlock()
		if active == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active batches did not reach %d", want)
}

func TestReadBatchQueuedAdmissionRechecksAllowlistServerAndClientKey(t *testing.T) {
	for _, tc := range []string{"allowlist", "server_disabled", "client_key_revoked"} {
		t.Run(tc, func(t *testing.T) {
			backend := &controlledBatchBackend{entered: make(chan string, 8), activeByGroup: map[string]int{}, maxByGroup: map[string]int{}}
			g, headers, path := newControlledBatchGateway(t, backend)
			for i := 0; i < readBatchGlobalWorkers; i++ {
				g.ReadBatch.global <- struct{}{}
			}
			done := make(chan *mcp.CallToolResult, 1)
			go func() { done <- g.readBatch(context.Background(), headers, batchRaw("queued", 1)) }()
			waitForBatchActive(t, g.ReadBatch, 1)
			switch tc {
			case "allowlist":
				replaceReadBatchPolicy(t, g.ReadBatch.policy.Path)
			case "server_disabled":
				cfg, e := config.Load(path)
				if e != nil {
					t.Fatal(e)
				}
				srv := cfg.Servers["demo"]
				srv.Enabled = false
				cfg.Servers["demo"] = srv
				b, _ := json.Marshal(cfg)
				if e = os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			case "client_key_revoked":
				t.Setenv("TEST_ROTATED_CLIENT_TOKEN", "rotated-client-token-value-123456")
				cfg, e := config.Load(path)
				if e != nil {
					t.Fatal(e)
				}
				principal := cfg.Principals["local"]
				principal.TokenEnv = "TEST_ROTATED_CLIENT_TOKEN"
				cfg.Principals["local"] = principal
				b, _ := json.Marshal(cfg)
				if e = os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			// Release exactly one global permit; the queued worker must reread current authorization.
			<-g.ReadBatch.global
			var result *mcp.CallToolResult
			select {
			case result = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("queued batch did not complete")
			}
			if result == nil || result.IsError {
				t.Fatalf("expected per-item denial result, got %#v", result)
			}
			item := result.StructuredContent.(map[string]any)["results"].([]readBatchItemResult)[0]
			if item.Status != "denied" || item.Dispatched {
				t.Fatalf("stale admission reached dispatch: %#v", item)
			}
			if backend.calls.Load() != 0 {
				t.Fatalf("revoked queued item invoked upstream %d times", backend.calls.Load())
			}
			if len(g.ReadBatch.global) != readBatchGlobalWorkers-1 {
				t.Fatalf("unexpected remaining held permits: %d", len(g.ReadBatch.global))
			}
			g.ReadBatch.global <- struct{}{}
			waitForBatchActive(t, g.ReadBatch, 0)
		})
	}
}

func TestReadBatchRechecksPolicyAfterInitialize(t *testing.T) {
	backend := &controlledBatchBackend{initEntered: make(chan struct{}, 4), initRelease: make(chan struct{}), entered: make(chan string, 4), activeByGroup: map[string]int{}, maxByGroup: map[string]int{}}
	g, headers, _ := newControlledBatchGateway(t, backend)
	config, err := config.Load(g.Path)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := catalog.FromSnapshot(store.Snapshot{Config: config}, "demo")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err = g.Catalog.Get(ctx, conn, false); err != nil {
		t.Fatal("warm schema", err)
	}
	backend.blockInit.Store(true)
	done := make(chan *mcp.CallToolResult, 1)
	go func() { done <- g.readBatch(ctx, headers, batchRaw("init", 1)) }()
	select {
	case <-backend.initEntered:
	case <-ctx.Done():
		backend.mu.Lock()
		methods := append([]string(nil), backend.methods...)
		backend.mu.Unlock()
		t.Fatalf("dispatch initialization did not block; requests=%d calls=%d methods=%v", backend.initRequests.Load(), backend.calls.Load(), methods)
	}
	replaceReadBatchPolicy(t, g.ReadBatch.policy.Path)
	close(backend.initRelease)
	result := <-done
	item := result.StructuredContent.(map[string]any)["results"].([]readBatchItemResult)[0]
	if item.Status != "denied" || item.Dispatched {
		t.Fatalf("revocation during initialize reached dispatch: %#v", item)
	}
	if backend.calls.Load() != 0 {
		t.Fatalf("CallTool ran after initialization revocation: %d", backend.calls.Load())
	}
}

func TestReadBatchCancellationReleasesExecutorSlots(t *testing.T) {
	backend := &controlledBatchBackend{callRelease: make(chan struct{}), entered: make(chan string, 8), activeByGroup: map[string]int{}, maxByGroup: map[string]int{}}
	backend.blockCalls.Store(true)
	g, headers, _ := newControlledBatchGateway(t, backend)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *mcp.CallToolResult, 1)
	go func() { done <- g.readBatch(ctx, headers, batchRaw("cancel", 1)) }()
	select {
	case <-backend.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("call did not enter barrier")
	}
	cancel()
	close(backend.callRelease)
	select {
	case got := <-done:
		item := got.StructuredContent.(map[string]any)["results"].([]readBatchItemResult)[0]
		if !item.Dispatched || (item.Status != "timeout" && item.Status != "ok") {
			t.Fatalf("canceled dispatched call outcome lost: %#v", item)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled batch did not return")
	}
	waitForBatchActive(t, g.ReadBatch, 0)
	if len(g.ReadBatch.global) != 0 {
		t.Fatalf("global slot leaked after cancellation: %d", len(g.ReadBatch.global))
	}
	backend.blockCalls.Store(false)
	again := g.readBatch(context.Background(), headers, batchRaw("after-cancel", 1))
	if again.IsError {
		t.Fatalf("executor did not recover after cancellation: %#v", again)
	}
}

func TestReadBatchTransportFailureIsUnknownAndNotRetried(t *testing.T) {
	backend := &controlledBatchBackend{entered: make(chan string, 4), activeByGroup: map[string]int{}, maxByGroup: map[string]int{}}
	backend.failCall.Store(true)
	g, headers, _ := newControlledBatchGateway(t, backend)
	got := g.readBatch(context.Background(), headers, batchRaw("failure", 1))
	if got.IsError {
		t.Fatalf("item transport failure should be reported per item: %#v", got)
	}
	item := got.StructuredContent.(map[string]any)["results"].([]readBatchItemResult)[0]
	if item.Status != "transport_error" || !item.Dispatched {
		t.Fatalf("transport outcome falsely confirmed: %#v", item)
	}
	if backend.callRequests.Load() != 1 {
		t.Fatalf("transport call was retried %d times", backend.callRequests.Load())
	}
	if backend.calls.Load() != 0 {
		t.Fatalf("failed HTTP request reached tool handler %d times", backend.calls.Load())
	}
}

func TestBoundedReadBatchResultPreservesSDKContent(t *testing.T) {
	got := &mcp.CallToolResult{Meta: mcp.Meta{"trace": "safe"}, Content: []mcp.Content{&mcp.ImageContent{Data: []byte{1, 2, 3}, MIMEType: "image/png"}, &mcp.AudioContent{Data: []byte{4, 5}, MIMEType: "audio/wav"}, &mcp.ResourceLink{URI: "file:///result", Name: "result", MIMEType: "text/plain"}, &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{URI: "file:///embedded", MIMEType: "text/plain", Text: "body"}}}, StructuredContent: map[string]any{"ok": true}}
	res := boundedReadBatchResult(true, []readBatchItemResult{{ID: "id", Status: "ok", Dispatched: true, ToolResult: got}})
	if res.IsError {
		t.Fatal("batch result unexpectedly errored")
	}
	items := res.StructuredContent.(map[string]any)["results"].([]readBatchItemResult)
	if items[0].ToolResult == nil || len(items[0].ToolResult.Content) != 4 {
		t.Fatal("SDK content was not retained")
	}
	if _, ok := items[0].ToolResult.Content[0].(*mcp.ImageContent); !ok {
		t.Fatalf("image content type changed: %T", items[0].ToolResult.Content[0])
	}
	if _, ok := items[0].ToolResult.Content[1].(*mcp.AudioContent); !ok {
		t.Fatalf("audio content type changed: %T", items[0].ToolResult.Content[1])
	}
	if _, ok := items[0].ToolResult.Content[2].(*mcp.ResourceLink); !ok {
		t.Fatalf("resource link type changed: %T", items[0].ToolResult.Content[2])
	}
	if _, ok := items[0].ToolResult.Content[3].(*mcp.EmbeddedResource); !ok {
		t.Fatalf("embedded resource type changed: %T", items[0].ToolResult.Content[3])
	}
	if items[0].ToolResult.Meta["trace"] != "safe" {
		t.Fatal("upstream metadata was not retained")
	}
	if items[0].UpstreamIsError == nil || *items[0].UpstreamIsError {
		t.Fatal("successful result omission state must be explicitly false")
	}
}

func TestReadBatchInputRequiredResultIsIncompleteAndPreserved(t *testing.T) {
	var upstreamResult mcp.CallToolResult
	if err := json.Unmarshal([]byte(`{"content":[],"inputRequests":{},"requestState":"opaque-state","resultType":"input_required"}`), &upstreamResult); err != nil {
		t.Fatal(err)
	}
	if !upstreamResult.NeedsInput() {
		t.Fatal("fixture did not decode as input_required")
	}
	var item readBatchItemResult
	processReadBatchUpstreamResult(&item, &upstreamResult)
	if item.Status != "upstream_error" || item.UpstreamIsError == nil || *item.UpstreamIsError || item.ToolResult == nil || !item.ToolResult.NeedsInput() || item.ToolResult.RequestState != "opaque-state" || item.ToolResult.InputRequests == nil {
		t.Fatalf("input-required outcome was not preserved as incomplete: %#v", item)
	}
}

func TestReadBatchActualSDKWireResponseRespectsBudget(t *testing.T) {
	items := make([]readBatchItemResult, 3)
	for i := range items {
		items[i] = readBatchItemResult{ID: string(rune('a' + i)), Status: "ok", Dispatched: true, ToolResult: &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", 43562)}}}}
	}
	batchResult := boundedReadBatchResult(true, items)
	var wireBytes atomic.Int32
	server := mcp.NewServer(&mcp.Implementation{Name: "wire-budget-test", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "batch", InputSchema: map[string]any{"type": "object", "additionalProperties": false}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return batchResult, nil })
	protocol := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &request)
		r.Body = io.NopCloser(bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		protocol.ServeHTTP(recorder, r)
		if request.Method == "tools/call" {
			wireBytes.Store(int32(recorder.Body.Len()))
		}
		for key, values := range recorder.Header() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	}))
	defer web.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := mcp.NewClient(&mcp.Implementation{Name: "wire-budget-client", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: web.URL + "/mcp", HTTPClient: &http.Client{Timeout: time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.CallTool(ctx, &mcp.CallToolParams{Name: "batch", Arguments: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if got := int(wireBytes.Load()); got == 0 || got > readBatchOutputBudget {
		t.Fatalf("actual SDK JSON-RPC response size %d exceeds %d", got, readBatchOutputBudget)
	}
}

func TestReadBatchLargeItemIsOmittedWithoutChangingDispatch(t *testing.T) {
	large := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", readBatchItemBudget)}}}
	items := []readBatchItemResult{{ID: "id", Status: "ok", Dispatched: true, ToolResult: large}}
	res := boundedReadBatchResult(true, items)
	out := res.StructuredContent.(map[string]any)
	item := out["results"].([]readBatchItemResult)[0]
	if item.Status != "result_omitted" || !item.Dispatched || item.ToolResult != nil {
		t.Fatalf("unexpected omitted result: %#v", item)
	}
}

func TestReadBatchAggregateBudgetOmitsPayloadsWithoutRetry(t *testing.T) {
	items := make([]readBatchItemResult, readBatchMaxItems)
	for i := range items {
		items[i] = readBatchItemResult{ID: string(rune('a' + i)), Status: "ok", Dispatched: true, ToolResult: &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", 40<<10)}}}}
	}
	result := boundedReadBatchResult(true, items)
	if serializedSize(result) > readBatchOutputBudget {
		t.Fatalf("aggregate result exceeds budget: %d", serializedSize(result))
	}
	out := result.StructuredContent.(map[string]any)
	if out["complete"] != false {
		t.Fatal("omitted aggregate result was marked complete")
	}
	got := out["results"].([]readBatchItemResult)
	for _, item := range got {
		if item.ToolResult != nil || item.Status != "result_omitted" || !item.Dispatched {
			t.Fatalf("unexpected aggregate omission: %#v", item)
		}
	}
}
