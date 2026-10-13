package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/config"
)

func TestReadOnceDisablesSDKLoadSheddingContinuation(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "load-shedding-fixture", Version: "1"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	var calls atomic.Int32
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var req struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		json.Unmarshal(body, &req)
		if req.Method == "tools/call" {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"resultType": "input_required", "inputRequests": map[string]any{}, "requestState": "synthetic-state"}})
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer web.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, close, err := ConnectReadOnceWithToken(ctx, config.Server{URL: web.URL + "/mcp"}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "read", Arguments: map[string]any{}})
	if calls.Load() != 1 {
		t.Fatalf("SDK automatically continued invocation: calls=%d err=%v", calls.Load(), err)
	}
	if err == nil && (result == nil || !result.NeedsInput()) {
		t.Fatalf("input-required result silently completed: %#v", result)
	}
}
