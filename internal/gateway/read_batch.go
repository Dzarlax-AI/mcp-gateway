package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/policy"
	"mcp-gateway/internal/store"
	"mcp-gateway/internal/upstream"
)

const (
	readBatchMaxItems      = 8
	readBatchMaxActive     = 4
	readBatchGlobalWorkers = 8
	readBatchItemWorkers   = 3
	readBatchItemBudget    = 64 << 10
	readBatchOutputBudget  = 256 << 10
	readBatchSDKReserve    = 1 << 10
)

var readBatchID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type ReadBatchExecutor struct {
	policy *ReadBatchPolicy
	mu     sync.Mutex
	active int
	global chan struct{}
}

func NewReadBatchExecutor(policy *ReadBatchPolicy) *ReadBatchExecutor {
	return &ReadBatchExecutor{policy: policy, global: make(chan struct{}, readBatchGlobalWorkers)}
}

func (b *ReadBatchExecutor) Validate() error {
	if b == nil {
		return readBatchDenied
	}
	return b.policy.Validate()
}

type readBatchOperation struct {
	ID        string          `json:"id"`
	ServerID  string          `json:"server_id"`
	ToolName  string          `json:"tool_name"`
	Arguments json.RawMessage `json:"arguments"`
}

type readBatchRequest struct {
	Operations []readBatchOperation `json:"operations"`
}

type readBatchItemResult struct {
	ID              string              `json:"id"`
	Status          string              `json:"status"`
	Dispatched      bool                `json:"dispatched"`
	ToolResult      *mcp.CallToolResult `json:"tool_result,omitempty"`
	UpstreamIsError *bool               `json:"upstream_is_error,omitempty"`
}

func decodeReadBatch(raw json.RawMessage) ([]readBatchOperation, bool) {
	if rejectDuplicateJSONKeys(raw) != nil {
		return nil, false
	}
	var req readBatchRequest
	d := json.NewDecoder(bytesReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || len(req.Operations) < 1 || len(req.Operations) > readBatchMaxItems {
		return nil, false
	}
	seen := map[string]bool{}
	for _, op := range req.Operations {
		if !readBatchID.MatchString(op.ID) || seen[op.ID] || op.ServerID == "" || op.ToolName == "" || len(op.Arguments) == 0 || string(op.Arguments) == "null" {
			return nil, false
		}
		seen[op.ID] = true
		var args map[string]any
		dec := json.NewDecoder(bytesReader(op.Arguments))
		dec.UseNumber()
		if dec.Decode(&args) != nil || args == nil {
			return nil, false
		}
		if dec.Decode(new(any)) != io.EOF {
			return nil, false
		}
	}
	return req.Operations, true
}

// Small wrappers keep the batch parser's strict decoder behavior explicit.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func (g *Gateway) readBatch(ctx context.Context, headers http.Header, raw json.RawMessage) *mcp.CallToolResult {
	ops, ok := decodeReadBatch(raw)
	if !ok {
		return failure(ErrArguments)
	}
	b := g.ReadBatch
	if b == nil || g.Catalog == nil {
		return failure(readBatchDenied)
	}
	b.mu.Lock()
	if b.active >= readBatchMaxActive {
		b.mu.Unlock()
		return failure(errReadBatchBusy)
	}
	b.active++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.active--; b.mu.Unlock() }()
	if b.policy.Validate() != nil {
		return failure(readBatchDenied)
	}
	duration := g.Timeout
	if duration <= 0 {
		duration = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	results := make([]readBatchItemResult, len(ops))
	for i, op := range ops {
		results[i] = readBatchItemResult{ID: op.ID, Status: "unavailable"}
	}
	jobs := make(chan int, len(ops))
	for i := range ops {
		jobs <- i
	}
	close(jobs)
	workers := readBatchItemWorkers
	if len(ops) < workers {
		workers = len(ops)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				select {
				case b.global <- struct{}{}:
				case <-ctx.Done():
					mu.Lock()
					results[i].Status = "timeout"
					mu.Unlock()
					continue
				}
				r := b.execute(ctx, g, headers, ops[i])
				<-b.global
				mu.Lock()
				results[i] = r
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	complete := true
	for i := range results {
		if results[i].Status != "ok" {
			complete = false
		}
	}
	return boundedReadBatchResult(complete, results)
}

var errReadBatchBusy = errors.New("read batch busy")

func (b *ReadBatchExecutor) execute(ctx context.Context, g *Gateway, headers http.Header, op readBatchOperation) readBatchItemResult {
	r := readBatchItemResult{ID: op.ID, Status: "denied"}
	var args map[string]any
	d := json.NewDecoder(bytesReader(op.Arguments))
	d.UseNumber()
	if d.Decode(&args) != nil || args == nil {
		r.Status = "invalid_arguments"
		return r
	}
	if ctx.Err() != nil {
		r.Status = "timeout"
		return r
	}
	admit := func() (store.Snapshot, string, catalog.Connection, error) {
		return readBatchAdmit(ctx, g, b.policy, headers, op, args)
	}
	snapshot, principal, conn, err := admit()
	if err != nil {
		r.Status = readBatchAdmissionStatus(ctx, err)
		return r
	}
	tools, refreshed, err := g.Catalog.GetWithStatus(ctx, conn, false)
	if err != nil {
		if ctx.Err() != nil {
			r.Status = "timeout"
		} else {
			r.Status = "unavailable"
		}
		return r
	}
	find := func() *mcp.Tool {
		for _, tool := range tools {
			if tool.Name == op.ToolName {
				return tool
			}
		}
		return nil
	}
	tool := find()
	if tool == nil && !refreshed {
		tools, err = g.Catalog.Get(ctx, conn, true)
		if err == nil {
			tool = find()
		}
	}
	if err != nil || tool == nil {
		if ctx.Err() != nil {
			r.Status = "timeout"
		} else {
			r.Status = "unavailable"
		}
		return r
	}
	if upstream.Validate(tool.InputSchema, args) != nil {
		r.Status = "invalid_arguments"
		return r
	}
	// Refresh current auth, grants, arguments, and the exact connection immediately before transport setup.
	_, _, beforeConnect, err := admit()
	if err != nil {
		r.Status = readBatchAdmissionStatus(ctx, err)
		return r
	}
	if catalog.Fingerprint(conn) != catalog.Fingerprint(beforeConnect) {
		return r
	}
	session, closeFn, err := upstream.ConnectReadOnceWithToken(ctx, conn.Server, conn.Token)
	if err != nil {
		if ctx.Err() != nil {
			r.Status = "timeout"
		} else {
			r.Status = "unavailable"
		}
		return r
	}
	defer closeFn()
	// initialize may block while credentials or grants are revoked; recheck before CallTool.
	_, _, beforeDispatch, err := admit()
	if err != nil || catalog.Fingerprint(conn) != catalog.Fingerprint(beforeDispatch) {
		if err != nil {
			r.Status = readBatchAdmissionStatus(ctx, err)
		}
		return r
	}
	if ctx.Err() != nil {
		r.Status = "timeout"
		return r
	}
	r.Dispatched = true
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: op.ToolName, Arguments: args})
	if err != nil || res == nil {
		g.Catalog.Invalidate(conn.ID, conn.Revision)
		if ctx.Err() != nil {
			r.Status = "timeout"
		} else {
			r.Status = "transport_error"
		}
		return r
	}
	processReadBatchUpstreamResult(&r, res)
	if res.IsError {
		g.Catalog.Invalidate(conn.ID, conn.Revision)
	}
	_ = snapshot
	_ = principal
	return r
}

func processReadBatchUpstreamResult(item *readBatchItemResult, res *mcp.CallToolResult) {
	upstreamIsError := res.IsError
	item.UpstreamIsError = &upstreamIsError
	if res.IsError || res.NeedsInput() {
		item.Status = "upstream_error"
	} else {
		item.Status = "ok"
	}
	copyResult := *res
	item.ToolResult = &copyResult
}

func readBatchAdmissionStatus(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "timeout"
	}
	if errors.Is(err, readBatchDenied) {
		return "denied"
	}
	return "unavailable"
}

func readBatchAdmit(ctx context.Context, g *Gateway, p *ReadBatchPolicy, headers http.Header, op readBatchOperation, args map[string]any) (store.Snapshot, string, catalog.Connection, error) {
	snapshot, err := g.snapshot(ctx)
	if err != nil {
		return snapshot, "", catalog.Connection{}, err
	}
	principal, err := snapshot.Config.AuthenticateHeaders(headers)
	if err != nil {
		return snapshot, "", catalog.Connection{}, readBatchDenied
	}
	grant, err := policy.Grant(snapshot.Config, principal, op.ServerID, op.ToolName)
	if err != nil || policy.Arguments(grant, args) != nil {
		return snapshot, "", catalog.Connection{}, readBatchDenied
	}
	server, ok := snapshot.Config.Servers[op.ServerID]
	if !ok || p.Allows(op.ServerID, op.ToolName, server.URL) != nil {
		return snapshot, "", catalog.Connection{}, readBatchDenied
	}
	conn, err := catalog.FromSnapshot(snapshot, op.ServerID)
	if err != nil {
		return snapshot, "", catalog.Connection{}, err
	}
	return snapshot, principal, conn, nil
}

func boundedReadBatchResult(complete bool, items []readBatchItemResult) *mcp.CallToolResult {
	for i := range items {
		if items[i].ToolResult != nil && items[i].UpstreamIsError == nil {
			upstreamIsError := items[i].ToolResult.IsError
			items[i].UpstreamIsError = &upstreamIsError
		}
		if items[i].ToolResult != nil && serializedSize(items[i].ToolResult) > readBatchItemBudget {
			items[i].ToolResult = nil
			items[i].Status = "result_omitted"
			complete = false
		}
	}
	out := map[string]any{"complete": complete, "results": items}
	res := result(out)
	if serializedSize(res) <= readBatchOutputBudget-readBatchSDKReserve {
		return res
	}
	for i := range items {
		if items[i].ToolResult != nil {
			items[i].ToolResult = nil
			items[i].Status = "result_omitted"
		}
	}
	return result(map[string]any{"complete": false, "results": items})
}

func serializedSize(v any) int {
	b, e := json.Marshal(v)
	if e != nil {
		return readBatchOutputBudget + 1
	}
	return len(b)
}
