package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/policy"
	"mcp-gateway/internal/readpolicy"
	"mcp-gateway/internal/store"
	"mcp-gateway/internal/upstream"
)

func (g *Gateway) cached(ctx context.Context, snapshot store.Snapshot, principal string, a input, operation string, headers http.Header) *mcp.CallToolResult {
	c, err := catalog.FromSnapshot(snapshot, a.Server)
	if err != nil {
		return failure(err)
	}
	tools, refreshed, err := g.Catalog.GetWithStatus(ctx, c, false)
	if err != nil {
		return failure(err)
	}
	snapshot, principal, _, err = g.admitOperation(ctx, headers, a, c, false)
	if err != nil {
		return failure(err)
	}
	if operation == "discover_tools" {
		type item struct {
			Name             string `json:"name"`
			Description      string `json:"description"`
			BatchReadAllowed bool   `json:"batch_read_allowed"`
			BatchReadReason  string `json:"batch_read_reason"`
			OperationKind    string `json:"operation_kind,omitempty"`
			OperationSource  string `json:"operation_source,omitempty"`
			OperationReason  string `json:"operation_reason,omitempty"`
		}
		out := []item{}
		for _, t := range tools {
			if _, err := policy.Grant(snapshot.Config, principal, a.Server, t.Name); err == nil {
				allowed, reason := g.batchEligibility(a.Server, snapshot.Config.Servers[a.Server], t, catalog.ConnectionBinding(c))
				setting := snapshot.Config.Servers[a.Server].Tools[t.Name]
				operation := readpolicy.ClassifyOperation(setting.OperationKind, setting.OperationContractHash, t, catalog.ConnectionBinding(c))
				out = append(out, item{t.Name, t.Description, allowed, reason, operation.Kind, operation.Source, operation.Reason})
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return result(map[string]any{"tools": out})
	}
	find := func(ts []*mcp.Tool) *mcp.Tool {
		for _, t := range ts {
			if t.Name == a.Tool {
				return t
			}
		}
		return nil
	}
	tool := find(tools)
	// Refresh a missing authorized name only if this lookup used an existing cache.
	if tool == nil && !refreshed {
		tools, err = g.Catalog.Get(ctx, c, true)
		if err != nil {
			return failure(err)
		}
		tool = find(tools)
	}
	if _, _, _, err = g.admitOperation(ctx, headers, a, c, false); err != nil {
		return failure(err)
	}
	if tool == nil {
		return failure(errors.New("tool unavailable"))
	}
	if operation == "get_tool_schema" {
		return result(tool)
	}
	if err = upstream.Validate(tool.InputSchema, a.Arguments); err != nil {
		return failure(err)
	}
	if _, _, _, err = g.admitOperation(ctx, headers, a, c, true); err != nil {
		return failure(err)
	}
	s, close, err := upstream.ConnectWithToken(ctx, c.Server, c.Token)
	if err != nil {
		return failure(err)
	}
	defer close()
	if err = g.checkDispatch(ctx, headers, a, c, tool); err != nil {
		return failure(err)
	}
	markDispatched(ctx)
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: a.Tool, Arguments: a.Arguments})
	if err != nil {
		g.Catalog.Invalidate(c.ID, c.Revision)
		return failure(upstream.ErrUpstream)
	}
	if res.IsError {
		g.Catalog.Invalidate(c.ID, c.Revision)
	}
	return res
}

const searchBudget = 128 << 10

type searchItem struct {
	ServerID         string    `json:"server_id"`
	ToolName         string    `json:"tool_name"`
	Description      string    `json:"description"`
	Definition       *mcp.Tool `json:"tool_definition,omitempty"`
	SchemaIncluded   bool      `json:"schema_included"`
	OmittedReason    string    `json:"schema_omitted_reason,omitempty"`
	BatchReadAllowed bool      `json:"batch_read_allowed"`
	BatchReadReason  string    `json:"batch_read_reason"`
	OperationKind    string    `json:"operation_kind,omitempty"`
	OperationSource  string    `json:"operation_source,omitempty"`
	OperationReason  string    `json:"operation_reason,omitempty"`
	score            int
}
type searchResult struct {
	Tools       []searchItem `json:"tools"`
	Complete    bool         `json:"complete"`
	Unavailable []string     `json:"unavailable_servers"`
	Truncated   bool         `json:"results_truncated,omitempty"`
}

func (g *Gateway) search(ctx context.Context, snapshot store.Snapshot, principal string, a input, headers http.Header) *mcp.CallToolResult {
	if g.Catalog == nil || strings.TrimSpace(a.Query) == "" || len(a.Query) > 512 {
		return failure(ErrArguments)
	}
	if a.Limit == 0 {
		a.Limit = 5
	}
	if a.Limit < 1 || a.Limit > 10 {
		return failure(ErrArguments)
	}
	if a.Server != "" && !policy.Visible(snapshot.Config, principal, a.Server) {
		return failure(policy.ErrDenied)
	}
	ids := []string{}
	for id := range snapshot.Config.Servers {
		if (a.Server == "" || a.Server == id) && policy.Visible(snapshot.Config, principal, id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	// Bound fan-out and response metadata; callers can narrow an unusually large registry.
	if len(ids) > 256 {
		return failure(errors.New("too many available servers; specify server_id"))
	}
	out := searchResult{Tools: []searchItem{}, Complete: true, Unavailable: []string{}}
	candidates := []searchItem{}
	words := strings.Fields(strings.ToLower(a.Query))
	var mu sync.Mutex
	var wg sync.WaitGroup
	workers := make(chan struct{}, 4)
	less := func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].ServerID != candidates[j].ServerID {
			return candidates[i].ServerID < candidates[j].ServerID
		}
		return candidates[i].ToolName < candidates[j].ToolName
	}
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case workers <- struct{}{}:
				defer func() { <-workers }()
			case <-ctx.Done():
				mu.Lock()
				out.Complete = false
				out.Unavailable = append(out.Unavailable, id)
				mu.Unlock()
				return
			}
			c, err := catalog.FromSnapshot(snapshot, id)
			var tools []*mcp.Tool
			if err == nil {
				tools, err = g.Catalog.Get(ctx, c, false)
			}
			current, identity, _, authErr := g.admitOperation(ctx, headers, input{Server: id}, c, false)
			mu.Lock()
			defer mu.Unlock()
			if authErr != nil {
				return
			}
			if err != nil {
				out.Complete = false
				out.Unavailable = append(out.Unavailable, id)
				return
			}
			server := current.Config.Servers[id]
			serverText := strings.ToLower(id + " " + server.Description + " " + strings.Join(server.Keywords, " "))
			for _, t := range tools {
				if _, err := policy.Grant(current.Config, identity, id, t.Name); err != nil {
					continue
				}
				score := 0
				for _, word := range words {
					if strings.Contains(strings.ToLower(t.Name), word) {
						score += 3
					}
					if strings.Contains(strings.ToLower(t.Description), word) {
						score += 2
					}
					if strings.Contains(serverText, word) {
						score++
					}
				}
				if score > 0 {
					allowed, reason := g.batchEligibility(id, server, t, catalog.ConnectionBinding(c))
					setting := server.Tools[t.Name]
					operation := readpolicy.ClassifyOperation(setting.OperationKind, setting.OperationContractHash, t, catalog.ConnectionBinding(c))
					candidates = append(candidates, searchItem{OperationKind: operation.Kind, OperationSource: operation.Source, OperationReason: operation.Reason, BatchReadAllowed: allowed, BatchReadReason: reason, ServerID: id, ToolName: t.Name, Description: t.Description, Definition: t, SchemaIncluded: true, score: score})
					if len(candidates) > a.Limit {
						sort.Slice(candidates, less)
						candidates = candidates[:a.Limit]
					}
				}
			}
		}()
	}
	wg.Wait()
	latest, e := g.snapshot(ctx)
	if e != nil {
		return failure(e)
	}
	identity, e := resolvePrincipal(ctx, latest.Config, headers)
	if expected, ok := ctx.Value(admittedPrincipalKey{}).(string); e != nil || (ok && expected != identity) {
		return failure(policy.ErrDenied)
	}
	filtered := candidates[:0]
	for _, item := range candidates {
		if _, e := policy.Grant(latest.Config, identity, item.ServerID, item.ToolName); e == nil {
			old, _ := catalog.FromSnapshot(snapshot, item.ServerID)
			next, er := catalog.FromSnapshot(latest, item.ServerID)
			if er == nil && catalog.Fingerprint(old) == catalog.Fingerprint(next) {
				filtered = append(filtered, item)
			}
		}
	}
	if len(filtered) != len(candidates) {
		out.Complete = false
	}
	candidates = filtered
	visible := out.Unavailable[:0]
	for _, id := range out.Unavailable {
		if policy.Visible(latest.Config, identity, id) {
			visible = append(visible, id)
		}
	}
	out.Unavailable = visible
	sort.Strings(out.Unavailable)
	if len(ids) > 0 && len(out.Unavailable) == len(ids) {
		return failure(errors.New("available server catalogs could not be loaded"))
	}
	sort.Slice(candidates, less)
	if len(candidates) > a.Limit {
		candidates = candidates[:a.Limit]
	}
	fits := func() bool { b, err := json.Marshal(result(out)); return err == nil && len(b) <= searchBudget }
	for _, item := range candidates {
		out.Tools = append(out.Tools, item)
		if !fits() {
			item.Definition = nil
			item.SchemaIncluded = false
			item.OmittedReason = "response_budget"
			out.Tools[len(out.Tools)-1] = item
		}
		if !fits() {
			out.Tools = out.Tools[:len(out.Tools)-1]
			out.Truncated = true
			break
		}
	}
	if !fits() {
		return failure(errors.New("search response exceeds budget"))
	}
	return result(out)
}

func (g *Gateway) batchEligibility(id string, s config.Server, t *mcp.Tool, binding ...string) (bool, string) {
	if g.ReadBatch == nil {
		return false, "batch_disabled"
	}
	if g.ReadBatch.ClassifiedMode() {
		return s.ClassifiedReadDecision(t, binding...)
	}
	if g.ReadBatch.RegistryMode() {
		return s.BatchReadDecision(t)
	}
	if s.Enabled && s.Tools[t.Name].Enabled && g.ReadBatch.policy.Allows(id, t.Name, s.URL) == nil {
		return true, "operator_file_read"
	}
	return false, "operator_file_denied"
}
