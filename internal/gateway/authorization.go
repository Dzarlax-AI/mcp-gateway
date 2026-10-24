package gateway

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/policy"
	"mcp-gateway/internal/store"
	"mcp-gateway/internal/upstream"
	"net/http"
	"sync/atomic"
)

// admitOperation always resolves current identity and policy, even for a warm catalog.
func (g *Gateway) admitOperation(ctx context.Context, headers http.Header, a input, binding catalog.Connection, invoke bool) (store.Snapshot, string, catalog.Connection, error) {
	snap, e := g.snapshot(ctx)
	if e != nil {
		return snap, "", catalog.Connection{}, e
	}
	if trace, ok := ctx.Value(callTraceKey{}).(*callTrace); ok {
		trace.revision.Store(snap.Revision)
	}
	p, e := resolvePrincipal(ctx, snap.Config, headers)
	if expected, ok := ctx.Value(admittedPrincipalKey{}).(string); e != nil || (ok && expected != p) {
		return snap, "", catalog.Connection{}, policy.ErrDenied
	}
	if !policy.Visible(snap.Config, p, a.Server) {
		return snap, p, catalog.Connection{}, policy.ErrDenied
	}
	if a.Tool != "" {
		grant, e := policy.Grant(snap.Config, p, a.Server, a.Tool)
		if e != nil {
			return snap, p, catalog.Connection{}, policy.ErrDenied
		}
		if invoke && policy.Arguments(grant, a.Arguments) != nil {
			return snap, p, catalog.Connection{}, policy.ErrDenied
		}
	}
	conn, e := catalog.FromSnapshot(snap, a.Server)
	if e != nil {
		return snap, p, conn, e
	}
	if catalog.Fingerprint(conn) != catalog.Fingerprint(binding) {
		return snap, p, conn, policy.ErrDenied
	}
	return snap, p, conn, nil
}
func (g *Gateway) checkDispatch(ctx context.Context, headers http.Header, a input, binding catalog.Connection, tool *mcp.Tool) error {
	_, _, conn, e := g.admitOperation(ctx, headers, a, binding, true)
	if e != nil {
		return e
	}
	if g.Catalog != nil {
		tools, e := g.Catalog.Get(ctx, conn, false)
		if e != nil {
			return e
		}
		tool = nil
		for _, t := range tools {
			if t.Name == a.Tool {
				tool = t
				break
			}
		}
		if tool == nil {
			return policy.ErrDenied
		}
	}
	if _, _, _, e = g.admitOperation(ctx, headers, a, binding, true); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return upstream.Validate(tool.InputSchema, a.Arguments)
}

type admittedPrincipalKey struct{}

type callTraceKey struct{}
type callTrace struct {
	dispatched bool
	revision   atomic.Int64
}

func markDispatched(ctx context.Context) {
	if t, ok := ctx.Value(callTraceKey{}).(*callTrace); ok {
		t.dispatched = true
	}
}
