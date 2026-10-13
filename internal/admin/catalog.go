package admin

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/store"
)

// Publish only committed checks. A failed check or CAS never reaches this hook.
func (h *handler) updateCatalog(before, after store.Snapshot, id string, p *probe, fresh bool) {
	if h.catalog == nil {
		return
	}
	c, err := catalog.FromSnapshot(after, id)
	if err != nil {
		h.catalog.Invalidate(id, after.Revision)
		return
	}
	if fresh && p != nil {
		// Bind the metadata to the exact credentials used for its connection check.
		if p.key != connectionDigest(c.Server, c.Token, after.Config.HTTPSAllowlist) {
			h.catalog.Invalidate(id, after.Revision)
			return
		}
		tools := make([]*mcp.Tool, 0, len(p.tools))
		for _, t := range p.tools {
			tools = append(tools, t)
		}
		if err := h.catalog.Publish(c, after.Revision, p.at, tools); err != nil {
			h.catalog.Invalidate(id, after.Revision)
		}
		return
	}
	old, err := catalog.FromSnapshot(before, id)
	if err != nil || catalog.Fingerprint(old) != catalog.Fingerprint(c) || !sameToolNames(before, after, id) {
		h.catalog.Invalidate(id, after.Revision)
	}
}

func sameToolNames(before, after store.Snapshot, id string) bool {
	old, next := before.Config.Servers[id].Tools, after.Config.Servers[id].Tools
	if len(old) != len(next) {
		return false
	}
	for name := range old {
		if _, ok := next[name]; !ok {
			return false
		}
	}
	return true
}
