package admin

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/readpolicy"
	"mcp-gateway/internal/store"
)

func serverPathParts(path string) []string {
	if !strings.HasPrefix(path, "/admin/servers/") {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "/admin/servers/"), "/")
	if len(parts) < 1 || !config.ValidIdentifier(parts[0]) {
		return nil
	}
	return parts
}
func isServerDetailPath(path string) bool { return len(serverPathParts(path)) == 1 }
func isBulkToolPath(path string) bool {
	p := serverPathParts(path)
	return len(p) == 2 && (p[1] == "bulk-enable" || p[1] == "bulk-disable" || p[1] == "bulk-operation")
}
func (h *handler) returnURL(r *http.Request, id string) string {
	list := h.a.basePath + "/admin/servers"
	if h.batchClassified && config.ValidIdentifier(id) && !strings.HasSuffix(r.URL.Path, "/delete") {
		return list + "/" + url.PathEscape(id)
	}
	return list
}
func operationLabel(d readpolicy.OperationDecision) string {
	switch d.Kind {
	case "read":
		if d.Source == "manual" {
			return "Read · manual"
		}
		return "Read · automatic"
	case "write":
		if d.Source == "manual" {
			return "Write · manual"
		}
		return "Write · automatic"
	default:
		return "Unclassified"
	}
}

// managementCatalog uses the same bounded metadata as dispatch, without extending
// its TTL. Only an explicit management operation may refresh an absent catalog.
func (h *handler) managementCatalog(r *http.Request, snap store.Snapshot, id string) (probe, bool, error) {
	if conn, err := catalog.FromSnapshot(snap, id); err == nil {
		if meta, ok := h.catalog.Peek(conn); ok && meta.Fresh {
			tools := map[string]*mcp.Tool{}
			for _, tool := range meta.Tools {
				tools[tool.Name] = tool
			}
			return probe{revision: snap.Revision, key: connectionDigest(conn.Server, conn.Token, snap.Config.HTTPSAllowlist), at: meta.At, tools: tools}, false, nil
		}
	}
	p, err := h.check(r.Context(), snap, id, snap.Config.Servers[id])
	return p, true, err
}

func (h *handler) managementError(w http.ResponseWriter, r *http.Request, snap store.Snapshot, csrf, user, message string, code int) {
	if !wantsJSON(r) && h.batchClassified {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		// Keep the trusted error separate from submitted form values. Secrets are never
		// copied into rendering state or responses.
		h.renderWorkspaceError(w, r, snap, csrf, user, message, code)
		return
	}
	h.inputError(w, r, snap, csrf, user, message, code)
}

func (h *handler) toolManagement(w http.ResponseWriter, r *http.Request, snap store.Snapshot, csrf, user string) bool {
	parts := serverPathParts(r.URL.Path)
	if len(parts) != 2 || (parts[1] != "bulk-enable" && parts[1] != "bulk-disable" && parts[1] != "tool-operation" && parts[1] != "bulk-operation") {
		return false
	}
	if !h.batchClassified {
		http.NotFound(w, r)
		return true
	}
	id, action := parts[0], parts[1]
	server, exists := snap.Config.Servers[id]
	if !exists {
		http.NotFound(w, r)
		return true
	}
	fail := func(message string, status int) { h.managementError(w, r, snap, csrf, user, message, status) }
	c := clone(snap.Config)
	var next *probe
	fresh := false
	if action == "tool-operation" {
		name, kind := r.Form.Get("tool"), r.Form.Get("operation_kind")
		setting, ok := server.Tools[name]
		if !ok || (kind != "" && kind != "read" && kind != "write") {
			fail("Invalid tool classification.", 400)
			return true
		}
		setting.OperationKind, setting.OperationContractHash = kind, ""
		if kind == "read" {
			p, checked, err := h.managementCatalog(r, snap, id)
			if err != nil {
				fail("Could not verify the current tool catalog. No changes were saved.", 502)
				return true
			}
			tool := p.tools[name]
			conn, connectionErr := catalog.FromSnapshot(snap, id)
			if connectionErr != nil {
				fail("Connection unavailable.", 503)
				return true
			}
			hash, err := readpolicy.OperationFingerprint(tool, catalog.ConnectionBinding(conn))
			if err != nil || r.Form.Get("contract_hash") == "" || r.Form.Get("contract_hash") != hash {
				fail("Tool definition changed or is unavailable. Refresh the catalog before classifying it as a read.", 409)
				return true
			}
			setting.OperationContractHash = hash
			next, fresh = &p, checked
		}
		server.Tools[name] = setting
	} else {
		names := r.Form["tools"]
		if len(names) == 0 || len(names) > 500 {
			fail("Select between 1 and 500 tools.", 400)
			return true
		}
		seen := map[string]bool{}
		for _, name := range names {
			if !config.ValidIdentifier(name) || seen[name] {
				fail("Invalid or repeated tool selection.", 400)
				return true
			}
			if _, ok := server.Tools[name]; !ok {
				fail("A selected tool no longer exists. Refresh the selection.", 409)
				return true
			}
			seen[name] = true
		}
		group := r.Form.Get("selection_kind")
		if group != "" && group != "read" && group != "write" && group != "unknown" {
			fail("Invalid operation group.", 400)
			return true
		}
		if action == "bulk-operation" {
			kinds, present := r.Form["operation_kind"]
			if !present || len(kinds) != 1 || (kinds[0] != "" && kinds[0] != "read" && kinds[0] != "write") {
				fail("Choose Read, Write or Automatic for the selected tools.", 400)
				return true
			}
			kind := kinds[0]
			hashes := map[string]string{}
			if kind == "read" {
				p, checked, err := h.managementCatalog(r, snap, id)
				if err != nil {
					fail("Could not verify the current tool catalog. No classifications were saved.", 502)
					return true
				}
				conn, err := catalog.FromSnapshot(snap, id)
				if err != nil {
					fail("Connection unavailable.", 503)
					return true
				}
				for _, name := range names {
					hash, err := readpolicy.OperationFingerprint(p.tools[name], catalog.ConnectionBinding(conn))
					if err != nil || r.Form.Get("contract."+name) != hash {
						fail("A selected tool definition changed or is unavailable. Refresh before marking the selection as reads. No classifications were saved.", 409)
						return true
					}
					hashes[name] = hash
				}
				next, fresh = &p, checked
			}
			for _, name := range names {
				setting := server.Tools[name]
				setting.OperationKind, setting.OperationContractHash = kind, hashes[name]
				server.Tools[name] = setting
			}
		} else {
			if action == "bulk-disable" && group != "" {
				conn, err := catalog.FromSnapshot(snap, id)
				if err != nil {
					fail("Connection unavailable. Refresh the selection.", 409)
					return true
				}
				metadata, _ := h.catalog.Peek(conn)
				defs := map[string]*mcp.Tool{}
				for _, tool := range metadata.Tools {
					defs[tool.Name] = tool
				}
				for _, name := range names {
					setting := server.Tools[name]
					d := readpolicy.ClassifyOperation(setting.OperationKind, setting.OperationContractHash, defs[name], catalog.ConnectionBinding(conn))
					if d.Kind != group {
						fail("The type of a selected tool changed. Refresh the selection before disabling it.", 409)
						return true
					}
				}
			}
			if action == "bulk-enable" {
				p, checked, err := h.managementCatalog(r, snap, id)
				if err != nil {
					fail("Connection check failed. No selected tools were enabled.", 502)
					return true
				}
				for _, name := range names {
					tool := p.tools[name]
					if tool == nil {
						fail("A selected tool is missing from the current catalog. No changes were saved.", 409)
						return true
					}
					setting := server.Tools[name]
					conn, _ := catalog.FromSnapshot(snap, id)
					d := readpolicy.ClassifyOperation(setting.OperationKind, setting.OperationContractHash, tool, catalog.ConnectionBinding(conn))
					if group != "" && d.Kind != group {
						fail("The type of a selected tool changed. Refresh and review the selection before enabling it.", 409)
						return true
					}
				}
				reconcileCatalogACL(c, id, &server, p.tools)
				next, fresh = &p, checked
			}
			for _, name := range names {
				setting := server.Tools[name]
				setting.Enabled = action == "bulk-enable"
				server.Tools[name] = setting
			}
		}
	}
	c.Servers[id] = server
	if c.Validate() != nil {
		fail("Invalid tool settings. No changes were saved.", 400)
		return true
	}
	saved, err := h.s.CompareAndSwap(r.Context(), snap.Revision, c, nil)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			h.auditMutation(w, snap, snap, user, "tool_management", "", "conflict")
			fail("Registry changed. Refresh before retrying.", 409)
		} else {
			h.auditMutation(w, snap, snap, user, "tool_management", "", "unknown")
			fail("Change could not be confirmed. Refresh saved state before retrying.", 503)
		}
		return true
	}
	h.auditMutation(w, snap, saved, user, "tool_management", "", "committed")
	h.updateCatalog(snap, saved, id, next, fresh)
	if next != nil {
		h.mu.Lock()
		if len(h.probes) >= 256 {
			h.probes = map[string]probe{}
		}
		next.revision = saved.Revision
		h.probes[id] = *next
		h.mu.Unlock()
	}
	if wantsJSON(r) {
		h.actionState(w, saved)
	} else {
		http.Redirect(w, r, h.returnURL(r, id), 303)
	}
	return true
}

func (h *handler) renderWorkspaceError(w http.ResponseWriter, r *http.Request, snap store.Snapshot, csrf, user, message string, code int) {
	v := h.view(snap, csrf)
	v.User, v.Authentik, v.Error = user, h.a.forward != nil, message
	v.Uncertain = code == 409 || code >= 500
	v.Draft = map[string]string{}
	for _, name := range []string{"id", "description", "keywords", "url", "auth_mode", "auth_header", "https_consent"} {
		v.Draft[name] = r.Form.Get(name)
	}
	p := workspacePage{page: v}
	parts := serverPathParts(r.URL.Path)
	if len(parts) > 0 {
		for i := range p.Servers {
			if p.Servers[i].ID == parts[0] {
				p.Selected = &p.Servers[i]
				break
			}
		}
	}
	if p.Selected != nil {
		selected := map[string]bool{}
		for _, name := range r.Form["tools"] {
			selected[name] = true
		}
		for i := range p.Selected.Tools {
			p.Selected.Tools[i].Selected = selected[p.Selected.Tools[i].Name]
		}
		if len(parts) == 2 && parts[1] == "update" {
			p.Selected.Server.Description = r.Form.Get("description")
			p.Selected.Server.Keywords = csv(r.Form.Get("keywords"))
			p.Selected.Server.URL = r.Form.Get("url")
			switch r.Form.Get("auth_mode") {
			case "none":
				p.Selected.Secret = false
				p.Selected.Server.AuthHeader = ""
			case "bearer":
				p.Selected.Secret = true
				p.Selected.Server.AuthHeader = ""
			case "header":
				p.Selected.Secret = true
				p.Selected.Server.AuthHeader = r.Form.Get("auth_header")
			}
		}
	}
	_ = workspaceTpl.Execute(w, p)
}
