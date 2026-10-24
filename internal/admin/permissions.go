package admin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"mcp-gateway/internal/audit"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/policy"
	"mcp-gateway/internal/store"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type permissionRow struct {
	Server, Tool, Field, Constraints string
	Selected, Enabled, Allowed       bool
}
type permissionView struct {
	Base, CSRF, Principal, Policy, Audit, Message string
	Revision                                      int64
	Legacy                                        bool
	Uncertain                                     bool
	Rows                                          []permissionRow
}

func permissionField(s, t string) string {
	b, _ := json.Marshal([]string{s, t})
	return "grant:" + base64.RawURLEncoding.EncodeToString(b)
}
func (h *handler) permissionView(snap store.Snapshot, id, csrf string) permissionView {
	p := snap.Config.Principals[id]
	v := permissionView{Base: h.a.basePath, CSRF: csrf, Principal: id, Policy: p.AccessPolicy, Legacy: p.AccessPolicy == config.LegacyShared, Revision: snap.Revision, Audit: h.audit.State()}
	ids := []string{}
	for s := range snap.Config.Servers {
		ids = append(ids, s)
	}
	sort.Strings(ids)
	for _, s := range ids {
		srv := snap.Config.Servers[s]
		names := []string{}
		for n := range srv.Tools {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, t := range names {
			tool := srv.Tools[t]
			row := permissionRow{Server: s, Tool: t, Field: permissionField(s, t), Enabled: srv.Enabled && tool.Enabled}
			for _, n := range p.ToolAllowlist[s] {
				if n == t {
					row.Selected = true
				}
			}
			_, e := policy.Grant(snap.Config, id, s, t)
			row.Allowed = e == nil
			if tool.AccessMode != "shared" {
				if grant, ok := p.Grants[s][t]; ok {
					b, _ := json.Marshal(grant)
					row.Constraints = string(b)
				} else {
					row.Constraints = "Legacy tool requires an existing argument grant."
				}
			}
			v.Rows = append(v.Rows, row)
		}
	}
	return v
}
func (h *handler) permissions(w http.ResponseWriter, r *http.Request, snap store.Snapshot, sess session, user string) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/connection/permissions/")
	p, ok := snap.Config.Principals[id]
	if !ok || !config.ValidIdentifier(id) {
		http.NotFound(w, r)
		return
	}
	v := h.permissionView(snap, id, sess.csrf)
	render := func(status int) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = permissionTpl.Execute(w, v)
	}
	if r.Method == "GET" {
		render(200)
		return
	}
	fail := func(code int, message string, outcome string) {
		h.auditMutation(w, snap, snap, user, "permission_save", id, outcome)
		if wantsJSON(r) {
			http.Error(w, message, code)
		} else {
			v.Message = message
			v.Uncertain = code != 400
			if mode := r.Form.Get("policy"); mode == config.Restricted || (v.Legacy && mode == config.LegacyShared) {
				v.Policy = mode
			}
			for i := range v.Rows {
				v.Rows[i].Selected = r.Form.Get(v.Rows[i].Field) == "1"
			}
			render(code)
		}
	}
	rev, e := strconv.ParseInt(r.Form.Get("revision"), 10, 64)
	if e != nil || rev != snap.Revision {
		fail(409, "Registry changed. Reload before saving; your draft has not been applied.", "conflict")
		return
	}
	mode := r.Form.Get("policy")
	if mode != config.Restricted && !(mode == config.LegacyShared && p.AccessPolicy == config.LegacyShared) {
		fail(400, "Invalid access policy.", "rejected")
		return
	}
	acl := map[string][]string{}
	for key, value := range r.Form {
		if key == "csrf" || key == "revision" || key == "policy" {
			continue
		}
		if !strings.HasPrefix(key, "grant:") || len(value) != 1 || value[0] != "1" || len(key) > 512 {
			fail(400, "Invalid permission selection.", "rejected")
			return
		}
		raw, er := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, "grant:"))
		var pair []string
		if er != nil || json.Unmarshal(raw, &pair) != nil || len(pair) != 2 || permissionField(pair[0], pair[1]) != key {
			fail(400, "Invalid permission selection.", "rejected")
			return
		}
		server, exists := snap.Config.Servers[pair[0]]
		if _, tool := server.Tools[pair[1]]; !exists || !tool {
			fail(400, "Unknown permission selection. Reload the catalog.", "rejected")
			return
		}
		acl[pair[0]] = append(acl[pair[0]], pair[1])
	}
	if mode == config.LegacyShared && len(acl) > 0 {
		fail(400, "Choose restricted policy before selecting tools.", "rejected")
		return
	}
	for sid := range acl {
		sort.Strings(acl[sid])
	}
	c := clone(snap.Config)
	p.AccessPolicy = mode
	p.ToolAllowlist = acl
	c.Principals[id] = p
	next, e := h.s.CompareAndSwap(r.Context(), rev, c, nil)
	if e != nil {
		if errors.Is(e, store.ErrConflict) {
			fail(409, "Registry changed. Reload before saving.", "conflict")
		} else {
			fail(503, "Save could not be confirmed. Reload before retrying.", "unknown")
		}
		return
	}
	h.auditMutation(w, snap, next, user, "permission_save", id, "committed")
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		rights := map[string]bool{}
		for _, row := range h.permissionView(next, id, sess.csrf).Rows {
			rights[row.Field] = row.Allowed
		}
		_ = json.NewEncoder(w).Encode(struct {
			Revision int64           `json:"revision"`
			Audit    string          `json:"audit_status"`
			Message  string          `json:"message"`
			Rights   map[string]bool `json:"rights"`
		}{next.Revision, h.audit.State(), "Permissions saved.", rights})
		return
	}
	http.Redirect(w, r, h.a.basePath+"/admin/connection/permissions/"+id, 303)
}
func flattenPermissions(p config.Principal) map[audit.Permission]bool {
	m := map[audit.Permission]bool{}
	for s, names := range p.ToolAllowlist {
		for _, t := range names {
			m[audit.Permission{Server: s, Tool: t}] = true
		}
	}
	return m
}
func (h *handler) auditMutation(w http.ResponseWriter, before, after store.Snapshot, user, cause, target, outcome string) {
	actor := user
	if actor == "" {
		actor = "token-admin"
	}
	ids := []string{}
	if target != "" {
		ids = append(ids, target)
	} else {
		seen := map[string]bool{}
		for id := range before.Config.Principals {
			seen[id] = true
		}
		for id := range after.Config.Principals {
			seen[id] = true
		}
		for id := range seen {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		old, next := before.Config.Principals[id], after.Config.Principals[id]
		a, b := flattenPermissions(old), flattenPermissions(next)
		e := audit.Event{RequestID: audit.RequestID(), Kind: "registry_change", Actor: actor, Target: id, Cause: cause, Outcome: outcome, BaseRevision: before.Revision, PolicyBefore: old.AccessPolicy, PolicyAfter: next.AccessPolicy}
		if outcome == "committed" {
			e.Revision = after.Revision
		}
		for tuple := range b {
			if !a[tuple] {
				e.Added = append(e.Added, tuple)
			}
		}
		for tuple := range a {
			if !b[tuple] {
				e.Removed = append(e.Removed, tuple)
			}
		}
		sort.Slice(e.Added, func(i, j int) bool {
			return e.Added[i].Server+"\x00"+e.Added[i].Tool < e.Added[j].Server+"\x00"+e.Added[j].Tool
		})
		sort.Slice(e.Removed, func(i, j int) bool {
			return e.Removed[i].Server+"\x00"+e.Removed[i].Tool < e.Removed[j].Server+"\x00"+e.Removed[j].Tool
		})
		_ = h.audit.Record(e)
	}
	w.Header().Set("X-Gateway-Audit-Status", h.audit.State())
}

var permissionTpl = template.Must(template.New("permissions").Parse(permissionTemplate))
