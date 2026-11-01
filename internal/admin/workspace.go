package admin

import (
	"embed"
	"html/template"
	"net/http"
	"strings"

	"mcp-gateway/internal/store"
)

//go:embed workspace.js
var workspaceFiles embed.FS

var workspaceJS = func() string {
	b, err := workspaceFiles.ReadFile("workspace.js")
	if err != nil {
		panic(err)
	}
	return string(b)
}()

var workspaceTpl = template.Must(template.New("workspace").Funcs(template.FuncMap{"args": func(v ...any) []any { return v }, "inc": func(v int) int { return v + 1 }}).Parse(workspaceTemplate))

type workspacePage struct {
	page
	Selected *serverView
}

func (h *handler) renderWorkspace(w http.ResponseWriter, r *http.Request, snap store.Snapshot, csrf, user string) {
	v := h.view(snap, csrf)
	v.User = user
	v.Authentik = h.a.sso()
	v.AuthProvider = h.a.provider()
	p := workspacePage{page: v}
	id := strings.TrimPrefix(r.URL.Path, "/admin/servers/")
	if id == r.URL.Path || strings.Contains(id, "/") {
		id = ""
	}
	for i := range p.Servers {
		if p.Servers[i].ID == id {
			p.Selected = &p.Servers[i]
			break
		}
	}
	if id != "" && p.Selected == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = workspaceTpl.Execute(w, p)
}
