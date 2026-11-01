// Package admin serves the separate, explicitly enabled registry administration listener.
package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/audit"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/readpolicy"
	"mcp-gateway/internal/store"
	"mcp-gateway/internal/upstream"
)

var errInput = errors.New("invalid input")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)

type Options struct {
	Audit             *audit.Sink
	BatchClassified   bool
	BatchRegistry     bool
	Catalog           *catalog.Provider
	MCPEndpoint       string
	BasePath          string
	Token             string
	Origin            string
	AccessIssuer      string
	AccessAudience    string
	AccessEmails      []string
	AuthMode          string
	TrustedProxyCIDRs []string
	AllowedUsers      []string
	AllowedGroups     []string
}
type probe struct {
	revision int64
	key      [32]byte
	at       time.Time
	tools    map[string]*mcp.Tool
	failed   bool
}
type handler struct {
	audit           *audit.Sink
	batchClassified bool
	batchRegistry   bool
	catalog         *catalog.Provider
	s               store.Store
	a               *auth
	mu              sync.Mutex
	probes          map[string]probe
	tpl             *template.Template
	connectionTpl   *template.Template
	mcpEndpoint     string
}

func New(s store.Store, o Options) (http.Handler, error) {
	if o.MCPEndpoint != "" && !config.ValidHTTPS(o.MCPEndpoint) && !config.ValidURL(o.MCPEndpoint) {
		return nil, errInput
	}
	if o.BasePath != "" && !regexp.MustCompile(`^(/[a-zA-Z0-9_-]+)+$`).MatchString(o.BasePath) {
		return nil, errInput
	}
	a, e := newConfiguredAuth(o)
	if e != nil {
		return nil, e
	}
	a.basePath = o.BasePath
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snap, e := s.ReadSnapshot(ctx)
	if e != nil {
		return nil, e
	}
	for _, p := range snap.Config.Principals {
		if p.MatchesToken(o.Token) {
			return nil, errInput
		}
	}
	for id, server := range snap.Config.Servers {
		token := os.Getenv(server.TokenEnv)
		if server.TokenRef != "" {
			token, e = store.ResolveSnapshotSecret(snap, id)
			if e != nil {
				return nil, e
			}
		}
		if equal(o.Token, token) {
			return nil, errInput
		}
	}
	return &handler{batchClassified: o.BatchClassified, audit: o.Audit, batchRegistry: o.BatchRegistry, s: s, a: a, catalog: o.Catalog, probes: map[string]probe{}, mcpEndpoint: o.MCPEndpoint, connectionTpl: template.Must(template.New("connection").Parse(connectionTemplate + permissionTemplate)), tpl: template.Must(template.New("page").Parse(strings.ReplaceAll(pageTemplate, `"/admin`, `"{{$.BasePath}}/admin`)))}, nil
}
func equal(a, b string) bool { return b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	if !h.a.validRequest(r) {
		http.Error(w, "Invalid host or origin", 403)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if r.ParseForm() != nil {
			http.Error(w, "Invalid or oversized form", 400)
			return
		}
		for name, v := range r.PostForm {
			if name == "tools" && isBulkToolPath(r.URL.Path) {
				continue
			}
			if len(v) != 1 {
				http.Error(w, "Duplicate form field", 400)
				return
			}
		}
		r.Form = r.PostForm
	}
	user, binding := "", ""
	if h.a.sso() {
		var allowed bool
		user, binding, allowed = h.a.identity(r)
		if !allowed {
			http.Error(w, "SSO access denied", 403)
			return
		}
	}
	if r.URL.Path == "/admin/login" {
		if h.a.sso() {
			if r.Method == "POST" {
				http.Error(w, "Token login disabled", 403)
			} else {
				http.Redirect(w, r, h.a.basePath+"/admin/servers", 303)
			}
			return
		}
		if r.Method == "POST" {
			h.a.login(w, r)
			return
		}
		nonce := random()
		h.a.cookie(w, "gateway_login_csrf", nonce, 600)
		h.render(w, page{Login: true, CSRF: nonce, BasePath: h.a.basePath})
		return
	}
	sess, ok := h.a.current(r)
	if h.a.sso() {
		if ok && sess.user != binding {
			ok = false
		}
		if !ok && r.Method == "GET" {
			sess, ok = h.a.ssoSession(w, r, binding)
			if !ok {
				http.Error(w, "Session limit reached", 429)
				return
			}
		}
	}
	if !ok {
		if r.Method == "POST" {
			http.Error(w, "Authentication required", 401)
		} else {
			http.Redirect(w, r, h.a.basePath+"/admin/login", 303)
		}
		return
	}
	if r.Method == "POST" && !h.a.csrf(r, sess.csrf) {
		http.Error(w, "Invalid CSRF token", 403)
		return
	}
	if r.URL.Path == "/admin/logout" && r.Method == "POST" {
		h.a.logout(w, r)
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/admin/" {
		http.Redirect(w, r, h.a.basePath+"/admin/servers", 303)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/admin/workspace.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(workspaceJS))
		return
	}
	if r.Method == "GET" && r.URL.Path == "/admin/actions.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(actionsJS))
		return
	}
	if r.Method == "GET" && r.URL.Path == "/admin/permissions.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(permissionsJS))
		return
	}
	if r.Method == "GET" && r.URL.Path == "/admin/connection.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(connectionJS))
		return
	}
	w.Header().Set("X-Gateway-Audit-Status", h.audit.State())
	snap, e := h.s.ReadSnapshot(r.Context())
	if e != nil {
		http.Error(w, "Registry unavailable", 503)
		return
	}
	if r.URL.Path == "/admin/connection" || strings.HasPrefix(r.URL.Path, "/admin/connection/") {
		h.connection(w, r, snap, sess, user)
		return
	}
	if h.batchClassified && r.Method == "GET" && (r.URL.Path == "/admin/servers" || isServerDetailPath(r.URL.Path)) {
		if wantsJSON(r) {
			h.actionState(w, snap)
			return
		}
		h.renderWorkspace(w, r, snap, sess.csrf, user)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/admin/servers" {
		if wantsJSON(r) {
			h.actionState(w, snap)
			return
		}
		v := h.view(snap, sess.csrf)
		v.User = user
		v.Authentik = h.a.sso()
		v.AuthProvider = h.a.provider()
		h.render(w, v)
		return
	}
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	rev, e := strconv.ParseInt(r.Form.Get("revision"), 10, 64)
	if e != nil || rev != snap.Revision {
		h.inputError(w, r, snap, sess.csrf, user, "Registry changed. Reload before saving.", 409)
		return
	}
	if h.toolManagement(w, r, snap, sess.csrf, user) {
		return
	}
	c := clone(snap.Config)
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/servers/"), "/")
	secrets := map[string]*string{}
	var nextProbe *probe
	freshCheck := false
	id := ""
	if r.URL.Path == "/admin/servers/create" {
		id = r.Form.Get("id")
		if !identifier.MatchString(id) {
			e = errInput
		} else if _, exists := c.Servers[id]; exists {
			e = errInput
		} else {
			server := config.Server{Description: r.Form.Get("description"), Keywords: csv(r.Form.Get("keywords")), URL: r.Form.Get("url"), Tools: map[string]config.Tool{}}
			e = endpoint(c, server.URL, r.Form.Get("https_consent") == "yes")
			if e == nil {
				e = h.secret(r, c, snap, id, &server, secrets)
			}
			if e == nil {
				c.Servers[id] = server
			}
		}
	} else if len(parts) == 2 {
		id = parts[0]
		server, exists := c.Servers[id]
		if !exists {
			http.NotFound(w, r)
			return
		}
		p, pok := h.currentProbe(id, snap)
		switch parts[1] {
		case "batch-profile":
			if !h.batchRegistry {
				e = errInput
				break
			}
			profile := r.Form.Get("batch_read_profile")
			if profile != "" && !readpolicy.Known(profile) {
				e = errInput
				break
			}
			server.BatchReadProfile = profile
			server.BatchReadEnabled = false
			server.BatchReadEndpoint = ""
			c.Servers[id] = server
			if pok {
				nextProbe = &p
			}
		case "batch-disable":
			if !h.batchRegistry {
				e = errInput
				break
			}
			server.BatchReadEnabled = false
			server.BatchReadEndpoint = ""
			c.Servers[id] = server
			if pok {
				nextProbe = &p
			}
		case "batch-enable":
			if !h.batchRegistry {
				e = errInput
				break
			}
			if !readpolicy.Known(server.BatchReadProfile) {
				h.inputError(w, r, snap, sess.csrf, user, "Choose a reviewed read profile in Server settings before enabling batch.", 400)
				return
			}
			if !pok {
				p, e = h.check(r.Context(), snap, id, server)
				if e != nil {
					h.inputError(w, r, snap, sess.csrf, user, "Connection check failed. No tools were invoked.", 502)
					return
				}
				freshCheck = true
			}
			safe := 0
			for name, t := range p.tools {
				if allowed, _ := readpolicy.Classify(server.BatchReadProfile, t); allowed && server.Tools[name].Enabled {
					safe++
				}
			}
			if !server.Enabled || safe == 0 {
				h.inputError(w, r, snap, sess.csrf, user, "Enable the connector and at least one verified read tool before enabling batch.", 400)
				return
			}
			reconcileCatalogACL(c, id, &server, p.tools)
			server.BatchReadEnabled = true
			server.BatchReadEndpoint = server.URL
			c.Servers[id] = server
			nextProbe = &p
		case "update":
			oldURL := server.URL
			oldHeader := server.AuthHeader
			oldEnv, oldRef := server.TokenEnv, server.TokenRef
			server.Description = r.Form.Get("description")
			server.Keywords = csv(r.Form.Get("keywords"))
			server.URL = r.Form.Get("url")
			e = endpoint(c, server.URL, r.Form.Get("https_consent") == "yes")
			if e == nil {
				e = h.secret(r, c, snap, id, &server, secrets)
			}
			if server.URL != oldURL {
				server.Enabled = false
				server.Tools = map[string]config.Tool{}
				clearGrants(c, id)
			} else if pok && len(secrets) == 0 && oldHeader == server.AuthHeader && oldEnv == server.TokenEnv && oldRef == server.TokenRef {
				nextProbe = &p
			}
			if server.URL != oldURL || server.AuthHeader != oldHeader || server.TokenEnv != oldEnv || server.TokenRef != oldRef || len(secrets) > 0 {
				server.BatchReadEnabled = false
				server.BatchReadEndpoint = ""
				server.ClearManualReadOperations()
			}
			c.Servers[id] = server

		case "check", "enable", "tool-enable":
			if !pok || parts[1] == "check" {
				p, e = h.check(r.Context(), snap, id, server)
				if e != nil {
					h.mu.Lock()
					if len(h.probes) >= 256 {
						h.probes = map[string]probe{}
					}
					h.probes[id] = probe{revision: rev, at: time.Now(), failed: true}
					h.mu.Unlock()
					h.inputError(w, r, snap, sess.csrf, user, "Connection check failed. Verify the endpoint and authentication. No tools were invoked.", 502)
					return
				}
				freshCheck = true
			}
			reconcileCatalogACL(c, id, &server, p.tools)
			if parts[1] == "enable" {
				server.Enabled = true
			}
			if parts[1] == "tool-enable" {
				name := r.Form.Get("tool")
				if p.tools[name] == nil {
					e = errInput
					break
				}
				tool := server.Tools[name]
				tool.Enabled = true
				server.Tools[name] = tool
			}
			c.Servers[id] = server
			nextProbe = &p
		case "tool-disable":
			name := r.Form.Get("tool")
			tool, exists := server.Tools[name]
			if !exists {
				e = errInput
				break
			}
			tool.Enabled = false
			server.Tools[name] = tool
			c.Servers[id] = server
			if pok {
				nextProbe = &p
			}
		case "disable":
			server.Enabled = false
			c.Servers[id] = server
			if pok {
				nextProbe = &p
			}
		case "delete":
			if r.Form.Get("confirm") != id {
				e = errInput
				break
			}
			delete(c.Servers, id)
			clearGrants(c, id)
			secrets[id] = nil
		default:
			http.NotFound(w, r)
			return
		}
	} else {
		http.NotFound(w, r)
		return
	}
	if e != nil || c.Validate() != nil {
		h.inputError(w, r, snap, sess.csrf, user, "Invalid settings. Check server ID, HTTPS endpoint consent and authentication. For a custom header, enter a header name and a nonempty secret without surrounding whitespace.", 400)
		return
	}
	saved, e := h.s.CompareAndSwap(r.Context(), rev, c, secrets)
	if errors.Is(e, store.ErrConflict) {
		h.auditMutation(w, snap, snap, user, "server_change", "", "conflict")
		http.Error(w, "Registry changed. Reload before saving.", 409)
		return
	}
	if errors.Is(e, store.ErrSecret) {
		h.auditMutation(w, snap, snap, user, "server_change", "", "rejected")
		h.inputError(w, r, snap, sess.csrf, user, "Credential rejected. Check its format and use a value different from gateway client keys. No changes were saved.", 400)
		return
	}
	if e != nil {
		h.auditMutation(w, snap, snap, user, "server_change", "", "unknown")
		http.Error(w, "Change could not be confirmed. Reload before retrying.", 503)
		return
	}
	h.auditMutation(w, snap, saved, user, "server_change", "", "committed")
	h.updateCatalog(snap, saved, id, nextProbe, freshCheck)
	h.mu.Lock()
	delete(h.probes, id)
	if nextProbe != nil {
		nextProbe.revision = saved.Revision
		if len(h.probes) >= 256 {
			h.probes = map[string]probe{}
		}
		h.probes[id] = *nextProbe
	}
	h.mu.Unlock()
	if wantsJSON(r) {
		h.actionState(w, saved)
		return
	}
	http.Redirect(w, r, h.returnURL(r, id), 303)
}
func clone(c *config.Config) *config.Config {
	b, _ := json.Marshal(c)
	var out config.Config
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	_ = d.Decode(&out)
	return &out
}
func csv(s string) []string {
	out := []string{}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
func clearGrants(c *config.Config, id string) {
	for pid, p := range c.Principals {
		delete(p.ToolAllowlist, id)
		c.Principals[pid] = p
	}
	for pid, p := range c.Principals {
		delete(p.Grants, id)
		c.Principals[pid] = p
	}
}
func endpoint(c *config.Config, raw string, consent bool) error {
	if c.AllowsEndpoint(raw) {
		return nil
	}
	if !config.ValidHTTPS(raw) || !consent {
		return errInput
	}
	c.HTTPSAllowlist = append(c.HTTPSAllowlist, raw)
	return nil
}
func (h *handler) secret(r *http.Request, c *config.Config, snap store.Snapshot, id string, s *config.Server, secrets map[string]*string) error {
	token := r.Form.Get("secret")
	mode := r.Form.Get("auth_mode")
	// Old form submissions retain their existing behavior.
	if mode == "" {
		if s.AuthHeader != "" {
			mode = "header"
		} else {
			mode = "bearer"
		}
	}
	remove := r.Form.Get("remove_secret") == "yes" || mode == "none"
	if token != "" && remove {
		return errInput
	}
	oldHeader := s.AuthHeader
	switch mode {
	case "none", "bearer":
		s.AuthHeader = ""
	case "header":
		name := r.Form.Get("auth_header")
		if name == "" && r.Form.Get("auth_mode") == "" {
			name = s.AuthHeader
		}
		if !config.ValidAuthHeader(name) {
			return errInput
		}
		s.AuthHeader = http.CanonicalHeaderKey(name)
	default:
		return errInput
	}
	if remove {
		if oldHeader == "" && s.TokenEnv == "" && s.TokenRef == "" {
			return nil
		}
		s.Enabled = false
		s.AuthHeader, s.TokenEnv, s.TokenRef = "", "", ""
		secrets[id] = nil
		return nil
	}
	if token != "" {
		if len(token) > 4096 || !config.ValidCredential(s.AuthHeader, token) || equal(token, h.a.token) {
			return errInput
		}
		for _, p := range c.Principals {
			if p.MatchesToken(token) {
				return errInput
			}
		}
		s.Enabled = false
		s.TokenEnv = ""
		s.TokenRef = id
		secrets[id] = &token
	} else if oldHeader != s.AuthHeader {
		value := os.Getenv(s.TokenEnv)
		if s.TokenRef != "" {
			var err error
			value, err = store.ResolveSnapshotSecret(snap, id)
			if err != nil {
				return errInput
			}
		}
		if !config.ValidCredential(s.AuthHeader, value) {
			return errInput
		}
		s.Enabled = false
	}
	if (s.AuthHeader != "" || r.Form.Get("auth_mode") == "bearer") && s.TokenEnv == "" && s.TokenRef == "" {
		return errInput
	}
	return nil
}
func (h *handler) probe(id string, rev int64) (probe, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.probes[id]
	return p, ok && !p.failed && p.revision == rev && time.Since(p.at) < 15*time.Minute
}

func clearToolGrants(c *config.Config, id, name string) {
	for pid, p := range c.Principals {
		delete(p.Grants[id], name)
		if len(p.Grants[id]) == 0 {
			delete(p.Grants, id)
		}
		c.Principals[pid] = p
	}
}

func (h *handler) check(ctx context.Context, snap store.Snapshot, id string, server config.Server) (probe, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	token := os.Getenv(server.TokenEnv)
	if server.TokenRef != "" {
		var err error
		token, err = store.ResolveSnapshotSecret(snap, id)
		if err != nil {
			return probe{}, errInput
		}
	}
	key := connectionDigest(server, token, snap.Config.HTTPSAllowlist)
	session, done, err := upstream.ConnectWithToken(ctx, server, token)
	if err != nil {
		return probe{}, errInput
	}
	defer done()
	tools, err := upstream.Tools(ctx, session)
	if err != nil {
		return probe{}, errInput
	}
	b, err := json.Marshal(tools)
	if err != nil || len(b) > 1<<20 || len(tools) > 500 {
		return probe{}, errInput
	}
	p := probe{key: key, at: time.Now(), tools: map[string]*mcp.Tool{}}
	for _, tool := range tools {
		if tool == nil || !identifier.MatchString(tool.Name) || p.tools[tool.Name] != nil {
			return probe{}, errInput
		}
		p.tools[tool.Name] = tool
	}
	return p, nil
}

func (h *handler) inputError(w http.ResponseWriter, r *http.Request, snap store.Snapshot, csrf, user, message string, status int) {
	if h.batchClassified && !wantsJSON(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		h.renderWorkspaceError(w, r, snap, csrf, user, message, status)
		return
	}
	if wantsJSON(r) {
		http.Error(w, message, status)
		return
	}
	v := h.view(snap, csrf)
	v.User, v.Authentik, v.Error = user, h.a.sso(), message
	v.AuthProvider = h.a.provider()
	if r.URL.Path == "/admin/servers/create" {
		v.Draft = map[string]string{}
		for _, key := range []string{"id", "description", "keywords", "url", "auth_mode", "auth_header", "https_consent"} {
			v.Draft[key] = r.Form.Get(key)
		}
		v.Error += " Re-enter the secret before saving; secrets are never returned to the browser."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = h.tpl.Execute(w, v)
}

type toolView struct {
	Selected                                                                                    bool
	Name, Description, Schema                                                                   string
	OperationKind, OperationSource, OperationReason, OperationLabel, ManualKind, DefinitionHash string
	Enabled                                                                                     bool
	BatchAllowed                                                                                bool
	BatchReason                                                                                 string
}
type serverView struct {
	ID                         string
	Server                     config.Server
	Secret                     bool
	Checked                    string
	Failed                     string
	Tools                      []toolView
	EnabledTools               int
	BatchClassified            bool
	CatalogKnown, CatalogFresh bool
	CatalogAt                  string
	BatchRegistry              bool
	BatchCount                 int
}
type page struct {
	Uncertain       bool
	BatchClassified bool
	BasePath        string
	Error           string
	Draft           map[string]string
	Login           bool
	User            string
	AuthProvider    string
	Authentik       bool
	CSRF            string
	Revision        int64
	Servers         []serverView
}

func (h *handler) view(s store.Snapshot, csrf string) page {
	v := page{BatchClassified: h.batchClassified, CSRF: csrf, Revision: s.Revision, BasePath: h.a.basePath}
	ids := []string{}
	for id := range s.Config.Servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		server := s.Config.Servers[id]
		sv := serverView{BatchClassified: h.batchClassified, BatchRegistry: h.batchRegistry, ID: id, Server: server, Secret: server.TokenEnv != "" || server.TokenRef != ""}
		p, ok := h.currentProbe(id, s)
		if p.failed && p.revision == s.Revision {
			sv.Failed = p.at.Format(time.RFC3339)
		}

		if ok {
			sv.Checked = p.at.Format(time.RFC3339)
		}
		binding := ""
		metadata := map[string]*mcp.Tool{}
		if h.batchClassified {
			sv.Checked = ""
			if conn, err := catalog.FromSnapshot(s, id); err == nil {
				binding = catalog.ConnectionBinding(conn)
				if cached, found := h.catalog.Peek(conn); found {
					sv.CatalogKnown, sv.CatalogFresh, sv.CatalogAt = true, cached.Fresh, cached.At.Format(time.RFC3339)
					if cached.Fresh {
						sv.Checked = sv.CatalogAt
					}
					for _, tool := range cached.Tools {
						metadata[tool.Name] = tool
					}
				}
			}
		}
		names := []string{}
		for name := range server.Tools {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			tv := toolView{Name: name, Enabled: server.Tools[name].Enabled}
			if tv.Enabled {
				sv.EnabledTools++
			}
			if ok && p.tools[name] != nil {
				tool := p.tools[name]
				schema, _ := json.MarshalIndent(tool.InputSchema, "", "  ")
				tv.Description, tv.Schema = tool.Description, string(schema)
			}
			if h.batchClassified {
				setting := server.Tools[name]
				tv.ManualKind = setting.OperationKind
				var current *mcp.Tool
				if sv.CatalogFresh {
					current = metadata[name]
				}
				decision := readpolicy.ClassifyOperation(setting.OperationKind, setting.OperationContractHash, metadata[name], binding)
				tv.OperationKind, tv.OperationSource, tv.OperationReason = decision.Kind, decision.Source, decision.Reason
				tv.OperationLabel = operationLabel(decision)
				if definition := metadata[name]; definition != nil {
					tv.DefinitionHash, _ = readpolicy.OperationFingerprint(definition, binding)
				}
				if tool := metadata[name]; tool != nil {
					schema, _ := json.MarshalIndent(tool.InputSchema, "", "  ")
					tv.Description, tv.Schema = tool.Description, string(schema)
				}
				tv.BatchAllowed, tv.BatchReason = server.ClassifiedReadDecision(current, binding)
			} else if h.batchRegistry {
				tv.BatchAllowed, tv.BatchReason = server.BatchReadDecision(p.tools[name])
				if !ok {
					tv.BatchAllowed = false
					tv.BatchReason = "catalog_unavailable"
				}
			} else {
				tv.BatchReason = "operator_file"
			}
			if tv.BatchAllowed {
				sv.BatchCount++
			}
			tv.BatchReason = readpolicy.Label(tv.BatchReason)
			sv.Tools = append(sv.Tools, tv)
		}
		v.Servers = append(v.Servers, sv)
	}
	return v
}
func (h *handler) render(w http.ResponseWriter, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tpl.Execute(w, p)
}

func wantsJSON(r *http.Request) bool { return r.Header.Get("Accept") == "application/json" }

// Bind cached catalogs to connection inputs, not unrelated registry edits.
func connectionKey(s store.Snapshot, id string) ([32]byte, error) {
	server, exists := s.Config.Servers[id]
	if !exists {
		return [32]byte{}, errInput
	}
	token := os.Getenv(server.TokenEnv)
	if server.TokenRef != "" {
		var err error
		token, err = store.ResolveSnapshotSecret(s, id)
		if err != nil {
			return [32]byte{}, err
		}
	}
	return connectionDigest(server, token, s.Config.HTTPSAllowlist), nil
}
func connectionDigest(server config.Server, token string, allowlist []string) [32]byte {
	raw, _ := json.Marshal([]any{server.URL, server.AuthHeader, server.TokenEnv, server.TokenRef, token, allowlist})
	return sha256.Sum256(raw)
}

func (h *handler) currentProbe(id string, s store.Snapshot) (probe, bool) {
	h.mu.Lock()
	p, exists := h.probes[id]
	h.mu.Unlock()
	key, err := connectionKey(s, id)
	return p, exists && err == nil && !p.failed && p.key == key && time.Since(p.at) < 15*time.Minute
}

// Only display metadata is returned. Credential sources and values never enter this response.
func (h *handler) actionState(w http.ResponseWriter, s store.Snapshot) {
	type serverState struct {
		ID              string     `json:"id"`
		Enabled         bool       `json:"enabled"`
		Checked         string     `json:"checked"`
		Tools           []toolView `json:"tools"`
		BatchRegistry   bool       `json:"batch_registry"`
		BatchEnabled    bool       `json:"batch_enabled"`
		BatchProfile    string     `json:"batch_profile"`
		BatchCount      int        `json:"batch_count"`
		BatchClassified bool       `json:"batch_classified"`
		CatalogKnown    bool       `json:"catalog_known"`
		CatalogFresh    bool       `json:"catalog_fresh"`
		CatalogAt       string     `json:"catalog_at"`
	}
	out := struct {
		Audit    string        `json:"audit_status"`
		Revision int64         `json:"revision"`
		Servers  []serverState `json:"servers"`
	}{Audit: h.audit.State(), Revision: s.Revision, Servers: []serverState{}}
	for _, v := range h.view(s, "").Servers {
		if v.Tools == nil {
			v.Tools = []toolView{}
		}
		out.Servers = append(out.Servers, serverState{v.ID, v.Server.Enabled, v.Checked, v.Tools, v.BatchRegistry, v.BatchRegistry && v.Server.BatchReadEnabled, v.Server.BatchReadProfile, v.BatchCount, v.BatchClassified, v.CatalogKnown, v.CatalogFresh, v.CatalogAt})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func clearToolACL(c *config.Config, id, name string) {
	for pid, p := range c.Principals {
		names := p.ToolAllowlist[id]
		kept := make([]string, 0, len(names))
		for _, v := range names {
			if v != name {
				kept = append(kept, v)
			}
		}
		if len(kept) == 0 {
			delete(p.ToolAllowlist, id)
		} else {
			p.ToolAllowlist[id] = kept
		}
		c.Principals[pid] = p
	}
}

// Every successful admin probe publication uses the same lifecycle invalidation.
func reconcileCatalogACL(c *config.Config, id string, server *config.Server, tools map[string]*mcp.Tool) {
	for name := range tools {
		if _, exists := server.Tools[name]; !exists {
			server.Tools[name] = config.Tool{AccessMode: "shared"}
		}
	}
	for name, tool := range server.Tools {
		if tools[name] == nil {
			tool.Enabled = false
			clearToolACL(c, id, name)
			server.Tools[name] = tool
		}
	}
}
