package admin

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"mcp-gateway/internal/config"
	"mcp-gateway/internal/policy"
	"mcp-gateway/internal/store"
)

//go:embed connection.js
var connectionJS string

type keyView struct {
	Policy      string `json:"policy"`
	Configured  int    `json:"configured"`
	Effective   int    `json:"effective"`
	Legacy      bool   `json:"legacy"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Prefix      string `json:"prefix,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	Managed     bool   `json:"managed"`
	Recoverable bool   `json:"recoverable"`
}
type connectionView struct {
	AuthProvider string          `json:"-"`
	Selected     *keyView        `json:"-"`
	Permission   *permissionView `json:"-"`
	Audit        string          `json:"audit_status"`
	BasePath     string          `json:"-"`
	CSRF         string          `json:"-"`
	User         string          `json:"-"`
	Authentik    bool            `json:"-"`
	Endpoint     string          `json:"endpoint"`
	Command      string          `json:"command"`
	ClaudeBearer string          `json:"-"`
	ClaudeAPIKey string          `json:"-"`
	Revision     int64           `json:"revision"`
	Keys         []keyView       `json:"keys"`
	Token        string          `json:"token,omitempty"`
}

func (h *handler) connectionView(snap store.Snapshot, sess session, user string) connectionView {
	v := connectionView{AuthProvider: h.a.provider(), Audit: h.audit.State(), BasePath: h.a.basePath, CSRF: sess.csrf, User: user, Authentik: h.a.sso(), Endpoint: h.mcpEndpoint, Revision: snap.Revision, Keys: []keyView{}}
	if h.mcpEndpoint != "" {
		// Shell-quote the configured URL without interpolating a credential.
		v.Command = "codex mcp add my-gateway --url '" + strings.ReplaceAll(h.mcpEndpoint, "'", "'\"'\"'") + "' --bearer-token-env-var MCP_GATEWAY_TOKEN"
		claudeConfig := func(header, value string) string {
			data, _ := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{"gateway": map[string]any{
				"type": "http", "url": h.mcpEndpoint, "headers": map[string]string{header: value},
			}}}, "", "  ")
			return string(data)
		}
		v.ClaudeBearer = claudeConfig("Authorization", "Bearer ${MCP_GATEWAY_TOKEN}")
		v.ClaudeAPIKey = claudeConfig("X-API-Key", "${MCP_GATEWAY_TOKEN}")
	}
	ids := make([]string, 0, len(snap.Config.Principals))
	for id := range snap.Config.Principals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := snap.Config.Principals[id]
		k := keyView{ID: id, Name: id, Managed: p.TokenHash != "", Policy: p.AccessPolicy, Legacy: p.AccessPolicy == config.LegacyShared}
		for _, names := range p.ToolAllowlist {
			k.Configured += len(names)
		}
		for sid, server := range snap.Config.Servers {
			for tool := range server.Tools {
				if _, e := policy.Grant(snap.Config, id, sid, tool); e == nil {
					k.Effective++
				}
			}
		}
		if p.Key != nil {
			k.Name = p.Key.Name
			k.Prefix = p.Key.Prefix
			k.CreatedAt = p.Key.CreatedAt
			k.Recoverable = p.Key.Recoverable
		}
		v.Keys = append(v.Keys, k)
	}
	return v
}

func (h *handler) renderConnection(w http.ResponseWriter, r *http.Request, v connectionView) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.connectionTpl.Execute(w, v)
}

func (h *handler) connection(w http.ResponseWriter, r *http.Request, snap store.Snapshot, sess session, user string) {
	if strings.HasPrefix(r.URL.Path, "/admin/connection/permissions/") {
		h.permissions(w, r, snap, sess, user)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/admin/connection" {
		h.renderConnection(w, r, h.connectionView(snap, sess, user))
		return
	}
	create := r.URL.Path == "/admin/connection/keys/create"
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/connection/keys/"), "/")
	reveal := len(parts) == 2 && parts[1] == "reveal" && config.ValidIdentifier(parts[0])
	remove := len(parts) == 2 && parts[1] == "delete" && config.ValidIdentifier(parts[0])
	if r.Method != "POST" || (!create && !remove && !reveal) {
		http.NotFound(w, r)
		return
	}
	revision, err := strconv.ParseInt(r.Form.Get("revision"), 10, 64)
	if err != nil || revision != snap.Revision {
		h.auditMutation(w, snap, snap, user, "client_key_change", "", "conflict")
		http.Error(w, "Registry changed. Refresh keys before saving.", 409)
		return
	}
	if reveal {
		token, err := h.s.RevealClientKey(r.Context(), revision, parts[0])
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				http.Error(w, "Registry changed. Refresh keys before showing a key.", 409)
			} else {
				http.Error(w, "Key cannot be shown. Refresh keys and check its availability.", 400)
			}
			return
		}
		if wantsJSON(r) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_ = json.NewEncoder(w).Encode(struct {
				ID    string `json:"id"`
				Token string `json:"token"`
			}{parts[0], token})
		} else {
			v := h.connectionView(snap, sess, user)
			v.Token = token
			h.renderConnection(w, r, v)
		}
		return
	}
	c := clone(snap.Config)
	token := ""
	clientChanges := map[string]*string{}
	if create {
		name := strings.TrimSpace(r.Form.Get("name"))
		if !config.ValidKeyName(name) {
			http.Error(w, "Enter a key name (1–128 bytes, no control characters).", 400)
			return
		}
		secret := make([]byte, 32)
		idBytes := make([]byte, 16)
		if _, err = rand.Read(secret); err != nil {
			http.Error(w, "Key generation unavailable", 503)
			return
		}
		if _, err = rand.Read(idBytes); err != nil {
			http.Error(w, "Key generation unavailable", 503)
			return
		}
		token = "mgw_" + base64.RawURLEncoding.EncodeToString(secret)
		id := "key_" + hex.EncodeToString(idBytes)
		if _, exists := c.Principals[id]; exists || equal(token, h.a.token) {
			http.Error(w, "Key generation unavailable", 503)
			return
		}
		c.Principals[id] = config.Principal{ToolAllowlist: map[string][]string{}, AccessPolicy: config.Restricted,

			TokenHash: config.TokenDigest(token), Key: &config.ClientKey{Name: name, Prefix: token[:12], CreatedAt: time.Now().UTC().Format(time.RFC3339), Recoverable: true}}
		clientChanges[id] = &token
	} else {
		p, ok := c.Principals[parts[0]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if p.TokenHash == "" {
			http.Error(w, "Environment-managed keys cannot be deleted here.", 400)
			return
		}
		if r.Form.Get("confirm") != p.Key.Name {
			http.Error(w, "Enter the key name to confirm deletion.", 400)
			return
		}
		if len(c.Principals) == 1 {
			http.Error(w, "Keep at least one client key in the registry.", 400)
			return
		}
		delete(c.Principals, parts[0])
	}
	next, err := h.s.CompareAndSwapClientKeys(r.Context(), revision, c, clientChanges)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			h.auditMutation(w, snap, snap, user, "client_key_change", "", "conflict")
			http.Error(w, "Registry changed. Refresh keys before saving.", 409)
		} else {
			h.auditMutation(w, snap, snap, user, "client_key_change", "", "unknown")
			http.Error(w, "Key change could not be confirmed. Refresh keys before retrying.", 503)
		}
		return
	}
	h.auditMutation(w, snap, next, user, "client_key_change", "", "committed")
	v := h.connectionView(next, sess, user)
	if !create && !wantsJSON(r) {
		http.Redirect(w, r, h.a.basePath+"/admin/connection", 303)
		return
	}
	h.renderConnection(w, r, v)
}
