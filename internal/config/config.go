// Package config loads immutable, fail-closed registry snapshots.
package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"mcp-gateway/internal/readpolicy"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Config struct {
	RegistryVersion int                  `json:"registry_version"`
	HTTPSAllowlist  []string             `json:"https_allowlist,omitempty"`
	Servers         map[string]Server    `json:"servers"`
	Principals      map[string]Principal `json:"principals"`
}
type Server struct {
	BatchReadEnabled  bool            `json:"batch_read_enabled,omitempty"`
	BatchReadProfile  string          `json:"batch_read_profile,omitempty"`
	BatchReadEndpoint string          `json:"batch_read_endpoint,omitempty"`
	Description       string          `json:"description"`
	Keywords          []string        `json:"keywords"`
	URL               string          `json:"url"`
	TokenEnv          string          `json:"token_env,omitempty"`
	TokenRef          string          `json:"token_ref,omitempty"`
	AuthHeader        string          `json:"auth_header,omitempty"`
	Enabled           bool            `json:"enabled"`
	Tools             map[string]Tool `json:"tools"`
}
type Tool struct {
	Enabled               bool   `json:"enabled"`
	AccessMode            string `json:"access_mode,omitempty"`
	OperationKind         string `json:"operation_kind,omitempty"`
	OperationContractHash string `json:"operation_contract_hash,omitempty"`
}
type Principal struct {
	AccessPolicy  string                      `json:"access_policy"`
	ToolAllowlist map[string][]string         `json:"tool_allowlist"`
	TokenEnv      string                      `json:"token_env,omitempty"`
	TokenHash     string                      `json:"token_hash,omitempty"`
	Key           *ClientKey                  `json:"key,omitempty"`
	Grants        map[string]map[string]Grant `json:"grants"`
}
type ClientKey struct {
	Recoverable bool   `json:"recoverable,omitempty"`
	Name        string `json:"name"`
	Prefix      string `json:"prefix"`
	CreatedAt   string `json:"created_at"`
}

// TokenDigest hashes high-entropy client credentials; raw keys are never persisted.
func TokenDigest(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func ValidKeyName(name string) bool {
	return utf8.ValidString(name) && name == strings.TrimSpace(name) && len(name) > 0 && len(name) <= 128 && !strings.ContainsFunc(name, unicode.IsControl)
}

func (p Principal) MatchesToken(token string) bool {
	if token == "" {
		return false
	}
	if p.TokenHash != "" {
		return subtle.ConstantTimeCompare([]byte(TokenDigest(token)), []byte(p.TokenHash)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(os.Getenv(p.TokenEnv))) == 1
}

type Grant struct {
	SchemaOnly        bool           `json:"-"`
	AllowedArguments  []string       `json:"allowed_arguments"`
	RequiredArguments []string       `json:"required_arguments"`
	ArgumentEquals    map[string]any `json:"argument_equals"`
}

const RegistryVersion = 2
const Restricted = "restricted"
const LegacyShared = "legacy_shared"

var ErrRegistryVersion = errors.New("registry document upgrade required")

var ErrConfig = errors.New("configuration unavailable or invalid")
var ident = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
var keyPrefix = regexp.MustCompile(`^mgw_[A-Za-z0-9_-]{8}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Loopback(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
func ValidURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "http" && Loopback(u.Hostname()) && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == ""
}

// ValidHTTPS permits explicitly configured TLS endpoints, with standard certificate validation.
func ValidHTTPS(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && !strings.Contains(raw, "*") && (u.Port() == "" || u.Port() == "443") && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == ""
}
func (c *Config) AllowsEndpoint(raw string) bool {
	if ValidURL(raw) {
		return true
	}
	if !ValidHTTPS(raw) {
		return false
	}
	for _, endpoint := range c.HTTPSAllowlist {
		if endpoint == raw {
			return true
		}
	}
	return false
}
func Load(path string) (*Config, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrConfig
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return nil, ErrConfig
	}
	c, e := Decode(b)
	if e != nil {
		return nil, e
	}
	for _, s := range c.Servers {
		if s.TokenRef != "" {
			return nil, ErrConfig
		}
	}
	for _, p := range c.Principals {
		if p.Key != nil && p.Key.Recoverable {
			return nil, ErrConfig
		}
	}
	return c, nil
}

// Decode validates a bounded registry without loading external secret values.
func Decode(b []byte) (*Config, error) {
	if len(b) > 1<<20 {
		return nil, ErrConfig
	}
	var e error
	// Duplicate keys are rejected at every depth, including policy constraints.
	d := json.NewDecoder(bytes.NewReader(b))
	if e = unique(d); e != nil {
		return nil, ErrConfig
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrConfig
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	d.UseNumber()
	var c Config
	if d.Decode(&c) != nil {
		return nil, ErrConfig
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
func unique(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return ErrConfig
			}
			seen[s] = true
			if e := unique(d); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	case json.Delim('['):
		for d.More() {
			if e := unique(d); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	}
	return nil
}
func (c *Config) Validate() error {
	if c.RegistryVersion != RegistryVersion {
		return ErrRegistryVersion
	}
	if c.Servers == nil || len(c.Principals) == 0 {
		return ErrConfig
	}
	allowed := map[string]bool{}
	for _, endpoint := range c.HTTPSAllowlist {
		if !ValidHTTPS(endpoint) || allowed[endpoint] {
			return ErrConfig
		}
		allowed[endpoint] = true
	}
	tokens := map[string]bool{}
	clientEnvs := map[string]bool{}
	for id, p := range c.Principals {
		token := os.Getenv(p.TokenEnv)
		if !ident.MatchString(id) {
			return ErrConfig
		}
		digest := p.TokenHash
		if digest != "" {
			b, err := hex.DecodeString(digest)
			if err != nil || len(b) != 32 || digest != strings.ToLower(digest) || p.TokenEnv != "" || p.Key == nil || !ValidKeyName(p.Key.Name) || !keyPrefix.MatchString(p.Key.Prefix) {
				return ErrConfig
			}
			created, err := time.Parse(time.RFC3339, p.Key.CreatedAt)
			if err != nil || created.Format(time.RFC3339) != p.Key.CreatedAt || !strings.HasSuffix(p.Key.CreatedAt, "Z") {
				return ErrConfig
			}
		} else {
			if p.Key != nil || !envName.MatchString(p.TokenEnv) || len(token) < 16 || strings.ContainsAny(token, " \r\n\t") {
				return ErrConfig
			}
			digest = TokenDigest(token)
			clientEnvs[p.TokenEnv] = true
		}
		if tokens[digest] {
			return ErrConfig
		}
		tokens[digest] = true
	}
	for id, s := range c.Servers {
		if (s.BatchReadProfile != "" && !readpolicy.Known(s.BatchReadProfile)) || (s.BatchReadEnabled && (s.BatchReadProfile == "" || s.BatchReadEndpoint != s.URL)) || (!s.BatchReadEnabled && s.BatchReadEndpoint != "") {
			return ErrConfig
		}
		if !ident.MatchString(id) || !c.AllowsEndpoint(s.URL) || s.Tools == nil || (s.TokenRef != "" && (s.TokenRef != id || s.TokenEnv != "")) {
			return ErrConfig
		}
		if s.AuthHeader != "" && (!ValidAuthHeader(s.AuthHeader) || (s.TokenEnv == "" && s.TokenRef == "")) {
			return ErrConfig
		}
		if s.TokenEnv != "" {
			v := os.Getenv(s.TokenEnv)
			if !envName.MatchString(s.TokenEnv) || clientEnvs[s.TokenEnv] || !ValidCredential(s.AuthHeader, v) || tokens[TokenDigest(v)] {
				return ErrConfig
			}
		}
		for name, tool := range s.Tools {
			if !ident.MatchString(name) || (tool.AccessMode != "" && tool.AccessMode != "shared") || !validOperation(tool) {
				return ErrConfig
			}
		}
	}
	for _, p := range c.Principals {
		if (p.AccessPolicy != Restricted && p.AccessPolicy != LegacyShared) || p.ToolAllowlist == nil || (p.AccessPolicy == LegacyShared && len(p.ToolAllowlist) != 0) {
			return ErrConfig
		}
		for sid, names := range p.ToolAllowlist {
			srv, ok := c.Servers[sid]
			if !ok || !ValidIdentifier(sid) || names == nil {
				return ErrConfig
			}
			seen := map[string]bool{}
			for _, name := range names {
				if _, ok := srv.Tools[name]; !ok || !ValidIdentifier(name) || seen[name] {
					return ErrConfig
				}
				seen[name] = true
			}
		}
		for sid, gs := range p.Grants {
			s, ok := c.Servers[sid]
			if !ok {
				return ErrConfig
			}
			for name, g := range gs {
				if _, ok := s.Tools[name]; !ok {
					return ErrConfig
				}
				allowed := map[string]bool{}
				for _, k := range g.AllowedArguments {
					if k == "" || k == "*" || allowed[k] {
						return ErrConfig
					}
					allowed[k] = true
				}
				required := map[string]bool{}
				for _, k := range g.RequiredArguments {
					if !allowed[k] || required[k] {
						return ErrConfig
					}
					required[k] = true
				}
				for k := range g.ArgumentEquals {
					if !allowed[k] {
						return ErrConfig
					}
				}
			}
		}
	}
	return nil
}
func (c *Config) Authenticate(header string) (string, error) {
	return c.AuthenticateHeaders(http.Header{"Authorization": {header}})
}

// AuthenticateHeaders accepts exactly one unambiguous client credential.
func (c *Config) AuthenticateHeaders(headers http.Header) (string, error) {
	var authorization, apiKey []string
	var hasAuthorization, hasAPIKey bool
	for name, values := range headers {
		switch {
		case strings.EqualFold(name, "Authorization"):
			hasAuthorization = true
			authorization = append(authorization, values...)
		case strings.EqualFold(name, "X-API-Key"):
			hasAPIKey = true
			apiKey = append(apiKey, values...)
		}
	}
	if hasAuthorization == hasAPIKey {
		return "", errors.New("unauthorized")
	}
	var token string
	if hasAPIKey {
		if len(apiKey) != 1 {
			return "", errors.New("unauthorized")
		}
		token = apiKey[0]
	} else {
		if len(authorization) != 1 {
			return "", errors.New("unauthorized")
		}
		header := authorization[0]
		if !strings.HasPrefix(header, "Bearer ") {
			return "", errors.New("unauthorized")
		}
		token = strings.TrimPrefix(header, "Bearer ")
	}
	if token == "" || strings.IndexFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("unauthorized")
	}
	for id, p := range c.Principals {
		if p.MatchesToken(token) {
			return id, nil
		}
	}
	return "", errors.New("unauthorized")
}

// ValidIdentifier checks server and tool identifiers accepted by the registry.
func ValidIdentifier(s string) bool { return ident.MatchString(s) }

// Clone isolates a mutation from a snapshot currently used by admitted requests.
func Clone(c *Config) (*Config, error) {
	b, e := json.Marshal(c)
	if e != nil {
		return nil, ErrConfig
	}
	return Decode(b)
}

// DecodeObject rejects duplicate keys and trailing data in policy JSON entered in the UI.
func DecodeObject(b []byte) (map[string]any, error) {
	if len(b) > 1<<20 {
		return nil, ErrConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if unique(d) != nil {
		return nil, ErrConfig
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, ErrConfig
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var out map[string]any
	if d.Decode(&out) != nil || out == nil {
		return nil, ErrConfig
	}
	return out, nil
}

// SimplifyAccess replaces legacy grants with shared tool enablement atomically
// when its returned configuration is committed by the caller.
func SimplifyAccess(c *Config) bool {
	changed := false
	for id, s := range c.Servers {
		for name, tool := range s.Tools {
			if tool.AccessMode != "shared" {
				tool.AccessMode = "shared"
				s.Tools[name] = tool
				changed = true
			}
		}
		c.Servers[id] = s
	}
	for id, p := range c.Principals {
		if len(p.Grants) != 0 {
			p.Grants = map[string]map[string]Grant{}
			c.Principals[id] = p
			changed = true
		}
	}
	return changed
}

// BatchReadDecision is shared by runtime and admin presentation. It grants no client access.
func (s Server) BatchReadDecision(tool *mcp.Tool) (bool, string) {
	if !s.Enabled {
		return false, "server_disabled"
	}
	if !s.BatchReadEnabled {
		return false, "connector_batch_disabled"
	}
	if s.BatchReadEndpoint != s.URL {
		return false, "endpoint_changed"
	}
	if tool == nil {
		return false, "catalog_unavailable"
	}
	if !s.Tools[tool.Name].Enabled {
		return false, "tool_disabled"
	}
	return readpolicy.Classify(s.BatchReadProfile, tool)
}

// validOperation enforces the binding of manual reads to a specific contract.
func validOperation(t Tool) bool {
	switch t.OperationKind {
	case "", "write":
		return t.OperationContractHash == ""
	case "read":
		b, err := hex.DecodeString(t.OperationContractHash)
		return err == nil && len(b) == 32 && t.OperationContractHash == strings.ToLower(t.OperationContractHash)
	default:
		return false
	}
}

// ClassifiedReadDecision checks global switches; it grants no client access.
func (s Server) ClassifiedReadDecision(tool *mcp.Tool, connectionBinding ...string) (bool, string) {
	if !s.Enabled {
		return false, "server_disabled"
	}
	if tool == nil {
		return false, "catalog_unavailable"
	}
	configured, ok := s.Tools[tool.Name]
	if !ok || !configured.Enabled {
		return false, "tool_disabled"
	}
	d := readpolicy.ClassifyOperation(configured.OperationKind, configured.OperationContractHash, tool, connectionBinding...)
	return d.Kind == "read", d.Reason
}

// ClearManualReadOperations removes approvals bound to the prior connection.
func (s *Server) ClearManualReadOperations() {
	for name, tool := range s.Tools {
		if tool.OperationKind == "read" {
			tool.OperationKind, tool.OperationContractHash = "", ""
			s.Tools[name] = tool
		}
	}
}
