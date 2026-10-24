package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/accessauth"
	"mcp-gateway/internal/catalog"
	"mcp-gateway/internal/config"
)

type accessRoundTrip func(*http.Request) (*http.Response, error)

func (f accessRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func accessFixture(t *testing.T, users map[string]string) (*accessauth.Verifier, func(string) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(intBytes(key.E))
	body, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "access-key", "use": "sig", "alg": "RS256", "n": n, "e": e, "public_cert": "ignored"}}})
	client := &http.Client{Transport: accessRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body))}, nil
	}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	now := time.Now().UTC()
	verifier, err := accessauth.NewForTesting(accessauth.Options{Issuer: "https://issuer.example.org", Audience: "mcp-audience", Users: users}, "https://issuer.example.org/certs", client, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	token := func(email string) string {
		claims := jwt.MapClaims{"iss": "https://issuer.example.org", "sub": "cf-subject", "aud": []string{"browser-aud", "mcp-audience"}, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(), "type": "app", "email": email}
		v := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		v.Header["kid"] = "access-key"
		s, err := v.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	return verifier, token
}

func unavailableAccessVerifier(t *testing.T) (*accessauth.Verifier, *atomic.Int32) {
	t.Helper()
	fetches := &atomic.Int32{}
	client := &http.Client{Transport: accessRoundTrip(func(*http.Request) (*http.Response, error) { fetches.Add(1); return nil, io.ErrUnexpectedEOF }), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	v, err := accessauth.NewForTesting(accessauth.Options{Issuer: "https://issuer.example.org", Audience: "mcp-audience", Users: map[string]string{"alice@example.net": "local"}}, "https://issuer.example.org/certs", client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return v, fetches
}
func intBytes(v int) []byte {
	if v == 0 {
		return []byte{0}
	}
	out := []byte{}
	for v > 0 {
		out = append([]byte{byte(v)}, out...)
		v >>= 8
	}
	return out
}

func TestAccessOAuthRouteAdmissionAndReservation(t *testing.T) {
	f := newFixture(t)
	verifier, token := accessFixture(t, map[string]string{"alice@example.net": "local"})
	handler, err := (&Gateway{Path: f.path, PublicOrigin: "https://mcp.example.org", AccessOAuth: verifier}).Handler()
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, method string, headers http.Header) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://gateway.invalid"+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
		r.Host = "mcp.example.org"
		r.Header = headers.Clone()
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	valid := http.Header{"Cf-Access-Jwt-Assertion": {token("alice@example.net")}, "Authorization": {"Bearer oauth:syntheticopaque"}}
	if w := request("/mcp/oauth", "POST", valid); w.Code != http.StatusOK {
		t.Fatalf("valid assertion + opaque bearer rejected: %d %s", w.Code, w.Body.String())
	}
	if w := request("/mcp/oauth", "POST", http.Header{"Cf-Access-Jwt-Assertion": {token("alice@example.net")}}); w.Code != http.StatusOK {
		t.Fatalf("valid assertion-only request rejected: %d %s", w.Code, w.Body.String())
	}
	if w := request("/mcp", "POST", http.Header{"Authorization": {"Bearer " + clientToken}, "Cf-Access-Jwt-Assertion": {"unverified incidental header"}}); w.Code != http.StatusOK {
		t.Fatalf("native key failed with an unrelated Access assertion: %d %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		path, method string
		headers      http.Header
		code         int
	}{
		{"/mcp/oauth", "GET", nil, 405}, {"/mcp/oauth/", "POST", valid, 404}, {"/MCP/oauth", "POST", valid, 404}, {"/mcp/%6fauth", "POST", valid, 404}, {"/mcp/oauth/../mcp", "POST", valid, 404},
		{"/mcp/oauth?token=secret", "POST", valid, 404}, {"/mcp/oauth", "POST", http.Header{"Cf-Access-Jwt-Assertion": {token("alice@example.net"), token("alice@example.net")}}, 401},
		{"/mcp/oauth", "POST", http.Header{"Cf-Access-Jwt-Assertion": {token("alice@example.net")}, "X-API-Key": {"synthetic-key"}}, 401},
		{"/mcp/oauth", "POST", http.Header{"Cf-Access-Jwt-Assertion": {token("alice@example.net")}, "Authorization": {"Bearer native-client-key"}}, 401},
		{"/mcp/oauth", "POST", http.Header{"Cf-Access-Jwt-Assertion": {token("alice@example.net")}, "Origin": {"https://mcp.example.org"}}, 403},
		{"/mcp/oauth", "POST", http.Header{"Cf-Access-Jwt-Assertion": {token("unknown@example.net")}}, 401},
	} {
		w := request(tc.path, tc.method, tc.headers)
		if w.Code != tc.code {
			t.Errorf("%s %s got %d want %d: %s", tc.method, tc.path, w.Code, tc.code, w.Body.String())
		}
		if tc.method == "GET" && w.Header().Get("Allow") != "POST" {
			t.Errorf("unsupported method Allow=%q", w.Header().Get("Allow"))
		}
	}
	disabled, err := (&Gateway{Path: f.path, PublicOrigin: "https://mcp.example.org"}).Handler()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/mcp/oauth", "/mcp/oauth/", "/mcp/%6fauth", "/mcp/oauth/../mcp"} {
		r := httptest.NewRequest("POST", "http://gateway.invalid"+p, nil)
		r.Host = "mcp.example.org"
		w := httptest.NewRecorder()
		disabled.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("disabled route variant %q fell through: %d", p, w.Code)
		}
	}
}

func TestJWKSUnavailableDoesNotBreakNativeKeys(t *testing.T) {
	f := newFixture(t)
	verifier, fetches := unavailableAccessVerifier(t)
	h, err := (&Gateway{Path: f.path, PublicOrigin: "https://mcp.example.org", AccessOAuth: verifier}).Handler()
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string, headers http.Header) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://gateway.invalid"+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
		r.Host = "mcp.example.org"
		r.Header = headers.Clone()
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	_, validToken := accessFixture(t, map[string]string{"alice@example.net": "local"})
	if got := request("/mcp/oauth", http.Header{"Cf-Access-Jwt-Assertion": {validToken("alice@example.net")}, "Authorization": {"Bearer oauth:opaque"}}).Code; got != http.StatusUnauthorized {
		t.Fatalf("JWKS outage should deny OAuth, got %d", got)
	}
	if fetches.Load() == 0 {
		t.Fatal("JWKS outage test did not attempt a JWKS fetch")
	}
	if got := request("/mcp", http.Header{"Authorization": {"Bearer " + clientToken}}).Code; got != http.StatusOK {
		t.Fatalf("JWKS outage affected native Bearer, got %d", got)
	}
	if got := request("/mcp", http.Header{"X-API-Key": {clientToken}}).Code; got != http.StatusOK {
		t.Fatalf("JWKS outage affected native X-API-Key, got %d", got)
	}
}

func TestAccessOAuthSDKIdentityAndLivePrincipalGrantChecks(t *testing.T) {
	f := newFixture(t)
	f.t.Setenv("TEST_REMOTE_TOKEN", "synthetic-remote-key-123456")
	f.config.Servers["remote"] = config.Server{Enabled: true, Description: "Remote synthetic server", URL: "http://127.0.0.1:1/mcp", Tools: map[string]config.Tool{"read": {Enabled: true}}}
	f.config.Principals["remote"] = config.Principal{ToolAllowlist: map[string][]string{"remote": {"read"}}, AccessPolicy: config.Restricted,

		TokenEnv: "TEST_REMOTE_TOKEN", Grants: map[string]map[string]config.Grant{"remote": {"read": {}}}}
	p := f.config.Principals["local"]
	p.AccessPolicy = config.Restricted
	p.ToolAllowlist = map[string][]string{"demo": {"echo", "error"}}
	f.config.Principals["local"] = p
	f.write()
	verifier, tokens := accessFixture(t, map[string]string{"alice@example.net": "local", "bob@example.net": "remote"})
	policyPath := filepath.Join(t.TempDir(), "read-batch.json")
	policyBytes, _ := json.Marshal(map[string]any{"version": 1, "operations": []map[string]string{{"server_id": "demo", "tool_name": "echo", "endpoint": f.config.Servers["demo"].URL}}})
	if err := os.WriteFile(policyPath, policyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	cache := catalog.New()
	t.Cleanup(cache.Close)
	h, err := (&Gateway{Path: f.path, PublicOrigin: "https://mcp.example.org", AccessOAuth: verifier, Catalog: cache, ReadBatch: NewReadBatchExecutor(&ReadBatchPolicy{Path: policyPath})}).Handler()
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(h)
	t.Cleanup(web.Close)
	var identity atomic.Value
	identity.Store("alice@example.net")
	client := &http.Client{Transport: accessRoundTrip(func(r *http.Request) (*http.Response, error) {
		email := identity.Load().(string)
		r.Host = "mcp.example.org"
		r.Header.Set("Cf-Access-Jwt-Assertion", tokens(email))
		r.Header.Set("Authorization", "Bearer oauth:syntheticopaque")
		return http.DefaultTransport.RoundTrip(r)
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "access-test", Version: "1"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: web.URL + "/mcp/oauth", HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	call := func(want string, wantErr bool) {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "discover_server", Arguments: map[string]any{"query": ""}})
		if wantErr {
			if err == nil {
				t.Fatalf("expected transport denial; got result %#v", res)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(res.StructuredContent)
		var out struct {
			Servers []struct {
				ID string `json:"id"`
			} `json:"servers"`
		}
		if err := json.Unmarshal(b, &out); err != nil || len(out.Servers) != 1 || out.Servers[0].ID != want {
			t.Fatalf("identity %q saw unexpected servers: %s (decode=%v)", identity.Load(), b, err)
		}
	}
	call("demo", false)
	identity.Store("bob@example.net")
	call("remote", false)
	identity.Store("alice@example.net")
	call("demo", false)
	invoked, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_tool", Arguments: invocation("synthetic oauth invoke")})
	if err != nil || invoked.IsError || invoked.StructuredContent.(map[string]any)["text"] != "synthetic oauth invoke" {
		t.Fatalf("synthetic upstream invocation failed: %#v %v", invoked, err)
	}
	batchArgs := map[string]any{"operations": []any{map[string]any{"id": "one", "server_id": "demo", "tool_name": "echo", "arguments": map[string]any{"text": "synthetic oauth batch"}}}}
	batch, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_read_batch", Arguments: batchArgs})
	if err != nil || batch.IsError {
		t.Fatalf("synthetic OAuth batch failed: %#v %v", batch, err)
	}
	var batchOut struct {
		Results []struct {
			Status     string `json:"status"`
			Dispatched bool   `json:"dispatched"`
		} `json:"results"`
	}
	encoded, _ := json.Marshal(batch.StructuredContent)
	if err := json.Unmarshal(encoded, &batchOut); err != nil {
		t.Fatal(err)
	}
	if len(batchOut.Results) != 1 || batchOut.Results[0].Status != "ok" || !batchOut.Results[0].Dispatched {
		t.Fatalf("OAuth batch item did not succeed: %s", encoded)
	}
	identity.Store("alice@example.net")
	p = f.config.Principals["local"]
	p.ToolAllowlist = map[string][]string{}
	f.config.Principals["local"] = p
	f.write()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_tool", Arguments: map[string]any{"server_id": "demo", "tool_name": "echo", "arguments": map[string]any{"text": "blocked"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("grant removal did not deny ordinary tool call")
	}
	batch, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "invoke_read_batch", Arguments: batchArgs})
	if err != nil || batch.IsError {
		t.Fatalf("revoked batch should return per-item denial: %#v %v", batch, err)
	}
	encoded, _ = json.Marshal(batch.StructuredContent)
	if err := json.Unmarshal(encoded, &batchOut); err != nil {
		t.Fatal(err)
	}
	if len(batchOut.Results) != 1 || batchOut.Results[0].Status != "denied" || batchOut.Results[0].Dispatched {
		t.Fatalf("batch admission did not recheck current grant: %s", encoded)
	}
	identity.Store("bob@example.net")
	delete(f.config.Principals, "remote")
	f.write()
	call("", true)
}
