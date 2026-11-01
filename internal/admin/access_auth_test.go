package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"mcp-gateway/internal/accessauth"
)

func accessOptions() Options {
	return Options{AuthMode: "cloudflare", Origin: "https://mcp.example.com", BasePath: "/gateway", AccessIssuer: "https://issuer.example.org", AccessAudience: "admin-aud", AccessEmails: []string{"alice@example.net", "bob@example.net"}}
}

func TestAccessAdminConfiguration(t *testing.T) {
	if _, err := newConfiguredAuth(accessOptions()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Options){
		"missing issuer":               func(o *Options) { o.AccessIssuer = "" },
		"invalid issuer":               func(o *Options) { o.AccessIssuer = "http://issuer.example.org" },
		"missing audience":             func(o *Options) { o.AccessAudience = "" },
		"missing emails":               func(o *Options) { o.AccessEmails = nil },
		"duplicate email":              func(o *Options) { o.AccessEmails = append(o.AccessEmails, o.AccessEmails[0]) },
		"invalid email":                func(o *Options) { o.AccessEmails = []string{"not-an-email"} },
		"display name":                 func(o *Options) { o.AccessEmails = []string{"Alice <alice@example.net>"} },
		"empty email":                  func(o *Options) { o.AccessEmails = append(o.AccessEmails, "") },
		"token fallback":               func(o *Options) { o.Token = adminToken },
		"proxy settings":               func(o *Options) { o.TrustedProxyCIDRs = []string{"192.0.2.2/32"} },
		"legacy users":                 func(o *Options) { o.AllowedUsers = []string{"alice"} },
		"legacy groups":                func(o *Options) { o.AllowedGroups = []string{"admins"} },
		"http origin":                  func(o *Options) { o.Origin = "http://127.0.0.1:8081" },
		"token with access config":     func(o *Options) { o.AuthMode = "token"; o.Token = adminToken },
		"authentik with access config": func(o *Options) { *o = ssoOptions(); o.AccessAudience = "admin-aud" },
	} {
		t.Run(name, func(t *testing.T) {
			o := accessOptions()
			change(&o)
			if _, err := newConfiguredAuth(o); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestAccessAdminRequests(t *testing.T) {
	_, store := adminFixture(t)
	raw, err := New(store, accessOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := raw.(*handler)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// An actual HTTPS JWKS fixture exercises signature verification in the handler.
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "key-a", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer jwks.Close()
	client := jwks.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h.a.access, err = accessauth.NewForTesting(accessauth.Options{Issuer: accessOptions().AccessIssuer, Audience: "admin-aud", Users: map[string]string{"alice@example.net": "a", "bob@example.net": "b"}}, jwks.URL, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(email, sub string, alter func(jwt.MapClaims)) string {
		t.Helper()
		now := time.Now()
		claims := jwt.MapClaims{"iss": accessOptions().AccessIssuer, "aud": "admin-aud", "email": email, "sub": sub, "type": "app", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix()}
		if alter != nil {
			alter(claims)
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "key-a"
		s, e := tok.SignedString(key)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	valid := sign("alice@example.net", "subject-a", nil)
	req := func(method, path, assertion string, form url.Values, cookie *http.Cookie, alter func(*http.Request)) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://mcp.example.com"+path, strings.NewReader(form.Encode()))
		if assertion != "" {
			r.Header.Set("Cf-Access-Jwt-Assertion", assertion)
		}
		if method == "POST" {
			r.Header.Set("Origin", "https://mcp.example.com")
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if alter != nil {
			alter(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := req("GET", "/admin/servers", valid, nil, nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "alice@example.net via Cloudflare Access") || strings.Contains(w.Body.String(), "via Authentik") {
		t.Fatal("SSO page", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	sess := h.a.sessions[cookie.Value]
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/gateway/admin/" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie flags")
	}
	if w = req("GET", "/admin/servers", valid, nil, cookie, nil); w.Code != 200 || len(w.Result().Cookies()) != 0 {
		t.Fatal("session not retained")
	}
	for _, path := range []string{"/admin/servers", "/admin/connection", "/admin/actions.js", "/admin/login"} {
		for _, assertion := range []string{"", "forged", valid + "," + valid} {
			if w = req("GET", path, assertion, nil, cookie, func(r *http.Request) {
				r.Header.Set("X-authentik-username", "alice")
				r.Header.Set("X-authentik-groups", "admins")
			}); w.Code != 403 {
				t.Fatal("unsigned headers/cookie accepted", path, w.Code)
			}
		}
	}
	for name, alter := range map[string]func(jwt.MapClaims){
		"issuer":       func(c jwt.MapClaims) { c["iss"] = "https://other.example.org" },
		"MCP audience": func(c jwt.MapClaims) { c["aud"] = "mcp-aud" },
		"email":        func(c jwt.MapClaims) { c["email"] = "Alice@example.net" },
		"expiry":       func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"iat":          func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Hour).Unix() },
		"subject":      func(c jwt.MapClaims) { delete(c, "sub") },
	} {
		t.Run(name, func(t *testing.T) {
			if w := req("GET", "/admin/servers", sign("alice@example.net", "subject-a", alter), nil, cookie, nil); w.Code != 403 {
				t.Fatal("bad assertion accepted", w.Code)
			}
		})
	}
	for name, alter := range map[string]func(*http.Request){
		"duplicate assertion": func(r *http.Request) { r.Header.Add("Cf-Access-Jwt-Assertion", valid) },
		"wrong host":          func(r *http.Request) { r.Host = "evil.example" },
		"wrong origin":        func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
	} {
		t.Run(name, func(t *testing.T) {
			if w := req("POST", "/admin/logout", valid, url.Values{"csrf": {sess.csrf}}, cookie, alter); w.Code != 403 {
				t.Fatal("invalid request accepted", w.Code)
			}
		})
	}
	if w = req("POST", "/admin/logout", valid, url.Values{"csrf": {"wrong"}}, cookie, nil); w.Code != 403 {
		t.Fatal("CSRF accepted")
	}
	if w = req("POST", "/admin/login", valid, url.Values{"token": {adminToken}}, nil, nil); w.Code != 403 {
		t.Fatal("token fallback")
	}
	if w = req("GET", "/admin/login", valid, nil, nil, nil); w.Code != 303 || w.Header().Get("Location") != "/gateway/admin/servers" {
		t.Fatal("SSO login")
	}
	good := url.Values{"csrf": {sess.csrf}, "revision": {"1"}, "id": {"fixture"}, "url": {"http://127.0.0.1:1234/mcp"}}
	if w = req("POST", "/admin/servers/create", valid, good, cookie, nil); w.Code != 303 {
		t.Fatal("authenticated action", w.Code, w.Body.String())
	}
	// Same email with a different signed subject is a different session identity.
	changed := sign("alice@example.net", "subject-b", nil)
	if w = req("POST", "/admin/logout", changed, url.Values{"csrf": {sess.csrf}}, cookie, nil); w.Code != 401 {
		t.Fatal("subject change reused CSRF")
	}
	w = req("GET", "/admin/servers", changed, nil, cookie, nil)
	next := w.Result().Cookies()[0]
	nextSess := h.a.sessions[next.Value]
	if nextSess.csrf == sess.csrf || nextSess.user == sess.user {
		t.Fatal("identity inherited session")
	}
	if _, ok := h.a.sessions[cookie.Value]; ok {
		t.Fatal("old session retained")
	}
	if w = req("POST", "/admin/logout", sign("bob@example.net", "subject-b", nil), url.Values{"csrf": {nextSess.csrf}}, next, nil); w.Code != 401 {
		t.Fatal("email change reused session")
	}
	w = req("POST", "/admin/logout", changed, url.Values{"csrf": {nextSess.csrf}, "next": {"https://evil.example"}}, next, nil)
	if w.Code != 303 || w.Header().Get("Location") != "/cdn-cgi/access/logout" {
		t.Fatal("logout redirect")
	}
	if _, ok := h.a.sessions[next.Value]; ok {
		t.Fatal("logout retained session")
	}
	if w = req("POST", "/admin/logout", changed, url.Values{"csrf": {nextSess.csrf}}, next, nil); w.Code != 401 {
		t.Fatal("logged-out session accepted")
	}
}

func TestTokenModeIndependentOfSSOHeaders(t *testing.T) {
	h, _ := adminFixture(t)
	cookie, csrf := login(t, h)
	r := httptest.NewRequest("GET", "http://127.0.0.1:8081/admin/servers", nil)
	r.Header.Set("Cf-Access-Jwt-Assertion", "invalid assertion")
	r.Header.Set("X-authentik-username", "spoofed")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatal("SSO headers authenticated token mode")
	}
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Signed in with administrator token.") {
		t.Fatal("token session requires SSO")
	}
	w = request(h, "POST", "/admin/logout", url.Values{"csrf": {csrf}}, cookie)
	if w.Code != 303 || w.Header().Get("Location") != "/admin/login" {
		t.Fatal("token logout")
	}
	if w = request(h, "GET", "/admin/servers", nil, cookie); w.Code != 303 {
		t.Fatal("token session not revoked")
	}
}
