package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func ssoOptions() Options {
	return Options{Origin: "https://mcp.example.com", BasePath: "/gateway", AuthMode: "authentik", TrustedProxyCIDRs: []string{"192.0.2.2/32", "2001:db8::2/128"}, AllowedGroups: []string{"gateway-admins"}}
}
func TestForwardAuthConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Options)
	}{
		{"mode", func(o *Options) { o.AuthMode = "unknown" }},
		{"token", func(o *Options) { o.Token = adminToken }},
		{"no peer", func(o *Options) { o.TrustedProxyCIDRs = nil }},
		{"bad peer", func(o *Options) { o.TrustedProxyCIDRs = []string{"invalid"} }},
		{"subnet", func(o *Options) { o.TrustedProxyCIDRs = []string{"192.0.2.0/24"} }},
		{"no policy", func(o *Options) { o.AllowedGroups = nil }},
		{"empty policy", func(o *Options) { o.AllowedGroups = []string{""} }},
		{"duplicate", func(o *Options) { o.AllowedGroups = []string{"admins", "admins"} }},
		{"pipe", func(o *Options) { o.AllowedGroups = []string{"admins|users"} }},
		{"comma", func(o *Options) { o.AllowedUsers = []string{"a,b"} }},
		{"control", func(o *Options) { o.AllowedUsers = []string{"a\nb"} }},
		{"mixed token mode", func(o *Options) { o.AuthMode = "token"; o.Token = adminToken }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := ssoOptions()
			tc.change(&o)
			if _, err := newConfiguredAuth(o); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}
func TestForwardAuthIdentity(t *testing.T) {
	a, err := newConfiguredAuth(ssoOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, peer, user, groups string
		modify                   func(*http.Request)
		want                     bool
	}{
		{name: "allowed group", peer: "192.0.2.2:123", user: "alice", groups: "users|gateway-admins", want: true},
		{name: "ipv6", peer: "[2001:db8::2]:123", user: "alice", groups: "gateway-admins", want: true},
		{name: "mapped ipv4", peer: "[::ffff:192.0.2.2]:123", user: "alice", groups: "gateway-admins", want: true},
		{name: "untrusted", peer: "192.0.2.3:123", user: "alice", groups: "gateway-admins"},
		{name: "spoof forwarded", peer: "192.0.2.3:123", user: "alice", groups: "gateway-admins", modify: func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "192.0.2.2")
			r.Header.Set("X-Real-IP", "192.0.2.2")
		}},
		{name: "missing identity", peer: "192.0.2.2:123", groups: "gateway-admins"},
		{name: "substring", peer: "192.0.2.2:123", user: "alice", groups: "gateway-admins-extra"},
		{name: "duplicate user", peer: "192.0.2.2:123", user: "alice", groups: "gateway-admins", modify: func(r *http.Request) { r.Header.Add("X-authentik-username", "alice") }},
		{name: "duplicate group header", peer: "192.0.2.2:123", user: "alice", groups: "gateway-admins", modify: func(r *http.Request) { r.Header.Add("X-authentik-groups", "users") }},
		{name: "duplicate group", peer: "192.0.2.2:123", user: "alice", groups: "gateway-admins|gateway-admins"},
		{name: "empty group", peer: "192.0.2.2:123", user: "alice", groups: "gateway-admins|"},
		{name: "combined username", peer: "192.0.2.2:123", user: "alice,bob", groups: "gateway-admins"},
		{name: "bad remote", peer: "192.0.2.2", user: "alice", groups: "gateway-admins"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://mcp.example.com/admin/servers", nil)
			r.RemoteAddr = tc.peer
			if tc.user != "" {
				r.Header.Set("X-authentik-username", tc.user)
			}
			if tc.groups != "" {
				r.Header.Set("X-authentik-groups", tc.groups)
			}
			if tc.modify != nil {
				tc.modify(r)
			}
			_, ok := a.forward.identity(r)
			if ok != tc.want {
				t.Fatal("authorization", ok)
			}
		})
	}
	a.forward.users["bob"] = true
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.2:99"
	r.Header.Set("X-authentik-username", "bob")
	if _, ok := a.forward.identity(r); !ok {
		t.Fatal("explicit username rejected")
	}
	r.Header.Set("X-authentik-groups", "")
	if _, ok := a.forward.identity(r); ok {
		t.Fatal("ambiguous empty header")
	}
}

func TestSSOHandlerSessionsAndRevocation(t *testing.T) {
	_, s := adminFixture(t)
	raw, err := New(s, ssoOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := raw.(*handler)
	req := func(method, path, user, groups string, form url.Values, cookie *http.Cookie, alter func(*http.Request)) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://mcp.example.com"+path, strings.NewReader(form.Encode()))
		r.RemoteAddr = "192.0.2.2:321"
		r.Header.Set("X-authentik-username", user)
		r.Header.Set("X-authentik-groups", groups)
		if method == "POST" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "https://mcp.example.com")
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
	w := req("GET", "/admin/servers", "alice", "gateway-admins", nil, nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "alice via Authentik") {
		t.Fatal("SSO page", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	sess := h.a.sessions[cookie.Value]
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/gateway/admin/" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie flags")
	}
	good := url.Values{"csrf": {sess.csrf}, "revision": {"1"}, "id": {"fixture"}, "url": {"http://127.0.0.1:1234/mcp"}}
	if w = req("POST", "/admin/servers/create", "alice", "gateway-admins", good, cookie, nil); w.Code != 303 {
		t.Fatal("mutation", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		name, user, groups string
		alter              func(*http.Request)
	}{
		{name: "no SSO", user: "", groups: ""}, {name: "group revoked", user: "alice", groups: "users"},
		{name: "wrong peer", user: "alice", groups: "gateway-admins", alter: func(r *http.Request) { r.RemoteAddr = "192.0.2.8:321" }},
		{name: "changed identity POST", user: "bob", groups: "gateway-admins"},
		{name: "wrong origin", user: "alice", groups: "gateway-admins", alter: func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
		{name: "wrong host", user: "alice", groups: "gateway-admins", alter: func(r *http.Request) { r.Host = "evil.example" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := req("POST", "/admin/servers/create", tc.user, tc.groups, good, cookie, tc.alter)
			if w.Code != 403 && w.Code != 401 {
				t.Fatal("accepted unauthorized mutation", w.Code)
			}
		})
	}
	if w = req("POST", "/admin/login", "alice", "gateway-admins", url.Values{"token": {adminToken}}, cookie, nil); w.Code != 403 {
		t.Fatal("token fallback")
	}
	if w = req("GET", "/admin/login", "alice", "gateway-admins", nil, nil, nil); w.Code != 303 || w.Header().Get("Location") != "/gateway/admin/servers" {
		t.Fatal("SSO login")
	}
	if w = req("POST", "/admin/logout", "alice", "gateway-admins", url.Values{"csrf": {"wrong"}}, cookie, nil); w.Code != 403 {
		t.Fatal("logout CSRF")
	}
	// Switching identity creates a new bound session and invalidates the old one.
	w = req("GET", "/admin/servers", "bob", "gateway-admins", nil, cookie, nil)
	next := w.Result().Cookies()[0]
	nextSession := h.a.sessions[next.Value]
	if nextSession.user != "bob" || nextSession.csrf == sess.csrf {
		t.Fatal("identity inherited session")
	}
	if _, ok := h.a.sessions[cookie.Value]; ok {
		t.Fatal("old session retained")
	}
	h.a.sessions[next.Value] = session{csrf: nextSession.csrf, user: "bob", expires: time.Now().Add(-time.Second)}
	if w = req("POST", "/admin/logout", "bob", "gateway-admins", url.Values{"csrf": {nextSession.csrf}}, next, nil); w.Code != 401 {
		t.Fatal("expired session")
	}
	w = req("GET", "/admin/servers", "bob", "gateway-admins", nil, nil, nil)
	next = w.Result().Cookies()[0]
	nextSession = h.a.sessions[next.Value]
	w = req("POST", "/admin/logout", "bob", "gateway-admins", url.Values{"csrf": {nextSession.csrf}, "next": {"https://evil.example"}}, next, nil)
	if w.Code != 303 || w.Header().Get("Location") != "/outpost.goauthentik.io/sign_out" {
		t.Fatal("logout redirect")
	}
	if _, ok := h.a.sessions[next.Value]; ok {
		t.Fatal("logout retained session")
	}
}
