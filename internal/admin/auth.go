package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"mcp-gateway/internal/accessauth"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type session struct {
	csrf    string
	user    string
	expires time.Time
}
type attempt struct {
	count int
	until time.Time
}
type auth struct {
	basePath            string
	mu                  sync.Mutex
	sessions            map[string]session
	attempts            map[string]attempt
	token, host, origin string
	secure              bool
	forward             *forwardAuth
	access              *accessauth.Verifier
}

func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("random source unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func newAuth(token, origin string) (*auth, error) {
	if len(token) < 16 || strings.ContainsAny(token, " \r\n\t") {
		return nil, errInput
	}
	a, err := newBaseAuth(origin)
	if err != nil {
		return nil, err
	}
	a.token = token
	return a, nil
}
func newBaseAuth(origin string) (*auth, error) {
	u, e := url.Parse(origin)
	if e != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) {
		return nil, errInput
	}
	return &auth{sessions: map[string]session{}, attempts: map[string]attempt{}, host: u.Host, origin: origin, secure: u.Scheme == "https"}, nil
}
func (a *auth) cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: a.basePath + "/admin/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func (a *auth) validRequest(r *http.Request) bool {
	if r.Host != a.host {
		return false
	}
	if r.Method == http.MethodPost {
		v := r.Header.Values("Origin")
		return len(v) == 1 && v[0] == a.origin
	}
	return true
}
func (a *auth) current(r *http.Request) (session, bool) {
	c, e := r.Cookie("gateway_admin")
	if e != nil {
		return session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok || time.Now().After(s.expires) {
		delete(a.sessions, c.Value)
		return session{}, false
	}
	return s, true
}
func (a *auth) csrf(r *http.Request, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(r.Form.Get("csrf")), []byte(want)) == 1
}
func (a *auth) loginAllowed(peer string) bool {
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, v := range a.attempts {
		if now.After(v.until) {
			delete(a.attempts, k)
		}
	}
	v, ok := a.attempts[peer]
	if !ok {
		if len(a.attempts) >= 1024 {
			return false
		}
		v = attempt{until: now.Add(time.Minute)}
	}
	v.count++
	a.attempts[peer] = v
	return v.count <= 5
}
func (a *auth) login(w http.ResponseWriter, r *http.Request) bool {
	c, e := r.Cookie("gateway_login_csrf")
	if e != nil || !a.csrf(r, c.Value) {
		http.Error(w, "Invalid CSRF token", 403)
		return false
	}
	if !a.loginAllowed(r.RemoteAddr) {
		http.Error(w, "Too many login attempts", 429)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(r.Form.Get("token")), []byte(a.token)) != 1 {
		http.Error(w, "Invalid credentials", 401)
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, v := range a.sessions {
		if now.After(v.expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 256 {
		http.Error(w, "Session limit reached", 429)
		return false
	}
	id := random()
	a.sessions[id] = session{csrf: random(), expires: now.Add(8 * time.Hour)}
	a.cookie(w, "gateway_admin", id, 8*3600)
	a.cookie(w, "gateway_login_csrf", "", -1)
	http.Redirect(w, r, a.basePath+"/admin/servers", http.StatusSeeOther)
	return true
}
func (a *auth) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("gateway_admin"); e == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	a.cookie(w, "gateway_admin", "", -1)
	target := a.basePath + "/admin/login"
	if a.forward != nil {
		target = "/outpost.goauthentik.io/sign_out"
	} else if a.access != nil {
		target = "/cdn-cgi/access/logout"
	}
	http.Redirect(w, r, target, 303)
}
