package admin

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

// Identity headers are trusted only from a pinned immediate proxy peer.
// Forwarded client addresses never participate in this decision.
type forwardAuth struct {
	peers         []netip.Prefix
	users, groups map[string]bool
}

func identityValue(s string) bool {
	if s == "" || len(s) > 256 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ',' || r == '|' {
			return false
		}
	}
	return true
}

func identitySet(values []string) (map[string]bool, error) {
	result := map[string]bool{}
	if len(values) > 256 {
		return nil, errInput
	}
	for _, v := range values {
		// Configuration permits padding around comma-separated entries.
		v = strings.TrimSpace(v)
		if !identityValue(v) || result[v] {
			return nil, errInput
		}
		result[v] = true
	}
	return result, nil
}

func newConfiguredAuth(o Options) (*auth, error) {
	mode := o.AuthMode
	if mode == "" {
		mode = "token"
	}
	if mode == "token" {
		if len(o.TrustedProxyCIDRs)+len(o.AllowedUsers)+len(o.AllowedGroups) != 0 {
			return nil, errInput
		}
		return newAuth(o.Token, o.Origin)
	}
	if mode != "authentik" || o.Token != "" || len(o.TrustedProxyCIDRs) == 0 || len(o.TrustedProxyCIDRs) > 16 {
		return nil, errInput
	}
	f := &forwardAuth{}
	for _, raw := range o.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		// Require individual addresses, never a whole shared Docker subnet.
		if err != nil || prefix.Addr().Is4In6() || prefix.Bits() != prefix.Addr().BitLen() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return nil, errInput
		}
		f.peers = append(f.peers, prefix)
	}
	var err error
	f.users, err = identitySet(o.AllowedUsers)
	if err != nil {
		return nil, err
	}
	f.groups, err = identitySet(o.AllowedGroups)
	if err != nil || len(f.users)+len(f.groups) == 0 {
		return nil, errInput
	}
	a, err := newBaseAuth(o.Origin)
	if err != nil {
		return nil, err
	}
	a.forward = f
	return a, nil
}

func (f *forwardAuth) identity(r *http.Request) (string, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	addr = addr.Unmap()
	trusted := false
	for _, peer := range f.peers {
		if peer.Contains(addr) {
			trusted = true
			break
		}
	}
	if !trusted {
		return "", false
	}
	usernames := r.Header.Values("X-authentik-username")
	if len(usernames) != 1 || !identityValue(usernames[0]) {
		return "", false
	}
	user := usernames[0]
	values := r.Header.Values("X-authentik-groups")
	if len(values) > 1 {
		return "", false
	}
	groupAllowed := false
	if len(values) == 1 {
		if len(values[0]) > 8192 {
			return "", false
		}
		seen := map[string]bool{}
		parts := strings.Split(values[0], "|")
		if len(parts) > 256 {
			return "", false
		}
		for _, group := range parts {
			if !identityValue(group) || seen[group] {
				return "", false
			}
			seen[group] = true
			if f.groups[group] {
				groupAllowed = true
			}
		}
	}
	return user, f.users[user] || groupAllowed
}

func (a *auth) ssoSession(w http.ResponseWriter, r *http.Request, user string) (session, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for id, s := range a.sessions {
		if now.After(s.expires) {
			delete(a.sessions, id)
		}
	}
	// A changed identity cannot reuse or keep the old browser session alive.
	if c, err := r.Cookie("gateway_admin"); err == nil {
		delete(a.sessions, c.Value)
	}
	if len(a.sessions) >= 256 {
		return session{}, false
	}
	id := random()
	s := session{csrf: random(), user: user, expires: now.Add(8 * time.Hour)}
	a.sessions[id] = s
	a.cookie(w, "gateway_admin", id, 8*3600)
	return s, true
}
