package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"

	"mcp-gateway/internal/accessauth"
)

func hasAccessOptions(o Options) bool {
	return o.AccessIssuer != "" || o.AccessAudience != "" || len(o.AccessEmails) != 0
}

func newAccessAuth(o Options) (*auth, error) {
	if o.Token != "" || len(o.TrustedProxyCIDRs)+len(o.AllowedUsers)+len(o.AllowedGroups) != 0 || !strings.HasPrefix(o.Origin, "https://") {
		return nil, errInput
	}
	emails, err := identitySet(o.AccessEmails)
	if err != nil || len(emails) == 0 {
		return nil, errInput
	}
	users := make(map[string]string, len(emails))
	for email := range emails {
		parsed, err := mail.ParseAddress(email)
		if err != nil || parsed.Address != email {
			return nil, errInput
		}
		// Principal IDs are internal to this verifier; admin identities never map
		// to MCP principals. Hashing keeps verifier IDs within its length bound.
		digest := sha256.Sum256([]byte(email))
		users[email] = hex.EncodeToString(digest[:])
	}
	verifier, err := accessauth.New(accessauth.Options{Issuer: o.AccessIssuer, Audience: o.AccessAudience, Users: users})
	if err != nil {
		return nil, errInput
	}
	a, err := newBaseAuth(o.Origin)
	if err != nil {
		return nil, err
	}
	a.access = verifier
	return a, nil
}

func (a *auth) sso() bool { return a.forward != nil || a.access != nil }
func (a *auth) provider() string {
	if a.access != nil {
		return "Cloudflare Access"
	}
	if a.forward != nil {
		return "Authentik"
	}
	return ""
}

// Both providers return a display identity and an unambiguous session binding.
func (a *auth) identity(r *http.Request) (string, string, bool) {
	if a.forward != nil {
		user, ok := a.forward.identity(r)
		return user, user, ok
	}
	values := r.Header.Values("Cf-Access-Jwt-Assertion")
	if a.access == nil || len(values) != 1 {
		return "", "", false
	}
	id, err := a.access.Verify(r.Context(), values[0])
	if err != nil {
		return "", "", false
	}
	// Encode the tuple rather than concatenate identity fields with a delimiter.
	binding, _ := json.Marshal([]string{id.Principal, id.Subject})
	digest := sha256.Sum256(binding)
	return id.Email, hex.EncodeToString(digest[:]), true
}
