package config

import (
	"strings"
	"unicode"
)

// ValidAuthHeader permits one credential field without overriding routing,
// proxy identity, browser cookies or MCP transport semantics.
func ValidAuthHeader(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, c := range []byte(name) {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	n := strings.ToLower(name)
	for _, prefix := range []string{"proxy-", "x-forwarded-", "x-authentik-", "mcp-", "sec-"} {
		if strings.HasPrefix(n, prefix) {
			return false
		}
	}
	switch n {
	case "authorization", "host", "cookie", "set-cookie", "forwarded", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "content-length", "content-type", "content-encoding", "accept", "accept-encoding", "origin", "referer", "user-agent", "last-event-id", "expect", "via", "x-real-ip", "true-client-ip", "x-original-url", "x-original-host", "x-original-method", "x-rewrite-url":
		return false
	}
	return true
}

// ValidCredential keeps legacy Bearer constraints and allows literal custom
// field values, including spaces, but never controls or malformed text.
func ValidCredential(header, value string) bool {
	if header == "" {
		return len(value) >= 16 && len(value) <= 16<<10 && strings.IndexFunc(value, unicode.IsSpace) < 0 && strings.IndexFunc(value, unicode.IsControl) < 0
	}
	if !ValidAuthHeader(header) || len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, c := range []byte(value) {
		if c < 32 || c == 127 {
			return false
		}
	}
	// HTTP trims surrounding spaces: reject them rather than silently changing a key.
	return strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
