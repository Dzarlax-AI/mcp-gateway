package gateway

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var dnsHost = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ValidatePublicOrigin accepts only a canonical HTTPS origin, never forwarded headers.
func ValidatePublicOrigin(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || raw != "https://"+u.Host || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("public origin must be a canonical HTTPS origin without path or credentials")
	}
	host := u.Hostname()
	if len(host) > 253 || host != strings.ToLower(host) || (net.ParseIP(host) == nil && !dnsHost.MatchString(host)) {
		return errors.New("invalid public origin host")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return errors.New("invalid public origin port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return errors.New("invalid public origin port")
	}
	return nil
}
