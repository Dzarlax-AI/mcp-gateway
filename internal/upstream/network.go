package upstream

import (
	"context"
	"net"
	"net/netip"
	"time"
)

var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range deniedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// Resolve once and dial the validated IP; the TLS hostname remains the endpoint hostname.
func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil || port != "443" {
		return nil, ErrUpstream
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil || len(ips) == 0 {
		return nil, ErrUpstream
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, ErrUpstream
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	for _, ip := range ips {
		c, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, ErrUpstream
}
