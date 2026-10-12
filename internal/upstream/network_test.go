package upstream

import (
	"context"
	"mcp-gateway/internal/config"
	"net/netip"
	"testing"
	"time"
)

func TestPublicIP(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "192.168.1.1", "0.1.2.3", "192.0.2.1", "192.88.99.1", "2001:20::1", "198.18.0.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "2001:db8::1", "64:ff9b::a00:1", "2002:a00:1::"} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Errorf("allowed reserved %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(raw)) {
			t.Errorf("blocked public %s", raw)
		}
	}
}
func TestPrivateHTTPSBlocked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, url := range []string{"https://127.0.0.1/mcp", "https://[::1]/mcp", "https://169.254.169.254/mcp", "https://127.0.0.1:8888/mcp"} {
		if _, close, e := ConnectWithToken(ctx, config.Server{URL: url}, "synthetic-upstream-token"); e == nil {
			close()
			t.Fatal("private endpoint allowed")
		}
	}
}
