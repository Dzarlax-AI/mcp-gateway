package main

import "testing"

func TestAdminBindRequiresExplicitHTTPS(t *testing.T) {
	for _, x := range [][2]string{{"127.0.0.1:8081", "http://127.0.0.1:8081"}, {"0.0.0.0:8081", "https://mcp.example.com"}} {
		if e := validateAdminListen(x[0], x[1]); e != nil {
			t.Fatal(e)
		}
	}
	for _, x := range [][2]string{{"0.0.0.0:8081", "http://example.com"}, {"127.0.0.1:8081", "http://evil.example"}, {"127.0.0.1:8081", "http://127.0.0.1:8081/?token=x"}, {"localhost:8081", "https://mcp.example.com"}} {
		if e := validateAdminListen(x[0], x[1]); e == nil {
			t.Fatal("unsafe admin bind", x)
		}
	}
}

func TestAdminAuthEnvironment(t *testing.T) {
	t.Setenv("GATEWAY_ADMIN_AUTH_MODE", "authentik")
	t.Setenv("GATEWAY_ADMIN_TOKEN", "")
	t.Setenv("GATEWAY_ADMIN_BASE_PATH", "/gateway")
	t.Setenv("GATEWAY_ADMIN_TRUSTED_PROXY_CIDRS", "192.0.2.2/32,2001:db8::2/128")
	t.Setenv("GATEWAY_ADMIN_ALLOWED_USERS", "alice,bob")
	t.Setenv("GATEWAY_ADMIN_ALLOWED_GROUPS", "gateway-admins")
	o := adminOptions("https://mcp.example.com")
	if o.AuthMode != "authentik" || o.Token != "" || o.BasePath != "/gateway" || len(o.TrustedProxyCIDRs) != 2 || len(o.AllowedUsers) != 2 || len(o.AllowedGroups) != 1 {
		t.Fatal("SSO env contract")
	}
	t.Setenv("GATEWAY_ADMIN_ALLOWED_USERS", "alice,")
	if o = adminOptions("https://mcp.example.com"); len(o.AllowedUsers) != 2 || o.AllowedUsers[1] != "" {
		t.Fatal("empty entry must reach strict validation")
	}
}

func TestAdminAccessEnvironment(t *testing.T) {
	t.Setenv("GATEWAY_ADMIN_AUTH_MODE", "cloudflare")
	t.Setenv("GATEWAY_ADMIN_ACCESS_ISSUER", "https://issuer.example.org")
	t.Setenv("GATEWAY_ADMIN_ACCESS_AUD", "admin-aud")
	t.Setenv("GATEWAY_ADMIN_ACCESS_ALLOWED_EMAILS", "alice@example.net,bob@example.net")
	t.Setenv("GATEWAY_MCP_ACCESS_AUD", "mcp-aud")
	o := adminOptions("https://mcp.example.com")
	if o.AuthMode != "cloudflare" || o.AccessIssuer != "https://issuer.example.org" || o.AccessAudience != "admin-aud" || len(o.AccessEmails) != 2 {
		t.Fatal("admin Access env contract")
	}
	t.Setenv("GATEWAY_ADMIN_ACCESS_ALLOWED_EMAILS", "alice@example.net,")
	if o = adminOptions("https://mcp.example.com"); len(o.AccessEmails) != 2 || o.AccessEmails[1] != "" {
		t.Fatal("empty entry must reach validation")
	}
}
