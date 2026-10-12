package admin

import (
	"context"
	"mcp-gateway/internal/config"
	"net/url"
	"strings"
	"testing"
)

func TestCompactSwitchesAndClosedTools(t *testing.T) {
	h, s := adminFixture(t)
	snap, _ := s.ReadSnapshot(context.Background())
	c := clone(snap.Config)
	c.Servers["demo"] = config.Server{URL: "http://127.0.0.1:9999/mcp", Description: "<script>untrusted</script>", Tools: map[string]config.Tool{"read": {Enabled: true, AccessMode: "shared"}}}
	if _, err := s.CompareAndSwap(context.Background(), snap.Revision, c, nil); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := login(t, h)
	body := request(h, "GET", "/admin/servers", nil, cookie).Body.String()
	for _, want := range []string{`class="switch" role="switch" aria-checked="false" aria-label="Enable server demo"`, `aria-checked="true" aria-label="Enable tool read on server demo"`, `<details class="tools" data-tools>`, `data-server-unavailable`, `&lt;script&gt;untrusted&lt;/script&gt;`, `</details><form data-quick`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing compact UI contract %q", want)
		}
	}
	if strings.Contains(body, `<details class="tools" data-tools open`) || strings.Contains(body, "<script>untrusted") {
		t.Fatal("unsafe or expanded default")
	}
	// Plain forms remain usable without JavaScript and do not contact upstream on Disable.
	w := request(h, "POST", "/admin/servers/demo/tool-disable", url.Values{"csrf": {csrf}, "revision": {"2"}, "tool": {"read"}}, cookie)
	if w.Code != 303 {
		t.Fatal("HTML fallback", w.Code)
	}
	snap, _ = s.ReadSnapshot(context.Background())
	if snap.Config.Servers["demo"].Tools["read"].Enabled {
		t.Fatal("disable not persisted")
	}
}
