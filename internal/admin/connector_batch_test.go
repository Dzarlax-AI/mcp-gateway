package admin

import (
	"context"
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/readpolicy"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestConnectorBatchActionsCASAndCredentialReset(t *testing.T) {
	h, s := adminFixture(t)
	h.batchRegistry = true
	cookie, csrf := login(t, h)
	snap, _ := s.ReadSnapshot(context.Background())
	name := "llm__GetDateTime"
	snap.Config.Servers["ha"] = config.Server{URL: "http://127.0.0.1:18082/mcp", Tools: map[string]config.Tool{name: {Enabled: true, AccessMode: "shared"}}, Enabled: true}
	snap, e := s.CompareAndSwap(context.Background(), snap.Revision, snap.Config, nil)
	if e != nil {
		t.Fatal(e)
	}
	post := func(action string, extra url.Values) int {
		now, _ := s.ReadSnapshot(context.Background())
		f := values(csrf, now.Revision)
		for k, v := range extra {
			f[k] = v
		}
		return request(h, "POST", "/admin/servers/ha/"+action, f, cookie).Code
	}
	if code := post("batch-profile", url.Values{"batch_read_profile": {"home-assistant-v1"}}); code != 303 {
		t.Fatalf("profile %d", code)
	}
	snap, _ = s.ReadSnapshot(context.Background())
	key, _ := connectionKey(snap, "ha")
	h.probes["ha"] = probe{revision: snap.Revision, key: key, at: time.Now(), tools: map[string]*mcp.Tool{name: readpolicy.ReviewedTools("home-assistant-v1")[1]}}
	if code := post("batch-enable", nil); code != 303 {
		t.Fatalf("enable %d", code)
	}
	snap, _ = s.ReadSnapshot(context.Background())
	if !snap.Config.Servers["ha"].BatchReadEnabled {
		t.Fatal("batch not saved")
	}
	page := request(h, "GET", "/admin/servers", nil, cookie)
	if !strings.Contains(page.Body.String(), "Batch for reads") || !strings.Contains(page.Body.String(), "Verified read") {
		t.Fatal("missing UI eligibility")
	}
	stale := values(csrf, snap.Revision-1)
	if code := request(h, "POST", "/admin/servers/ha/batch-disable", stale, cookie).Code; code != 409 {
		t.Fatalf("CAS %d", code)
	}
	if code := post("batch-disable", nil); code != 303 {
		t.Fatalf("disable %d", code)
	}
	if code := post("batch-enable", nil); code != 303 {
		t.Fatalf("reenable %d", code)
	}
	if code := post("update", url.Values{"url": {"http://127.0.0.1:18083/mcp"}, "auth_mode": {"none"}}); code != 303 {
		t.Fatalf("endpoint %d", code)
	}
	snap, _ = s.ReadSnapshot(context.Background())
	srv := snap.Config.Servers["ha"]
	if srv.BatchReadEnabled || srv.BatchReadEndpoint != "" {
		t.Fatal("endpoint kept batch approval")
	}
	h.batchRegistry = false
	if code := post("batch-profile", url.Values{"batch_read_profile": {"home-assistant-v1"}}); code != 400 {
		t.Fatalf("file mode %d", code)
	}
}
func values(csrf string, rev int64) url.Values {
	b, _ := json.Marshal(rev)
	return url.Values{"csrf": {csrf}, "revision": {string(b)}}
}

func TestConnectorBatchAuthChangesClearApproval(t *testing.T) {
	for _, mode := range []string{"replacement", "header", "none"} {
		t.Run(mode, func(t *testing.T) {
			h, s := adminFixture(t)
			h.batchRegistry = true
			cookie, csrf := login(t, h)
			snap, _ := s.ReadSnapshot(context.Background())
			token := "synthetic-original-upstream-token"
			snap.Config.Servers["ha"] = config.Server{URL: "http://127.0.0.1:18082/mcp", Enabled: true, TokenRef: "ha", BatchReadEnabled: true, BatchReadEndpoint: "http://127.0.0.1:18082/mcp", BatchReadProfile: "home-assistant-v1", Tools: map[string]config.Tool{"llm__GetDateTime": {Enabled: true, AccessMode: "shared"}}}
			snap, e := s.CompareAndSwap(context.Background(), snap.Revision, snap.Config, map[string]*string{"ha": &token})
			if e != nil {
				t.Fatal(e)
			}
			f := values(csrf, snap.Revision)
			f.Set("url", snap.Config.Servers["ha"].URL)
			f.Set("auth_mode", "bearer")
			switch mode {
			case "replacement":
				f.Set("secret", "synthetic-replacement-upstream-token")
			case "header":
				f.Set("auth_mode", "header")
				f.Set("auth_header", "X-API-Key")
			case "none":
				f.Set("auth_mode", "none")
			}
			if code := request(h, "POST", "/admin/servers/ha/update", f, cookie).Code; code != 303 {
				t.Fatalf("update %d", code)
			}
			snap, _ = s.ReadSnapshot(context.Background())
			server := snap.Config.Servers["ha"]
			if server.BatchReadEnabled || server.BatchReadEndpoint != "" || server.Enabled {
				t.Fatal("connection change kept approval")
			}
		})
	}
}
