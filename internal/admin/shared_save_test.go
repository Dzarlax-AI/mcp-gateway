package admin

import (
	"context"
	"fmt"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"net/url"
	"strings"
	"testing"
)

func TestSaveSharedUpstreamCredentials(t *testing.T) {
	h, s := adminFixture(t)
	cookie, csrf := login(t, h)
	ctx := context.Background()
	token := "synthetic-shared-upstream-token"
	for _, id := range []string{"first", "second"} {
		snap, err := s.ReadSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "id": {id}, "url": {"http://127.0.0.1:9999/mcp"}, "auth_mode": {"bearer"}, "secret": {token}}
		w := request(h, "POST", "/admin/servers/create", form, cookie)
		if w.Code != 303 {
			t.Fatalf("shared create %s status=%d", id, w.Code)
		}
	}
	// Changing a distinct credential back to a shared one follows the same path.
	for _, value := range []string{"synthetic-distinct-upstream-token", token} {
		snap, err := s.ReadSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		w := request(h, "POST", "/admin/servers/second/update", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "url": {"http://127.0.0.1:9999/mcp"}, "auth_mode": {"header"}, "auth_header": {"X-Api-Key"}, "secret": {value}}, cookie)
		if w.Code != 303 {
			t.Fatalf("shared update status=%d", w.Code)
		}
	}
	snap, err := s.ReadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "second"} {
		if got, err := store.ResolveSnapshotSecret(snap, id); err != nil || got != token {
			t.Fatal("saved shared value", id, err)
		}
		if snap.Config.Servers[id].Enabled {
			t.Fatal("credential replacement enabled server")
		}
	}
	body := request(h, "GET", "/admin/servers", nil, cookie).Body.String()
	if strings.Contains(body, token) {
		t.Fatal("credential leaked into HTML")
	}
}

type rejectedCredentialStore struct{ store.Store }

func (s rejectedCredentialStore) CompareAndSwap(context.Context, int64, *config.Config, map[string]*string) (store.Snapshot, error) {
	return store.Snapshot{}, store.ErrSecret
}

func TestServerSaveCredentialRejectionAndUnknownCommit(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			h, s := adminFixture(t)
			cookie, csrf := login(t, h)
			snap, err := s.ReadSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if unknown {
				h.s = &permissionUnknownStore{Store: s}
			} else {
				h.s = rejectedCredentialStore{Store: s}
			}
			w := request(h, "POST", "/admin/servers/create", url.Values{"csrf": {csrf}, "revision": {fmt.Sprint(snap.Revision)}, "id": {"new"}, "url": {"http://127.0.0.1:9999/mcp"}, "auth_mode": {"none"}}, cookie)
			want := 400
			if unknown {
				want = 503
			}
			if w.Code != want {
				t.Fatalf("status=%d want=%d", w.Code, want)
			}
			if strings.Contains(w.Body.String(), "could not be confirmed") != unknown {
				t.Fatal("wrong failure classification")
			}
			after, err := s.ReadSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			delta := int64(0)
			if unknown {
				delta = 1
			}
			if after.Revision != snap.Revision+delta {
				t.Fatal("unexpected saved state")
			}
		})
	}
}
