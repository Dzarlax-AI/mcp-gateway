package catalog

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/config"
)

func sampleConnection() Connection {
	return Connection{ID: "srv", Revision: 1, Server: config.Server{URL: "http://127.0.0.1:8081/mcp", Tools: map[string]config.Tool{}}, Token: "opaque-token"}
}
func sampleTools() []*mcp.Tool {
	return []*mcp.Tool{{Name: "echo", Description: "echo text", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}}}}
}

func TestGetTTLAndCloneIsolation(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	p := newProvider(options{now: func() time.Time { return now }, ttl: time.Minute, load: func(context.Context, Connection) ([]*mcp.Tool, error) { calls.Add(1); return sampleTools(), nil }})
	defer p.Close()
	c := sampleConnection()
	got, err := p.Get(context.Background(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	got[0].Description = "mutated"
	got[0].InputSchema.(map[string]any)["type"] = "mutated"
	got, err = p.Get(context.Background(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || got[0].Description != "echo text" || got[0].InputSchema.(map[string]any)["type"] != "object" {
		t.Fatalf("cache was not immutable: calls=%d tool=%+v", calls.Load(), got[0])
	}
	now = now.Add(time.Minute)
	if _, err = p.Get(context.Background(), c, false); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expired cache did not refresh: %d", calls.Load())
	}
}

func TestAuthoritativeInvalidationIgnoresRuntimeReadRevision(t *testing.T) {
	var calls atomic.Int32
	p := newProvider(options{load: func(context.Context, Connection) ([]*mcp.Tool, error) { calls.Add(1); return sampleTools(), nil }})
	defer p.Close()
	c := sampleConnection()
	c.Revision = 3
	if _, err := p.Get(context.Background(), c, false); err != nil {
		t.Fatal(err)
	}
	p.Invalidate(c.ID, 2)
	if _, refreshed, err := p.GetWithStatus(context.Background(), c, false); err != nil || !refreshed || calls.Load() != 2 {
		t.Fatal("runtime snapshot revision protected rejected metadata", refreshed, err, calls.Load())
	}
	c.Revision = 4
	if err := p.Publish(c, 4, time.Now(), sampleTools()); err != nil {
		t.Fatal(err)
	}
	p.Invalidate(c.ID, 2)
	if _, refreshed, err := p.GetWithStatus(context.Background(), c, false); err != nil || refreshed {
		t.Fatal("old invalidation removed newer committed publication", refreshed, err)
	}
}

func TestFailureDoesNotServeExpiredEntry(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	p := newProvider(options{now: func() time.Time { return now }, ttl: time.Second, load: func(context.Context, Connection) ([]*mcp.Tool, error) {
		if calls.Add(1) == 1 {
			return sampleTools(), nil
		}
		return nil, errors.New("sensitive upstream detail")
	}})
	defer p.Close()
	c := sampleConnection()
	if _, err := p.Get(context.Background(), c, false); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := p.Get(context.Background(), c, false); !errors.Is(err, ErrCatalog) {
		t.Fatalf("expected generic refresh error, got %v", err)
	}
}

func TestCancelledWaiterDoesNotCancelSharedFetch(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	p := newProvider(options{load: func(ctx context.Context, _ Connection) ([]*mcp.Tool, error) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return sampleTools(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	defer p.Close()
	c := sampleConnection()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := p.Get(ctx, c, false); first <- err }()
	<-started
	second := make(chan error, 1)
	go func() { _, err := p.Get(context.Background(), c, false); second <- err }()
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter cancellation lost: %v", err)
	}
	close(release)
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("got %d upstream loads", calls.Load())
	}
}

func TestPublishAndInvalidateProtectAgainstLateFetch(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var startOnce sync.Once
	var calls atomic.Int32
	p := newProvider(options{load: func(ctx context.Context, _ Connection) ([]*mcp.Tool, error) {
		if calls.Add(1) == 1 {
			startOnce.Do(func() { close(started) })
			<-release
			return sampleTools(), nil
		}
		return []*mcp.Tool{{Name: "fresh", InputSchema: map[string]any{"type": "object"}}}, nil
	}})
	defer p.Close()
	c := sampleConnection()
	done := make(chan error, 1)
	go func() { _, err := p.Get(context.Background(), c, false); done <- err }()
	<-started
	admin := []*mcp.Tool{{Name: "admin", InputSchema: map[string]any{"type": "object"}}}
	checkedAt := time.Now()
	if err := p.Publish(c, 2, checkedAt, admin); err != nil {
		t.Fatal(err)
	}
	// A new lookup must use the post-CAS catalog rather than join the old flight.
	c.Revision = 2
	got, err := p.Get(context.Background(), c, false)
	if err != nil || got[0].Name != "admin" {
		t.Fatalf("new request joined obsolete fetch: %v %+v", err, got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, err = p.Get(context.Background(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "admin" {
		t.Fatalf("late fetch replaced admin catalog: %+v", got)
	}
	p.Invalidate(c.ID, 3)
	if _, err = p.Get(context.Background(), c, false); err != nil {
		t.Fatal(err)
	}
	// Revision 2 actions are stale and cannot evict the refreshed revision 3 entry.
	p.Invalidate(c.ID, 2)
	c.Revision = 3
	got, err = p.Get(context.Background(), c, false)
	if err != nil || got[0].Name != "fresh" {
		t.Fatalf("stale invalidation evicted current data: %v %+v", err, got)
	}
}

func TestRevisionOrderingAndPublishTimestamp(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	p := newProvider(options{now: func() time.Time { return now }, load: func(context.Context, Connection) ([]*mcp.Tool, error) { calls.Add(1); return sampleTools(), nil }})
	defer p.Close()
	c := sampleConnection()
	at := now.Add(-time.Minute)
	if err := p.Publish(c, 4, at, sampleTools()); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(c, 3, now, sampleTools()); err == nil {
		t.Fatal("older publish accepted")
	}
	// A newer successful check resets freshness to its supplied completion time.
	if err := p.Publish(c, 5, now, sampleTools()); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(c, 6, now.Add(-time.Second), sampleTools()); err == nil {
		t.Fatal("late older check timestamp accepted")
	}
	c.Revision = 5
	if _, refreshed, err := p.GetWithStatus(context.Background(), c, false); err != nil || refreshed || calls.Load() != 0 {
		t.Fatalf("fresh admin catalog was not reused: refreshed=%v calls=%d err=%v", refreshed, calls.Load(), err)
	}
	// A higher registry revision with identical connection inputs can consume fresh metadata.
	c.Revision = 6
	if _, err := p.Get(context.Background(), c, false); err != nil {
		t.Fatal(err)
	}
}

func TestAdminEventsAreNotOrderedByRuntimeReadsOrFetchCompletion(t *testing.T) {
	now := time.Now()
	p := newProvider(options{now: func() time.Time { return now }, load: func(context.Context, Connection) ([]*mcp.Tool, error) { return sampleTools(), nil }})
	defer p.Close()
	a := sampleConnection()
	b := sampleConnection()
	b.ID = "server-b"
	b.Revision = 3
	if _, err := p.Get(context.Background(), b, false); err != nil {
		t.Fatal(err)
	}

	// A same-server read at a later global registry revision is not an admin event.
	a.Revision = 3
	if _, err := p.Get(context.Background(), a, false); err != nil {
		t.Fatal(err)
	}
	a.Revision = 2
	admin := []*mcp.Tool{{Name: "new_tool", InputSchema: map[string]any{"type": "object"}}}
	if err := p.Publish(a, 2, now, admin); err != nil {
		t.Fatalf("valid delayed publish rejected: %v", err)
	}
	a.Revision = 3
	got, refreshed, err := p.GetWithStatus(context.Background(), a, false)
	if err != nil || refreshed || got[0].Name != "new_tool" {
		t.Fatalf("published check not visible: refreshed=%v tools=%+v err=%v", refreshed, got, err)
	}

	// A runtime fetch may finish later in wall-clock time, but a newer committed
	// admin event remains authoritative and fences that refresh.
	c := sampleConnection()
	c.ID = "server-c"
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	p2 := newProvider(options{now: func() time.Time { return now }, load: func(ctx context.Context, _ Connection) ([]*mcp.Tool, error) {
		once.Do(func() { close(started) })
		<-release
		return sampleTools(), nil
	}})
	defer p2.Close()
	done := make(chan error, 1)
	go func() { _, e := p2.Get(context.Background(), c, false); done <- e }()
	<-started
	adminAt := now.Add(-time.Second)
	newer := []*mcp.Tool{{Name: "admin_new", InputSchema: map[string]any{"type": "object"}}}
	if err := p2.Publish(c, 2, adminAt, newer); err != nil {
		t.Fatalf("newer committed check rejected due to runtime timestamp: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	c.Revision = 2
	got, err = p2.Get(context.Background(), c, false)
	if err != nil || got[0].Name != "admin_new" {
		t.Fatalf("late runtime fetch poisoned check: tools=%+v err=%v", got, err)
	}

	// A runtime catalog that completed at a later wall-clock time still cannot
	// outrank the completion time of a newer committed admin check.
	p3 := newProvider(options{now: func() time.Time { return now }, load: func(context.Context, Connection) ([]*mcp.Tool, error) { return sampleTools(), nil }})
	defer p3.Close()
	d := sampleConnection()
	d.ID = "server-d"
	if _, err := p3.Get(context.Background(), d, false); err != nil {
		t.Fatal(err)
	}
	d.Revision = 2
	if err := p3.Publish(d, 2, now.Add(-time.Second), newer); err != nil {
		t.Fatalf("admin check was rejected by later runtime timestamp: %v", err)
	}
	got, err = p3.Get(context.Background(), d, false)
	if err != nil || got[0].Name != "admin_new" {
		t.Fatalf("admin check did not replace runtime catalog: tools=%+v err=%v", got, err)
	}
}

func TestRetiredRevisionFencesStaleReadsAndPublishes(t *testing.T) {
	var calls atomic.Int32
	p := newProvider(options{load: func(context.Context, Connection) ([]*mcp.Tool, error) {
		switch calls.Add(1) {
		case 1:
			return []*mcp.Tool{{Name: "stale_read", InputSchema: map[string]any{"type": "object"}}}, nil
		default:
			return []*mcp.Tool{{Name: "fresh_runtime", InputSchema: map[string]any{"type": "object"}}}, nil
		}
	}})
	defer p.Close()
	c := sampleConnection()
	p.Invalidate(c.ID, 3)
	c.Revision = 2
	got, _, err := p.GetWithStatus(context.Background(), c, false)
	if err != nil || got[0].Name != "stale_read" {
		t.Fatalf("stale admitted read did not finish: tools=%+v err=%v", got, err)
	}
	c.Revision = 4
	got, refreshed, err := p.GetWithStatus(context.Background(), c, false)
	if err != nil || !refreshed || got[0].Name != "fresh_runtime" {
		t.Fatalf("stale read poisoned cache: refreshed=%v tools=%+v err=%v", refreshed, got, err)
	}
	old := []*mcp.Tool{{Name: "late_admin", InputSchema: map[string]any{"type": "object"}}}
	if err := p.Publish(c, 2, time.Now(), old); err == nil {
		t.Fatal("retired lower-revision publish accepted")
	}
	got, refreshed, err = p.GetWithStatus(context.Background(), c, false)
	if err != nil || refreshed || got[0].Name != "fresh_runtime" {
		t.Fatalf("old publish replaced repopulated cache: refreshed=%v tools=%+v err=%v", refreshed, got, err)
	}
}

func TestFlightCapacityRejectionLeavesNoPerIDState(t *testing.T) {
	p := newProvider(options{})
	defer p.Close()
	p.mu.Lock()
	for i := 0; i < maxFlights; i++ {
		id := fmt.Sprintf("occupied-%d", i)
		p.flights[fmt.Sprintf("flight-%d", i)] = &flight{id: id, done: make(chan struct{})}
	}
	p.mu.Unlock()
	c := sampleConnection()
	c.ID = "rejected-new"
	if _, err := p.Get(context.Background(), c, false); !errors.Is(err, ErrCatalog) {
		t.Fatalf("expected capacity rejection, got %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.generation[c.ID]; ok {
		t.Fatal("rejected id retained generation state")
	}
	if _, ok := p.target[c.ID]; ok {
		t.Fatal("rejected id retained target state")
	}
	if _, ok := p.targetSet[c.ID]; ok {
		t.Fatal("rejected id retained target flag")
	}
	if _, ok := p.authorityRevision[c.ID]; ok {
		t.Fatal("rejected id retained authority watermark")
	}
}

func TestFlightTrackingUsesExactServerID(t *testing.T) {
	p := newProvider(options{})
	defer p.Close()
	p.mu.Lock()
	p.flights["flight-a-colon"] = &flight{id: "a:b", done: make(chan struct{})}
	p.generation["a"] = 1
	p.authorityRevision["a"] = 1
	p.mu.Unlock()
	p.Invalidate("a", 2)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.generation["a"]; ok {
		t.Fatal("server a:b was mistaken for live server a")
	}
}

func TestQueuedRefreshDeadlineIncludesSemaphoreWait(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	p := newProvider(options{maxRefreshes: 1, refreshTimeout: 40 * time.Millisecond, load: func(ctx context.Context, _ Connection) ([]*mcp.Tool, error) {
		calls.Add(1)
		close(started)
		<-release
		return sampleTools(), nil
	}})
	defer p.Close()
	first := sampleConnection()
	done := make(chan error, 1)
	go func() { _, err := p.Get(context.Background(), first, false); done <- err }()
	<-started
	second := sampleConnection()
	second.ID = "second"
	start := time.Now()
	_, err := p.Get(context.Background(), second, false)
	if !errors.Is(err, ErrCatalog) || time.Since(start) > time.Second {
		t.Fatalf("queued fetch escaped its deadline: elapsed=%s err=%v", time.Since(start), err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expired queued fetch reached loader; calls=%d", calls.Load())
	}
	close(release)
	<-done
}

func TestLimitsAndFingerprint(t *testing.T) {
	p := newProvider(options{maxTools: 1, maxCatalogBytes: 2048, load: func(context.Context, Connection) ([]*mcp.Tool, error) {
		return []*mcp.Tool{{Name: "a"}, {Name: "b"}}, nil
	}})
	defer p.Close()
	if _, err := p.Get(context.Background(), sampleConnection(), false); !errors.Is(err, ErrCatalog) {
		t.Fatalf("oversized catalog accepted: %v", err)
	}
	for _, bad := range [][]*mcp.Tool{{{Name: "bad name"}}, {{Name: "same"}, {Name: "same"}}, {{Name: "valid", Description: string(make([]byte, 16<<10+1))}}} {
		if _, _, err := validateClone(bad, 10, 1<<20); !errors.Is(err, ErrCatalog) {
			t.Fatalf("malformed tool catalog accepted: %v", err)
		}
	}
	c := sampleConnection()
	a := Fingerprint(c)
	c.Token = "rotated-token"
	if Fingerprint(c) == a {
		t.Fatal("credential rotation did not change fingerprint")
	}
	c = sampleConnection()
	c.Allowlist = []string{"https://b.example/mcp", "https://a.example/mcp"}
	a = Fingerprint(c)
	c.Allowlist = []string{"https://a.example/mcp", "https://b.example/mcp"}
	if Fingerprint(c) != a {
		t.Fatal("allowlist ordering changed fingerprint")
	}
}

func TestLRUEviction(t *testing.T) {
	var calls atomic.Int32
	p := newProvider(options{maxEntries: 2, load: func(context.Context, Connection) ([]*mcp.Tool, error) {
		calls.Add(1)
		return sampleTools(), nil
	}})
	defer p.Close()
	for _, id := range []string{"one", "two", "three"} {
		c := sampleConnection()
		c.ID = id
		if err := p.Publish(c, 1, time.Now(), sampleTools()); err != nil {
			t.Fatal(err)
		}
	}
	// The first record is least recently used and must have been evicted.
	c := sampleConnection()
	if _, err := p.Get(context.Background(), c, false); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected an LRU miss to reload, got %d upstream loads", calls.Load())
	}
}
