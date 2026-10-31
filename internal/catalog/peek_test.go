package catalog

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"testing"
	"time"
)

func TestPeekDoesNotRefreshOrExtendTTL(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	calls := 0
	p := newProvider(options{now: func() time.Time { return now }, ttl: time.Minute, load: func(context.Context, Connection) ([]*mcp.Tool, error) { calls++; return sampleTools(), nil }})
	defer p.Close()
	c := sampleConnection()
	if _, ok := p.Peek(c); ok || calls != 0 {
		t.Fatal("empty peek loaded catalog")
	}
	if _, err := p.Get(context.Background(), c, false); err != nil {
		t.Fatal(err)
	}
	v, ok := p.Peek(c)
	if !ok || !v.Fresh || calls != 1 {
		t.Fatal("fresh peek")
	}
	v.Tools[0].Description = "changed"
	again, _ := p.Peek(c)
	if again.Tools[0].Description == "changed" {
		t.Fatal("mutable peek")
	}
	now = now.Add(time.Minute)
	v, ok = p.Peek(c)
	if !ok || v.Fresh || calls != 1 {
		t.Fatal("peek extended TTL or refreshed")
	}
	c.Server.URL = "http://127.0.0.1:8082/mcp"
	if _, ok = p.Peek(c); ok {
		t.Fatal("old endpoint metadata leaked")
	}
}
