// Package upstream connects only to endpoints from validated registry snapshots.
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	js "github.com/santhosh-tekuri/jsonschema/v6"

	"mcp-gateway/internal/config"
)

var ErrUpstream = errors.New("upstream unavailable or invalid")

type authTransport struct {
	base       http.RoundTripper
	token      string
	authHeader string
	endpoint   string
}

func (t authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if (t.endpoint == "" && !config.ValidURL(r.URL.String())) || (t.endpoint != "" && r.URL.String() != t.endpoint) {
		return nil, ErrUpstream
	}
	r = r.Clone(r.Context())
	r.Header = r.Header.Clone()
	if t.authHeader != "" && !config.ValidAuthHeader(t.authHeader) {
		return nil, ErrUpstream
	}
	if t.token != "" && !config.ValidCredential(t.authHeader, t.token) {
		return nil, ErrUpstream
	}
	r.Header.Del("Authorization")
	if t.authHeader != "" {
		r.Header.Del(t.authHeader)
	}
	if t.token != "" {
		if t.authHeader == "" {
			r.Header.Set("Authorization", "Bearer "+t.token)
		} else {
			r.Header.Set(t.authHeader, t.token)
		}
	}
	res, e := t.base.RoundTrip(r)
	if e != nil {
		return nil, e
	}
	if res.ContentLength > 10<<20 {
		res.Body.Close()
		return nil, ErrUpstream
	}
	res.Body = &boundedBody{ReadCloser: res.Body, left: 10 << 20}
	return res, nil
}
func (t authTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
func HTTPClient(token string, timeout time.Duration) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &http.Client{Transport: authTransport{base: t, token: token}, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUpstream }}
}

type deadlineTransport struct {
	base http.RoundTripper
	ctx  context.Context
}
type deadlineBody struct {
	io.ReadCloser
	done func()
}

func (b *deadlineBody) Close() error { defer b.done(); return b.ReadCloser.Close() }
func (t deadlineTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
func (t deadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	done := func() { stop(); cancel() }
	if t.ctx.Err() != nil {
		done()
		return nil, t.ctx.Err()
	}
	res, e := t.base.RoundTrip(r.Clone(ctx))
	if e != nil {
		done()
		return nil, e
	}
	res.Body = &deadlineBody{res.Body, done}
	return res, nil
}
func Connect(ctx context.Context, s config.Server) (*mcp.ClientSession, func(), error) {
	return connect(ctx, s, os.Getenv(s.TokenEnv), false)
}

// ConnectWithToken uses a snapshot credential and rejects non-public HTTPS destinations.
func ConnectWithToken(ctx context.Context, s config.Server, token string) (*mcp.ClientSession, func(), error) {
	return connect(ctx, s, token, true)
}

// ConnectReadOnceWithToken disables SDK-driven input continuation as well as
// transport retries. Batch items must perform at most one upstream invocation.
func ConnectReadOnceWithToken(ctx context.Context, s config.Server, token string) (*mcp.ClientSession, func(), error) {
	return connectOptions(ctx, s, token, true, true)
}
func connect(ctx context.Context, s config.Server, token string, restricted bool) (*mcp.ClientSession, func(), error) {
	return connectOptions(ctx, s, token, restricted, false)
}
func connectOptions(ctx context.Context, s config.Server, token string, restricted, readOnce bool) (*mcp.ClientSession, func(), error) {
	if restricted && !config.ValidURL(s.URL) && !config.ValidHTTPS(s.URL) {
		return nil, func() {}, ErrUpstream
	}
	if s.AuthHeader != "" && (!config.ValidAuthHeader(s.AuthHeader) || !config.ValidCredential(s.AuthHeader, token)) {
		return nil, func() {}, ErrUpstream
	}
	h := HTTPClient(token, 30*time.Second)
	auth := h.Transport.(authTransport)
	auth.authHeader = s.AuthHeader
	h.Transport = auth
	if restricted && config.ValidHTTPS(s.URL) {
		t := h.Transport.(authTransport)
		base := t.base.(*http.Transport)
		base.DialContext = publicDial
		h.Transport = t
	}
	base := h.Transport
	pinned := base.(authTransport)
	pinned.endpoint = s.URL
	base = pinned
	h.Transport = deadlineTransport{base, ctx}
	options := &mcp.ClientOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if readOnce {
		options.MultiRoundTrip = &mcp.MultiRoundTripOptions{Disabled: true}
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "mcp-gateway-upstream", Version: "0.1.0"}, options)
	session, e := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: s.URL, HTTPClient: h, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	cleanup := h.CloseIdleConnections
	if e != nil {
		cleanup()
		return nil, func() {}, ErrUpstream
	}
	return session, func() { session.Close(); cleanup() }, nil
}
func Tools(ctx context.Context, s *mcp.ClientSession) ([]*mcp.Tool, error) {
	out := []*mcp.Tool{}
	cursor := ""
	seen := map[string]bool{}
	names := map[string]bool{}
	total := 0
	for page := 0; page < 100; page++ {
		r, e := s.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if e != nil {
			return nil, ErrUpstream
		}
		for _, t := range r.Tools {
			if t == nil || names[t.Name] || !config.ValidIdentifier(t.Name) {
				return nil, ErrUpstream
			}
			b, e := json.Marshal(t)
			if e != nil || len(t.Description) > 16<<10 {
				return nil, ErrUpstream
			}
			total += len(b)
			if total > 10<<20 {
				return nil, ErrUpstream
			}
			names[t.Name] = true
			out = append(out, t)
		}
		if len(out) > 10000 {
			return nil, ErrUpstream
		}
		if r.NextCursor == "" {
			return out, nil
		}
		if seen[r.NextCursor] {
			return nil, ErrUpstream
		}
		seen[r.NextCursor] = true
		cursor = r.NextCursor
	}
	return nil, ErrUpstream
}

type noLoader struct{}

func (noLoader) Load(string) (any, error) { return nil, ErrUpstream }
func Validate(schema any, args map[string]any) error {
	// Normalize typed Go slices and numeric literals to JSON data for the compiler.
	b, e := json.Marshal(schema)
	if e != nil {
		return ErrUpstream
	}
	var doc any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&doc) != nil {
		return ErrUpstream
	}
	c := js.NewCompiler()
	c.UseLoader(noLoader{})
	if c.AddResource("urn:gateway:input", doc) != nil {
		return ErrUpstream
	}
	s, e := c.Compile("urn:gateway:input")
	if e != nil {
		return ErrUpstream
	}
	if s.Validate(args) != nil {
		return errors.New("arguments do not match upstream schema")
	}
	return nil
}

// boundedBody fails once an upstream response exceeds its budget.
type boundedBody struct {
	io.ReadCloser
	left int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.left == 0 {
		var one [1]byte
		n, e := b.ReadCloser.Read(one[:])
		if n > 0 {
			return 0, ErrUpstream
		}
		return 0, e
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, e := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, e
}
