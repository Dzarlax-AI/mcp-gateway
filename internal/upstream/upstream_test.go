package upstream

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/config"
)

func TestSchemaReferencesAreOffline(t *testing.T) {
	for _, ref := range []string{"file:///etc/passwd", "http://127.0.0.1:9999/schema"} {
		if Validate(map[string]any{"$ref": ref}, map[string]any{}) == nil {
			t.Fatal("external ref accepted")
		}
	}
	schema := map[string]any{"type": "object", "$defs": map[string]any{"value": map[string]any{"type": "integer"}}, "properties": map[string]any{"n": map[string]any{"$ref": "#/$defs/value"}}}
	if e := Validate(schema, map[string]any{"n": json.Number("3")}); e != nil {
		t.Fatal(e)
	}
}
func TestNoRedirectOrProxy(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	t.Setenv("HTTP_PROXY", target.URL)
	h := HTTPClient("synthetic-token-long-enough", time.Second)
	custom := h.Transport.(authTransport)
	custom.authHeader = "x-api-key"
	h.Transport = custom
	defer h.CloseIdleConnections()
	if r, e := h.Get(redirect.URL); e == nil {
		r.Body.Close()
		t.Fatal("redirect followed")
	}
	if hits.Load() != 0 {
		t.Fatal("redirect or proxy contacted")
	}
}

type headerCapture struct{ header http.Header }

func (t *headerCapture) RoundTrip(r *http.Request) (*http.Response, error) {
	t.header = r.Header.Clone()
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func TestLiteralCredentialAndPinning(t *testing.T) {
	for _, header := range []string{"", "x-api-key", "X-Access-Key"} {
		t.Run("header="+header, func(t *testing.T) {
			base := &headerCapture{}
			tr := authTransport{base: base, endpoint: "https://example.com/mcp", token: "synthetic-key-long-enough", authHeader: header}
			req, _ := http.NewRequest("POST", tr.endpoint, nil)
			req.Header.Set("Authorization", "inherited-client-secret")
			if header != "" {
				req.Header.Set(header, "stale-key")
			}
			res, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if header == "" {
				if base.header.Get("Authorization") != "Bearer "+tr.token {
					t.Fatal("legacy bearer changed")
				}
			} else if base.header.Get(header) != tr.token || base.header.Get("Authorization") != "" {
				t.Fatal("literal custom header failed")
			}
			if req.Header.Get("Authorization") != "inherited-client-secret" {
				t.Fatal("caller request mutated")
			}
			base.header = nil
			req, _ = http.NewRequest("POST", "https://example.com/other", nil)
			if _, err = tr.RoundTrip(req); err == nil || base.header != nil {
				t.Fatal("credential escaped pinned endpoint")
			}
		})
	}
	for _, tc := range []struct{ name, value string }{{"Host", "key"}, {"x-api-key", "key\r\nHost: evil"}} {
		base := &headerCapture{}
		tr := authTransport{base: base, endpoint: "https://example.com/mcp", authHeader: tc.name, token: tc.value}
		req, _ := http.NewRequest("POST", tr.endpoint, nil)
		if _, err := tr.RoundTrip(req); err == nil || base.header != nil {
			t.Fatal("invalid header reached transport")
		}
	}
}
func TestToolsPagination(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		t.Run(map[bool]string{false: "pages", true: "cursor-cycle"}[cycle], func(t *testing.T) {
			server := mcp.NewServer(&mcp.Implementation{Name: "paged", Version: "0.1.0"}, nil)
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
			var pages atomic.Int32
			h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					var msg struct {
						ID     any    `json:"id"`
						Method string `json:"method"`
						Params struct {
							Cursor string `json:"cursor"`
						} `json:"params"`
					}
					b, _ := io.ReadAll(r.Body)
					raw := string(b)
					r.Body = http.NoBody
					json.Unmarshal([]byte(raw), &msg)
					r.Body = io.NopCloser(strings.NewReader(raw))
					if msg.Method == "tools/list" {
						pages.Add(1)
						name := "one"
						cursor := "next"
						if msg.Params.Cursor != "" {
							name = "two"
							if !cycle {
								cursor = ""
							}
						}
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"tools": []any{map[string]any{"name": name, "inputSchema": map[string]any{"type": "object"}}}, "nextCursor": cursor}})
						return
					}
				}
				handler.ServeHTTP(w, r)
			}))
			defer h.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			s, e := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0.1.0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: h.URL, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			tools, e := Tools(ctx, s)
			if cycle {
				if e == nil {
					t.Fatal("cycle not rejected")
				}
			} else if e != nil || len(tools) != 2 || pages.Load() != 2 {
				t.Fatalf("tools=%v pages=%d err=%v", tools, pages.Load(), e)
			}
		})
	}
}

type captureTransport struct{ called bool }

func (t *captureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.called = true
	return nil, ErrUpstream
}
func TestPinnedEndpoint(t *testing.T) {
	base := &captureTransport{}
	transport := authTransport{base: base, endpoint: "https://developers.openai.com/mcp"}
	req, _ := http.NewRequest("POST", "https://example.com/mcp", nil)
	if _, e := transport.RoundTrip(req); e == nil || base.called {
		t.Fatal("unconfigured endpoint reached transport")
	}
	req, _ = http.NewRequest("POST", "https://developers.openai.com/mcp", nil)
	transport.RoundTrip(req)
	if !base.called {
		t.Fatal("configured endpoint blocked")
	}
}

func TestTLSCertificateValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted certificate accepted") }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if s, close, e := Connect(ctx, config.Server{URL: server.URL}); e == nil {
		close()
		s.Close()
		t.Fatal("self-signed certificate accepted")
	}
}
