// Demo provides an authenticated synthetic upstream or runs a gateway client.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcp-gateway/internal/config"
	"mcp-gateway/internal/upstream"
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	endpoint := flag.String("endpoint", "http://127.0.0.1:8080/mcp", "gateway endpoint")
	addr := flag.String("listen", "127.0.0.1:8081", "synthetic server listener")
	flag.Parse()
	if e := run(*mode, *endpoint, *addr); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run(mode, endpoint, addr string) error {
	token := os.Getenv("DEMO_UPSTREAM_TOKEN")
	if mode == "client" {
		token = os.Getenv("GATEWAY_DEMO_TOKEN")
	}
	if len(token) < 16 {
		return errors.New("demo token env must contain at least 16 characters")
	}
	if mode == "client" {
		if !config.ValidURL(endpoint) {
			return errors.New("invalid local endpoint")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		h := upstream.HTTPClient(token, 30*time.Second)
		defer h.CloseIdleConnections()
		s, e := mcp.NewClient(&mcp.Implementation{Name: "gateway-demo", Version: "0.1.0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: h, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if e != nil {
			return errors.New("gateway connection failed")
		}
		defer s.Close()
		list, e := s.ListTools(ctx, nil)
		want := 4
		if raw := os.Getenv("GATEWAY_TOOL_SEARCH_ENABLED"); raw != "" {
			enabled, err := strconv.ParseBool(raw)
			if err != nil {
				return errors.New("invalid GATEWAY_TOOL_SEARCH_ENABLED")
			}
			if enabled {
				want = 5
			}
		}
		if raw := os.Getenv("GATEWAY_READ_BATCH_ENABLED"); raw != "" {
			enabled, err := strconv.ParseBool(raw)
			if err != nil {
				return errors.New("invalid GATEWAY_READ_BATCH_ENABLED")
			}
			if enabled {
				if want != 5 {
					return errors.New("read batch requires tool search")
				}
				want = 6
			}
		}
		if e != nil || len(list.Tools) != want {
			return errors.New("unexpected gateway tool count")
		}
		for _, call := range []mcp.CallToolParams{{Name: "discover_server", Arguments: map[string]any{"query": "echo"}}, {Name: "discover_tools", Arguments: map[string]any{"server_id": "demo"}}, {Name: "get_tool_schema", Arguments: map[string]any{"server_id": "demo", "tool_name": "echo"}}, {Name: "invoke_tool", Arguments: map[string]any{"server_id": "demo", "tool_name": "echo", "arguments": map[string]any{"text": "Hello MVP"}}}} {
			r, e := s.CallTool(ctx, &call)
			if e != nil || r.IsError {
				return errors.New("demo call failed: " + call.Name)
			}
			b, e := json.MarshalIndent(r, "", "  ")
			if e != nil {
				return e
			}
			fmt.Printf("%s\n%s\n", call.Name, b)
		}
		return nil
	}
	if mode != "server" {
		return errors.New("unknown mode")
	}
	host, _, e := net.SplitHostPort(addr)
	if e != nil || !config.Loopback(host) {
		return errors.New("demo listener must use loopback IP")
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "synthetic-demo", Version: "0.1.0"}, nil)
	type args struct {
		Text string `json:"text"`
	}
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echo synthetic text"}, func(ctx context.Context, r *mcp.CallToolRequest, a args) (*mcp.CallToolResult, args, error) {
		return nil, a, nil
	})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	mux := http.NewServeMux()
	mux.Handle("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		h.ServeHTTP(w, r)
	}))
	log.Print("synthetic upstream listening on ", addr)
	return (&http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe()
}
