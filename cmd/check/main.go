// Check verifies the restricted real-server scenario through a configured gateway.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/upstream"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	token := os.Getenv("GATEWAY_CODEX_TOKEN")
	if len(token) < 16 {
		return errors.New("missing gateway token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	endpoint := os.Getenv("GATEWAY_CHECK_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:18080/mcp"
	}
	if !config.ValidURL(endpoint) && !config.ValidHTTPS(endpoint) {
		return errors.New("check endpoint must be loopback HTTP or HTTPS on port 443")
	}
	session, cleanup, e := connectGateway(ctx, endpoint)
	if e != nil {
		return errors.New("gateway connection failed")
	}
	defer cleanup()
	tools, e := session.ListTools(ctx, nil)
	if e != nil || len(tools.Tools) != 4 {
		return errors.New("expected four gateway tools")
	}
	fmt.Println("PASS gateway tools/list: four fixed tools")
	invoke := func(name string, args map[string]any, wantError bool) (*mcp.CallToolResult, error) {
		r, e := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if e != nil {
			return nil, fmt.Errorf("%s transport failed", name)
		}
		if r.IsError != wantError {
			if r.IsError && len(r.Content) > 0 {
				if text, ok := r.Content[0].(*mcp.TextContent); ok {
					return nil, fmt.Errorf("%s: %s", name, text.Text)
				}
			}
			return nil, fmt.Errorf("%s unexpected error state", name)
		}
		return r, nil
	}
	r, e := invoke("discover_server", map[string]any{"query": "openai docs"}, false)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), "openai-docs") {
		return errors.New("real server not discovered")
	}
	fmt.Println("PASS discover_server: openai-docs")
	r, e = invoke("discover_tools", map[string]any{"server_id": "openai-docs"}, false)
	if e != nil {
		return e
	}
	b, _ = json.Marshal(r.StructuredContent)
	var listing struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if json.Unmarshal(b, &listing) != nil || len(listing.Tools) != 2 {
		return errors.New("expected exactly two authorized real tools")
	}
	fmt.Println("PASS discover_tools: two authorized read-only tools")
	for _, name := range []string{"search_openai_docs", "fetch_openai_doc"} {
		r, e = invoke("get_tool_schema", map[string]any{"server_id": "openai-docs", "tool_name": name}, false)
		if e != nil {
			return e
		}
		b, _ = json.Marshal(r.StructuredContent)
		if !strings.Contains(string(b), "draft-07") {
			return errors.New("expected real Draft-07 schema")
		}
		fmt.Println("PASS get_tool_schema:", name)
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{{"search_openai_docs", map[string]any{"query": "Codex MCP configuration", "limit": 3}}, {"fetch_openai_doc", map[string]any{"url": "https://learn.chatgpt.com/docs/extend/mcp"}}} {
		r, e = invoke("invoke_tool", map[string]any{"server_id": "openai-docs", "tool_name": tc.name, "arguments": tc.args}, false)
		if e != nil {
			return e
		}
		size := 0
		for _, content := range r.Content {
			if text, ok := content.(*mcp.TextContent); ok {
				size += len(text.Text)
			}
		}
		if size < 100 {
			return errors.New("empty real upstream result")
		}
		fmt.Printf("PASS invoke_tool %s: %d bytes of real documentation\n", tc.name, size)
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{{"list_api_endpoints", map[string]any{}}, {"search_openai_docs", map[string]any{"query": "unapproved query", "limit": 3}}} {
		_, e = invoke("invoke_tool", map[string]any{"server_id": "openai-docs", "tool_name": tc.name, "arguments": tc.args}, true)
		if e != nil {
			return e
		}
		fmt.Println("PASS denied:", tc.name)
	}
	return nil
}

// Pin credential-bearing requests to the validated gateway endpoint, including HTTPS.
func connectGateway(ctx context.Context, endpoint string) (*mcp.ClientSession, func(), error) {
	return upstream.Connect(ctx, config.Server{URL: endpoint, TokenEnv: "GATEWAY_CODEX_TOKEN"})
}
