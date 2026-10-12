package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestClientHeadersRejectedAtBothBoundaries(t *testing.T) {
	f := newFixture(t)
	g := &Gateway{Path: f.path}
	args, _ := json.Marshal(invocation("denied"))
	before := f.requests.Load()
	for _, headers := range []http.Header{
		nil,
		{"Authorization": {"Bearer wrong"}},
		{"X-API-Key": {"wrong"}},
		{"Authorization": {""}},
		{"X-API-Key": {""}},
		{"Authorization": {"Bearer " + clientToken}, "X-API-Key": {clientToken}},
		{"Authorization": {"Bearer wrong"}, "X-API-Key": {clientToken}},
		{"Authorization": {"Bearer " + clientToken, "Bearer " + clientToken}},
		{"X-API-Key": {clientToken, clientToken}},
	} {
		r, _ := http.NewRequest("POST", f.server.URL+"/mcp", strings.NewReader("{}"))
		r.Header = headers.Clone()
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatal("HTTP credential accepted", response.StatusCode)
		}
		result, err := g.call(context.Background(), &mcp.CallToolRequest{Extra: &mcp.RequestExtra{Header: headers}, Params: &mcp.CallToolParamsRaw{Name: "invoke_tool", Arguments: args}})
		if err != nil || !result.IsError {
			t.Fatal("tool credential accepted", err)
		}
	}
	if f.requests.Load() != before {
		t.Fatal("rejected credentials contacted upstream")
	}
}
