package readpolicy

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestOperationClassification(t *testing.T) {
	tool := &mcp.Tool{Name: "find", InputSchema: map[string]any{"type": "object"}, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}
	hash, err := OperationFingerprint(tool)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		kind, hash string
		tool       *mcp.Tool
		want       OperationDecision
	}{
		{"", "", tool, OperationDecision{"read", "auto", "read_only_annotation"}},
		{"", "", nil, OperationDecision{"unknown", "auto", "catalog_unavailable"}},
		{"", "", &mcp.Tool{Name: "find"}, OperationDecision{"unknown", "auto", "operation_unknown"}},
		{"", "", &mcp.Tool{Name: "find", Annotations: &mcp.ToolAnnotations{}}, OperationDecision{"unknown", "auto", "operation_unknown"}},
		{"write", "", nil, OperationDecision{"write", "manual", "manual_write"}},
		{"write", "", tool, OperationDecision{"write", "manual", "manual_write"}},
		{"read", hash, tool, OperationDecision{"read", "manual", "manual_read"}},
		{"read", hash, nil, OperationDecision{"unknown", "manual", "manual_read_stale"}},
		{"read", "invalid", tool, OperationDecision{"unknown", "manual", "manual_read_stale"}},
	}
	for _, tc := range cases {
		if got := ClassifyOperation(tc.kind, tc.hash, tc.tool); got != tc.want {
			t.Errorf("got %+v want %+v", got, tc.want)
		}
	}
	tool.Description = "changed"
	tool.Title = "new title"
	tool.Annotations.Title = "other"
	if got := ClassifyOperation("read", hash, tool); got.Kind != "read" {
		t.Fatal(got)
	}
	tool.InputSchema = map[string]any{"type": "string"}
	if got := ClassifyOperation("read", hash, tool); got.Reason != "manual_read_stale" {
		t.Fatal(got)
	}
	tool.InputSchema = nil
	if _, err = OperationFingerprint(tool); err != nil {
		t.Fatal(err)
	}
	tool.InputSchema = make(chan int)
	if _, err = OperationFingerprint(tool); err == nil {
		t.Fatal("expected invalid schema error")
	}
}

// The SDK's bool loses JSON member presence, including when other annotations exist.
func TestSDKReadOnlyHintPresenceIsLost(t *testing.T) {
	var absent, explicitFalse mcp.Tool
	for raw, dst := range map[string]*mcp.Tool{
		`{"name":"find","inputSchema":{},"annotations":{"title":"a"}}`:                      &absent,
		`{"name":"find","inputSchema":{},"annotations":{"title":"a","readOnlyHint":false}}`: &explicitFalse,
	} {
		if err := json.Unmarshal([]byte(raw), dst); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []*mcp.Tool{&absent, &explicitFalse} {
		if got := ClassifyOperation("", "", tool); got != (OperationDecision{"unknown", "auto", "operation_unknown"}) {
			t.Fatal(got)
		}
	}
}

func TestManualReadConnectionBinding(t *testing.T) {
	tool := &mcp.Tool{Name: "lookup", InputSchema: map[string]any{"type": "object"}}
	hash, err := OperationFingerprint(tool, "connection-one")
	if err != nil {
		t.Fatal(err)
	}
	if got := ClassifyOperation("read", hash, tool, "connection-one"); got.Reason != "manual_read" {
		t.Fatal(got)
	}
	tool.Description = "New description"
	if got := ClassifyOperation("read", hash, tool, "connection-one"); got.Reason != "manual_read" {
		t.Fatal(got)
	}
	if got := ClassifyOperation("read", hash, tool, "connection-two"); got.Reason != "manual_read_stale" {
		t.Fatal(got)
	}
	if got := ClassifyOperation("read", hash, tool); got.Reason != "manual_read_stale" {
		t.Fatal(got)
	}
	if _, err := OperationFingerprint(tool, "one", "two"); err == nil {
		t.Fatal("multiple bindings accepted")
	}
}
