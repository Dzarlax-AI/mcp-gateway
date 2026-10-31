package readpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type OperationDecision struct {
	Kind, Source, Reason string
}

// OperationFingerprint binds a manual read to the parts of the advertised contract
// that affect invocation and classification, ignoring presentation metadata.
func OperationFingerprint(t *mcp.Tool, connectionBinding ...string) (string, error) {
	if t == nil || len(connectionBinding) > 1 {
		return "", fmt.Errorf("missing tool")
	}
	var hint *bool
	if t.Annotations != nil && t.Annotations.ReadOnlyHint {
		v := true
		hint = &v
	}
	contract := struct {
		Name       string `json:"name"`
		Input      any    `json:"inputSchema"`
		Output     any    `json:"outputSchema"`
		Hint       *bool  `json:"readOnlyHint"`
		Connection string `json:"connection,omitempty"`
	}{Name: t.Name, Input: t.InputSchema, Output: t.OutputSchema, Hint: hint}
	if len(connectionBinding) == 1 {
		contract.Connection = connectionBinding[0]
	}
	b, err := json.Marshal(contract)
	if err != nil {
		return "", err
	}
	var normalized any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err = d.Decode(&normalized); err != nil {
		return "", err
	}
	b, err = json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func ClassifyOperation(kind, contractHash string, t *mcp.Tool, connectionBinding ...string) OperationDecision {
	switch kind {
	case "write":
		return OperationDecision{"write", "manual", "manual_write"}
	case "read":
		h, err := OperationFingerprint(t, connectionBinding...)
		if err != nil || h != contractHash {
			return OperationDecision{"unknown", "manual", "manual_read_stale"}
		}
		return OperationDecision{"read", "manual", "manual_read"}
	case "":
		if t == nil {
			return OperationDecision{"unknown", "auto", "catalog_unavailable"}
		}
		if t.Annotations != nil && t.Annotations.ReadOnlyHint {
			return OperationDecision{"read", "auto", "read_only_annotation"}
		}
		// The SDK decodes both absent and false readOnlyHint into the same bool.
		return OperationDecision{"unknown", "auto", "operation_unknown"}
	default:
		return OperationDecision{"unknown", "manual", "operation_unknown"}
	}
}
