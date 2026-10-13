package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"mcp-gateway/internal/config"
)

const readBatchPolicyMaxBytes = 32 << 10
const readBatchPolicyMaxOperations = 256

var readBatchDenied = errors.New("batch operation denied")

// ReadBatchPolicy grants narrowly scoped batch reads from an operator-managed file.
// The file is loaded for every decision so revocations take effect immediately.
type ReadBatchPolicy struct {
	Path string
}

type readBatchPolicyFile struct {
	Version    int                      `json:"version"`
	Operations []readBatchPolicyOpEntry `json:"operations"`
}

type readBatchPolicyOpEntry struct {
	ServerID string `json:"server_id"`
	ToolName string `json:"tool_name"`
	Endpoint string `json:"endpoint"`
}

func (p *ReadBatchPolicy) Validate() error {
	if _, err := p.load(); err != nil {
		return readBatchDenied
	}
	return nil
}

// Allows succeeds only for an exact server, tool, and endpoint tuple.
func (p *ReadBatchPolicy) Allows(serverID, toolName, endpoint string) error {
	policy, err := p.load()
	if err != nil {
		return readBatchDenied
	}
	for _, operation := range policy.Operations {
		if operation.ServerID == serverID && operation.ToolName == toolName && operation.Endpoint == endpoint {
			return nil
		}
	}
	return readBatchDenied
}

func (p *ReadBatchPolicy) load() (*readBatchPolicyFile, error) {
	if p == nil || strings.TrimSpace(p.Path) == "" {
		return nil, readBatchDenied
	}
	f, err := os.OpenFile(p.Path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, readBatchDenied
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, readBatchDenied
	}
	b, err := io.ReadAll(io.LimitReader(f, readBatchPolicyMaxBytes+1))
	if err != nil || len(b) == 0 || len(b) > readBatchPolicyMaxBytes {
		return nil, readBatchDenied
	}
	policy, err := decodeReadBatchPolicy(b)
	if err != nil {
		return nil, readBatchDenied
	}
	return policy, nil
}

func decodeReadBatchPolicy(data []byte) (*readBatchPolicyFile, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, readBatchDenied
	}
	var policy readBatchPolicyFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return nil, readBatchDenied
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, readBatchDenied
	}
	if policy.Version != 1 || len(policy.Operations) == 0 || len(policy.Operations) > readBatchPolicyMaxOperations {
		return nil, readBatchDenied
	}
	seen := make(map[string]struct{}, len(policy.Operations))
	for _, operation := range policy.Operations {
		if operation.ServerID == "" || operation.ServerID != strings.TrimSpace(operation.ServerID) ||
			operation.ToolName == "" || operation.ToolName != strings.TrimSpace(operation.ToolName) ||
			operation.Endpoint == "" || operation.Endpoint != strings.TrimSpace(operation.Endpoint) ||
			(!config.ValidURL(operation.Endpoint) && !config.ValidHTTPS(operation.Endpoint)) {
			return nil, readBatchDenied
		}
		key := operation.ServerID + "\x00" + operation.ToolName
		if _, exists := seen[key]; exists {
			return nil, readBatchDenied
		}
		seen[key] = struct{}{}
	}
	return &policy, nil
}
