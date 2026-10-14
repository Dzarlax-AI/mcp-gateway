// Package readpolicy classifies only reviewed, exact upstream read contracts.
package readpolicy

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed contracts/*.json
var contracts embed.FS
var profiles = loadProfiles()

func loadProfiles() map[string]map[string][32]byte {
	out := map[string]map[string][32]byte{}
	for _, name := range []string{"calendar-mcp-v1", "home-assistant-v1"} {
		b, err := contracts.ReadFile("contracts/" + name + ".json")
		if err != nil {
			panic(err)
		}
		var tools []*mcp.Tool
		if err = json.Unmarshal(b, &tools); err != nil {
			panic(err)
		}
		out[name] = map[string][32]byte{}
		for _, t := range tools {
			h, err := Fingerprint(t)
			if err != nil {
				panic(err)
			}
			if _, exists := out[name][t.Name]; exists {
				panic("duplicate reviewed contract")
			}
			out[name][t.Name] = h
		}
	}
	return out
}
func Known(profile string) bool { _, ok := profiles[profile]; return ok }

// Fingerprint normalizes JSON object key order without normalizing away contract changes.
func Fingerprint(t *mcp.Tool) ([32]byte, error) {
	if t == nil || t.InputSchema == nil {
		return [32]byte{}, fmt.Errorf("missing contract")
	}
	b, err := json.Marshal(t)
	if err != nil {
		return [32]byte{}, err
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err = d.Decode(&v); err != nil {
		return [32]byte{}, err
	}
	b, err = json.Marshal(v)
	return sha256.Sum256(b), err
}

// ReviewedTools returns copies for synthetic fixtures and review, never mutable policy state.
func ReviewedTools(profile string) []*mcp.Tool {
	if !Known(profile) {
		return nil
	}
	b, err := contracts.ReadFile("contracts/" + profile + ".json")
	if err != nil {
		return nil
	}
	var ts []*mcp.Tool
	_ = json.Unmarshal(b, &ts)
	return ts
}
func Classify(profile string, t *mcp.Tool) (bool, string) {
	rules, ok := profiles[profile]
	if !ok {
		return false, "profile_unknown"
	}
	if t == nil {
		return false, "catalog_unavailable"
	}
	expected, ok := rules[t.Name]
	if !ok {
		switch t.Name {
		case "intent__HassTurnOn", "intent__HassTurnOff", "intent_script__CleanRoom", "light__HassLightSet", "climate__HassClimateSetTemperature", "fan__HassFanSetSpeed", "humidifier__HassHumidifierMode", "humidifier__HassHumidifierSetpoint", "vacuum__HassVacuumCleanArea", "vacuum__HassVacuumReturnToBase", "vacuum__HassVacuumStart", "create_event_v2", "update_event_v2", "delete_event_v2", "respond_to_event_v2":
			return false, "write_operation"
		}
		return false, "unreviewed_tool"
	}
	h, err := Fingerprint(t)
	if err != nil || h != expected {
		return false, "contract_changed"
	}
	return true, "reviewed_read"
}

// Arguments rejects undeclared top-level arguments even when an upstream schema
// permits additional properties. Reviewed reads have explicit filter/query keys.
func Arguments(t *mcp.Tool, args map[string]any) bool {
	if t == nil {
		return false
	}
	b, e := json.Marshal(t.InputSchema)
	if e != nil {
		return false
	}
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(b, &s) != nil {
		return false
	}
	for name := range args {
		if _, ok := s.Properties[name]; !ok {
			return false
		}
	}
	return true
}

// Label is presentation only; clients and runtime use finite reason codes.
func Label(reason string) string {
	switch reason {
	case "reviewed_read":
		return "Verified read: allowed in batch"
	case "server_disabled":
		return "Connector disabled"
	case "connector_batch_disabled":
		return "Batch reads disabled"
	case "tool_disabled":
		return "Tool disabled"
	case "endpoint_changed":
		return "Connection changed: check and enable batch again"
	case "catalog_unavailable":
		return "Check the connection to verify the catalog"
	case "contract_changed":
		return "Tool contract changed: not verified for batch"
	case "operator_file":
		return "Batch managed by the operator policy file"
	case "write_operation":
		return "Control operation: ordinary invocation only"
	default:
		return "No reviewed batch read rule"
	}
}
