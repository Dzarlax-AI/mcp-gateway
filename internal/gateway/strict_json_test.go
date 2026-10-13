package gateway

import "testing"

func TestRejectDuplicateJSONKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
	}{
		{"duplicate version", `{"version":2,"version":1}`},
		{"duplicate endpoint", `{"endpoint":"http://127.0.0.1:1","endpoint":"http://127.0.0.1:2"}`},
		{"duplicate server id", `{"server_id":"first","server_id":"second"}`},
		{"duplicate tool name", `{"tool_name":"first","tool_name":"second"}`},
		{"nested arguments", `{"arguments":{"filter":{"x":1,"x":2}}}`},
		{"trailing json", `{} []`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := rejectDuplicateJSONKeys([]byte(tc.json)); err == nil {
				t.Fatal("rejectDuplicateJSONKeys() accepted invalid input")
			}
		})
	}
}

func TestRejectDuplicateJSONKeysAllowsRepeatedArrayValues(t *testing.T) {
	if err := rejectDuplicateJSONKeys([]byte(`{"values":["same","same",{"id":1},{"id":1}]}`)); err != nil {
		t.Fatalf("repeated array values were rejected: %v", err)
	}
}

func TestDecodeReadBatchPolicyRejectsDuplicateFields(t *testing.T) {
	for _, body := range []string{
		`{"version":2,"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp"}]}`,
		`{"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp","endpoint":"http://127.0.0.1:8082/mcp"}]}`,
		`{"version":1,"operations":[{"server_id":"demo","server_id":"other","tool_name":"read_alpha","endpoint":"http://127.0.0.1:8081/mcp"}]}`,
		`{"version":1,"operations":[{"server_id":"demo","tool_name":"read_alpha","tool_name":"read_beta","endpoint":"http://127.0.0.1:8081/mcp"}]}`,
	} {
		if _, err := decodeReadBatchPolicy([]byte(body)); err == nil {
			t.Fatal("decodeReadBatchPolicy() accepted a duplicate field")
		}
	}
}
