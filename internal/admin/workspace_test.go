package admin

import (
	"bytes"
	"strings"
	"testing"
)

func TestWorkspaceTemplateGroupsAndForms(t *testing.T) {
	tool := map[string]any{"Name": "list_items", "Description": "List items", "OperationKind": "read", "OperationLabel": "Read · automatic", "ManualKind": "", "OperationReason": "", "DefinitionHash": "hash", "Schema": "", "Enabled": true}
	server := map[string]any{"ID": "demo", "Server": map[string]any{"Enabled": true, "URL": "https://example.test/mcp"}, "Tools": []any{tool}, "CatalogFresh": true}
	p := map[string]any{"BasePath": "/gateway", "CSRF": "csrf", "Revision": 3, "Selected": server, "Servers": []any{server}}
	var out bytes.Buffer
	if err := workspaceTpl.Execute(&out, p); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{"Read · automatic", `name="tools"`, `/gateway/admin/servers/demo/bulk-enable`, `/gateway/admin/servers/demo/tool-operation`, `name="contract_hash"`, `data-group="unknown"`} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(html, "Type: Auto") {
		t.Fatal("obsolete classification label")
	}
}
