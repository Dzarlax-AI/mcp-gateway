# MCP Gateway contributor instructions

## Commands
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `go build -o /tmp/mcp-gateway ./cmd/mcp-gateway`
- `go build -o /tmp/mcp-gateway-registry ./cmd/registry`
- `python3 -m unittest discover -s scripts -p 'test_*.py'`
- `node scripts/test_connection_actions.cjs`

## Architecture
Four fixed MCP tools on `/mcp`. Registry/auth in `internal/config`, authorization in `internal/policy`, native HTTP upstream transport in `internal/upstream`, MCP handlers in `internal/gateway`, SQLite/PostgreSQL snapshots and encrypted credentials in `internal/store`, optional web admin in `internal/admin`.

## Rules
Preserve unrelated changes. Never log or commit credentials. Use synthetic data and disposable databases in tests. Runtime startup must not migrate storage. New servers/tools default to disabled. Preserve MCP result types and do not retry invocations automatically. Read docs/security-model.md before changing auth, proxy trust or credential storage. No deployment, publication or Git mutation without corresponding authorization.
