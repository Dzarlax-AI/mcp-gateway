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

`GATEWAY_TOOL_SEARCH_ENABLED=true` adds `search_tools` with matching schemas and enables the shared bounded catalog in `internal/catalog`. Admin checks publish only after successful registry CAS; current authorization is checked on every operation. TTL is 60 seconds and toggles never extend it. New enabled upstream tools must become visible in an existing MCP client session. Upstream notifications and session pooling are deferred. Use a separate empty database via `TEST_CATALOG_POSTGRES_DSN` for the PostgreSQL session acceptance test.

## Rules
Preserve unrelated changes. Never log or commit credentials. Use synthetic data and disposable databases in tests. Runtime startup must not migrate storage. New servers/tools default to disabled. Preserve MCP result types and do not retry invocations automatically. Read docs/security-model.md before changing auth, proxy trust or credential storage. No deployment, publication or Git mutation without corresponding authorization.
