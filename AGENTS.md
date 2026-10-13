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

## Read batches
`GATEWAY_READ_BATCH_ENABLED=true` adds `invoke_read_batch` only with tool search and a valid operator-controlled JSON allowlist (`GATEWAY_READ_BATCH_ALLOWLIST`). Exact server/tool/endpoint tuples only; annotations do not authorize reads. Both normal access and allowlist are rechecked before each dispatch, including after initialization. The feature requires no registry or SQL migration.

Route all operator-allowlisted reads, including a single read, through `invoke_read_batch`. Use `invoke_tool` for other operations. Batches allow 1-8 independent reads, three workers per batch, eight globally and four active batches. Queue and initial admission count toward the ten-second deadline. Preserve input IDs/order and complete MCP results. Known omissions and unknown dispatched outcomes are explicit. Batch connections disable SDK multi-round-trip continuation; do not broaden ordinary invocation semantics implicitly. Final serialized results including SDK metadata stay below 256 KiB. Use `TEST_READ_BATCH_POSTGRES_DSN` only for a separate empty disposable database.

Server instructions prefer direct known invocations and one search for unknown upstream tools. `search_tools` does not discover gateway tools. Model guidance does not replace runtime policy.
