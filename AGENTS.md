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


## Connector batch reading (local revision 1, 2026-10-14)
- `GATEWAY_READ_BATCH_POLICY_MODE=file|registry`, default file. Registry mode requires search+batch flags and rejects a simultaneous allowlist path. Legacy file mode is unchanged.
- Optional server batch fields are default-off; one connector switch and reviewed profile selector, no per-tool override. `internal/readpolicy` pins reviewed Calendar MCP and Home Assistant contracts; unknown or changed definitions and undeclared arguments fail closed. Endpoint/auth replacement clears approval; ordinary access remains separate.
- Registry JSON/CAS persists settings with no SQL migration. Search/discovery eligibility is advisory; batch rechecks current settings/catalog and connection before dispatch. Older binaries reject new fields; downgrade requires scoped field removal while preserving unrelated state.
- Local synthetic SDK, admin/browser, SQLite/disposable PostgreSQL, TTL, isolated Codex and benchmark checks are documented in `docs/deployment/connector-batch-reading.md`. Protocol 2025-11-25 was tested; the SDK default 2026-07-28 context incompatibility is outside this revision. No production, release or real-device invocation is authorized by this local work.

## Secret rotation (approved local revision 1, 2026-10-14)
- Explicit `registry rotate-secret-key` validates both encrypted tables and preserves exact registry document/client hashes/upstream plaintext; one transaction, revision+1, no migration/startup rotation. SQLite writer/PostgreSQL registry+table locks; fresh nonce and existing AAD. Unknown commit must be inspected before recovery.
- Optional PostgreSQL role/password rotation shares that transaction, requires privileged maintenance access, client-side SCRAM verifier and transaction-local sensitive-statement logging protection; detected pgaudit is refused. Do not broaden runtime privileges.
- `scripts/rotate_gateway_secrets.py prepare|apply` uses private input files and a private phase journal, seals a schema/env/old-key recovery bundle under an independent key, verifies new physical runtime login, then fsync/rename installs env. Quiescence is an explicit operator assertion; no service/SSH actions are automatic.
- Local synthetic implementation and rehearsal only. Production env/password/ciphertext, Git commit/push, CI publication and deployment remain unmodified and separately authorized. See docs/deployment/secret-rotation.md and docs/ai-plans/2026-10-14-gateway-secret-rotation.html.


## Working repository and export
- Edit this permanent Git checkout; root `AGENTS.md` and `.gitignore` are authoritative. Historical `docs/repository/` templates are not export inputs.
- `python3 scripts/prepare_github.py --output <new-directory>` creates a reviewed allowlist export with a checksum manifest and performs no Git or deployment actions.
- Preserve embedded JSON contracts and reviewed scripts when extending the export. Test real output builds and deterministic re-export; never treat export omissions as instructions to delete checkout files.
- Keep private operator files, approval plans, credentials and receipts outside Git. Ignore rules do not remove already tracked files or history. Local operator context may be referenced from ignored `docs/local/`.

## Optional MCP Access OAuth
- `GATEWAY_MCP_ACCESS_ENABLED` defaults false. Enabling requires `GATEWAY_PUBLIC_ORIGIN`, `GATEWAY_MCP_ACCESS_ISSUER`, `GATEWAY_MCP_ACCESS_AUD` and strict `GATEWAY_MCP_ACCESS_USER_MAP`.
- `/mcp/oauth` verifies signed Access assertions and maps exact identities to existing principals. Native `/mcp` key authentication remains independent; no fallback from invalid assertions to native keys.
- Synthetic tests are in `internal/accessauth` and `internal/gateway/access_oauth_test.go`. Public setup guidance and a variable-only Compose example are linked from `docs/deployment/chatgpt-oauth.md`; actual provider/client settings and deployment state require separate verification and authorization.

## Agent ACL R1 (local implementation, 2026-10-24)
- Registry JSON requires registry_version=2 and each principal's explicit access_policy and tool_allowlist. New keys are restricted and empty; migration preserves existing principals as legacy_shared. SQL schema stays2.
- Restricted policy checks exact ACL before shared enablement. Legacy tool modes also require existing argument grants. Current identity, globals, endpoint and credential binding are checked before dispatch, including after initialize.
- Explicit registry migrate-agent-acl defaults to dry-run; SQL apply requires expected revision, file apply requires offline mode and expected SHA-256. Runtime never upgrades documents; simplify is unsupported for v2. Unknown outcomes require inspection, never automatic retry.
- Connection permission forms share existing auth/CSRF/Origin/CAS. Endpoint/delete and verified tool removal clear applicable ACL. Ordinary enable preserves legacy constraints.
- GATEWAY_AUDIT_ENABLED defaults false; enabled mode requires private GATEWAY_AUDIT_DIR (0700/0600). Bounded local audit status is disabled/ok/degraded; sink failure does not undo or retry saved work. No payloads or credential material in events.
- ACL PostgreSQL parity uses a separate disposable TEST_ACL_POSTGRES_DSN. Run node scripts/test_permission_actions.cjs alongside existing checks. Export includes ACL runbook/assets/tests, excludes private plans and operational state.
- Approved scope is local implementation and synthetic checks only. No commit, push, deployment, Hermes or live client/provider changes are authorized. Runbook: docs/deployment/agent-acl.md.

## Classified batch and admin workspace
- `GATEWAY_READ_BATCH_POLICY_MODE=classified` is a separate opt-in mode; file/registry compatibility remains. The classified mode exposes the compact admin workspace and per-tool automatic/manual operation types.
- True read-only annotations are trusted server declarations, false/missing are unknown in the pinned SDK. Manual read binds invocation schemas and connection identity; changes require review. Manual write always denies batch. No classification grants ACL or enables a tool.
- Bulk tool changes commit one bounded selection with one CAS; disabling never contacts upstream. Display-only catalog peek never refreshes or extends TTL.
- New optional Tool fields are not understood by older binaries: remove them with a reviewed, revision-bound export/import before rollback. No SQL/startup migration. See docs/deployment/classified-batch.md.
