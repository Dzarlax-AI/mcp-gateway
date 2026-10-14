# Connector batch reads (local revision 1)

This revision is implemented and tested locally. No deployment or production registry change has been performed.

## Policy mode

Keep `GATEWAY_TOOL_SEARCH_ENABLED=true` and `GATEWAY_READ_BATCH_ENABLED=true`.

- Unset `GATEWAY_READ_BATCH_POLICY_MODE`, or set `file`: preserves the existing mandatory `GATEWAY_READ_BATCH_ALLOWLIST`. Admin cannot change batch permission in this mode.
- Set `GATEWAY_READ_BATCH_POLICY_MODE=registry`: batch eligibility comes from connector settings and reviewed contracts. Unset `GATEWAY_READ_BATCH_ALLOWLIST`; supplying both sources fails startup. Sources are never unioned.

New optional registry server fields are `batch_read_enabled`, `batch_read_profile`, and `batch_read_endpoint`. Defaults are off/no profile/no binding. SQL schema is unchanged; there is no automatic migration or import.

## Admin workflow

1. Connect, Check and enable a server and the ordinary tools needed.
2. Select a reviewed read profile in Server settings. Saving a profile disables batch.
3. Enable **Batch for reads** on the connector. Enable requires a current successful catalog check and at least one ordinary enabled reviewed read. Expired checks are refreshed without calling any tools.
4. Inspect informational tool eligibility and the verified read count. There is no per-tool override or batch switch.

An endpoint, authentication-header/source or secret replacement clears the batch binding and disables batch. A description/keyword change preserves it. Disable does not contact the upstream. CAS, authenticated sessions, exact Origin and CSRF protections are shared with existing admin actions.

## Reviewed profiles

- `calendar-mcp-v1`: six reads from the existing calendar policy: `list_calendars`, `get_calendar_capabilities`, `get_events_v2`, `get_event_v2`, `get_event_instances_v2`, `search_events_v2`.
- `home-assistant-v1`: `homeassistant__GetLiveContext` and `llm__GetDateTime`.

`internal/readpolicy/contracts/` contains exact MCP definitions. Calendar contracts were exported from a local synthetic Calendar MCP server at source `ab23c0590f73af613a9c2513189e485a8d9c4501`; MCP registrations, application handlers and provider read dispatch were reviewed. Reads can perform ordinary authentication refresh or internal cache access; they do not authorize event/device mutations.

The HA profile is checked against official handlers at commit `0596e129ec5df7e840e78c5d8869150c38663ca6`; provenance and source hashes are in `home-assistant-review.json`. Its contracts match the previously observed current-chat tool metadata. Both official handlers declare read-only behavior and read states/clock. Their default destructive annotation remains true: this exact reviewed exception is not a generic permission based on hints.

Contract fingerprints include parsed MCP tool definitions (schemas, annotations, description/title/metadata) with normalized JSON object-key order. Unknown names, missing/changed contracts and undeclared top-level arguments fail closed. No LLM, name-prefix heuristic or upstream annotation grants permission. A profile represents operator trust in that connector's reviewed implementation contract, not protection against a malicious upstream preserving metadata while changing implementation.

## Sessions, freshness and client routing

`search_tools` and `discover_tools` return advisory gateway-generated `batch_read_allowed` / `batch_read_reason`. Responses remain authorization filtered. The runtime rechecks current ordinary access, connector settings, endpoint binding, latest cached contract and connection fingerprint before dispatch, including after upstream initialize.

Check publishes only after committed CAS; the existing 60s TTL remains the fallback. An existing MCP session observes new server/settings/catalog snapshots. Newly discovered tools still need ordinary Enable. A newly visible tool receives batch permission only if it matches an existing reviewed rule; unknown tools remain ordinary-only. New profiles/rules require a reviewed gateway update, not a UI wildcard.

Batch limits, deadlines, ordered per-item statuses, output budgets, no automatic retry, and SDK continuation suppression remain unchanged. Already dispatched operations can finish after revocation. Enabling a connector does not itself grant ordinary server/tool access.

## Local acceptance and reproduction

- `go test -race ./...`: includes a real 61s TTL acceptance in a persistent SDK session; `-short` skips only this slow acceptance.
- `TEST_CONNECTOR_POSTGRES_DSN`: an additional **empty disposable** database for connector settings, store reopen and persistent SDK tests. Do not point it to production or reuse a populated contract database.
- Existing `TEST_POSTGRES_DSN`, `TEST_CLIENT_KEYS_POSTGRES_DSN`, `TEST_CATALOG_POSTGRES_DSN` and `TEST_READ_BATCH_POSTGRES_DSN` each use their own empty database.
- `go test ./internal/gateway -run TestConnectorBatchWarmBenchmark -v`: 20 alternating file/registry cycles for 1/3 synthetic 10ms reads; output `/tmp/connector-batch-benchmark.json` contains medians/p95 and upstream call count.
- `go test ./internal/readpolicy -bench BenchmarkClassification -benchmem -run '^$'` measures local classification cost.
- Build fixture: `go build -o /tmp/gateway-connector-fixture scripts/connector_batch_fixture.go`. Start it and use its printed synthetic admin origin and gateway endpoint. SIGTERM cleans its temporary SQLite registry.
- `node scripts/test_connector_batch_admin.cjs <admin-origin>` uses the installed local Playwright runtime to test switches, CAS/unknown outcomes, draft preservation, responsive sizes and no-JS behavior.
- `python3 scripts/verify_connector_batch_agent.py <admin-origin> <gateway-endpoint>` uses a temporary isolated Codex home containing the existing auth file and only the synthetic fixture connector. It does not edit the real Codex config. Fixture-only approval applies to discovery/read routes. Authentication files are removed with the temporary home.

SDK acceptance explicitly uses MCP protocol `2025-11-25`. The current SDK's default `2026-07-28` revealed an existing nested upstream initialize/context incompatibility; no transport/protocol changes are included here. Compatibility with that protocol is not claimed. Production/native-chat acceptance requires a separately authorized release.

## Future release and rollback

A future deployment must explicitly select registry mode and remove the file-path environment option, then configure profiles/switches with operator approval. This revision does not run that transition and does not modify existing production allowlist or registry.

Older binaries reject the new JSON fields, even when batch is disabled. Before an authorized downgrade, use the new binary to export to a private file, remove only the three new server fields preserving current servers/tools/principals/secrets, and CAS-import the reviewed document; restore the compatible file policy and only then change the binary. Disabling a flag alone is insufficient. Do not perform automatic rollback or reset/import unrelated state.

Local baseline binary rejection of new fields and successful startup after their scoped removal were verified using synthetic file registry data. PostgreSQL/SQLite settings persistence was verified independently. A production rollback remains separately gated.
