# MCP Gateway

A self-hosted gateway for using multiple MCP servers from Codex, Claude Code and other Streamable HTTP clients through one connection.

## Why this exists

As your collection of MCP servers grows, each AI client needs its own list of
endpoints, credentials and available tools. Adding a server or changing its
credentials means updating those connections across applications. Exposing
every upstream tool directly also gives the client a larger catalog to work
through, even when a task needs only one service.

MCP Gateway moves those connections into one place. Register your servers once,
keep their credentials at the gateway, and connect each application to a single
MCP endpoint with its own client key. You can then add servers, rotate upstream
credentials or disable tools centrally, without editing each client's upstream
configuration.

By default, the client sees four gateway tools instead of the full upstream
catalog. It discovers a server, lists that server's tools, loads the schema it
needs, and invokes the selected tool. This lets an agent explore capabilities
as the task requires them, rather than receiving every upstream tool definition
at once. An explicit `GATEWAY_TOOL_SEARCH_ENABLED=true` opt-in adds
`search_tools`, which returns matching tools with their schemas. It also enables
a shared in-memory catalog cache with a 60-second TTL for metadata and invoke
paths. A successful admin connection check publishes its verified catalog after
the registry update commits. Tool switches use current policy and do not extend
the catalog TTL.

The project is inspired by [Uber's MCP Gateway](https://www.uber.com/re/en/blog/designing-mcp-gateway/)
and built for running your own collection of MCP services.

## How you use it

For example, you might have separate MCP servers for documentation, a calendar
and a personal knowledge base. Add them in the web admin, configure their
authentication, and enable the tools you want to expose. Connect Codex and
Claude Code to the gateway using a separate key for each application.

When you ask an agent to search documentation, it can discover the documentation
server and retrieve the search tool's schema before calling it. A later task
can discover a different server through the same connection. The gateway routes
the invocation to the saved endpoint and returns the upstream MCP result.

The admin gives you one place to manage this catalog and its credentials. A
server or tool switch controls availability across clients. Separate client
keys let you revoke one application's connection while keeping the others.
All client keys share access to enabled tools; they are not separate permission
profiles.

## What is supported

- Streamable HTTP upstreams with explicit HTTPS endpoint consent.
- A web admin for registering servers and enabling individual tools.
- Separate client keys, with Bearer or `X-API-Key` authentication.
- Upstream Bearer or custom credential headers, including `X-API-Key`.
- Encrypted credential storage with SQLite for a standalone installation or
  PostgreSQL for an existing infrastructure database.
- Administrator sign-in through a separate token or a trusted Authentik proxy.
- Input schema validation and preservation of upstream MCP result types.

## Try the synthetic demo

Requires Go 1.26.4 or newer. No external services or real data are needed.

```sh
cp config/example.json config/local.json
```

Set these **synthetic demo-only** values in each of three terminals:

```sh
export GATEWAY_DEMO_TOKEN='synthetic-local-client-token'
export DEMO_UPSTREAM_TOKEN='synthetic-local-upstream-token'
```

Then run one command per terminal:

```sh
# Terminal 1: synthetic upstream on 127.0.0.1:8081
go run ./cmd/demo -mode server
# Terminal 2: gateway on 127.0.0.1:8080
go run ./cmd/mcp-gateway
# Terminal 3: discovery, tool listing, schema and echo invocation
go run ./cmd/demo -mode client
```

The gateway endpoint is `http://127.0.0.1:8080/mcp`; health is `/healthz`. Stop the processes with Ctrl+C. File mode has no web admin. The demo config uses legacy argument grants; servers added through the admin use shared enablement instead.

## Run the web admin

See [self-hosting](docs/self-hosting.md) for SQLite setup, PostgreSQL roles, HTTPS routing and Authentik trust requirements. A new installation explicitly migrates and imports an empty bootstrap registry before starting the gateway. Startup never applies migrations automatically.

In the admin, add an upstream, consent to its exact HTTPS endpoint, choose its authentication header, and run the connection check. That check only initializes MCP and lists tools. Enable the server and the tools you want clients to use. New additions default to disabled.

The **Connection** page displays the configured MCP URL and lets you create a separate key for each application. Keys are hidden until Show or Copy is pressed. Existing environment-managed keys are preserved and cannot be revealed or deleted there.

## Connect a client

Use the externally routed URL shown on the Connection page. Send exactly one header:

```text
Authorization: Bearer <key>
```

or:

```text
X-API-Key: <same-key>
```

Both, repeated or empty credentials are rejected. Client credentials are never forwarded upstream.

For Codex, set `MCP_GATEWAY_TOKEN` in the environment of the actual Codex process, then add this configuration:

```toml
[mcp_servers.gateway]
url = "https://mcp.example.com/gateway/mcp"
bearer_token_env_var = "MCP_GATEWAY_TOKEN"
```

Replace the example URL with your deployment's URL. Do not put a real key in tracked configuration.

For **Claude Code**, use [the connection guide](docs/claude.md) and
[the MCP configuration example](config/claude-mcp.json.example). It supports
Bearer or `X-API-Key` with an environment variable for the key. The root
`CLAUDE.md` imports the shared `AGENTS.md` contributor instructions.

## Gateway tools

| Tool | Input | Purpose |
| --- | --- | --- |
| `discover_server` | optional `query`, `limit` | Find enabled, accessible servers |
| `discover_tools` | `server_id` | List accessible tools on a server |
| `get_tool_schema` | `server_id`, `tool_name` | Load the current tool schema |
| `invoke_tool` | `server_id`, `tool_name`, `arguments` | Validate and invoke an upstream tool |

When `GATEWAY_TOOL_SEARCH_ENABLED=true`, the gateway also exposes:

| Tool | Input | Purpose |
| --- | --- | --- |
| `search_tools` | `query`, optional `limit` and `server_id` | Find enabled, accessible tools and return their schemas |

This option is disabled by default. The catalog is held in process memory and
expires 60 seconds after a successful upstream catalog fetch. A successful
admin **Check connection** publishes its checked catalog after the registry
commit, so newly enabled tools can appear in the same client session. Enabling
or disabling a tool applies current access policy and does not refresh the
catalog's expiry time. Upstream change notifications are not used.

Upstream MCP results preserve content types, structured content and `isError`. Schemas and returned content remain untrusted data. Tool annotations do not authorize an invocation.


### Optional read batches

Server initialization instructions describe the shortest supported path: invoke
known tools directly, search unknown tools once, and reuse returned schemas.
With both `GATEWAY_TOOL_SEARCH_ENABLED=true` and
`GATEWAY_READ_BATCH_ENABLED=true`, the gateway exposes `invoke_read_batch`.
`GATEWAY_READ_BATCH_ALLOWLIST` must point to a valid operator-managed JSON file;
see [the synthetic example](config/read-batch.example.json). The exact server,
tool and endpoint tuple must be listed. Upstream annotations do not authorize
batch reads, and the allowlist never grants normal tool access or enables a tool.
Keep this file operator-controlled and replace it atomically.

```json
{"operations": [
  {"id": "alpha", "server_id": "demo", "tool_name": "read_alpha", "arguments": {}},
  {"id": "beta", "server_id": "demo", "tool_name": "read_beta", "arguments": {}}
]}
```

Use batches only for independent reads whose behavior the operator has verified.
For one operation, use `invoke_tool`. Each batch contains 1–8 unique operation IDs;
at most three operations run concurrently per batch, eight globally for batch
workloads, and four batches are admitted concurrently. Busy requests fail fast.
The ten-second request deadline includes queue waiting and upstream calls.
Current client authorization, switches, argument policy, allowlist and connection
inputs are checked again before each invocation. Already dispatched operations
can finish after revocation. No batch invocation is retried or deduplicated. Batch connections also disable
the SDK automatic multi-round-trip continuation middleware.

Results preserve input ID/order and contain per-item `status`, `dispatched` and
an original MCP `tool_result` when available. Inspect every item and `complete`:
a valid envelope with `isError=false` can contain failed operations.
`upstream_error` also covers unsupported input-required results; inspect the
original result rather than assuming its `isError` must be true. A dispatched
transport error or timeout has an unknown upstream outcome. Results over 64 KiB
per item or the 256 KiB total serialized response budget can be replaced with
`result_omitted`; omission is not success and must not trigger an automatic retry.

The feature is off by default and requires no registry change or SQL migration.
The admin UI does not manage batch eligibility. Changing the fixed tool set may
require an initial client refresh; changing the allowlist is read on subsequent
admissions. Generic `invoke_tool` remains capable of writes and is not marked
read-only. Disabling the batch flag restores the five-tool search interface.

## Access and security

A client key grants access to **all shared enabled tools**, including tools that modify data. There are no per-client grants in the ordinary UI. Disable a tool if clients must not use it. Legacy file configurations can still use argument grants.

Client keys authenticate using SHA-256 digests. Recoverable keys are stored separately with AES-256-GCM under `GATEWAY_SECRET_KEY`. Deleting a key revokes subsequent requests, including existing MCP sessions; admitted operations may finish. Protect the admin and keep the encryption key separate from database backups.

Read the [security model](docs/security-model.md) before exposing the service. The gateway does not implement client OAuth, stdio upstreams, legacy SSE upstreams, automatic retries, or semantic approval of modifying operations. HTTPS is terminated by your reverse proxy.

## Development

Set `GATEWAY_TOOL_SEARCH_ENABLED=true` on the gateway process to try the optional
search tool and catalog cache locally. Leave it unset or false to retain the
four-tool catalog.

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o /tmp/mcp-gateway ./cmd/mcp-gateway
go build -o /tmp/mcp-gateway-registry ./cmd/registry
python3 -m unittest discover -s scripts -p 'test_*.py'
node scripts/test_connection_actions.cjs
```

Go tests use synthetic credentials and local listeners. PostgreSQL parity tests require **two separate disposable databases**; they must never run against a production database. See [development](docs/development.md) for the environment variables and CI coverage.

## Layout

- `cmd/mcp-gateway`: HTTP gateway and optional admin process.
- `cmd/registry`: explicit migration, import/export and compatibility commands.
- `cmd/demo`: synthetic MCP server/client.
- `internal/config`, `policy`, `upstream`, `gateway`: registry, authorization and transport.
- `internal/store`, `admin`: persistence, encrypted credentials and web admin.
- `Dockerfile`: non-root image containing gateway and registry binaries.

Publication bundles exclude local deployment history, production settings, screenshots, private credentials and machine-specific agent instructions.
