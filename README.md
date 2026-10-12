# MCP Gateway

A self-hosted Go gateway that connects MCP clients to multiple MCP servers through one Streamable HTTP endpoint. Inspired by [Uber's MCP Gateway](https://www.uber.com/re/en/blog/designing-mcp-gateway/).

Clients see four fixed tools: discover servers, list tools, fetch a schema, and invoke a tool. The optional web admin manages servers, per-tool enablement, upstream credentials and client keys.

## Features

- Native Streamable HTTP upstreams, with explicit HTTPS endpoint consent.
- Server and tool enable/disable controls without page reloads.
- SQLite or PostgreSQL persistence; explicit schema migrations.
- Client authentication with one key through either Bearer or `X-API-Key`.
- Named client keys with encrypted storage and on-demand show/copy/delete.
- Upstream Bearer or custom credential headers, including `X-API-Key`.
- Separate administrator authentication: token/session or trusted Authentik proxy.
- Schema validation before invocation, bounded requests and no automatic invocation retries.

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

Upstream MCP results preserve content types, structured content and `isError`. Schemas and returned content remain untrusted data. Tool annotations do not authorize an invocation.

## Access and security

A client key grants access to **all shared enabled tools**, including tools that modify data. There are no per-client grants in the ordinary UI. Disable a tool if clients must not use it. Legacy file configurations can still use argument grants.

Client keys authenticate using SHA-256 digests. Recoverable keys are stored separately with AES-256-GCM under `GATEWAY_SECRET_KEY`. Deleting a key revokes subsequent requests, including existing MCP sessions; admitted operations may finish. Protect the admin and keep the encryption key separate from database backups.

Read the [security model](docs/security-model.md) before exposing the service. The gateway does not implement client OAuth, stdio upstreams, legacy SSE upstreams, automatic retries, or semantic approval of modifying operations. HTTPS is terminated by your reverse proxy.

## Development

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
