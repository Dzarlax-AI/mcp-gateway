# MCP Gateway

One connection from your AI client to your MCP servers. Add servers during a
session, discover tools when needed, and control what each client can use.

I built this after reading Uber Engineering's
[Designing MCP Gateway](https://www.uber.com/re/en/blog/designing-mcp-gateway/),
particularly its Omni MCP approach to incremental tool discovery. I wanted the
same idea for my own collection of MCP services: one place to manage connections
and credentials, with tools available as I add them.

This is a self-hosted Go service for Codex, Claude Code and other MCP clients
that support Streamable HTTP.

## Why a gateway?

Connecting each AI application to every MCP server means maintaining the same
addresses and credentials in several places. It can also put a large catalog of
tool definitions into the client's context before the agent knows what it needs.

The gateway keeps upstream connections in one registry and gives each client a
small set of discovery and invocation tools. The agent finds a service, loads
the relevant tool schema, and calls it through the gateway.

- **Add servers without restarting the client session.** Check and enable a new
  server in the admin, then grant its tools to the client. With search and the
  catalog cache enabled, the agent can discover and use them through its existing
  connection. No client configuration change is needed.
- **Load schemas as needed.** Four gateway tools cover discovery and invocation;
  optional search returns matching tools together with their schemas.
- **Give each client its own permissions.** Issue separate keys for different
  applications or agents and choose the exact tools each may use. New keys start
  with no tool access.
- **Batch independent reads.** In classified mode, tools declaring
  `readOnlyHint: true` are automatically eligible for read batches. No separate
  per-tool batch allowlist is needed. Client permissions still apply.
- **Keep upstream credentials in one place.** Manage server authentication in
  the admin, with encrypted storage in SQLite or PostgreSQL. Clients receive
  their own gateway keys.

Dynamic upstream discovery works because the client's gateway tool set stays
fixed. Changing the gateway's own feature flags can change that set and may
require a client reconnect. Discovery also depends on the agent choosing to
search; the gateway does not push new upstream tools into the client's catalog.

## The admin

**Servers** manages upstream URLs, authentication, connection checks and global
tool availability. Tools are grouped as Read, Write or Unclassified, with bulk
enable, disable and classification actions.

![Servers and tool selection, using synthetic data](docs/screenshots/servers.jpg)

**Connection** manages client keys and permissions. Select tools across servers
and save the permission set together. Global server and tool switches remain an
upper bound on every client's access.

![Client keys and tool permissions, using synthetic data](docs/screenshots/clients.jpg)

These screenshots use local mock servers and synthetic clients. See the
[fixture notes](docs/screenshots/README.md) to reproduce them.

<details>
<summary>Mobile permissions view</summary>

<img src="docs/screenshots/clients-mobile.jpg" width="375" alt="Synthetic client permissions on a mobile viewport">

</details>

## Run locally

Requires Go 1.27.3 or newer, matching [go.mod](go.mod), and OpenSSL for generating
local secrets. Run from a fresh checkout. This setup uses SQLite, a local admin
token, tool search and classified read batches.

```sh
go build -o /tmp/mcp-gateway ./cmd/mcp-gateway
go build -o /tmp/mcp-gateway-registry ./cmd/registry

mkdir -p .runtime
chmod 700 .runtime
export GATEWAY_STORAGE=sqlite
export GATEWAY_SQLITE_PATH="$PWD/.runtime/gateway.db"
export GATEWAY_SECRET_KEY="$(openssl rand -base64 32)"
export GATEWAY_CODEX_TOKEN="$(openssl rand -hex 32)"
export GATEWAY_ADMIN_TOKEN="$(openssl rand -hex 32)"
export GATEWAY_ADMIN_ADDR=127.0.0.1:8091
export GATEWAY_ADMIN_ORIGIN=http://127.0.0.1:8091
export GATEWAY_MCP_EXTERNAL_URL=http://127.0.0.1:8080/mcp
export GATEWAY_TOOL_SEARCH_ENABLED=true
export GATEWAY_READ_BATCH_ENABLED=true
export GATEWAY_READ_BATCH_POLICY_MODE=classified

/tmp/mcp-gateway-registry migrate
/tmp/mcp-gateway-registry import --file config/bootstrap.json
/tmp/mcp-gateway
```

Open `http://127.0.0.1:8091/admin/servers` and sign in with
`GATEWAY_ADMIN_TOKEN` from the same shell. Both listeners bind to loopback.

These generated secrets live only in the current shell. For an installation you
intend to keep, save them in a secret manager or an owner-only secret file and
reuse them on restart. Regenerating `GATEWAY_SECRET_KEY` makes stored credentials
unreadable. The process does not load `.env` files automatically. Migration and
bootstrap import are explicit setup steps, not commands to repeat on each start.

For Docker, PostgreSQL, HTTPS routing and administrator authentication, see
[self-hosting](docs/self-hosting.md). Existing installations should read the
[registry and ACL migration guide](docs/deployment/agent-acl.md) before upgrading.

### Add a server and connect a client

1. In **Servers**, add the upstream's Streamable HTTP URL. For HTTPS, approve its
   exact endpoint and choose Bearer, a custom credential header, or no credentials.
2. Run **Check connection**. This initializes MCP and lists tools; it does not
   invoke them. Enable the server and the tools you want to make available.
3. In **Connection**, create a named client key, select the tools that client may
   use, and save its permissions. Creating a key alone grants no tool access.
4. Copy the MCP URL and key into your client configuration. Then ask the agent to
   find a service and use one of its permitted tools.

For Codex, set `MCP_GATEWAY_TOKEN` in the environment of the process that starts
Codex and add:

```toml
[mcp_servers.gateway]
url = "http://127.0.0.1:8080/mcp"
bearer_token_env_var = "MCP_GATEWAY_TOKEN"
```

Use your externally routed HTTPS URL for a remote gateway. For Claude Code, see
the [connection guide](docs/claude.md) and
[configuration example](config/claude-mcp.json.example).

Native clients send exactly one credential header: `Authorization: Bearer <key>`
or `X-API-Key: <key>`. Client credentials are never forwarded upstream.

To add another server later, add and check it in **Servers**, enable its tools,
then grant them to the existing key in **Connection**. Keep the client session
open. Enabling tools globally does not add them to a restricted key's permissions.

## How tool calls work

The default interface has four tools. Search and read batches are opt-in at
process startup; the local setup above enables both, for six tools in total.

| Tool | What it does |
| --- | --- |
| `discover_server` | Finds enabled servers the client can access |
| `discover_tools` | Lists accessible tools on a server |
| `get_tool_schema` | Returns a tool's current schema |
| `invoke_tool` | Validates arguments and invokes an upstream tool |
| `search_tools` | Searches accessible tools and returns matching schemas |
| `invoke_read_batch` | Runs 1–8 independent permitted reads in one gateway request |

An agent that already knows a tool can invoke it directly. For an unfamiliar
operation, it can search once and reuse the returned schema. Read-batch-eligible
operations use `invoke_read_batch`, including a single read; other operations
use `invoke_tool`. The gateway supplies this guidance in its MCP instructions.
Discovery adds round trips, so a smaller initial tool catalog is a tradeoff,
not a guarantee of lower latency or token usage for every task.

With search enabled, the catalog cache has a 60-second TTL. A successful admin
connection check publishes the checked catalog after the registry save. Access
checks use current permissions and switches even when metadata is cached.

### Read batches

Classified mode automatically admits enabled tools whose upstream declaration
includes `readOnlyHint: true`, subject to the calling client's permissions.
Operators can override a tool to **Write** to exclude it, or explicitly approve
it as **Read** when the upstream does not supply a usable hint. Missing or false
hints remain Unclassified unless reviewed. A manual Read approval must be
reviewed again if its bound schema or connection changes.

The annotation is a declaration by the upstream server. The gateway trusts that
declaration; it does not establish that the implementation has no side effects.
Only connect servers whose declarations you trust.

Batches run at most three operations concurrently per request, with a ten-second
total deadline. Each result has its own status; callers must inspect every item
and the batch's `complete` field. A timeout after dispatch can leave the upstream
outcome unknown. Invocations are not automatically retried.

See [classified batches](docs/deployment/classified-batch.md) for classification,
limits and compatibility. Legacy file allowlists and connector profiles remain
available; they are separate policy modes, not prerequisites for classified mode.

## Access, credentials and boundaries

- New keys are restricted to exact selected server/tool pairs. Migrated
  `legacy_shared` principals retain their previous access until explicitly
  restricted. Discovery and invocation use the same permission checks.
- Servers and tools start disabled. Changes to permissions and switches apply
  to subsequent checks; work already dispatched upstream may finish.
- Client authentication uses SHA-256 key digests. Recoverable client keys and
  upstream credentials are stored separately with AES-256-GCM encryption under
  `GATEWAY_SECRET_KEY`.
- Upstreams use Streamable HTTP with literal loopback HTTP or an explicitly
  approved HTTPS endpoint. Bearer and custom credential headers are supported.
  Stdio and legacy SSE upstreams are not supported.
- Input schemas are validated, and upstream MCP content types, structured content
  and error flags are preserved. Schemas and results remain untrusted content;
  schema validation does not make a modifying operation safe to execute.

Public installations need an HTTPS reverse proxy and protected admin access.
Native MCP connections use client keys. An optional separate
[Cloudflare Managed OAuth route](docs/deployment/chatgpt-oauth.md) maps verified
identities to gateway principals; Cloudflare provides OAuth, and the gateway
validates its signed assertions. Browser admin authentication is configured
separately. Read the [security model](docs/security-model.md) before exposing
the service.

## Development

The service uses Go, server-rendered HTML and embedded browser JavaScript/CSS.
No frontend build is required. SQLite and PostgreSQL share the versioned registry
store; startup never applies migrations automatically.

```sh
go test ./...
go test -race ./...
go vet ./...
python3 -m unittest discover -s scripts -p 'test_*.py'
node scripts/test_connection_actions.cjs
node scripts/test_permission_actions.cjs
```

Tests use synthetic credentials and local listeners. PostgreSQL contract tests
require separate disposable databases. See [development](docs/development.md)
for test settings, CI and repository conventions, and
[contributing](CONTRIBUTING.md) for contribution guidance.

## License

[MIT](LICENSE) © 2026 Alexey Panfilov.
