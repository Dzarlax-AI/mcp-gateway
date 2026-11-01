# MCP Gateway

A self-hosted Go service that connects Streamable HTTP clients to multiple MCP
servers through one endpoint. It stores upstream connection settings and applies
client permissions before forwarding tool calls.

## Administration

The admin has two workspaces:

- **Servers**: connection checks, global server/tool switches, and bulk operation
  classification. The compact server workspace requires classified batch mode.
- **Connection**: client keys and exact tool permissions, grouped by MCP server.
  A client can be granted a whole current server catalog or selected tools from
  several servers, then saved in one operation. Filtering does not remove hidden
  grants. New tools are not added to a client's ACL automatically.

The Connection page also shows the MCP address, a Codex connection command and
Claude Code JSON examples. Show/Copy reveals a key only on request. Shown values
are cleared after 60 seconds or navigation. Environment-managed keys cannot be
shown or deleted through the admin.

### Screenshots

These captures use an isolated local fixture with synthetic servers, tools and
clients. Every endpoint is loopback; no production data or key values are shown.
[Capture setup](docs/screenshots/README.md).

**Servers: tool groups and bulk selection.**

![Synthetic server workspace](docs/screenshots/servers.jpg)

**Connection: clients, MCP groups and exact tool permissions.**

![Synthetic client workspace](docs/screenshots/clients.jpg)

<details>
<summary>Client workspace on a mobile viewport</summary>

<img src="docs/screenshots/clients-mobile.jpg" width="375" alt="Synthetic client permissions on a mobile viewport">

</details>

## Running locally

Requires Go **1.27.3** or newer, as declared in `go.mod`.

The file-backed demo uses only synthetic credentials and a local echo server;
it has no web admin.

```sh
cp config/example.json config/local.json
```

Set these demo-only values in each of three terminals:

```sh
export GATEWAY_DEMO_TOKEN='synthetic-local-client-token'
export DEMO_UPSTREAM_TOKEN='synthetic-local-upstream-token'
```

Run one command per terminal:

```sh
# Terminal 1: synthetic upstream on 127.0.0.1:8081
go run ./cmd/demo -mode server
# Terminal 2: gateway on 127.0.0.1:8080
go run ./cmd/mcp-gateway
# Terminal 3: discovery, schema lookup and echo invocation
go run ./cmd/demo -mode client
```

The MCP endpoint is `http://127.0.0.1:8080/mcp`; health is `/healthz`.
Stop the processes with Ctrl+C. Do not reuse demo credentials in a deployment.

For the web admin, follow [self-hosting](docs/self-hosting.md): configure SQLite
or PostgreSQL, explicitly migrate/import the registry, and set a separate admin
credential or trusted Authentik proxy. Startup does not migrate or import data.
The screenshot fixture can also be run locally as described in its
[capture setup](docs/screenshots/README.md).

## Server and client access

1. Add an upstream in **Servers**, approve its exact HTTPS endpoint and configure
   its Bearer or custom-header credential. Credentials remain at the gateway.
2. Run **Check**. This initializes MCP and lists tools; it does not invoke tools.
   New servers and tools start disabled.
3. Enable the server and tools that should be globally available.
4. Create a separate client key in **Connection**. New keys are restricted with
   no tool access. Select exact tools or MCP groups and save permissions.
5. Connect the application using the address and instructions in Connection.

Client ACLs cannot override global server/tool switches. Migrated
`legacy_shared` principals keep their existing shared-tool access until an
operator explicitly selects Restricted. Existing argument constraints on legacy
tools still apply. See [ACL and migration](docs/deployment/agent-acl.md).

Admin changes use versioned compare-and-swap. A conflict or unknown save result
requires reading back the saved state before retrying. The admin does not
retry a mutation automatically.

## Connecting clients

Use exactly one authentication header with the same client key:

```text
Authorization: Bearer <key>
```

or:

```text
X-API-Key: <key>
```

Both headers together, repeated headers, and empty or invalid credentials are
rejected. Client credentials are not forwarded upstream.

### Codex

Set `MCP_GATEWAY_TOKEN` in the environment of the process running Codex, then use
the command shown by Connection. With an example deployment address:

```sh
codex mcp add my-gateway --url 'https://mcp.example.com/gateway/mcp' --bearer-token-env-var MCP_GATEWAY_TOKEN
```

The equivalent configuration is:

```toml
[mcp_servers.my-gateway]
url = "https://mcp.example.com/gateway/mcp"
bearer_token_env_var = "MCP_GATEWAY_TOKEN"
```

Replace the example URL. For a desktop app, the environment variable must be
available to the app process; exporting it in an unrelated terminal does not
configure an already running app. Reload the MCP connection after configuration.
Do not put a real key in tracked configuration.

### Claude Code

Set `MCP_GATEWAY_TOKEN` in the terminal that starts Claude Code. Merge this entry
into the project's `.mcp.json`, preserving other servers:

```json
{
  "mcpServers": {
    "gateway": {
      "type": "http",
      "url": "https://mcp.example.com/gateway/mcp",
      "headers": { "Authorization": "Bearer ${MCP_GATEWAY_TOKEN}" }
    }
  }
}
```

To use `X-API-Key`, replace the `headers` object with:

```json
{ "X-API-Key": "${MCP_GATEWAY_TOKEN}" }
```

Choose one header. The key remains in the environment, not in the JSON file.
Start a new session after configuration changes and use `/mcp` to inspect the
connection. See [Claude Code setup](docs/claude.md).

## Gateway tools

The default client catalog contains four tools:

| Tool | Input | Purpose |
| --- | --- | --- |
| `discover_server` | optional `query`, `limit` | Find enabled, accessible servers |
| `discover_tools` | `server_id` | List accessible tools |
| `get_tool_schema` | `server_id`, `tool_name` | Get the current input schema |
| `invoke_tool` | `server_id`, `tool_name`, `arguments` | Validate and invoke a tool |

`GATEWAY_TOOL_SEARCH_ENABLED=true` adds `search_tools` with `query` and optional
`limit`/`server_id`. It returns matching tools and their schemas. The shared
in-memory catalog has a 60-second TTL. Successful admin checks publish checked
metadata after the registry commit; toggles do not extend the TTL. Upstream
change notifications are not used.

Known tools can be invoked directly. Search is for unknown tools; reuse the
returned schemas. Upstream schemas and results are untrusted data. The gateway
preserves MCP content types, structured content and error status.

### Optional read batches

With tool search and `GATEWAY_READ_BATCH_ENABLED=true`, the gateway exposes
`invoke_read_batch`. Select one policy mode:

| `GATEWAY_READ_BATCH_POLICY_MODE` | Read eligibility |
| --- | --- |
| `file` (default) | Exact server/tool/endpoint tuples in `GATEWAY_READ_BATCH_ALLOWLIST` |
| `registry` | Existing connector switches and reviewed read profiles |
| `classified` | Effective Read classification for each enabled tool |

Registry and classified modes reject a simultaneous allowlist file. All modes
also require normal client authorization, global switches and valid arguments.
Classification does not enable a tool or grant client access.

In classified mode, `readOnlyHint: true` is treated as an automatic Read.
False and missing hints are unclassified because the pinned Go SDK cannot
distinguish them. Operators can mark selected tools as **Read**, **Write**, or
**Automatic** in the admin. Manual Read is bound to the tool contract and
connection; changed bindings require review. Manual Write excludes the tool
from batches. An annotation is a server declaration, not proof that its code has
no side effects. See [classified batches](docs/deployment/classified-batch.md)
and [legacy connector profiles](docs/deployment/connector-batch-reading.md).

```json
{"operations": [
  {"id": "a", "server_id": "demo", "tool_name": "read_alpha", "arguments": {}},
  {"id": "b", "server_id": "demo", "tool_name": "read_beta", "arguments": {}}
]}
```

Use `invoke_read_batch` for permitted independent reads, including a single
read. Use `invoke_tool` for other operations. Batches support 1–8 items, three
workers per batch, eight global batch workers, and four admitted batches. The
ten-second deadline includes waiting and upstream calls. Current identity,
permissions, arguments and connection are rechecked before dispatch.

Inspect `complete`, every item's `status`, and `dispatched`; an accepted envelope
can contain failed items. `upstream_error` includes unsupported input-required
results. A dispatched timeout or transport failure has an unknown upstream
outcome. Results may be omitted above 64 KiB per item or 256 KiB total; omission
is not success. Invocations are not automatically retried or deduplicated.

## Storage and deployment

- File mode supports static configuration; SQLite and PostgreSQL support the
  versioned registry and web administration.
- Registry document version 2 and SQL schema version 2 are required. Upgrades
  are explicit; see the [ACL runbook](docs/deployment/agent-acl.md).
- Client authentication uses SHA-256 key digests. Recoverable keys and upstream
  credentials are stored separately with AES-256-GCM. Retain the encryption key
  outside the database backup.
- Removing a client key rejects subsequent requests, including existing MCP
  sessions. Already admitted operations may finish.
- Put TLS termination at a reverse proxy and protect the separate admin listener.
  See [self-hosting](docs/self-hosting.md) and the
  [security model](docs/security-model.md).
- Optional [Cloudflare Access Managed OAuth](docs/deployment/chatgpt-oauth.md)
  uses a separate MCP route and maps verified assertions to existing principals.
  The gateway does not provide its own OAuth authorization server; native keys
  remain independent.

The gateway does not support stdio or legacy SSE upstreams. It does not provide
semantic approval of writes. Read-batch and tool-search features are off by
default. Older binaries can reject newer registry fields; review downgrade
requirements before changing images.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o /tmp/mcp-gateway ./cmd/mcp-gateway
go build -o /tmp/mcp-gateway-registry ./cmd/registry
python3 -m unittest discover -s scripts -p 'test_*.py'
node scripts/test_connection_actions.cjs
node scripts/test_permission_actions.cjs
```

Tests use synthetic credentials and local listeners. PostgreSQL tests need
separate disposable databases and must not run against production data.
See [development](docs/development.md) for environment variables and CI checks.

`cmd/mcp-gateway` runs the service; `cmd/registry` handles explicit storage
operations; `cmd/demo` is the local echo demo. Runtime code is in `internal/`.
The Docker image contains non-root gateway and registry binaries.

Publication exports include the explicitly listed synthetic screenshots.
Private deployment settings, operational captures, credentials and local agent
state are excluded.
