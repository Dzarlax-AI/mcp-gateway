# Self-hosting

## Local SQLite with web admin

Build from the repository root:

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
/tmp/mcp-gateway-registry migrate
/tmp/mcp-gateway-registry import --file config/bootstrap.json
/tmp/mcp-gateway
```

Open `http://127.0.0.1:8091/admin/servers`, sign in with the separate admin token, then use `/admin/connection` to issue named client keys. The bootstrap's `codex` principal uses `GATEWAY_CODEX_TOKEN`.

The generated environment variables last only for the current shell. Before a persistent installation, retain the encryption key and environment-managed tokens in an owner-only secret file or secret manager. Reuse them when restarting; regenerating the encryption key makes stored secrets unreadable. The process does not load `.env` files automatically. This example binds both listeners to loopback.

## PostgreSQL

Set `GATEWAY_STORAGE=postgres` and `GATEWAY_DATABASE_URL` instead of the SQLite path. Use a dedicated schema `mcp_gateway`, a migration owner and a runtime role. Apply `/registry migrate` explicitly as the owner, then import only into an empty registry. Runtime must have:

- `USAGE` on schema `mcp_gateway`.
- `SELECT` on `mcp_gateway.schema_version`.
- `SELECT, INSERT, UPDATE, DELETE` on `registry_state`, `upstream_secrets` and `client_key_secrets`.

Runtime needs no DDL or unrelated schema access. `CREATE SCHEMA IF NOT EXISTS` in the migration also requires CREATE on the selected database; grant it only during migration and revoke it afterward. Arrange role ownership and connection credentials before executing the migration. Choose TLS settings appropriate to your database network; do not copy a production DSN into source.

Schema v2 is required. A v1-to-v2 migration retains the registry document, revision and upstream ciphertext, and creates the client-key table. Back up the database and original encryption key before upgrades. `registry export` includes hashes and metadata, but is not a complete credential backup.

## Docker

```sh
docker build -t mcp-gateway:local .
```

The image runs as UID/GID 65532, with `/mcp-gateway` as entrypoint and `/registry` included. To run an explicit migration, override the entrypoint: `--entrypoint /registry ... migrate`. Supply storage/env settings securely. A mounted SQLite directory must be writable by UID 65532 and database files must be owner-only. Use a read-only root filesystem and drop capabilities; grant writable storage only where needed.

## Public HTTPS

The service's listeners speak HTTP. Put a TLS-validating HTTPS reverse proxy in front of them; do not expose their ports directly to the Internet.

For a deployment at `https://mcp.example.com/gateway/mcp`:

```text
GATEWAY_LISTEN_ADDR=0.0.0.0:8080
GATEWAY_PUBLIC_ORIGIN=https://mcp.example.com
GATEWAY_ADMIN_ADDR=0.0.0.0:8081
GATEWAY_ADMIN_ORIGIN=https://mcp.example.com
GATEWAY_ADMIN_BASE_PATH=/gateway
GATEWAY_MCP_EXTERNAL_URL=https://mcp.example.com/gateway/mcp
```

Route the exact `/gateway/mcp` to port 8080 and `/gateway/admin/` to port 8081, stripping `/gateway` before forwarding. Preserve the canonical Host; Origin checks use explicit settings, not forwarded headers. Keep `/healthz` internal and use the image's `/mcp-gateway healthcheck`. Configure proxy body, concurrency and rate limits for your deployment.

`GATEWAY_MCP_EXTERNAL_URL` is an advertised address, not a routing configuration. Set it to the URL clients actually reach.

## Optional tool search and catalog cache

Set `GATEWAY_TOOL_SEARCH_ENABLED=true` on the gateway process to expose the fifth
`search_tools` tool. It searches enabled, accessible tools and returns matching
definitions and schemas. Existing discovery and invocation tools remain available.

The gateway and admin share an in-memory catalog. A successful **Check connection**
publishes the checked definitions after the registry commit. After explicitly
enabling a newly discovered tool, clients can find and invoke it in their existing
MCP session. Access switches are checked against the current registry on every
request; they do not extend cache freshness. A 60-second TTL refreshes upstream
changes made outside admin checks. Upstream notifications are not used.

Changing from the default four-tool interface to the five-tool interface may
require a one-time client catalog refresh. Subsequent upstream additions do not
require reconnecting. Disable this feature and restart to restore the old live
catalog path. No database migration is needed.

## Authentik

Set `GATEWAY_ADMIN_AUTH_MODE=authentik`, clear `GATEWAY_ADMIN_TOKEN`, and configure at least one of `GATEWAY_ADMIN_ALLOWED_USERS` or `GATEWAY_ADMIN_ALLOWED_GROUPS`. Configure `GATEWAY_ADMIN_TRUSTED_PROXY_CIDRS` with exact immediate proxy peers (`/32` or `/128`).

Only a trusted, isolated proxy may supply `X-authentik-username` and `X-authentik-groups`. Strip incoming identity headers, run Authentik forward auth, then attach its response headers. Group values use pipe separators. Ensure clients and other containers cannot reach the admin listener from a trusted peer address. Forwarded client addresses do not grant trust.

Protect only admin routes with SSO; the MCP route uses its own Bearer/X-API-Key authentication. Configure Authentik's callback/sign-out routes for your host. Verify real login, callback and an AJAX action after the session has aged; a healthy gateway alone does not prove SSO works.
