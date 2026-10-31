# Security model

The gateway is a privileged bridge to upstream tools. Restricted principals require exact server/tool ACL entries, current authentication, enabled global switches and input validation. Migrated legacy_shared principals retain old shared access until restricted. ACL is not an approval engine for destructive actions.

## Boundaries

- Client requests select registered server/tool IDs, never arbitrary endpoints.
- Remote upstreams require exact HTTPS consent. TLS validation stays enabled; redirects and system HTTP proxies are disabled. Literal loopback HTTP is supported for local upstreams.
- Incoming credentials use exactly one Bearer or X-API-Key header. Client credentials are never forwarded to upstreams.
- Registered upstream servers may share a credential, including environment-backed and encrypted values. Upstream credentials must differ from all gateway client keys. Each encrypted server credential remains bound to its own server ID; updating one saved credential does not update other servers. Revoking the shared value at its provider affects every upstream that uses it.
- Upstream secrets and recoverable client keys use AES-256-GCM with distinct associated data. Client authentication uses a digest; normal registry snapshots do not decrypt client keys.
- Admin authentication is separate. Sessions require CSRF and Origin/Host validation. Reveal is protected POST with no-store responses. Normal list/GET/create responses contain no full client key.
- Upstream schemas/content are untrusted. Arguments are schema-validated; external schema references are not loaded. Tool annotations do not expand access.
- Requests, results and operation duration are bounded. Invocation has no automatic retries.

## Optional Access OAuth route

The default-off `/mcp/oauth` route accepts signed Cloudflare Access application
assertions and maps exact configured identities to existing gateway principals.
It does not authenticate opaque forwarded OAuth bearer values as gateway keys.
Native key authentication remains separate. OAuth inherits the principal's
exact ACL or explicit legacy compatibility policy, including applicable legacy argument constraints.
Multiple clients mapped to the same principal have the same effective rights.
The route validates assertions on requests; deleting a principal denies later
admissions. Ordinary and batch calls recheck current access before dispatch; already dispatched operations may finish. No instantaneous identity-provider
revocation guarantee is made for an otherwise valid assertion.

See [the OAuth guide](deployment/chatgpt-oauth.md) for required settings,
origin/edge boundaries and acceptance limits. Keep actual identity mappings and
rendered deployment configuration outside Git.

## Operations

Keep the encryption key outside the database and its backup. Back up both securely; losing either may make stored secrets unrecoverable. Never commit tokens, `.env` files, databases, private keys, or authentication callback URLs. A copied key stays in the system clipboard until another item replaces it; automatic hiding clears only the browser display.

Deleting a key affects later requests, including established sessions, but admitted operations may finish. Environment-managed keys cannot be displayed or deleted in the UI. Existing hash-only keys still authenticate but cannot be recovered.

Reverting a schema-v2 image alone is unsafe: old binaries expect schema v1. The explicit `registry downgrade-client-keys` loses recoverable values while retaining hashes, env principals and current server state. Pre-client-key binaries additionally require removing managed principals before downgrade. Review the actual target version and take a current backup before any rollback.

## Reporting

Do not put secrets or private production data in a public issue. Until a private vulnerability-reporting channel is enabled for the GitHub repository, contact the repository maintainer through a private channel you already have. No specific support SLA or security audit is claimed.

See [Agent ACL](deployment/agent-acl.md) for required document migration, lifecycle invalidation, audit failure semantics and compatible rollback.

## Classified batch mode

The opt-in classified policy trusts `readOnlyHint: true` from the configured upstream. An operator can override the operation type. Manual-read approvals are bound to tool invocation schemas and exact connection identity; stale approvals deny batch, and manual writes override annotations. Missing/false hints are unclassified in the pinned SDK. These decisions never bypass client ACL, enabled switches, argument validation or endpoint binding. Legacy profile/file modes are unchanged. See [classified batch administration](deployment/classified-batch.md) for persistence and safe downgrade.
