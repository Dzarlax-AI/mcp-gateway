# Security model

The gateway is a privileged bridge to upstream tools. Every shared enabled tool is available to every valid client key. It is not a per-user permission system or an approval engine for destructive actions. Keep modifying tools disabled until their clients are trusted.

## Boundaries

- Client requests select registered server/tool IDs, never arbitrary endpoints.
- Remote upstreams require exact HTTPS consent. TLS validation stays enabled; redirects and system HTTP proxies are disabled. Literal loopback HTTP is supported for local upstreams.
- Incoming credentials use exactly one Bearer or X-API-Key header. Client credentials are never forwarded to upstreams.
- Upstream secrets and recoverable client keys use AES-256-GCM with distinct associated data. Client authentication uses a digest; normal registry snapshots do not decrypt client keys.
- Admin authentication is separate. Sessions require CSRF and Origin/Host validation. Reveal is protected POST with no-store responses. Normal list/GET/create responses contain no full client key.
- Upstream schemas/content are untrusted. Arguments are schema-validated; external schema references are not loaded. Tool annotations do not expand access.
- Requests, results and operation duration are bounded. Invocation has no automatic retries.

## Operations

Keep the encryption key outside the database and its backup. Back up both securely; losing either may make stored secrets unrecoverable. Never commit tokens, `.env` files, databases, private keys, or authentication callback URLs. A copied key stays in the system clipboard until another item replaces it; automatic hiding clears only the browser display.

Deleting a key affects later requests, including established sessions, but admitted operations may finish. Environment-managed keys cannot be displayed or deleted in the UI. Existing hash-only keys still authenticate but cannot be recovered.

Reverting a schema-v2 image alone is unsafe: old binaries expect schema v1. The explicit `registry downgrade-client-keys` loses recoverable values while retaining hashes, env principals and current server state. Pre-client-key binaries additionally require removing managed principals before downgrade. Review the actual target version and take a current backup before any rollback.

## Reporting

Do not put secrets or private production data in a public issue. Until a private vulnerability-reporting channel is enabled for the GitHub repository, contact the repository maintainer through a private channel you already have. No specific support SLA or security audit is claimed.
