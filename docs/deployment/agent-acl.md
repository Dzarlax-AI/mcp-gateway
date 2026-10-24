# Agent ACL, registry document v2

This release adds exact per-principal tool permissions. It requires an explicit
registry document migration before starting the new runtime against an existing
registry. SQL schema stays at version 2; the JSON document becomes version 2.
No automatic document migration, import, grant reset or deployment occurs.

## Policy

Every principal has required `access_policy` and `tool_allowlist` fields:

```json
{
  "access_policy": "restricted",
  "tool_allowlist": {"demo": ["read_summary"]}
}
```

The root document requires `"registry_version": 2`. Unknown/missing versions,
null policy/allowlist, duplicate entries, wildcard names and references to
unsaved server/tool names are rejected. Names are exact, case-sensitive ASCII
identifiers. Disabled saved tools may be selected without enabling them.

`restricted` requires an exact server/tool entry in addition to globally enabled
server/tool switches. For shared tools, input schema validation applies. For
legacy tools, the existing legacy Grant and its allowed/required/equality
argument constraints also apply. An empty legacy Grant permits only empty
arguments. ACL does not remove these constraints or grant batch eligibility.

`legacy_shared` preserves old policy semantics and requires an empty allowlist.
The explicit migration assigns this mode to existing principals. New client keys
are restricted with no tools. Operators can convert legacy principals to
restricted; the ordinary UI cannot convert them back. OAuth clients mapped to
the same principal share its rights. Separate agent profiles require distinct
principals and credentials; a client-supplied agent label grants no authority.

All discovery, schema, search, invocation and batch paths use the same policy.
The raw catalog cache is shared; each response is filtered against current
rights. Invocations recheck identity, policy, globals and connection binding
before transport and after initialize. Revocation before dispatch denies the
operation; already dispatched work may finish. No new automatic retry is added.
Batch additionally requires the existing file or registry read policy.

## Administration

On **Connection**, each key shows its principal, policy and configured/effective
permission counts. **Edit permissions** displays saved server/tool checkboxes,
global availability, current policy access and inherited legacy constraints.
Policy access does not guarantee an upstream connection is ready or healthy.
Saving is explicit and revision checked. New tools never gain restricted ACL
entries automatically. Disabling retains ACL; enabling a legacy tool preserves
its access mode and argument constraints.

Endpoint changes and server deletion clear the server's ACL entries and legacy
grants in the same CAS. A successful complete connection check disables missing
tools and removes their ACL entries. Reappearing tools need explicit permission.
Failed/incomplete checks do not publish catalog state or clear grants. Credential
changes disable the server and require verification again.

A stale/conflicting save requires reload; an unconfirmed save may already have
committed. The enhanced page preserves its draft and blocks another POST until
reload. It never automatically retries a mutation. HTML forms also work without
JavaScript and redirect after successful saves. Reload discards the current draft.
Existing key Show/Copy/reveal/delete behavior is unchanged.

## Explicit migration

Use a maintenance window. Stop the gateway and other writers, take protected
current backups of the registry and encrypted secret tables, and retain the
separate encryption key. Do not paste backups, tokens or migration input into
logs. Review actual revision and backend before applying. The migration changes
only document version/policy fields; it does not rewrite credentials, encrypted
secrets, Grants, switches, endpoint settings or SQL schema.

SQL uses the existing `GATEWAY_STORAGE=sqlite|postgres` and corresponding
`GATEWAY_SQLITE_PATH` or `GATEWAY_DATABASE_URL`. No secret decryption key is needed
for the document migration. The normal runtime still requires its existing key.

```sh
registry migrate-agent-acl --dry-run
registry migrate-agent-acl --apply --expect-revision EXPECTED_REVISION
```

Default is dry-run. Substitute the reviewed numeric revision. A successful apply
advances the revision once. Repeated execution on a valid v2 document is a no-op.
A stale revision fails without retry. Read back the current state if commit
acknowledgement is lost; do not assume the transaction was rolled back.
`registry simplify` is unsupported for v2 because it would widen tool access and
remove legacy constraints.

File registries use a separate offline path:

```sh
registry migrate-agent-acl --file /path/to/registry.json --dry-run
registry migrate-agent-acl --file /path/to/registry.json --apply --offline --expect-sha256 EXPECTED_SHA256
```

Substitute the reviewed digest of the current file. The source must be an
operator-owned regular file, not a symlink. Apply uses an owner-controlled
advisory lock, verifies the expected digest, writes an owner-only temporary file,
fsyncs and atomically replaces the document, then syncs the directory. A sync
failure after replacement is an unknown outcome requiring read-back. This is a
cooperative-writer maintenance contract, not protection from arbitrary local OS
writers. Runtime refuses unversioned documents with a safe upgrade error.

## Local audit

`GATEWAY_AUDIT_ENABLED` defaults to false. When enabled,
`GATEWAY_AUDIT_DIR` is required and must be an owner-only directory (0700).
Audit segments are regular owner-only JSONL files (0600); symlinks are refused.
Use a dedicated persistent private directory, outside the repository, with one
process per directory. Never point gateway and maintenance CLI at the same live
sink concurrently. There is no remote upload, web log endpoint or stdout fallback.

Events contain generated request IDs, authentication kind, principal, validated
server/tool identifiers, decision/outcome/revision/dispatch state, and mutation
actor/target/policy/ACL deltas. Maintenance uses an operator label. Payloads,
arguments/results, endpoints, credentials, JWTs, email assertions, hashes,
ciphertext and connection fingerprints are excluded. Retention is 30 days with
a 100 MiB total cap; oldest segments are removed, append/rotation is serialized.

Invalid enabled configuration fails startup. Later sink loss changes status to
`degraded`; an already saved registry mutation or invoked tool is not rolled
back or retried. Admin responses expose confirmed saved revision and an audit
warning; `/healthz` exposes `X-Gateway-Audit-Status: disabled|ok|degraded` while
retaining the existing health body. Disabled status is explicit in the UI.
Migration summaries include audit status. An audit failure can lose an event;
there is a crash window between commit and audit append. This is bounded local
security logging, not a durable transactional compliance log. Future production
acceptance requires audit explicitly enabled and healthy.

## Verification and rollback

Use only synthetic upstreams and disposable databases. Run Go tests/race/vet,
command builds, Python tests, both connection and permission Node harnesses,
SQLite/PostgreSQL migration parity, browser mobile/keyboard/no-JS checks and a
real standalone publication export/re-export. PostgreSQL ACL migration tests use
`TEST_ACL_POSTGRES_DSN` in a separate database from existing contract suites.
The exporter explicitly includes ACL documentation, runtime assets and tests;
private plans, audit logs, databases, local configuration and operational files
remain outside publication inputs.

An old binary rejects document v2. Image-only rollback is unsafe. During an
approved maintenance window, inspect the actual saved rights and current
credential/server changes. Before new v2 changes, restoring the protected v1
backup can restore the old behavior. After v2 changes, restoring an old backup
would discard those changes: prepare a reviewed compatible document and preserve
current encrypted secrets/keys. No automatic downgrade or reset is provided.
Production deployment, live identity-provider changes and Hermes integration
require separate approval and verification.
