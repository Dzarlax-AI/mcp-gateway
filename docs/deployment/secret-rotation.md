# Gateway secret rotation

Revision 1 is implemented and rehearsed locally. No production rotation, release commit, push or deployment is included. Use only synthetic data until the tested release and maintenance window receive explicit authorization.

## Preserved state

`registry rotate-secret-key` replaces every row in `upstream_secrets` and `client_key_secrets` in one transaction. It preserves the registry document bytes, schema, row IDs, upstream credential plaintext, client tokens/hashes/metadata, grants, switches, endpoints and connector batch profiles. Revision advances exactly once. The runtime store instance must be closed after rotation and reopened with the new key; startup never rotates secrets.

PostgreSQL locks the registry row and both secret tables; SQLite acquires its writer before validation. All ciphertext and recoverable client digests are checked before updating any row. Stale revision, orphan rows, corrupt ciphertext or missing secrets fail closed. Fresh nonces and the existing AAD domains/formats are retained. A failed commit is reported as **unknown**, never retried automatically.

## Operator interface

Inputs are absolute paths to regular owner-only files in private directories. Key files contain exactly the base64 encoding of 32 bytes, without newline. Database-location files contain an exact URL for PostgreSQL, or a SQLite path. Password files contain 32–256 printable ASCII bytes; the orchestration script generates 64 hex characters. No secret appears in an argument or CLI output.

```sh
registry rotate-secret-key --storage postgres \
  --database-url-file /private/operator.url \
  --old-key-file /private/old.key --new-key-file /private/new.key \
  --expected-revision 56 --verify-only
```

Omitting `--verify-only` commits the key change. Adding `--role mcp_gateway_runtime --new-password-file /private/new.password` changes the role password in **the same database transaction**. This combined operation requires a privileged maintenance connection, rejects detected `pgaudit`, generates a client-side SCRAM-SHA-256 verifier and suppresses statement/error/duration logging locally for the password statement. Global logging settings are preserved. Before production, separately inspect other auditing/logging agents; this is not a universal audit-extension detector. Do not give runtime new permanent privileges. The PostgreSQL connection must use an existing approved operator path; the runtime DSN remains restricted.

Reports contain only revision, row counts, committed/password-rotated booleans. Fixed errors do not include driver exceptions, DSNs, input values or child stderr. Wrong inputs, symlinks, readable-by-others files, existing recovery outputs and corrupt envelopes are rejected.

## Offline orchestration

`scripts/rotate_gateway_secrets.py` performs no SSH, Docker start/stop, migration or network-policy changes. The operator stops gateway, drains outstanding operations and excludes other writers before `apply`. `--service-quiesced` is an explicit assertion, not automatic proof that a service is stopped. The script uses a strict dotenv subset; verify the actual production env syntax before use. Unsupported interpolation/escapes/duplicate variables are rejected rather than guessed.

Create empty mode0700 state and recovery directories. A private operator URL and an existing validated schema dump are inputs. Runtime/operator URLs must identify the same host, port and database.

```sh
python3 scripts/rotate_gateway_secrets.py prepare \
  --registry /registry --state-dir /private/state \
  --env-file /private/gateway.env --operator-url-file /private/operator.url \
  --backup-file /private/registry.dump --recovery-key-file /private/recovery/key \
  --expected-revision 56

python3 scripts/rotate_gateway_secrets.py apply \
  --registry /registry --state-dir /private/state --service-quiesced
```

`prepare` generates a new key/password and preserves all env values except the AES key and the password component of the runtime DSN. It verifies the original DB/key/revision, creates an independently encrypted recovery bundle, round-trips its envelope and persists a private journal. It does not alter database, role or active env. A partial prepare is not replayed into a nonempty state directory; inspect its private files and use a new empty directory after resolving the failure.

`apply` checks staged-file integrity and active env drift, inspects both key generations/revisions, commits key/password together and verifies a **new physical runtime connection** with the new password/key before atomic env replacement. Publication includes file and directory fsync. Recovery after an ambiguous commit checks the current state; it does not resubmit a mutation that may have committed. Repeated apply at a confirmed completed revision is inspection-only and preserves revision. Any additional registry revision causes a halt for operator review.

Journal states are `prepared`, `db_committed`, `env_installed`. A crash after DB commit but before journal update is recovered by inspecting the new-key snapshot. A crash after env rename but before journal update is recovered by verifying its staged hash. Env drift, corrupted private files or unavailable DB stop the operation. Never restart gateway until DB, password and env agree.

## Recovery material

`registry seal-recovery` seals an archive under an independent AES-GCM recovery key with an explicit recovery AAD domain. `--open` authenticates and writes a new private output; existing output paths are never overwritten. The orchestration bundle contains the schema dump, original env and old key. The recovery key lives outside the state directory and must be backed up separately by the operator. Generated temporary plaintext archives are removed only after successful envelope verification; original backup/env and staged secret files are retained for controlled recovery.

The local rehearsal restored a sealed pre-rotation schema dump into a separate database, verified unchanged upstream/client credentials and rotated that restored snapshot forward under the new key. Historical production copies, external backup/sync locations and retention/deletion are not handled automatically. Do not return exposed keys/passwords to active service during rollback. Keep new credentials for an image-only rollback; restore DB snapshots only while quiesced and only with explicit authorization and a check for later user changes.

## Acceptance and evidence

Local Go rotation contracts cover SQLite and disposable PostgreSQL17.11, exact document preservation, all three client types, late corrupt client ciphertext, stale/concurrent CAS, row/before-commit rollback, password rollback and a simulated unknown response after commit. The operator rehearsal includes actual subprocess exit after DB commit, env-rename/fsync failures, staged drift, repeated recovery, real gateway process restarts and authenticated reads through Bearer/custom-header synthetic upstreams with all three unchanged client tokens.

The leak checks scan operator stdout/stderr and PostgreSQL logs configured with `log_statement=all` and `log_min_duration_statement=0`, looking for generated key/password/recovery-key values, synthetic upstream/client tokens and a SCRAM-verifier statement. This verifies tested surfaces; it does not prove absence from every external logger or OS diagnostic facility.

CI defines a separate disposable rotation PostgreSQL service and builds/runs the synthetic fixture. CI execution is pending commit/push; local checks are recorded in `docs/verification/secret-rotation-local.json` and the approved HTML plan.
