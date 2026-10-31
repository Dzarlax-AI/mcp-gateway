# Development

Go version comes from `go.mod`; dependency versions are pinned in `go.mod`/`go.sum`. Do not run registry or contract tests against real data.

Run `go test ./...`, `go test -race ./...`, `go vet ./...`, the Python unit tests and `node scripts/test_connection_actions.cjs`. Test environments must permit local TCP listeners. PostgreSQL tests are skipped when their DSNs are unset; SQLite still runs.

For PostgreSQL parity, provide separate empty disposable databases:

```text
TEST_POSTGRES_DSN=postgres://user:password@127.0.0.1:5432/store_contract?sslmode=disable
TEST_CLIENT_KEYS_POSTGRES_DSN=postgres://user:password@127.0.0.1:5432/client_key_contract?sslmode=disable
TEST_OPERATION_POSTGRES_DSN=postgres://user:password@127.0.0.1:5432/operation_contract?sslmode=disable
TEST_MANAGEMENT_POSTGRES_DSN=postgres://user:password@127.0.0.1:5432/management_contract?sslmode=disable
TEST_SHARED_CREDENTIALS_POSTGRES_DSN=postgres://user:password@127.0.0.1:5432/shared_credentials_contract?sslmode=disable
```

These are illustrative local test DSNs. The contract suites modify schema and data. Use distinct databases, especially under parallel execution. GitHub CI supplies two disposable PostgreSQL services and runs the race-enabled Go suite, vet, builds, Python tests and the JavaScript harness. CI uses synthetic test credentials and no production secrets.

Go handles authentication, storage and server-side HTML. The admin has dependency-free browser JavaScript and CSS embedded into Go. The Node harness exercises the actual connection script. No frontend build is required.

After tests pass, CI builds the non-root `linux/amd64` image. Pushes to `main`
in `Dzarlax-AI/mcp-gateway` publish it to `ghcr.io/dzarlax-ai/mcp-gateway`
using the workflow's `GITHUB_TOKEN`, with `latest` and full commit SHA tags.
Pull requests and other branches only build. Package visibility is checked to
be private before updating `latest`; no deployment is performed. Private pulls
require GHCR authentication with package read access. Pin a commit tag or image
digest when deploying rather than relying on the moving `latest` tag.

## Working repository and publication exports

Use the permanent Git checkout for source changes, reviews and future commits.
Keep operator credentials and deployment history outside Git; a legacy source
workspace or `docs/local/` can retain private context. The root `AGENTS.md` and
`.gitignore` are authoritative. Historical files under `docs/repository/` are
legacy templates; the exporter does not map them over the root files.
Git ignore rules do not untrack files already committed or remove old history.

Run `python3 scripts/prepare_github.py --output /tmp/mcp-gateway-github` with a
fresh output path to produce a reviewed allowlist export and `PUBLICATION.json`
checksums. It includes Go/embedded JavaScript sources, explicitly reviewed JSON
contracts, test/rotation helpers, public guides and the variable-only OAuth
Compose example. New non-Go/JavaScript runtime assets or scripts must be added
to the allowlist explicitly; do not export every tracked or untracked file.

The exporter preserves bytes and current root instructions, refuses missing
required inputs, symlinks, known private-path/key markers and output overwrites,
and validates inputs before creating the output. It is not a general secret
scanner: review newly included files and the complete diff before publication.
It never initializes Git, commits, pushes or applies deployment settings.
An export is a disposable verification artifact, not the working repository or
a deletion manifest. It must be able to re-export itself with identical bytes.

Run `python3 -m unittest discover -s scripts -p 'test_prepare_github.py'` for
export regressions. Verify a real export with Go build/tests and Python tests
from its output directory, so omitted embedded assets and helper dependencies
cannot be masked by files in the original workspace. OAuth settings and a
reviewable Compose example are in [the OAuth guide](deployment/chatgpt-oauth.md).

## Agent permissions

Registry document v2 requires explicit per-principal policy and exact tool ACL. New keys start restricted with no access. OAuth and native credentials resolve to the same policy evaluator. Existing installations require a reviewed explicit migration; see the [ACL runbook](deployment/agent-acl.md). Local audit is opt-in and has explicit degraded status.

The classified workspace can be previewed with `go run scripts/admin_workspace_fixture.go`. This creates only synthetic SQLite/loopback upstream data. See [classified batches](deployment/classified-batch.md) for the opt-in policy and compatibility boundaries.
