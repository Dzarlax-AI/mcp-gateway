# Development

Go version comes from `go.mod`; dependency versions are pinned in `go.mod`/`go.sum`. Do not run registry or contract tests against real data.

Run `go test ./...`, `go test -race ./...`, `go vet ./...`, the Python unit tests and `node scripts/test_connection_actions.cjs`. Test environments must permit local TCP listeners. PostgreSQL tests are skipped when their DSNs are unset; SQLite still runs.

For PostgreSQL parity, provide two separate empty disposable databases:

```text
TEST_POSTGRES_DSN=postgres://user:password@127.0.0.1:5432/store_contract?sslmode=disable
TEST_CLIENT_KEYS_POSTGRES_DSN=postgres://user:password@127.0.0.1:5432/client_key_contract?sslmode=disable
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

Before publication, run `python3 scripts/prepare_github.py --output /tmp/mcp-gateway-github` to produce an explicit allowlist export and checksum manifest. The export preserves runtime source bytes; it does not initialize Git, create a remote, commit or push. Local deployment records and machine-specific instructions remain in the working directory.
