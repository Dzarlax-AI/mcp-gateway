# Contributing

Read [development](docs/development.md), [self-hosting](docs/self-hosting.md) and the [security model](docs/security-model.md).

Keep changes focused and describe the resulting behavior and validation. Run the affected tests, then the race-enabled Go suite and vet for changes to shared code. Test SQLite and disposable PostgreSQL separately when modifying persistence. Never use production credentials or real calendar/notification data in tests.

Keep new servers and tools disabled by default. Preserve MCP content types, current-snapshot authorization and explicit migrations. Do not add automatic invocation retries. Cover failure paths for authentication, CSRF, CAS conflicts, encryption and proxy trust when changing those boundaries.

Report vulnerabilities privately as described in the security model. Public issues and pull requests must contain no secrets or private deployment details.
