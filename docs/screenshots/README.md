# Synthetic screenshots

These are browser captures of the local `scripts/admin_workspace_fixture.go`
fixture, built from commit `41548a7` and captured on 2026-11-01. The fixture uses
a new temporary SQLite database, fixed demo credentials and loopback MCP handlers.
It does not connect to production services or read personal data.

- `servers.jpg`: synthetic Calendar connector, operation groups and selection.
- `clients.jpg`: synthetic client and permissions grouped by MCP server.
- `clients-mobile.jpg`: the same client layout at a 390 × 844 CSS viewport.

The endpoint and upstream ports are assigned by the fixture. Client names are
`Demo phone` and `Demo laptop`; the `client` principal is a synthetic
environment-managed example. No key was revealed during capture. The images do
not include browser chrome, production domains or production account names.
They are direct screenshots, without compositing or replacement text.
The desktop client image is a full-page capture. Image sizes are 1265 × 712
(servers), 1265 × 1391 (clients), and 375 × 1940 (mobile full page).

## Reproduce

From the repository root:

```sh
go run scripts/admin_workspace_fixture.go
```

Open the printed `admin_origin`. Sign in using the synthetic administrator token
defined in the fixture source. Use these credentials only for this local demo.

Create the two demo clients. For `Demo phone`, select the six Calendar read tools
and `memory/list_calendars`, then save the permissions. Server/tool switches are
left at their synthetic defaults. Capture the server and client workspaces with
keys hidden. Stop the fixture with Ctrl+C; its temporary database is removed.

These three images are the README screenshots. No operational or production
captures are included.
