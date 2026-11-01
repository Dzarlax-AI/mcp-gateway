# README screenshot fixture

Captured on 2026-11-01 from `scripts/readme_fixture.go`, using a new temporary
SQLite database and local mock MCP handlers. This fixture does not load an
existing registry or connect to external services.

All server identifiers are fictional: `demo-inventory`, `demo-library`,
`demo-recipes`, `demo-weather`, and `demo-workshop`. Client names are
`Demo desktop`, `Demo terminal`, and the environment-managed `demo-cli`.
Tools such as `list_items` and `get_stock` are mock operations returning
`{"synthetic":true}`. All URLs are loopback addresses. No key was revealed.

Run from the repository root:

```sh
go run scripts/readme_fixture.go
```

Open the printed `admin_origin` and sign in with the demo administrator token
defined in the fixture source. Create the two demo clients. For `Demo desktop`,
allow `get_item`, `get_stock`, and `list_items` on `demo-inventory`, then save.
Collapse the tool group for the client captures. On the server page, select the
Read group without changing the switches.

`servers.jpg` is a desktop viewport capture; `clients.jpg` is a desktop full-page
capture; `clients-mobile.jpg` is a full-page capture at a 390 × 844 CSS viewport.
These are direct browser screenshots without replacement text or compositing.
Stop the fixture with Ctrl+C to remove its temporary database.
