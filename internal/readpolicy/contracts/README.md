# Reviewed contracts

These definitions are an operator-reviewed positive policy, not dynamically accepted upstream metadata.

Calendar MCP source: `ab23c0590f73af613a9c2513189e485a8d9c4501`.

- MCP handlers: `internal/mcpserver/tools.go` and `tools_v2.go`.
- Application read dispatch: `internal/application/events.go`, `actions.go` and `fanout.go`.
- Calendar/provider reads were inspected; no mutation handler is included. OAuth refresh and internal read-model/cache activity are ordinary read-path behavior.
- Definitions were exported through initialize/tools/list from a local synthetic server with v2 registration enabled. No real calendar was accessed.

Home Assistant sources:

- https://github.com/home-assistant/core/blob/0596e129ec5df7e840e78c5d8869150c38663ca6/homeassistant/components/homeassistant/llm.py
- https://github.com/home-assistant/core/blob/0596e129ec5df7e840e78c5d8869150c38663ca6/homeassistant/components/llm/llm.py

`GetLiveContextTool` reads exposed entity state and matches filters. `GetDateTimeTool` reads the clock. Neither calls device-control services. Fixtures match the two tool definitions observed earlier in the current chat. Provenance hashes and exact title/description comparison are in `home-assistant-review.json`.

An intentional reviewed-contract change requires source review, fixture update, meaningful tests and a gateway release. Do not accept a newly observed fingerprint automatically. A malicious implementation retaining these definitions remains outside this metadata-based assurance.
