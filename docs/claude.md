# Claude Code

## Working on this repository

The root CLAUDE.md imports AGENTS.md so Claude Code and Codex share contributor
instructions. The publication export substitutes the public AGENTS.md; private
deployment history stays in the original working directory. In Claude Code,
use `/context` to check that the project instructions were loaded.

The import follows [Claude Code's instruction-file documentation](https://code.claude.com/docs/en/memory#share-one-file-with-other-coding-tools).

## Connecting to the gateway

1. Create a separate key named **Claude Code** on the admin Connection page.
2. Copy the real MCP endpoint from that page. Use the MCP URL, not the admin URL.
3. Set `MCP_GATEWAY_TOKEN` in the environment of the terminal that starts Claude
   Code. Supply the key through your secret manager or a hidden shell prompt;
   keep the value out of shell history and tracked files.
4. Merge the `gateway` entry from
   [the example](../config/claude-mcp.json.example) into your project's
   `.mcp.json`, under `mcpServers`. Replace the example URL with the copied URL.
   Preserve existing entries. Keep `${MCP_GATEWAY_TOKEN}` literally in the file;
   Claude Code expands it from its process environment.
5. Start Claude Code in that project and approve the project MCP configuration
   when prompted. Run `/mcp` to inspect the connection.

The example uses Streamable HTTP and Bearer authentication. To use the same key
through X-API-Key instead, replace the entire `headers` object with:

```json
{
  "X-API-Key": "${MCP_GATEWAY_TOKEN}"
}
```

Send exactly one credential header. Gateway rejects both headers together.
After changing the environment or configuration, start a new Claude Code session.
Claude Code documents HTTP headers, project configuration and environment
expansion in its [MCP reference](https://code.claude.com/docs/en/mcp).

## Read-only smoke test

With a read-only tool enabled on your upstream, ask Claude Code:

> Through gateway, discover the documentation server, list its tools, get the
> schema of a read-only search tool, and run one documentation search. Do not
> invoke any tool that creates, updates or deletes data.

The expected sequence is `discover_server` → `discover_tools` →
`get_tool_schema` → `invoke_tool`. Check the tool calls and result, not only a
Connected label. A restricted key can access only explicitly selected tools. Grant only the required reads in Connection → Edit permissions. Migrated legacy keys retain their prior shared access until restricted.

For 401 errors, check that the environment is set in the actual Claude Code
process and that the key is still present. For missing servers/tools, check
their enablement and connection check in the admin. Administrator SSO does not
authenticate MCP clients; native connections use client keys; the optional separate Access OAuth route maps verified identities to the same principal ACL.

These instructions target Claude Code. They do not establish compatibility with
the separate Claude Desktop custom-connector setup. No Claude Code end-to-end
connection is claimed by the publication package's automated checks.
