# Use ActionProxy As An MCP Server In Codex And Claude Code

This example shows the shortest path for a coding agent to use ActionProxy as one of its MCP servers.

Codex, Claude Code, Cursor, Windsurf, or another tool is the MCP host. ActionProxy is the local stdio MCP server you add to that host as `actionproxy-demo`. ActionProxy does not call Codex or Claude Code; the host calls tools exposed by ActionProxy.

```text
Codex, Claude Code, or another MCP host
  -> actionproxy-demo MCP server
  -> ActionProxy MCP wrapper
  -> ActionProxy HTTP gateway for policy, approval, grants, and audit
  -> demo downstream MCP server
```

The demo uses only the local mock MCP server in `examples/mcp-demo`. It does not call real Gmail, Slack, OpenAI, Anthropic, or any other SaaS API.

## What You Prove

- `docs.search` is allowed and forwarded immediately.
- `gmail.send_email` pauses for ActionProxy approval before the downstream MCP server sees it.
- Rejected or blocked calls are returned to the host as MCP errors and are not forwarded.
- ActionProxy records the proposal, policy decision, approval, execution grant, grant consumption, downstream outcome, and audit trail.

## Three-Terminal Setup

Terminal 1: start ActionProxy in proxy mode:

```bash
corepack pnpm dev:proxy
```

Terminal 2: start the local web console for approvals:

```bash
corepack pnpm dev:web
```

Terminal 3: build the wrapper and print host-specific setup commands:

```bash
corepack pnpm demo:mcp:hosts
```

The command prints absolute paths for your checkout. Use those printed commands
instead of copying the literal `<repo>` markers from this README.

Before registering the wrapper, inspect the static configuration. This does not
spawn the configured downstream MCP server:

```bash
node <repo>/packages/mcp-wrapper/dist/index.js doctor --config <repo>/examples/mcp-demo/actionproxy.mcp.yaml
```

When you intend to execute the configured local command, add `--discover` to
perform only MCP `initialize` and `tools/list`, then close it. Both modes list
what remains unverified; neither contacts the ActionProxy HTTP endpoint.

Discovery still executes the configured child commands with the current OS
privileges. It is not sandboxed, and a child can act during startup without a
`tools/call`; use it only for reviewed configurations in a suitable isolation
boundary.

Doctor's `configured_mcp_wrapper` coverage does not prove the real host has only
this entry. It also cannot verify or disable host-native/provider-hosted tools,
direct network or shell access, unmediated credentials, conversation identity,
ActionProxy server policy, or prompt-injection behavior. Review those host
capabilities separately.

The committed single-entry templates are
[codex.config.toml.example](./codex.config.toml.example),
[claude.mcp.json.example](./claude.mcp.json.example), and
[generic.mcp.json.example](./generic.mcp.json.example). Replace `<repo>` with
this checkout's absolute path, or use the printer below.

## Codex

Use the printed Codex command to add ActionProxy as a local stdio MCP server in Codex. It has this shape:

```bash
codex mcp add actionproxy-demo -- node <repo>/packages/mcp-wrapper/dist/index.js wrap --config <repo>/examples/mcp-demo/actionproxy.mcp.yaml
```

After adding the server, open Codex and use `/mcp` to confirm `actionproxy-demo` is active. Then ask Codex to list or call the demo tools from that MCP server.

Optional `config.toml` form:

```toml
[mcp_servers."actionproxy-demo"]
command = "node"
args = ["<repo>/packages/mcp-wrapper/dist/index.js", "wrap", "--config", "<repo>/examples/mcp-demo/actionproxy.mcp.yaml"]
```

This is the same relationship as the CLI command: Codex uses ActionProxy as an MCP server. Use a project-scoped `.codex/config.toml` only in a trusted checkout. Use your global Codex config for a personal setup.

Keep `actionproxy-demo` as the single entry for this tool plane. Do not also
register `examples/mcp-demo/server.mjs` directly: a direct entry bypasses
ActionProxy policy, approval, outcome reporting, and audit.

## Claude Code

Use the printed Claude Code command to add ActionProxy as a local stdio MCP server in Claude Code. It has this shape:

```bash
claude mcp add --transport stdio actionproxy-demo -- node <repo>/packages/mcp-wrapper/dist/index.js wrap --config <repo>/examples/mcp-demo/actionproxy.mcp.yaml
```

Then run Claude Code in this project and use `/mcp` to confirm `actionproxy-demo` is connected. If Claude Code marks the project MCP server as pending, approve it from the interactive Claude Code session before trying the tools.

Optional `.mcp.json` form:

```json
{
  "mcpServers": {
    "actionproxy-demo": {
      "type": "stdio",
      "command": "node",
      "args": [
        "<repo>/packages/mcp-wrapper/dist/index.js",
        "wrap",
        "--config",
        "<repo>/examples/mcp-demo/actionproxy.mcp.yaml"
      ]
    }
  }
}
```

This is the same relationship as the CLI command: Claude Code uses ActionProxy as an MCP server. Do not commit user-specific `.mcp.json` files with absolute paths unless your team intentionally wants project-shared MCP setup.

The same single-entry rule applies: the host starts the ActionProxy wrapper,
and only the wrapper starts the downstream demo server.

## Generic Stdio MCP Host

For Cursor, Windsurf, IDE extensions, or other MCP hosts, add ActionProxy as a stdio MCP server with this process:

```text
command: node
args: ["<repo>/packages/mcp-wrapper/dist/index.js", "wrap", "--config", "<repo>/examples/mcp-demo/actionproxy.mcp.yaml"]
```

Exact UI steps differ by host. The relationship stays the same: the host uses ActionProxy as an MCP server, the wrapper submits each tool call to ActionProxy, and only grant-authorized calls reach the downstream demo MCP server.

For source-aware policy, ActionProxy treats the wrapper process as one verified
transport influence scope. Classified model-visible results are exposure-
recorded before release and later guarded actions can be narrowed. The scope may
span several chats, and a restart does not prove the model forgot prior data.
This limits consequences after hostile content; it does not prevent prompt
injection or inspect content.

## Try The Demo

Once Codex, Claude Code, or another host is using ActionProxy as `actionproxy-demo`:

1. Ask the host to list tools from `actionproxy-demo`.
2. Ask it to call `docs.search` with a query like `refund policy`.
3. Ask it to call `gmail.send_email` with demo values:

```json
{
  "to": "customer@example.com",
  "subject": "Refund update",
  "body": "Your request is ready."
}
```

4. Open `http://127.0.0.1:5173/#/approvals` and approve the pending email action.
5. Confirm the host receives the downstream MCP result.
6. Open the audit view and confirm the lifecycle events.

For a no-host automated smoke test, run:

```bash
corepack pnpm demo:mcp
```

For the same flow with manual approval through the web UI, run:

```bash
corepack pnpm demo:mcp:manual
```
