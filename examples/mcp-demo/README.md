# MCP Demo

This folder contains a tiny downstream MCP server and wrapper configuration for
the complete local approval lifecycle.

The demo server exposes exactly three tools:

- `docs.search`: read-only
- `gmail.send_email`: sensitive demo action
- `dangerous.delete_customer`: destructive simulated action

ActionProxy policy still lives in the gateway server. The wrapper config documents intent, but the server YAML policy decides whether a tool is allowed, blocked, or approval-required.

## One-command smoke test

Start ActionProxy in proxy mode:

```bash
corepack pnpm dev:proxy
```

In another terminal, run the MCP smoke test:

```bash
corepack pnpm demo:mcp
```

This script acts as a tiny MCP host. It starts the ActionProxy MCP wrapper, verifies the three-tool catalog, runs `docs.search`, proves `gmail.send_email` has not executed before approval, approves it, and confirms `dangerous.delete_customer` is denied without a grant or downstream dispatch. Every downstream effect is simulated.

To approve through the web UI instead, keep the proxy-mode gateway running and
use two more terminals.

Terminal 2 — start the dashboard:

```bash
corepack pnpm dev:web
```

Terminal 3 — start the manual MCP proof:

```bash
corepack pnpm demo:mcp:manual
```

Open `http://127.0.0.1:5173/#/approvals` and approve the pending MCP email request.

## Run With A Real MCP Host

Build the wrapper:

```bash
corepack pnpm --filter @actionproxy/mcp-wrapper build
```

Run the wrapper as an MCP stdio server:

```bash
./packages/mcp-wrapper/dist/index.js wrap --config examples/mcp-demo/actionproxy.mcp.yaml
```

Connect an MCP host to that command. Tool calls made through the host are submitted to ActionProxy first:

- `docs.search` is authorized immediately, receives a one-time grant, and is then forwarded to the demo MCP server.
- `gmail.send_email` creates a pending ActionProxy approval. After approval, the wrapper forwards the tool call to the demo MCP server.
- `dangerous.delete_customer` is denied before the downstream MCP server is called.

The ActionProxy audit log records the MCP tool-call proposals because the
wrapper submits them through the authenticated `POST /v1/mcp/tool-calls`
adapter boundary.
