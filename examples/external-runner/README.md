# External Runner Example

This example shows ActionProxy as the approval backend for a runner that owns downstream tool execution.

The script submits a `gmail.send_email` proposal, waits for ActionProxy to allow or approve it, consumes the one-time execution grant, runs a fake downstream mailer, and reports the outcome back to ActionProxy. No Gmail, MCP, or SaaS credentials are required.

Terminal 1 — start ActionProxy without local tool execution:

```bash
corepack pnpm dev:proxy
```

Terminal 2 — start the dashboard:

```bash
corepack pnpm dev:web
```

Terminal 3 — build the SDK, then start the external runner:

```bash
corepack pnpm --filter @actionproxy/sdk-js build
node examples/external-runner/run-external-action.mjs
```

Open `http://127.0.0.1:5173/#/approvals` and approve the pending email action. The runner then prints the fake downstream result. Inspect `#/authorized`, the tool-call detail page, and `#/audit` to verify the grant was consumed and the outcome was recorded.

The same pattern works beside MCP servers, internal APIs, LangGraph nodes, queues, or systems such as Agentgateway: ActionProxy decides and audits; the external runner keeps the real tool credentials and executes only after consuming a matching grant.
