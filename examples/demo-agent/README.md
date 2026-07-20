# Demo agent

This is a deterministic local customer-support demo agent. It does not call an LLM, Gmail, Salesforce, Jira, Slack, or any real external service. It only proposes tool calls to the local ActionProxy server so the gateway can allow, queue, or block them.

## Run

Start the ActionProxy server:

```bash
corepack pnpm dev
```

Start the dashboard in another terminal:

```bash
corepack pnpm dev:web
```

Run the demo agent:

```bash
node examples/demo-agent/demo-agent.mjs
```

The script submits three proposed actions:

1. `docs.search`, which executes immediately in mock mode.
2. `gmail.send_email`, which creates a pending approval.
3. `dangerous.delete_customer`, which is blocked by policy.

Use the dashboard at `http://127.0.0.1:5173` to approve or reject the pending email, inspect recent tool calls, and watch the audit timeline.

## Override server URL

```bash
ACTIONPROXY_BASE_URL=http://127.0.0.1:8787 node examples/demo-agent/demo-agent.mjs
```
