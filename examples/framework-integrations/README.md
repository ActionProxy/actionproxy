# Framework Integration Examples

These examples use ActionProxy as an authorization proxy, not as a connector runtime.

The shared pattern is:

```text
framework tool call
  -> ActionProxy POST /v1/tool-calls with metadata.actionproxyExecution = "external"
  -> approval if policy requires it
  -> one-time execution grant
  -> external runner consumes the grant
  -> existing MCP server, internal API, or connector performs the real work
```

Start ActionProxy in proxy-first mode:

```bash
corepack pnpm dev:proxy
```

Use local mock execution only for the curl and guided browser demos.

## Shared Proxy Runner

`proxy-runner.ts` contains the reusable grant-consuming flow:

```ts
import { ActionProxyClient } from '@actionproxy/sdk-js';
import { authorizeAndRunExternalTool } from './proxy-runner';

const client = new ActionProxyClient({ baseUrl: 'http://localhost:8787' });

await authorizeAndRunExternalTool({
  agentId: 'support-agent',
  client,
  requestedBy: 'agent@example.com',
  toolName: 'gmail.send_email',
  reason: 'Send customer response',
  input: {
    to: 'customer@example.com',
    subject: 'Refund update',
    body: 'Your request is ready to send.',
  },
  execute: async (approvedInput) => {
    return existingOrgEmailService.send(approvedInput);
  },
});
```

The `execute` function is intentionally outside ActionProxy. In a real org this can be an MCP server call, internal API, connector platform, queue worker, or existing service.

## LangGraph

Use ActionProxy at the LangGraph tool boundary. Let LangGraph manage graph state and resumes, while ActionProxy owns policy, approval, grants, and audit.

```ts
const sendEmailTool = tool(
  async (input) =>
    authorizeAndRunExternalTool({
      agentId: 'langgraph-support-agent',
      client: actionProxy,
      requestedBy: 'langgraph@example.com',
      toolName: 'gmail.send_email',
      reason: 'LangGraph customer-support action',
      input,
      execute: (approvedInput) => downstreamMcp.callTool('gmail.send_email', approvedInput),
    }),
  {
    name: 'gmail.send_email',
    description: 'Send a customer email after ActionProxy authorization.',
    schema: emailSchema,
  },
);
```

If the graph also uses LangGraph `interrupt()` for human review, keep that review as UX/state orchestration. The enforcement point remains the ActionProxy grant consumption before downstream execution.

## Mastra

Use ActionProxy inside a Mastra tool or workflow step. Mastra controls the workflow lifecycle; ActionProxy controls whether the downstream side effect may happen.

```ts
export const sendEmail = createTool({
  id: 'gmail.send_email',
  description: 'Send email through an existing downstream runner.',
  inputSchema: emailSchema,
  execute: async ({ context }) =>
    authorizeAndRunExternalTool({
      agentId: 'mastra-support-agent',
      client: actionProxy,
      requestedBy: 'mastra@example.com',
      toolName: 'gmail.send_email',
      reason: 'Mastra workflow email step',
      input: context,
      execute: (approvedInput) => downstreamMcp.callTool('gmail.send_email', approvedInput),
    }),
});
```

Mastra `suspend()` / `resume()` can still be used for workflow UX. Do not use Mastra as the only enforcement layer for external side effects; consume the ActionProxy grant before the downstream call.

## Vercel AI SDK

Use ActionProxy inside the AI SDK tool `execute` function, or pair AI SDK tool approval UI with ActionProxy's grant-backed authorization.

```ts
const sendEmail = tool({
  description: 'Send a customer email after ActionProxy authorization.',
  inputSchema: emailSchema,
  execute: async (input) =>
    authorizeAndRunExternalTool({
      agentId: 'vercel-ai-sdk-agent',
      client: actionProxy,
      requestedBy: 'ai-sdk@example.com',
      toolName: 'gmail.send_email',
      reason: 'AI SDK tool call',
      input,
      execute: (approvedInput) => downstreamMcp.callTool('gmail.send_email', approvedInput),
    }),
});
```

If using AI SDK `needsApproval`, treat that as product UX. ActionProxy still provides the shared policy/audit record and the one-time grant consumed by the runner.

## OpenAI Agents SDK

Use ActionProxy inside an Agents SDK function tool. The Agents SDK can ask for tool approval; ActionProxy remains the system of record for policy and replay-resistant execution.

```ts
const sendEmail = tool({
  name: 'gmail.send_email',
  description: 'Send customer email through an existing runner.',
  parameters: emailSchema,
  execute: async (input) =>
    authorizeAndRunExternalTool({
      agentId: 'openai-agents-sdk-agent',
      client: actionProxy,
      requestedBy: 'agents-sdk@example.com',
      toolName: 'gmail.send_email',
      reason: 'Agents SDK function tool call',
      input,
      execute: (approvedInput) => downstreamMcp.callTool('gmail.send_email', approvedInput),
    }),
});
```

## MCP Wrapper

Prefer MCP when the organization already has tools exposed as MCP servers:

```bash
./packages/mcp-wrapper/dist/index.js wrap --config examples/mcp-demo/actionproxy.mcp.yaml
```

The wrapper acts as the local MCP server that Codex or another MCP host starts. It reads downstream tools, submits every `tools/call` to ActionProxy as external execution, consumes the returned grant, and only then forwards to the downstream MCP server. This is the canonical proxy-first integration path for Codex and other MCP hosts.

For copy-paste-ready commands that configure Codex, Claude Code, or another host to use ActionProxy as an MCP server, see `examples/mcp-hosts/README.md` or run:

```bash
corepack pnpm demo:mcp:hosts
```
