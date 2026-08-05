# ActionProxy JS SDK

Tiny TypeScript client for routing agent tool-call proposals and external-runner grant checks through a local ActionProxy gateway.

ActionProxy is proxy-first for production-shaped integrations. The SDK submits proposed tool calls, checks status, lists pending approvals, polls until a tool call reaches a terminal state, consumes one-time execution grants before an external runner calls a downstream tool, reports outcomes, and works with governed remediation plans when supported.


## Install

The SDK is independently packable from a reviewed ActionProxy source checkout.
Before installing by package name, verify the exact `0.1.0` registry record and
its repository metadata. To evaluate from source or pin the reviewed artifact,
create a local tarball:

```sh
corepack pnpm install --frozen-lockfile
corepack pnpm --filter @actionproxy/sdk-js pack \
  --out /absolute/path/to/your-app/vendor/actionproxy-sdk-js-0.1.0.tgz
```

Then install that exact tarball from the consumer repository:

```sh
corepack pnpm add ./vendor/actionproxy-sdk-js-0.1.0.tgz
```

For local workspace development, run the gateway first:

```sh
corepack pnpm dev
```

## Basic Usage

```ts
import { ActionProxyClient, gatedTool } from '@actionproxy/sdk-js';

type EmailInput = {
  to: string;
  subject: string;
  body: string;
};

const actionProxy = new ActionProxyClient({
  baseUrl: 'http://localhost:8787',
});

const sendEmail = gatedTool<EmailInput>({
  client: actionProxy,
  toolName: 'gmail.send_email',
  agentId: 'demo-agent',
  requestedBy: 'dev@example.com',
  reason: (input) => `Send customer email to ${input.to}`,
  metadata: { actionproxyExecution: 'external' },
});

const result = await sendEmail({
  to: 'customer@example.com',
  subject: 'Update',
  body: 'Thanks for contacting support.',
});

if (result.status === 'pending_approval') {
  console.log(`Waiting for approval ${result.approval?.id}`);
}
```

## Client Methods

```ts
const client = new ActionProxyClient({
  baseUrl: 'http://localhost:8787',
});

const submitted = await client.submitToolCall({
  toolName: 'docs.search',
  input: { query: 'refund policy' },
  requestedBy: 'dev@example.com',
  agentId: 'support-agent',
  reason: 'Find policy context',
  metadata: { actionproxyExecution: 'external' },
}, {
  idempotencyKey: 'support-run-123:docs-search',
});

const latest = await client.getToolCall(submitted.id);
const recent = await client.listToolCalls({ limit: 20, status: 'pending_approval' });
const pending = await client.listPendingApprovals();
const decisionTrace = await client.getDecisionTrace(submitted.id);
const attempts = await client.listExecutionAttempts(submitted.id);
const remediationPlan = await client.getRemediationPlan(submitted.id);

console.log(latest.status, decisionTrace.decisionV1?.reasonCodes, attempts.length, recent.length, pending.length);
```

`idempotencyKey` is sent only as the `Idempotency-Key` header. The SDK never embeds it in the action body and never generates a key automatically. Reuse a key only for retries of the exact same logical action; the server scopes it to authenticated tenant state, returns the stored action for an exact replay, and rejects another payload as a conflict.

## External Runner Grant Consumption

External runners should submit with `metadata.actionproxyExecution = "external"`, wait for an authorized terminal state, consume the returned grant, and only then call the downstream tool they already own.

```ts
const submitted = await client.submitToolCall({
  toolName: 'gmail.send_email',
  input: {
    to: 'customer@example.com',
    subject: 'Refund update',
    body: 'Your request is ready to send.',
  },
  requestedBy: 'support-agent@example.com',
  agentId: 'support-agent',
  reason: 'Send customer response',
  metadata: { actionproxyExecution: 'external' },
});

const finalToolCall =
  submitted.status === 'pending_approval'
    ? await client.waitForToolCall(submitted.id, { intervalMs: 1000, timeoutMs: 120_000 })
    : submitted.toolCall;

if (finalToolCall.status !== 'authorized') {
  throw new Error(`ActionProxy did not authorize execution: ${finalToolCall.status}`);
}

const result = finalToolCall.result as { grant?: { id: string; policyVersionHash?: string } };
if (!result.grant) {
  throw new Error('ActionProxy did not return an execution grant.');
}

await client.consumeExecutionGrant(result.grant.id, {
  input: finalToolCall.input,
  policyVersionHash: result.grant.policyVersionHash,
  toolCallId: finalToolCall.id,
  toolName: finalToolCall.toolName,
});

await existingEmailService.send(finalToolCall.input);

await client.reportExecutionGrantOutcome(result.grant.id, {
  status: 'succeeded',
  result: { messageId: 'msg_123' },
  remediation: {
    kind: 'compensating_action',
    status: 'available',
    reason: 'Send a follow-up correction email if the original message needs remediation.',
    toolName: 'gmail.send_email',
    input: {
      to: finalToolCall.input.to,
      subject: 'Correction',
      body: 'Please disregard the previous message.',
    },
  },
});
```

For the same flow with less boilerplate, use `runExternalAction`:

```ts
import { ActionProxyClient, runExternalAction } from '@actionproxy/sdk-js';

const client = new ActionProxyClient({ baseUrl: 'http://localhost:8787' });

const result = await runExternalAction({
  client,
  toolName: 'gmail.send_email',
  input: {
    to: 'customer@example.com',
    subject: 'Refund update',
    body: 'Your request is ready to send.',
  },
  requestedBy: 'support-agent@example.com',
  agentId: 'support-agent',
  idempotencyKey: 'support-run-123:customer-email',
  reason: 'Send customer response',
  execute: async (approvedInput) => existingEmailService.send(approvedInput),
});

console.log(result.toolCall.status, result.result);
```

The helper does not call `execute` if ActionProxy blocks/rejects the action or if grant consumption fails because of replay, expiry, policy mismatch, or payload hash mismatch.

The helper does not retry downstream execution. `timed_out` and `unknown_outcome` reports remain non-retryable server evidence that requires reconciliation; a same-key submission replay does not create another attempt.

## Governed Remediation

Remediation is a linked follow-up action, not a privileged undo. If a successful outcome includes an available remediation descriptor, the SDK can fetch and submit it through normal ActionProxy policy and approval handling.

```ts
const plan = await client.getRemediationPlan('toolcall_123');

if (plan.remediation.status === 'available') {
  const submittedRemediation = await client.submitRemediation('toolcall_123');
  console.log(submittedRemediation.status, submittedRemediation.approval?.id);
}
```

## Polling

```ts
const submitted = await client.submitToolCall({
  toolName: 'gmail.send_email',
  input: {
    to: 'customer@example.com',
    subject: 'Refund update',
    body: 'Your request is being reviewed.',
  },
  requestedBy: 'dev@example.com',
  agentId: 'support-agent',
  reason: 'Send approved customer follow-up',
});

const finalToolCall = await client.waitForToolCall(submitted.id, {
  intervalMs: 1000,
  timeoutMs: 60_000,
});

console.log(finalToolCall.status, finalToolCall.result);
```

## Simple Agent Loop

```ts
import { ActionProxyClient, gatedTool } from '@actionproxy/sdk-js';

const client = new ActionProxyClient({ baseUrl: 'http://localhost:8787' });

const tools = {
  searchDocs: gatedTool({
    client,
    toolName: 'docs.search',
    requestedBy: 'demo-agent@example.com',
    agentId: 'customer-support-demo-agent',
    reason: 'Find support policy context',
    metadata: { actionproxyExecution: 'external', demo: 'customer-support-agent' },
  }),
  sendEmail: gatedTool({
    client,
    toolName: 'gmail.send_email',
    requestedBy: 'demo-agent@example.com',
    agentId: 'customer-support-demo-agent',
    reason: 'Send customer response drafted by the support agent',
    metadata: { actionproxyExecution: 'external', demo: 'customer-support-agent' },
  }),
};

for (const step of [
  () => tools.searchDocs({ query: 'refund policy for delayed shipment' }),
  () =>
    tools.sendEmail({
      to: 'customer@example.com',
      subject: 'Refund policy update',
      body: 'Your delayed shipment qualifies for review.',
    }),
]) {
  const result = await step();

  if (result.status === 'pending_approval') {
    console.log(`Approval required: ${result.approval?.id}`);
  } else {
    console.log(`${result.toolCall.toolName}: ${result.status}`);
  }
}
```

## Notes

- The HTTP server, not the SDK, derives tenant/workspace, actor, source protocol, and environment; evaluates policy; creates canonical hashes and decisions; owns approval and attempt state; and creates/consumes the opaque executor authorization. `requestedBy`, `agentId`, metadata, and action hints remain caller assertions.
- The SDK exports read-only TypeScript projections for canonical request evidence, decision v1, approval authorization, execution attempts, and minimized executor-authorization evidence. It exports no canonicalizer, hash builder, authorization token/issuer, credential field, or automatic recovery API.
- `execute` may be passed to `gatedTool` to preserve a future agent-side execution shape, but `gatedTool` does not call it.
- Unknown tools still require approval by default.
- Destructive demo tools are denied by policy.

## Support and Security

For usage questions and confirmed non-sensitive defects, use
[GitHub Issues](https://github.com/ActionProxy/actionproxy/issues). For a
suspected vulnerability, follow the
[ActionProxy security policy](https://github.com/ActionProxy/actionproxy/security/policy)
and do not disclose credentials, exploit details, or other sensitive evidence
in a public issue.
