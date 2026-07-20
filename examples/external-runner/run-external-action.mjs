#!/usr/bin/env node

import { ActionProxyClient, runExternalAction } from '../../packages/sdk-js/dist/index.js';

const baseUrl = process.env.ACTIONPROXY_BASE_URL ?? 'http://127.0.0.1:8787';
const apiKey = process.env.ACTIONPROXY_API_KEY;

const client = new ActionProxyClient({
  baseUrl,
  ...(apiKey ? { apiKey } : {}),
});

console.log(`Submitting external action to ${baseUrl}`);
console.log('Approve the pending gmail.send_email action in the web UI when policy requires it.');

const result = await runExternalAction({
  action: {
    executionMode: 'external_grant',
    operation: { kind: 'external_send', name: 'fake_mailer.send' },
    protocol: 'custom',
    source: { name: 'external-runner-example', type: 'custom' },
  },
  agentId: 'external-runner-example',
  client,
  execute: async (input, context) => {
    console.log(`Consumed grant ${context.consumed.grant.id}; executing fake downstream call.`);
    await sleep(250);
    return {
      downstream: 'fake-mailer',
      messageId: `fake_${Date.now()}`,
      sentTo: input.to,
    };
  },
  input: {
    body: 'This was authorized through ActionProxy and executed by a fake external runner.',
    subject: 'ActionProxy external runner demo',
    to: 'customer@example.com',
  },
  metadata: {
    runner: 'examples/external-runner',
  },
  reason: 'Send a customer email through a fake downstream runner.',
  requestedBy: 'runner@example.com',
  toolName: 'gmail.send_email',
  wait: {
    intervalMs: 1000,
    timeoutMs: Number(process.env.ACTIONPROXY_EXTERNAL_RUNNER_TIMEOUT_MS ?? 120_000),
  },
});

console.log(JSON.stringify({
  finalStatus: result.toolCall.status,
  toolCallId: result.toolCall.id,
  outcome: result.result,
}, null, 2));

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
