#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const manualApproval = process.argv.includes('--manual-approval');
const configuredBaseUrl = process.env.ACTIONPROXY_BASE_URL;
const baseUrl = normalizeLoopbackApiUrl(configuredBaseUrl ?? 'http://127.0.0.1:8787');
const approvalUrl = normalizeLoopbackBrowserUrl(
  process.env.ACTIONPROXY_APPROVAL_URL ??
    (configuredBaseUrl ? `${baseUrl}/app#/approvals` : 'http://127.0.0.1:5173/#/approvals'),
);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const wrapperPath = path.join(repoRoot, 'packages/mcp-wrapper/dist/index.js');
const configPath = path.join(repoRoot, 'examples/mcp-demo/actionproxy.mcp.yaml');
const startedAt = Date.now();

async function main() {
  await assertActionProxyReady();
  assertWrapperBuilt();

  console.log(`ActionProxy: ${baseUrl}`);
  console.log('Starting ActionProxy MCP wrapper...');

  const wrapper = spawn(wrapperPath, ['wrap', '--config', configPath], {
    cwd: repoRoot,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  wrapper.stderr.on('data', (chunk) => process.stderr.write(String(chunk)));

  const peer = new JsonRpcPeer(wrapper.stdout, wrapper.stdin);
  peer.start();

  try {
    await peer.request('initialize', {
      capabilities: {},
      clientInfo: { name: 'actionproxy-mcp-smoke-test', version: '0.1.0' },
      protocolVersion: '2025-06-18',
    });
    peer.notify('notifications/initialized', {});

    const listed = await peer.request('tools/list', {});
    const toolNames = (listed.tools ?? []).map((tool) => tool.name).sort();
    const expectedToolNames = ['dangerous.delete_customer', 'docs.search', 'gmail.send_email'];
    if (JSON.stringify(toolNames) !== JSON.stringify(expectedToolNames)) {
      throw new Error(`Unexpected MCP tools: ${toolNames.join(', ')}`);
    }
    console.log(`Tools: ${toolNames.join(', ')}`);

    console.log('\nCalling docs.search through MCP wrapper...');
    const docsResult = await peer.request('tools/call', {
      arguments: { query: 'refund policy' },
      name: 'docs.search',
    });
    printToolResult('docs.search', docsResult);

    console.log('\nCalling gmail.send_email through MCP wrapper...');
    const emailCall = peer.request(
      'tools/call',
      {
        arguments: {
          body: 'Your request is ready.',
          subject: 'Refund update',
          to: 'customer@example.com',
        },
        name: 'gmail.send_email',
      },
      130_000,
    );

    const pending = await waitForMcpEmailApproval();
    console.log(`Pending approval: ${pending.approval.id}`);

    const auditBeforeApproval = await getJson('/v1/audit?limit=100');
    assertNoExecutionBeforeApproval(auditBeforeApproval.events, pending.toolCall.id);

    if (manualApproval) {
      console.log(`Open ${approvalUrl} and approve ${pending.approval.id}.`);
      console.log('Waiting for manual approval...');
    } else {
      await approve(pending.approval.id);
      console.log(`Auto-approved ${pending.approval.id}.`);
    }

    const emailResult = await emailCall;
    printToolResult('gmail.send_email', emailResult);

    console.log('\nCalling dangerous.delete_customer through MCP wrapper...');
    const deleteResult = await peer.request('tools/call', {
      arguments: { customerId: 'cus_123' },
      name: 'dangerous.delete_customer',
    });
    if (deleteResult.isError !== true) {
      throw new Error('dangerous.delete_customer was expected to be denied by ActionProxy.');
    }
    printToolResult('dangerous.delete_customer', deleteResult);

    const audit = await getJson('/v1/audit?limit=160');
    const grantEvents = audit.events.filter((event) =>
      event.toolCallId === pending.toolCall.id && ['execution_grant.created', 'execution_grant.consumed'].includes(event.type),
    );
    if (grantEvents.filter((event) => event.type === 'execution_grant.created').length !== 1) {
      throw new Error('Expected exactly one email execution grant.');
    }
    if (grantEvents.filter((event) => event.type === 'execution_grant.consumed').length !== 1) {
      throw new Error('Expected exactly one consumed email execution grant.');
    }
    const docsCall = findRecentMcpToolCall(audit.events, 'docs.search');
    const deleteCall = findRecentMcpToolCall(audit.events, 'dangerous.delete_customer');
    assertAuditEvidence(audit.events, docsCall.id, [
      'tool_call.submitted',
      'policy.allow',
      'execution_grant.created',
      'execution_grant.consumed',
      'execution.attempt_dispatched',
      'tool_call.executed',
    ]);
    assertAuditEvidence(audit.events, pending.toolCall.id, [
      'tool_call.submitted',
      'policy.require_approval',
      'approval.created',
      'approval.approved',
      'execution_grant.created',
      'execution_grant.consumed',
      'execution.attempt_dispatched',
      'tool_call.executed',
    ]);
    assertExactlyOneExecution(audit.events, pending.toolCall.id);
    assertDeniedWithoutDispatch(audit.events, deleteCall.id);
    console.log(`\nGrant audit events for ${pending.toolCall.id}: ${grantEvents.map((event) => event.type).join(', ')}`);
    console.log(`Denied without dispatch: ${deleteCall.id}`);
    console.log('\nMCP proxy demo passed.');
  } finally {
    wrapper.kill();
  }
}

async function assertActionProxyReady() {
  try {
    const health = await getJson('/health');
    if (!health.ok) throw new Error('Health response was not ok.');
  } catch (error) {
    throw new Error(`ActionProxy is not reachable at ${baseUrl}. Start it in another terminal with: pnpm dev:proxy`);
  }
}

function assertWrapperBuilt() {
  if (fs.existsSync(wrapperPath)) return;
  throw new Error('MCP wrapper is not built. Run: corepack pnpm --filter @actionproxy/mcp-wrapper build');
}

async function waitForMcpEmailApproval() {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const [{ approvals }, { toolCalls }] = await Promise.all([
      getJson('/v1/approvals/pending'),
      getJson('/v1/tool-calls?limit=100&status=pending_approval&toolName=gmail.send_email'),
    ]);
    const toolCall = toolCalls.find(
      (candidate) =>
        Date.parse(candidate.createdAt) >= startedAt - 1000 &&
        candidate.metadata?.source === 'mcp-wrapper' &&
        candidate.metadata?.mcpTool === 'gmail.send_email',
    );
    const approval = toolCall ? approvals.find((candidate) => candidate.toolCallId === toolCall.id) : undefined;
    if (approval && toolCall) return { approval, toolCall };
    await sleep(250);
  }
  throw new Error('Timed out waiting for gmail.send_email approval.');
}

async function approve(approvalId) {
  const response = await fetch(`${baseUrl}/v1/approvals/${encodeURIComponent(approvalId)}/approve`, {
    body: JSON.stringify({ approvedBy: 'mcp-demo-manager@example.com', note: 'Approved by MCP smoke test.' }),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  });
  if (!response.ok) {
    throw new Error(`Approval failed: ${response.status} ${await response.text()}`);
  }
}

async function getJson(pathname) {
  const response = await fetch(`${baseUrl}${pathname}`);
  if (!response.ok) throw new Error(`${pathname} failed: ${response.status} ${await response.text()}`);
  return response.json();
}

function printToolResult(toolName, result) {
  const texts = (result.content ?? []).map((item) => (typeof item.text === 'string' ? item.text : JSON.stringify(item)));
  console.log(`${toolName} result: ${texts.join('\n')}`);
}

function assertNoExecutionBeforeApproval(events, toolCallId) {
  const forbidden = new Set([
    'execution_grant.created',
    'execution_grant.consumed',
    'execution.attempt_dispatched',
    'execution.attempt_completed',
  ]);
  const earlyExecution = events.find((event) => event.toolCallId === toolCallId && forbidden.has(event.type));
  if (earlyExecution) throw new Error(`Email execution began before approval: ${earlyExecution.type}`);
}

function findRecentMcpToolCall(events, toolName) {
  const submitted = events.find(
    (event) =>
      event.type === 'tool_call.submitted' &&
      Date.parse(event.timestamp) >= startedAt - 1000 &&
      event.data?.reason === `MCP tool call ${toolName} from server demo` &&
      event.data?.toolName === toolName,
  );
  if (!submitted?.toolCallId) throw new Error(`No ActionProxy audit proposal found for ${toolName}.`);
  return { id: submitted.toolCallId };
}

function assertAuditEvidence(events, toolCallId, requiredTypes) {
  const observed = new Set(events.filter((event) => event.toolCallId === toolCallId).map((event) => event.type));
  const missing = requiredTypes.filter((type) => !observed.has(type));
  if (missing.length) throw new Error(`Missing audit evidence for ${toolCallId}: ${missing.join(', ')}`);
}

function assertDeniedWithoutDispatch(events, toolCallId) {
  const callEvents = events.filter((event) => event.toolCallId === toolCallId);
  if (!callEvents.some((event) => event.type === 'policy.deny')) {
    throw new Error('Delete call did not record a policy.deny event.');
  }
  const forbidden = callEvents.find(
    (event) =>
      event.type.startsWith('execution_grant.') ||
      event.type.startsWith('execution.attempt_') ||
      event.type === 'tool_call.executed',
  );
  if (forbidden) throw new Error(`Denied delete unexpectedly reached execution: ${forbidden.type}`);
}

function assertExactlyOneExecution(events, toolCallId) {
  const callEvents = events.filter((event) => event.toolCallId === toolCallId);
  for (const type of [
    'execution_grant.created',
    'execution_grant.consumed',
    'execution.attempt_dispatched',
    'execution.attempt_completed',
    'tool_call.executed',
  ]) {
    const count = callEvents.filter((event) => event.type === type).length;
    if (count !== 1) {
      throw new Error(`Expected exactly one ${type} event for ${toolCallId}; observed ${count}.`);
    }
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeLoopbackApiUrl(value) {
  const url = normalizeLoopbackUrl(value, 'ACTIONPROXY_BASE_URL');
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new Error('ACTIONPROXY_BASE_URL must be a loopback HTTP origin without a path, query, or fragment.');
  }
  return url.origin;
}

function normalizeLoopbackBrowserUrl(value) {
  const url = normalizeLoopbackUrl(value, 'ACTIONPROXY_APPROVAL_URL');
  return url.toString();
}

function normalizeLoopbackUrl(value, name) {
  const url = new URL(value);
  if (
    url.protocol !== 'http:' ||
    !['127.0.0.1', 'localhost'].includes(url.hostname) ||
    url.username ||
    url.password
  ) {
    throw new Error(`${name} must use loopback HTTP without credentials.`);
  }
  return url;
}

class JsonRpcPeer {
  constructor(input, output) {
    this.input = input;
    this.output = output;
    this.framer = new JsonRpcFramer();
    this.nextId = 1;
    this.pending = new Map();
  }

  start() {
    this.input.on('data', (chunk) => {
      for (const message of this.framer.push(Buffer.from(chunk))) {
        if (message.id === undefined || message.id === null || message.method) continue;
        const pending = this.pending.get(message.id);
        if (!pending) continue;
        this.pending.delete(message.id);
        clearTimeout(pending.timeout);
        if (message.error) pending.reject(new Error(JSON.stringify(message.error)));
        else pending.resolve(message.result);
      }
    });
  }

  notify(method, params) {
    this.output.write(encodeJsonRpcMessage({ jsonrpc: '2.0', method, params }));
  }

  request(method, params, timeoutMs = 30_000) {
    const id = this.nextId++;
    this.output.write(encodeJsonRpcMessage({ id, jsonrpc: '2.0', method, params }));

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out waiting for MCP response to ${method}.`));
      }, timeoutMs);
      this.pending.set(id, { reject, resolve, timeout });
    });
  }
}

class JsonRpcFramer {
  constructor() {
    this.buffer = Buffer.alloc(0);
  }

  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const messages = [];

    while (true) {
      const headerEnd = this.buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return messages;

      const header = this.buffer.subarray(0, headerEnd).toString('utf8');
      const match = header.match(/content-length:\s*(\d+)/i);
      if (!match) throw new Error('Invalid JSON-RPC frame: missing Content-Length.');

      const length = Number(match[1]);
      const bodyStart = headerEnd + 4;
      const bodyEnd = bodyStart + length;
      if (this.buffer.length < bodyEnd) return messages;

      messages.push(JSON.parse(this.buffer.subarray(bodyStart, bodyEnd).toString('utf8')));
      this.buffer = this.buffer.subarray(bodyEnd);
    }
  }
}

function encodeJsonRpcMessage(message) {
  const body = JSON.stringify(message);
  return `Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`;
}

await main();
