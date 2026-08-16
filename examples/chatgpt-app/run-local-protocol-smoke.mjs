#!/usr/bin/env node

import { createSign, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const serverDir = path.join(repoRoot, 'apps/server');
const serverEntry = path.join(serverDir, 'dist/index.js');
const protocolVersion = '2025-06-18';
const proposedProtocolVersion = '2025-11-25';
const origin = 'https://chatgpt.com';

if (!existsSync(serverEntry)) {
  fail('The server build is missing. Run: corepack pnpm --filter @actionproxy/server build');
}

const port = await freePort();
const baseUrl = `http://127.0.0.1:${port}`;
const resourceUrl = `${baseUrl}/mcp`;
const issuer = `${baseUrl}/demo-authorization-server`;
const apiAudience = `${baseUrl}/api`;
const dataDir = mkdtempSync(path.join(tmpdir(), 'actionproxy-chatgpt-smoke-'));
const bootstrapToken = `bootstrap_${randomBytes(32).toString('base64url')}`;
const keyId = `demo-${randomBytes(8).toString('hex')}`;
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = { ...publicKey.export({ format: 'jwk' }), alg: 'RS256', kid: keyId, use: 'sig' };
const accessToken = signJwt({
  aud: resourceUrl,
  client_id: 'chatgpt-local-smoke',
  email: 'chatgpt-user@example.com',
  exp: Math.floor(Date.now() / 1000) + 300,
  iat: Math.floor(Date.now() / 1000),
  iss: issuer,
  name: 'ChatGPT local smoke user',
  scope: 'tool_call:read tool_call:submit',
  sub: 'chatgpt-local-user',
});

const server = spawn(process.execPath, [serverEntry], {
  cwd: serverDir,
  env: {
    ...process.env,
    ACTIONPROXY_AUTH_MODE: 'oidc_jwt',
    ACTIONPROXY_BOOTSTRAP_ADMIN_API_KEY: bootstrapToken,
    ACTIONPROXY_DATA_DIR: dataDir,
    ACTIONPROXY_DEPLOYMENT_MODE: 'self_hosted',
    ACTIONPROXY_EXECUTION_GRANT_SECRET: randomBytes(32).toString('base64url'),
    ACTIONPROXY_HOST: '127.0.0.1',
    ACTIONPROXY_LOCAL_EXECUTION: 'mock',
    ACTIONPROXY_MCP_ALLOWED_ORIGINS: origin,
    ACTIONPROXY_MCP_AUTHORIZATION_SERVER: issuer,
    ACTIONPROXY_MCP_RESOURCE_URL: resourceUrl,
    ACTIONPROXY_MCP_SESSION_SECRET: randomBytes(32).toString('base64url'),
    ACTIONPROXY_MCP_STREAMABLE_HTTP_ENABLED: 'true',
    ACTIONPROXY_OIDC_AUDIENCE: apiAudience,
    ACTIONPROXY_OIDC_ISSUER: issuer,
    ACTIONPROXY_OIDC_JWKS_JSON: JSON.stringify({ keys: [publicJwk] }),
    ACTIONPROXY_PORT: String(port),
    ACTIONPROXY_STORAGE: 'memory',
    ACTIONPROXY_WORKSPACE_ID: 'chatgpt-local-smoke',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let serverOutput = '';
for (const stream of [server.stdout, server.stderr]) {
  stream.on('data', (chunk) => {
    serverOutput = `${serverOutput}${String(chunk)}`.slice(-32_000);
  });
}

try {
  await waitForHealth();
  await verifyDiscovery();
  await createDefaultApprover();

  const initialized = await initialize();
  assert(initialized.protocolVersion === protocolVersion, 'Server did not negotiate its supported MCP version.');

  const listed = await rpc(initialized.session, 'list-1', 'tools/list', {});
  const toolNames = listed.tools?.map((tool) => tool.name) ?? [];
  assert(
    JSON.stringify(toolNames) === JSON.stringify([
      'docs.search',
      'gmail.send_email',
      'dangerous.delete_customer',
      'actionproxy.get_action_status',
      'actionproxy.resume_approved_action',
    ]),
    `Unexpected tool list: ${toolNames.join(', ')}`,
  );
  console.log(`Tools: ${toolNames.join(', ')}`);

  const allowed = await callTool(initialized.session, 'allow-1', 'docs.search', { query: 'refund policy' });
  assert(toolStatus(allowed) === 'executed', 'docs.search did not execute.');
  console.log('PASS docs.search: allowed and executed once');

  const pending = await callTool(initialized.session, 'email-1', 'gmail.send_email', {
    body: 'Your request is ready.',
    subject: 'Refund update',
    to: 'customer@example.com',
  });
  assert(toolStatus(pending) === 'pending_approval', 'gmail.send_email did not pause for approval.');
  const action = pending.structuredContent?.actionproxy;
  const approvalId = action?.approval?.id;
  const toolCallId = action?.toolCallId;
  assert(typeof approvalId === 'string' && typeof toolCallId === 'string', 'Pending result omitted approval identifiers.');
  const beforeApproval = await auditFor(toolCallId);
  assert(!beforeApproval.some((event) => event.type === 'tool_call.executed'), 'Email executed before approval.');
  console.log('PASS gmail.send_email: pending with zero pre-approval execution');

  await operatorRequest(`/v1/approvals/${encodeURIComponent(approvalId)}/approve`, {
    body: JSON.stringify({ note: 'Approved by the local ChatGPT protocol smoke.' }),
    method: 'POST',
  });

  const status = await callTool(initialized.session, 'status-1', 'actionproxy.get_action_status', { toolCallId });
  assert(toolStatus(status) === 'executed', 'Approved email did not reach executed status.');
  await callTool(initialized.session, 'status-2', 'actionproxy.get_action_status', { toolCallId });
  const afterApproval = await auditFor(toolCallId);
  assert(afterApproval.filter((event) => event.type === 'approval.approved').length === 1, 'Approval was not recorded once.');
  assert(afterApproval.filter((event) => event.type === 'tool_call.executed').length === 1, 'Approved email did not execute exactly once.');
  console.log('PASS gmail.send_email: approved, executed once, and status reads did not redispatch');

  const denied = await callTool(initialized.session, 'deny-1', 'dangerous.delete_customer', {
    customerId: 'cus_123',
    reason: 'policy test',
  });
  assert(toolStatus(denied) === 'blocked' && denied.isError === true, 'Destructive demo was not denied.');
  const deniedId = denied.structuredContent?.actionproxy?.toolCallId;
  const deniedAudit = await auditFor(deniedId);
  assert(deniedAudit.some((event) => event.type === 'policy.deny'), 'Denied action has no policy.deny audit event.');
  assert(!deniedAudit.some((event) => event.type === 'tool_call.executed'), 'Denied action reached execution.');
  console.log('PASS dangerous.delete_customer: denied without execution');

  const verification = await operatorRequest('/v1/audit/verify');
  assert(verification.valid === true && verification.errors?.length === 0, 'Audit-chain verification failed.');
  console.log('PASS audit: lifecycle present and chain valid');
  console.log('Local ChatGPT-shaped MCP smoke passed. No ChatGPT or external identity provider was contacted.');
} catch (error) {
  if (serverOutput.trim()) console.error(`ActionProxy output:\n${serverOutput.trim()}`);
  throw error;
} finally {
  server.kill('SIGTERM');
  await Promise.race([onceExit(server), delay(2_000)]);
  if (server.exitCode === null) server.kill('SIGKILL');
  rmSync(dataDir, { force: true, recursive: true });
}

async function verifyDiscovery() {
  const metadataResponse = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);
  assert(metadataResponse.ok, 'Protected-resource metadata was unavailable.');
  const metadata = await metadataResponse.json();
  assert(metadata.resource === resourceUrl, 'Protected-resource metadata has the wrong resource.');
  assert(metadata.authorization_servers?.[0] === issuer, 'Protected-resource metadata has the wrong issuer.');
  assert(metadata.scopes_supported?.includes('tool_call:read'), 'Metadata omitted tool_call:read.');
  assert(metadata.scopes_supported?.includes('tool_call:submit'), 'Metadata omitted tool_call:submit.');

  const unauthorized = await fetch(resourceUrl, {
    body: JSON.stringify(initializeMessage('unauthorized')),
    headers: mcpHeaders(),
    method: 'POST',
  });
  assert(unauthorized.status === 401, 'Unauthenticated MCP request did not return 401.');
  assert(
    (unauthorized.headers.get('www-authenticate') ?? '').includes('resource_metadata='),
    'MCP 401 omitted protected-resource discovery.',
  );
  console.log('PASS discovery: metadata and OAuth challenge');
}

async function createDefaultApprover() {
  const created = await operatorRequest('/v1/approvers/users', {
    body: JSON.stringify({
      defaultApprover: true,
      displayName: 'Local ChatGPT demo reviewer',
      enabled: true,
      principalId: 'bootstrap-admin',
    }),
    method: 'POST',
  });
  assert(created.user?.principalId === 'bootstrap-admin', 'Default approver bootstrap failed.');
}

async function initialize() {
  const response = await fetch(resourceUrl, {
    body: JSON.stringify(initializeMessage('initialize-1')),
    headers: mcpHeaders(accessToken),
    method: 'POST',
  });
  if (!response.ok) fail(`MCP initialize failed: HTTP ${response.status} ${await response.text()}`);
  const body = await response.json();
  const session = response.headers.get('mcp-session-id');
  assert(typeof session === 'string' && session.length > 0, 'MCP initialize omitted its signed session.');
  assert(body.result?.protocolVersion === protocolVersion, 'MCP initialize returned the wrong protocol version.');
  return { protocolVersion: body.result.protocolVersion, session };
}

function initializeMessage(id) {
  return {
    id,
    jsonrpc: '2.0',
    method: 'initialize',
    params: {
      capabilities: {},
      clientInfo: { name: 'actionproxy-chatgpt-local-smoke', version: '0.1.1' },
      protocolVersion: proposedProtocolVersion,
    },
  };
}

async function callTool(session, id, name, args) {
  return rpc(session, id, 'tools/call', { arguments: args, name });
}

async function rpc(session, id, method, params) {
  const response = await fetch(resourceUrl, {
    body: JSON.stringify({ id, jsonrpc: '2.0', method, params }),
    headers: {
      ...mcpHeaders(accessToken),
      'mcp-protocol-version': protocolVersion,
      'mcp-session-id': session,
    },
    method: 'POST',
  });
  if (!response.ok) fail(`${method} failed: HTTP ${response.status} ${await response.text()}`);
  const body = await response.json();
  if (body.error) fail(`${method} returned JSON-RPC error: ${JSON.stringify(body.error)}`);
  return body.result;
}

function mcpHeaders(token) {
  return {
    accept: 'application/json, text/event-stream',
    ...(token ? { authorization: `Bearer ${token}` } : {}),
    'content-type': 'application/json',
    origin,
  };
}

async function auditFor(toolCallId) {
  assert(typeof toolCallId === 'string', 'Tool result omitted toolCallId.');
  const audit = await operatorRequest(`/v1/audit?limit=100&toolCallId=${encodeURIComponent(toolCallId)}`);
  return audit.events ?? [];
}

async function operatorRequest(pathname, init = {}) {
  const response = await fetch(`${baseUrl}${pathname}`, {
    ...init,
    headers: {
      authorization: `Bearer ${bootstrapToken}`,
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) fail(`${pathname} failed: HTTP ${response.status} ${await response.text()}`);
  return response.json();
}

function toolStatus(result) {
  return result?.structuredContent?.actionproxy?.status;
}

function signJwt(payload) {
  const header = { alg: 'RS256', kid: keyId, typ: 'JWT' };
  const signedValue = `${base64urlJson(header)}.${base64urlJson(payload)}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signedValue);
  signer.end();
  return `${signedValue}.${signer.sign(privateKey).toString('base64url')}`;
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

async function waitForHealth() {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (server.exitCode !== null) fail(`ActionProxy exited before becoming ready (exit ${server.exitCode}).`);
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return;
    } catch {
      // The loopback listener is still starting.
    }
    await delay(50);
  }
  fail('Timed out waiting for the local ActionProxy server.');
}

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      const selected = typeof address === 'object' && address ? address.port : undefined;
      probe.close((error) => (error ? reject(error) : resolve(selected)));
    });
  });
}

function onceExit(child) {
  if (child.exitCode !== null) return Promise.resolve();
  return new Promise((resolve) => child.once('exit', resolve));
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function fail(message) {
  throw new Error(message);
}
