#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const image = productEnv('ACTIONPROXY_DOCKER_IMAGE') ?? 'actionproxy:local';
const port = productEnv('ACTIONPROXY_DOCKER_SMOKE_PORT') ?? '18887';
const containerName =
  productEnv('ACTIONPROXY_DOCKER_SMOKE_CONTAINER') ?? `actionproxy-community-smoke-${process.pid}`;
const volumeName = `${containerName}-sqlite-data`;
const baseUrl = `http://127.0.0.1:${port}`;
const mcpSessionId = '550e8400-e29b-41d4-a716-446655440000';

const shouldBuild = productEnv('ACTIONPROXY_DOCKER_SKIP_BUILD') !== '1';
let containerStarted = false;
let volumeCreated = false;

try {
  if (shouldBuild) {
    run('docker', ['build', '-t', image, '.']);
  }

  await runMemorySmoke();
  await runSqlitePersistenceSmoke();

  console.log(`Community Docker memory and SQLite persistence smoke passed for ${image} on ${baseUrl}`);
} catch (error) {
  if (containerStarted) {
    console.error(`Community Docker smoke failed for ${image}; container logs follow.`);
    spawnSync('docker', ['logs', containerName], { stdio: 'inherit' });
  }
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  if (containerStarted) {
    cleanupContainer();
  }
  if (volumeCreated) {
    cleanupVolume();
  }
}

async function runMemorySmoke() {
  startContainer({ storage: 'memory' });
  await waitForHealth();
  await assertHealth();
  await assertCommunityBoundary();
  await assertWebApp();
  await assertRuntimeImageBoundary();
  await assertPackagedTunnelWrapper();
  await configureBrowserAccessibleEmailOutbox();
  await assertDemoLifecycle();
  stopContainer();
}

async function runSqlitePersistenceSmoke() {
  cleanupVolume();
  run('docker', ['volume', 'create', volumeName]);
  volumeCreated = true;
  startContainer({ storage: 'sqlite', volume: volumeName });
  await waitForHealth();
  await assertHealth();

  const email = await submitToolCall({
    agentId: 'docker-sqlite-smoke-agent',
    input: {
      body: 'Persist this approval across a container restart.',
      subject: 'SQLite persistence smoke',
      to: 'customer@example.com',
    },
    reason: 'Docker SQLite persistence action',
    toolName: 'gmail.send_email',
  });
  assert(email.status === 'pending_approval', 'SQLite smoke email should wait for approval');
  assert(email.approval?.id, 'SQLite smoke email should include an approval id');
  const approvalId = email.approval.id;
  const exposure = await recordPublicMcpExposure();
  const guardedBeforeRestart = await submitMcpToolCall(
    'docker-guarded-before-restart',
    'research.notes.append',
    { note: 'This must be reviewed after public content.' },
  );
  assert(
    guardedBeforeRestart.status === 'pending_approval' && guardedBeforeRestart.decision === 'require_approval',
    'A same-scope guarded action should require approval after public-untrusted content',
  );
  assert(
    guardedBeforeRestart.toolCall?.influenceScopeId === exposure.influenceScopeId,
    'The guarded action should use the verified scope that received public content',
  );
  assert(
    guardedBeforeRestart.toolCall?.contentInfluence?.observedSources?.includes('public_untrusted'),
    'The guarded action should cite public-untrusted influence before restart',
  );
  stopContainer();

  startContainer({ storage: 'sqlite', volume: volumeName });
  await waitForHealth();
  const pending = await getJson('/v1/approvals/pending');
  assert(
    pending.approvals?.some((approval) => approval.id === approvalId),
    'SQLite pending approval should survive a container restart against the same volume',
  );
  const audit = await getJson('/v1/audit');
  assert(
    audit.events?.some((event) => event.approvalId === approvalId && event.type === 'approval.created'),
    'SQLite approval audit state should survive a container restart',
  );
  const verification = await getJson('/v1/audit/verify');
  assert(
    verification.valid === true,
    `SQLite audit chain should remain valid after restart: ${JSON.stringify(verification.errors ?? [])}`,
  );
  const guardedAfterRestart = await submitMcpToolCall(
    'docker-guarded-after-restart',
    'research.notes.append',
    { note: 'Persisted public influence must still require review.' },
  );
  assert(
    guardedAfterRestart.status === 'pending_approval' && guardedAfterRestart.decision === 'require_approval',
    'Persisted public influence should narrow the same verified scope after restart',
  );
  assert(
    guardedAfterRestart.toolCall?.influenceScopeId === exposure.influenceScopeId,
    'The same wrapper session should derive the same verified influence scope after restart',
  );
  assert(
    guardedAfterRestart.toolCall?.contentInfluence?.sourceReferences?.some(
      (reference) => reference.sourceToolCallId === exposure.sourceToolCallId,
    ),
    'The post-restart decision should reference the persisted public source tool call',
  );
  assert(
    audit.events?.some(
      (event) => event.toolCallId === exposure.sourceToolCallId && event.type === 'content.exposure_recorded',
    ),
    'SQLite exposure audit evidence should survive a container restart',
  );
  const exposureState = runCapture('docker', [
    'exec',
    containerName,
    'sqlite3',
    '/data/actionproxy.sqlite',
    `SELECT CAST(s.revision AS TEXT) || ':' || CAST(COUNT(e.source_tool_call_id) AS TEXT) FROM content_exposure_scopes s LEFT JOIN content_exposures e ON e.workspace_id = s.workspace_id AND e.influence_scope_id = s.influence_scope_id WHERE s.influence_scope_id = '${exposure.influenceScopeId}' GROUP BY s.revision;`,
  ]).trim();
  assert(
    exposureState === '1:1',
    `SQLite content-exposure evidence should survive a container restart, got ${JSON.stringify(exposureState)}`,
  );
  stopContainer();
}

async function recordPublicMcpExposure() {
  const submitted = await submitMcpToolCall(
    'docker-public-read',
    'web.fetch',
    { url: 'https://evil.example/docker-smoke-prompt' },
  );
  assert(submitted.status === 'pending_approval', 'Unknown public content should require approval before retrieval');
  assert(submitted.approval?.id, 'The public MCP read should include an approval id');
  assert(submitted.toolCall?.influenceScopeId, 'The public MCP read should have a verified influence scope');
  assert(
    /^influence_[a-f0-9]{64}$/u.test(submitted.toolCall.influenceScopeId),
    'The public MCP read should expose only an opaque influence scope',
  );

  const approved = await postJson(`/v1/approvals/${submitted.approval.id}/approve`, {
    approvedBy: 'manager@example.com',
    inputDecision: { mode: 'original' },
    note: 'Approved public retrieval for Docker artifact smoke',
  });
  const toolCall = approved.toolCall;
  const grant = toolCall?.result?.grant;
  assert(toolCall?.status === 'authorized' && grant?.id, 'Approved public MCP read should issue an external grant');
  await postMcpJson(`/v1/execution-grants/${grant.id}/consume`, {
    input: toolCall.input,
    policyVersionHash: toolCall.policyVersionHash,
    toolCallId: toolCall.id,
    toolName: toolCall.toolName,
  });

  const result = {
    content: [{ text: 'Hostile public instructions from the Docker fixture.', type: 'text' }],
  };
  const canonicalResult = canonicalJson(result);
  const outcome = await postMcpJson(`/v1/execution-grants/${grant.id}/outcome`, {
    result,
    resultDelivery: {
      byteCount: Buffer.byteLength(canonicalResult, 'utf8'),
      canonicalResultHash: createHash('sha256').update(canonicalResult).digest('hex'),
      modelVisible: true,
      version: 'actionproxy.result-delivery.v1',
    },
    status: 'succeeded',
  });
  assert(outcome.toolCall?.resultWithheld === false, 'Classified result should release only after exposure evidence');
  return {
    influenceScopeId: submitted.toolCall.influenceScopeId,
    sourceToolCallId: toolCall.id,
  };
}

function startContainer({ storage, volume }) {
  cleanupContainer();
  const args = [
    'run',
    '--rm',
    '-d',
    '--name',
    containerName,
    '-e',
    'ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND=true',
    '-e',
    `ACTIONPROXY_STORAGE=${storage}`,
  ];
  if (storage === 'sqlite') {
    args.push('-e', 'ACTIONPROXY_SQLITE_PATH=/data/actionproxy.sqlite');
  }
  if (volume) {
    args.push('-v', `${volume}:/data`);
  }
  args.push('-p', `127.0.0.1:${port}:8787`, image);
  run('docker', args);
  containerStarted = true;
}

function stopContainer() {
  if (!containerStarted) return;
  cleanupContainer();
  containerStarted = false;
}

function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) {
    throw new Error(`Command failed: ${result.error.message}: ${command} ${args.join(' ')}`);
  }
  if (result.status !== 0) {
    const suffix = result.signal ? ` signal ${result.signal}` : ` exit ${result.status}`;
    throw new Error(`Command failed:${suffix}: ${command} ${args.join(' ')}`);
  }
}

function runCapture(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  if (result.error) {
    throw new Error(`Command failed: ${result.error.message}: ${command} ${args.join(' ')}`);
  }
  if (result.status !== 0) {
    const suffix = result.signal ? ` signal ${result.signal}` : ` exit ${result.status}`;
    throw new Error(`Command failed:${suffix}: ${command} ${args.join(' ')}\n${result.stderr ?? ''}`);
  }
  return result.stdout ?? '';
}

function cleanupContainer() {
  spawnSync('docker', ['rm', '-f', containerName], { stdio: 'ignore' });
}

function cleanupVolume() {
  spawnSync('docker', ['volume', 'rm', '-f', volumeName], { stdio: 'ignore' });
  volumeCreated = false;
}

async function waitForHealth() {
  const deadline = Date.now() + Number(productEnv('ACTIONPROXY_DOCKER_SMOKE_TIMEOUT_MS') ?? '60000');
  let lastError;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return;
      lastError = new Error(`health returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(500);
  }

  throw new Error(`Timed out waiting for ${baseUrl}/health: ${lastError instanceof Error ? lastError.message : lastError}`);
}

async function assertHealth() {
  const body = await getJson('/health');
  assert(body.ok === true, 'health response should be ok');
  assert(body.service === 'actionproxy-server', 'health service should be actionproxy-server');
}

async function assertCommunityBoundary() {
  const unavailableRoutes = [
    '/v1/system/capabilities',
    '/v1/task-contracts',
    '/v1/integrations/connected-apps',
    '/v1/integrations/business-actions/example/dry-run',
    '/v1/agents/templates',
  ];
  for (const route of unavailableRoutes) {
    const response = await fetch(`${baseUrl}${route}`);
    assert(response.status === 404, `${route} should be unavailable in Community`);
  }

  const legacySubmission = await fetch(`${baseUrl}/v1/tool-calls`, {
    body: JSON.stringify({
      input: { query: 'community boundary' },
      requestedBy: 'docker-smoke',
      taskContractId: 'removed-interface',
      tool: 'docs.search',
    }),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  });
  assert(legacySubmission.status === 400, 'taskContractId should fail strict request validation');
}

async function assertWebApp() {
  const response = await fetch(`${baseUrl}/app`);
  const body = await response.text();
  assert(response.status === 200, '/app should return 200');
  assert(body.includes('<div id="root"'), '/app should serve the bundled web shell');
}

async function assertPackagedTunnelWrapper() {
  const raw = runCapture('docker', [
    'exec',
    containerName,
    'node',
    'packages/mcp-wrapper/dist/index.js',
    'doctor',
    '--config',
    'examples/chatgpt-tunnel/actionproxy.mcp.yaml',
    '--discover',
    '--json',
  ]);
  const report = JSON.parse(raw);
  const server = report.servers?.[0];
  const tools = [...(server?.discovery?.tools ?? [])].sort();
  assert(report.ok === true, 'Packaged MCP wrapper doctor should pass in the runtime image');
  assert(server?.name === 'chatgpt-tunnel-demo', 'Packaged MCP wrapper should discover the tunnel fixture');
  assert(
    JSON.stringify(tools) ===
      JSON.stringify(['dangerous.delete_customer', 'docs.search', 'gmail.send_email']),
    `Packaged MCP wrapper should expose exactly the three tunnel tools, got ${JSON.stringify(tools)}`,
  );
}

async function assertRuntimeImageBoundary() {
  const report = JSON.parse(
    runCapture('docker', [
      'exec',
      containerName,
      'node',
      '-e',
      [
        "const fs=require('node:fs');",
        "const forbidden=['/app/node_modules','/app/apps/web/node_modules','/app/apps/server/node_modules/.bin/vitest','/app/apps/server/node_modules/.bin/tsc','/app/apps/server/node_modules/.bin/tsx','/app/apps/server/node_modules/.bin/tsup','/app/packages/mcp-wrapper/node_modules/.bin/vitest','/app/packages/mcp-wrapper/node_modules/.bin/tsc','/app/packages/mcp-wrapper/node_modules/.bin/tsx','/app/packages/mcp-wrapper/node_modules/.bin/tsup'];",
        "process.stdout.write(JSON.stringify({uid:process.getuid?.()??0,unexpected:forbidden.filter((entry)=>fs.existsSync(entry))}));",
      ].join(''),
    ]),
  );
  assert(report.uid > 0, `Runtime container should use a non-root UID, got ${report.uid}`);
  assert(
    report.unexpected?.length === 0,
    `Runtime image should exclude root/dev dependency trees, found ${JSON.stringify(report.unexpected)}`,
  );
}

async function configureBrowserAccessibleEmailOutbox() {
  await postJson('/v1/approvers/users', {
    defaultApprover: true,
    displayName: 'Docker smoke approver',
    email: 'approvals@example.com',
    enabled: true,
    groups: [],
  });
  const configured = await putJson('/v1/integrations/email', {
    approvalRecipient: 'approvals@example.com',
    enabled: true,
    from: 'actionproxy@example.com',
    publicBaseUrl: baseUrl,
    transport: 'outbox',
  });
  assert(configured.email?.status === 'ready', 'Docker outbox email should be ready');
  assert(
    configured.email?.fields?.publicBaseUrl === baseUrl,
    'Docker outbox email should use the browser-accessible demo origin',
  );
}

async function assertDemoLifecycle() {
  const docs = await submitToolCall({
    agentId: 'docker-smoke-agent',
    input: { query: 'refund policy' },
    reason: 'Docker smoke read-only action',
    toolName: 'docs.search',
  });
  assert(docs.status === 'executed', 'docs.search should execute');
  assert(docs.decision === 'allow', 'docs.search should be allowed');

  const email = await submitToolCall({
    agentId: 'docker-smoke-agent',
    input: {
      body: 'Thanks for contacting support.',
      subject: 'Update',
      to: 'customer@example.com',
    },
    reason: 'Docker smoke approval action',
    toolName: 'gmail.send_email',
  });
  assert(email.status === 'pending_approval', 'gmail.send_email should wait for approval');
  assert(email.approval?.id, 'gmail.send_email should include an approval id');
  assertOutboxReviewLink(email.approval.id);

  const pending = await getJson('/v1/approvals/pending');
  assert(
    pending.approvals?.some((approval) => approval.id === email.approval.id),
    'pending approval should be listed',
  );

  const approved = await postJson(`/v1/approvals/${email.approval.id}/approve`, {
    approvedBy: 'manager@example.com',
    note: 'Approved from Docker smoke',
  });
  assert(approved.approval?.status === 'approved', 'approval should be approved');
  assert(approved.toolCall?.status === 'executed', 'approved email should execute');

  const denied = await submitToolCall({
    agentId: 'docker-smoke-agent',
    input: { customerId: 'cus_123' },
    reason: 'Docker smoke deny action',
    toolName: 'dangerous.delete_customer',
  });
  assert(denied.status === 'blocked', 'dangerous.delete_customer should be blocked');
  assert(denied.decision === 'deny', 'dangerous.delete_customer should be denied');

  const audit = await getJson('/v1/audit');
  const eventTypes = new Set((audit.events ?? []).map((event) => event.type));
  for (const eventType of ['policy.allow', 'approval.approved', 'tool_call.executed', 'policy.deny']) {
    assert(eventTypes.has(eventType), `audit should include ${eventType}`);
  }
}

function assertOutboxReviewLink(approvalId) {
  const filenames = runCapture('docker', [
    'exec',
    containerName,
    'ls',
    '-1',
    '/data/outbox/email',
  ])
    .split('\n')
    .map((entry) => entry.trim())
    .filter(Boolean);
  const messages = filenames.map((filename) =>
    JSON.parse(
      runCapture('docker', [
        'exec',
        containerName,
        'cat',
        `/data/outbox/email/${filename}`,
      ]),
    ),
  );
  const message = messages.find((entry) => entry.text?.includes(approvalId));
  assert(message, `Docker outbox should contain approval ${approvalId}`);
  assert(
    message.text.includes(`${baseUrl}/#/approvals/${approvalId}`),
    `Docker outbox review link should use ${baseUrl}`,
  );
  assert(
    !message.text.includes('127.0.0.1:5173'),
    'Docker outbox review link must not use the removed port-5173 fallback',
  );
}

async function submitToolCall(body) {
  return postJson('/v1/tool-calls', {
    requestedBy: 'dev@example.com',
    ...body,
  });
}

async function submitMcpToolCall(idempotencyKey, toolName, input) {
  return postJsonWithHeaders('/v1/mcp/tool-calls', {
    agentId: 'docker-mcp-wrapper',
    input,
    reason: 'Docker verified MCP influence smoke',
    requestedBy: 'docker-mcp-wrapper',
    toolName,
  }, {
    'idempotency-key': idempotencyKey,
    'x-actionproxy-mcp-session-id': mcpSessionId,
  });
}

async function getJson(path) {
  const response = await fetch(`${baseUrl}${path}`);
  const body = await response.json();
  assert(response.ok, `${path} should return 2xx, got ${response.status}: ${JSON.stringify(body)}`);
  return body;
}

async function postJson(path, body) {
  return postJsonWithHeaders(path, body);
}

async function putJson(path, body) {
  return requestJsonWithHeaders(path, body, {}, 'PUT');
}

async function postMcpJson(path, body) {
  return postJsonWithHeaders(path, body, {
    'x-actionproxy-mcp-session-id': mcpSessionId,
  });
}

async function postJsonWithHeaders(path, body, headers = {}) {
  return requestJsonWithHeaders(path, body, headers, 'POST');
}

async function requestJsonWithHeaders(path, body, headers = {}, method = 'POST') {
  const response = await fetch(`${baseUrl}${path}`, {
    body: JSON.stringify(body),
    headers: { 'content-type': 'application/json', ...headers },
    method,
  });
  const responseBody = await response.json();
  assert(response.ok, `${path} should return 2xx, got ${response.status}: ${JSON.stringify(responseBody)}`);
  return responseBody;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function productEnv(name) {
  return process.env[name];
}
