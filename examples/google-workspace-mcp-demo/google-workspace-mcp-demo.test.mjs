import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import {
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import YAML from 'yaml';
import {
  APPROVAL_TIMEOUT_MS,
  DOWNSTREAM_REQUEST_TIMEOUT_MS,
  OUTER_APPROVAL_TIMEOUT_MS,
  OUTER_DOWNSTREAM_TIMEOUT_MS,
  WORKSPACE_MCP_SPEC,
  WORKSPACE_MCP_WHEEL_SHA256,
  WORKSPACE_MCP_WHEEL_URL,
  assertAuditChainValid,
  assertExactlyOneSuccessfulExecution,
  assertExpectedGatewayPolicy,
  assertLoopbackPortAvailable,
  assertNoExecutionBeforeApproval,
  assertSelfTarget,
  assertTerminalWithoutDispatch,
  buildWrapperEnvironment,
  callWithSingleGoogleAuthenticationRetry,
  findExactCurrentMcpCall,
  isGoogleAuthenticationRequired,
  loadPrivateEnvFile,
  normalizeLoopbackApiUrl,
  normalizeLoopbackBrowserUrl,
  preparePrivateRuntime,
  redactKnownSecrets,
  terminateChildProcessTree,
} from './demo-support.mjs';
import { devProcessSpecs, isolateGoogleWorkspaceDemoEnvironment } from '../../scripts/dev.mjs';

const demoDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(demoDir, '..', '..');
const mcpPath = join(demoDir, 'actionproxy.mcp.yaml');
const policyPath = join(demoDir, 'actionproxy.policy.yaml');
const envExamplePath = join(demoDir, '.env.example');
const runnerPath = join(demoDir, 'run-gmail-draft-test.mjs');

const mcpSource = readFileSync(mcpPath, 'utf8');
const mcpConfig = YAML.parse(mcpSource);
const policy = YAML.parse(readFileSync(policyPath, 'utf8'));
const envExample = readFileSync(envExamplePath, 'utf8');
const readmeSource = readFileSync(join(demoDir, 'README.md'), 'utf8');
const runnerSource = readFileSync(runnerPath, 'utf8');
const rootPackage = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
const googleClientIdName = ['GOOGLE', 'OAUTH', 'CLIENT', 'ID'].join('_');
const googleClientSecretName = ['GOOGLE', 'OAUTH', 'CLIENT', 'SECRET'].join('_');

test('pins the reviewed downstream package and grants only the Gmail draft permission', () => {
  const server = mcpConfig.servers['google-workspace'];

  assert.equal(server.command, 'uvx');
  assert.deepEqual(server.args.slice(0, 3), [
    '--from',
    WORKSPACE_MCP_WHEEL_URL,
    'workspace-mcp',
  ]);
  const pinnedArtifact = new URL(server.args[1]);
  assert.equal(pinnedArtifact.protocol, 'https:');
  assert.equal(pinnedArtifact.hostname, 'files.pythonhosted.org');
  assert.match(pinnedArtifact.pathname, /\/workspace_mcp-1\.22\.0-py3-none-any\.whl$/u);
  assert.equal(pinnedArtifact.hash, `#sha256=${WORKSPACE_MCP_WHEEL_SHA256}`);
  assert.match(WORKSPACE_MCP_WHEEL_SHA256, /^[0-9a-f]{64}$/u);
  assert.equal(WORKSPACE_MCP_SPEC, 'workspace-mcp==1.22.0');
  assert.equal(server.args.filter((entry) => entry === '--permissions').length, 1);
  assert.equal(server.args[server.args.indexOf('--permissions') + 1], 'gmail:drafts');
  assert.equal(server.args[server.args.indexOf('--tool-tier') + 1], 'extended');
  assert.equal(server.requestTimeoutMs, DOWNSTREAM_REQUEST_TIMEOUT_MS);
  assert.doesNotMatch(server.args.join(' '), /(?:@latest|>=|~=|\^|\*)/u);
});

test('passes through only the reviewed Google and local-state environment names', () => {
  const server = mcpConfig.servers['google-workspace'];

  assert.equal(server.env, undefined, 'Secrets must never be written inline in the MCP profile.');
  assert.deepEqual([...server.envPassthrough].sort(), [
    'ALLOWED_FILE_DIRS',
    'GOOGLE_MCP_CREDENTIALS_DIR',
    'GOOGLE_OAUTH_CLIENT_ID',
    'GOOGLE_OAUTH_CLIENT_SECRET',
    'OAUTHLIB_INSECURE_TRANSPORT',
    'USER_GOOGLE_EMAIL',
    'UV_CACHE_DIR',
    'UV_NO_PROGRESS',
    'UV_PYTHON_INSTALL_DIR',
    'WORKSPACE_ATTACHMENT_DIR',
    'WORKSPACE_MCP_BASE_URI',
    'WORKSPACE_MCP_CREDENTIALS_DIR',
    'WORKSPACE_MCP_HOST',
    'WORKSPACE_MCP_LOG_DIR',
    'WORKSPACE_MCP_PORT',
  ]);
  assert.equal(new Set(server.envPassthrough.map((name) => name.toLowerCase())).size, server.envPassthrough.length);
  assert.ok(server.envPassthrough.every((name) => /^[A-Z_][A-Z0-9_]*$/u.test(name)));
  assert.equal(mcpConfig.actionproxy.bearerToken, undefined);
  assert.equal(mcpConfig.actionproxy.apiKey, undefined);
  assert.equal(mcpConfig.actionproxy.token, undefined);
  assert.doesNotMatch(mcpSource, /(?:sk-[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)/u);
});

test('keeps the wrapper and gateway policy aligned on allow, approval, deny, and fail-closed defaults', () => {
  const expectedDecisions = {
    draft_gmail_message: 'required',
    get_gmail_message_content: 'never',
    get_gmail_messages_content_batch: 'never',
    search_gmail_messages: 'never',
    send_gmail_message: 'deny',
  };

  assert.equal(policy.version, 1);
  assert.equal(policy.default.approval, 'required');
  assert.deepEqual(
    Object.fromEntries(Object.entries(expectedDecisions).map(([toolName]) => [toolName, policy.tools[toolName].approval])),
    expectedDecisions,
  );
  assert.deepEqual(
    Object.fromEntries(Object.entries(expectedDecisions).map(([toolName]) => [toolName, mcpConfig.policies[toolName].approval])),
    expectedDecisions,
  );
  assert.equal(policy.tools.search_gmail_messages.risk, 'read_only');
  assert.equal(policy.tools.draft_gmail_message.risk, 'external_communication');
  assert.equal(policy.tools.send_gmail_message.risk, 'external_communication');
  assert.equal(mcpConfig.actionproxy.approvalTimeoutMs, APPROVAL_TIMEOUT_MS);
  assert.equal(mcpConfig.actionproxy.cancelPendingOnAbort, true);
  assert.equal(APPROVAL_TIMEOUT_MS, 300_000);
  assert.equal(DOWNSTREAM_REQUEST_TIMEOUT_MS, 180_000);
  assert.equal(OUTER_DOWNSTREAM_TIMEOUT_MS, 210_000);
  assert.equal(OUTER_APPROVAL_TIMEOUT_MS, 510_000);
  assert.ok(OUTER_DOWNSTREAM_TIMEOUT_MS > DOWNSTREAM_REQUEST_TIMEOUT_MS);
  assert.ok(OUTER_APPROVAL_TIMEOUT_MS > APPROVAL_TIMEOUT_MS + DOWNSTREAM_REQUEST_TIMEOUT_MS);
});

test('requires the live gateway policy to match the safe Google proof before any downstream process starts', () => {
  const expectedSummary = gatewayPolicySummary();
  assert.doesNotThrow(() => assertExpectedGatewayPolicy(expectedSummary));

  const invalidSummaries = [
    undefined,
    { ...expectedSummary, version: 2 },
    { ...expectedSummary, defaultRule: { decision: 'allow' } },
    { ...expectedSummary, rules: expectedSummary.rules.filter((rule) => rule.pattern !== 'send_gmail_message') },
    {
      ...expectedSummary,
      rules: expectedSummary.rules.map((rule) =>
        rule.pattern === 'search_gmail_messages' ? { ...rule, decision: 'require_approval' } : rule,
      ),
    },
    {
      ...expectedSummary,
      rules: [...expectedSummary.rules, { decision: 'deny', matchType: 'exact', pattern: 'send_gmail_message' }],
    },
  ];
  for (const summary of invalidSummaries) {
    assert.throws(() => assertExpectedGatewayPolicy(summary), /running gateway|gateway policy/u);
  }
});

test('ships a credential-free environment template', () => {
  const assignedValues = new Map();
  for (const line of envExample.split(/\r?\n/u)) {
    const match = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/u);
    if (match) assignedValues.set(match[1], match[2]);
  }

  assert.equal(assignedValues.get('GOOGLE_OAUTH_CLIENT_ID'), '');
  assert.equal(assignedValues.get('GOOGLE_OAUTH_CLIENT_SECRET'), '');
  assert.equal(assignedValues.get('USER_GOOGLE_EMAIL'), '');
  assert.doesNotMatch(envExample, /(?:sk-[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)/u);
});

test('builds a least-privilege wrapper environment and excludes unrelated secret canaries', () => {
  const awsSecretName = ['AWS', 'SECRET', 'ACCESS', 'KEY'].join('_');
  const controlPlaneKeyName = ['CONTROL', 'PLANE', 'API', 'KEY'].join('_');
  const googleSecretName = ['GOOGLE', 'OAUTH', 'CLIENT', 'SECRET'].join('_');
  const googleSecretFixture = ['google', 'client', 'secret'].join('-');
  const result = buildWrapperEnvironment({
    ACTIONPROXY_BASE_URL: 'http://127.0.0.1:8787',
    [awsSecretName]: ['unrelated', 'aws', 'secret', 'canary'].join('-'),
    [controlPlaneKeyName]: ['unrelated', 'openai', 'secret', 'canary'].join('-'),
    GMAIL_DRAFT_BODY: 'private draft body that the wrapper does not need',
    GOOGLE_OAUTH_CLIENT_ID: 'google-client-id',
    [googleSecretName]: googleSecretFixture,
    NODE_OPTIONS: '--require=/tmp/untrusted.cjs',
    PATH: '/usr/bin:/bin',
    USER_GOOGLE_EMAIL: 'tester@example.com',
    UV_NO_PROGRESS: '1',
    WORKSPACE_MCP_PORT: '8000',
  });

  assert.deepEqual(result, {
    ACTIONPROXY_BASE_URL: 'http://127.0.0.1:8787',
    GOOGLE_OAUTH_CLIENT_ID: 'google-client-id',
    [googleSecretName]: googleSecretFixture,
    PATH: '/usr/bin:/bin',
    USER_GOOGLE_EMAIL: 'tester@example.com',
    UV_NO_PROGRESS: '1',
    WORKSPACE_MCP_PORT: '8000',
  });
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /unrelated-(?:aws|openai)-secret-canary/u);
  assert.doesNotMatch(serialized, /private draft body|NODE_OPTIONS|untrusted\.cjs/u);
});

test('creates removable local runtime state with private modes and ignores unknown env-file keys', (context) => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'actionproxy-google-mcp-test-'));
  context.after(() => rmSync(temporaryRoot, { force: true, recursive: true }));
  const repoRoot = join(temporaryRoot, 'checkout');
  const envPath = join(repoRoot, '.env.local');
  const fileClientId = ['file', 'client', 'id'].join('-');
  const fileClientSecret = ['file', 'client', 'value'].join('-');
  const ambientClientId = ['ambient', 'client', 'id'].join('-');
  const ambientClientSecret = ['ambient', 'client', 'value'].join('-');
  const unrelatedName = ['AWS', 'SECRET', 'ACCESS', 'KEY'].join('_');
  const unrelatedValue = ['must', 'not', 'be', 'loaded'].join('-');
  mkdirSync(repoRoot, { recursive: true });
  writeFileSync(
    envPath,
    [
      `${googleClientIdName}=${fileClientId}`,
      `${googleClientSecretName}=${fileClientSecret}`,
      'USER_GOOGLE_EMAIL=tester@example.com',
      `${unrelatedName}=${unrelatedValue}`,
      '',
    ].join('\n'),
    { mode: 0o644 },
  );

  const runtime = preparePrivateRuntime({
    envPath,
    environment: {
      [googleClientIdName]: ambientClientId,
      [googleClientSecretName]: ambientClientSecret,
      USER_GOOGLE_EMAIL: 'ambient@example.com',
    },
    repoRoot,
  });

  assert.equal(mode(envPath), 0o600);
  for (const directory of [join(repoRoot, '.actionproxy'), runtime.dataDir, ...Object.values(runtime.paths)]) {
    assert.equal(mode(directory), 0o700, `${directory} should be mode 0700`);
  }
  assert.equal(runtime.environment[googleClientIdName], fileClientId);
  assert.equal(runtime.environment[googleClientSecretName], fileClientSecret);
  assert.equal(runtime.environment.USER_GOOGLE_EMAIL, 'tester@example.com');
  assert.equal(runtime.environment[unrelatedName], undefined);
  assert.equal(runtime.environment.WORKSPACE_MCP_HOST, '127.0.0.1');
  assert.equal(runtime.environment.WORKSPACE_MCP_BASE_URI, 'http://127.0.0.1');
  assert.equal(runtime.environment.WORKSPACE_MCP_PORT, '8000');
  assert.equal(runtime.environment.ALLOWED_FILE_DIRS, runtime.paths.attachmentsDir);
});

test('requires an explicit env file and rejects ambiguous duplicate values', (context) => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'actionproxy-google-mcp-env-'));
  context.after(() => rmSync(temporaryRoot, { force: true, recursive: true }));
  const missingPath = join(temporaryRoot, '.env.local');

  assert.throws(
    () => loadPrivateEnvFile(missingPath, {
      [googleClientIdName]: ['ambient', 'id'].join('-'),
      [googleClientSecretName]: ['ambient', 'value'].join('-'),
      USER_GOOGLE_EMAIL: 'ambient@example.com',
    }),
    /requires .*\.env\.local/u,
  );

  const duplicatePath = join(temporaryRoot, 'duplicate.env');
  writeFileSync(
    duplicatePath,
    [
      `${googleClientIdName}=${['first', 'id'].join('-')}`,
      `${googleClientIdName}=${['second', 'id'].join('-')}`,
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  assert.throws(() => loadPrivateEnvFile(duplicatePath, {}), /Duplicate GOOGLE_OAUTH_CLIENT_ID/u);
});

test('rejects a symlinked env file before reading it', (context) => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'actionproxy-google-mcp-symlink-'));
  context.after(() => rmSync(temporaryRoot, { force: true, recursive: true }));
  const target = join(temporaryRoot, 'target.env');
  const link = join(temporaryRoot, '.env.local');
  const symlinkCanary = ['symlink', 'private', 'canary'].join('-');
  const targetContents = `${googleClientSecretName}=${symlinkCanary}\n`;
  writeFileSync(target, targetContents, { mode: 0o600 });
  symlinkSync(target, link);

  assert.throws(() => loadPrivateEnvFile(link, {}), /regular file, not a symbolic link/u);
  assert.equal(readFileSync(target, 'utf8'), targetContents);
});

test('limits the proof to a self-targeted mailbox and loopback browser/API URLs', () => {
  assert.deepEqual(assertSelfTarget('Tester@Example.com', 'tester@example.com'), {
    recipient: 'tester@example.com',
    user: 'tester@example.com',
  });
  assert.throws(
    () => assertSelfTarget('tester@example.com', 'customer@example.com'),
    /must match USER_GOOGLE_EMAIL/u,
  );
  assert.equal(normalizeLoopbackApiUrl('http://localhost:8787'), 'http://localhost:8787');
  assert.equal(
    normalizeLoopbackBrowserUrl('http://127.0.0.1:5173/#/approvals'),
    'http://127.0.0.1:5173/#/approvals',
  );
  assert.throws(() => normalizeLoopbackApiUrl('https://127.0.0.1:8787'), /loopback HTTP/u);
  assert.throws(() => normalizeLoopbackApiUrl('http://example.com:8787'), /loopback HTTP/u);
  assert.throws(() => normalizeLoopbackApiUrl('http://127.0.0.1:8787/v1'), /without a path/u);
  const credentialUrl = ['http://user', 'pass@127.0.0.1:5173'].join(':');
  assert.throws(() => normalizeLoopbackBrowserUrl(credentialUrl), /without credentials/u);
});

test('correlates only an exact current input and fails closed on ambiguity or exclusions', () => {
  const startedAt = Date.parse('2026-08-04T10:00:00.000Z');
  const expectedInput = {
    body: 'Synthetic body',
    nested: { alpha: 1, beta: ['two', 3] },
    subject: 'Session-specific subject',
  };
  const exact = mcpToolCall({
    createdAt: new Date(startedAt).toISOString(),
    id: 'call_exact',
    input: { subject: 'Session-specific subject', nested: { beta: ['two', 3], alpha: 1 }, body: 'Synthetic body' },
  });
  const candidates = [
    mcpToolCall({ createdAt: new Date(startedAt - 1).toISOString(), id: 'call_old', input: expectedInput }),
    mcpToolCall({ createdAt: new Date(startedAt + 1).toISOString(), id: 'call_wrong_input', input: { ...expectedInput, body: 'Different' } }),
    mcpToolCall({ createdAt: new Date(startedAt + 2).toISOString(), id: 'call_wrong_tool', input: expectedInput, toolName: 'other_tool' }),
    exact,
  ];

  assert.equal(
    findExactCurrentMcpCall(candidates, { expectedInput, startedAt, toolName: 'draft_gmail_message' }),
    exact,
  );
  assert.equal(
    findExactCurrentMcpCall(candidates, {
      excludedToolCallIds: ['call_exact'],
      expectedInput,
      startedAt,
      toolName: 'draft_gmail_message',
    }),
    undefined,
  );
  assert.throws(
    () => findExactCurrentMcpCall(
      [exact, { ...exact, createdAt: new Date(startedAt + 3).toISOString(), id: 'call_duplicate' }],
      { expectedInput, startedAt, toolName: 'draft_gmail_message' },
    ),
    /Ambiguous current-session draft_gmail_message correlation/u,
  );
  assert.throws(
    () => findExactCurrentMcpCall({}, { expectedInput, startedAt, toolName: 'draft_gmail_message' }),
    /invalid tool-call list/u,
  );
});

test('reserves the fixed loopback OAuth callback port and detects a real listener', async (context) => {
  const listener = createServer();
  context.after(() => {
    if (listener.listening) listener.close();
  });
  try {
    await listenOnLoopback(listener);
  } catch (error) {
    if (error?.code === 'EPERM') {
      context.skip('This test runner sandbox does not permit loopback listeners.');
      return;
    }
    throw error;
  }
  const address = listener.address();
  assert.ok(address && typeof address === 'object');
  const occupiedPort = address.port;

  await assert.rejects(
    assertLoopbackPortAvailable(occupiedPort),
    new RegExp(`port ${occupiedPort} is occupied`, 'u'),
  );
  await closeServer(listener);
  await assert.doesNotReject(assertLoopbackPortAvailable(occupiedPort));
  await assert.rejects(assertLoopbackPortAvailable(80), /1024 through 65535/u);
  await assert.rejects(assertLoopbackPortAvailable(65_536), /1024 through 65535/u);
});

test('classifies only failed MCP results that require Google authentication', () => {
  const authenticationResults = [
    mcpError('Authentication required. Visit the authorization URL to continue.'),
    mcpError('OAuth credentials are missing and authorization is needed.'),
    mcpError('Open https://accounts.google.com/o/oauth2/auth to authenticate.'),
  ];
  for (const result of authenticationResults) assert.equal(isGoogleAuthenticationRequired(result), true);

  const ordinaryResults = [
    undefined,
    { content: [{ text: 'Authentication required' }], isError: false },
    mcpError('Google API quota exceeded.'),
    { content: [], isError: true },
    { content: [{ type: 'image' }], isError: true },
  ];
  for (const result of ordinaryResults) assert.equal(isGoogleAuthenticationRequired(result), false);
});

test('allows exactly one explicit Google authentication retry', async () => {
  const success = { content: [{ text: 'Search completed.', type: 'text' }] };
  let ordinaryCalls = 0;
  let ordinaryPrompts = 0;
  const ordinary = await callWithSingleGoogleAuthenticationRetry({
    call: async () => {
      ordinaryCalls += 1;
      return success;
    },
    onAuthenticationRequired: async () => {
      ordinaryPrompts += 1;
    },
  });
  assert.deepEqual(ordinary, { result: success, retried: false });
  assert.equal(ordinaryCalls, 1);
  assert.equal(ordinaryPrompts, 0);

  const authRequired = mcpError('OAuth authentication is required.');
  let retryCalls = 0;
  let retryPrompts = 0;
  const retried = await callWithSingleGoogleAuthenticationRetry({
    call: async () => {
      retryCalls += 1;
      return retryCalls === 1 ? authRequired : success;
    },
    onAuthenticationRequired: async (result) => {
      retryPrompts += 1;
      assert.equal(result, authRequired);
    },
  });
  assert.deepEqual(retried, { result: success, retried: true });
  assert.equal(retryCalls, 2);
  assert.equal(retryPrompts, 1);

  let persistentCalls = 0;
  let persistentPrompts = 0;
  await assert.rejects(
    callWithSingleGoogleAuthenticationRetry({
      call: async () => {
        persistentCalls += 1;
        return authRequired;
      },
      onAuthenticationRequired: async () => {
        persistentPrompts += 1;
      },
    }),
    /still required after the single explicit retry/u,
  );
  assert.equal(persistentCalls, 2, 'Persistent authentication failure must not trigger a third provider call.');
  assert.equal(persistentPrompts, 1);

  await assert.rejects(
    callWithSingleGoogleAuthenticationRetry({ call: undefined, onAuthenticationRequired: async () => {} }),
    /requires explicit call and authentication handlers/u,
  );
});

test('stops the local wrapper gracefully and treats repeated cleanup as a no-op', async () => {
  const signals = [];
  const child = fakeChildProcess((signal, process) => {
    if (signal !== 'SIGTERM') return;
    queueMicrotask(() => finishFakeChild(process, signal));
  }, signals);

  await terminateChildProcessTree(child, { graceMs: 50 });
  assert.deepEqual(signals, ['SIGTERM']);
  assert.equal(child.signalCode, 'SIGTERM');

  await terminateChildProcessTree(child, { graceMs: 50 });
  assert.deepEqual(signals, ['SIGTERM'], 'Cleanup after exit must not signal the child twice.');
});

test('bounds wrapper cleanup and escalates an unresponsive child from SIGTERM to SIGKILL', async () => {
  const signals = [];
  const child = fakeChildProcess((signal, process) => {
    if (signal !== 'SIGKILL') return;
    queueMicrotask(() => finishFakeChild(process, signal));
  }, signals);

  await terminateChildProcessTree(child, { graceMs: 10 });
  assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(child.signalCode, 'SIGKILL');

  const stuckSignals = [];
  const stuckChild = fakeChildProcess(() => undefined, stuckSignals);
  const startedAt = Date.now();
  await assert.rejects(
    terminateChildProcessTree(stuckChild, { graceMs: 5 }),
    /did not stop within the bounded shutdown window/u,
  );
  assert.deepEqual(stuckSignals, ['SIGTERM', 'SIGKILL']);
  assert.ok(Date.now() - startedAt < 2_000, 'A stuck child must fail within the configured bounded waits.');

  await assert.rejects(
    terminateChildProcessTree(fakeChildProcess(() => undefined, []), { graceMs: 0 }),
    /grace must be an integer from 1 through 30000 milliseconds/u,
  );
});

test('waits for the entire detached process group and kills a surviving descendant', () => {
  const supportUrl = pathToFileURL(join(demoDir, 'demo-support.mjs')).href;
  const probe = [
    `import { terminateChildProcessTree } from ${JSON.stringify(supportUrl)};`,
    'const signals = [];',
    'let groupAlive = true;',
    'const originalKill = process.kill;',
    'process.kill = (pid, signal) => {',
    "  if (pid !== -424242) throw new Error('Unexpected process-group target.');",
    '  if (signal === 0) {',
    '    if (groupAlive) return true;',
    "    const error = new Error('Process group is gone.');",
    "    error.code = 'ESRCH';",
    '    throw error;',
    '  }',
    '  signals.push(signal);',
    "  if (signal === 'SIGKILL') groupAlive = false;",
    '  return true;',
    '};',
    'try {',
    '  await terminateChildProcessTree({ exitCode: null, pid: 424242, signalCode: null }, { graceMs: 10, processGroup: true });',
    '  console.log(JSON.stringify(signals));',
    '} finally {',
    '  process.kill = originalKill;',
    '}',
  ].join('\n');
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', probe], {
    cwd: demoDir,
    encoding: 'utf8',
    timeout: 2_000,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), ['SIGTERM', 'SIGKILL']);
});

test('proves zero dispatch before approval and rejects premature execution evidence', async () => {
  await assertNoExecutionBeforeApproval(
    fixtureGetJson({ attempts: [], events: [event('call_1', 'approval.created')] }),
    'call_1',
  );

  await assert.rejects(
    assertNoExecutionBeforeApproval(
      fixtureGetJson({ attempts: [successfulAttempt()], events: [event('call_1', 'execution.attempt_dispatched')] }),
      'call_1',
    ),
    /Expected zero execution attempts before approval/u,
  );
});

test('requires exactly one successful dispatch and one copy of every terminal audit event', async () => {
  const requiredEvents = [
    'execution_grant.created',
    'execution_grant.consumed',
    'execution.attempt_dispatched',
    'execution.attempt_completed',
    'receipt.outcome_recorded',
    'tool_call.executed',
  ].map((type) => event('call_1', type));
  await assertExactlyOneSuccessfulExecution(
    fixtureGetJson({ attempts: [successfulAttempt()], events: requiredEvents }),
    'call_1',
  );

  await assert.rejects(
    assertExactlyOneSuccessfulExecution(
      fixtureGetJson({ attempts: [successfulAttempt(), successfulAttempt()], events: requiredEvents }),
      'call_1',
    ),
    /Expected exactly one execution attempt/u,
  );
  await assert.rejects(
    assertExactlyOneSuccessfulExecution(
      fixtureGetJson({ attempts: [successfulAttempt()], events: [...requiredEvents, event('call_1', 'tool_call.executed')] }),
      'call_1',
    ),
    /Expected exactly 1 tool_call\.executed event; observed 2/u,
  );
});

test('proves rejection or policy denial terminates without downstream dispatch', async () => {
  await assertTerminalWithoutDispatch(
    fixtureGetJson({ attempts: [], events: [event('call_1', 'policy.deny')] }),
    'call_1',
    'policy.deny',
  );
  await assertTerminalWithoutDispatch(
    fixtureGetJson({ attempts: [], events: [event('call_2', 'approval.rejected')] }),
    'call_2',
    'approval.rejected',
  );
  await assertTerminalWithoutDispatch(
    fixtureGetJson({ attempts: [], events: [event('call_3', 'approval.cancelled')] }),
    'call_3',
    'approval.cancelled',
  );

  await assert.rejects(
    assertTerminalWithoutDispatch(
      fixtureGetJson({
        attempts: [successfulAttempt()],
        events: [event('call_1', 'policy.deny'), event('call_1', 'execution.attempt_dispatched')],
      }),
      'call_1',
      'policy.deny',
    ),
    /Expected no execution attempt/u,
  );
});

test('requires audit-chain validity and redacts known OAuth canaries from diagnostics', async () => {
  const verification = await assertAuditChainValid(async () => ({ checked: 12, errors: [], valid: true }));
  assert.equal(verification.valid, true);
  await assert.rejects(
    assertAuditChainValid(async () => ({ errors: ['hash mismatch'], valid: false })),
    /audit hash chain did not verify/u,
  );

  const googleSecretName = ['GOOGLE', 'OAUTH', 'CLIENT', 'SECRET'].join('_');
  const clientCanary = ['client', 'secret', 'canary'].join('-');
  const oauthCanary = ['oauth', 'secret', 'canary'].join('-');
  const redacted = redactKnownSecrets(`client=${clientCanary} secret=${oauthCanary}`, {
    GOOGLE_OAUTH_CLIENT_ID: clientCanary,
    [googleSecretName]: oauthCanary,
  });
  assert.equal(redacted, 'client=[REDACTED] secret=[REDACTED]');
});

test('wires every safety verifier into the real proof runner before reporting success', () => {
  for (const call of [
    'assertExpectedGatewayPolicy(await getJson',
    'assertLoopbackPortAvailable(',
    'assertNoExecutionBeforeApproval(',
    'assertExactlyOneSuccessfulExecution(',
    'assertTerminalWithoutDispatch(',
    'assertAuditChainValid(',
    'buildWrapperEnvironment(environment)',
    'callWithSingleGoogleAuthenticationRetry({',
    'findExactCurrentMcpCall(',
    "postJson(baseUrl, '/v1/tool-calls'",
  ]) {
    assert.ok(runnerSource.includes(call), `Runner must call ${call}`);
  }
  assert.ok(
    runnerSource.indexOf('assertExpectedGatewayPolicy(await getJson') < runnerSource.indexOf("spawn(wrapperPath"),
    'The active gateway policy must be checked before the third-party process starts.',
  );
  assert.ok(
    runnerSource.indexOf('confirmPinnedDependency(') < runnerSource.indexOf("spawn(wrapperPath"),
    'Dependency approval must occur before the third-party process starts.',
  );
  assert.doesNotMatch(runnerSource, /\/v1\/policy\/simulate/u);
  assert.match(runnerSource, /waitForPendingApproval\(baseUrl, 'draft_gmail_message', callStartedAt, input\)/u);
  assert.match(runnerSource, /findExactCurrentMcpCall\(toolCalls, \{ expectedInput, startedAt: callStartedAt, toolName \}\)/u);

  const allowedSearchSource = sourceBetween('async function callAllowedSearch', 'async function callApprovedDraft');
  assert.equal(matches(allowedSearchSource, /callWithSingleGoogleAuthenticationRetry\(\{/gu), 1);
  assert.equal(matches(allowedSearchSource, /peer\.request\(/gu), 1, 'The retry helper owns the bounded second call.');
  assert.match(allowedSearchSource, /onAuthenticationRequired: async \(\) =>/u);
  assert.match(allowedSearchSource, /excludedToolCallIds\.push\(authenticationAttempt\.id\)/u);

  const consentSource = sourceBetween('async function confirmPinnedDependency', 'async function waitForGoogleAuthentication');
  assert.match(consentSource, /Allow this third-party network\/download activity for this launch/u);
  assert.doesNotMatch(consentSource, /marker|receipt|cache.*ready|return true/iu);
  assert.doesNotMatch(runnerSource, /dependencyMarkerMatches/u);
  assert.match(runnerSource, /crypto\.randomUUID\(\)\.slice\(0, 8\)/u);
  assert.match(runnerSource, /actionproxy-proof-\$\{sessionTag\}/u);
  assert.match(runnerSource, /peer\.request\('initialize',[\s\S]{0,260}\}, OUTER_DOWNSTREAM_TIMEOUT_MS\)/u);
  assert.match(runnerSource, /peer\.request\('tools\/list', \{\}, OUTER_DOWNSTREAM_TIMEOUT_MS\)/u);
  assert.equal(matches(runnerSource, /OUTER_DOWNSTREAM_TIMEOUT_MS/gu), 5);
  assert.equal(matches(runnerSource, /OUTER_APPROVAL_TIMEOUT_MS/gu), 4);
  assert.match(readmeSource, /startup timeout is three minutes/u);
  assert.doesNotMatch(runnerSource, /env:\s*process\.env/u);
  assert.doesNotMatch(runnerSource, /printToolResult|process\.stderr\.write/u);

  const runSource = sourceBetween('async function run()', 'async function callAllowedSearch');
  assert.match(runSource, /const wrapperProcessGroup = process\.platform !== 'win32'/u);
  assert.match(runSource, /detached: wrapperProcessGroup/u);
  assert.match(runSource, /wrapperShutdown \?\?= terminateChildProcessTree\(wrapper, \{/u);
  assert.match(runSource, /graceMs: 5_000/u);
  assert.match(runSource, /processGroup: wrapperProcessGroup/u);
  assert.match(runSource, /if \(receivedShutdownSignal\) return/u);
  assert.match(runSource, /activeTerminal\?\.close\(\)/u);
  assert.match(runSource, /process\.once\('SIGINT', handleInterrupt\)/u);
  assert.match(runSource, /process\.once\('SIGTERM', handleTerminate\)/u);
  assert.match(runSource, /process\.off\('SIGINT', handleInterrupt\)/u);
  assert.match(runSource, /process\.off\('SIGTERM', handleTerminate\)/u);
  assert.match(runSource, /process\.exit\(signal === 'SIGINT' \? 0 : 143\)/u);
  assert.match(runSource, /restoreUmask\(\)/u);
  assert.match(runSource, /\.then\(\(\) => cancelPendingApprovalOnShutdown\(\)\)/u);
  assert.ok(
    runSource.indexOf("process.once('SIGINT', handleInterrupt)") < runSource.indexOf("spawn(wrapperPath"),
    'Signal cleanup must be installed before the wrapper process starts.',
  );
  assert.match(runnerSource, /activeTerminal = terminal/u);
  assert.match(runnerSource, /if \(activeTerminal === terminal\) activeTerminal = undefined/u);
  const shutdownCancellationSource = sourceBetween(
    'async function cancelPendingApprovalOnShutdown',
    'async function assertActionProxyReady',
  );
  assert.match(shutdownCancellationSource, /activePendingApproval = undefined/u);
  assert.match(shutdownCancellationSource, /\/v1\/approvals\/\$\{encodeURIComponent\(pending\.id\)\}\/cancel/u);
  assert.match(shutdownCancellationSource, /AbortSignal\.timeout\(2_000\)/u);
  assert.match(shutdownCancellationSource, /catch \{/u);
  assert.match(runnerSource, /if \(!receivedShutdownSignal\) clearTrackedPendingApproval\(pending\.approval\.id\)/u);
});

test('keeps the Google proof gateway data in its own removable private subtree', () => {
  assert.equal(
    rootPackage.scripts['dev:proxy:gmail-mcp'],
    'node scripts/dev.mjs --server-only --google-workspace-demo',
  );
  assert.equal(
    rootPackage.scripts['dev:web:gmail-mcp'],
    'node scripts/dev.mjs --web-only --google-workspace-demo',
  );
  assert.match(readmeSource, /corepack pnpm dev:web:gmail-mcp/u);
  assert.match(
    readmeSource,
    /strip Google Workspace, Gmail, OAuth,[\s\S]{0,220}only to the downstream wrapper process; they are not[\s\S]{0,120}gateway or Vite process/u,
  );
});

test('strips ambient Google provider material from both gateway and web children', () => {
  const providerNames = [
    ['ACTIONPROXY', 'GOOGLE', 'OAUTH', 'CLIENT', 'ID'].join('_'),
    ['ACTIONPROXY', 'GOOGLE', 'OAUTH', 'CLIENT', 'SECRET'].join('_'),
    ['GMAIL', 'DRAFT', 'BODY'].join('_'),
    ['GOOGLE', 'APPLICATION', 'CREDENTIALS'].join('_'),
    googleClientIdName,
    googleClientSecretName,
    ['USER', 'GOOGLE', 'EMAIL'].join('_'),
    ['WORKSPACE', 'MCP', 'CREDENTIALS', 'DIR'].join('_'),
    ['ALLOWED', 'FILE', 'DIRS'].join('_'),
    ['OAUTHLIB', 'INSECURE', 'TRANSPORT'].join('_'),
  ];
  const canary = ['provider', 'material', 'canary'].join('-');
  const environment = Object.fromEntries(providerNames.map((name) => [name, `${canary}-${name}`]));
  environment.ACTIONPROXY_PORT = '18787';
  environment.PATH = '/test/bin';

  const isolated = isolateGoogleWorkspaceDemoEnvironment(environment);
  for (const name of providerNames) assert.equal(isolated[name], undefined);
  assert.equal(isolated.ACTIONPROXY_PORT, undefined);
  assert.equal(isolated.PATH, '/test/bin');

  const [gateway] = devProcessSpecs(
    ['--server-only', '--google-workspace-demo'],
    environment,
  );
  const [web] = devProcessSpecs(['--web-only', '--google-workspace-demo'], environment);
  for (const child of [gateway, web]) {
    for (const name of providerNames) assert.equal(child.env[name], undefined);
    assert.doesNotMatch(JSON.stringify(child.env), new RegExp(canary, 'u'));
  }
  assert.equal(gateway.env.ACTIONPROXY_PORT, '8787');
  assert.equal(gateway.env.ACTIONPROXY_HOST, '127.0.0.1');
  assert.equal(gateway.env.ACTIONPROXY_AUTH_MODE, 'none');
  assert.equal(gateway.env.ACTIONPROXY_DISABLE_LOCAL_ENV_FILES, 'true');
  assert.equal(gateway.env.ACTIONPROXY_EMAIL_TRANSPORT, 'outbox');
  assert.equal(gateway.env.ACTIONPROXY_STORAGE, 'memory');
  assert.equal(gateway.env.ACTIONPROXY_LOCAL_EXECUTION, 'disabled');
  assert.equal(gateway.env.ACTIONPROXY_POLICY_PATH, 'examples/google-workspace-mcp-demo/actionproxy.policy.yaml');
  assert.equal(gateway.env.ACTIONPROXY_DATA_DIR, '.actionproxy/google-workspace-mcp/actionproxy-data');
  assert.equal(web.env.ACTIONPROXY_PORT, undefined);
});

test('prevents server config from reloading provider, database, or channel canaries from repo env files', (context) => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'actionproxy-google-config-'));
  context.after(() => rmSync(temporaryRoot, { force: true, recursive: true }));
  mkdirSync(join(temporaryRoot, 'apps', 'server'), { recursive: true });
  writeFileSync(join(temporaryRoot, 'pnpm-workspace.yaml'), 'packages: []\n');
  writeFileSync(join(temporaryRoot, 'apps', 'server', 'package.json'), '{"private":true}\n');

  const databaseName = ['DATABASE', 'URL'].join('_');
  const slackName = ['ACTIONPROXY', 'SLACK', 'BOT', 'TOKEN'].join('_');
  const smtpName = ['ACTIONPROXY', 'EMAIL', 'SMTP', 'PASSWORD'].join('_');
  const providerCanary = ['repo', 'provider', 'canary'].join('-');
  const databaseCanary = ['repo', 'database', 'canary'].join('-');
  const slackCanary = ['repo', 'channel', 'canary'].join('-');
  const smtpCanary = ['repo', 'smtp', 'canary'].join('-');
  writeFileSync(
    join(temporaryRoot, '.env.local'),
    [
      `${googleClientIdName}=${providerCanary}`,
      `${googleClientSecretName}=${providerCanary}`,
      `${databaseName}=${databaseCanary}`,
      `${slackName}=${slackCanary}`,
      `${smtpName}=${smtpCanary}`,
      'ACTIONPROXY_PORT=19999',
      '',
    ].join('\n'),
    { mode: 0o600 },
  );

  const [gateway] = devProcessSpecs(['--server-only', '--google-workspace-demo'], {
    PATH: process.env.PATH ?? '',
  });
  const configUrl = pathToFileURL(join(repoRoot, 'apps', 'server', 'src', 'config.ts')).href;
  const probe = [
    `import { loadConfig } from ${JSON.stringify(configUrl)};`,
    'const config = loadConfig();',
    `console.log(JSON.stringify({ config, provider: process.env[${JSON.stringify(googleClientSecretName)}], database: process.env[${JSON.stringify(databaseName)}], slack: process.env[${JSON.stringify(slackName)}], smtp: process.env[${JSON.stringify(smtpName)}] }));`,
  ].join('\n');
  const tsxLoader = pathToFileURL(join(repoRoot, 'apps', 'server', 'node_modules', 'tsx', 'dist', 'loader.mjs')).href;
  const result = spawnSync(process.execPath, ['--import', tsxLoader, '--eval', probe], {
    cwd: temporaryRoot,
    encoding: 'utf8',
    env: gateway.env,
    timeout: 10_000,
  });

  assert.equal(result.status, 0, result.stderr);
  const observed = JSON.parse(result.stdout.trim());
  assert.equal(observed.provider, undefined);
  assert.equal(observed.database, undefined);
  assert.equal(observed.slack, undefined);
  assert.equal(observed.smtp, undefined);
  assert.equal(observed.config.port, 8787);
  assert.equal(observed.config.host, '127.0.0.1');
  assert.equal(observed.config.storage.mode, 'memory');
  assert.equal(observed.config.storage.databaseUrl, undefined);
  assert.equal(observed.config.slack.botToken, undefined);
  assert.equal(observed.config.email.smtp.password, undefined);
  assert.equal(observed.config.email.transport, 'outbox');
  assert.doesNotMatch(result.stdout, new RegExp([providerCanary, databaseCanary, slackCanary, smtpCanary].join('|'), 'u'));
});

test('keeps the public Google reference sources free of credential material', () => {
  const sourceNames = [
    '.env.example',
    'README.md',
    'actionproxy.mcp.yaml',
    'actionproxy.policy.yaml',
    'demo-support.mjs',
    'google-workspace-mcp-demo.test.mjs',
    'package.json',
    'run-gmail-draft-test.mjs',
  ];
  const forbiddenPatterns = [
    /-----BEGIN [A-Z ]+PRIVATE KEY-----/u,
    /AIza[0-9A-Za-z_-]{30,}/u,
    /ya29\.[0-9A-Za-z._-]{10,}/u,
    /sk-[0-9A-Za-z_-]{20,}/u,
    /gh[opusr]_[0-9A-Za-z]{20,}/u,
    /[0-9]{8,}-[0-9A-Za-z_-]{20,}\.apps\.googleusercontent\.com/u,
  ];

  for (const sourceName of sourceNames) {
    const source = readFileSync(join(demoDir, sourceName), 'utf8');
    for (const pattern of forbiddenPatterns) {
      assert.doesNotMatch(source, pattern, `${sourceName} contains credential-shaped material`);
    }
    for (const line of source.split(/\r?\n/u)) {
      if (!line.startsWith(`${googleClientSecretName}=`)) continue;
      const value = line.slice(googleClientSecretName.length + 1).trim();
      assert.ok(['', '...', '<...>'].includes(value), `${sourceName} contains a populated Google secret assignment`);
    }
  }
});

test('shows offline help without reading secrets, contacting Google, or echoing environment canaries', () => {
  const googleSecretName = ['GOOGLE', 'OAUTH', 'CLIENT', 'SECRET'].join('_');
  const secretCanary = ['offline', 'help', 'secret', 'canary'].join('-');
  const result = spawnSync(process.execPath, [runnerPath, '--help'], {
    cwd: demoDir,
    encoding: 'utf8',
    env: {
      ...process.env,
      GOOGLE_OAUTH_CLIENT_ID: secretCanary,
      [googleSecretName]: secretCanary,
    },
    timeout: 5_000,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Usage: corepack pnpm demo:gmail-mcp/u);
  assert.match(result.stdout, /--allow-download/u);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, new RegExp(secretCanary, 'u'));
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /https:\/\/(?:accounts|gmail)\.google\.com/u);
});

function fixtureGetJson({ attempts, events }) {
  return async (pathname) => {
    if (pathname.includes('/execution-attempts')) return { attempts };
    if (pathname.startsWith('/v1/audit?')) return { events };
    throw new Error(`Unexpected fixture path: ${pathname}`);
  };
}

function event(toolCallId, type) {
  return { toolCallId, type };
}

function fakeChildProcess(onSignal, signals) {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  child.kill = (signal) => {
    signals.push(signal);
    onSignal(signal, child);
    return true;
  };
  return child;
}

function finishFakeChild(child, signal) {
  child.signalCode = signal;
  child.emit('exit', null, signal);
}

function successfulAttempt() {
  return { outcome: { status: 'succeeded' }, state: 'succeeded' };
}

function mcpToolCall({ createdAt, id, input, toolName = 'draft_gmail_message' }) {
  return {
    createdAt,
    id,
    input,
    metadata: { mcpTool: toolName, source: 'mcp-wrapper' },
  };
}

function mcpError(text) {
  return { content: [{ text, type: 'text' }], isError: true };
}

function listenOnLoopback(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: 0 }, resolve);
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

function sourceBetween(start, end) {
  const startIndex = runnerSource.indexOf(start);
  const endIndex = runnerSource.indexOf(end, startIndex + start.length);
  assert.notEqual(startIndex, -1, `Runner source is missing ${start}`);
  assert.notEqual(endIndex, -1, `Runner source is missing ${end}`);
  return runnerSource.slice(startIndex, endIndex);
}

function matches(value, pattern) {
  return [...value.matchAll(pattern)].length;
}

function gatewayPolicySummary() {
  return {
    defaultRule: { decision: 'require_approval' },
    rules: [
      { decision: 'allow', matchType: 'exact', pattern: 'search_gmail_messages' },
      { decision: 'require_approval', matchType: 'exact', pattern: 'draft_gmail_message' },
      { decision: 'deny', matchType: 'exact', pattern: 'send_gmail_message' },
    ],
    version: 1,
  };
}

function mode(filePath) {
  return lstatSync(filePath).mode & 0o777;
}
