#!/usr/bin/env node
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import {
  OUTER_APPROVAL_TIMEOUT_MS,
  OUTER_DOWNSTREAM_TIMEOUT_MS,
  WORKSPACE_MCP_SPEC,
  WORKSPACE_MCP_VERSION,
  WORKSPACE_MCP_WHEEL_SHA256,
  assertAuditChainValid,
  assertExpectedGatewayPolicy,
  assertExactlyOneSuccessfulExecution,
  assertLoopbackPortAvailable,
  assertNoExecutionBeforeApproval,
  assertSelfTarget,
  assertTerminalWithoutDispatch,
  buildWrapperEnvironment,
  callWithSingleGoogleAuthenticationRetry,
  findExactCurrentMcpCall,
  normalizeLoopbackApiUrl,
  normalizeLoopbackBrowserUrl,
  preparePrivateRuntime,
  redactKnownSecrets,
  terminateChildProcessTree,
} from './demo-support.mjs';

const demoDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(demoDir, '../..');
const envPath = path.join(demoDir, '.env.local');
const wrapperPath = path.join(repoRoot, 'packages/mcp-wrapper/dist/index.js');
const configPath = path.join(demoDir, 'actionproxy.mcp.yaml');
const options = parseArguments(process.argv.slice(2));
let diagnosticEnvironment = process.env;
let activeTerminal;
let activePendingApproval;
let receivedShutdownSignal;

if (options.help) {
  printHelp();
} else {
  await run().catch((error) => {
    if (receivedShutdownSignal) return;
    const message = error instanceof Error ? error.message : 'Unknown operational failure.';
    console.error(`Google Workspace MCP proof failed: ${redactKnownSecrets(message, diagnosticEnvironment)}`);
    process.exitCode = 1;
  });
}

async function run() {
  const previousUmask = process.umask(0o077);
  const wrapperProcessGroup = process.platform !== 'win32';
  let wrapper;
  let wrapperShutdown;
  let umaskRestored = false;
  const restoreUmask = () => {
    if (umaskRestored) return;
    process.umask(previousUmask);
    umaskRestored = true;
  };
  const stopWrapper = () => {
    if (!wrapper) return Promise.resolve();
    wrapperShutdown ??= terminateChildProcessTree(wrapper, {
      graceMs: 5_000,
      processGroup: wrapperProcessGroup,
    });
    return wrapperShutdown;
  };
  const handleShutdownSignal = (signal) => {
    if (receivedShutdownSignal) return;
    receivedShutdownSignal = signal;
    activeTerminal?.close();
    void stopWrapper()
      .catch(() => undefined)
      .then(() => cancelPendingApprovalOnShutdown())
      .finally(() => {
        restoreUmask();
        process.exit(signal === 'SIGINT' ? 0 : 143);
      });
  };
  const handleInterrupt = () => handleShutdownSignal('SIGINT');
  const handleTerminate = () => handleShutdownSignal('SIGTERM');
  process.once('SIGINT', handleInterrupt);
  process.once('SIGTERM', handleTerminate);
  try {
    const runtime = preparePrivateRuntime({ envPath, environment: process.env, repoRoot });
    const environment = runtime.environment;
    diagnosticEnvironment = environment;
    const baseUrl = normalizeLoopbackApiUrl(environment.ACTIONPROXY_BASE_URL ?? 'http://127.0.0.1:8787');
    const approvalUrl = normalizeLoopbackBrowserUrl(
      environment.ACTIONPROXY_APPROVAL_URL ??
        (environment.ACTIONPROXY_BASE_URL ? `${baseUrl}/app#/approvals` : 'http://127.0.0.1:5173/#/approvals'),
    );
    environment.ACTIONPROXY_BASE_URL = baseUrl;

    const identity = validateEnvironment(environment);
    assertWrapperBuilt();
    assertCommandAvailable('uvx', environment.PATH);
    await assertActionProxyReady(baseUrl);
    assertExpectedGatewayPolicy(await getJson(baseUrl, '/v1/policy/summary'));
    await assertLoopbackPortAvailable(Number(environment.WORKSPACE_MCP_PORT));
    await confirmPinnedDependency(options);

    console.log('ActionProxy Google Workspace MCP proof');
    console.log(`Downstream: ${WORKSPACE_MCP_SPEC} (pinned)`);
    console.log('Scope: one test mailbox; draft recipient is locked to that same mailbox');
    console.log('Provider results and credentials are withheld from terminal output');
    console.log('Starting the local MCP wrapper…');

    wrapper = spawn(wrapperPath, ['wrap', '--config', configPath], {
      cwd: repoRoot,
      detached: wrapperProcessGroup,
      env: buildWrapperEnvironment(environment),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    // The wrapper already drains downstream stderr. Its own stderr is also
    // intentionally discarded so a third-party failure cannot echo tokens,
    // mailbox content, or credential paths into an ordinary terminal log.
    wrapper.stderr.resume();

    const peer = new JsonRpcPeer(wrapper.stdout, wrapper.stdin);
    peer.start();

    await peer.request('initialize', {
      capabilities: {},
      clientInfo: { name: 'actionproxy-google-workspace-mcp-demo', version: '0.1.1' },
      protocolVersion: '2025-06-18',
    }, OUTER_DOWNSTREAM_TIMEOUT_MS);
    peer.notify('notifications/initialized', {});

    const listed = await peer.request('tools/list', {}, OUTER_DOWNSTREAM_TIMEOUT_MS);
    const toolNames = (listed.tools ?? []).map((tool) => tool.name).sort();
    requireTools(toolNames, ['search_gmail_messages', 'draft_gmail_message']);
    recordDependencyReady(runtime.dataDir);
    console.log('✓ Required Gmail search and draft tools discovered');

    const sessionTag = crypto.randomUUID().slice(0, 8);
    const proof = createProofInputs(environment, identity, sessionTag);

    const searchCall = await callAllowedSearch(peer, baseUrl, proof.searchQuery, identity.user);
    console.log(`✓ Read-only search executed once (${searchCall.id}; provider result withheld)`);

    const approved = await callApprovedDraft(peer, {
      approvalUrl,
      autoApprove: options.autoApprove,
      baseUrl,
      input: proof.approvedDraft,
    });
    console.log(`✓ Draft held with zero attempts, then executed exactly once (${approved.toolCall.id})`);

    const rejected = await callRejectedDraft(peer, baseUrl, proof.rejectedDraft);
    console.log(`✓ Second draft rejected with no downstream dispatch (${rejected.toolCall.id})`);

    const cancelled = await callCancelledDraft(peer, baseUrl, proof.cancelledDraft);
    console.log(`✓ Third draft cancelled with no downstream dispatch (${cancelled.toolCall.id})`);

    if (toolNames.includes('send_gmail_message')) {
      const denied = await callDeniedSend(peer, baseUrl, proof.deniedSend);
      console.log(`✓ Live send denied by policy with no downstream dispatch (${denied.id})`);
    } else {
      const denied = await submitDeniedSendBoundary(baseUrl, proof.deniedSend);
      console.log(`✓ Send tool withheld by gmail:drafts; a real ActionProxy send proposal was denied with no dispatch (${denied.id})`);
    }

    const verification = await assertAuditChainValid((pathname) => getJson(baseUrl, pathname));
    console.log(`✓ Local audit hash chain verified (${verification.checked ?? 'all'} events checked)`);
    console.log('\nGoogle Workspace MCP proof passed.');
    console.log('Expected provider effect: exactly one draft in the test account and no sent email.');
    console.log('Delete that draft after inspection. Remove .actionproxy/google-workspace-mcp to delete local OAuth/cache state.');
  } finally {
    process.off('SIGINT', handleInterrupt);
    process.off('SIGTERM', handleTerminate);
    activeTerminal?.close();
    await stopWrapper();
    restoreUmask();
  }
}

async function callAllowedSearch(peer, baseUrl, query, userEmail) {
  console.log('\n[1/5] Run a narrow, read-only Gmail search');
  const callStartedAt = Date.now();
  const input = {
    page_size: 3,
    query,
    user_google_email: userEmail,
  };
  const excludedToolCallIds = [];
  let successfulCallStartedAt = callStartedAt;
  const { result } = await callWithSingleGoogleAuthenticationRetry({
    call: () => peer.request(
      'tools/call',
      { arguments: input, name: 'search_gmail_messages' },
      OUTER_DOWNSTREAM_TIMEOUT_MS,
    ),
    onAuthenticationRequired: async () => {
      const authenticationAttempt = await waitForRecentToolCall(
        baseUrl,
        'search_gmail_messages',
        callStartedAt,
        input,
      );
      excludedToolCallIds.push(authenticationAttempt.id);
      await waitForGoogleAuthentication();
      successfulCallStartedAt = Date.now();
    },
  });
  assertSuccessfulMcpResult('search_gmail_messages', result);
  const toolCall = await waitForRecentToolCall(
    baseUrl,
    'search_gmail_messages',
    successfulCallStartedAt,
    input,
    excludedToolCallIds,
  );
  await assertExactlyOneSuccessfulExecution((pathname) => getJson(baseUrl, pathname), toolCall.id);
  return toolCall;
}

async function callApprovedDraft(peer, { approvalUrl, autoApprove, baseUrl, input }) {
  console.log('\n[2/5] Hold one Gmail draft for human approval');
  const callStartedAt = Date.now();
  const draftCall = peer.request(
    'tools/call',
    { arguments: input, name: 'draft_gmail_message' },
    OUTER_APPROVAL_TIMEOUT_MS,
  );
  const pending = await waitForPendingApproval(baseUrl, 'draft_gmail_message', callStartedAt, input);
  trackPendingApproval(baseUrl, pending.approval.id);
  try {
    await assertNoExecutionBeforeApproval((pathname) => getJson(baseUrl, pathname), pending.toolCall.id);
    console.log('✓ Action paused; zero execution attempts exist');

    if (autoApprove) {
      await decideApproval(baseUrl, pending.approval.id, 'approve');
      console.log('Automation-only flag approved the exact proposal. This does not count as manual acceptance evidence.');
    } else {
      console.log(`Open ${approvalUrl}`);
      console.log(`Review approval ${pending.approval.id} and choose “Approve exact proposal”. Do not edit the JSON.`);
      console.log('Waiting up to five minutes…');
    }

    const result = await draftCall;
    assertSuccessfulMcpResult('draft_gmail_message', result);
    await assertExactlyOneSuccessfulExecution((pathname) => getJson(baseUrl, pathname), pending.toolCall.id);
    return pending;
  } finally {
    if (!receivedShutdownSignal) clearTrackedPendingApproval(pending.approval.id);
  }
}

async function callRejectedDraft(peer, baseUrl, input) {
  console.log('\n[3/5] Prove rejection never reaches Google');
  const callStartedAt = Date.now();
  const call = peer.request(
    'tools/call',
    { arguments: input, name: 'draft_gmail_message' },
    OUTER_APPROVAL_TIMEOUT_MS,
  );
  const pending = await waitForPendingApproval(baseUrl, 'draft_gmail_message', callStartedAt, input);
  trackPendingApproval(baseUrl, pending.approval.id);
  try {
    await assertNoExecutionBeforeApproval((pathname) => getJson(baseUrl, pathname), pending.toolCall.id);
    await decideApproval(baseUrl, pending.approval.id, 'reject');
    const result = await call;
    assertDeniedMcpResult('rejected draft', result);
    await assertTerminalWithoutDispatch(
      (pathname) => getJson(baseUrl, pathname),
      pending.toolCall.id,
      'approval.rejected',
    );
    return pending;
  } finally {
    if (!receivedShutdownSignal) clearTrackedPendingApproval(pending.approval.id);
  }
}

async function callCancelledDraft(peer, baseUrl, input) {
  console.log('\n[4/5] Prove cancellation clears a pending proposal');
  const callStartedAt = Date.now();
  const call = peer.request(
    'tools/call',
    { arguments: input, name: 'draft_gmail_message' },
    OUTER_APPROVAL_TIMEOUT_MS,
  );
  const pending = await waitForPendingApproval(baseUrl, 'draft_gmail_message', callStartedAt, input);
  trackPendingApproval(baseUrl, pending.approval.id);
  try {
    await assertNoExecutionBeforeApproval((pathname) => getJson(baseUrl, pathname), pending.toolCall.id);
    await decideApproval(baseUrl, pending.approval.id, 'cancel');
    const result = await call;
    assertDeniedMcpResult('cancelled draft', result);
    await assertTerminalWithoutDispatch(
      (pathname) => getJson(baseUrl, pathname),
      pending.toolCall.id,
      'approval.cancelled',
    );
    return pending;
  } finally {
    if (!receivedShutdownSignal) clearTrackedPendingApproval(pending.approval.id);
  }
}

async function callDeniedSend(peer, baseUrl, input) {
  console.log('\n[5/5] Prove live Gmail send is denied before dispatch');
  const callStartedAt = Date.now();
  const result = await peer.request(
    'tools/call',
    { arguments: input, name: 'send_gmail_message' },
    OUTER_DOWNSTREAM_TIMEOUT_MS,
  );
  assertDeniedMcpResult('send_gmail_message', result);
  const toolCall = await waitForRecentToolCall(baseUrl, 'send_gmail_message', callStartedAt, input);
  await assertTerminalWithoutDispatch((pathname) => getJson(baseUrl, pathname), toolCall.id, 'policy.deny');
  return toolCall;
}

async function submitDeniedSendBoundary(baseUrl, input) {
  console.log('\n[5/5] Submit a real send proposal to ActionProxy without broadening Google permissions');
  const result = await postJson(baseUrl, '/v1/tool-calls', {
    action: {
      executionMode: 'external_grant',
      operation: { kind: 'external_send', name: 'send_gmail_message' },
      protocol: 'mcp',
      resources: [{ name: 'send_gmail_message', type: 'mcp.tool' }],
      source: { name: 'google-workspace', type: 'mcp_server' },
    },
    agentId: 'actionproxy-google-workspace-mcp-demo',
    input,
    reason: 'Verify that ActionProxy denies the Gmail send boundary before downstream dispatch.',
    requestedBy: 'google-workspace-mcp-demo@example.local',
    toolName: 'send_gmail_message',
  });
  if (result.decision !== 'deny' || result.status !== 'blocked' || result.toolCall?.status !== 'blocked') {
    throw new Error('The real ActionProxy send proposal was not blocked by the exact deny policy.');
  }
  await assertTerminalWithoutDispatch((pathname) => getJson(baseUrl, pathname), result.id, 'policy.deny');
  return result;
}

function createProofInputs(environment, identity, sessionTag) {
  const subjectBase = cleanSyntheticText(
    environment.GMAIL_DRAFT_SUBJECT || 'ActionProxy local Gmail MCP draft test',
    'GMAIL_DRAFT_SUBJECT',
    160,
  );
  const body = cleanSyntheticText(
    environment.GMAIL_DRAFT_BODY || 'This draft was created only after ActionProxy approval.',
    'GMAIL_DRAFT_BODY',
    4000,
  );
  const approvedDraft = {
    body,
    subject: `${subjectBase} [${sessionTag}]`,
    to: identity.recipient,
    user_google_email: identity.user,
  };
  return {
    approvedDraft,
    cancelledDraft: { ...approvedDraft, subject: `${subjectBase} [cancel-${sessionTag}]` },
    deniedSend: { ...approvedDraft, subject: `${subjectBase} [deny-${sessionTag}]` },
    rejectedDraft: { ...approvedDraft, subject: `${subjectBase} [reject-${sessionTag}]` },
    searchQuery: cleanSyntheticText(
      `${environment.GMAIL_SEARCH_QUERY || `subject:"${subjectBase}" newer_than:1d`} "actionproxy-proof-${sessionTag}"`,
      'GMAIL_SEARCH_QUERY',
      500,
    ),
  };
}

async function waitForPendingApproval(baseUrl, toolName, callStartedAt, expectedInput) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const [{ approvals }, { toolCalls }] = await Promise.all([
      getJson(baseUrl, '/v1/approvals/pending'),
      getJson(baseUrl, `/v1/tool-calls?limit=100&status=pending_approval&toolName=${encodeURIComponent(toolName)}`),
    ]);
    const toolCall = findExactCurrentMcpCall(toolCalls, { expectedInput, startedAt: callStartedAt, toolName });
    const approval = toolCall ? approvals.find((candidate) => candidate.toolCallId === toolCall.id) : undefined;
    if (approval && toolCall) return { approval, toolCall };
    await sleep(500);
  }
  throw new Error(`Timed out waiting for the ${toolName} approval proposal.`);
}

async function waitForRecentToolCall(
  baseUrl,
  toolName,
  callStartedAt,
  expectedInput,
  excludedToolCallIds = [],
) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const { toolCalls } = await getJson(
      baseUrl,
      `/v1/tool-calls?limit=100&toolName=${encodeURIComponent(toolName)}`,
    );
    const toolCall = findExactCurrentMcpCall(toolCalls, {
      excludedToolCallIds,
      expectedInput,
      startedAt: callStartedAt,
      toolName,
    });
    if (toolCall) return toolCall;
    await sleep(250);
  }
  throw new Error(`No current-session ActionProxy record appeared for ${toolName}.`);
}

async function decideApproval(baseUrl, approvalId, decision) {
  const bodies = {
    approve: {
      approvedBy: 'google-workspace-mcp-demo@example.local',
      inputDecision: { mode: 'original' },
      note: 'Automation-only exact-proposal approval for the local Google Workspace MCP proof.',
    },
    cancel: {
      cancelledBy: 'google-workspace-mcp-demo@example.local',
      reason: 'Local cancellation evidence; no provider execution is permitted.',
    },
    reject: {
      reason: 'Local rejection evidence; no provider execution is permitted.',
      rejectedBy: 'google-workspace-mcp-demo@example.local',
    },
  };
  const endpoint = decision === 'approve' ? 'approve' : decision;
  const response = await fetch(`${baseUrl}/v1/approvals/${encodeURIComponent(approvalId)}/${endpoint}`, {
    body: JSON.stringify(bodies[decision]),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  });
  if (!response.ok) throw new Error(`ActionProxy ${decision} request failed with HTTP ${response.status}.`);
}

function trackPendingApproval(baseUrl, approvalId) {
  activePendingApproval = { baseUrl, id: approvalId };
}

function clearTrackedPendingApproval(approvalId) {
  if (activePendingApproval?.id === approvalId) activePendingApproval = undefined;
}

async function cancelPendingApprovalOnShutdown() {
  const pending = activePendingApproval;
  activePendingApproval = undefined;
  if (!pending) return;
  try {
    await fetch(`${pending.baseUrl}/v1/approvals/${encodeURIComponent(pending.id)}/cancel`, {
      body: JSON.stringify({
        cancelledBy: 'google-workspace-mcp-demo@example.local',
        reason: 'The local Google Workspace MCP proof was interrupted before approval completed.',
      }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
      signal: AbortSignal.timeout(2_000),
    });
  } catch {
    // Process-tree cleanup remains authoritative; this is best-effort queue hygiene.
  }
}

async function assertActionProxyReady(baseUrl) {
  try {
    const health = await getJson(baseUrl, '/health');
    if (!health.ok) throw new Error('not healthy');
  } catch {
    throw new Error(`ActionProxy is not reachable on the configured loopback origin. Start it with: corepack pnpm dev:proxy:gmail-mcp`);
  }
}

function assertWrapperBuilt() {
  if (fs.existsSync(wrapperPath)) return;
  throw new Error('MCP wrapper is not built. Run: corepack pnpm --filter @actionproxy/mcp-wrapper build');
}

function assertCommandAvailable(command, pathValue) {
  const executable = String(pathValue ?? '')
    .split(path.delimiter)
    .map((directory) => path.join(directory, command))
    .find((candidate) => {
      try {
        fs.accessSync(candidate, fs.constants.X_OK);
        return true;
      } catch {
        return false;
      }
    });
  if (!executable) {
    throw new Error('uvx is not installed. Install uv from https://docs.astral.sh/uv/ and rerun this command.');
  }
}

async function confirmPinnedDependency(parsedOptions) {
  if (!parsedOptions.allowDownload) {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      throw new Error(`Launching pinned ${WORKSPACE_MCP_SPEC} requires consent for possible network/download activity. Rerun in a terminal or add --allow-download after review.`);
    }
    console.log(`\nThe next step launches uvx for ${WORKSPACE_MCP_SPEC}.`);
    console.log('uvx may contact package indexes and resolve transitive Python dependencies on every launch, even when its local cache is warm.');
    console.log('Downloaded state is confined under .actionproxy/google-workspace-mcp and removable with that directory.');
    const terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
    activeTerminal = terminal;
    let answer;
    try {
      answer = await terminal.question('Allow this third-party network/download activity for this launch? [y/N] ');
    } finally {
      terminal.close();
      if (activeTerminal === terminal) activeTerminal = undefined;
    }
    if (!/^y(?:es)?$/i.test(answer.trim())) throw new Error('Dependency preparation cancelled; nothing was downloaded by this run.');
  }
}

async function waitForGoogleAuthentication() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Google authentication is required. Rerun this proof in an interactive terminal, complete the browser flow, and retry.');
  }
  console.log('\nGoogle authentication is required for the dedicated test mailbox.');
  console.log('Complete the Google consent flow in the browser. Provider URLs and account details remain withheld here.');
  const terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
  activeTerminal = terminal;
  try {
    await terminal.question('After the browser confirms success, press Enter to retry the same read-only search once. ');
  } finally {
    terminal.close();
    if (activeTerminal === terminal) activeTerminal = undefined;
  }
}

function recordDependencyReady(dataDir) {
  const markerPath = path.join(dataDir, 'dependency-ready.json');
  const temporaryPath = path.join(dataDir, `.dependency-ready.${process.pid}.${crypto.randomUUID()}.tmp`);
  const contents = `${JSON.stringify({
    package: 'workspace-mcp',
    schemaVersion: 'actionproxy.google-mcp-dependency.v1',
    version: WORKSPACE_MCP_VERSION,
    wheelSha256: WORKSPACE_MCP_WHEEL_SHA256,
  }, null, 2)}\n`;
  const descriptor = fs.openSync(temporaryPath, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, contents, 'utf8');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporaryPath, markerPath);
  fs.chmodSync(markerPath, 0o600);
}

function validateEnvironment(environment) {
  const missing = ['GOOGLE_OAUTH_CLIENT_ID', 'GOOGLE_OAUTH_CLIENT_SECRET', 'USER_GOOGLE_EMAIL'].filter(
    (key) => typeof environment[key] !== 'string' || !environment[key].trim(),
  );
  if (missing.length) {
    throw new Error('Google OAuth setup is incomplete. Copy examples/google-workspace-mcp-demo/.env.example to .env.local and fill all required values.');
  }
  for (const name of ['GOOGLE_OAUTH_CLIENT_ID', 'GOOGLE_OAUTH_CLIENT_SECRET']) {
    const value = environment[name];
    if (value.length > 8192 || value.trim() !== value || /\p{Cc}/u.test(value)) {
      throw new Error(`${name} is invalid.`);
    }
  }
  return assertSelfTarget(environment.USER_GOOGLE_EMAIL, environment.GMAIL_DRAFT_TO);
}

function requireTools(toolNames, requiredTools) {
  const missing = requiredTools.filter((toolName) => !toolNames.includes(toolName));
  if (missing.length) {
    throw new Error(`The pinned downstream server did not expose the required Gmail proof tools: ${missing.join(', ')}.`);
  }
}

async function getJson(baseUrl, pathname) {
  const response = await fetch(`${baseUrl}${pathname}`);
  if (!response.ok) throw new Error(`ActionProxy request failed for ${pathname.split('?')[0]} with HTTP ${response.status}.`);
  return response.json();
}

async function postJson(baseUrl, pathname, body) {
  const response = await fetch(`${baseUrl}${pathname}`, {
    body: JSON.stringify(body),
    headers: { 'content-type': 'application/json' },
    method: 'POST',
  });
  if (!response.ok) throw new Error(`ActionProxy request failed for ${pathname} with HTTP ${response.status}.`);
  return response.json();
}

function assertSuccessfulMcpResult(toolName, result) {
  if (!result || result.isError === true) throw new Error(`${toolName} returned an error. Provider details were withheld.`);
}

function assertDeniedMcpResult(label, result) {
  if (result?.isError !== true) throw new Error(`${label} was expected to stop before downstream dispatch.`);
}

function cleanSyntheticText(value, name, maximumLength) {
  if (typeof value !== 'string' || !value.trim() || value.length > maximumLength || /\p{Cc}/u.test(value)) {
    throw new Error(`${name} must be nonempty synthetic test text no longer than ${maximumLength} characters.`);
  }
  return value.trim();
}

function parseArguments(args) {
  const known = new Set(['--allow-download', '--auto-approve', '--help', '--manual-approval']);
  const unknown = args.find((arg) => !known.has(arg));
  if (unknown) throw new Error(`Unknown argument: ${unknown}. Run with --help for usage.`);
  if (args.includes('--auto-approve') && args.includes('--manual-approval')) {
    throw new Error('--auto-approve and --manual-approval cannot be combined.');
  }
  return {
    allowDownload: args.includes('--allow-download'),
    autoApprove: args.includes('--auto-approve'),
    help: args.includes('--help'),
  };
}

function printHelp() {
  console.log(`Usage: corepack pnpm demo:gmail-mcp -- [options]

Options:
  --allow-download   Approve possible uvx network/download activity for this launch
  --auto-approve     Automation only: approve the exact first draft proposal through the API
  --manual-approval  Explicitly select the default human-review flow
  --help             Show this help

Default proof: narrow Gmail search, one manually approved self-addressed draft,
one rejected draft, one cancelled draft, denied live send, and audit verification.`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
        if (message.error) pending.reject(new Error('The local MCP wrapper returned a protocol error.'));
        else pending.resolve(message.result);
      }
    });
    this.input.once('error', () => this.failPending('The local MCP wrapper stream failed.'));
    this.input.once('close', () => this.failPending('The local MCP wrapper exited before the proof completed.'));
  }

  failPending(message) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error(message));
    }
    this.pending.clear();
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
        reject(new Error(`Timed out waiting for the local MCP ${method} response.`));
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
      if (headerEnd > 8192) throw new Error('Invalid local MCP frame header.');

      const header = this.buffer.subarray(0, headerEnd).toString('utf8');
      const matches = [...header.matchAll(/^content-length:\s*(\d+)\s*$/gimu)];
      if (matches.length !== 1) throw new Error('Invalid local MCP frame header.');
      const length = Number(matches[0][1]);
      if (!Number.isSafeInteger(length) || length < 0 || length > 8 * 1024 * 1024) {
        throw new Error('Invalid local MCP frame length.');
      }

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
