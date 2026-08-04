import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';

export const WORKSPACE_MCP_VERSION = '1.22.0';
export const WORKSPACE_MCP_SPEC = `workspace-mcp==${WORKSPACE_MCP_VERSION}`;
export const WORKSPACE_MCP_WHEEL_SHA256 = 'c17daecb5b3050f7e89019a1f364cf20e950ecadca9a705c1627387ebc987b21';
export const WORKSPACE_MCP_WHEEL_URL =
  `https://files.pythonhosted.org/packages/c1/84/d6ea7b10c3e4213036964e81d4bd32a868b44f70ea84d88c13dc1a886c84/` +
  `workspace_mcp-${WORKSPACE_MCP_VERSION}-py3-none-any.whl#sha256=${WORKSPACE_MCP_WHEEL_SHA256}`;
export const APPROVAL_TIMEOUT_MS = 300_000;
export const DOWNSTREAM_REQUEST_TIMEOUT_MS = 180_000;
export const OUTER_DOWNSTREAM_TIMEOUT_MS = 210_000;
export const OUTER_APPROVAL_TIMEOUT_MS = 510_000;

const PRIVATE_DIRECTORY_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const MAX_ENV_VALUE_LENGTH = 8192;
const EXECUTION_EVENT_TYPES = new Set([
  'execution_grant.created',
  'execution_grant.consumed',
  'execution.attempt_dispatched',
  'execution.attempt_completed',
  'receipt.outcome_recorded',
  'tool_call.executed',
]);
const WRAPPER_ENVIRONMENT_NAMES = [
  'ACTIONPROXY_BASE_URL',
  'ALLOWED_FILE_DIRS',
  'GOOGLE_MCP_CREDENTIALS_DIR',
  'GOOGLE_OAUTH_CLIENT_ID',
  'GOOGLE_OAUTH_CLIENT_SECRET',
  'HOME',
  'LANG',
  'LC_ALL',
  'OAUTHLIB_INSECURE_TRANSPORT',
  'PATH',
  'Path',
  'TEMP',
  'TMP',
  'TMPDIR',
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
];
const ENV_FILE_NAMES = new Set([
  'ACTIONPROXY_APPROVAL_URL',
  'ACTIONPROXY_BASE_URL',
  'GMAIL_DRAFT_BODY',
  'GMAIL_DRAFT_SUBJECT',
  'GMAIL_DRAFT_TO',
  'GMAIL_SEARCH_PAGE_SIZE',
  'GMAIL_SEARCH_QUERY',
  'GOOGLE_OAUTH_CLIENT_ID',
  'GOOGLE_OAUTH_CLIENT_SECRET',
  'USER_GOOGLE_EMAIL',
]);

export function preparePrivateRuntime({ repoRoot, envPath, environment = process.env }) {
  const loadedEnvironment = loadPrivateEnvFile(envPath, environment);
  const actionProxyRoot = path.resolve(repoRoot, '.actionproxy');
  const dataDir = path.join(actionProxyRoot, 'google-workspace-mcp');
  const credentialsDir = path.join(dataDir, 'credentials');
  const attachmentsDir = path.join(dataDir, 'attachments');
  const logsDir = path.join(dataDir, 'logs');
  const homeDir = path.join(dataDir, 'home');
  const tempDir = path.join(dataDir, 'tmp');
  const uvCacheDir = path.join(dataDir, 'uv-cache');
  const uvPythonDir = path.join(dataDir, 'uv-python');

  for (const directory of [
    actionProxyRoot,
    dataDir,
    credentialsDir,
    attachmentsDir,
    logsDir,
    homeDir,
    tempDir,
    uvCacheDir,
    uvPythonDir,
  ]) {
    ensurePrivateDirectory(directory);
  }

  const runtimeEnvironment = {
    ...loadedEnvironment,
    ALLOWED_FILE_DIRS: attachmentsDir,
    GOOGLE_MCP_CREDENTIALS_DIR: credentialsDir,
    HOME: homeDir,
    OAUTHLIB_INSECURE_TRANSPORT: '1',
    TMPDIR: tempDir,
    UV_CACHE_DIR: uvCacheDir,
    UV_NO_PROGRESS: '1',
    UV_PYTHON_INSTALL_DIR: uvPythonDir,
    WORKSPACE_ATTACHMENT_DIR: attachmentsDir,
    WORKSPACE_MCP_BASE_URI: 'http://127.0.0.1',
    WORKSPACE_MCP_CREDENTIALS_DIR: credentialsDir,
    WORKSPACE_MCP_HOST: '127.0.0.1',
    WORKSPACE_MCP_LOG_DIR: logsDir,
    WORKSPACE_MCP_PORT: '8000',
  };

  return {
    dataDir,
    environment: runtimeEnvironment,
    paths: {
      attachmentsDir,
      credentialsDir,
      homeDir,
      logsDir,
      tempDir,
      uvCacheDir,
      uvPythonDir,
    },
  };
}

export function buildWrapperEnvironment(environment) {
  const result = {};
  for (const name of WRAPPER_ENVIRONMENT_NAMES) {
    const value = environment[name];
    if (typeof value === 'string') result[name] = value;
  }
  return result;
}

export function loadPrivateEnvFile(filePath, environment = process.env) {
  const result = { ...environment };
  for (const name of ENV_FILE_NAMES) delete result[name];
  if (!fs.existsSync(filePath)) {
    throw new Error('The Google Workspace proof requires examples/google-workspace-mcp-demo/.env.local. Copy the provided .env.example first.');
  }

  protectPrivateFile(filePath);
  const seen = new Set();
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const match = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match || !ENV_FILE_NAMES.has(match[1])) continue;
    if (seen.has(match[1])) throw new Error(`Duplicate ${match[1]} entry in .env.local.`);
    seen.add(match[1]);
    const value = unquoteEnvValue(match[2].trim());
    validateEnvironmentValue(match[1], value);
    result[match[1]] = value;
  }
  return result;
}

export function findExactCurrentMcpCall(
  toolCalls,
  { excludedToolCallIds = [], expectedInput, startedAt, toolName },
) {
  if (!Array.isArray(toolCalls)) throw new Error('ActionProxy returned an invalid tool-call list.');
  const expectedCanonicalInput = canonicalJson(expectedInput);
  const excluded = new Set(excludedToolCallIds);
  const matches = toolCalls.filter((candidate) => {
    const createdAt = Date.parse(candidate?.createdAt);
    return Number.isFinite(createdAt) &&
      createdAt >= startedAt &&
      !excluded.has(candidate.id) &&
      candidate.metadata?.source === 'mcp-wrapper' &&
      candidate.metadata?.mcpTool === toolName &&
      canonicalJson(candidate.input) === expectedCanonicalInput;
  });
  if (matches.length > 1) {
    throw new Error(`Ambiguous current-session ${toolName} correlation; refusing to select or approve any proposal.`);
  }
  return matches[0];
}

export async function assertLoopbackPortAvailable(port) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error('Google OAuth callback port must be an integer from 1024 through 65535.');
  }
  await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', () => {
      reject(new Error(
        `Google OAuth callback port ${port} is occupied on 127.0.0.1. Stop the owning process (inspect with: lsof -nP -iTCP:${port} -sTCP:LISTEN), then rerun.`,
      ));
    });
    server.listen({ exclusive: true, host: '127.0.0.1', port }, () => {
      server.close((error) => {
        if (error) reject(new Error(`Could not release the Google OAuth callback port ${port} preflight.`));
        else resolve();
      });
    });
  });
}

export function isGoogleAuthenticationRequired(result) {
  if (result?.isError !== true || !Array.isArray(result.content)) return false;
  const text = result.content
    .map((item) => typeof item?.text === 'string' ? item.text : '')
    .join('\n')
    .toLowerCase();
  if (!text) return false;
  return text.includes('accounts.google.com') ||
    text.includes('authorization url') ||
    /(?:authentication|authenticate|authorization|oauth|credentials?)[\s\S]{0,120}(?:required|missing|not found|needed|complete|visit)/u.test(text) ||
    /(?:required|missing|not found|needed)[\s\S]{0,120}(?:authentication|authorization|oauth|credentials?)/u.test(text);
}

export async function callWithSingleGoogleAuthenticationRetry({ call, onAuthenticationRequired }) {
  if (typeof call !== 'function' || typeof onAuthenticationRequired !== 'function') {
    throw new Error('Google authentication retry requires explicit call and authentication handlers.');
  }

  const initialResult = await call();
  if (!isGoogleAuthenticationRequired(initialResult)) {
    return { result: initialResult, retried: false };
  }

  await onAuthenticationRequired(initialResult);
  const result = await call();
  if (isGoogleAuthenticationRequired(result)) {
    throw new Error(
      'Google authentication was still required after the single explicit retry. Rerun after confirming the browser callback completed.',
    );
  }
  return { result, retried: true };
}

export async function terminateChildProcessTree(
  child,
  { graceMs = 5_000, processGroup = false } = {},
) {
  if (!child) return;
  if (!Number.isSafeInteger(graceMs) || graceMs < 1 || graceMs > 30_000) {
    throw new Error('Child-process shutdown grace must be an integer from 1 through 30000 milliseconds.');
  }
  const groupId = processGroup && Number.isInteger(child.pid) && child.pid > 0
    ? child.pid
    : undefined;
  if (groupId ? !processGroupExists(groupId) : child.exitCode !== null || child.signalCode !== null) return;

  const gracefulExit = groupId
    ? waitForProcessGroupExit(groupId, graceMs)
    : waitForChildExit(child, graceMs);
  signalChildProcessTree(child, 'SIGTERM', processGroup);
  if (await gracefulExit) return;

  const forcedExit = groupId
    ? waitForProcessGroupExit(groupId, graceMs)
    : waitForChildExit(child, graceMs);
  signalChildProcessTree(child, 'SIGKILL', processGroup);
  if (!(await forcedExit)) {
    throw new Error('Local MCP wrapper process tree did not stop within the bounded shutdown window.');
  }
}

export function ensurePrivateDirectory(directory) {
  fs.mkdirSync(directory, { mode: PRIVATE_DIRECTORY_MODE, recursive: true });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('Google Workspace demo state path must be a real directory, not a symbolic link.');
  }
  fs.chmodSync(directory, PRIVATE_DIRECTORY_MODE);
}

export function protectPrivateFile(filePath) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('Google Workspace demo environment path must be a regular file, not a symbolic link.');
  }
  fs.chmodSync(filePath, PRIVATE_FILE_MODE);
}

export function assertSelfTarget(userEmail, draftTo) {
  const user = normalizeEmail(userEmail, 'USER_GOOGLE_EMAIL');
  const recipient = normalizeEmail(draftTo || user, 'GMAIL_DRAFT_TO');
  if (recipient !== user) {
    throw new Error('GMAIL_DRAFT_TO must match USER_GOOGLE_EMAIL. This Community proof only creates a draft in the test account for itself.');
  }
  return { recipient, user };
}

export function normalizeLoopbackApiUrl(value) {
  const url = normalizeLoopbackUrl(value, 'ACTIONPROXY_BASE_URL');
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new Error('ACTIONPROXY_BASE_URL must be a loopback HTTP origin without a path, query, or fragment.');
  }
  return url.origin;
}

export function normalizeLoopbackBrowserUrl(value) {
  return normalizeLoopbackUrl(value, 'ACTIONPROXY_APPROVAL_URL').toString();
}

export async function assertNoExecutionBeforeApproval(getJson, toolCallId) {
  const [{ attempts }, { events }] = await Promise.all([
    getJson(`/v1/tool-calls/${encodeURIComponent(toolCallId)}/execution-attempts`),
    getJson(`/v1/audit?limit=500&toolCallId=${encodeURIComponent(toolCallId)}`),
  ]);
  if (!Array.isArray(attempts) || attempts.length !== 0) {
    throw new Error(`Expected zero execution attempts before approval; observed ${Array.isArray(attempts) ? attempts.length : 'an invalid response'}.`);
  }
  const earlyEvent = Array.isArray(events)
    ? events.find((event) => event.toolCallId === toolCallId && EXECUTION_EVENT_TYPES.has(event.type))
    : undefined;
  if (earlyEvent) throw new Error(`Execution began before approval: ${earlyEvent.type}.`);
}

export async function assertExactlyOneSuccessfulExecution(getJson, toolCallId) {
  const [{ attempts }, { events }] = await Promise.all([
    getJson(`/v1/tool-calls/${encodeURIComponent(toolCallId)}/execution-attempts`),
    getJson(`/v1/audit?limit=500&toolCallId=${encodeURIComponent(toolCallId)}`),
  ]);
  if (!Array.isArray(attempts) || attempts.length !== 1) {
    throw new Error(`Expected exactly one execution attempt; observed ${Array.isArray(attempts) ? attempts.length : 'an invalid response'}.`);
  }
  if (attempts[0]?.state !== 'succeeded' || attempts[0]?.outcome?.status !== 'succeeded') {
    throw new Error('The single execution attempt did not finish with a known successful outcome.');
  }

  const requiredOnce = [
    'execution_grant.created',
    'execution_grant.consumed',
    'execution.attempt_dispatched',
    'execution.attempt_completed',
    'receipt.outcome_recorded',
    'tool_call.executed',
  ];
  assertEventCounts(events, toolCallId, Object.fromEntries(requiredOnce.map((type) => [type, 1])));
}

export async function assertTerminalWithoutDispatch(getJson, toolCallId, requiredEvent) {
  const [{ attempts }, { events }] = await Promise.all([
    getJson(`/v1/tool-calls/${encodeURIComponent(toolCallId)}/execution-attempts`),
    getJson(`/v1/audit?limit=500&toolCallId=${encodeURIComponent(toolCallId)}`),
  ]);
  if (!Array.isArray(attempts) || attempts.length !== 0) {
    throw new Error(`Expected no execution attempt for ${requiredEvent}; observed ${Array.isArray(attempts) ? attempts.length : 'an invalid response'}.`);
  }
  if (!Array.isArray(events) || !events.some((event) => event.toolCallId === toolCallId && event.type === requiredEvent)) {
    throw new Error(`Missing ${requiredEvent} audit evidence.`);
  }
  const dispatchEvent = events.find(
    (event) => event.toolCallId === toolCallId && EXECUTION_EVENT_TYPES.has(event.type),
  );
  if (dispatchEvent) throw new Error(`${requiredEvent} unexpectedly reached execution: ${dispatchEvent.type}.`);
}

export async function assertAuditChainValid(getJson) {
  const verification = await getJson('/v1/audit/verify');
  if (verification.valid !== true || (Array.isArray(verification.errors) && verification.errors.length > 0)) {
    throw new Error('The local ActionProxy audit hash chain did not verify.');
  }
  return verification;
}

export function assertExpectedGatewayPolicy(summary) {
  if (!summary || summary.version !== 1 || summary.defaultRule?.decision !== 'require_approval') {
    throw new Error('The running gateway does not have the Google proof fail-closed default policy.');
  }
  const expected = new Map([
    ['draft_gmail_message', 'require_approval'],
    ['search_gmail_messages', 'allow'],
    ['send_gmail_message', 'deny'],
  ]);
  for (const [pattern, decision] of expected) {
    const matches = Array.isArray(summary.rules)
      ? summary.rules.filter((rule) => rule.pattern === pattern && rule.matchType === 'exact')
      : [];
    if (matches.length !== 1 || matches[0].decision !== decision) {
      throw new Error(`The running gateway policy must map ${pattern} to ${decision} before this proof can start.`);
    }
  }
}

export function redactKnownSecrets(value, environment) {
  let redacted = String(value);
  for (const name of ['GOOGLE_OAUTH_CLIENT_ID', 'GOOGLE_OAUTH_CLIENT_SECRET']) {
    const secret = environment[name];
    if (typeof secret === 'string' && secret.length > 0) redacted = redacted.split(secret).join('[REDACTED]');
  }
  return redacted;
}

function assertEventCounts(events, toolCallId, expectedCounts) {
  if (!Array.isArray(events)) throw new Error('Audit endpoint returned an invalid events list.');
  const callEvents = events.filter((event) => event.toolCallId === toolCallId);
  for (const [type, expected] of Object.entries(expectedCounts)) {
    const observed = callEvents.filter((event) => event.type === type).length;
    if (observed !== expected) throw new Error(`Expected exactly ${expected} ${type} event; observed ${observed}.`);
  }
}

function normalizeEmail(value, name) {
  if (typeof value !== 'string' || !value.trim() || value.length > 320 || /[\p{Cc}\s]/u.test(value)) {
    throw new Error(`${name} must be one plain email address.`);
  }
  const normalized = value.trim().toLowerCase();
  if (!/^[^@]+@[^@]+\.[^@]+$/.test(normalized)) throw new Error(`${name} must be one plain email address.`);
  return normalized;
}

function normalizeLoopbackUrl(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be a valid loopback HTTP URL.`);
  }
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

function validateEnvironmentValue(name, value) {
  if (value.length > MAX_ENV_VALUE_LENGTH || /\p{Cc}/u.test(value)) {
    throw new Error(`${name} in .env.local is invalid.`);
  }
}

function unquoteEnvValue(value) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(sortJson(value));
}

function signalChildProcessTree(child, signal, processGroup) {
  if (processGroup && Number.isInteger(child.pid) && child.pid > 0) {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {
      // Fall through so the wrapper can still close its own downstream child.
    }
  }
  try {
    child.kill(signal);
  } catch {
    // The process may have exited between the status check and the signal.
  }
}

function waitForChildExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    let timer;
    const finish = (exited) => {
      if (timer) clearTimeout(timer);
      child.off?.('exit', onExit);
      child.off?.('close', onExit);
      resolve(exited);
    };
    const onExit = () => finish(true);
    child.once('exit', onExit);
    child.once('close', onExit);
    timer = setTimeout(() => finish(false), timeoutMs);
  });
}

async function waitForProcessGroupExit(groupId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (processGroupExists(groupId) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return !processGroupExists(groupId);
}

function processGroupExists(groupId) {
  try {
    process.kill(-groupId, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortJson(value[key])]),
    );
  }
  return value;
}
