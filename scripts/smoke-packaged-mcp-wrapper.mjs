#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(process.cwd());
const wrapperEntry = path.join(root, 'packages/mcp-wrapper/dist/index.js');
const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-packaged-mcp-'));
const fixturePath = path.join(temporaryDirectory, 'fixture.mjs');
const tracePath = path.join(temporaryDirectory, 'fixture.trace');
const configPath = path.join(temporaryDirectory, 'actionproxy.mcp.yaml');
const bearerToken = 'actionproxy-test-bearer-token';
const gatewayRequests = [];
let wrapper;
let gateway;

try {
  assert(fs.existsSync(wrapperEntry), `Built MCP wrapper is missing: ${wrapperEntry}. Run the repository build first.`);
  fs.writeFileSync(fixturePath, fixtureSource(), 'utf8');
  fs.writeFileSync(tracePath, '', 'utf8');

  gateway = http.createServer(async (request, response) => {
    const body = await readJsonBody(request);
    gatewayRequests.push({
      authorization: request.headers.authorization,
      body,
      idempotencyKey: request.headers['idempotency-key'],
      method: request.method,
      path: request.url,
      sessionId: request.headers['x-actionproxy-mcp-session-id'],
    });

    if (request.method === 'POST' && request.url === '/v1/mcp/tool-calls') {
      sendJson(response, {
        decision: 'allow',
        id: 'packaged-tool-call-1',
        status: 'authorized',
        toolCall: {
          decision: 'allow',
          id: 'packaged-tool-call-1',
          input: body.input,
          policyVersionHash: 'packaged-policy-v1',
          result: {
            grant: {
              id: 'packaged-grant-1',
              policyVersionHash: 'packaged-policy-v1',
            },
          },
          status: 'authorized',
        },
      });
      return;
    }
    if (request.method === 'POST' && request.url === '/v1/execution-grants/packaged-grant-1/consume') {
      sendJson(response, { consumed: true });
      return;
    }
    if (request.method === 'POST' && request.url === '/v1/execution-grants/packaged-grant-1/outcome') {
      sendJson(response, { recorded: true });
      return;
    }
    sendJson(response, { error: 'unexpected packaged smoke request' }, 404);
  });
  await listen(gateway);
  const address = gateway.address();
  assert(address && typeof address === 'object', 'Packaged smoke gateway did not expose a TCP address.');
  fs.writeFileSync(configPath, configSource(address.port), 'utf8');

  const environment = {
    ...process.env,
    ACTIONPROXY_SMOKE_GATEWAY_TOKEN: bearerToken,
  };
  const doctor = spawnSync(process.execPath, [
    wrapperEntry,
    'doctor',
    '--config',
    configPath,
    '--discover',
    '--json',
  ], {
    cwd: root,
    encoding: 'utf8',
    env: environment,
    maxBuffer: 1024 * 1024,
  });
  assert(doctor.status === 0, `Packaged doctor failed: ${doctor.stderr || doctor.stdout}`);
  const report = JSON.parse(doctor.stdout);
  assert(report.version === 'actionproxy.tool-plane-report.v1', 'Packaged doctor returned the wrong report version.');
  assert(report.coverage === 'configured_mcp_wrapper', 'Packaged doctor returned the wrong coverage boundary.');
  assert(report.mode === 'discover' && report.ok === true, 'Packaged doctor discovery did not succeed.');
  assert(report.servers?.[0]?.discovery?.status === 'verified', 'Packaged doctor did not verify its configured server.');
  assert(report.servers?.[0]?.discovery?.tools?.join(',') === 'docs.search', 'Packaged doctor discovered unexpected tools.');
  assertTrace(['initialize', 'tools/list', 'close'], 'doctor discovery');

  fs.writeFileSync(tracePath, '', 'utf8');
  wrapper = spawn(process.execPath, [wrapperEntry, 'wrap', '--config', configPath], {
    cwd: root,
    env: environment,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let wrapperStderr = '';
  wrapper.stderr.on('data', (chunk) => { wrapperStderr += chunk.toString('utf8'); });
  const host = createJsonRpcPeer(wrapper);

  const initialized = await host.request('initialize', {
    capabilities: {},
    clientInfo: { name: 'packaged-smoke-host', version: '1.0.0' },
    protocolVersion: '2025-06-18',
  });
  assert(initialized.result?.serverInfo?.name === 'actionproxy-mcp-wrapper', 'Packaged wrapper did not initialize for the host.');

  const listed = await host.request('tools/list', {});
  assert(listed.result?.tools?.length === 1, 'Packaged wrapper did not expose exactly one fixture tool.');
  assert(listed.result.tools[0].name === 'docs.search', 'Packaged wrapper exposed the wrong fixture tool.');

  const called = await host.request('tools/call', {
    arguments: { query: 'packaged release' },
    name: 'docs.search',
  });
  const expectedResult = {
    content: [{ text: 'packaged fixture result', type: 'text' }],
  };
  assert(JSON.stringify(called.result) === JSON.stringify(expectedResult), 'Packaged wrapper did not return the mediated result.');

  await stopChild(wrapper);
  wrapper = undefined;
  assert(wrapperStderr === '', `Packaged wrapper wrote unexpected stderr: ${wrapperStderr}`);
  assertTrace(['initialize', 'tools/list', 'tools/call', 'close'], 'wrapper mediation');
  assertGatewayMediation(expectedResult);

  console.log('Packaged MCP doctor discovery and wrapper mediation smoke passed.');
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  if (wrapper) await stopChild(wrapper).catch(() => undefined);
  if (gateway) await closeServer(gateway).catch(() => undefined);
  fs.rmSync(temporaryDirectory, { force: true, recursive: true });
}

function assertGatewayMediation(expectedResult) {
  assert(
    gatewayRequests.map((request) => request.path).join(',') === [
      '/v1/mcp/tool-calls',
      '/v1/execution-grants/packaged-grant-1/consume',
      '/v1/execution-grants/packaged-grant-1/outcome',
    ].join(','),
    `Packaged wrapper used an unexpected gateway sequence: ${gatewayRequests.map((request) => request.path).join(', ')}`,
  );
  assert(gatewayRequests.every((request) => request.method === 'POST'), 'Every packaged gateway request must use POST.');
  assert(
    gatewayRequests.every((request) => request.authorization === `Bearer ${bearerToken}`),
    'Packaged wrapper did not authenticate every gateway request.',
  );
  const sessionIds = new Set(gatewayRequests.map((request) => request.sessionId));
  assert(sessionIds.size === 1, 'Packaged wrapper did not use one stable influence-session id.');
  const [sessionId] = sessionIds;
  assert(
    typeof sessionId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(sessionId),
    'Packaged wrapper did not send a canonical UUID session id.',
  );
  assert(typeof gatewayRequests[0].idempotencyKey === 'string', 'Packaged submission omitted its idempotency key.');
  assert(gatewayRequests[0].body.toolName === 'docs.search', 'Packaged submission used the wrong tool name.');
  assert(gatewayRequests[0].body.input?.query === 'packaged release', 'Packaged submission changed the tool input.');
  assert(gatewayRequests[1].body.toolCallId === 'packaged-tool-call-1', 'Packaged grant consumption used the wrong tool call.');
  const outcome = gatewayRequests[2].body;
  assert(outcome.status === 'succeeded', 'Packaged outcome did not report success.');
  assert(JSON.stringify(outcome.result) === JSON.stringify(expectedResult), 'Packaged outcome changed the downstream result.');
  const canonicalResult = canonicalJson(expectedResult);
  assert(outcome.resultDelivery?.version === 'actionproxy.result-delivery.v1', 'Packaged outcome omitted delivery metadata version.');
  assert(outcome.resultDelivery?.modelVisible === true, 'Packaged outcome did not mark content model-visible.');
  assert(
    outcome.resultDelivery?.byteCount === Buffer.byteLength(canonicalResult, 'utf8'),
    'Packaged outcome reported the wrong result byte count.',
  );
  assert(
    outcome.resultDelivery?.canonicalResultHash === createHash('sha256').update(canonicalResult).digest('hex'),
    'Packaged outcome reported the wrong canonical result hash.',
  );
}

function assertTrace(expected, phase) {
  const actual = fs.readFileSync(tracePath, 'utf8').trim().split('\n').filter(Boolean);
  assert(JSON.stringify(actual) === JSON.stringify(expected), `${phase} trace was ${JSON.stringify(actual)}.`);
  assert(!actual.includes('tools/call') || phase === 'wrapper mediation', `${phase} unexpectedly called a tool.`);
}

function configSource(port) {
  return `actionproxy:\n  baseUrl: http://127.0.0.1:${port}\n  bearerTokenEnv: ACTIONPROXY_SMOKE_GATEWAY_TOKEN\n  requestTimeoutMs: 5000\nservers:\n  fixture:\n    command: ${JSON.stringify(process.execPath)}\n    args: [${JSON.stringify(fixturePath)}]\n    env:\n      ACTIONPROXY_SMOKE_TRACE_PATH: ${JSON.stringify(tracePath)}\n    requestTimeoutMs: 5000\n    stdioFraming: content-length\n`;
}

function fixtureSource() {
  return `import fs from 'node:fs';

const tracePath = process.env.ACTIONPROXY_SMOKE_TRACE_PATH;
let buffer = Buffer.alloc(0);
const trace = (event) => fs.appendFileSync(tracePath, event + '\\n', 'utf8');

if (process.env.ACTIONPROXY_SMOKE_GATEWAY_TOKEN !== undefined) {
  trace('gateway-bearer-token-leaked');
}

process.once('SIGTERM', () => {
  trace('close');
  process.exit(0);
});

process.stdin.on('data', (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  for (;;) {
    const headerEnd = buffer.indexOf('\\r\\n\\r\\n');
    if (headerEnd === -1) return;
    const header = buffer.subarray(0, headerEnd).toString('utf8');
    const match = header.match(/content-length:\\s*(\\d+)/i);
    if (!match) process.exit(2);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + Number(match[1]);
    if (buffer.length < bodyEnd) return;
    const message = JSON.parse(buffer.subarray(bodyStart, bodyEnd).toString('utf8'));
    buffer = buffer.subarray(bodyEnd);
    handle(message);
  }
});

function handle(message) {
  if (message.method?.startsWith('notifications/')) return;
  if (message.id === undefined || message.id === null) return;
  trace(message.method);
  if (message.method === 'initialize') {
    send({ id: message.id, jsonrpc: '2.0', result: { capabilities: { tools: {} }, protocolVersion: '2025-06-18', serverInfo: { name: 'packaged-fixture', version: '1.0.0' } } });
    return;
  }
  if (message.method === 'tools/list') {
    send({ id: message.id, jsonrpc: '2.0', result: { tools: [{ description: 'Packaged fixture read.', inputSchema: { type: 'object' }, name: 'docs.search' }] } });
    return;
  }
  if (message.method === 'tools/call') {
    send({ id: message.id, jsonrpc: '2.0', result: { content: [{ text: 'packaged fixture result', type: 'text' }] } });
    return;
  }
  send({ error: { code: -32601, message: 'unsupported' }, id: message.id, jsonrpc: '2.0' });
}

function send(message) {
  const body = JSON.stringify(message);
  process.stdout.write('Content-Length: ' + Buffer.byteLength(body, 'utf8') + '\\r\\n\\r\\n' + body);
}
`;
}

function createJsonRpcPeer(child) {
  let buffer = Buffer.alloc(0);
  let nextId = 1;
  const pending = new Map();
  child.stdout.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return;
      const header = buffer.subarray(0, headerEnd).toString('utf8');
      const match = header.match(/content-length:\s*(\d+)/i);
      if (!match) throw new Error('Packaged wrapper returned an invalid MCP frame.');
      const bodyStart = headerEnd + 4;
      const bodyEnd = bodyStart + Number(match[1]);
      if (buffer.length < bodyEnd) return;
      const message = JSON.parse(buffer.subarray(bodyStart, bodyEnd).toString('utf8'));
      buffer = buffer.subarray(bodyEnd);
      const waiter = pending.get(message.id);
      if (waiter) {
        pending.delete(message.id);
        clearTimeout(waiter.timeout);
        waiter.resolve(message);
      }
    }
  });
  child.once('exit', (code, signal) => {
    for (const waiter of pending.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(new Error(`Packaged wrapper exited before responding (${signal ?? code}).`));
    }
    pending.clear();
  });

  return {
    request(method, params) {
      const id = nextId++;
      const message = { id, jsonrpc: '2.0', method, params };
      const body = JSON.stringify(message);
      child.stdin.write(`Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`);
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`Timed out waiting for packaged wrapper response to ${method}.`));
        }, 10_000);
        pending.set(id, { reject, resolve, timeout });
      });
    },
  };
}

async function readJsonBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  const body = Buffer.concat(chunks).toString('utf8');
  return body ? JSON.parse(body) : undefined;
}

function sendJson(response, body, statusCode = 200) {
  response.writeHead(statusCode, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('Timed out stopping the packaged MCP wrapper.'));
    }, 5_000);
    child.once('exit', () => {
      clearTimeout(timeout);
      resolve();
    });
    child.kill('SIGTERM');
  });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
