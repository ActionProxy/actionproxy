import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  EXPECTED_DEMO_TOOLS,
  markerPath,
  parseArguments,
  profileMarker,
  redact,
  runTunnelDemo,
  validateDoctorReport,
} from './run-tunnel.mjs';

const doctorReport = JSON.stringify({
  coverage: 'configured_mcp_wrapper',
  mode: 'discover',
  ok: true,
  servers: [{ discovery: { status: 'verified', toolCount: 3, tools: EXPECTED_DEMO_TOOLS }, name: 'chatgpt-tunnel-demo' }],
  version: 'actionproxy.tool-plane-report.v1',
});

test('validates the public launcher arguments', () => {
  assert.deepEqual(parseArguments(['--tunnel-id', 'tunnel_0123456789abcdef']), {
    help: false,
    profile: 'actionproxy-local-demo',
    tunnelId: 'tunnel_0123456789abcdef',
  });
  assert.throws(() => parseArguments([]), /--tunnel-id/u);
  assert.throws(() => parseArguments(['--tunnel-id', '../bad']), /--tunnel-id/u);
  assert.throws(
    () => parseArguments(['--tunnel-id', 'tunnel_0123456789abcdef', '--profile', '../bad']),
    /--profile/u,
  );
});

test('requires exact three-tool wrapper discovery', () => {
  assert.equal(validateDoctorReport(doctorReport).ok, true);
  assert.throws(
    () => validateDoctorReport(JSON.stringify({
      mode: 'discover',
      ok: true,
      coverage: 'configured_mcp_wrapper',
      servers: [{ discovery: { status: 'verified', tools: ['docs.search'] } }],
      version: 'actionproxy.tool-plane-report.v1',
    })),
    /exactly/u,
  );
});

test('orchestrates fake Docker and tunnel-client processes without storing credentials', async () => {
  const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-chatgpt-tunnel-'));
  const calls = [];
  let output = '';
  let dockerSawSecret = false;
  let tunnelSawSecret = false;
  const secret = 'test-placeholder-control-plane-secret';
  const runCommand = async (executable, args, options) => {
    calls.push([executable, ...args]);
    if (executable === 'docker' && options.env.CONTROL_PLANE_API_KEY) dockerSawSecret = true;
    if (executable === 'tunnel-client' && options.env.CONTROL_PLANE_API_KEY === secret) tunnelSawSecret = true;
    if (executable === 'docker' && args.includes('--json')) return { code: 0, stderr: '', stdout: doctorReport };
    return { code: 0, stderr: '', stdout: '' };
  };
  const dependencies = {
    fetchFn: async () => ({ json: async () => ({ ok: true }), ok: true, status: 200 }),
    fileSystem: fs,
    runCommand,
    runForeground: async (executable, args, options) => {
      calls.push([executable, ...args]);
      if (executable === 'tunnel-client' && options.env.CONTROL_PLANE_API_KEY === secret) tunnelSawSecret = true;
      return { code: 0, interrupted: false };
    },
    stderr: { write: (value) => { output += String(value); return true; } },
    stdout: { write: (value) => { output += String(value); return true; } },
  };

  await runTunnelDemo({
    args: ['--tunnel-id', 'tunnel_0123456789abcdef'],
    env: { CONTROL_PLANE_API_KEY: secret, PATH: process.env.PATH },
    repoRoot,
  }, dependencies);

  assert.ok(calls.some((call) => call[0] === 'docker' && call.includes('up') && call.includes('--build')));
  const init = calls.find((call) => call[0] === 'tunnel-client' && call[1] === 'init');
  assert.ok(init);
  assert.match(init.join(' '), /packages\/mcp-wrapper\/dist\/index\.js wrap/u);
  assert.doesNotMatch(init.join(' '), /examples\/mcp-demo\/server\.mjs/u);
  assert.ok(calls.some((call) => call[0] === 'tunnel-client' && call[1] === 'doctor'));
  assert.ok(calls.some((call) => call[0] === 'tunnel-client' && call[1] === 'run'));
  assert.equal(dockerSawSecret, false);
  assert.equal(tunnelSawSecret, true);

  const statePath = markerPath(repoRoot, 'actionproxy-local-demo');
  const stored = fs.readFileSync(statePath, 'utf8');
  assert.deepEqual(JSON.parse(stored), profileMarker({
    profile: 'actionproxy-local-demo',
    tunnelId: 'tunnel_0123456789abcdef',
  }));
  assert.equal(stored.includes(secret), false);
  assert.equal(output.includes(secret), false);

  calls.length = 0;
  await runTunnelDemo({
    args: ['--tunnel-id', 'tunnel_0123456789abcdef'],
    env: { CONTROL_PLANE_API_KEY: secret, PATH: process.env.PATH },
    repoRoot,
  }, dependencies);
  assert.equal(calls.some((call) => call[0] === 'tunnel-client' && call[1] === 'init'), false);
});

test('rejects profile reuse across tunnels and redacts subprocess errors', async () => {
  const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-chatgpt-profile-'));
  const statePath = markerPath(repoRoot, 'actionproxy-local-demo');
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  fs.writeFileSync(statePath, JSON.stringify(profileMarker({
    profile: 'actionproxy-local-demo',
    tunnelId: 'tunnel_aaaaaaaaaaaaaaaa',
  })));

  await assert.rejects(
    runTunnelDemo({
      args: ['--tunnel-id', 'tunnel_bbbbbbbbbbbbbbbb'],
      env: { CONTROL_PLANE_API_KEY: 'test-placeholder-profile-runtime-key' },
      repoRoot,
    }, {
      fetchFn: async () => ({ json: async () => ({ ok: true }), ok: true, status: 200 }),
      fileSystem: fs,
      runCommand: async (executable, args) => ({
        code: 0,
        stderr: '',
        stdout: executable === 'docker' && args.includes('--json') ? doctorReport : '',
      }),
      runForeground: async () => ({ code: 0, interrupted: false }),
      stderr: { write: () => true },
      stdout: { write: () => true },
    }),
    /different tunnel/u,
  );

  assert.equal(
    redact('failure test-placeholder-profile-runtime-key detail', 'test-placeholder-profile-runtime-key'),
    'failure [REDACTED] detail',
  );
});

test('fails before orchestration when the control-plane key is missing', async () => {
  await assert.rejects(
    runTunnelDemo({ args: ['--tunnel-id', 'tunnel_0123456789abcdef'], env: {} }),
    /CONTROL_PLANE_API_KEY/u,
  );
});

test('reports dependency, port, health, entitlement, and disconnection failures clearly', async () => {
  const key = 'test-placeholder-error-runtime-key';
  await assert.rejects(
    runTunnelDemo({
      args: ['--tunnel-id', 'tunnel_0123456789abcdef'],
      env: { CONTROL_PLANE_API_KEY: key },
    }, {
      runCommand: async () => ({ code: 127, stderr: `missing ${key}`, stdout: '' }),
      stderr: { write: () => true },
      stdout: { write: () => true },
    }),
    (error) => {
      assert.match(error.message, /Docker is required/u);
      assert.doesNotMatch(error.message, new RegExp(key, 'u'));
      assert.match(error.message, /\[REDACTED\]/u);
      return true;
    },
  );
  await assert.rejects(
    runTunnelDemo({
      args: ['--tunnel-id', 'tunnel_0123456789abcdef'],
      env: { ACTIONPROXY_DOCKER_PORT: '70000', CONTROL_PLANE_API_KEY: key },
    }),
    /ACTIONPROXY_DOCKER_PORT/u,
  );

  const healthRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-chatgpt-health-'));
  await assert.rejects(
    runTunnelDemo({
      args: ['--tunnel-id', 'tunnel_0123456789abcdef'],
      env: { CONTROL_PLANE_API_KEY: key },
      repoRoot: healthRoot,
    }, fakeDependencies({
      fetchFn: async () => ({ json: async () => ({ ok: false }), ok: false, status: 503 }),
      healthOptions: { retryMs: 0, timeoutMs: 2 },
    })),
    /did not become healthy.*HTTP 503/u,
  );
  fs.rmSync(healthRoot, { force: true, recursive: true });

  const entitlementRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-chatgpt-entitlement-'));
  await assert.rejects(
    runTunnelDemo({
      args: ['--tunnel-id', 'tunnel_0123456789abcdef'],
      env: { CONTROL_PLANE_API_KEY: key },
      repoRoot: entitlementRoot,
    }, fakeDependencies({
      runCommand: async (executable, args) => {
        if (executable === 'docker' && args.includes('--json')) {
          return { code: 0, stderr: '', stdout: doctorReport };
        }
        if (executable === 'tunnel-client' && args[0] === 'doctor') {
          return { code: 1, stderr: 'workspace association missing', stdout: '' };
        }
        return { code: 0, stderr: '', stdout: '' };
      },
    })),
    /entitlement, permissions, and workspace association.*workspace association missing/u,
  );
  fs.rmSync(entitlementRoot, { force: true, recursive: true });

  const disconnectRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-chatgpt-disconnect-'));
  await assert.rejects(
    runTunnelDemo({
      args: ['--tunnel-id', 'tunnel_0123456789abcdef'],
      env: { CONTROL_PLANE_API_KEY: key },
      repoRoot: disconnectRoot,
    }, fakeDependencies({ runForeground: async () => ({ code: 23, interrupted: false }) })),
    /disconnected with exit code 23/u,
  );
  fs.rmSync(disconnectRoot, { force: true, recursive: true });
});

test('treats an interrupted tunnel as a clean shutdown and prints Docker cleanup', async () => {
  const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-chatgpt-shutdown-'));
  let output = '';
  await runTunnelDemo({
    args: ['--tunnel-id', 'tunnel_0123456789abcdef'],
    env: { CONTROL_PLANE_API_KEY: 'test-placeholder-shutdown-runtime-key' },
    repoRoot,
  }, fakeDependencies({
    runForeground: async () => ({ code: null, interrupted: true }),
    stdout: { write: (value) => { output += String(value); return true; } },
  }));
  assert.match(output, /docker compose down/u);
  fs.rmSync(repoRoot, { force: true, recursive: true });
});

test('runs through fake Docker and tunnel-client binaries without leaking the runtime key', async () => {
  const repoRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-chatgpt-cli-')));
  const scriptDirectory = path.join(repoRoot, 'examples', 'chatgpt-tunnel');
  const binDirectory = path.join(repoRoot, 'fake-bin');
  const commandLog = path.join(repoRoot, 'commands.jsonl');
  const fetchHook = path.join(repoRoot, 'fake-fetch.mjs');
  const secret = 'test-placeholder-runtime-key-never-print';
  fs.mkdirSync(scriptDirectory, { recursive: true });
  fs.mkdirSync(binDirectory, { recursive: true });
  fs.copyFileSync(new URL('./run-tunnel.mjs', import.meta.url), path.join(scriptDirectory, 'run-tunnel.mjs'));
  fs.writeFileSync(fetchHook, `
globalThis.fetch = async () => ({
  json: async () => ({ ok: true }),
  ok: true,
  status: 200,
});
`);

  const fakeBinary = (name, body) => {
    const file = path.join(binDirectory, name);
    fs.writeFileSync(file, `#!${process.execPath}\n${body}\n`, { mode: 0o755 });
    fs.chmodSync(file, 0o755);
    return file;
  };
  fakeBinary('docker', `
import fs from 'node:fs';
fs.appendFileSync(process.env.FAKE_COMMAND_LOG, JSON.stringify({ args: process.argv.slice(2), executable: 'docker', hasRuntimeKey: Boolean(process.env.CONTROL_PLANE_API_KEY) }) + '\\n');
if (process.argv.includes('--json')) process.stdout.write(process.env.FAKE_DOCTOR_REPORT);
`);
  const tunnelClient = fakeBinary('tunnel-client', `
import fs from 'node:fs';
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FAKE_COMMAND_LOG, JSON.stringify({ args, executable: 'tunnel-client', hasRuntimeKey: Boolean(process.env.CONTROL_PLANE_API_KEY) }) + '\\n');
if (args[0] === 'run') {
  process.stdout.write('tunnel connected ' + process.env.CONTROL_PLANE_API_KEY + '\\n');
  process.stderr.write('tunnel diagnostic ' + process.env.CONTROL_PLANE_API_KEY + '\\n');
}
`);

  try {
    const child = spawn(process.execPath, [
      '--import', fetchHook,
      path.join(scriptDirectory, 'run-tunnel.mjs'),
      '--tunnel-id', 'tunnel_0123456789abcdef',
    ], {
      cwd: repoRoot,
      env: {
        ...process.env,
        ACTIONPROXY_DOCKER_PORT: '18787',
        CONTROL_PLANE_API_KEY: secret,
        FAKE_COMMAND_LOG: commandLog,
        FAKE_DOCTOR_REPORT: doctorReport,
        PATH: `${binDirectory}${path.delimiter}${process.env.PATH ?? ''}`,
        TUNNEL_CLIENT_BIN: tunnelClient,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const result = await collectChild(child);
    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stdout.includes(secret), false);
    assert.equal(result.stderr.includes(secret), false);
    assert.match(result.stdout, /\[REDACTED\]/u);
    assert.match(result.stderr, /\[REDACTED\]/u);

    const commands = fs.readFileSync(commandLog, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    const init = commands.find((command) => command.executable === 'tunnel-client' && command.args[0] === 'init');
    assert.ok(init);
    assert.match(init.args.join(' '), /docker compose -f docker-compose\.yml exec -T actionproxy node packages\/mcp-wrapper\/dist\/index\.js wrap/u);
    assert.doesNotMatch(init.args.join(' '), /examples\/mcp-demo\/server\.mjs/u);
    assert.equal(JSON.stringify(commands).includes(secret), false);
    assert.equal(commands.filter((command) => command.executable === 'docker').some((command) => command.hasRuntimeKey), false);
    assert.equal(commands.filter((command) => command.executable === 'tunnel-client').every((command) => command.hasRuntimeKey), true);
    assert.equal(fs.readFileSync(markerPath(repoRoot, 'actionproxy-local-demo'), 'utf8').includes(secret), false);
  } finally {
    fs.rmSync(repoRoot, { force: true, recursive: true });
  }
});

function collectChild(child) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    child.once('error', reject);
    child.stdout.on('data', (chunk) => { stdout += String(chunk); });
    child.stderr.on('data', (chunk) => { stderr += String(chunk); });
    child.once('close', (code) => resolve({ code, stderr, stdout }));
  });
}

function fakeDependencies(overrides = {}) {
  return {
    fetchFn: async () => ({ json: async () => ({ ok: true }), ok: true, status: 200 }),
    fileSystem: fs,
    runCommand: async (executable, args) => ({
      code: 0,
      stderr: '',
      stdout: executable === 'docker' && args.includes('--json') ? doctorReport : '',
    }),
    runForeground: async () => ({ code: 0, interrupted: false }),
    stderr: { write: () => true },
    stdout: { write: () => true },
    ...overrides,
  };
}
