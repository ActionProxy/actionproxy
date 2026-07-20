#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PROFILE_MARKER_VERSION = 'actionproxy.chatgpt-tunnel-profile.v1';
export const EXPECTED_DEMO_TOOLS = [
  'dangerous.delete_customer',
  'docs.search',
  'gmail.send_email',
];

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultRepoRoot = path.resolve(scriptDirectory, '..', '..');
const defaultProfile = 'actionproxy-local-demo';
const defaultTunnelClient = 'tunnel-client';
const mcpCommand = [
  'docker',
  'compose',
  '-f',
  'docker-compose.yml',
  'exec',
  '-T',
  'actionproxy',
  'node',
  'packages/mcp-wrapper/dist/index.js',
  'wrap',
  '--config',
  'examples/chatgpt-tunnel/actionproxy.mcp.yaml',
].join(' ');

export function parseArguments(args) {
  const result = { help: false, profile: defaultProfile, tunnelId: undefined };
  let profileSeen = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--help' || argument === '-h') {
      result.help = true;
      continue;
    }
    if (argument === '--tunnel-id' && result.tunnelId === undefined) {
      result.tunnelId = args[index + 1];
      index += 1;
      continue;
    }
    if (argument === '--profile' && !profileSeen) {
      result.profile = args[index + 1];
      profileSeen = true;
      index += 1;
      continue;
    }
    throw new Error(`Unknown or incomplete argument: ${argument ?? '(missing)'}`);
  }

  if (result.help) return result;
  if (!result.tunnelId || !/^tunnel_[A-Za-z0-9_-]{8,128}$/u.test(result.tunnelId)) {
    throw new Error('Provide --tunnel-id with the tunnel_... identifier from OpenAI Platform tunnel settings.');
  }
  if (!result.profile || !/^[A-Za-z0-9._-]{1,64}$/u.test(result.profile)) {
    throw new Error('--profile must contain 1-64 letters, numbers, dots, underscores, or hyphens.');
  }
  return result;
}

export function usage() {
  return [
    'Usage:',
    '  corepack pnpm demo:chatgpt:tunnel -- --tunnel-id tunnel_... [--profile actionproxy-local-demo]',
    '',
    'Environment:',
    '  CONTROL_PLANE_API_KEY   Required by OpenAI tunnel-client. Never stored by ActionProxy.',
    '  TUNNEL_CLIENT_BIN       Optional tunnel-client binary path.',
    '  ACTIONPROXY_DOCKER_PORT Optional loopback port for the bundled console (default 8787).',
    '',
  ].join('\n');
}

export function profileMarker({ tunnelId }) {
  return {
    commandHash: createHash('sha256').update(mcpCommand).digest('hex'),
    tunnelId,
    version: PROFILE_MARKER_VERSION,
  };
}

export function markerPath(repoRoot, profile) {
  return path.join(repoRoot, '.actionproxy', 'chatgpt-tunnel', `${profile}.json`);
}

export function validateDoctorReport(raw) {
  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    throw new Error('ActionProxy MCP doctor returned invalid JSON. Rebuild the Docker image and try again.');
  }
  const server = report.servers?.[0];
  const tools = server?.discovery?.status === 'verified'
    ? [...(server.discovery.tools ?? [])].sort()
    : [];
  if (
    report.version !== 'actionproxy.tool-plane-report.v1' ||
    report.coverage !== 'configured_mcp_wrapper' ||
    report.mode !== 'discover' ||
    report.ok !== true ||
    report.servers?.length !== 1 ||
    server?.name !== 'chatgpt-tunnel-demo' ||
    server?.discovery?.toolCount !== EXPECTED_DEMO_TOOLS.length ||
    JSON.stringify(tools) !== JSON.stringify(EXPECTED_DEMO_TOOLS)
  ) {
    throw new Error(`MCP discovery must expose exactly: ${EXPECTED_DEMO_TOOLS.join(', ')}.`);
  }
  return report;
}

export function redact(value, secret) {
  if (!secret) return String(value);
  return String(value).split(secret).join('[REDACTED]');
}

export async function runTunnelDemo(
  { args = process.argv.slice(2), env = process.env, repoRoot = defaultRepoRoot } = {},
  dependencies = {},
) {
  const parsed = parseArguments(args);
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  if (parsed.help) {
    stdout.write(usage());
    return 0;
  }

  const controlPlaneKey = validSecret(env.CONTROL_PLANE_API_KEY, 'CONTROL_PLANE_API_KEY');
  const tunnelClient = env.TUNNEL_CLIENT_BIN?.trim() || defaultTunnelClient;
  const port = dockerPort(env.ACTIONPROXY_DOCKER_PORT);
  const baseUrl = `http://127.0.0.1:${port}`;
  const command = dependencies.runCommand ?? runCommand;
  const foreground = dependencies.runForeground ?? runForeground;
  const fetchFn = dependencies.fetchFn ?? fetch;
  const fileSystem = dependencies.fileSystem ?? fs;
  const safeEnvironment = { ...env, ACTIONPROXY_DOCKER_PORT: String(port) };
  const dockerEnvironment = { ...safeEnvironment };
  delete dockerEnvironment.CONTROL_PLANE_API_KEY;

  await checked(command, 'Docker is required for this local demo.', 'docker', ['--version'], {
    capture: true,
    cwd: repoRoot,
    env: dockerEnvironment,
  }, controlPlaneKey);
  await checked(command, 'Docker Compose is required for this local demo.', 'docker', ['compose', 'version'], {
    capture: true,
    cwd: repoRoot,
    env: dockerEnvironment,
  }, controlPlaneKey);
  await checked(command, 'Install OpenAI tunnel-client or set TUNNEL_CLIENT_BIN.', tunnelClient, ['help', 'quickstart'], {
    capture: true,
    cwd: repoRoot,
    env: safeEnvironment,
  }, controlPlaneKey);

  stdout.write('Starting the bundled ActionProxy Community demo...\n');
  await checked(command, 'Docker could not start the ActionProxy demo.', 'docker', [
    'compose', '-f', 'docker-compose.yml', 'up', '-d', '--build', 'actionproxy',
  ], {
    capture: false,
    cwd: repoRoot,
    env: dockerEnvironment,
    secret: controlPlaneKey,
    stderr,
    stdout,
  }, controlPlaneKey);
  await waitForHealth(fetchFn, `${baseUrl}/health`, dependencies.healthOptions);

  const doctor = await checked(command, 'ActionProxy MCP wrapper discovery failed.', 'docker', [
    'compose', '-f', 'docker-compose.yml', 'exec', '-T', 'actionproxy',
    'node', 'packages/mcp-wrapper/dist/index.js', 'doctor',
    '--config', 'examples/chatgpt-tunnel/actionproxy.mcp.yaml', '--discover', '--json',
  ], {
    capture: true,
    cwd: repoRoot,
    env: dockerEnvironment,
  }, controlPlaneKey);
  validateDoctorReport(doctor.stdout);

  const expectedMarker = profileMarker(parsed);
  const statePath = markerPath(repoRoot, parsed.profile);
  const existingMarker = readMarker(fileSystem, statePath);
  if (existingMarker && JSON.stringify(existingMarker) !== JSON.stringify(expectedMarker)) {
    throw new Error(
      `Tunnel profile ${parsed.profile} belongs to a different tunnel or command. ` +
      'Choose a new name with --profile instead of overwriting it.',
    );
  }

  if (!existingMarker) {
    stdout.write(`Initializing OpenAI tunnel profile ${parsed.profile}...\n`);
    await checked(command, 'OpenAI tunnel profile initialization failed.', tunnelClient, [
      'init',
      '--sample', 'sample_mcp_stdio_local',
      '--profile', parsed.profile,
      '--tunnel-id', parsed.tunnelId,
      '--mcp-command', mcpCommand,
    ], {
      capture: true,
      cwd: repoRoot,
      env: safeEnvironment,
    }, controlPlaneKey);
    fileSystem.mkdirSync(path.dirname(statePath), { recursive: true });
    fileSystem.writeFileSync(statePath, `${JSON.stringify(expectedMarker, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  } else {
    stdout.write(`Reusing OpenAI tunnel profile ${parsed.profile}.\n`);
  }

  await checked(command, 'OpenAI tunnel doctor failed. Check tunnel entitlement, permissions, and workspace association.', tunnelClient, [
    'doctor', '--profile', parsed.profile, '--explain',
  ], {
    capture: true,
    cwd: repoRoot,
    env: safeEnvironment,
  }, controlPlaneKey);

  stdout.write([
    '',
    `ActionProxy console: ${baseUrl}/app#/demo`,
    'In ChatGPT, create a developer-mode app with Connection → Tunnel and select this tunnel.',
    'Keep this terminal open while testing. Press Ctrl+C to stop the tunnel.',
    '',
  ].join('\n'));

  const tunnelResult = await foreground(tunnelClient, ['run', '--profile', parsed.profile], {
    cwd: repoRoot,
    env: safeEnvironment,
    secret: controlPlaneKey,
    stderr,
    stdout,
  });
  if (tunnelResult.code !== 0 && !tunnelResult.interrupted) {
    throw new Error(`OpenAI tunnel disconnected with exit code ${tunnelResult.code ?? 'unknown'}.`);
  }
  stdout.write('\nTunnel stopped. ActionProxy is still running; use `docker compose down` when finished.\n');
  return 0;
}

async function checked(command, message, executable, args, options, secret) {
  let result;
  try {
    result = await command(executable, args, options);
  } catch (error) {
    throw new Error(`${message} ${redact(error instanceof Error ? error.message : error, secret)}`);
  }
  if (result.code !== 0) {
    const detail = redact(result.stderr || result.stdout || '', secret).trim();
    throw new Error(`${message}${detail ? ` ${detail}` : ''}`);
  }
  return result;
}

async function waitForHealth(fetchFn, url, options = {}) {
  const deadline = Date.now() + (options.timeoutMs ?? 120_000);
  let lastError = '';
  while (Date.now() < deadline) {
    try {
      const response = await fetchFn(url, { signal: AbortSignal.timeout(2_000) });
      if (response.ok && (await response.json()).ok === true) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, options.retryMs ?? 500));
  }
  throw new Error(`ActionProxy did not become healthy at ${url}${lastError ? ` (${lastError})` : ''}.`);
}

function readMarker(fileSystem, statePath) {
  if (!fileSystem.existsSync(statePath)) return undefined;
  try {
    const marker = JSON.parse(fileSystem.readFileSync(statePath, 'utf8'));
    if (!marker || marker.version !== PROFILE_MARKER_VERSION) throw new Error('unsupported marker');
    return marker;
  } catch {
    throw new Error(`Tunnel profile marker is invalid: ${statePath}. Remove it or choose a new --profile.`);
  }
}

function dockerPort(value) {
  if (value === undefined || value === '') return 8787;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error('ACTIONPROXY_DOCKER_PORT must be an integer from 1 to 65535.');
  }
  return parsed;
}

function validSecret(value, name) {
  if (!value || value.trim() !== value || value.length > 8192 || /\p{Cc}/u.test(value)) {
    throw new Error(`${name} is required and must be supplied only through the shell environment.`);
  }
  return value;
}

function runCommand(executable, args, options) {
  return spawnAndCollect(executable, args, options);
}

function spawnAndCollect(executable, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const forwardOut = options.capture ? undefined : redactingWriter(options.secret, (value) => options.stdout.write(value));
    const forwardErr = options.capture ? undefined : redactingWriter(options.secret, (value) => options.stderr.write(value));
    child.once('error', reject);
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
      forwardOut?.push(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
      forwardErr?.push(chunk);
    });
    child.once('close', (code) => {
      forwardOut?.end();
      forwardErr?.end();
      resolve({ code, stderr, stdout });
    });
  });
}

function runForeground(executable, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['inherit', 'pipe', 'pipe'],
    });
    const forwardOut = redactingWriter(options.secret, (value) => options.stdout.write(value));
    const forwardErr = redactingWriter(options.secret, (value) => options.stderr.write(value));
    let interrupted = false;
    const forwardSignal = (signal) => {
      interrupted = true;
      child.kill(signal);
    };
    const onSigint = () => forwardSignal('SIGINT');
    const onSigterm = () => forwardSignal('SIGTERM');
    process.once('SIGINT', onSigint);
    process.once('SIGTERM', onSigterm);
    child.once('error', reject);
    child.stdout.on('data', (chunk) => forwardOut.push(chunk));
    child.stderr.on('data', (chunk) => forwardErr.push(chunk));
    child.once('close', (code) => {
      process.removeListener('SIGINT', onSigint);
      process.removeListener('SIGTERM', onSigterm);
      forwardOut.end();
      forwardErr.end();
      resolve({ code, interrupted });
    });
  });
}

function redactingWriter(secret, write) {
  let buffer = '';
  return {
    push(chunk) {
      buffer += String(chunk);
      for (;;) {
        const newline = buffer.indexOf('\n');
        if (newline === -1) return;
        write(redact(buffer.slice(0, newline + 1), secret));
        buffer = buffer.slice(newline + 1);
      }
    },
    end() {
      if (buffer) write(redact(buffer, secret));
      buffer = '';
    },
  };
}

async function main() {
  try {
    process.exitCode = await runTunnelDemo();
  } catch (error) {
    process.stderr.write(`ActionProxy ChatGPT tunnel demo: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
