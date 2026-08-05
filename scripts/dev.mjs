#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const defaultUiUrl = 'http://127.0.0.1:5173/#/demo';
const googleWorkspaceDataDir =
  '.actionproxy/google-workspace-mcp/actionproxy-data';
const googleWorkspacePolicyPath =
  'examples/google-workspace-mcp-demo/actionproxy.policy.yaml';
const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
);

export function loadDevEnvironment(
  rootDirectory = repositoryRoot,
  environment = process.env,
) {
  const fromFiles = {};
  for (const filename of ['.env', '.env.local']) {
    const envPath = path.join(rootDirectory, filename);
    if (!fs.existsSync(envPath)) continue;
    for (const rawLine of fs.readFileSync(envPath, 'utf8').split(/\r?\n/u)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/u.exec(line);
      if (!match) continue;
      fromFiles[match[1]] = parseDotEnvValue(match[2]);
    }
  }
  return { ...fromFiles, ...environment };
}

export function devProcessSpecs(args = [], environment = process.env) {
  const options = new Set(args);
  const googleWorkspaceDemo = options.has('--google-workspace-demo');
  const childEnvironment = googleWorkspaceDemo
    ? isolateGoogleWorkspaceDemoEnvironment(environment)
    : environment;
  const serverOnly = options.has('--server-only');
  const webOnly = options.has('--web-only');
  if (serverOnly && webOnly) {
    throw new Error('Choose only one of --server-only or --web-only.');
  }

  const policyIndex = args.indexOf('--policy');
  if (googleWorkspaceDemo && policyIndex !== -1) {
    throw new Error(
      '--google-workspace-demo owns its policy and cannot be combined with --policy.',
    );
  }
  const policyPath = googleWorkspaceDemo
    ? googleWorkspacePolicyPath
    : policyIndex === -1
      ? undefined
      : args[policyIndex + 1];
  if (policyIndex !== -1 && !policyPath) {
    throw new Error('--policy requires a repository-relative policy path.');
  }
  const privateDataDir = resolvePrivateDataDir(args);

  const corepack = process.platform === 'win32' ? 'corepack.cmd' : 'corepack';
  const specs = [];
  if (!webOnly) {
    specs.push({
      args: ['pnpm', '--filter', '@actionproxy/server', 'dev'],
      command: corepack,
      env: {
        ...childEnvironment,
        ACTIONPROXY_DEPLOYMENT_MODE: 'local',
        ACTIONPROXY_LOCAL_EXECUTION:
          googleWorkspaceDemo || options.has('--proxy') ? 'disabled' : 'mock',
        ...(policyPath ? { ACTIONPROXY_POLICY_PATH: policyPath } : {}),
        ...(privateDataDir
          ? { ACTIONPROXY_DATA_DIR: privateDataDir }
          : {}),
        ...(googleWorkspaceDemo
          ? {
              ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND: 'false',
              ACTIONPROXY_AUTH_MODE: 'none',
              ACTIONPROXY_DISABLE_LOCAL_ENV_FILES: 'true',
              ACTIONPROXY_EMAIL_TRANSPORT: 'outbox',
              ACTIONPROXY_HOST: '127.0.0.1',
              ACTIONPROXY_MCP_STDIO_DISCOVERY_ENABLED: 'false',
              ACTIONPROXY_MCP_STREAMABLE_HTTP_ENABLED: 'false',
              ACTIONPROXY_OTEL_ENABLED: 'false',
              ACTIONPROXY_PORT: '8787',
              ACTIONPROXY_QUICKSTART_MODE: 'false',
              ACTIONPROXY_STORAGE: 'memory',
            }
          : {}),
      },
      label: 'server',
    });
  }
  if (!serverOnly) {
    specs.push({
      args: ['pnpm', '--filter', '@actionproxy/web', 'dev'],
      command: corepack,
      env: { ...childEnvironment },
      label: 'web',
    });
  }
  return specs;
}

export function isolateGoogleWorkspaceDemoEnvironment(environment) {
  const result = {};
  for (const name of [
    'ALL_PROXY',
    'CI',
    'COLORTERM',
    'COREPACK_HOME',
    'FORCE_COLOR',
    'HOME',
    'HTTPS_PROXY',
    'HTTP_PROXY',
    'LANG',
    'LC_ALL',
    'LC_CTYPE',
    'LOGNAME',
    'NO_COLOR',
    'NO_PROXY',
    'NVM_BIN',
    'NVM_DIR',
    'PATH',
    'PNPM_HOME',
    'Path',
    'SHELL',
    'SSL_CERT_DIR',
    'SSL_CERT_FILE',
    'TEMP',
    'TERM',
    'TMP',
    'TMPDIR',
    'TZ',
    'USER',
    'VOLTA_HOME',
    'all_proxy',
    'http_proxy',
    'https_proxy',
    'no_proxy',
  ]) {
    if (typeof environment[name] === 'string') result[name] = environment[name];
  }
  return result;
}

export function startDev({
  args = process.argv.slice(2),
  environment = process.env,
  onExit = (code) => {
    process.exitCode = code;
  },
  output = process.stdout,
  rootDirectory = repositoryRoot,
  spawnProcess = spawn,
} = {}) {
  const privateDataDir = resolvePrivateDataDir(args);
  if (privateDataDir) {
    preparePrivateDataDirectory(rootDirectory, privateDataDir);
  }
  const previousUmask = privateDataDir ? process.umask(0o077) : undefined;
  let specs;
  try {
    const loadedEnvironment = args.includes('--google-workspace-demo')
      ? environment
      : loadDevEnvironment(rootDirectory, environment);
    specs = devProcessSpecs(
      args,
      loadedEnvironment,
    );
  } catch (error) {
    if (previousUmask !== undefined) process.umask(previousUmask);
    throw error;
  }
  const children = new Set();
  let stopping = false;

  function stop(signal = 'SIGTERM', exitCode = 0) {
    if (stopping) return;
    stopping = true;
    for (const child of children) {
      if (child.exitCode === null && child.signalCode === null) child.kill(signal);
    }
    onExit(exitCode);
  }

  try {
    for (const spec of specs) {
      const child = spawnProcess(spec.command, spec.args, {
        env: spec.env,
        stdio: 'inherit',
      });
      children.add(child);
      child.once('error', (error) => {
        output.write(`[ActionProxy] Could not start ${spec.label}: ${error.message}\n`);
        stop('SIGTERM', 1);
      });
      child.once('exit', (code, signal) => {
        children.delete(child);
        if (stopping) return;
        if (code !== 0 || signal) {
          output.write(
            `[ActionProxy] ${spec.label} stopped${signal ? ` after ${signal}` : ` with exit code ${code}`}. Check for an occupied port or the error above.\n`,
          );
        }
        stop('SIGTERM', code ?? (signal ? 1 : 0));
      });
    }
  } finally {
    if (previousUmask !== undefined) process.umask(previousUmask);
  }

  const handleInterrupt = () => stop('SIGINT', 0);
  const handleTerminate = () => stop('SIGTERM', 0);
  process.once('SIGINT', handleInterrupt);
  process.once('SIGTERM', handleTerminate);

  if (specs.length === 2) {
    output.write(`[ActionProxy] Starting the Community gateway and web console.\n`);
    output.write(`[ActionProxy] Open ${defaultUiUrl}\n`);
  }

  return {
    children,
    dispose() {
      process.off('SIGINT', handleInterrupt);
      process.off('SIGTERM', handleTerminate);
      stop('SIGTERM', 0);
    },
    stop,
  };
}

export function preparePrivateDataDirectory(rootDirectory, relativePath) {
  const privateRoot = path.resolve(rootDirectory, '.actionproxy');
  const target = path.resolve(rootDirectory, relativePath);
  if (
    path.isAbsolute(relativePath) ||
    target === privateRoot ||
    !target.startsWith(`${privateRoot}${path.sep}`)
  ) {
    throw new Error(
      '--private-data-dir must name a repository-relative child of .actionproxy.',
    );
  }

  let current = path.resolve(rootDirectory);
  for (const segment of path.relative(rootDirectory, target).split(path.sep)) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) {
      fs.mkdirSync(current, { mode: 0o700 });
    }
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(
        '--private-data-dir must not traverse a symbolic link or non-directory.',
      );
    }
    fs.chmodSync(current, 0o700);
  }
  return target;
}

function parsePrivateDataDir(args) {
  const indexes = args.flatMap((argument, index) =>
    argument === '--private-data-dir' ? [index] : [],
  );
  if (indexes.length > 1) {
    throw new Error('--private-data-dir may be provided only once.');
  }
  if (indexes.length === 0) return undefined;
  const value = args[indexes[0] + 1];
  if (!value || value.startsWith('--')) {
    throw new Error('--private-data-dir requires a repository-relative path.');
  }
  return value;
}

function resolvePrivateDataDir(args) {
  const explicit = parsePrivateDataDir(args);
  if (!args.includes('--google-workspace-demo')) return explicit;
  if (explicit && explicit !== googleWorkspaceDataDir) {
    throw new Error(
      `--google-workspace-demo requires --private-data-dir ${googleWorkspaceDataDir}.`,
    );
  }
  return args.includes('--web-only') ? undefined : googleWorkspaceDataDir;
}

function parseDotEnvValue(rawValue) {
  const value = rawValue.trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    const unquoted = value.slice(1, -1);
    return value.startsWith('"')
      ? unquoted
          .replace(/\\n/gu, '\n')
          .replace(/\\"/gu, '"')
          .replace(/\\\\/gu, '\\')
      : unquoted;
  }
  const commentIndex = value.indexOf(' #');
  return commentIndex >= 0 ? value.slice(0, commentIndex).trim() : value;
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
) {
  try {
    startDev();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
