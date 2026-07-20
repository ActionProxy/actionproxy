#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const defaultUiUrl = 'http://127.0.0.1:5173/#/demo';
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
  const serverOnly = options.has('--server-only');
  const webOnly = options.has('--web-only');
  if (serverOnly && webOnly) {
    throw new Error('Choose only one of --server-only or --web-only.');
  }

  const policyIndex = args.indexOf('--policy');
  const policyPath = policyIndex === -1 ? undefined : args[policyIndex + 1];
  if (policyIndex !== -1 && !policyPath) {
    throw new Error('--policy requires a repository-relative policy path.');
  }

  const corepack = process.platform === 'win32' ? 'corepack.cmd' : 'corepack';
  const specs = [];
  if (!webOnly) {
    specs.push({
      args: ['pnpm', '--filter', '@actionproxy/server', 'dev'],
      command: corepack,
      env: {
        ...environment,
        ACTIONPROXY_DEPLOYMENT_MODE: 'local',
        ACTIONPROXY_LOCAL_EXECUTION: options.has('--proxy') ? 'disabled' : 'mock',
        ...(policyPath ? { ACTIONPROXY_POLICY_PATH: policyPath } : {}),
      },
      label: 'server',
    });
  }
  if (!serverOnly) {
    specs.push({
      args: ['pnpm', '--filter', '@actionproxy/web', 'dev'],
      command: corepack,
      env: { ...environment },
      label: 'web',
    });
  }
  return specs;
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
  const specs = devProcessSpecs(
    args,
    loadDevEnvironment(rootDirectory, environment),
  );
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
