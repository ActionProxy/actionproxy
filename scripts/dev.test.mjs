import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  devProcessSpecs,
  loadDevEnvironment,
  startDev,
} from './dev.mjs';

test('combined development starts Community server and web without edition flags', () => {
  const specs = devProcessSpecs([], { PATH: '/test/bin' });
  assert.equal(specs.length, 2);
  assert.equal(specs[0].env.ACTIONPROXY_LOCAL_EXECUTION, 'mock');
  assert.equal(specs[0].env.ACTIONPROXY_DEPLOYMENT_MODE, 'local');
  assert.equal(specs[0].env.ACTIONPROXY_EDITION, undefined);
  assert.deepEqual(specs[1].args, ['pnpm', '--filter', '@actionproxy/web', 'dev']);
});

test('proxy development disables local execution and accepts an explicit policy', () => {
  const [server] = devProcessSpecs(
    ['--server-only', '--proxy', '--policy', 'examples/demo.policy.yaml'],
    {},
  );
  assert.equal(server.env.ACTIONPROXY_LOCAL_EXECUTION, 'disabled');
  assert.equal(server.env.ACTIONPROXY_POLICY_PATH, 'examples/demo.policy.yaml');
});

test('root env files configure both children while the shell remains authoritative', () => {
  const rootDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'actionproxy-dev-env-'),
  );
  try {
    fs.writeFileSync(
      path.join(rootDirectory, '.env'),
      'ACTIONPROXY_PORT=9000\nACTIONPROXY_HOST=127.0.0.1\n',
    );
    fs.writeFileSync(
      path.join(rootDirectory, '.env.local'),
      'ACTIONPROXY_PORT=9001\nACTIONPROXY_LOG_LEVEL="warn"\n',
    );
    const environment = loadDevEnvironment(rootDirectory, {
      ACTIONPROXY_PORT: '9002',
      PATH: '/test/bin',
    });
    const specs = devProcessSpecs([], environment);

    assert.equal(specs[0].env.ACTIONPROXY_PORT, '9002');
    assert.equal(specs[1].env.ACTIONPROXY_PORT, '9002');
    assert.equal(specs[0].env.ACTIONPROXY_HOST, '127.0.0.1');
    assert.equal(specs[1].env.ACTIONPROXY_LOG_LEVEL, 'warn');
  } finally {
    fs.rmSync(rootDirectory, { force: true, recursive: true });
  }
});

test('a child failure terminates its sibling and exits non-zero', () => {
  const children = [];
  const output = [];
  const exitCodes = [];
  const spawnProcess = () => {
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    child.kill = (signal) => {
      child.killedWith = signal;
      return true;
    };
    children.push(child);
    return child;
  };

  const supervisor = startDev({
    environment: {},
    onExit: (code) => exitCodes.push(code),
    output: { write: (value) => output.push(value) },
    spawnProcess,
  });
  children[0].emit('exit', 1, null);

  assert.equal(children[1].killedWith, 'SIGTERM');
  assert.deepEqual(exitCodes, [1]);
  assert.match(output.join(''), /occupied port or the error above/);
  supervisor.dispose();
});
