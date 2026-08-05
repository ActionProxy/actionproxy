import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  devProcessSpecs,
  isolateGoogleWorkspaceDemoEnvironment,
  loadDevEnvironment,
  preparePrivateDataDirectory,
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

test('private development data stays in a repository-scoped directory', () => {
  const relativePath = '.actionproxy/google-workspace-mcp/actionproxy-data';
  const [server] = devProcessSpecs(
    ['--server-only', '--proxy', '--private-data-dir', relativePath],
    {},
  );
  assert.equal(server.env.ACTIONPROXY_DATA_DIR, relativePath);

  const rootDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'actionproxy-private-dev-data-'),
  );
  try {
    const target = preparePrivateDataDirectory(rootDirectory, relativePath);
    assert.equal(target, path.join(rootDirectory, relativePath));
    for (const directory of [
      path.join(rootDirectory, '.actionproxy'),
      path.join(rootDirectory, '.actionproxy/google-workspace-mcp'),
      target,
    ]) {
      assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
    }
    assert.throws(
      () => preparePrivateDataDirectory(rootDirectory, '../outside'),
      /repository-relative child of \.actionproxy/u,
    );
  } finally {
    fs.rmSync(rootDirectory, { force: true, recursive: true });
  }
});

test('private development data rejects symlink traversal', (context) => {
  if (process.platform === 'win32') {
    context.skip('symlink permissions vary on Windows');
    return;
  }
  const rootDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'actionproxy-private-dev-symlink-'),
  );
  const outside = fs.mkdtempSync(
    path.join(os.tmpdir(), 'actionproxy-private-dev-outside-'),
  );
  try {
    fs.symlinkSync(outside, path.join(rootDirectory, '.actionproxy'));
    assert.throws(
      () =>
        preparePrivateDataDirectory(
          rootDirectory,
          '.actionproxy/google-workspace-mcp/actionproxy-data',
        ),
      /must not traverse a symbolic link/u,
    );
  } finally {
    fs.rmSync(rootDirectory, { force: true, recursive: true });
    fs.rmSync(outside, { force: true, recursive: true });
  }
});

test('private development children inherit umask 077 and caller umask is restored', () => {
  const rootDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'actionproxy-private-dev-umask-'),
  );
  const observedUmasks = [];
  const previousUmask = process.umask();
  try {
    const supervisor = startDev({
      args: [
        '--server-only',
        '--private-data-dir',
        '.actionproxy/google-workspace-mcp/actionproxy-data',
      ],
      environment: {},
      rootDirectory,
      spawnProcess: () => {
        observedUmasks.push(process.umask());
        const child = new EventEmitter();
        child.exitCode = null;
        child.signalCode = null;
        child.kill = () => true;
        return child;
      },
    });
    assert.deepEqual(observedUmasks, [0o077]);
    assert.equal(process.umask(), previousUmask);
    supervisor.dispose();
  } finally {
    process.umask(previousUmask);
    fs.rmSync(rootDirectory, { force: true, recursive: true });
  }
});

test('Google Workspace demo launcher strips provider credentials from gateway children', () => {
  const unsafeNames = [
    ['ACTIONPROXY', 'GOOGLE', 'OAUTH', 'CLIENT', 'ID'].join('_'),
    ['ACTIONPROXY', 'GOOGLE', 'OAUTH', 'CLIENT', 'SECRET'].join('_'),
    'ACTIONPROXY_BOOTSTRAP_ADMIN_API_KEY',
    'ACTIONPROXY_EMAIL_SMTP_PASSWORD',
    'ACTIONPROXY_EXECUTION_GRANT_SECRET',
    'ACTIONPROXY_HOST',
    'ACTIONPROXY_OTEL_EXPORTER_OTLP_HEADERS',
    'ACTIONPROXY_STORAGE',
    'DATABASE_URL',
    'GMAIL_DRAFT_BODY',
    'GOOGLE_APPLICATION_CREDENTIALS',
    'GOOGLE_OAUTH_CLIENT_ID',
    'GOOGLE_OAUTH_CLIENT_SECRET',
    'SLACK_BOT_TOKEN',
    'TELEGRAM_BOT_TOKEN',
    'USER_GOOGLE_EMAIL',
    'WORKSPACE_MCP_CREDENTIALS_DIR',
    'ALLOWED_FILE_DIRS',
    'OAUTHLIB_INSECURE_TRANSPORT',
  ];
  const environment = Object.fromEntries(
    unsafeNames.map((name) => [name, `canary-${name}`]),
  );
  environment.ACTIONPROXY_PORT = '18787';
  environment.HOME = '/test/home';
  environment.PATH = '/test/bin';

  const isolated = isolateGoogleWorkspaceDemoEnvironment(environment);
  for (const name of unsafeNames) assert.equal(isolated[name], undefined);
  assert.equal(isolated.ACTIONPROXY_PORT, undefined);
  assert.deepEqual(isolated, { HOME: '/test/home', PATH: '/test/bin' });

  const [server] = devProcessSpecs(
    ['--server-only', '--google-workspace-demo'],
    environment,
  );
  for (const name of unsafeNames) {
    if (name !== 'ACTIONPROXY_HOST' && name !== 'ACTIONPROXY_STORAGE') {
      assert.equal(server.env[name], undefined);
    }
  }
  assert.equal(server.env.ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND, 'false');
  assert.equal(server.env.ACTIONPROXY_AUTH_MODE, 'none');
  assert.equal(server.env.ACTIONPROXY_DISABLE_LOCAL_ENV_FILES, 'true');
  assert.equal(
    server.env.ACTIONPROXY_DATA_DIR,
    '.actionproxy/google-workspace-mcp/actionproxy-data',
  );
  assert.equal(server.env.ACTIONPROXY_DEPLOYMENT_MODE, 'local');
  assert.equal(server.env.ACTIONPROXY_EMAIL_TRANSPORT, 'outbox');
  assert.equal(server.env.ACTIONPROXY_HOST, '127.0.0.1');
  assert.equal(server.env.ACTIONPROXY_LOCAL_EXECUTION, 'disabled');
  assert.equal(server.env.ACTIONPROXY_MCP_STDIO_DISCOVERY_ENABLED, 'false');
  assert.equal(server.env.ACTIONPROXY_MCP_STREAMABLE_HTTP_ENABLED, 'false');
  assert.equal(server.env.ACTIONPROXY_OTEL_ENABLED, 'false');
  assert.equal(
    server.env.ACTIONPROXY_POLICY_PATH,
    'examples/google-workspace-mcp-demo/actionproxy.policy.yaml',
  );
  assert.equal(server.env.ACTIONPROXY_PORT, '8787');
  assert.equal(server.env.ACTIONPROXY_QUICKSTART_MODE, 'false');
  assert.equal(server.env.ACTIONPROXY_STORAGE, 'memory');

  const [web] = devProcessSpecs(
    ['--web-only', '--google-workspace-demo'],
    environment,
  );
  for (const name of unsafeNames) assert.equal(web.env[name], undefined);
  assert.deepEqual(web.env, { HOME: '/test/home', PATH: '/test/bin' });
});

test('Google Workspace demo launcher does not read repository env files', () => {
  const rootDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'actionproxy-google-demo-env-isolation-'),
  );
  const spawnedEnvironments = [];
  try {
    fs.writeFileSync(
      path.join(rootDirectory, '.env.local'),
      [
        'GOOGLE_OAUTH_CLIENT_SECRET=root-file-canary',
        'DATABASE_URL=postgres://root-file-canary',
        'SLACK_BOT_TOKEN=root-file-canary',
      ].join('\n'),
    );
    const supervisor = startDev({
      args: ['--server-only', '--google-workspace-demo'],
      environment: { HOME: '/test/home', PATH: '/test/bin' },
      rootDirectory,
      spawnProcess: (_command, _args, options) => {
        spawnedEnvironments.push(options.env);
        const child = new EventEmitter();
        child.exitCode = null;
        child.signalCode = null;
        child.kill = () => true;
        return child;
      },
    });
    assert.equal(spawnedEnvironments.length, 1);
    assert.equal(spawnedEnvironments[0].GOOGLE_OAUTH_CLIENT_SECRET, undefined);
    assert.equal(spawnedEnvironments[0].DATABASE_URL, undefined);
    assert.equal(spawnedEnvironments[0].SLACK_BOT_TOKEN, undefined);
    supervisor.dispose();
  } finally {
    fs.rmSync(rootDirectory, { force: true, recursive: true });
  }
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
