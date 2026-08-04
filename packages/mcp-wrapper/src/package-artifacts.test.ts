import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
);
const corepack = process.platform === 'win32' ? 'corepack.cmd' : 'corepack';
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const expectedPackageFiles = [
  'LICENSE',
  'README.md',
  'dist/index.d.ts',
  'dist/index.js',
  'package.json',
];

describe('independently packed npm artifacts', () => {
  it('installs SDK and MCP tarballs into an isolated consumer and exercises their public surfaces', () => {
    const temporaryRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), 'actionproxy-package-consumer-'),
    );

    try {
      assertCanonicalPackageManifests();

      const artifactsDirectory = path.join(temporaryRoot, 'artifacts');
      const consumerDirectory = path.join(temporaryRoot, 'consumer');
      fs.mkdirSync(artifactsDirectory, { recursive: true, mode: 0o700 });
      fs.mkdirSync(consumerDirectory, { recursive: true, mode: 0o700 });

      const sdkTarball = path.join(
        artifactsDirectory,
        'actionproxy-sdk-js-0.1.0.tgz',
      );
      const mcpTarball = path.join(
        artifactsDirectory,
        'actionproxy-mcp-wrapper-0.1.0.tgz',
      );
      const yamlTarball = path.join(artifactsDirectory, 'yaml.tgz');
      const sdkReport = pack('@actionproxy/sdk-js', sdkTarball);
      const mcpReport = pack('@actionproxy/mcp-wrapper', mcpTarball);
      const npmCacheDirectory = path.join(temporaryRoot, 'npm-cache');
      const sdkNpmReport = npmPackDryRun('sdk-js', npmCacheDirectory);
      const mcpNpmReport = npmPackDryRun('mcp-wrapper', npmCacheDirectory);
      const yamlPackageRoot = path.dirname(
        createRequire(import.meta.url).resolve('yaml/package.json'),
      );
      run(
        corepack,
        ['pnpm', 'pack', '--out', yamlTarball],
        yamlPackageRoot,
      );

      assertExactPackageInventory(sdkReport.files);
      assertExactPackageInventory(mcpReport.files);
      assertExactPackageInventory(sdkNpmReport.files);
      assertExactPackageInventory(mcpNpmReport.files);
      expect(sdkNpmReport.entryCount).toBe(5);
      expect(mcpNpmReport.entryCount).toBe(5);
      expect(
        mcpNpmReport.files.find(({ path: filePath }) =>
          filePath === 'dist/index.js'
        )?.mode,
      ).toBe(0o755);

      const configPath = path.join(consumerDirectory, 'actionproxy.mcp.yaml');
      fs.writeFileSync(
        configPath,
        [
          'actionproxy:',
          '  baseUrl: http://127.0.0.1:8787',
          '  requestedBy: packed-consumer@example.com',
          '  agentId: packed-consumer',
          'servers:',
          '  fixture:',
          `    command: ${JSON.stringify(process.execPath)}`,
          '',
        ].join('\n'),
        'utf8',
      );
      fs.writeFileSync(
        path.join(consumerDirectory, 'package.json'),
        `${JSON.stringify(
          {
            name: 'actionproxy-isolated-package-consumer',
            version: '1.0.0',
            private: true,
            type: 'module',
            packageManager: 'pnpm@11.10.0',
            dependencies: {
              '@actionproxy/mcp-wrapper': `file:${mcpTarball}`,
              '@actionproxy/sdk-js': `file:${sdkTarball}`,
            },
          },
          null,
          2,
        )}\n`,
        'utf8',
      );
      fs.writeFileSync(
        path.join(consumerDirectory, 'pnpm-workspace.yaml'),
        [
          'packages:',
          '  - .',
          'overrides:',
          `  yaml: ${JSON.stringify(`file:${yamlTarball}`)}`,
          '',
        ].join('\n'),
        'utf8',
      );
      fs.writeFileSync(
        path.join(consumerDirectory, 'consumer.mjs'),
        consumerSource(),
        'utf8',
      );

      expect(
        run(corepack, ['pnpm', '--version'], consumerDirectory).stdout.trim(),
      ).toBe('11.10.0');

      run(
        corepack,
        [
          'pnpm',
          'install',
          '--offline',
          '--ignore-scripts',
          '--store-dir',
          path.join(temporaryRoot, 'pnpm-store'),
        ],
        consumerDirectory,
      );

      for (const packageName of [
        '@actionproxy/sdk-js',
        '@actionproxy/mcp-wrapper',
      ]) {
        const canonicalConsumerDirectory = fs.realpathSync(consumerDirectory);
        const canonicalRepositoryRoot = fs.realpathSync(repositoryRoot);
        const installedRoot = fs.realpathSync(
          path.join(consumerDirectory, 'node_modules', packageName),
        );
        expect(
          installedRoot.startsWith(`${canonicalConsumerDirectory}${path.sep}`),
        ).toBe(true);
        expect(
          installedRoot.startsWith(`${canonicalRepositoryRoot}${path.sep}`),
        ).toBe(false);
        assertInstalledManifest(packageName, installedRoot);
      }

      const sdkDeclarations = fs.readFileSync(
        path.join(
          consumerDirectory,
          'node_modules/@actionproxy/sdk-js/dist/index.d.ts',
        ),
        'utf8',
      );
      expect(sdkDeclarations).toContain('ActionProxyDecisionV1');
      expect(sdkDeclarations).toContain('runExternalAction');
      const mcpDeclarations = fs.readFileSync(
        path.join(
          consumerDirectory,
          'node_modules/@actionproxy/mcp-wrapper/dist/index.d.ts',
        ),
        'utf8',
      );
      expect(mcpDeclarations).toContain('ConfiguredMcpWrapperReportV1');
      expect(mcpDeclarations).toContain('runMcpWrapperCli');

      const consumer = run(
        process.execPath,
        ['consumer.mjs'],
        consumerDirectory,
      );
      expect(JSON.parse(consumer.stdout)).toEqual({
        mcpContract: 'actionproxy.tool-plane-report.v1',
        sdkCalls: 1,
        sdkOutcome: 'executed',
        unknownOutcome: true,
      });

      const binary = path.join(
        consumerDirectory,
        'node_modules',
        '.bin',
        process.platform === 'win32'
          ? 'actionproxy-mcp.cmd'
          : 'actionproxy-mcp',
      );
      expect(fs.existsSync(binary)).toBe(true);
      const doctor = run(
        binary,
        ['doctor', '--config', configPath, '--json'],
        consumerDirectory,
      );
      const report = JSON.parse(doctor.stdout) as {
        coverage?: string;
        mode?: string;
        ok?: boolean;
        version?: string;
      };
      expect(report).toMatchObject({
        coverage: 'configured_mcp_wrapper',
        mode: 'static',
        ok: true,
        version: 'actionproxy.tool-plane-report.v1',
      });
    } finally {
      fs.rmSync(temporaryRoot, { force: true, recursive: true });
    }
  }, 120_000);
});

interface PackReport {
  files: Array<{ path: string }>;
  name: string;
  version: string;
}

interface NpmPackReport extends PackReport {
  entryCount: number;
  files: Array<{ mode: number; path: string }>;
}

function pack(packageName: string, outputPath: string): PackReport {
  const result = run(
    corepack,
    [
      'pnpm',
      '--filter',
      packageName,
      'pack',
      '--out',
      outputPath,
      '--json',
    ],
    repositoryRoot,
  );
  const jsonStart = result.stdout.lastIndexOf('\n{');
  if (jsonStart === -1) {
    throw new Error(`pnpm pack did not return its JSON report:\n${result.stdout}`);
  }
  const report = JSON.parse(result.stdout.slice(jsonStart + 1)) as PackReport;
  expect(report.name).toBe(packageName);
  expect(report.version).toBe('0.1.0');
  expect(fs.existsSync(outputPath)).toBe(true);
  return report;
}

function npmPackDryRun(
  packageDirectory: string,
  npmCacheDirectory: string,
): NpmPackReport {
  const result = run(
    npm,
    ['pack', '--dry-run', '--json'],
    path.join(repositoryRoot, 'packages', packageDirectory),
    { npm_config_cache: npmCacheDirectory },
  );
  const jsonStart = result.stdout.lastIndexOf('\n[');
  if (jsonStart === -1 && !result.stdout.startsWith('[')) {
    throw new Error(
      `npm pack --dry-run did not return its JSON report:\n${result.stdout}`,
    );
  }
  const reports = JSON.parse(
    result.stdout.slice(jsonStart === -1 ? 0 : jsonStart + 1),
  ) as NpmPackReport[];
  expect(reports).toHaveLength(1);
  const report = reports[0];
  if (!report) {
    throw new Error('npm pack --dry-run returned an empty JSON report');
  }
  expect(report.name).toBe(`@actionproxy/${packageDirectory}`);
  expect(report.version).toBe('0.1.0');
  return report;
}

function assertExactPackageInventory(
  files: Array<{ path: string }>,
): void {
  const actual = files
    .map(({ path: filePath }) => filePath)
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  expect(actual).toEqual(expectedPackageFiles);
  expect(new Set(actual).size).toBe(5);
}

function assertCanonicalPackageManifests(): void {
  for (const packageName of ['sdk-js', 'mcp-wrapper']) {
    const workspacePath = path.join(
      repositoryRoot,
      'packages',
      packageName,
      'package.json',
    );
    const workspace = readJson(workspacePath);
    const publicCanonicalPath = path.join(
      repositoryRoot,
      'scripts/public-repo',
      `${packageName}.package.json`,
    );
    if (fs.existsSync(publicCanonicalPath)) {
      expect(
        Buffer.compare(
          fs.readFileSync(publicCanonicalPath),
          fs.readFileSync(workspacePath),
        ),
      ).toBe(0);
      expect(readJson(publicCanonicalPath)).toEqual(workspace);
    }
    expect(workspace.private).toBeUndefined();
    expect(workspace.version).toBe('0.1.0');
    expect(workspace.files).toEqual(['dist']);
    expect(workspace.engines).toEqual({ node: '>=22 <25' });
    expect(workspace.repository).toEqual({
      type: 'git',
      url: 'git+https://github.com/ActionProxy/actionproxy.git',
      directory: `packages/${packageName}`,
    });
    expect(workspace.homepage).toBe(
      'https://github.com/ActionProxy/actionproxy#readme',
    );
    expect(workspace.bugs).toEqual({
      url: 'https://github.com/ActionProxy/actionproxy/issues',
    });
    expect(workspace.keywords).toEqual(
      packageName === 'sdk-js'
        ? [
            'ai-agents',
            'approval-gateway',
            'audit',
            'human-in-the-loop',
            'tool-calls',
          ]
        : [
            'ai-agents',
            'approval-gateway',
            'audit',
            'human-in-the-loop',
            'mcp',
            'model-context-protocol',
          ],
    );
    expect(workspace.publishConfig).toEqual({
      access: 'public',
      registry: 'https://registry.npmjs.org/',
    });
    expect(workspace.scripts?.prepack).toBe('npm run build');
    expect(
      Buffer.compare(
        fs.readFileSync(path.join(repositoryRoot, 'LICENSE')),
        fs.readFileSync(
          path.join(repositoryRoot, 'packages', packageName, 'LICENSE'),
        ),
      ),
    ).toBe(0);
    const readme = fs.readFileSync(
      path.join(repositoryRoot, 'packages', packageName, 'README.md'),
      'utf8',
    );
    expect(readme).toContain(
      'https://github.com/ActionProxy/actionproxy/issues',
    );
    expect(readme).toContain(
      'https://github.com/ActionProxy/actionproxy/security/policy',
    );
  }
}

function assertInstalledManifest(
  packageName: string,
  installedRoot: string,
): void {
  const manifest = readJson(path.join(installedRoot, 'package.json'));
  expect(manifest.name).toBe(packageName);
  expect(manifest.version).toBe('0.1.0');
  expect(manifest.private).toBeUndefined();
  expect(manifest.files).toEqual(['dist']);
  expect(manifest.engines).toEqual({ node: '>=22 <25' });
  expect(manifest.publishConfig).toEqual({
    access: 'public',
    registry: 'https://registry.npmjs.org/',
  });
  expect(fs.existsSync(path.join(installedRoot, 'README.md'))).toBe(true);
  expect(fs.existsSync(path.join(installedRoot, 'LICENSE'))).toBe(true);
  expect(fs.existsSync(path.join(installedRoot, 'dist/index.js'))).toBe(true);
  expect(fs.existsSync(path.join(installedRoot, 'dist/index.d.ts'))).toBe(true);
  expect(fs.existsSync(path.join(installedRoot, 'src'))).toBe(false);
}

function readJson(filePath: string): Record<string, any> {
  return JSON.parse(fs.readFileSync(filePath, 'utf8')) as Record<string, any>;
}

function run(
  command: string,
  args: string[],
  cwd: string,
  environment: Record<string, string | undefined> = {},
): { stderr: string; stdout: string } {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_PATH: undefined,
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      ...environment,
    },
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail = [
      result.error?.message,
      result.stderr,
      result.stdout,
      `exit ${String(result.status)}`,
    ]
      .filter(Boolean)
      .join('\n');
    throw new Error(
      `${command} ${args.join(' ')} failed: ${detail}`,
    );
  }
  return { stderr: result.stderr, stdout: result.stdout };
}

function consumerSource(): string {
  return `import assert from 'node:assert/strict';
import {
  ActionProxyClient,
  ActionProxyExternalActionError,
  runExternalAction,
} from '@actionproxy/sdk-js';
import {
  TOOL_PLANE_REPORT_VERSION,
  loadMcpWrapperConfig,
} from '@actionproxy/mcp-wrapper';

const requests = [];
let currentFlow = 'success';
let downstreamCalls = 0;
const toolCall = () => ({
  decision: 'allow',
  id: 'tc_' + currentFlow,
  input: { customerId: 'cus_123' },
  policyVersionHash: 'policy_v1',
  result: { grant: { id: 'grant_' + currentFlow } },
  status: 'authorized',
  toolName: 'crm.update_customer',
});
const json = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  text: async () => JSON.stringify(body),
});
const client = new ActionProxyClient({
  baseUrl: 'http://127.0.0.1:8787',
  fetch: async (url, init = {}) => {
    const route = new URL(url).pathname;
    const body = init.body ? JSON.parse(init.body) : undefined;
    requests.push({ body, method: init.method ?? 'GET', route });
    if (route === '/v1/tool-calls' && init.method === 'POST') {
      return json({ id: toolCall().id, status: 'authorized', toolCall: toolCall() });
    }
    if (route === '/v1/tool-calls/' + toolCall().id) return json(toolCall());
    if (route.endsWith('/consume')) return json({ grant: { id: 'grant_' + currentFlow }, ok: true });
    if (route.endsWith('/outcome')) {
      return json({ toolCall: { ...toolCall(), status: body.status === 'succeeded' ? 'executed' : 'failed' } });
    }
    return json({ error: 'unexpected_route' }, 404);
  },
});

const succeeded = await runExternalAction({
  agentId: 'packed-consumer',
  client,
  execute: async (input) => {
    downstreamCalls += 1;
    return { updatedCustomerId: input.customerId };
  },
  idempotencyKey: 'packed-consumer-success',
  input: { customerId: 'cus_123' },
  reason: 'Exercise the packed SDK external-runner boundary.',
  requestedBy: 'packed-consumer@example.com',
  toolName: 'crm.update_customer',
});
assert.equal(succeeded.toolCall.status, 'executed');
assert.equal(downstreamCalls, 1);

currentFlow = 'unknown';
let unknownOutcome = false;
try {
  await runExternalAction({
    agentId: 'packed-consumer',
    client,
    execute: async () => {
      throw new Error('ambiguous provider response');
    },
    idempotencyKey: 'packed-consumer-unknown',
    input: { customerId: 'cus_123' },
    reason: 'Prove ambiguous outcomes do not become success.',
    requestedBy: 'packed-consumer@example.com',
    toolName: 'crm.update_customer',
  });
} catch (error) {
  assert.ok(error instanceof ActionProxyExternalActionError);
  unknownOutcome = true;
}
assert.equal(requests.at(-1).body.status, 'unknown_outcome');
assert.equal(requests.filter(({ route }) => route.endsWith('/consume')).length, 2);

const config = loadMcpWrapperConfig('./actionproxy.mcp.yaml', {});
assert.equal(config.actionproxy.baseUrl, 'http://127.0.0.1:8787');
assert.equal(config.servers.fixture.command, process.execPath);

process.stdout.write(JSON.stringify({
  mcpContract: TOOL_PLANE_REPORT_VERSION,
  sdkCalls: downstreamCalls,
  sdkOutcome: succeeded.toolCall.status,
  unknownOutcome,
}));
`;
}
