#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const postgresReleaseTestFiles = [
  'src/storage/postgres-atomicity.test.ts',
  'src/storage/migrate.test.ts',
  'src/storage/forensic-query-store.test.ts',
  'src/storage/content-influence-upgrade.test.ts',
  'src/routes/mcp-backends.test.ts',
];

export function createPostgresReleaseTestArgs(reportPath) {
  return [
    'pnpm',
    '--filter',
    '@actionproxy/server',
    'exec',
    'vitest',
    'run',
    '--config',
    'vitest.config.ts',
    '--no-file-parallelism',
    '--reporter=json',
    `--outputFile=${reportPath}`,
    ...postgresReleaseTestFiles,
  ];
}

export function validatePostgresReleaseReport(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('Vitest did not produce a JSON release-test report.');
  }
  const total = requiredCount(report.numTotalTests, 'numTotalTests');
  const failed = requiredCount(report.numFailedTests, 'numFailedTests');
  const skipped = requiredCount(report.numPendingTests, 'numPendingTests');
  const todo = optionalCount(report.numTodoTests, 'numTodoTests');
  if (total === 0) throw new Error('Postgres release suite ran zero tests.');
  if (failed !== 0) throw new Error(`Postgres release suite reports ${failed} failed test(s).`);
  if (skipped !== 0 || todo !== 0) {
    throw new Error(
      `Postgres release suite must have zero skips/todos; received ${skipped} skipped and ${todo} todo.`,
    );
  }

  if (!Array.isArray(report.testResults)) {
    throw new Error('Vitest report is missing testResults.');
  }
  const reportedFiles = report.testResults
    .map((result) => typeof result?.name === 'string' ? result.name.replaceAll('\\', '/') : '')
    .filter(Boolean);
  const missing = postgresReleaseTestFiles.filter((relativePath) => {
    const suffix = `/apps/server/${relativePath}`;
    return !reportedFiles.some((reportedPath) =>
      reportedPath === relativePath || reportedPath.endsWith(suffix),
    );
  });
  if (missing.length > 0) {
    throw new Error(`Vitest report omitted required Postgres release files: ${missing.join(', ')}`);
  }
  return total;
}

function main() {
  const databaseUrl = process.env.ACTIONPROXY_TEST_POSTGRES_URL?.trim();
  if (!databaseUrl) {
    throw new Error('ACTIONPROXY_TEST_POSTGRES_URL is required for the zero-skip Postgres release suite.');
  }
  assertCommandAvailable('sqlite3', ['--version']);

  const reportDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-postgres-release-'));
  const reportPath = path.join(reportDirectory, 'vitest.json');
  try {
    const result = spawnSync('corepack', createPostgresReleaseTestArgs(reportPath), {
      encoding: 'utf8',
      env: {
        ...process.env,
        ACTIONPROXY_REQUIRE_POSTGRES_TESTS: '1',
        ACTIONPROXY_TEST_POSTGRES_URL: databaseUrl,
      },
      maxBuffer: 32 * 1024 * 1024,
      shell: process.platform === 'win32',
    });
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(`Postgres release suite exited with status ${result.status}.`);
    }
    if (!fs.existsSync(reportPath)) {
      throw new Error('Postgres release suite did not write its JSON report.');
    }
    const count = validatePostgresReleaseReport(
      JSON.parse(fs.readFileSync(reportPath, 'utf8')),
    );
    console.log(
      `Postgres release suite passed ${count} tests across ${postgresReleaseTestFiles.length} required files with zero skips.`,
    );
  } finally {
    fs.rmSync(reportDirectory, { force: true, recursive: true });
  }
}

function assertCommandAvailable(command, args) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${command} is required for zero-skip SQLite coverage in the Postgres release job.`,
    );
  }
}

function requiredCount(value, field) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`Vitest report has invalid ${field}.`);
  }
  return value;
}

function optionalCount(value, field) {
  if (value === undefined) return 0;
  return requiredCount(value, field);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
