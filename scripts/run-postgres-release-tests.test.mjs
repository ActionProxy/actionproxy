import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createPostgresReleaseTestArgs,
  postgresReleaseTestFiles,
  validatePostgresReleaseReport,
} from './run-postgres-release-tests.mjs';

function passingReport(overrides = {}) {
  return {
    numFailedTests: 0,
    numPendingTests: 0,
    numTodoTests: 0,
    numTotalTests: 17,
    testResults: postgresReleaseTestFiles.map((file) => ({
      name: `/checkout/apps/server/${file}`,
    })),
    ...overrides,
  };
}

test('Postgres release invocation is serial, explicit, and machine-reportable', () => {
  const args = createPostgresReleaseTestArgs('/tmp/report.json');
  assert.deepEqual(args.slice(0, 8), [
    'pnpm',
    '--filter',
    '@actionproxy/server',
    'exec',
    'vitest',
    'run',
    '--config',
    'vitest.config.ts',
  ]);
  assert.ok(args.includes('--no-file-parallelism'));
  assert.ok(args.includes('--reporter=json'));
  assert.ok(args.includes('--outputFile=/tmp/report.json'));
  for (const file of postgresReleaseTestFiles) assert.ok(args.includes(file));
});

test('Postgres release report accepts all five required files with zero skips', () => {
  assert.equal(validatePostgresReleaseReport(passingReport()), 17);
});

test('Postgres release report rejects skips, todos, failures, and missing files', () => {
  assert.throws(
    () => validatePostgresReleaseReport(passingReport({ numPendingTests: 1 })),
    /zero skips\/todos/,
  );
  assert.throws(
    () => validatePostgresReleaseReport(passingReport({ numTodoTests: 1 })),
    /zero skips\/todos/,
  );
  assert.throws(
    () => validatePostgresReleaseReport(passingReport({ numFailedTests: 1 })),
    /1 failed test/,
  );
  assert.throws(
    () => validatePostgresReleaseReport(passingReport({ testResults: [] })),
    /omitted required Postgres release files/,
  );
});
