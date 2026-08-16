import { execFile, execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';
import { createPgPool, runPostgresMigrations, runSqlite, runSqliteMigrations } from './migrate';

const execFileAsync = promisify(execFile);
const describeIfSqlite = hasSqliteCli() ? describe : describe.skip;
const postgresUrl = process.env.ACTIONPROXY_TEST_POSTGRES_URL;
const describeIfPostgres = postgresUrl ? describe : describe.skip;

describeIfSqlite('SQLite migration ledger', () => {
  it('records an ordered checksum ledger once and uses the stable restart path', () => {
    const databasePath = sqlitePath();

    expect(runSqliteMigrations(databasePath)).toEqual({
      adoptedLegacySchema: false,
      applied: [
        '0001_initial',
        '0002_legacy_schema_reconciliation',
        '0003_approver_principal_identity',
        '0004_unique_approver_principal',
        '0005_unique_approver_effective_identity',
      ],
    });
    expect(runSqliteMigrations(databasePath)).toEqual({ adoptedLegacySchema: false, applied: [] });

    const records = migrationRows(databasePath);
    expect(records.map(({ id, position }) => ({ id, position }))).toEqual([
      { id: '0001_initial', position: 1 },
      { id: '0002_legacy_schema_reconciliation', position: 2 },
      { id: '0003_approver_principal_identity', position: 3 },
      { id: '0004_unique_approver_principal', position: 4 },
      { id: '0005_unique_approver_effective_identity', position: 5 },
    ]);
    expect(records.every((record) => /^[a-f0-9]{64}$/.test(String(record.checksum)))).toBe(true);
    expect(
      runSqlite(
        databasePath,
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'uq_approver_users_workspace_principal';",
        { json: true },
      ),
    ).toEqual([
      {
        sql: expect.stringMatching(/UNIQUE INDEX[\s\S]*\(workspace_id, principal_id\)[\s\S]*WHERE principal_id IS NOT NULL/iu),
      },
    ]);
    expect(
      runSqlite(
        databasePath,
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'uq_approver_users_workspace_effective_identity';",
        { json: true },
      ),
    ).toEqual([
      {
        sql: expect.stringMatching(
          /UNIQUE INDEX[\s\S]*\(workspace_id, COALESCE\(NULLIF\(principal_id, ''\), id\)\)/iu,
        ),
      },
    ]);
  });

  it('fails closed when a pre-0004 database contains duplicate principal bindings', () => {
    const databasePath = sqlitePath();
    runSqliteMigrations(databasePath);
    runSqlite(
      databasePath,
      `DROP INDEX uq_approver_users_workspace_effective_identity;
       DROP INDEX uq_approver_users_workspace_principal;
       DELETE FROM actionproxy_schema_migrations WHERE position >= 4;
       INSERT INTO approver_users (
         id, workspace_id, display_name, principal_id, groups_json, default_approver, enabled, created_at, updated_at
       ) VALUES
         ('u_alice', 'default', 'Alice', 'oidc|shared', '[]', 0, 1, '2026-08-09T10:00:00.000Z', '2026-08-09T10:00:00.000Z'),
         ('u_bob', 'default', 'Bob', 'oidc|shared', '[]', 0, 1, '2026-08-09T10:00:00.000Z', '2026-08-09T10:00:00.000Z');`,
    );

    expect(() => runSqliteMigrations(databasePath)).toThrow(/unique constraint failed/i);
    expect(migrationRows(databasePath).map(({ id, position }) => ({ id, position }))).toEqual([
      { id: '0001_initial', position: 1 },
      { id: '0002_legacy_schema_reconciliation', position: 2 },
      { id: '0003_approver_principal_identity', position: 3 },
    ]);
  });

  it('upgrades a recovered pre-0005 approver directory without rewriting records', () => {
    const databasePath = sqlitePath();
    runSqliteMigrations(databasePath);
    runSqlite(
      databasePath,
      `DROP INDEX uq_approver_users_workspace_effective_identity;
       DELETE FROM actionproxy_schema_migrations WHERE position = 5;
       INSERT INTO approver_users (
         id, workspace_id, display_name, principal_id, groups_json, default_approver, enabled, created_at, updated_at
       ) VALUES
         ('u_recovered', 'default', 'Recovered approver', NULL, '[]', 1, 1, '2026-08-09T10:00:00.000Z', '2026-08-09T10:00:00.000Z'),
         ('u_operator', 'default', 'OIDC operator', 'oidc|operator', '[]', 0, 1, '2026-08-09T10:00:00.000Z', '2026-08-09T10:00:00.000Z');`,
    );
    const before = runSqlite(
      databasePath,
      `SELECT id, workspace_id, display_name, principal_id, default_approver, enabled, created_at, updated_at
       FROM approver_users ORDER BY id;`,
      { json: true },
    );

    expect(runSqliteMigrations(databasePath)).toEqual({
      adoptedLegacySchema: false,
      applied: ['0005_unique_approver_effective_identity'],
    });
    expect(
      runSqlite(
        databasePath,
        `SELECT id, workspace_id, display_name, principal_id, default_approver, enabled, created_at, updated_at
         FROM approver_users ORDER BY id;`,
        { json: true },
      ),
    ).toEqual(before);
    expect(migrationRows(databasePath).map(({ id, position }) => ({ id, position }))).toEqual([
      { id: '0001_initial', position: 1 },
      { id: '0002_legacy_schema_reconciliation', position: 2 },
      { id: '0003_approver_principal_identity', position: 3 },
      { id: '0004_unique_approver_principal', position: 4 },
      { id: '0005_unique_approver_effective_identity', position: 5 },
    ]);
  });

  it('fails closed when a recovered pre-0005 directory has an effective-identity collision', () => {
    const databasePath = sqlitePath();
    runSqliteMigrations(databasePath);
    runSqlite(
      databasePath,
      `DROP INDEX uq_approver_users_workspace_effective_identity;
       DELETE FROM actionproxy_schema_migrations WHERE position = 5;
       INSERT INTO approver_users (
         id, workspace_id, display_name, principal_id, groups_json, default_approver, enabled, created_at, updated_at
       ) VALUES
         ('u_recovered', 'default', 'Recovered approver', 'oidc|operator', '[]', 1, 1, '2026-08-09T10:00:00.000Z', '2026-08-09T10:00:00.000Z'),
         ('oidc|operator', 'default', 'Legacy operator id', NULL, '[]', 0, 1, '2026-08-09T10:00:00.000Z', '2026-08-09T10:00:00.000Z');`,
    );

    expect(() => runSqliteMigrations(databasePath)).toThrow(/unique constraint failed/iu);
    expect(migrationRows(databasePath).map(({ id, position }) => ({ id, position }))).toEqual([
      { id: '0001_initial', position: 1 },
      { id: '0002_legacy_schema_reconciliation', position: 2 },
      { id: '0003_approver_principal_identity', position: 3 },
      { id: '0004_unique_approver_principal', position: 4 },
    ]);
  });

  it('fails closed when an applied migration checksum is rewritten', () => {
    const databasePath = sqlitePath();
    runSqliteMigrations(databasePath);
    runSqlite(
      databasePath,
      "UPDATE actionproxy_schema_migrations SET checksum = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE position = 1;",
    );

    expect(() => runSqliteMigrations(databasePath)).toThrow(/checksum mismatch for 0001_initial/i);
  });

  it.each([
    'f9346e1b1a5048d06c71eb99c706ad69b8af03a05da9d4261708ce4ad633207c',
    'c1b33438c4420dd805b7f10a1314cfa27f9ba9934163d9e4f50f33cb0330bb04',
  ])('recognizes the pre-release 0001 schema checksum %s', (checksum) => {
    const databasePath = sqlitePath();
    runSqliteMigrations(databasePath);
    runSqlite(
      databasePath,
      `UPDATE actionproxy_schema_migrations SET checksum = '${checksum}' WHERE position = 1;
       UPDATE actionproxy_schema_migrations SET checksum = '639e206a317dfd0677d20ff8ddc0d1a44a26f96025657f53705233241f361eaf' WHERE position = 2;
       UPDATE actionproxy_schema_migrations SET checksum = '95e369c548f2c3eabfb399a9b9b076cc3f61c1f107ee2e791734e7d733e91983' WHERE position = 3;`,
    );

    expect(runSqliteMigrations(databasePath)).toEqual({
      adoptedLegacySchema: false,
      applied: [],
    });
  });

  it('rejects migration history that is not the known ordered prefix', () => {
    const databasePath = sqlitePath();
    runSqliteMigrations(databasePath);
    runSqlite(
      databasePath,
      "UPDATE actionproxy_schema_migrations SET id = '0003_unknown' WHERE position = 2;",
    );

    expect(() => runSqliteMigrations(databasePath)).toThrow(/expected 0002_legacy_schema_reconciliation at position 2/i);
  });

  it('reclaims a migration lock left by a dead process', () => {
    const databasePath = sqlitePath();
    const lockPath = `${databasePath}.actionproxy-migrate.lock`;
    fs.writeFileSync(lockPath, JSON.stringify({ createdAt: '2000-01-01T00:00:00.000Z', pid: 2_147_483_647 }));

    expect(runSqliteMigrations(databasePath).applied).toEqual([
      '0001_initial',
      '0002_legacy_schema_reconciliation',
      '0003_approver_principal_identity',
      '0004_unique_approver_principal',
      '0005_unique_approver_effective_identity',
    ]);
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it('serializes concurrent process startup and records each migration once', async () => {
    const databasePath = sqlitePath();
    const migrateUrl = pathToFileURL(path.resolve(process.cwd(), 'src/storage/migrate.ts')).href;
    const script = `import { runSqliteMigrations } from ${JSON.stringify(migrateUrl)}; runSqliteMigrations(${JSON.stringify(databasePath)});`;

    await Promise.all(
      Array.from({ length: 4 }, () =>
        execFileAsync(process.execPath, ['--import', 'tsx', '--input-type=module', '--eval', script], {
          cwd: process.cwd(),
          env: process.env,
          timeout: 20_000,
        }),
      ),
    );

    expect(migrationRows(databasePath).map((record) => record.id)).toEqual([
      '0001_initial',
      '0002_legacy_schema_reconciliation',
      '0003_approver_principal_identity',
      '0004_unique_approver_principal',
      '0005_unique_approver_effective_identity',
    ]);
    expect(fs.existsSync(`${databasePath}.actionproxy-migrate.lock`)).toBe(false);
  }, 25_000);
});

describeIfPostgres('Postgres migration ledger', () => {
  it('serializes concurrent startup with a transaction-scoped advisory lock', async () => {
    const schema = `ap_migration_${randomUUID().replaceAll('-', '')}`;
    const administrator = await createPgPool(postgresUrl!);
    try {
      await administrator.query(`CREATE SCHEMA ${quoteIdentifier(schema)}`);
      const scopedUrl = postgresUrlForSchema(postgresUrl!, schema);
      const reports = await Promise.all(Array.from({ length: 4 }, () => runPostgresMigrations(scopedUrl)));
      expect(reports.filter((report) => report.applied.length === 5)).toHaveLength(1);
      expect(reports.filter((report) => report.applied.length === 0)).toHaveLength(3);

      const scoped = await createPgPool(scopedUrl);
      try {
        const records = await scoped.query<{ checksum: string; id: string; position: number }>(
          'SELECT id, position, checksum FROM actionproxy_schema_migrations ORDER BY position',
        );
        expect(records.rows.map(({ id, position }) => ({ id, position }))).toEqual([
          { id: '0001_initial', position: 1 },
          { id: '0002_legacy_schema_reconciliation', position: 2 },
          { id: '0003_approver_principal_identity', position: 3 },
          { id: '0004_unique_approver_principal', position: 4 },
          { id: '0005_unique_approver_effective_identity', position: 5 },
        ]);
        expect(records.rows.every((record) => /^[a-f0-9]{64}$/.test(record.checksum))).toBe(true);
        await scoped.query(
          "UPDATE actionproxy_schema_migrations SET checksum = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' WHERE position = 1",
        );
        await expect(runPostgresMigrations(scopedUrl)).rejects.toThrow(/checksum mismatch for 0001_initial/i);
      } finally {
        await scoped.end();
      }
    } finally {
      await administrator.query(`DROP SCHEMA IF EXISTS ${quoteIdentifier(schema)} CASCADE`);
      await administrator.end();
    }
  }, 30_000);
});

function sqlitePath(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-migrate-test-')), 'actionproxy.sqlite');
}

function migrationRows(databasePath: string): Array<Record<string, unknown>> {
  return runSqlite(
    databasePath,
    'SELECT id, position, checksum, applied_at FROM actionproxy_schema_migrations ORDER BY position;',
    { json: true },
  ) as Array<Record<string, unknown>>;
}

function postgresUrlForSchema(database: string, schema: string): string {
  const url = new URL(database);
  url.searchParams.set('options', `-c search_path=${schema}`);
  return url.toString();
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function hasSqliteCli(): boolean {
  try {
    execFileSync('sqlite3', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
