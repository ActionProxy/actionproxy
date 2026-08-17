import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { PolicyFile } from '../policy/policy-types';

export interface PolicyVersionRecord {
  id: string;
  version: string;
  policy: PolicyFile;
  createdAt: string;
}

export interface PolicyVersionStore {
  recordPolicyVersion(record: PolicyVersionRecord): Promise<void>;
}

export interface StorageMigrationRecord {
  id: string;
  position: number;
  checksum: string;
  appliedAt: string;
}

export interface StorageMigrationReport {
  adoptedLegacySchema: boolean;
  applied: string[];
}

interface StorageMigration {
  id: string;
  position: number;
  checksum: string;
  recognizedChecksums?: readonly string[];
  sql?: string;
}

interface LegacyColumnAddition {
  column: string;
  table: string;
  type: 'TEXT';
}

const SQLITE_BUSY_TIMEOUT_MS = 10_000;
const SQLITE_PROCESS_TIMEOUT_MS = 30_000;
const SQLITE_MIGRATION_LOCK_TIMEOUT_MS = 10_000;
const SQLITE_MIGRATION_LOCK_RETRY_MS = 25;
const SQLITE_MALFORMED_LOCK_STALE_MS = SQLITE_MIGRATION_LOCK_TIMEOUT_MS;
const MIGRATION_LEDGER_TABLE = 'actionproxy_schema_migrations';
const LEGACY_SCHEMA_MIGRATION_ID = '0002_legacy_schema_reconciliation';
const APPROVER_PRINCIPAL_MIGRATION_ID = '0003_approver_principal_identity';
const UNIQUE_APPROVER_PRINCIPAL_MIGRATION_ID = '0004_unique_approver_principal';
const UNIQUE_APPROVER_EFFECTIVE_IDENTITY_MIGRATION_ID =
  '0005_unique_approver_effective_identity';
const CORE_SCHEMA_TABLES = ['approvals', 'audit_events', 'tool_calls'] as const;

export function loadInitialMigrationSql(): string {
  return loadMigrationSql('0001_initial.sql');
}

export function loadMigrationSql(filename: string): string {
  const candidates = [
    path.resolve(process.cwd(), 'src/storage/migrations', filename),
    path.resolve(process.cwd(), 'apps/server/src/storage/migrations', filename),
    path.resolve(process.cwd(), 'dist/storage/migrations', filename),
  ];
  const migrationPath = candidates.find((candidate) => fs.existsSync(candidate));
  if (!migrationPath) {
    throw new Error(`Could not find storage migration ${filename}. Tried: ${candidates.join(', ')}`);
  }

  return fs.readFileSync(migrationPath, 'utf8');
}

export function storageMigrations(): readonly StorageMigration[] {
  const initialSql = loadInitialMigrationSql();
  const reconciliationSql = loadMigrationSql('0002_legacy_schema_reconciliation.sql');
  const approverPrincipalSql = loadMigrationSql('0003_approver_principal_identity.sql');
  const uniqueApproverPrincipalSql = loadMigrationSql('0004_unique_approver_principal.sql');
  const uniqueApproverEffectiveIdentitySql = loadMigrationSql(
    '0005_unique_approver_effective_identity.sql',
  );
  return [
    {
      checksum: migrationChecksum(initialSql),
      id: '0001_initial',
      position: 1,
      recognizedChecksums: [
        'f9346e1b1a5048d06c71eb99c706ad69b8af03a05da9d4261708ce4ad633207c',
        'c1b33438c4420dd805b7f10a1314cfa27f9ba9934163d9e4f50f33cb0330bb04',
      ],
      sql: initialSql,
    },
    {
      checksum: migrationChecksum(reconciliationSql),
      id: LEGACY_SCHEMA_MIGRATION_ID,
      position: 2,
      recognizedChecksums: ['639e206a317dfd0677d20ff8ddc0d1a44a26f96025657f53705233241f361eaf'],
      sql: reconciliationSql,
    },
    {
      checksum: migrationChecksum(approverPrincipalSql),
      id: APPROVER_PRINCIPAL_MIGRATION_ID,
      position: 3,
      recognizedChecksums: ['95e369c548f2c3eabfb399a9b9b076cc3f61c1f107ee2e791734e7d733e91983'],
      sql: approverPrincipalSql,
    },
    {
      checksum: migrationChecksum(uniqueApproverPrincipalSql),
      id: UNIQUE_APPROVER_PRINCIPAL_MIGRATION_ID,
      position: 4,
      sql: uniqueApproverPrincipalSql,
    },
    {
      checksum: migrationChecksum(uniqueApproverEffectiveIdentitySql),
      id: UNIQUE_APPROVER_EFFECTIVE_IDENTITY_MIGRATION_ID,
      position: 5,
      sql: uniqueApproverEffectiveIdentitySql,
    },
  ];
}

export function runSqliteMigrations(databasePath: string): StorageMigrationReport {
  const resolvedPath = path.resolve(databasePath);
  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
  return withSqliteMigrationLock(resolvedPath, () => {
    const migrations = storageMigrations();
    const stateRows = runSqlite(resolvedPath, `${sqliteMigrationLedgerSql()}
      SELECT
        '__actionproxy_state__' AS id,
        0 AS position,
        '' AS checksum,
        '' AS applied_at,
        EXISTS (
          SELECT 1 FROM sqlite_master
          WHERE type = 'table' AND name IN (${CORE_SCHEMA_TABLES.map(sqlLiteral).join(', ')})
        ) AS legacy_schema_present
      UNION ALL
      SELECT id, position, checksum, applied_at, 0 AS legacy_schema_present
      FROM ${MIGRATION_LEDGER_TABLE}
      ORDER BY position;
    `, { json: true }) as Record<string, unknown>[];
    const state = stateRows.find((row) => row.id === '__actionproxy_state__');
    const applied = stateRows
      .filter((row) => row.id !== '__actionproxy_state__')
      .map(sqliteMigrationRecordFromRow);
    validateMigrationLedger(applied, migrations);
    const adoptedLegacySchema = applied.length === 0 && Number(state?.legacy_schema_present ?? 0) === 1;
    const appliedIds: string[] = [];

    for (const migration of migrations.slice(applied.length)) {
      if (migration.id === LEGACY_SCHEMA_MIGRATION_ID) {
        applySqliteLegacySchemaMigration(resolvedPath, migration);
      } else if (migration.sql !== undefined) {
        applySqliteMigrationSql(resolvedPath, migration);
      } else {
        throw new Error(`Storage migration ${migration.id} has no SQLite implementation.`);
      }
      appliedIds.push(migration.id);
    }

    return { adoptedLegacySchema, applied: appliedIds };
  });
}

export async function runPostgresMigrations(databaseUrl: string): Promise<StorageMigrationReport> {
  const pool = await createPgPool(databaseUrl);
  try {
    return await runPostgresMigrationsWithPool(pool);
  } finally {
    await pool.end();
  }
}

export async function runPostgresMigrationsWithPool(pool: PgPool): Promise<StorageMigrationReport> {
  if (!pool.connect) throw new Error('Postgres pool does not support checked-out migration transactions.');
  const migrations = storageMigrations();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext(current_database()), hashtext(current_schema()))');
    await client.query(postgresMigrationLedgerSql());
    const applied = (
      await client.query<Record<string, unknown>>(
        `SELECT id, position, checksum, applied_at FROM ${MIGRATION_LEDGER_TABLE} ORDER BY position`,
      )
    ).rows.map(postgresMigrationRecordFromRow);
    validateMigrationLedger(applied, migrations);
    const legacySchemaPresent = Boolean(
      (
        await client.query<{ present: boolean }>(
          `SELECT EXISTS (
             SELECT 1 FROM information_schema.tables
             WHERE table_schema = current_schema()
               AND table_name = ANY($1::text[])
           ) AS present`,
          [[...CORE_SCHEMA_TABLES]],
        )
      ).rows[0]?.present,
    );
    const adoptedLegacySchema = applied.length === 0 && legacySchemaPresent;
    const appliedIds: string[] = [];

    for (const migration of migrations.slice(applied.length)) {
      if (migration.id === LEGACY_SCHEMA_MIGRATION_ID) {
        await applyPostgresLegacySchemaMigration(client, migration);
      } else if (migration.sql !== undefined) {
        await client.query(migration.sql);
      } else {
        throw new Error(`Storage migration ${migration.id} has no Postgres implementation.`);
      }
      await client.query(
        `INSERT INTO ${MIGRATION_LEDGER_TABLE} (id, position, checksum, applied_at) VALUES ($1, $2, $3, $4)`,
        [migration.id, migration.position, migration.checksum, new Date().toISOString()],
      );
      appliedIds.push(migration.id);
    }

    await client.query('COMMIT');
    return { adoptedLegacySchema, applied: appliedIds };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export function runSqlite(
  databasePath: string,
  sql: string,
  options: { json?: boolean; processTimeoutMs?: number } = {},
): unknown[] {
  const args = [
    '-bail',
    '-batch',
    '-cmd',
    `.timeout ${SQLITE_BUSY_TIMEOUT_MS}`,
    ...(options.json ? ['-json'] : []),
    databasePath,
  ];
  const output = execFileSync('sqlite3', args, {
    encoding: 'utf8',
    input: sql,
    maxBuffer: 1024 * 1024 * 10,
    timeout: options.processTimeoutMs ?? SQLITE_PROCESS_TIMEOUT_MS,
  }).trim();

  if (!options.json || !output) return [];
  return JSON.parse(output) as unknown[];
}

export function sqlLiteral(value: string | null | undefined): string {
  if (value === null || value === undefined) return 'NULL';
  return `'${value.replaceAll("'", "''")}'`;
}

export function sqlJsonLiteral(value: unknown): string {
  return sqlLiteral(JSON.stringify(value));
}

export interface PgQueryable {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

export interface PgClient extends PgQueryable {
  release(): void;
}

export interface PgPool extends PgQueryable {
  connect?(): Promise<PgClient>;
  end(): Promise<void>;
}

interface PgModule {
  Pool: new (config: { connectionString: string }) => PgPool;
}

export async function createPgPool(databaseUrl: string): Promise<PgPool> {
  try {
    const specifier: string = 'pg';
    const pg = (await import(specifier)) as PgModule;
    return new pg.Pool({ connectionString: databaseUrl });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Postgres storage requires the "pg" package to be installed. ${message}`);
  }
}

function applySqliteMigrationSql(databasePath: string, migration: StorageMigration): void {
  runSqlite(databasePath, `
    BEGIN IMMEDIATE;
    ${migration.sql ?? ''}
    ${sqliteMigrationInsertSql(migration)}
    COMMIT;
  `);
}

function applySqliteLegacySchemaMigration(databasePath: string, migration: StorageMigration): void {
  const additions = legacyColumnAdditions(migration);
  const tableNames = [...new Set(additions.map((entry) => entry.table))];
  const existingRows = runSqlite(
    databasePath,
    tableNames
      .map(
        (table) =>
          `SELECT ${sqlLiteral(table)} AS table_name, name AS column_name FROM pragma_table_info(${sqlLiteral(table)})`,
      )
      .join('\nUNION ALL\n') + ';',
    { json: true },
  ) as Record<string, unknown>[];
  const existing = new Set(existingRows.map((row) => `${String(row.table_name)}.${String(row.column_name)}`));
  const alterations = additions.filter(
    (entry) => !existing.has(`${entry.table}.${entry.column}`),
  ).map(
    (entry) =>
      `ALTER TABLE ${quoteIdentifier(entry.table)} ADD COLUMN ${quoteIdentifier(entry.column)} ${entry.type};`,
  );

  runSqlite(databasePath, `
    BEGIN IMMEDIATE;
    ${alterations.join('\n')}
    ${sqliteMigrationInsertSql(migration)}
    COMMIT;
  `);
}

async function applyPostgresLegacySchemaMigration(
  queryable: PgQueryable,
  migration: StorageMigration,
): Promise<void> {
  const additions = legacyColumnAdditions(migration);
  await queryable.query(
    additions.map(
      (entry) =>
        `ALTER TABLE ${quoteIdentifier(entry.table)} ADD COLUMN IF NOT EXISTS ${quoteIdentifier(entry.column)} ${entry.type};`,
    ).join('\n'),
  );
}

function legacyColumnAdditions(
  migration: StorageMigration,
): readonly LegacyColumnAddition[] {
  const sql = migration.sql;
  if (!sql) {
    throw new Error(`Storage migration ${migration.id} has no reconciliation declarations.`);
  }
  const additions = [...sql.matchAll(
    /^ALTER TABLE ([a-z][a-z0-9_]*) ADD COLUMN ([a-z][a-z0-9_]*) (TEXT);$/gmu,
  )].map((match) => ({
    column: match[2]!,
    table: match[1]!,
    type: match[3]! as LegacyColumnAddition['type'],
  }));
  if (additions.length === 0) {
    throw new Error(
      `Storage migration ${migration.id} contains no recognized reconciliation declarations.`,
    );
  }
  return additions;
}

function validateMigrationLedger(applied: StorageMigrationRecord[], migrations: readonly StorageMigration[]): void {
  if (applied.length > migrations.length) {
    throw new Error(
      `Storage migration ledger contains ${applied.length} entries but this ActionProxy build knows only ${migrations.length}.`,
    );
  }
  for (let index = 0; index < applied.length; index += 1) {
    const record = applied[index]!;
    const expected = migrations[index];
    if (!expected) throw new Error(`Unknown storage migration ${record.id} at position ${record.position}.`);
    if (record.position !== expected.position || record.id !== expected.id) {
      throw new Error(
        `Storage migration ledger is not an ordered prefix: expected ${expected.id} at position ${expected.position}, found ${record.id} at position ${record.position}.`,
      );
    }
    if (
      record.checksum !== expected.checksum &&
      !expected.recognizedChecksums?.includes(record.checksum)
    ) {
      throw new Error(
        `Storage migration checksum mismatch for ${record.id}: expected ${expected.checksum}, found ${record.checksum}. Refusing to run with rewritten migration history.`,
      );
    }
  }
}

function migrationChecksum(source: string): string {
  return createHash('sha256').update(source).digest('hex');
}

function sqliteMigrationLedgerSql(): string {
  return `
    CREATE TABLE IF NOT EXISTS ${MIGRATION_LEDGER_TABLE} (
      id TEXT PRIMARY KEY,
      position INTEGER NOT NULL UNIQUE CHECK (position > 0),
      checksum TEXT NOT NULL CHECK (length(checksum) = 64),
      applied_at TEXT NOT NULL
    );
  `;
}

function postgresMigrationLedgerSql(): string {
  return `
    CREATE TABLE IF NOT EXISTS ${MIGRATION_LEDGER_TABLE} (
      id TEXT PRIMARY KEY,
      position INTEGER NOT NULL UNIQUE CHECK (position > 0),
      checksum TEXT NOT NULL CHECK (length(checksum) = 64),
      applied_at TEXT NOT NULL
    )
  `;
}

function sqliteMigrationInsertSql(migration: StorageMigration): string {
  return `INSERT INTO ${MIGRATION_LEDGER_TABLE} (id, position, checksum, applied_at)
    VALUES (
      ${sqlLiteral(migration.id)},
      ${migration.position},
      ${sqlLiteral(migration.checksum)},
      ${sqlLiteral(new Date().toISOString())}
    );`;
}

function sqliteMigrationRecordFromRow(row: Record<string, unknown>): StorageMigrationRecord {
  return {
    appliedAt: String(row.applied_at),
    checksum: String(row.checksum),
    id: String(row.id),
    position: Number(row.position),
  };
}

function postgresMigrationRecordFromRow(row: Record<string, unknown>): StorageMigrationRecord {
  return {
    appliedAt: String(row.applied_at),
    checksum: String(row.checksum),
    id: String(row.id),
    position: Number(row.position),
  };
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function withSqliteMigrationLock<T>(databasePath: string, callback: () => T): T {
  const lockPath = `${databasePath}.actionproxy-migrate.lock`;
  const deadline = Date.now() + SQLITE_MIGRATION_LOCK_TIMEOUT_MS;
  let descriptor: number | undefined;

  while (descriptor === undefined) {
    try {
      descriptor = fs.openSync(lockPath, 'wx', 0o600);
      fs.writeFileSync(descriptor, JSON.stringify({ createdAt: new Date().toISOString(), pid: process.pid }));
    } catch (error) {
      if (!isNodeError(error, 'EEXIST')) throw error;
      if (reclaimStaleSqliteMigrationLock(lockPath)) continue;
      if (Date.now() >= deadline) {
        throw new Error(`Timed out waiting for SQLite migration lock ${lockPath}.`);
      }
      synchronousWait(SQLITE_MIGRATION_LOCK_RETRY_MS);
    }
  }

  try {
    return callback();
  } finally {
    fs.closeSync(descriptor);
    try {
      fs.unlinkSync(lockPath);
    } catch (error) {
      if (!isNodeError(error, 'ENOENT')) throw error;
    }
  }
}

function reclaimStaleSqliteMigrationLock(lockPath: string): boolean {
  try {
    const raw = fs.readFileSync(lockPath, 'utf8');
    const owner = JSON.parse(raw) as { pid?: unknown };
    const pid = typeof owner.pid === 'number' && Number.isInteger(owner.pid) && owner.pid > 0 ? owner.pid : undefined;
    if (pid !== undefined && processExists(pid)) return false;
    if (pid === undefined && Date.now() - fs.statSync(lockPath).mtimeMs < SQLITE_MALFORMED_LOCK_STALE_MS) return false;
    fs.unlinkSync(lockPath);
    return true;
  } catch (error) {
    return isNodeError(error, 'ENOENT');
  }
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return isNodeError(error, 'EPERM');
  }
}

function synchronousWait(durationMs: number): void {
  const view = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
  Atomics.wait(view, 0, 0, durationMs);
}

function isNodeError(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code;
}
