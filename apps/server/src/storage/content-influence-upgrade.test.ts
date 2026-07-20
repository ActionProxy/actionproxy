import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { createPgPool, runPostgresMigrations, runSqliteMigrations } from './migrate';
import { PostgresStore } from './postgres-store';
import { SqliteStore } from './sqlite-store';
import type { ContentExposureRecord, Store } from './store';
import type { AuditStore } from './audit-store';

const LEGACY_WORKSPACE_ID = 'workspace-before-content-influence';
const LEGACY_TOOL_CALL_ID = 'toolcall-before-content-influence';
const LEGACY_APPROVAL_ID = 'approval-before-content-influence';
const LEGACY_AUDIT_EVENT_ID = 'audit-before-content-influence';

const describeIfSqlite = hasSqliteCli() ? describe : describe.skip;

describeIfSqlite('SQLite content-influence schema upgrade', () => {
  it('preserves a prior pending lifecycle and adds exposure storage idempotently across restart', async () => {
    const databasePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-influence-upgrade-')), 'prior.sqlite');
    execFileSync('sqlite3', ['-bail', databasePath], {
      encoding: 'utf8',
      input: priorLifecycleSchemaSql(),
    });
    expect(sqliteRows(databasePath, "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'content_exposures';"))
      .toEqual([]);
    const beforeMigration = sqliteLegacyRows(databasePath);

    expect(runSqliteMigrations(databasePath)).toEqual({
      adoptedLegacySchema: true,
      applied: ['0001_initial', '0002_legacy_schema_reconciliation', '0003_approver_principal_identity'],
    });
    const record = upgradeExposure('sqlite');
    const upgraded = new SqliteStore(databasePath);
    await expectPriorLifecycle(upgraded);
    expect(sqliteLegacyRows(databasePath)).toEqual(beforeMigration);
    await expect(upgraded.recordContentExposure(record)).resolves.toBe('created');
    await expect(upgraded.listContentExposures({
      influenceScopeId: record.influenceScopeId,
      limit: 10,
      workspaceId: record.workspaceId,
    })).resolves.toMatchObject({ overflow: false, records: [record], revision: 1 });

    const restarted = new SqliteStore(databasePath);
    await expectPriorLifecycle(restarted);
    expect(sqliteLegacyRows(databasePath)).toEqual(beforeMigration);
    await expect(restarted.recordContentExposure(record)).resolves.toBe('replay');
    await expect(restarted.listContentExposures({
      influenceScopeId: record.influenceScopeId,
      limit: 10,
      workspaceId: record.workspaceId,
    })).resolves.toMatchObject({ overflow: false, records: [record], revision: 1 });
    expect(sqliteRows(databasePath, "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_content_exposures_scope_order_v1';"))
      .toEqual([{ name: 'idx_content_exposures_scope_order_v1' }]);
    expect(sqliteRows(databasePath, 'SELECT id, position FROM actionproxy_schema_migrations ORDER BY position;'))
      .toEqual([
        { id: '0001_initial', position: 1 },
        { id: '0002_legacy_schema_reconciliation', position: 2 },
        { id: '0003_approver_principal_identity', position: 3 },
      ]);
  });
});

const databaseUrl = process.env.ACTIONPROXY_TEST_POSTGRES_URL;
const describeIfPostgres = databaseUrl ? describe : describe.skip;

describeIfPostgres('Postgres content-influence schema upgrade', () => {
  it('preserves a prior pending lifecycle and adds exposure storage idempotently across restart', async () => {
    const schema = `ap_influence_upgrade_${randomUUID().replaceAll('-', '')}`;
    const escapedSchema = quoteIdentifier(schema);
    const administrator = await createPgPool(databaseUrl!);
    let priorSchemaPool: Awaited<ReturnType<typeof createPgPool>> | undefined;
    let upgraded: PostgresStore | undefined;
    let restarted: PostgresStore | undefined;
    try {
      await administrator.query(`CREATE SCHEMA ${escapedSchema}`);
      const scopedUrl = postgresUrlForSchema(databaseUrl!, schema);
      priorSchemaPool = await createPgPool(scopedUrl);
      await priorSchemaPool.query(priorLifecycleSchemaSql());
      const before = await priorSchemaPool.query<{ present: string | null }>(
        "SELECT to_regclass('content_exposures')::text AS present",
      );
      expect(before.rows[0]?.present).toBeNull();
      const beforeMigration = await postgresLegacyRows(priorSchemaPool);

      await expect(runPostgresMigrations(scopedUrl)).resolves.toEqual({
        adoptedLegacySchema: true,
        applied: ['0001_initial', '0002_legacy_schema_reconciliation', '0003_approver_principal_identity'],
      });
      const record = upgradeExposure('postgres');
      upgraded = await PostgresStore.connect(scopedUrl);
      await expectPriorLifecycle(upgraded);
      expect(await postgresLegacyRows(priorSchemaPool)).toEqual(beforeMigration);
      await expect(upgraded.recordContentExposure(record)).resolves.toBe('created');
      await expect(upgraded.listContentExposures({
        influenceScopeId: record.influenceScopeId,
        limit: 10,
        workspaceId: record.workspaceId,
      })).resolves.toMatchObject({ overflow: false, records: [record], revision: 1 });
      await upgraded.close();
      upgraded = undefined;

      restarted = await PostgresStore.connect(scopedUrl);
      await expectPriorLifecycle(restarted);
      expect(await postgresLegacyRows(priorSchemaPool)).toEqual(beforeMigration);
      await expect(restarted.recordContentExposure(record)).resolves.toBe('replay');
      await expect(restarted.listContentExposures({
        influenceScopeId: record.influenceScopeId,
        limit: 10,
        workspaceId: record.workspaceId,
      })).resolves.toMatchObject({ overflow: false, records: [record], revision: 1 });
      const indexes = await administrator.query<{ indexname: string }>(
        'SELECT indexname FROM pg_indexes WHERE schemaname = $1 AND indexname = $2',
        [schema, 'idx_content_exposures_scope_order_v1'],
      );
      expect(indexes.rows).toEqual([{ indexname: 'idx_content_exposures_scope_order_v1' }]);
      const migrations = await priorSchemaPool.query<{ id: string; position: number }>(
        'SELECT id, position FROM actionproxy_schema_migrations ORDER BY position',
      );
      expect(migrations.rows).toEqual([
        { id: '0001_initial', position: 1 },
        { id: '0002_legacy_schema_reconciliation', position: 2 },
        { id: '0003_approver_principal_identity', position: 3 },
      ]);
    } finally {
      await upgraded?.close();
      await restarted?.close();
      await priorSchemaPool?.end();
      await administrator.query(`DROP SCHEMA IF EXISTS ${escapedSchema} CASCADE`);
      await administrator.end();
    }
  });
});

async function expectPriorLifecycle(store: Store & AuditStore): Promise<void> {
  await expect(store.getToolCall(LEGACY_TOOL_CALL_ID)).resolves.toMatchObject({
    agentId: 'agent-before-upgrade',
    createdAt: '2026-07-14T10:00:00.000Z',
    decision: 'require_approval',
    decisionTrace: { decisionV1: { decisionId: 'decision-before-upgrade' } },
    id: LEGACY_TOOL_CALL_ID,
    input: { subject: 'Before upgrade', to: 'customer@example.com' },
    inputHash: 'input-hash-before-upgrade',
    metadata: { runId: 'run-before-upgrade', sessionId: 'session-before-upgrade' },
    policyReason: 'Legacy send requires review.',
    policyVersionHash: 'policy-hash-before-upgrade',
    policyVersionId: 'policy-before-upgrade',
    reason: 'Send a customer update',
    requestedBy: 'user-before-upgrade',
    risk: 'external_send',
    status: 'pending_approval',
    toolName: 'gmail.send_email',
    updatedAt: '2026-07-14T10:00:01.000Z',
    workspaceId: LEGACY_WORKSPACE_ID,
  });
  await expect(store.listToolCalls({
    runId: 'run-before-upgrade',
    sessionId: 'session-before-upgrade',
    workspaceId: LEGACY_WORKSPACE_ID,
  })).resolves.toMatchObject([{ id: LEGACY_TOOL_CALL_ID, status: 'pending_approval' }]);
  await expect(store.getApproval(LEGACY_APPROVAL_ID)).resolves.toMatchObject({
    createdAt: '2026-07-14T10:00:01.000Z',
    decisions: [],
    id: LEGACY_APPROVAL_ID,
    originalEnvelopeHash: 'envelope-hash-before-upgrade',
    originalInput: { subject: 'Before upgrade', to: 'customer@example.com' },
    originalInputHash: 'input-hash-before-upgrade',
    requestedBy: 'user-before-upgrade',
    requiredApprovals: 1,
    separationOfDuties: false,
    status: 'pending',
    toolCallId: LEGACY_TOOL_CALL_ID,
    updatedAt: '2026-07-14T10:00:01.000Z',
    workspaceId: LEGACY_WORKSPACE_ID,
  });
  await expect(store.listPendingApprovals()).resolves.toMatchObject([
    { id: LEGACY_APPROVAL_ID, toolCallId: LEGACY_TOOL_CALL_ID },
  ]);
  await expect(store.list('all', {
    toolCallId: LEGACY_TOOL_CALL_ID,
    workspaceId: LEGACY_WORKSPACE_ID,
  })).resolves.toEqual([{
    actor: 'actionproxy',
    approvalId: LEGACY_APPROVAL_ID,
    data: { legacyEvidence: 'preserve-me', status: 'pending' },
    eventHash: 'event-hash-before-upgrade',
    id: LEGACY_AUDIT_EVENT_ID,
    inputHash: 'input-hash-before-upgrade',
    policyVersionHash: 'policy-hash-before-upgrade',
    policyVersionId: 'policy-before-upgrade',
    previousEventHash: 'previous-event-hash-before-upgrade',
    timestamp: '2026-07-14T10:00:02.000Z',
    toolCallId: LEGACY_TOOL_CALL_ID,
    type: 'approval.created',
    workspaceId: LEGACY_WORKSPACE_ID,
  }]);
}

/** Mirrors the three lifecycle tables in checkpoint 78a0f34, before content exposure storage existed. */
function priorLifecycleSchemaSql(): string {
  return `
    CREATE TABLE tool_calls (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL DEFAULT 'default',
      tool_name TEXT NOT NULL,
      input_json TEXT NOT NULL,
      input_hash TEXT,
      action_envelope_json TEXT,
      action_envelope_hash TEXT,
      canonical_action_request_hash TEXT,
      canonical_action_request_version TEXT,
      canonical_decision_input_hash TEXT,
      canonical_policy_context_json TEXT,
      requested_by TEXT NOT NULL,
      requested_by_auth_json TEXT,
      agent_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      metadata_json TEXT NOT NULL,
      status TEXT NOT NULL,
      decision TEXT,
      decision_trace_json TEXT,
      policy_reason TEXT,
      policy_version_id TEXT,
      policy_version_hash TEXT,
      risk TEXT,
      result_json TEXT,
      error TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX idx_tool_calls_created_at ON tool_calls(created_at);
    CREATE INDEX idx_tool_calls_workspace_id ON tool_calls(workspace_id);
    CREATE INDEX idx_tool_calls_status ON tool_calls(status);
    CREATE INDEX idx_tool_calls_decision ON tool_calls(decision);
    CREATE INDEX idx_tool_calls_tool_name ON tool_calls(tool_name);

    CREATE TABLE approvals (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL DEFAULT 'default',
      tool_call_id TEXT NOT NULL,
      status TEXT NOT NULL,
      requested_by TEXT NOT NULL,
      requested_by_auth_json TEXT,
      authorization_json TEXT,
      authorization_consumed_at TEXT,
      authorization_consumed_reason TEXT,
      approved_by TEXT,
      cancelled_at TEXT,
      cancelled_by TEXT,
      cancellation_reason TEXT,
      expired_at TEXT,
      finalized_at TEXT,
      rejected_by TEXT,
      note TEXT,
      rejection_reason TEXT,
      original_input_json TEXT NOT NULL,
      original_input_hash TEXT,
      original_envelope_hash TEXT,
      edited_input_json TEXT,
      approved_input_hash TEXT,
      approved_envelope_hash TEXT,
      review_hash TEXT,
      approver_users_json TEXT,
      approver_groups_json TEXT,
      required_approvals INTEGER,
      separation_of_duties INTEGER,
      decisions_json TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX idx_approvals_status ON approvals(status);
    CREATE INDEX idx_approvals_tool_call_id ON approvals(tool_call_id);
    CREATE INDEX idx_approvals_workspace_id ON approvals(workspace_id);

    CREATE TABLE audit_events (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      workspace_id TEXT,
      tool_call_id TEXT,
      approval_id TEXT,
      actor TEXT,
      auth_json TEXT,
      input_hash TEXT,
      policy_version_id TEXT,
      policy_version_hash TEXT,
      previous_event_hash TEXT,
      event_hash TEXT,
      timestamp TEXT NOT NULL,
      data_json TEXT NOT NULL
    );
    CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp);
    CREATE INDEX idx_audit_events_workspace_id ON audit_events(workspace_id);
    CREATE INDEX idx_audit_events_tool_call_id ON audit_events(tool_call_id);
    CREATE INDEX idx_audit_events_approval_id ON audit_events(approval_id);
    CREATE INDEX idx_audit_events_event_hash ON audit_events(event_hash);

    INSERT INTO tool_calls (
      id, workspace_id, tool_name, input_json, input_hash, action_envelope_hash,
      canonical_action_request_hash, canonical_action_request_version, canonical_decision_input_hash,
      requested_by, agent_id, reason, metadata_json, status, decision, decision_trace_json,
      policy_reason, policy_version_id, policy_version_hash, risk, created_at, updated_at
    ) VALUES (
      '${LEGACY_TOOL_CALL_ID}', '${LEGACY_WORKSPACE_ID}', 'gmail.send_email',
      '{"to":"customer@example.com","subject":"Before upgrade"}', 'input-hash-before-upgrade',
      'envelope-hash-before-upgrade', 'request-hash-before-upgrade', 'actionproxy.action-request.v1',
      'decision-input-hash-before-upgrade', 'user-before-upgrade', 'agent-before-upgrade',
      'Send a customer update', '{"sessionId":"session-before-upgrade","runId":"run-before-upgrade"}',
      'pending_approval', 'require_approval', '{"decisionV1":{"decisionId":"decision-before-upgrade"}}',
      'Legacy send requires review.', 'policy-before-upgrade', 'policy-hash-before-upgrade',
      'external_send', '2026-07-14T10:00:00.000Z', '2026-07-14T10:00:01.000Z'
    );
    INSERT INTO approvals (
      id, workspace_id, tool_call_id, status, requested_by, original_input_json,
      original_input_hash, original_envelope_hash, approver_users_json, approver_groups_json,
      required_approvals, separation_of_duties, decisions_json, created_at, updated_at
    ) VALUES (
      '${LEGACY_APPROVAL_ID}', '${LEGACY_WORKSPACE_ID}', '${LEGACY_TOOL_CALL_ID}', 'pending',
      'user-before-upgrade', '{"to":"customer@example.com","subject":"Before upgrade"}',
      'input-hash-before-upgrade', 'envelope-hash-before-upgrade', '["ops-reviewer"]', '["operations"]',
      1, 0, '[]', '2026-07-14T10:00:01.000Z', '2026-07-14T10:00:01.000Z'
    );
    INSERT INTO audit_events (
      id, type, workspace_id, tool_call_id, approval_id, actor, input_hash,
      policy_version_id, policy_version_hash, previous_event_hash, event_hash, timestamp, data_json
    ) VALUES (
      '${LEGACY_AUDIT_EVENT_ID}', 'approval.created', '${LEGACY_WORKSPACE_ID}', '${LEGACY_TOOL_CALL_ID}',
      '${LEGACY_APPROVAL_ID}', 'actionproxy', 'input-hash-before-upgrade', 'policy-before-upgrade',
      'policy-hash-before-upgrade', 'previous-event-hash-before-upgrade', 'event-hash-before-upgrade',
      '2026-07-14T10:00:02.000Z', '{"status":"pending","legacyEvidence":"preserve-me"}'
    );
  `;
}

function upgradeExposure(backend: string): ContentExposureRecord {
  return {
    influenceScopeId: `scope_upgrade_${backend}_${randomUUID()}`,
    integrity: 'public_untrusted',
    observedAt: '2026-07-15T12:00:00.000Z',
    policyVersionHash: 'policy-upgrade-v1',
    sourceId: 'public-web',
    sourceToolCallId: LEGACY_TOOL_CALL_ID,
    workspaceId: LEGACY_WORKSPACE_ID,
  };
}

function sqliteLegacyRows(databasePath: string): LegacyRows {
  return {
    approvals: sqliteRows(databasePath, `SELECT ${PRIOR_APPROVAL_COLUMNS} FROM approvals WHERE id = '${LEGACY_APPROVAL_ID}';`),
    auditEvents: sqliteRows(databasePath, `SELECT ${PRIOR_AUDIT_COLUMNS} FROM audit_events WHERE id = '${LEGACY_AUDIT_EVENT_ID}';`),
    toolCalls: sqliteRows(databasePath, `SELECT ${PRIOR_TOOL_CALL_COLUMNS} FROM tool_calls WHERE id = '${LEGACY_TOOL_CALL_ID}';`),
  };
}

async function postgresLegacyRows(pool: Awaited<ReturnType<typeof createPgPool>>): Promise<LegacyRows> {
  const [approvals, auditEvents, toolCalls] = await Promise.all([
    pool.query(`SELECT ${PRIOR_APPROVAL_COLUMNS} FROM approvals WHERE id = $1`, [LEGACY_APPROVAL_ID]),
    pool.query(`SELECT ${PRIOR_AUDIT_COLUMNS} FROM audit_events WHERE id = $1`, [LEGACY_AUDIT_EVENT_ID]),
    pool.query(`SELECT ${PRIOR_TOOL_CALL_COLUMNS} FROM tool_calls WHERE id = $1`, [LEGACY_TOOL_CALL_ID]),
  ]);
  return { approvals: approvals.rows, auditEvents: auditEvents.rows, toolCalls: toolCalls.rows };
}

interface LegacyRows {
  approvals: Array<Record<string, unknown>>;
  auditEvents: Array<Record<string, unknown>>;
  toolCalls: Array<Record<string, unknown>>;
}

const PRIOR_TOOL_CALL_COLUMNS = [
  'id', 'workspace_id', 'tool_name', 'input_json', 'input_hash', 'action_envelope_json',
  'action_envelope_hash', 'canonical_action_request_hash', 'canonical_action_request_version',
  'canonical_decision_input_hash', 'canonical_policy_context_json', 'requested_by', 'requested_by_auth_json',
  'agent_id', 'reason', 'metadata_json', 'status', 'decision', 'decision_trace_json', 'policy_reason',
  'policy_version_id', 'policy_version_hash', 'risk', 'result_json', 'error', 'created_at', 'updated_at',
].join(', ');

const PRIOR_APPROVAL_COLUMNS = [
  'id', 'workspace_id', 'tool_call_id', 'status', 'requested_by', 'requested_by_auth_json',
  'authorization_json', 'authorization_consumed_at', 'authorization_consumed_reason', 'approved_by',
  'cancelled_at', 'cancelled_by', 'cancellation_reason', 'expired_at', 'finalized_at', 'rejected_by',
  'note', 'rejection_reason', 'original_input_json', 'original_input_hash', 'original_envelope_hash',
  'edited_input_json', 'approved_input_hash', 'approved_envelope_hash', 'review_hash', 'approver_users_json',
  'approver_groups_json', 'required_approvals', 'separation_of_duties', 'decisions_json', 'created_at', 'updated_at',
].join(', ');

const PRIOR_AUDIT_COLUMNS = [
  'id', 'type', 'workspace_id', 'tool_call_id', 'approval_id', 'actor', 'auth_json', 'input_hash',
  'policy_version_id', 'policy_version_hash', 'previous_event_hash', 'event_hash', 'timestamp', 'data_json',
].join(', ');

function postgresUrlForSchema(database: string, schema: string): string {
  const url = new URL(database);
  url.searchParams.set('options', `-c search_path=${schema}`);
  return url.toString();
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function sqliteRows(databasePath: string, sql: string): Array<Record<string, unknown>> {
  const output = execFileSync('sqlite3', ['-bail', '-json', databasePath], {
    encoding: 'utf8',
    input: sql,
  }).trim();
  return output ? JSON.parse(output) as Array<Record<string, unknown>> : [];
}

function hasSqliteCli(): boolean {
  try {
    execFileSync('sqlite3', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
