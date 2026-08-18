import type {
  ApiKeyRecord,
  ActionEnvelope,
  ActionReceiptRecord,
  ApproverGroupRecord,
  ApproverUserRecord,
  ApprovalDeliveryRecord,
  ApprovalDecisionRecord,
  ApprovalRecord,
  AuditEvent,
  AuthContext,
  ExecutionGrantRecord,
  IdempotencyRecord,
  JsonObject,
  ObservedToolRecord,
  ServiceAccountRecord,
  ToolCallRecord,
  WorkspaceRecord,
  WorkspaceUserRecord,
} from '../models';
import type { AuditListFilters, AuditListLimit, AuditStore } from './audit-store';
import type {
  AtomicActionReceiptOutcomeInput,
  AtomicActionReceiptOutcomeResult,
  AtomicApprovedExternalAuthorizationPublicationInput,
  AtomicApprovedExternalAuthorizationPublicationResult,
  AtomicKnownExternalExecutionOutcomeAdoptionInput,
  AtomicKnownExternalExecutionOutcomeAdoptionResult,
  AtomicKnownExternalExecutionOutcomeRecordingInput,
  AtomicKnownExternalExecutionOutcomeRecordingResult,
  AtomicExecutionAttemptGrantBindingInput,
  AtomicExecutionAttemptGrantBindingResult,
  AtomicExecutionAttemptReservationResult,
  AtomicExecutionAttemptTransitionInput,
  AtomicExecutionAttemptTransitionResult,
  AtomicGrantDispatchInput,
  AtomicGrantDispatchResult,
  AtomicIdempotentToolCallInput,
  AtomicIdempotentToolCallResult,
  AtomicApprovalCancellationInput,
  AtomicApprovalCancellationResult,
  AtomicApprovalDecisionInput,
  AtomicApprovalDecisionResult,
  AtomicApprovalExpiryInput,
  AtomicApprovalExpiryResult,
  AtomicApprovalRejectionInput,
  AtomicApprovalRejectionResult,
  ApprovalAuthorizationGuard,
  ContentExposureRecord,
  ListContentExposuresInput,
  ListContentExposuresResult,
  ListToolCallsFilters,
  Store,
} from './store';
import type {
  ExecutionAttemptRecordV1,
  ExecutionAttemptState,
} from '../contracts/execution-attempt';
import {
  approvalAuthorizationExpired,
  isValidApprovalAuthorization,
  type ApprovalAuthorizationV1,
} from '../contracts/approval-authorization';
import { validContentInfluenceBindingHash } from '../contracts/content-influence';
import { hashJson } from '../security/crypto';
import type { PolicyVersionRecord, PolicyVersionStore } from './migrate';
import { createPgPool, runPostgresMigrationsWithPool } from './migrate';
import {
  ApproverPrincipalConflictError,
  isPostgresApproverPrincipalUniqueViolation,
} from './approver-principal-constraint';
import {
  approvedExternalAuthorizationMatchesCurrent,
  assertApprovedExternalAuthorizationPublicationCandidate,
  sameApprovedExternalAuthorizationPublication,
} from './approved-external-authorization-atomicity';
import {
  assertKnownExternalExecutionOutcomeAdoptionCandidate,
  externalOutcomeAdoptionState,
  knownExternalOutcomeMatchesCurrent,
  outcomeProjectionCanBeAdopted,
  sameKnownExternalOutcomeProjection,
} from './external-outcome-adoption-atomicity';
import {
  assertKnownExternalExecutionOutcomeRecordingCandidate,
  knownExternalOutcomeRecordingBindingsMatch,
  knownExternalOutcomeRecordingConflictDisposition,
  knownExternalOutcomeRecordingMatchesCurrent,
  sameRecordedKnownExternalOutcomeProjection,
} from './external-outcome-recording-atomicity';

interface PgQueryable {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

interface PgClient extends PgQueryable {
  release(): void;
}

interface PgPool extends PgQueryable {
  connect?(): Promise<PgClient>;
  end(): Promise<void>;
}

type PgRow = Record<string, unknown>;

export class PostgresStore implements Store, AuditStore, PolicyVersionStore {
  private constructor(private readonly pool: PgPool) {}

  static async connect(databaseUrl: string): Promise<PostgresStore> {
    const pool = await createPgPool(databaseUrl);
    try {
      await runPostgresMigrationsWithPool(pool);
      return new PostgresStore(pool);
    } catch (error) {
      await pool.end();
      throw error;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async createToolCall(record: ToolCallRecord): Promise<ToolCallRecord> {
    await this.writeToolCall(record);
    return record;
  }

  async createToolCallIdempotentlyAtomically(
    input: AtomicIdempotentToolCallInput,
  ): Promise<AtomicIdempotentToolCallResult> {
    assertIdempotencyCandidate(input);
    return this.withTransaction(async (client) => {
      const inserted = await client.query(
        `
          INSERT INTO idempotency_records (workspace_id, route, key, request_hash, tool_call_id, created_at)
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT (workspace_id, route, key) DO NOTHING
          RETURNING *
        `,
        [
          input.idempotency.workspaceId,
          input.idempotency.route,
          input.idempotency.key,
          input.idempotency.requestHash,
          input.idempotency.toolCallId,
          input.idempotency.createdAt,
        ],
      );
      if (inserted.rows[0]) {
        await this.writeToolCall(input.toolCall, client, false);
        return { idempotency: input.idempotency, outcome: 'created', toolCall: input.toolCall };
      }

      const existingResult = await client.query(
        `
          SELECT * FROM idempotency_records
          WHERE workspace_id = $1 AND route = $2 AND key = $3
          FOR UPDATE
        `,
        [input.idempotency.workspaceId, input.idempotency.route, input.idempotency.key],
      );
      const row = existingResult.rows[0];
      if (!row) throw new Error('Atomic idempotency conflict did not expose the authoritative reservation.');
      const idempotency = idempotencyFromRow(row);
      const toolCallResult = await client.query('SELECT * FROM tool_calls WHERE id = $1 LIMIT 1', [idempotency.toolCallId]);
      const toolCallRow = toolCallResult.rows[0];
      if (!toolCallRow) throw new Error(`Idempotency record references missing tool call: ${idempotency.toolCallId}`);
      return {
        idempotency,
        outcome: idempotency.requestHash === input.idempotency.requestHash ? 'replay' : 'conflict',
        toolCall: toolCallFromRow(toolCallRow),
      };
    });
  }

  async updateToolCall(record: ToolCallRecord): Promise<ToolCallRecord> {
    await this.writeToolCall(record);
    return record;
  }

  async getToolCall(id: string): Promise<ToolCallRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM tool_calls WHERE id = $1 LIMIT 1', [id]);
    const row = result.rows[0];
    return row ? toolCallFromRow(row) : undefined;
  }

  async listToolCalls(filters: ListToolCallsFilters = {}): Promise<ToolCallRecord[]> {
    const clauses: string[] = [];
    const values: unknown[] = [];

    addFilter(clauses, values, 'workspace_id', filters.workspaceId);
    addFilter(
      clauses,
      values,
      `CASE
        WHEN (NULLIF(decision_trace_json, '')::jsonb #> '{canonicalRequestEvidence,session,value}') ? 'sessionId'
          THEN CASE
            WHEN jsonb_typeof(NULLIF(decision_trace_json, '')::jsonb #> '{canonicalRequestEvidence,session,value,sessionId}') = 'string'
              THEN NULLIF(decision_trace_json, '')::jsonb #>> '{canonicalRequestEvidence,session,value,sessionId}'
            ELSE NULL
          END
        ELSE metadata_json::jsonb ->> 'sessionId'
      END`,
      filters.sessionId,
    );
    addFilter(
      clauses,
      values,
      `CASE
        WHEN (NULLIF(decision_trace_json, '')::jsonb #> '{canonicalRequestEvidence,session,value}') ? 'runId'
          THEN CASE
            WHEN jsonb_typeof(NULLIF(decision_trace_json, '')::jsonb #> '{canonicalRequestEvidence,session,value,runId}') = 'string'
              THEN NULLIF(decision_trace_json, '')::jsonb #>> '{canonicalRequestEvidence,session,value,runId}'
            ELSE NULL
          END
        ELSE metadata_json::jsonb ->> 'runId'
      END`,
      filters.runId,
    );
    addFilter(clauses, values, 'status', filters.status);
    addFilter(clauses, values, 'decision', filters.decision);
    addFilter(clauses, values, 'tool_name', filters.toolName);

    const limit = Number.isFinite(filters.limit) ? Math.max(1, Math.trunc(filters.limit ?? 100)) : 100;
    values.push(limit);
    const result = await this.pool.query(
      `
        SELECT * FROM tool_calls
        ${clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : ''}
        ORDER BY created_at DESC
        LIMIT $${values.length}
      `,
      values,
    );
    return result.rows.map(toolCallFromRow);
  }

  async recordContentExposure(record: ContentExposureRecord): Promise<'conflict' | 'created' | 'replay'> {
    return this.withTransaction(async (client) => {
      await client.query(
        `
          INSERT INTO content_exposure_scopes (workspace_id, influence_scope_id, revision)
          VALUES ($1, $2, 0)
          ON CONFLICT (workspace_id, influence_scope_id) DO NOTHING
        `,
        [record.workspaceId, record.influenceScopeId],
      );
      await client.query(
        `
          SELECT revision FROM content_exposure_scopes
          WHERE workspace_id = $1 AND influence_scope_id = $2
          FOR UPDATE
        `,
        [record.workspaceId, record.influenceScopeId],
      );
      const existing = (
        await client.query(
          `
            SELECT * FROM content_exposures
            WHERE workspace_id = $1 AND influence_scope_id = $2 AND source_tool_call_id = $3
          `,
          [record.workspaceId, record.influenceScopeId, record.sourceToolCallId],
        )
      ).rows[0];
      if (existing) {
        const stored = contentExposureFromRow(existing);
        return stored.integrity === record.integrity &&
          (stored.sourceId ?? null) === (record.sourceId ?? null) &&
          stored.policyVersionHash === record.policyVersionHash
          ? 'replay'
          : 'conflict';
      }
      await client.query(
        `
          INSERT INTO content_exposures (
            workspace_id, influence_scope_id, source_tool_call_id, integrity,
            source_id, policy_version_hash, observed_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
        [
          record.workspaceId,
          record.influenceScopeId,
          record.sourceToolCallId,
          record.integrity,
          record.sourceId ?? null,
          record.policyVersionHash,
          record.observedAt,
        ],
      );
      await client.query(
        `
          UPDATE content_exposure_scopes SET revision = revision + 1
          WHERE workspace_id = $1 AND influence_scope_id = $2
        `,
        [record.workspaceId, record.influenceScopeId],
      );
      return 'created';
    });
  }

  async listContentExposures(input: ListContentExposuresInput): Promise<ListContentExposuresResult> {
    const limit = contentExposureLimit(input.limit);
    const result = await this.pool.query(
      `
        WITH scope_revision AS (
          SELECT revision
          FROM content_exposure_scopes
          WHERE workspace_id = $1 AND influence_scope_id = $2
          UNION ALL
          SELECT 0
          WHERE NOT EXISTS (
            SELECT 1 FROM content_exposure_scopes
            WHERE workspace_id = $1 AND influence_scope_id = $2
          )
        ), bounded AS (
          SELECT * FROM content_exposures
          WHERE workspace_id = $1 AND influence_scope_id = $2
          ORDER BY observed_at ASC, source_tool_call_id ASC
          LIMIT $3
        )
        SELECT bounded.*, scope_revision.revision AS scope_revision
        FROM scope_revision LEFT JOIN bounded ON TRUE
        ORDER BY bounded.observed_at ASC, bounded.source_tool_call_id ASC
      `,
      [input.workspaceId, input.influenceScopeId, limit + 1],
    );
    const exposureRows = result.rows.filter((row) => typeof row.source_tool_call_id === 'string');
    return {
      overflow: exposureRows.length > limit,
      records: exposureRows.slice(0, limit).map(contentExposureFromRow),
      revision: Number(result.rows[0]?.scope_revision ?? 0),
    };
  }

  async createApproval(record: ApprovalRecord): Promise<ApprovalRecord> {
    await this.writeApproval(record);
    return record;
  }

  async updateApproval(record: ApprovalRecord): Promise<ApprovalRecord> {
    await this.writeApproval(record);
    return record;
  }

  async getApproval(id: string): Promise<ApprovalRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM approvals WHERE id = $1 LIMIT 1', [id]);
    const row = result.rows[0];
    return row ? approvalFromRow(row) : undefined;
  }

  async getApprovalByToolCallId(toolCallId: string): Promise<ApprovalRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM approvals WHERE tool_call_id = $1 LIMIT 1', [toolCallId]);
    const row = result.rows[0];
    return row ? approvalFromRow(row) : undefined;
  }

  async listPendingApprovals(): Promise<ApprovalRecord[]> {
    const result = await this.pool.query("SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_at ASC");
    return result.rows.map(approvalFromRow);
  }

  async recordApprovalDecisionAtomically(input: AtomicApprovalDecisionInput): Promise<AtomicApprovalDecisionResult> {
    if (!decisionInputIsSelfConsistent(input)) return { outcome: 'authorization_mismatch' };
    const principalId = input.decision.auth?.principalId ?? null;
    const values: unknown[] = [
      input.approvalId,
      JSON.stringify([input.decision]),
      input.decision.actor,
      principalId,
      input.editedInput === undefined ? null : JSON.stringify(input.editedInput),
      input.approvedInputHash,
      input.approvedEnvelopeHash,
      input.note ?? null,
      input.reviewHash,
      input.updatedAt,
    ];
    const guardClause = postgresAuthorizationGuardClause(input.authorization, values);
    const expiresAt = pgParam(values, input.authorization.authorization.expiresAt);
    const decisionHistoryClause = postgresDecisionHistoryBindingClause(input, values);
    const updateSql = `
        UPDATE approvals
        SET decisions_json = (
              COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb || $2::jsonb
            )::text,
            status = CASE
              WHEN jsonb_array_length(COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb) + 1
                >= GREATEST(1, COALESCE(required_approvals, 1))
              THEN 'approved'
              ELSE 'pending'
            END,
            approved_by = CASE
              WHEN jsonb_array_length(COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb) + 1
                >= GREATEST(1, COALESCE(required_approvals, 1))
              THEN $3
              ELSE approved_by
            END,
            edited_input_json = COALESCE($5, edited_input_json),
            approved_input_hash = CASE
              WHEN jsonb_array_length(COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb) + 1
                >= GREATEST(1, COALESCE(required_approvals, 1))
              THEN $6
              ELSE approved_input_hash
            END,
            approved_envelope_hash = CASE
              WHEN jsonb_array_length(COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb) + 1
                >= GREATEST(1, COALESCE(required_approvals, 1))
              THEN $7
              ELSE approved_envelope_hash
            END,
            authorization_consumed_at = CASE
              WHEN jsonb_array_length(COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb) + 1
                >= GREATEST(1, COALESCE(required_approvals, 1))
              THEN $10
              ELSE authorization_consumed_at
            END,
            authorization_consumed_reason = CASE
              WHEN jsonb_array_length(COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb) + 1
                >= GREATEST(1, COALESCE(required_approvals, 1))
              THEN 'approved'
              ELSE authorization_consumed_reason
            END,
            finalized_at = CASE
              WHEN jsonb_array_length(COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb) + 1
                >= GREATEST(1, COALESCE(required_approvals, 1))
              THEN $10
              ELSE finalized_at
            END,
            note = $8,
            review_hash = $9,
            updated_at = $10
        WHERE id = $1
          AND status = 'pending'
          AND ${guardClause}
          AND ${expiresAt}::timestamptz > CURRENT_TIMESTAMP
          AND ${decisionHistoryClause}
          AND NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb) AS prior(decision)
            WHERE prior.decision ->> 'actor' = $3
               OR ($4::text IS NOT NULL AND prior.decision -> 'auth' ->> 'principalId' = $4)
          )
        RETURNING *
      `;
    let result: { rows: Record<string, unknown>[] };
    if (input.contentExposureRevision) {
      const expected = input.contentExposureRevision;
      const guarded = await this.withTransaction(async (client) => {
        await client.query(
          `
            INSERT INTO content_exposure_scopes (workspace_id, influence_scope_id, revision)
            VALUES ($1, $2, 0)
            ON CONFLICT (workspace_id, influence_scope_id) DO NOTHING
          `,
          [input.authorization.authorization.binding.approval.tenantId, expected.influenceScopeId],
        );
        const currentRevision = Number((await client.query(
          `
            SELECT revision FROM content_exposure_scopes
            WHERE workspace_id = $1 AND influence_scope_id = $2
            FOR UPDATE
          `,
          [input.authorization.authorization.binding.approval.tenantId, expected.influenceScopeId],
        )).rows[0]?.revision ?? 0);
        if (currentRevision !== expected.revision) return { mismatch: true, rows: [] as Record<string, unknown>[] };
        const updated = await client.query(updateSql, values);
        return { mismatch: false, rows: updated.rows };
      });
      if (guarded.mismatch) {
        const current = await this.getApproval(input.approvalId);
        return { approval: current, outcome: 'content_influence_mismatch' };
      }
      result = { rows: guarded.rows };
    } else {
      result = await this.pool.query(updateSql, values);
    }
    const updatedRow = result.rows[0];
    if (updatedRow) {
      const approval = approvalFromRow(updatedRow);
      return { approval, outcome: approval.status === 'approved' ? 'finalized' : 'recorded' };
    }

    const expiry = await this.expireApprovalAtomically({
      approvalId: input.approvalId,
      authorization: input.authorization.authorization,
      expiredAt: input.authorization.authorization.expiresAt,
    });
    if (expiry.outcome === 'expired') return expiry;
    const current = await this.getApproval(input.approvalId);
    if (!current) return { outcome: 'not_found' };
    if (
      current.authorizationConsumedAt &&
      sameAuthorization(current.authorization, input.authorization.authorization)
    ) {
      return { approval: current, outcome: 'replayed' };
    }
    if (current.status !== 'pending') return { approval: current, outcome: 'already_final' };
    if (!sameAuthorization(current.authorization, input.authorization.authorization)) {
      return { approval: current, outcome: 'authorization_mismatch' };
    }
    if (hasApprovalDecision(current.decisions, input.decision)) {
      return { approval: current, outcome: 'duplicate' };
    }
    return { approval: current, outcome: 'authorization_mismatch' };
  }

  async rejectApprovalAtomically(input: AtomicApprovalRejectionInput): Promise<AtomicApprovalRejectionResult> {
    if (input.authorization && !authorizationGuardIsSelfConsistent(input.authorization)) {
      return { outcome: 'authorization_mismatch' };
    }
    const values: unknown[] = [input.approvalId, input.rejectedBy, input.reason ?? null, input.updatedAt];
    const guardClause = postgresOptionalAuthorizationGuardClause(input.authorization, values);
    const expiryClause = postgresOptionalAuthorizationNotExpiredClause(input.authorization, values);
    const result = await this.pool.query(
      `
        UPDATE approvals
        SET status = 'rejected',
            rejected_by = $2,
            rejection_reason = $3,
            authorization_consumed_at = CASE WHEN authorization_json IS NULL THEN NULL ELSE $4 END,
            authorization_consumed_reason = CASE WHEN authorization_json IS NULL THEN NULL ELSE 'rejected' END,
            finalized_at = $4,
            updated_at = $4
        WHERE id = $1
          AND status = 'pending'
          AND ${guardClause}
          AND ${expiryClause}
        RETURNING *
      `,
      values,
    );
    const updatedRow = result.rows[0];
    if (updatedRow) return { approval: approvalFromRow(updatedRow), outcome: 'rejected' };
    return this.classifyTerminalTransitionFailure(input.approvalId, input.authorization);
  }

  async cancelApprovalAtomically(input: AtomicApprovalCancellationInput): Promise<AtomicApprovalCancellationResult> {
    if (input.authorization && !authorizationGuardIsSelfConsistent(input.authorization)) {
      return { outcome: 'authorization_mismatch' };
    }
    const values: unknown[] = [input.approvalId, input.cancelledBy, input.reason ?? null, input.updatedAt];
    const guardClause = postgresOptionalAuthorizationGuardClause(input.authorization, values);
    const expiryClause = postgresOptionalAuthorizationNotExpiredClause(input.authorization, values);
    const result = await this.pool.query(
      `
        UPDATE approvals
        SET status = 'cancelled',
            cancelled_by = $2,
            cancellation_reason = $3,
            cancelled_at = $4,
            authorization_consumed_at = CASE WHEN authorization_json IS NULL THEN NULL ELSE $4 END,
            authorization_consumed_reason = CASE WHEN authorization_json IS NULL THEN NULL ELSE 'cancelled' END,
            finalized_at = $4,
            updated_at = $4
        WHERE id = $1
          AND status = 'pending'
          AND ${guardClause}
          AND ${expiryClause}
        RETURNING *
      `,
      values,
    );
    const updatedRow = result.rows[0];
    if (updatedRow) return { approval: approvalFromRow(updatedRow), outcome: 'cancelled' };
    return this.classifyTerminalTransitionFailure(input.approvalId, input.authorization);
  }

  async expireApprovalAtomically(input: AtomicApprovalExpiryInput): Promise<AtomicApprovalExpiryResult> {
    if (!authorizationIdentityIsUsable(input.authorization)) return { outcome: 'authorization_mismatch' };
    const binding = input.authorization.binding;
    const result = await this.pool.query(
      `
        UPDATE approvals
        SET status = 'expired',
            expired_at = $3,
            authorization_consumed_at = $3,
            authorization_consumed_reason = 'expired',
            finalized_at = $3,
            updated_at = $3
        WHERE id = $1
          AND status = 'pending'
          AND authorization_consumed_at IS NULL
          AND authorization_json = $2
          AND id = $4
          AND tool_call_id = $5
          AND workspace_id = $6
          AND original_input_hash = $7
          AND original_envelope_hash = $8
          AND review_hash = $9
          AND $10::timestamptz <= CURRENT_TIMESTAMP
        RETURNING *
      `,
      [
        input.approvalId,
        JSON.stringify(input.authorization),
        input.expiredAt,
        binding.approval.approvalId,
        binding.approval.toolCallId,
        binding.approval.tenantId,
        binding.action.originalInputHash,
        binding.action.originalEnvelopeHash,
        binding.action.reviewHash,
        input.authorization.expiresAt,
      ],
    );
    if (result.rows[0]) return { approval: approvalFromRow(result.rows[0]), outcome: 'expired' };
    const current = await this.getApproval(input.approvalId);
    if (!current) return { outcome: 'not_found' };
    if (current.status !== 'pending') return { approval: current, outcome: 'already_final' };
    return { approval: current, outcome: 'authorization_mismatch' };
  }

  private async classifyTerminalTransitionFailure(
    approvalId: string,
    guard: AtomicApprovalRejectionInput['authorization'],
  ): Promise<{
    approval?: ApprovalRecord;
    outcome: 'already_final' | 'authorization_mismatch' | 'expired' | 'not_found' | 'replayed';
  }> {
    if (guard) {
      const expiry = await this.expireApprovalAtomically({
        approvalId,
        authorization: guard.authorization,
        expiredAt: guard.authorization.expiresAt,
      });
      if (expiry.outcome === 'expired') return expiry;
    }
    const current = await this.getApproval(approvalId);
    if (!current) return { outcome: 'not_found' };
    if (guard && current.authorizationConsumedAt && sameAuthorization(current.authorization, guard.authorization)) {
      return { approval: current, outcome: 'replayed' };
    }
    if (current.status !== 'pending') return { approval: current, outcome: 'already_final' };
    return { approval: current, outcome: 'authorization_mismatch' };
  }

  async createApprovalDelivery(record: ApprovalDeliveryRecord): Promise<ApprovalDeliveryRecord> {
    return this.writeApprovalDelivery(record);
  }

  async updateApprovalDelivery(record: ApprovalDeliveryRecord): Promise<ApprovalDeliveryRecord> {
    return this.writeApprovalDelivery(record);
  }

  async listApprovalDeliveries(approvalId: string): Promise<ApprovalDeliveryRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM approval_deliveries WHERE approval_id = $1 ORDER BY created_at DESC',
      [approvalId],
    );
    return result.rows.map(approvalDeliveryFromRow);
  }

  async upsertApproverUser(record: ApproverUserRecord): Promise<ApproverUserRecord> {
    try {
      await this.pool.query(
        `
        INSERT INTO approver_users (
          id, workspace_id, display_name, email, principal_id, slack_user_id, telegram_chat_id, telegram_username,
          telegram_user_id, groups_json, default_approver, enabled, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (workspace_id, id) DO UPDATE SET
          display_name = EXCLUDED.display_name,
          email = EXCLUDED.email,
          principal_id = EXCLUDED.principal_id,
          slack_user_id = EXCLUDED.slack_user_id,
          telegram_chat_id = EXCLUDED.telegram_chat_id,
          telegram_username = EXCLUDED.telegram_username,
          telegram_user_id = EXCLUDED.telegram_user_id,
          groups_json = EXCLUDED.groups_json,
          default_approver = EXCLUDED.default_approver,
          enabled = EXCLUDED.enabled,
          updated_at = EXCLUDED.updated_at
      `,
      [
        record.id,
        record.workspaceId,
        record.displayName,
        record.email ?? null,
        record.principalId ?? null,
        record.slackUserId ?? null,
        record.telegramChatId ?? null,
        record.telegramUsername ?? null,
        record.telegramUserId ?? null,
        JSON.stringify(record.groups),
        record.defaultApprover ? 1 : 0,
        record.enabled ? 1 : 0,
        record.createdAt,
        record.updatedAt,
        ],
      );
    } catch (error) {
      if (isPostgresApproverPrincipalUniqueViolation(error)) {
        throw new ApproverPrincipalConflictError();
      }
      throw error;
    }
    return record;
  }

  async getApproverUser(workspaceId: string, id: string): Promise<ApproverUserRecord | undefined> {
    const result = await this.pool.query(
      'SELECT * FROM approver_users WHERE workspace_id = $1 AND id = $2 LIMIT 1',
      [workspaceId, id],
    );
    const row = result.rows[0];
    return row ? approverUserFromRow(row) : undefined;
  }

  async listApproverUsers(workspaceId: string): Promise<ApproverUserRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM approver_users WHERE workspace_id = $1 ORDER BY display_name ASC',
      [workspaceId],
    );
    return result.rows.map(approverUserFromRow);
  }

  async deleteApproverUser(workspaceId: string, id: string): Promise<boolean> {
    await this.pool.query('DELETE FROM approver_users WHERE workspace_id = $1 AND id = $2', [workspaceId, id]);
    return true;
  }

  async upsertApproverGroup(record: ApproverGroupRecord): Promise<ApproverGroupRecord> {
    await this.pool.query(
      `
        INSERT INTO approver_groups (
          id, workspace_id, display_name, description, enabled, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (workspace_id, id) DO UPDATE SET
          display_name = EXCLUDED.display_name,
          description = EXCLUDED.description,
          enabled = EXCLUDED.enabled,
          updated_at = EXCLUDED.updated_at
      `,
      [
        record.id,
        record.workspaceId,
        record.displayName,
        record.description ?? null,
        record.enabled ? 1 : 0,
        record.createdAt,
        record.updatedAt,
      ],
    );
    return record;
  }

  async getApproverGroup(workspaceId: string, id: string): Promise<ApproverGroupRecord | undefined> {
    const result = await this.pool.query(
      'SELECT * FROM approver_groups WHERE workspace_id = $1 AND id = $2 LIMIT 1',
      [workspaceId, id],
    );
    const row = result.rows[0];
    return row ? approverGroupFromRow(row) : undefined;
  }

  async listApproverGroups(workspaceId: string): Promise<ApproverGroupRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM approver_groups WHERE workspace_id = $1 ORDER BY display_name ASC',
      [workspaceId],
    );
    return result.rows.map(approverGroupFromRow);
  }

  async deleteApproverGroup(workspaceId: string, id: string): Promise<boolean> {
    await this.pool.query('DELETE FROM approver_groups WHERE workspace_id = $1 AND id = $2', [workspaceId, id]);
    return true;
  }

  async createWorkspace(record: WorkspaceRecord): Promise<WorkspaceRecord> {
    await this.pool.query(
      `
        INSERT INTO workspaces (id, name, created_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
      `,
      [record.id, record.name, record.createdAt],
    );
    return record;
  }

  async getWorkspace(id: string): Promise<WorkspaceRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM workspaces WHERE id = $1 LIMIT 1', [id]);
    const row = result.rows[0];
    return row ? workspaceFromRow(row) : undefined;
  }

  async upsertWorkspaceUser(record: WorkspaceUserRecord): Promise<WorkspaceUserRecord> {
    await this.pool.query(
      `
        INSERT INTO workspace_users (id, workspace_id, principal_id, display_name, email, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (workspace_id, id) DO UPDATE SET
          principal_id = EXCLUDED.principal_id,
          display_name = EXCLUDED.display_name,
          email = EXCLUDED.email,
          updated_at = EXCLUDED.updated_at
      `,
      [record.id, record.workspaceId, record.principalId, record.displayName, record.email ?? null, record.createdAt, record.updatedAt],
    );
    return record;
  }

  async getWorkspaceUser(workspaceId: string, id: string): Promise<WorkspaceUserRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM workspace_users WHERE workspace_id = $1 AND id = $2 LIMIT 1', [
      workspaceId,
      id,
    ]);
    const row = result.rows[0];
    return row ? workspaceUserFromRow(row) : undefined;
  }

  async getWorkspaceUserByPrincipal(workspaceId: string, principalId: string): Promise<WorkspaceUserRecord | undefined> {
    const result = await this.pool.query(
      'SELECT * FROM workspace_users WHERE workspace_id = $1 AND principal_id = $2 LIMIT 1',
      [workspaceId, principalId],
    );
    const row = result.rows[0];
    return row ? workspaceUserFromRow(row) : undefined;
  }

  async listWorkspaceUsers(workspaceId: string): Promise<WorkspaceUserRecord[]> {
    const result = await this.pool.query('SELECT * FROM workspace_users WHERE workspace_id = $1 ORDER BY display_name ASC', [
      workspaceId,
    ]);
    return result.rows.map(workspaceUserFromRow);
  }

  async createServiceAccount(record: ServiceAccountRecord): Promise<ServiceAccountRecord> {
    await this.pool.query(
      `
        INSERT INTO service_accounts (
          id, workspace_id, name, description, groups_json, scopes_json, created_at, updated_at, revoked_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (id) DO UPDATE SET
          workspace_id = EXCLUDED.workspace_id,
          name = EXCLUDED.name,
          description = EXCLUDED.description,
          groups_json = EXCLUDED.groups_json,
          scopes_json = EXCLUDED.scopes_json,
          updated_at = EXCLUDED.updated_at,
          revoked_at = EXCLUDED.revoked_at
      `,
      [
        record.id,
        record.workspaceId,
        record.name,
        record.description ?? null,
        JSON.stringify(record.groups),
        JSON.stringify(record.scopes),
        record.createdAt,
        record.updatedAt,
        record.revokedAt ?? null,
      ],
    );
    return record;
  }

  async getServiceAccount(id: string): Promise<ServiceAccountRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM service_accounts WHERE id = $1 LIMIT 1', [id]);
    const row = result.rows[0];
    return row ? serviceAccountFromRow(row) : undefined;
  }

  async listServiceAccounts(workspaceId: string): Promise<ServiceAccountRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM service_accounts WHERE workspace_id = $1 ORDER BY created_at DESC',
      [workspaceId],
    );
    return result.rows.map(serviceAccountFromRow);
  }

  async createApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord> {
    return this.writeApiKey(record);
  }

  async getApiKeyByPrefix(keyPrefix: string): Promise<ApiKeyRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM api_keys WHERE key_prefix = $1 LIMIT 1', [keyPrefix]);
    const row = result.rows[0];
    return row ? apiKeyFromRow(row) : undefined;
  }

  async updateApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord> {
    return this.writeApiKey(record);
  }

  async createExecutionGrant(record: ExecutionGrantRecord): Promise<ExecutionGrantRecord> {
    return this.writeExecutionGrant(record);
  }

  async getExecutionGrant(id: string): Promise<ExecutionGrantRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM execution_grants WHERE id = $1 LIMIT 1', [id]);
    const row = result.rows[0];
    return row ? executionGrantFromRow(row) : undefined;
  }

  async listExecutionGrants(filters: { limit?: number; workspaceId?: string } = {}): Promise<ExecutionGrantRecord[]> {
    const limit = Math.max(1, Math.min(filters.limit ?? 100, 1000));
    const result = filters.workspaceId
      ? await this.pool.query('SELECT * FROM execution_grants WHERE workspace_id = $1 ORDER BY created_at DESC LIMIT $2', [
          filters.workspaceId,
          limit,
        ])
      : await this.pool.query('SELECT * FROM execution_grants ORDER BY created_at DESC LIMIT $1', [limit]);
    return result.rows.map(executionGrantFromRow);
  }

  async updateExecutionGrant(record: ExecutionGrantRecord): Promise<ExecutionGrantRecord> {
    return this.writeExecutionGrant(record);
  }

  async consumeExecutionGrantAtomically(id: string, consumedAt: string): Promise<ExecutionGrantRecord | undefined> {
    const result = await this.pool.query(
      `UPDATE execution_grants SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL RETURNING *`,
      [id, consumedAt],
    );
    const row = result.rows[0];
    return row ? executionGrantFromRow(row) : undefined;
  }

  async reserveExecutionAttemptAtomically(
    record: ExecutionAttemptRecordV1,
    approvalAuthorization?: ApprovalAuthorizationV1,
  ): Promise<AtomicExecutionAttemptReservationResult> {
    return this.withTransaction(async (client) => {
      const toolCallResult = await client.query('SELECT * FROM tool_calls WHERE id = $1 FOR UPDATE', [record.toolCallId]);
      const toolCallRow = toolCallResult.rows[0];
      if (!toolCallRow) return { outcome: 'not_found' };
      const toolCall = toolCallFromRow(toolCallRow);
      if ((toolCall.workspaceId ?? 'default') !== record.workspaceId) return { outcome: 'not_found' };

      const approvalRow = record.binding.approvalId
        ? (await client.query('SELECT * FROM approvals WHERE id = $1 FOR SHARE', [record.binding.approvalId])).rows[0]
        : undefined;
      const receiptRow = record.binding.receiptId
        ? (await client.query('SELECT * FROM action_receipts WHERE id = $1 FOR SHARE', [record.binding.receiptId])).rows[0]
        : undefined;
      const approval = approvalRow ? approvalFromRow(approvalRow) : undefined;
      const receipt = receiptRow ? actionReceiptFromRow(receiptRow) : undefined;
      const databaseNow = record.binding.approvalId
        ? new Date((await client.query<{ now: string | Date }>('SELECT CURRENT_TIMESTAMP AS now')).rows[0]!.now)
        : undefined;
      if (!executionAttemptBindingMatches(record, toolCall, approval, receipt, approvalAuthorization, databaseNow)) {
        return { outcome: 'binding_mismatch' };
      }
      const existingResult = await client.query(
        'SELECT * FROM execution_attempts WHERE workspace_id = $1 AND tool_call_id = $2 LIMIT 1',
        [record.workspaceId, record.toolCallId],
      );
      if (existingResult.rows[0]) {
        return { attempt: executionAttemptFromRow(existingResult.rows[0]), outcome: 'existing' };
      }
      const inserted = await insertExecutionAttempt(client, record);
      return { attempt: executionAttemptFromRow(inserted), outcome: 'reserved' };
    });
  }

  async getExecutionAttempt(id: string): Promise<ExecutionAttemptRecordV1 | undefined> {
    const row = (await this.pool.query('SELECT * FROM execution_attempts WHERE id = $1 LIMIT 1', [id])).rows[0];
    return row ? executionAttemptFromRow(row) : undefined;
  }

  async getExecutionAttemptByToolCallId(
    workspaceId: string,
    toolCallId: string,
  ): Promise<ExecutionAttemptRecordV1 | undefined> {
    const row = (
      await this.pool.query(
        'SELECT * FROM execution_attempts WHERE workspace_id = $1 AND tool_call_id = $2 LIMIT 1',
        [workspaceId, toolCallId],
      )
    ).rows[0];
    return row ? executionAttemptFromRow(row) : undefined;
  }

  async listExecutionAttempts(
    workspaceId: string,
    filters: { state?: ExecutionAttemptState; toolCallId?: string } = {},
  ): Promise<ExecutionAttemptRecordV1[]> {
    const clauses = ['workspace_id = $1'];
    const values: unknown[] = [workspaceId];
    if (filters.state) {
      values.push(filters.state);
      clauses.push(`state = $${values.length}`);
    }
    if (filters.toolCallId) {
      values.push(filters.toolCallId);
      clauses.push(`tool_call_id = $${values.length}`);
    }
    const result = await this.pool.query(
      `SELECT * FROM execution_attempts WHERE ${clauses.join(' AND ')} ORDER BY reserved_at DESC`,
      values,
    );
    return result.rows.map(executionAttemptFromRow);
  }

  async transitionExecutionAttemptAtomically(
    input: AtomicExecutionAttemptTransitionInput,
  ): Promise<AtomicExecutionAttemptTransitionResult> {
    const revision = input.contentExposureRevision;
    if (
      revision &&
      input.expectedState === 'reserved' &&
      input.nextState === 'dispatched' &&
      executionAttemptTransitionIsValid(input)
    ) {
      return this.withTransaction(async (client) => {
        await client.query(
          `
            INSERT INTO content_exposure_scopes (workspace_id, influence_scope_id, revision)
            VALUES ($1, $2, 0)
            ON CONFLICT (workspace_id, influence_scope_id) DO NOTHING
          `,
          [input.workspaceId, revision.influenceScopeId],
        );
        const currentRevision = Number((await client.query(
          `
            SELECT revision FROM content_exposure_scopes
            WHERE workspace_id = $1 AND influence_scope_id = $2
            FOR UPDATE
          `,
          [input.workspaceId, revision.influenceScopeId],
        )).rows[0]?.revision ?? 0);
        const currentRow = (await client.query(
          'SELECT * FROM execution_attempts WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
          [input.attemptId, input.workspaceId],
        )).rows[0];
        if (!currentRow) return { outcome: 'not_found' };
        const current = executionAttemptFromRow(currentRow);
        if (current.reservationOwner !== input.reservationOwner) return { attempt: current, outcome: 'owner_mismatch' };
        if (currentRevision !== revision.revision) {
          return { attempt: current, outcome: 'content_influence_mismatch' };
        }
        if (current.state !== input.expectedState) return { attempt: current, outcome: 'state_mismatch' };
        const updatedRow = (await client.query(
          `
            UPDATE execution_attempts
            SET state = $3, dispatched_at = $4, updated_at = $4
            WHERE id = $1 AND workspace_id = $2 AND state = $5
            RETURNING *
          `,
          [input.attemptId, input.workspaceId, input.nextState, input.transitionedAt, input.expectedState],
        )).rows[0];
        return updatedRow
          ? { attempt: executionAttemptFromRow(updatedRow), outcome: 'transitioned' }
          : { attempt: current, outcome: 'state_mismatch' };
      });
    }
    if (executionAttemptTransitionIsValid(input)) {
      const result = await this.pool.query(
        `
          UPDATE execution_attempts
          SET state = $5,
              dispatched_at = CASE WHEN $5 = 'dispatched' THEN $6 ELSE dispatched_at END,
              completed_at = CASE WHEN $5 NOT IN ('reserved', 'dispatched') THEN $6 ELSE completed_at END,
              outcome_json = $7,
              updated_at = $6
          WHERE id = $1
            AND workspace_id = $2
            AND reservation_owner = $3
            AND state = $4
          RETURNING *
        `,
        [
          input.attemptId,
          input.workspaceId,
          input.reservationOwner,
          input.expectedState,
          input.nextState,
          input.transitionedAt,
          input.outcome === undefined ? null : JSON.stringify(input.outcome),
        ],
      );
      if (result.rows[0]) return { attempt: executionAttemptFromRow(result.rows[0]), outcome: 'transitioned' };
    }
    const current = await this.getExecutionAttempt(input.attemptId);
    if (!current || current.workspaceId !== input.workspaceId) return { outcome: 'not_found' };
    if (current.reservationOwner !== input.reservationOwner) return { attempt: current, outcome: 'owner_mismatch' };
    if (executionAttemptTransitionIsReplay(current, input)) return { attempt: current, outcome: 'replay' };
    if (executionAttemptIsTerminal(current.state)) return { attempt: current, outcome: 'already_terminal' };
    return { attempt: current, outcome: 'state_mismatch' };
  }

  async bindExecutionAttemptGrantAtomically(
    input: AtomicExecutionAttemptGrantBindingInput,
  ): Promise<AtomicExecutionAttemptGrantBindingResult> {
    const result = await this.pool.query(
      `
        UPDATE execution_attempts
        SET grant_id = $4, updated_at = $5
        WHERE id = $1
          AND workspace_id = $2
          AND reservation_owner = $3
          AND state = 'reserved'
          AND grant_id IS NULL
        RETURNING *
      `,
      [input.attemptId, input.workspaceId, input.reservationOwner, input.grantId, input.updatedAt],
    );
    if (result.rows[0]) return { attempt: executionAttemptFromRow(result.rows[0]), outcome: 'bound' };
    const current = await this.getExecutionAttempt(input.attemptId);
    if (!current || current.workspaceId !== input.workspaceId) return { outcome: 'not_found' };
    if (current.reservationOwner !== input.reservationOwner) return { attempt: current, outcome: 'owner_mismatch' };
    if (current.state !== 'reserved') return { attempt: current, outcome: 'state_mismatch' };
    return { attempt: current, outcome: 'already_bound' };
  }

  async consumeExecutionGrantAndDispatchAttemptAtomically(
    input: AtomicGrantDispatchInput,
  ): Promise<AtomicGrantDispatchResult> {
    return this.withTransaction(async (client) => {
      if (input.contentExposureRevision) {
        const revision = input.contentExposureRevision;
        await client.query(
          `
            INSERT INTO content_exposure_scopes (workspace_id, influence_scope_id, revision)
            VALUES ($1, $2, 0)
            ON CONFLICT (workspace_id, influence_scope_id) DO NOTHING
          `,
          [input.workspaceId, revision.influenceScopeId],
        );
        const currentRevision = Number((await client.query(
          `
            SELECT revision FROM content_exposure_scopes
            WHERE workspace_id = $1 AND influence_scope_id = $2
            FOR UPDATE
          `,
          [input.workspaceId, revision.influenceScopeId],
        )).rows[0]?.revision ?? 0);
        if (currentRevision !== revision.revision) return { outcome: 'content_influence_mismatch' };
      }
      const attemptRow = (
        await client.query(
          'SELECT * FROM execution_attempts WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
          [input.attemptId, input.workspaceId],
        )
      ).rows[0];
      if (!attemptRow) return { outcome: 'attempt_not_found' };
      const attempt = executionAttemptFromRow(attemptRow);
      const grantRow = (
        await client.query(
          'SELECT * FROM execution_grants WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
          [input.grantId, input.workspaceId],
        )
      ).rows[0];
      if (!grantRow) return { attempt, outcome: 'grant_not_found' };
      const grant = executionGrantFromRow(grantRow);
      if (grant.consumedAt) return { attempt, grant, outcome: 'grant_already_consumed' };
      if (attempt.state !== 'reserved') return { attempt, grant, outcome: 'attempt_state_mismatch' };
      if (
        attempt.reservationOwner !== input.reservationOwner ||
        attempt.grantId !== input.grantId ||
        attempt.toolCallId !== input.toolCallId ||
        grant.toolCallId !== input.toolCallId
      ) {
        return { attempt, grant, outcome: 'binding_mismatch' };
      }
      const consumedGrantRow = (
        await client.query(
          'UPDATE execution_grants SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL RETURNING *',
          [input.grantId, input.dispatchedAt],
        )
      ).rows[0];
      const dispatchedAttemptRow = (
        await client.query(
          `
            UPDATE execution_attempts
            SET state = 'dispatched', dispatched_at = $2, updated_at = $2
            WHERE id = $1 AND state = 'reserved'
            RETURNING *
          `,
          [input.attemptId, input.dispatchedAt],
        )
      ).rows[0];
      if (!consumedGrantRow || !dispatchedAttemptRow) throw new Error('Atomic grant dispatch lost its locked state.');
      return {
        attempt: executionAttemptFromRow(dispatchedAttemptRow),
        grant: executionGrantFromRow(consumedGrantRow),
        outcome: 'dispatched',
      };
    });
  }

  async publishApprovedExternalAuthorizationAtomically(
    input: AtomicApprovedExternalAuthorizationPublicationInput,
  ): Promise<AtomicApprovedExternalAuthorizationPublicationResult> {
    assertApprovedExternalAuthorizationPublicationCandidate(input);
    const workspaceId = input.toolCall.workspaceId ?? 'default';
    return this.withTransaction(async (client) => {
      const toolCallRow = (await client.query(
        'SELECT * FROM tool_calls WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
        [input.toolCall.id, workspaceId],
      )).rows[0];
      const approvalRow = (await client.query(
        'SELECT * FROM approvals WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
        [input.approvalId, workspaceId],
      )).rows[0];
      const toolCall = toolCallRow ? toolCallFromRow(toolCallRow) : undefined;
      const approval = approvalRow ? approvalFromRow(approvalRow) : undefined;
      if (!toolCall || !approval) return { approval, outcome: 'not_found' as const, toolCall };

      const receiptRows = (await client.query(
        `SELECT * FROM action_receipts
         WHERE (workspace_id = $1 AND tool_call_id = $2) OR id = $3
         FOR UPDATE`,
        [workspaceId, toolCall.id, input.receipt.id],
      )).rows;
      const grantRows = (await client.query(
        `SELECT * FROM execution_grants
         WHERE (workspace_id = $1 AND tool_call_id = $2) OR id = $3
         FOR UPDATE`,
        [workspaceId, toolCall.id, input.grant.id],
      )).rows;
      const attemptRows = (await client.query(
        `SELECT * FROM execution_attempts
         WHERE (workspace_id = $1 AND tool_call_id = $2) OR id = $3
         FOR UPDATE`,
        [workspaceId, toolCall.id, input.attempt.id],
      )).rows;
      const receiptRow = receiptRows.find((row) => String(row.workspace_id) === workspaceId && String(row.tool_call_id) === toolCall.id);
      const grantRow = grantRows.find((row) => String(row.workspace_id) === workspaceId && String(row.tool_call_id) === toolCall.id);
      const attemptRow = attemptRows.find((row) => String(row.workspace_id) === workspaceId && String(row.tool_call_id) === toolCall.id);
      const receipt = receiptRow ? actionReceiptFromRow(receiptRow) : undefined;
      const grant = grantRow ? executionGrantFromRow(grantRow) : undefined;
      const attempt = attemptRow ? executionAttemptFromRow(attemptRow) : undefined;
      const candidateIdCollision = receiptRows.some((row) => row !== receiptRow)
        || grantRows.some((row) => row !== grantRow)
        || attemptRows.some((row) => row !== attemptRow);
      const publicationExists = candidateIdCollision
        || receipt !== undefined
        || grant !== undefined
        || attempt !== undefined
        || toolCall.status === 'authorized';
      if (publicationExists) {
        return !candidateIdCollision && sameApprovedExternalAuthorizationPublication(input, { attempt, grant, receipt, toolCall })
          ? { approval, attempt, grant, outcome: 'replay' as const, receipt, toolCall }
          : { approval, attempt, grant, outcome: 'conflict' as const, receipt, toolCall };
      }
      if (approval.status !== 'approved' || toolCall.status !== 'pending_approval') {
        return { approval, outcome: 'state_mismatch' as const, toolCall };
      }
      if (!approvedExternalAuthorizationMatchesCurrent(input, approval, toolCall)) {
        return { approval, outcome: 'binding_mismatch' as const, toolCall };
      }

      await this.writeActionReceipt(input.receipt, client, false);
      await this.writeExecutionGrant(input.grant, client, false);
      await insertExecutionAttempt(client, input.attempt);
      await this.writeToolCall(input.toolCall, client);
      return {
        approval,
        attempt: input.attempt,
        grant: input.grant,
        outcome: 'created' as const,
        receipt: input.receipt,
        toolCall: input.toolCall,
      };
    });
  }

  async adoptKnownExternalExecutionOutcomeAtomically(
    input: AtomicKnownExternalExecutionOutcomeAdoptionInput,
  ): Promise<AtomicKnownExternalExecutionOutcomeAdoptionResult> {
    assertKnownExternalExecutionOutcomeAdoptionCandidate(input);
    return this.withTransaction(async (client) => {
      const attemptRow = (await client.query(
        'SELECT * FROM execution_attempts WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
        [input.attemptId, input.workspaceId],
      )).rows[0];
      const attempt = attemptRow ? executionAttemptFromRow(attemptRow) : undefined;
      if (!attempt) return { outcome: 'not_found' as const };
      const toolCallRow = (await client.query(
        'SELECT * FROM tool_calls WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
        [attempt.toolCallId, input.workspaceId],
      )).rows[0];
      const receiptRow = (await client.query(
        'SELECT * FROM action_receipts WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
        [input.receipt.id, input.workspaceId],
      )).rows[0];
      const grantRow = attempt.grantId
        ? (await client.query(
            'SELECT * FROM execution_grants WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
            [attempt.grantId, input.workspaceId],
          )).rows[0]
        : undefined;
      const toolCall = toolCallRow ? toolCallFromRow(toolCallRow) : undefined;
      const receipt = receiptRow ? actionReceiptFromRow(receiptRow) : undefined;
      const grant = grantRow ? executionGrantFromRow(grantRow) : undefined;
      if (!toolCall || !receipt || !grant) return { attempt, grant, outcome: 'not_found' as const, receipt, toolCall };
      const state = externalOutcomeAdoptionState(attempt);
      if (state === 'reconciliation_required') return { attempt, grant, outcome: state, receipt, toolCall };
      if (state === 'state_mismatch') return { attempt, grant, outcome: state, receipt, toolCall };
      if (sameKnownExternalOutcomeProjection(input, receipt, toolCall)) {
        return { attempt, grant, outcome: 'replay' as const, receipt, toolCall };
      }
      if (!knownExternalOutcomeMatchesCurrent(input, { attempt, grant, receipt, toolCall })) {
        return { attempt, grant, outcome: 'binding_mismatch' as const, receipt, toolCall };
      }
      if (!outcomeProjectionCanBeAdopted(input, receipt, toolCall)) {
        return { attempt, grant, outcome: 'conflict' as const, receipt, toolCall };
      }
      let adoptedReceipt = receipt;
      if (!receipt.outcome) {
        const updated = (await client.query(
          'UPDATE action_receipts SET outcome_json = $3 WHERE id = $1 AND workspace_id = $2 AND outcome_json IS NULL RETURNING *',
          [input.receipt.id, input.workspaceId, JSON.stringify(input.receipt.outcome)],
        )).rows[0];
        if (!updated) throw new Error('Known external outcome adoption lost its locked receipt.');
        adoptedReceipt = actionReceiptFromRow(updated);
      }
      let adoptedToolCall = toolCall;
      if (toolCall.status === 'authorized') {
        await this.writeToolCall(input.toolCall, client);
        adoptedToolCall = input.toolCall;
      }
      return { attempt, grant, outcome: 'adopted' as const, receipt: adoptedReceipt, toolCall: adoptedToolCall };
    });
  }

  async recordKnownExternalExecutionOutcomeAtomically(
    input: AtomicKnownExternalExecutionOutcomeRecordingInput,
  ): Promise<AtomicKnownExternalExecutionOutcomeRecordingResult> {
    assertKnownExternalExecutionOutcomeRecordingCandidate(input);
    return this.withTransaction(async (client) => {
      const attemptRow = (await client.query(
        'SELECT * FROM execution_attempts WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
        [input.attemptId, input.workspaceId],
      )).rows[0];
      const attempt = attemptRow ? executionAttemptFromRow(attemptRow) : undefined;
      if (!attempt) return { outcome: 'not_found' as const };
      const toolCallRow = (await client.query(
        'SELECT * FROM tool_calls WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
        [attempt.toolCallId, input.workspaceId],
      )).rows[0];
      const receiptRow = attempt.binding.receiptId
        ? (await client.query(
            'SELECT * FROM action_receipts WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
            [attempt.binding.receiptId, input.workspaceId],
          )).rows[0]
        : undefined;
      const grantRow = attempt.grantId
        ? (await client.query(
            'SELECT * FROM execution_grants WHERE id = $1 AND workspace_id = $2 FOR UPDATE',
            [attempt.grantId, input.workspaceId],
          )).rows[0]
        : undefined;
      const toolCall = toolCallRow ? toolCallFromRow(toolCallRow) : undefined;
      const receipt = receiptRow ? actionReceiptFromRow(receiptRow) : undefined;
      const grant = grantRow ? executionGrantFromRow(grantRow) : undefined;
      if (!toolCall || !receipt || !grant) {
        return { attempt, grant, outcome: 'not_found' as const, receipt, toolCall };
      }
      if (attempt.reservationOwner !== input.reservationOwner) {
        return { attempt, grant, outcome: 'owner_mismatch' as const, receipt, toolCall };
      }
      const current = { attempt, grant, receipt, toolCall };
      if (!knownExternalOutcomeRecordingBindingsMatch(input, current)) {
        return { ...current, outcome: 'binding_mismatch' as const };
      }
      if (sameRecordedKnownExternalOutcomeProjection(input, attempt, receipt, toolCall)) {
        return { ...current, outcome: 'replay' as const };
      }
      if (!knownExternalOutcomeRecordingMatchesCurrent(input, current) || attempt.state !== 'dispatched') {
        return { ...current, outcome: knownExternalOutcomeRecordingConflictDisposition(attempt) };
      }
      const completedAttemptRow = (await client.query(
        `UPDATE execution_attempts
         SET state = $3, updated_at = $4, completed_at = $4, outcome_json = $5
         WHERE id = $1 AND workspace_id = $2 AND state = 'dispatched' AND outcome_json IS NULL
         RETURNING *`,
        [
          attempt.id,
          input.workspaceId,
          input.attemptOutcome.status,
          input.attemptOutcome.recordedAt,
          JSON.stringify(input.attemptOutcome),
        ],
      )).rows[0];
      if (!completedAttemptRow) {
        throw new Error('Known external outcome recording lost its locked execution attempt.');
      }
      const completedReceiptRow = (await client.query(
        `UPDATE action_receipts
         SET outcome_json = $3
         WHERE id = $1 AND workspace_id = $2 AND outcome_json IS NULL
         RETURNING *`,
        [receipt.id, input.workspaceId, JSON.stringify(input.receiptOutcome)],
      )).rows[0];
      if (!completedReceiptRow) {
        throw new Error('Known external outcome recording lost its locked receipt.');
      }
      await this.writeToolCall(input.toolCall, client);
      return {
        attempt: executionAttemptFromRow(completedAttemptRow),
        grant,
        outcome: 'recorded' as const,
        receipt: actionReceiptFromRow(completedReceiptRow),
        toolCall: input.toolCall,
      };
    });
  }

  async createActionReceipt(record: ActionReceiptRecord): Promise<ActionReceiptRecord> {
    return this.writeActionReceipt(record);
  }

  async getActionReceipt(id: string): Promise<ActionReceiptRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM action_receipts WHERE id = $1 LIMIT 1', [id]);
    const row = result.rows[0];
    return row ? actionReceiptFromRow(row) : undefined;
  }

  async getActionReceiptByToolCallId(toolCallId: string): Promise<ActionReceiptRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM action_receipts WHERE tool_call_id = $1 LIMIT 1', [toolCallId]);
    const row = result.rows[0];
    return row ? actionReceiptFromRow(row) : undefined;
  }

  async updateActionReceipt(record: ActionReceiptRecord): Promise<ActionReceiptRecord> {
    return this.writeActionReceipt(record);
  }

  async recordActionReceiptOutcomeAtomically(
    input: AtomicActionReceiptOutcomeInput,
  ): Promise<AtomicActionReceiptOutcomeResult> {
    const row = (await this.pool.query(
      `
        UPDATE action_receipts
        SET outcome_json = $2
        WHERE id = $1 AND outcome_json IS NULL
        RETURNING *
      `,
      [input.receiptId, JSON.stringify(input.outcome)],
    )).rows[0];
    if (row) return { outcome: 'recorded', receipt: actionReceiptFromRow(row) };
    const receipt = await this.getActionReceipt(input.receiptId);
    return receipt ? { outcome: 'existing', receipt } : { outcome: 'not_found' };
  }

  async createIdempotencyRecord(record: IdempotencyRecord): Promise<IdempotencyRecord> {
    await this.pool.query(
      `
        INSERT INTO idempotency_records (workspace_id, route, key, request_hash, tool_call_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (workspace_id, route, key) DO NOTHING
      `,
      [record.workspaceId, record.route, record.key, record.requestHash, record.toolCallId, record.createdAt],
    );
    return record;
  }

  async getIdempotencyRecord(workspaceId: string, route: string, key: string): Promise<IdempotencyRecord | undefined> {
    const result = await this.pool.query(
      `
        SELECT * FROM idempotency_records
        WHERE workspace_id = $1 AND route = $2 AND key = $3
        LIMIT 1
      `,
      [workspaceId, route, key],
    );
    const row = result.rows[0];
    return row ? idempotencyFromRow(row) : undefined;
  }

  async upsertObservedTool(record: ObservedToolRecord): Promise<ObservedToolRecord> {
    await this.writeObservedTool(record);
    return record;
  }

  async getObservedTool(id: string): Promise<ObservedToolRecord | undefined> {
    const result = await this.pool.query('SELECT * FROM observed_tools WHERE id = $1 LIMIT 1', [id]);
    const row = result.rows[0];
    return row ? observedToolFromRow(row) : undefined;
  }

  async getObservedToolByName(workspaceId: string, toolName: string): Promise<ObservedToolRecord | undefined> {
    const result = await this.pool.query(
      'SELECT * FROM observed_tools WHERE workspace_id = $1 AND tool_name = $2 LIMIT 1',
      [workspaceId, toolName],
    );
    const row = result.rows[0];
    return row ? observedToolFromRow(row) : undefined;
  }

  async listObservedTools(workspaceId: string): Promise<ObservedToolRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM observed_tools WHERE workspace_id = $1 ORDER BY last_seen_at DESC',
      [workspaceId],
    );
    return result.rows.map(observedToolFromRow);
  }

  async append(event: AuditEvent): Promise<void> {
    await this.pool.query(
      `
        INSERT INTO audit_events (
          id, type, workspace_id, tool_call_id, approval_id, actor, auth_json, input_hash,
          policy_version_id, policy_version_hash, previous_event_hash, event_hash, timestamp, data_json
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (id) DO NOTHING
      `,
      [
        event.id,
        event.type,
        event.workspaceId ?? null,
        event.toolCallId ?? null,
        event.approvalId ?? null,
        event.actor ?? null,
        event.auth === undefined ? null : JSON.stringify(event.auth),
        event.inputHash ?? null,
        event.policyVersionId ?? null,
        event.policyVersionHash ?? null,
        event.previousEventHash ?? null,
        event.eventHash ?? null,
        event.timestamp,
        JSON.stringify(event.data),
      ],
    );
  }

  async list(limit: AuditListLimit = 100, filters: AuditListFilters = {}): Promise<AuditEvent[]> {
    const safeLimit = limit === 'all' ? undefined : Number.isFinite(limit) ? Math.max(1, Math.trunc(limit)) : 100;
    const values: unknown[] = [];
    const conditions: string[] = [];
    if (filters.from) {
      values.push(filters.from);
      conditions.push(`timestamp >= $${values.length}`);
    }
    if (filters.to) {
      values.push(filters.to);
      conditions.push(`timestamp <= $${values.length}`);
    }
    if (filters.toolCallId) {
      values.push(filters.toolCallId);
      conditions.push(`tool_call_id = $${values.length}`);
    }
    if (filters.workspaceId) {
      values.push(filters.workspaceId);
      conditions.push(`workspace_id = $${values.length}`);
    }
    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const limitClause = safeLimit === undefined ? '' : `LIMIT $${values.length + 1}`;
    if (safeLimit !== undefined) values.push(safeLimit);
    const result = await this.pool.query(`SELECT * FROM audit_events ${whereClause} ORDER BY timestamp DESC ${limitClause}`, values);
    return result.rows.map(auditEventFromRow);
  }

  async recordPolicyVersion(record: PolicyVersionRecord): Promise<void> {
    await this.pool.query(
      `
        INSERT INTO policy_versions (id, version, policy_json, created_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO UPDATE SET
          version = EXCLUDED.version,
          policy_json = EXCLUDED.policy_json,
          created_at = EXCLUDED.created_at
      `,
      [record.id, record.version, JSON.stringify(record.policy), record.createdAt],
    );
  }

  private async withTransaction<T>(operation: (client: PgClient) => Promise<T>): Promise<T> {
    if (!this.pool.connect) throw new Error('Postgres pool does not support checked-out transactions.');
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await operation(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // Preserve the operation failure; a broken client is discarded by pg on release.
      }
      throw error;
    } finally {
      client.release();
    }
  }

  private async writeToolCall(record: ToolCallRecord, queryable: PgQueryable = this.pool, upsert = true): Promise<void> {
    await queryable.query(
      `
        INSERT INTO tool_calls (
          id, workspace_id, tool_name, input_json, input_hash, requested_by, requested_by_auth_json,
          action_envelope_json, action_envelope_hash, canonical_action_request_hash,
          canonical_action_request_version, canonical_decision_input_hash, canonical_policy_context_json,
          agent_id, reason, metadata_json, status, decision,
          decision_trace_json, governance_state_json, policy_reason, policy_version_id, policy_version_hash, risk, result_json, error, created_at, updated_at
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28
        )
        ${upsert ? `ON CONFLICT (id) DO UPDATE SET
          workspace_id = EXCLUDED.workspace_id,
          tool_name = EXCLUDED.tool_name,
          input_json = EXCLUDED.input_json,
          input_hash = EXCLUDED.input_hash,
          requested_by = EXCLUDED.requested_by,
          requested_by_auth_json = EXCLUDED.requested_by_auth_json,
          action_envelope_json = EXCLUDED.action_envelope_json,
          action_envelope_hash = EXCLUDED.action_envelope_hash,
          canonical_action_request_hash = EXCLUDED.canonical_action_request_hash,
          canonical_action_request_version = EXCLUDED.canonical_action_request_version,
          canonical_decision_input_hash = EXCLUDED.canonical_decision_input_hash,
          canonical_policy_context_json = EXCLUDED.canonical_policy_context_json,
          agent_id = EXCLUDED.agent_id,
          reason = EXCLUDED.reason,
          metadata_json = EXCLUDED.metadata_json,
          status = EXCLUDED.status,
          decision = EXCLUDED.decision,
          decision_trace_json = EXCLUDED.decision_trace_json,
          governance_state_json = EXCLUDED.governance_state_json,
          policy_reason = EXCLUDED.policy_reason,
          policy_version_id = EXCLUDED.policy_version_id,
          policy_version_hash = EXCLUDED.policy_version_hash,
          risk = EXCLUDED.risk,
          result_json = EXCLUDED.result_json,
          error = EXCLUDED.error,
          created_at = EXCLUDED.created_at,
          updated_at = EXCLUDED.updated_at` : ''}
      `,
      [
        record.id,
        record.workspaceId ?? 'default',
        record.toolName,
        JSON.stringify(record.input),
        record.inputHash ?? null,
        record.requestedBy,
        record.requestedByAuth === undefined ? null : JSON.stringify(record.requestedByAuth),
        record.actionEnvelope === undefined ? null : JSON.stringify(record.actionEnvelope),
        record.actionEnvelopeHash ?? null,
        record.canonicalActionRequestHash ?? null,
        record.canonicalActionRequestVersion ?? null,
        record.canonicalDecisionInputHash ?? null,
        record.canonicalPolicyContext === undefined ? null : JSON.stringify(record.canonicalPolicyContext),
        record.agentId,
        record.reason,
        JSON.stringify(record.metadata),
        record.status,
        record.decision ?? null,
        record.decisionTrace === undefined ? null : JSON.stringify(record.decisionTrace),
        JSON.stringify(toolCallGovernanceState(record)),
        record.policyReason ?? null,
        record.policyVersionId ?? null,
        record.policyVersionHash ?? null,
        record.risk ?? null,
        record.result === undefined ? null : JSON.stringify(record.result),
        record.error ?? null,
        record.createdAt,
        record.updatedAt,
      ],
    );
  }

  private async writeApproval(record: ApprovalRecord): Promise<void> {
    await this.pool.query(
      `
        INSERT INTO approvals (
          id, workspace_id, tool_call_id, status, requested_by, requested_by_auth_json,
          authorization_json, authorization_consumed_at, authorization_consumed_reason, approved_by,
          cancelled_at, cancelled_by, cancellation_reason, expired_at, finalized_at,
          rejected_by, note, rejection_reason, original_input_json, original_input_hash, original_envelope_hash,
          edited_input_json, approved_input_hash, approved_envelope_hash, review_hash, approver_users_json,
          approver_groups_json, required_approvals, separation_of_duties, decisions_json, created_at, updated_at
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
          $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32
        )
        ON CONFLICT (id) DO UPDATE SET
          workspace_id = EXCLUDED.workspace_id,
          tool_call_id = EXCLUDED.tool_call_id,
          status = EXCLUDED.status,
          requested_by = EXCLUDED.requested_by,
          requested_by_auth_json = EXCLUDED.requested_by_auth_json,
          authorization_json = EXCLUDED.authorization_json,
          authorization_consumed_at = EXCLUDED.authorization_consumed_at,
          authorization_consumed_reason = EXCLUDED.authorization_consumed_reason,
          approved_by = EXCLUDED.approved_by,
          cancelled_at = EXCLUDED.cancelled_at,
          cancelled_by = EXCLUDED.cancelled_by,
          cancellation_reason = EXCLUDED.cancellation_reason,
          expired_at = EXCLUDED.expired_at,
          finalized_at = EXCLUDED.finalized_at,
          rejected_by = EXCLUDED.rejected_by,
          note = EXCLUDED.note,
          rejection_reason = EXCLUDED.rejection_reason,
          original_input_json = EXCLUDED.original_input_json,
          original_input_hash = EXCLUDED.original_input_hash,
          original_envelope_hash = EXCLUDED.original_envelope_hash,
          edited_input_json = EXCLUDED.edited_input_json,
          approved_input_hash = EXCLUDED.approved_input_hash,
          approved_envelope_hash = EXCLUDED.approved_envelope_hash,
          review_hash = EXCLUDED.review_hash,
          approver_users_json = EXCLUDED.approver_users_json,
          approver_groups_json = EXCLUDED.approver_groups_json,
          required_approvals = EXCLUDED.required_approvals,
          separation_of_duties = EXCLUDED.separation_of_duties,
          decisions_json = EXCLUDED.decisions_json,
          created_at = EXCLUDED.created_at,
          updated_at = EXCLUDED.updated_at
      `,
      [
        record.id,
        record.workspaceId ?? 'default',
        record.toolCallId,
        record.status,
        record.requestedBy,
        record.requestedByAuth === undefined ? null : JSON.stringify(record.requestedByAuth),
        record.authorization === undefined ? null : JSON.stringify(record.authorization),
        record.authorizationConsumedAt ?? null,
        record.authorizationConsumedReason ?? null,
        record.approvedBy ?? null,
        record.cancelledAt ?? null,
        record.cancelledBy ?? null,
        record.cancellationReason ?? null,
        record.expiredAt ?? null,
        record.finalizedAt ?? null,
        record.rejectedBy ?? null,
        record.note ?? null,
        record.rejectionReason ?? null,
        JSON.stringify(record.originalInput),
        record.originalInputHash ?? null,
        record.originalEnvelopeHash ?? null,
        record.editedInput === undefined ? null : JSON.stringify(record.editedInput),
        record.approvedInputHash ?? null,
        record.approvedEnvelopeHash ?? null,
        record.reviewHash ?? null,
        record.approverUsers === undefined ? null : JSON.stringify(record.approverUsers),
        record.approverGroups === undefined ? null : JSON.stringify(record.approverGroups),
        record.requiredApprovals ?? null,
        record.separationOfDuties === undefined ? null : record.separationOfDuties ? 1 : 0,
        record.decisions === undefined ? null : JSON.stringify(record.decisions),
        record.createdAt,
        record.updatedAt,
      ],
    );
  }

  private async writeApprovalDelivery(record: ApprovalDeliveryRecord): Promise<ApprovalDeliveryRecord> {
    await this.pool.query(
      `
        INSERT INTO approval_deliveries (
          id, workspace_id, approval_id, tool_call_id, channel_id, provider, status,
          message_id, destination, error, recipient_user_id, recipient_email, recipient_slack_user_id,
          recipient_telegram_chat_id, recipient_telegram_user_id, data_json, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        ON CONFLICT (id) DO UPDATE SET
          status = EXCLUDED.status,
          message_id = EXCLUDED.message_id,
          destination = EXCLUDED.destination,
          error = EXCLUDED.error,
          recipient_user_id = EXCLUDED.recipient_user_id,
          recipient_email = EXCLUDED.recipient_email,
          recipient_slack_user_id = EXCLUDED.recipient_slack_user_id,
          recipient_telegram_chat_id = EXCLUDED.recipient_telegram_chat_id,
          recipient_telegram_user_id = EXCLUDED.recipient_telegram_user_id,
          data_json = EXCLUDED.data_json,
          updated_at = EXCLUDED.updated_at
      `,
      [
        record.id,
        record.workspaceId ?? 'default',
        record.approvalId,
        record.toolCallId,
        record.channelId,
        record.provider,
        record.status,
        record.messageId ?? null,
        record.destination ?? null,
        record.error ?? null,
        record.recipientUserId ?? null,
        record.recipientEmail ?? null,
        record.recipientSlackUserId ?? null,
        record.recipientTelegramChatId ?? null,
        record.recipientTelegramUserId ?? null,
        JSON.stringify(record.data),
        record.createdAt,
        record.updatedAt,
      ],
    );
    return record;
  }

  private async writeApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord> {
    await this.pool.query(
      `
        INSERT INTO api_keys (
          id, workspace_id, service_account_id, key_prefix, key_hash, scopes_json, created_at, last_used_at, revoked_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (id) DO UPDATE SET
          workspace_id = EXCLUDED.workspace_id,
          service_account_id = EXCLUDED.service_account_id,
          key_prefix = EXCLUDED.key_prefix,
          key_hash = EXCLUDED.key_hash,
          scopes_json = EXCLUDED.scopes_json,
          last_used_at = EXCLUDED.last_used_at,
          revoked_at = EXCLUDED.revoked_at
      `,
      [
        record.id,
        record.workspaceId,
        record.serviceAccountId,
        record.keyPrefix,
        record.keyHash,
        JSON.stringify(record.scopes),
        record.createdAt,
        record.lastUsedAt ?? null,
        record.revokedAt ?? null,
      ],
    );
    return record;
  }

  private async writeExecutionGrant(
    record: ExecutionGrantRecord,
    queryable: PgQueryable = this.pool,
    upsert = true,
  ): Promise<ExecutionGrantRecord> {
    await queryable.query(
      `
        INSERT INTO execution_grants (
          id, workspace_id, tool_call_id, tool_name, input_hash, approved_input_hash, approved_envelope_hash,
          policy_version_hash, receipt_id, receipt_hash, actor, auth_json, expires_at, nonce, signature,
          consumed_at, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
        ${upsert ? `ON CONFLICT (id) DO UPDATE SET
          consumed_at = EXCLUDED.consumed_at` : ''}
      `,
      [
        record.id,
        record.workspaceId,
        record.toolCallId,
        record.toolName,
        record.inputHash,
        record.approvedInputHash ?? null,
        record.approvedEnvelopeHash ?? null,
        record.policyVersionHash ?? null,
        record.receiptId ?? null,
        record.receiptHash ?? null,
        record.actor,
        record.auth === undefined ? null : JSON.stringify(record.auth),
        record.expiresAt,
        record.nonce,
        record.signature,
        record.consumedAt ?? null,
        record.createdAt,
      ],
    );
    return record;
  }

  private async writeActionReceipt(
    record: ActionReceiptRecord,
    queryable: PgQueryable = this.pool,
    upsert = true,
  ): Promise<ActionReceiptRecord> {
    await queryable.query(
      `
        INSERT INTO action_receipts (
          id, workspace_id, tool_call_id, approval_id, decision_kind, decision_actor,
          decision_auth_json, tool_name, source_json, protocol,
          operation_json, original_input_hash, approved_input_hash, original_envelope_hash,
          approved_envelope_hash, review_hash, policy_version_id, policy_version_hash, policy_decision,
          policy_reason, policy_risk, execution_mode, issued_at, expires_at, receipt_hash,
          key_id, signature_alg, signature, outcome_json, created_at
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
          $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30
        )
        ${upsert ? `ON CONFLICT (id) DO UPDATE SET
          outcome_json = EXCLUDED.outcome_json,
          receipt_hash = EXCLUDED.receipt_hash,
          signature = EXCLUDED.signature` : ''}
      `,
      [
        record.id,
        record.workspaceId,
        record.toolCallId,
        record.approvalId ?? null,
        record.decisionKind,
        record.decisionActor,
        record.decisionAuth === undefined ? null : JSON.stringify(record.decisionAuth),
        record.toolName,
        JSON.stringify(record.source),
        record.protocol,
        JSON.stringify(record.operation),
        record.originalInputHash,
        record.approvedInputHash,
        record.originalEnvelopeHash,
        record.approvedEnvelopeHash,
        record.reviewHash ?? null,
        record.policyVersionId ?? null,
        record.policyVersionHash ?? null,
        record.policyDecision ?? null,
        record.policyReason ?? null,
        record.policyRisk ?? null,
        record.executionMode,
        record.issuedAt,
        record.expiresAt ?? null,
        record.receiptHash,
        record.keyId,
        record.signatureAlg,
        record.signature,
        record.outcome === undefined ? null : JSON.stringify(record.outcome),
        record.createdAt,
      ],
    );
    return record;
  }

  private async writeObservedTool(record: ObservedToolRecord): Promise<void> {
    await this.pool.query(
      `
        INSERT INTO observed_tools (
          id, workspace_id, tool_name, sources_json, source_ids_json, first_seen_at, last_seen_at,
          call_count, schema_hash, coverage_json, status, suggestion_json, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (workspace_id, tool_name) DO UPDATE SET
          sources_json = EXCLUDED.sources_json,
          source_ids_json = EXCLUDED.source_ids_json,
          last_seen_at = EXCLUDED.last_seen_at,
          call_count = EXCLUDED.call_count,
          schema_hash = EXCLUDED.schema_hash,
          coverage_json = EXCLUDED.coverage_json,
          status = EXCLUDED.status,
          suggestion_json = EXCLUDED.suggestion_json,
          updated_at = EXCLUDED.updated_at
      `,
      [
        record.id,
        record.workspaceId,
        record.toolName,
        JSON.stringify(record.sources),
        JSON.stringify(record.sourceIds),
        record.firstSeenAt,
        record.lastSeenAt,
        record.callCount,
        record.schemaHash ?? null,
        JSON.stringify(record.coverage),
        record.status,
        JSON.stringify(record.suggestion),
        record.createdAt,
        record.updatedAt,
      ],
    );
  }
}

function addFilter(clauses: string[], values: unknown[], column: string, value: unknown): void {
  if (value === undefined) return;
  values.push(value);
  clauses.push(`${column} = $${values.length}`);
}

function toolCallFromRow(row: PgRow): ToolCallRecord {
  return {
    ...toolCallGovernanceStateFromRow(row.governance_state_json),
    agentId: stringValue(row.agent_id),
    createdAt: stringValue(row.created_at),
    decision: optionalString(row.decision) as ToolCallRecord['decision'],
    decisionTrace: parseOptionalJsonObject(row.decision_trace_json),
    error: optionalString(row.error),
    id: stringValue(row.id),
    input: parseJsonObject(row.input_json),
    inputHash: optionalString(row.input_hash),
    actionEnvelope: parseOptionalJsonObject(row.action_envelope_json) as ActionEnvelope | undefined,
    actionEnvelopeHash: optionalString(row.action_envelope_hash),
    canonicalActionRequestHash: optionalString(row.canonical_action_request_hash),
    canonicalActionRequestVersion: optionalString(row.canonical_action_request_version) as ToolCallRecord['canonicalActionRequestVersion'],
    canonicalDecisionInputHash: optionalString(row.canonical_decision_input_hash),
    canonicalPolicyContext: parseOptionalJsonObject(row.canonical_policy_context_json) as ToolCallRecord['canonicalPolicyContext'],
    metadata: parseJsonObject(row.metadata_json),
    policyReason: optionalString(row.policy_reason),
    policyVersionHash: optionalString(row.policy_version_hash),
    policyVersionId: optionalString(row.policy_version_id),
    reason: stringValue(row.reason),
    requestedBy: stringValue(row.requested_by),
    requestedByAuth: parseOptionalAuthContext(row.requested_by_auth_json),
    result: parseOptionalJson(row.result_json),
    risk: optionalString(row.risk),
    status: stringValue(row.status) as ToolCallRecord['status'],
    toolName: stringValue(row.tool_name),
    updatedAt: stringValue(row.updated_at),
    workspaceId: optionalString(row.workspace_id) ?? 'default',
  };
}

function toolCallGovernanceState(record: ToolCallRecord): JsonObject {
  return {
    version: 'actionproxy.tool-call-governance-state.v1',
    ...(record.authorizationDecision === undefined ? {} : { authorizationDecision: record.authorizationDecision }),
    ...(record.authorizationReason === undefined ? {} : { authorizationReason: record.authorizationReason }),
    ...(record.contentInfluence === undefined ? {} : { contentInfluence: record.contentInfluence }),
    ...(record.influenceScopeId === undefined ? {} : { influenceScopeId: record.influenceScopeId }),
    ...(record.resultDelivery === undefined ? {} : { resultDelivery: record.resultDelivery }),
    ...(record.resultSource === undefined ? {} : { resultSource: record.resultSource }),
    ...(record.resultWithheld === undefined ? {} : { resultWithheld: record.resultWithheld }),
  } as unknown as JsonObject;
}

function toolCallGovernanceStateFromRow(value: unknown): Partial<ToolCallRecord> {
  const state = parseOptionalJsonObject(value);
  if (!state || state.version !== 'actionproxy.tool-call-governance-state.v1') return {};
  const authorizationDecision = ['allow', 'deny', 'require_approval'].includes(String(state.authorizationDecision))
    ? state.authorizationDecision as ToolCallRecord['authorizationDecision']
    : undefined;
  const authorizationReason = typeof state.authorizationReason === 'string' ? state.authorizationReason : undefined;
  const contentInfluence = isJsonObject(state.contentInfluence) &&
      state.contentInfluence.version === 'actionproxy.content-influence.v1'
    ? state.contentInfluence as unknown as ToolCallRecord['contentInfluence']
    : undefined;
  const influenceScopeId = typeof state.influenceScopeId === 'string' ? state.influenceScopeId : undefined;
  const resultDelivery = isJsonObject(state.resultDelivery) &&
      state.resultDelivery.version === 'actionproxy.result-delivery.v1'
    ? state.resultDelivery as unknown as ToolCallRecord['resultDelivery']
    : undefined;
  const resultSource = state.resultSource === 'none' || isJsonObject(state.resultSource)
    ? state.resultSource as ToolCallRecord['resultSource']
    : undefined;
  const resultWithheld = typeof state.resultWithheld === 'boolean' ? state.resultWithheld : undefined;
  return {
    ...(authorizationDecision === undefined ? {} : { authorizationDecision }),
    ...(authorizationReason === undefined ? {} : { authorizationReason }),
    ...(contentInfluence === undefined ? {} : { contentInfluence }),
    ...(influenceScopeId === undefined ? {} : { influenceScopeId }),
    ...(resultDelivery === undefined ? {} : { resultDelivery }),
    ...(resultSource === undefined ? {} : { resultSource }),
    ...(resultWithheld === undefined ? {} : { resultWithheld }),
  };
}

function contentExposureFromRow(row: PgRow): ContentExposureRecord {
  const sourceId = optionalString(row.source_id);
  return {
    influenceScopeId: stringValue(row.influence_scope_id),
    integrity: stringValue(row.integrity) as ContentExposureRecord['integrity'],
    observedAt: stringValue(row.observed_at),
    policyVersionHash: stringValue(row.policy_version_hash),
    ...(sourceId === undefined ? {} : { sourceId }),
    sourceToolCallId: stringValue(row.source_tool_call_id),
    workspaceId: stringValue(row.workspace_id),
  };
}

async function insertExecutionAttempt(client: PgQueryable, record: ExecutionAttemptRecordV1): Promise<PgRow> {
  const result = await client.query(
    `
      INSERT INTO execution_attempts (
        id, workspace_id, tool_call_id, attempt_number, version, state, reservation_owner,
        execution_mode, executor_id, input_hash, provider_idempotency, retry_policy,
        binding_json, grant_id, outcome_json, reserved_at, dispatched_at, completed_at, updated_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
      )
      RETURNING *
    `,
    [
      record.id,
      record.workspaceId,
      record.toolCallId,
      record.attemptNumber,
      record.version,
      record.state,
      record.reservationOwner,
      record.executionMode,
      record.executorId,
      record.inputHash,
      record.providerIdempotency,
      record.retryPolicy,
      JSON.stringify(record.binding),
      record.grantId ?? null,
      record.outcome === undefined ? null : JSON.stringify(record.outcome),
      record.reservedAt,
      record.dispatchedAt ?? null,
      record.completedAt ?? null,
      record.updatedAt,
    ],
  );
  const row = result.rows[0];
  if (!row) throw new Error('Execution attempt reservation did not return its row.');
  return row;
}

function executionAttemptBindingMatches(
  record: ExecutionAttemptRecordV1,
  toolCall: ToolCallRecord,
  approval?: ApprovalRecord,
  receipt?: ActionReceiptRecord,
  approvalAuthorization?: ApprovalAuthorizationV1,
  databaseNow = new Date(),
): boolean {
  if (
    record.version !== 'actionproxy.execution-attempt.v1' ||
    record.attemptNumber !== 1 ||
    record.state !== 'reserved' ||
    record.outcome !== undefined ||
    record.dispatchedAt !== undefined ||
    record.completedAt !== undefined ||
    record.grantId !== undefined ||
    !record.id ||
    !record.reservationOwner ||
    record.providerIdempotency !== 'none' ||
    record.retryPolicy !== 'never_automatic' ||
    (record.executionMode === 'local_mock' && record.executorId !== 'actionproxy.local-tool-registry') ||
    (record.executionMode === 'external_grant' && record.executorId !== 'actionproxy.external-runner')
  ) {
    return false;
  }
  const decision = isJsonObject(toolCall.decisionTrace?.decisionV1) ? toolCall.decisionTrace.decisionV1 : undefined;
  if (
    record.binding.canonicalActionRequestHash !== (toolCall.canonicalActionRequestHash ?? null) ||
    record.binding.canonicalActionRequestVersion !== (toolCall.canonicalActionRequestVersion ?? null) ||
    record.binding.canonicalDecisionInputHash !== (toolCall.canonicalDecisionInputHash ?? null) ||
    record.binding.decisionId !== (typeof decision?.decisionId === 'string' ? decision.decisionId : null) ||
    record.binding.decisionVersion !== (typeof decision?.version === 'string' ? decision.version : null) ||
    record.binding.policyVersionHash !== (toolCall.policyVersionHash ?? null) ||
    !executionAttemptGovernanceBindingMatches(record, toolCall)
  ) {
    return false;
  }
  if (record.binding.approvalId !== null) {
    if (
      !approval ||
      approval.id !== record.binding.approvalId ||
      approval.status !== 'approved' ||
      approval.authorizationConsumedReason !== 'approved' ||
      !approval.authorizationConsumedAt ||
      !approval.authorization ||
      !approvalAuthorization ||
      !isValidApprovalAuthorization(approval.authorization) ||
      !isValidApprovalAuthorization(approvalAuthorization) ||
      approvalAuthorizationExpired(approval.authorization, databaseNow) ||
      approvalAuthorizationExpired(approvalAuthorization, databaseNow) ||
      approval.authorization.authorizationHash !== approvalAuthorization.authorizationHash ||
      approval.toolCallId !== record.toolCallId ||
      (approval.workspaceId ?? 'default') !== record.workspaceId ||
      approval.approvedInputHash !== record.inputHash ||
      approval.approvedEnvelopeHash !== record.binding.actionEnvelopeHash ||
      record.binding.approvalAuthorizationHash !== (approval.authorization?.authorizationHash ?? null) ||
      record.binding.approvalAuthorizationNonce !== (approval.authorization?.nonce ?? null)
    ) {
      return false;
    }
  } else if (
    record.binding.approvalAuthorizationHash !== null ||
    record.binding.approvalAuthorizationNonce !== null
  ) {
    return false;
  }
  if (record.binding.receiptId !== null) {
    if (
      !receipt ||
      receipt.id !== record.binding.receiptId ||
      receipt.toolCallId !== record.toolCallId ||
      receipt.workspaceId !== record.workspaceId ||
      receipt.receiptHash !== record.binding.receiptHash ||
      receipt.approvedEnvelopeHash !== record.binding.actionEnvelopeHash ||
      receipt.approvedInputHash !== record.inputHash ||
      (receipt.approvalId ?? null) !== record.binding.approvalId
    ) {
      return false;
    }
  } else if (record.binding.receiptHash !== null) {
    return false;
  } else if (
    record.binding.actionEnvelopeHash !== (toolCall.actionEnvelopeHash ?? null) ||
    record.inputHash !== toolCall.inputHash
  ) {
    return false;
  }
  return true;
}

function executionAttemptGovernanceBindingMatches(
  record: ExecutionAttemptRecordV1,
  toolCall: ToolCallRecord,
): boolean {
  const contentInfluenceBindingHash = validContentInfluenceBindingHash(toolCall.contentInfluence) ??
    (toolCall.contentInfluence ? 'invalid' : null);
  return (
    record.binding.contentInfluenceBindingHash === contentInfluenceBindingHash &&
    record.binding.influenceScopeId === (toolCall.influenceScopeId ?? null) &&
    record.binding.resultSourceHash === hashJson(toolCall.resultSource ?? null)
  );
}

function executionAttemptTransitionIsValid(input: AtomicExecutionAttemptTransitionInput): boolean {
  if (input.expectedState === 'reserved') {
    if (input.nextState === 'dispatched') return input.outcome === undefined;
    return input.nextState === 'failed_before_dispatch' && input.outcome?.status === input.nextState;
  }
  return (
    input.nextState !== 'reserved' &&
    input.nextState !== 'dispatched' &&
    input.nextState !== 'failed_before_dispatch' &&
    input.outcome?.status === input.nextState
  );
}

function executionAttemptTransitionIsReplay(
  current: ExecutionAttemptRecordV1,
  input: AtomicExecutionAttemptTransitionInput,
): boolean {
  if (current.state !== input.nextState) return false;
  if (current.state === 'dispatched') {
    return input.outcome === undefined && current.dispatchedAt === input.transitionedAt;
  }
  if (!executionAttemptIsTerminal(current.state)) return false;
  return (
    current.completedAt === input.transitionedAt &&
    current.outcome !== undefined &&
    input.outcome !== undefined &&
    hashJson(current.outcome) === hashJson(input.outcome)
  );
}

function executionAttemptIsTerminal(state: ExecutionAttemptState): boolean {
  return state !== 'reserved' && state !== 'dispatched';
}

function executionAttemptFromRow(row: PgRow): ExecutionAttemptRecordV1 {
  return {
    attemptNumber: Number(row.attempt_number),
    binding: parseJsonObject(row.binding_json) as unknown as ExecutionAttemptRecordV1['binding'],
    completedAt: optionalString(row.completed_at),
    dispatchedAt: optionalString(row.dispatched_at),
    executionMode: stringValue(row.execution_mode) as ExecutionAttemptRecordV1['executionMode'],
    executorId: stringValue(row.executor_id) as ExecutionAttemptRecordV1['executorId'],
    grantId: optionalString(row.grant_id),
    id: stringValue(row.id),
    inputHash: stringValue(row.input_hash),
    outcome: parseOptionalJsonObject(row.outcome_json) as unknown as ExecutionAttemptRecordV1['outcome'],
    providerIdempotency: stringValue(row.provider_idempotency) as ExecutionAttemptRecordV1['providerIdempotency'],
    reservedAt: stringValue(row.reserved_at),
    reservationOwner: stringValue(row.reservation_owner),
    retryPolicy: stringValue(row.retry_policy) as ExecutionAttemptRecordV1['retryPolicy'],
    state: stringValue(row.state) as ExecutionAttemptRecordV1['state'],
    toolCallId: stringValue(row.tool_call_id),
    updatedAt: stringValue(row.updated_at),
    version: stringValue(row.version) as ExecutionAttemptRecordV1['version'],
    workspaceId: stringValue(row.workspace_id),
  };
}

function assertIdempotencyCandidate(input: AtomicIdempotentToolCallInput): void {
  if (
    input.idempotency.toolCallId !== input.toolCall.id ||
    input.idempotency.workspaceId !== (input.toolCall.workspaceId ?? 'default')
  ) {
    throw new Error('Idempotency reservation does not match the candidate tool call.');
  }
}

function approvalFromRow(row: PgRow): ApprovalRecord {
  return {
    approverGroups: parseOptionalStringArray(row.approver_groups_json),
    approverUsers: parseOptionalStringArray(row.approver_users_json),
    approvedBy: optionalString(row.approved_by),
    authorization: parseOptionalJsonObject(row.authorization_json) as ApprovalRecord['authorization'],
    authorizationConsumedAt: optionalString(row.authorization_consumed_at),
    authorizationConsumedReason: optionalString(
      row.authorization_consumed_reason,
    ) as ApprovalRecord['authorizationConsumedReason'],
    cancellationReason: optionalString(row.cancellation_reason),
    cancelledAt: optionalString(row.cancelled_at),
    cancelledBy: optionalString(row.cancelled_by),
    createdAt: stringValue(row.created_at),
    decisions: parseOptionalApprovalDecisions(row.decisions_json),
    editedInput: parseOptionalJsonObject(row.edited_input_json),
    expiredAt: optionalString(row.expired_at),
    finalizedAt: optionalString(row.finalized_at),
    approvedEnvelopeHash: optionalString(row.approved_envelope_hash),
    approvedInputHash: optionalString(row.approved_input_hash),
    id: stringValue(row.id),
    note: optionalString(row.note),
    originalInput: parseJsonObject(row.original_input_json),
    originalEnvelopeHash: optionalString(row.original_envelope_hash),
    originalInputHash: optionalString(row.original_input_hash),
    rejectedBy: optionalString(row.rejected_by),
    rejectionReason: optionalString(row.rejection_reason),
    requestedByAuth: parseOptionalAuthContext(row.requested_by_auth_json),
    requestedBy: stringValue(row.requested_by),
    requiredApprovals: optionalNumber(row.required_approvals),
    separationOfDuties: optionalBoolean(row.separation_of_duties),
    reviewHash: optionalString(row.review_hash),
    status: stringValue(row.status) as ApprovalRecord['status'],
    toolCallId: stringValue(row.tool_call_id),
    updatedAt: stringValue(row.updated_at),
    workspaceId: optionalString(row.workspace_id) ?? 'default',
  };
}

function approvalDeliveryFromRow(row: PgRow): ApprovalDeliveryRecord {
  return {
    approvalId: stringValue(row.approval_id),
    channelId: stringValue(row.channel_id),
    createdAt: stringValue(row.created_at),
    data: parseJsonObject(row.data_json),
    destination: optionalString(row.destination),
    error: optionalString(row.error),
    id: stringValue(row.id),
    messageId: optionalString(row.message_id),
    provider: stringValue(row.provider) as ApprovalDeliveryRecord['provider'],
    recipientEmail: optionalString(row.recipient_email),
    recipientSlackUserId: optionalString(row.recipient_slack_user_id),
    recipientTelegramChatId: optionalString(row.recipient_telegram_chat_id),
    recipientTelegramUserId: optionalString(row.recipient_telegram_user_id),
    recipientUserId: optionalString(row.recipient_user_id),
    status: stringValue(row.status) as ApprovalDeliveryRecord['status'],
    toolCallId: stringValue(row.tool_call_id),
    updatedAt: stringValue(row.updated_at),
    workspaceId: optionalString(row.workspace_id) ?? 'default',
  };
}

function approverUserFromRow(row: PgRow): ApproverUserRecord {
  return {
    createdAt: stringValue(row.created_at),
    defaultApprover: optionalBoolean(row.default_approver) ?? false,
    displayName: stringValue(row.display_name),
    email: optionalString(row.email),
    enabled: optionalBoolean(row.enabled) ?? false,
    groups: parseStringArray(row.groups_json),
    id: stringValue(row.id),
    principalId: optionalString(row.principal_id),
    slackUserId: optionalString(row.slack_user_id),
    telegramChatId: optionalString(row.telegram_chat_id),
    telegramUsername: optionalString(row.telegram_username),
    telegramUserId: optionalString(row.telegram_user_id),
    updatedAt: stringValue(row.updated_at),
    workspaceId: stringValue(row.workspace_id),
  };
}

function approverGroupFromRow(row: PgRow): ApproverGroupRecord {
  return {
    createdAt: stringValue(row.created_at),
    description: optionalString(row.description),
    displayName: stringValue(row.display_name),
    enabled: optionalBoolean(row.enabled) ?? false,
    id: stringValue(row.id),
    updatedAt: stringValue(row.updated_at),
    workspaceId: stringValue(row.workspace_id),
  };
}

function auditEventFromRow(row: PgRow): AuditEvent {
  return {
    actor: optionalString(row.actor),
    approvalId: optionalString(row.approval_id),
    auth: parseOptionalAuthContext(row.auth_json),
    data: parseJsonObject(row.data_json),
    eventHash: optionalString(row.event_hash),
    id: stringValue(row.id),
    inputHash: optionalString(row.input_hash),
    policyVersionHash: optionalString(row.policy_version_hash),
    policyVersionId: optionalString(row.policy_version_id),
    previousEventHash: optionalString(row.previous_event_hash),
    timestamp: stringValue(row.timestamp),
    toolCallId: optionalString(row.tool_call_id),
    type: stringValue(row.type) as AuditEvent['type'],
    workspaceId: optionalString(row.workspace_id),
  };
}

function workspaceFromRow(row: PgRow): WorkspaceRecord {
  return {
    createdAt: stringValue(row.created_at),
    id: stringValue(row.id),
    name: stringValue(row.name),
  };
}

function workspaceUserFromRow(row: PgRow): WorkspaceUserRecord {
  return {
    createdAt: stringValue(row.created_at),
    displayName: stringValue(row.display_name),
    email: optionalString(row.email),
    id: stringValue(row.id),
    principalId: stringValue(row.principal_id),
    updatedAt: stringValue(row.updated_at),
    workspaceId: stringValue(row.workspace_id),
  };
}

function serviceAccountFromRow(row: PgRow): ServiceAccountRecord {
  return {
    createdAt: stringValue(row.created_at),
    description: optionalString(row.description),
    groups: parseStringArray(row.groups_json),
    id: stringValue(row.id),
    name: stringValue(row.name),
    revokedAt: optionalString(row.revoked_at),
    scopes: parseStringArray(row.scopes_json),
    updatedAt: stringValue(row.updated_at),
    workspaceId: stringValue(row.workspace_id),
  };
}

function apiKeyFromRow(row: PgRow): ApiKeyRecord {
  return {
    createdAt: stringValue(row.created_at),
    id: stringValue(row.id),
    keyHash: stringValue(row.key_hash),
    keyPrefix: stringValue(row.key_prefix),
    lastUsedAt: optionalString(row.last_used_at),
    revokedAt: optionalString(row.revoked_at),
    scopes: parseStringArray(row.scopes_json),
    serviceAccountId: stringValue(row.service_account_id),
    workspaceId: stringValue(row.workspace_id),
  };
}

function executionGrantFromRow(row: PgRow): ExecutionGrantRecord {
  return {
    actor: stringValue(row.actor),
    approvedEnvelopeHash: optionalString(row.approved_envelope_hash),
    approvedInputHash: optionalString(row.approved_input_hash),
    auth: parseOptionalAuthContext(row.auth_json),
    consumedAt: optionalString(row.consumed_at),
    createdAt: stringValue(row.created_at),
    expiresAt: stringValue(row.expires_at),
    id: stringValue(row.id),
    inputHash: stringValue(row.input_hash),
    nonce: stringValue(row.nonce),
    policyVersionHash: optionalString(row.policy_version_hash),
    receiptHash: optionalString(row.receipt_hash),
    receiptId: optionalString(row.receipt_id),
    signature: stringValue(row.signature),
    toolCallId: stringValue(row.tool_call_id),
    toolName: stringValue(row.tool_name),
    workspaceId: stringValue(row.workspace_id),
  };
}

function actionReceiptFromRow(row: PgRow): ActionReceiptRecord {
  return {
    approvalId: optionalString(row.approval_id),
    approvedEnvelopeHash: stringValue(row.approved_envelope_hash),
    approvedInputHash: stringValue(row.approved_input_hash),
    createdAt: stringValue(row.created_at),
    decisionActor: stringValue(row.decision_actor),
    decisionAuth: parseOptionalAuthContext(row.decision_auth_json),
    decisionKind: stringValue(row.decision_kind) as ActionReceiptRecord['decisionKind'],
    executionMode: stringValue(row.execution_mode) as ActionReceiptRecord['executionMode'],
    expiresAt: optionalString(row.expires_at),
    id: stringValue(row.id),
    issuedAt: stringValue(row.issued_at),
    keyId: stringValue(row.key_id),
    operation: parseJsonObject(row.operation_json) as ActionReceiptRecord['operation'],
    originalEnvelopeHash: stringValue(row.original_envelope_hash),
    originalInputHash: stringValue(row.original_input_hash),
    outcome: parseOptionalJsonObject(row.outcome_json) as ActionReceiptRecord['outcome'],
    policyDecision: optionalString(row.policy_decision) as ActionReceiptRecord['policyDecision'],
    policyReason: optionalString(row.policy_reason),
    policyRisk: optionalString(row.policy_risk),
    policyVersionHash: optionalString(row.policy_version_hash),
    policyVersionId: optionalString(row.policy_version_id),
    protocol: stringValue(row.protocol) as ActionReceiptRecord['protocol'],
    receiptHash: stringValue(row.receipt_hash),
    reviewHash: optionalString(row.review_hash),
    signature: stringValue(row.signature),
    signatureAlg: stringValue(row.signature_alg) as ActionReceiptRecord['signatureAlg'],
    source: parseJsonObject(row.source_json) as ActionReceiptRecord['source'],
    toolCallId: stringValue(row.tool_call_id),
    toolName: stringValue(row.tool_name),
    version: 'actionproxy.receipt.v1',
    workspaceId: stringValue(row.workspace_id),
  };
}

function idempotencyFromRow(row: PgRow): IdempotencyRecord {
  return {
    createdAt: stringValue(row.created_at),
    key: stringValue(row.key),
    requestHash: stringValue(row.request_hash),
    route: stringValue(row.route),
    toolCallId: stringValue(row.tool_call_id),
    workspaceId: stringValue(row.workspace_id),
  };
}

function observedToolFromRow(row: PgRow): ObservedToolRecord {
  return {
    callCount: optionalNumber(row.call_count) ?? 0,
    coverage: parseJsonObject(row.coverage_json) as unknown as ObservedToolRecord['coverage'],
    createdAt: stringValue(row.created_at),
    firstSeenAt: stringValue(row.first_seen_at),
    id: stringValue(row.id),
    lastSeenAt: stringValue(row.last_seen_at),
    schemaHash: optionalString(row.schema_hash),
    sourceIds: parseJsonObject(row.source_ids_json) as ObservedToolRecord['sourceIds'],
    sources: parseStringArray(row.sources_json) as ObservedToolRecord['sources'],
    status: stringValue(row.status) as ObservedToolRecord['status'],
    suggestion: parseJsonObject(row.suggestion_json) as unknown as ObservedToolRecord['suggestion'],
    toolName: stringValue(row.tool_name),
    updatedAt: stringValue(row.updated_at),
    workspaceId: stringValue(row.workspace_id),
  };
}

function pgParam(values: unknown[], value: unknown): string {
  values.push(value);
  return `$${values.length}`;
}

function authorizationGuardIsSelfConsistent(guard: ApprovalAuthorizationGuard): boolean {
  try {
    return (
      authorizationIdentityIsUsable(guard.authorization) &&
      guard.activePolicyVersionHash === guard.authorization.binding.policy.legacyVersionHash &&
      hashJson(guard.originalInput) === guard.authorization.binding.action.originalInputHash
    );
  } catch {
    return false;
  }
}

function authorizationIdentityIsUsable(authorization: ApprovalAuthorizationV1): boolean {
  try {
    return (
      isValidApprovalAuthorization(authorization) &&
      typeof authorization.binding.action.originalEnvelopeHash === 'string' &&
      typeof authorization.binding.action.originalInputHash === 'string' &&
      typeof authorization.binding.action.reviewHash === 'string' &&
      typeof authorization.binding.approval.approvalId === 'string' &&
      typeof authorization.binding.approval.tenantId === 'string' &&
      typeof authorization.binding.approval.toolCallId === 'string' &&
      typeof authorization.binding.policy.legacyVersionHash === 'string' &&
      Array.isArray(authorization.binding.requirements.eligibleGroups) &&
      Number.isInteger(authorization.binding.requirements.requiredApprovals)
    );
  } catch {
    return false;
  }
}

function decisionInputIsSelfConsistent(input: AtomicApprovalDecisionInput): boolean {
  if (!authorizationGuardIsSelfConsistent(input.authorization)) return false;
  const authorization = input.authorization.authorization;
  const decision = input.decision;
  if (authorization.binding.requirements.requiredApprovals > 1) {
    if (input.editedInput !== undefined || decision.editedInput !== undefined || decision.inputDecision !== 'original') {
      return false;
    }
  }
  return (
    decision.authorizationVersion === authorization.version &&
    decision.authorizationHash === authorization.authorizationHash &&
    decision.authorizationNonce === authorization.nonce &&
    (decision.decisionId ?? null) === authorization.binding.decision.decisionId &&
    decision.reviewHash === authorization.binding.action.reviewHash &&
    input.reviewHash === authorization.binding.action.reviewHash &&
    decision.approvedInputHash === input.approvedInputHash &&
    decision.approvedEnvelopeHash === input.approvedEnvelopeHash
  );
}

function sameAuthorization(
  stored: ApprovalAuthorizationV1 | undefined,
  supplied: ApprovalAuthorizationV1,
): stored is ApprovalAuthorizationV1 {
  try {
    return (
      stored !== undefined &&
      authorizationIdentityIsUsable(stored) &&
      authorizationIdentityIsUsable(supplied) &&
      stored.authorizationHash === supplied.authorizationHash &&
      stored.nonce === supplied.nonce &&
      JSON.stringify(stored) === JSON.stringify(supplied)
    );
  } catch {
    return false;
  }
}

function postgresAuthorizationGuardClause(guard: ApprovalAuthorizationGuard, values: unknown[]): string {
  const authorization = guard.authorization;
  const binding = authorization.binding;
  const authorizationJson = pgParam(values, JSON.stringify(authorization));
  const tenantId = pgParam(values, binding.approval.tenantId);
  const toolCallId = pgParam(values, binding.approval.toolCallId);
  const requestedBy = pgParam(values, binding.approval.requestedBy);
  const requestedPrincipal = pgParam(values, binding.approval.requestedByPrincipalId);
  const originalInput = pgParam(values, JSON.stringify(guard.originalInput));
  const originalInputHash = pgParam(values, binding.action.originalInputHash);
  const originalEnvelopeHash = pgParam(values, binding.action.originalEnvelopeHash);
  const reviewHash = pgParam(values, binding.action.reviewHash);
  const requiredApprovals = pgParam(values, Math.max(1, binding.requirements.requiredApprovals));
  const separationOfDuties = pgParam(values, binding.requirements.separationOfDuties ? 1 : 0);
  const eligibleGroups = pgParam(values, JSON.stringify(binding.requirements.eligibleGroups));
  const eligibleUsers = pgParam(
    values,
    binding.requirements.eligibleUsers === null ? null : JSON.stringify(binding.requirements.eligibleUsers),
  );
  const outcome = pgParam(values, binding.decision.outcome);
  const activePolicy = pgParam(values, guard.activePolicyVersionHash);
  const legacyPolicy = pgParam(values, binding.policy.legacyVersionHash);
  const legacyPolicyId = pgParam(values, binding.policy.legacyVersionId);
  const requestHash = pgParam(values, binding.request.requestHash);
  const requestVersion = pgParam(values, binding.request.version);
  const decisionInputHash = pgParam(values, binding.request.decisionInputHash);
  const decisionVersion = pgParam(values, binding.decision.version);
  const decisionId = pgParam(values, binding.decision.decisionId);
  const policyDigest = pgParam(values, binding.policy.digest);
  const policyVersion = pgParam(values, binding.policy.version);
  const providerId = pgParam(values, binding.policy.providerId);
  const providerVersion = pgParam(values, binding.policy.providerVersion);
  const evaluatorVersion = pgParam(values, binding.policy.evaluatorVersion);
  return `
    authorization_json = ${authorizationJson}
    AND authorization_consumed_at IS NULL
    AND workspace_id = ${tenantId}
    AND tool_call_id = ${toolCallId}
    AND requested_by = ${requestedBy}
    AND (NULLIF(requested_by_auth_json, '')::jsonb ->> 'principalId') IS NOT DISTINCT FROM ${requestedPrincipal}::text
    AND original_input_json = ${originalInput}
    AND original_input_hash = ${originalInputHash}
    AND original_envelope_hash = ${originalEnvelopeHash}
    AND review_hash = ${reviewHash}
    AND GREATEST(1, COALESCE(required_approvals, 1)) = ${requiredApprovals}::integer
    AND COALESCE(separation_of_duties, 0) = ${separationOfDuties}::integer
    AND COALESCE((
      SELECT jsonb_agg(value ORDER BY value)
      FROM (
        SELECT DISTINCT value
        FROM jsonb_array_elements_text(COALESCE(NULLIF(approver_groups_json, ''), '[]')::jsonb) AS value
      ) AS normalized_groups
    ), '[]'::jsonb) = ${eligibleGroups}::jsonb
    AND (
      (${eligibleUsers}::text IS NULL AND approver_users_json IS NULL)
      OR (
        ${eligibleUsers}::text IS NOT NULL
        AND COALESCE((
          SELECT jsonb_agg(value ORDER BY value)
          FROM (
            SELECT DISTINCT value
            FROM jsonb_array_elements_text(COALESCE(NULLIF(approver_users_json, ''), '[]')::jsonb) AS value
          ) AS normalized_users
        ), '[]'::jsonb) = ${eligibleUsers}::jsonb
      )
    )
    AND EXISTS (
      SELECT 1
      FROM tool_calls AS tc
      WHERE tc.id = approvals.tool_call_id
        AND tc.id = ${toolCallId}
        AND tc.workspace_id = ${tenantId}
        AND tc.status = 'pending_approval'
        AND tc.decision = ${outcome}
        AND tc.input_hash = ${originalInputHash}
        AND tc.action_envelope_hash = ${originalEnvelopeHash}
        AND tc.policy_version_hash = ${activePolicy}
        AND tc.policy_version_hash = ${legacyPolicy}
        AND tc.policy_version_id IS NOT DISTINCT FROM ${legacyPolicyId}::text
        AND tc.canonical_action_request_hash IS NOT DISTINCT FROM ${requestHash}::text
        AND tc.canonical_action_request_version IS NOT DISTINCT FROM ${requestVersion}::text
        AND COALESCE(
          tc.canonical_decision_input_hash,
          NULLIF(tc.decision_trace_json, '')::jsonb #>> '{decisionV1,decisionInputHash}'
        ) IS NOT DISTINCT FROM ${decisionInputHash}::text
        AND (NULLIF(tc.decision_trace_json, '')::jsonb #>> '{decisionV1,version}')
          IS NOT DISTINCT FROM ${decisionVersion}::text
        AND (NULLIF(tc.decision_trace_json, '')::jsonb #>> '{decisionV1,decisionId}')
          IS NOT DISTINCT FROM ${decisionId}::text
        AND (NULLIF(tc.decision_trace_json, '')::jsonb #>> '{decisionV1,policy,digest}')
          IS NOT DISTINCT FROM ${policyDigest}::text
        AND (NULLIF(tc.decision_trace_json, '')::jsonb #>> '{decisionV1,policy,version}')
          IS NOT DISTINCT FROM ${policyVersion}::text
        AND (NULLIF(tc.decision_trace_json, '')::jsonb #>> '{decisionV1,policy,provider,id}')
          IS NOT DISTINCT FROM ${providerId}::text
        AND (NULLIF(tc.decision_trace_json, '')::jsonb #>> '{decisionV1,policy,provider,version}')
          IS NOT DISTINCT FROM ${providerVersion}::text
        AND (NULLIF(tc.decision_trace_json, '')::jsonb #>> '{decisionV1,evaluatorVersion}')
          IS NOT DISTINCT FROM ${evaluatorVersion}::text
    )
  `;
}

function postgresOptionalAuthorizationGuardClause(
  guard: ApprovalAuthorizationGuard | undefined,
  values: unknown[],
): string {
  return guard ? postgresAuthorizationGuardClause(guard, values) : 'authorization_json IS NULL';
}

function postgresOptionalAuthorizationNotExpiredClause(
  guard: ApprovalAuthorizationGuard | undefined,
  values: unknown[],
): string {
  if (!guard) return 'TRUE';
  const expiresAt = pgParam(values, guard.authorization.expiresAt);
  return `${expiresAt}::timestamptz > CURRENT_TIMESTAMP`;
}

function postgresDecisionHistoryBindingClause(input: AtomicApprovalDecisionInput, values: unknown[]): string {
  const authorization = input.authorization.authorization;
  const version = pgParam(values, authorization.version);
  const authorizationHash = pgParam(values, authorization.authorizationHash);
  const nonce = pgParam(values, authorization.nonce);
  const decisionId = pgParam(values, authorization.binding.decision.decisionId);
  const reviewHash = pgParam(values, authorization.binding.action.reviewHash);
  const approvedInputHash = pgParam(values, input.approvedInputHash);
  const approvedEnvelopeHash = pgParam(values, input.approvedEnvelopeHash);
  return `NOT EXISTS (
    SELECT 1
    FROM jsonb_array_elements(COALESCE(NULLIF(decisions_json, ''), '[]')::jsonb) AS prior(decision)
    WHERE (prior.decision ->> 'authorizationVersion') IS DISTINCT FROM ${version}::text
       OR (prior.decision ->> 'authorizationHash') IS DISTINCT FROM ${authorizationHash}::text
       OR (prior.decision ->> 'authorizationNonce') IS DISTINCT FROM ${nonce}::text
       OR (prior.decision ->> 'decisionId') IS DISTINCT FROM ${decisionId}::text
       OR (prior.decision ->> 'reviewHash') IS DISTINCT FROM ${reviewHash}::text
       OR (prior.decision ->> 'approvedInputHash') IS DISTINCT FROM ${approvedInputHash}::text
       OR (prior.decision ->> 'approvedEnvelopeHash') IS DISTINCT FROM ${approvedEnvelopeHash}::text
  )`;
}

function hasApprovalDecision(
  decisions: ApprovalDecisionRecord[] | undefined,
  candidate: ApprovalDecisionRecord,
): boolean {
  return (decisions ?? []).some(
    (decision) =>
      decision.actor === candidate.actor ||
      (candidate.auth?.principalId !== undefined && decision.auth?.principalId === candidate.auth.principalId),
  );
}

function parseJsonObject(value: unknown): JsonObject {
  const parsed = parseOptionalJson(value);
  return isJsonObject(parsed) ? parsed : {};
}

function parseOptionalJsonObject(value: unknown): JsonObject | undefined {
  const parsed = parseOptionalJson(value);
  return isJsonObject(parsed) ? parsed : undefined;
}

function parseStringArray(value: unknown): string[] {
  const parsed = parseOptionalJson(value);
  return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
}

function parseJsonArray(value: unknown): unknown[] {
  const parsed = parseOptionalJson(value);
  return Array.isArray(parsed) ? parsed : [];
}

function parseOptionalStringArray(value: unknown): string[] | undefined {
  const parsed = parseOptionalJson(value);
  return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : undefined;
}

function parseOptionalAuthContext(value: unknown): AuthContext | undefined {
  const parsed = parseOptionalJson(value);
  return isJsonObject(parsed) ? (parsed as unknown as AuthContext) : undefined;
}

function parseOptionalApprovalDecisions(value: unknown): ApprovalDecisionRecord[] | undefined {
  const parsed = parseOptionalJson(value);
  return Array.isArray(parsed) ? (parsed as ApprovalDecisionRecord[]) : undefined;
}

function parseOptionalJson(value: unknown): unknown {
  const raw = optionalString(value);
  if (raw === undefined) return undefined;
  return JSON.parse(raw) as unknown;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string {
  return String(value ?? '');
}

function optionalString(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  const stringified = String(value);
  return stringified.length > 0 ? stringified : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  if (value === null || value === undefined || value === '') return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function optionalBoolean(value: unknown): boolean | undefined {
  if (value === null || value === undefined || value === '') return undefined;
  return value === true || value === 1 || value === '1' || value === 'true';
}

function contentExposureLimit(limit: number): number {
  return Number.isFinite(limit) ? Math.min(1000, Math.max(1, Math.trunc(limit))) : 100;
}
