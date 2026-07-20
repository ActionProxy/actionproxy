import path from 'node:path';
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
  isValidApprovalAuthorization,
  type ApprovalAuthorizationV1,
} from '../contracts/approval-authorization';
import { validContentInfluenceBindingHash } from '../contracts/content-influence';
import { hashJson } from '../security/crypto';
import type { PolicyVersionRecord, PolicyVersionStore } from './migrate';
import { runSqlite, runSqliteMigrations, sqlJsonLiteral, sqlLiteral } from './migrate';

type SqliteRow = Record<string, unknown>;

export class SqliteStore implements Store, AuditStore, PolicyVersionStore {
  readonly databasePath: string;

  constructor(databasePath: string) {
    this.databasePath = path.resolve(databasePath);
    runSqliteMigrations(this.databasePath);
  }

  async createToolCall(record: ToolCallRecord): Promise<ToolCallRecord> {
    await this.writeToolCall(record);
    return record;
  }

  async createToolCallIdempotentlyAtomically(
    input: AtomicIdempotentToolCallInput,
  ): Promise<AtomicIdempotentToolCallResult> {
    assertIdempotencyCandidate(input);
    const marker = this.query(`CREATE TEMP TABLE actionproxy_idempotency_result (created INTEGER NOT NULL);
      BEGIN IMMEDIATE;
      INSERT OR IGNORE INTO idempotency_records (workspace_id, route, key, request_hash, tool_call_id, created_at)
      VALUES (
        ${sqlLiteral(input.idempotency.workspaceId)},
        ${sqlLiteral(input.idempotency.route)},
        ${sqlLiteral(input.idempotency.key)},
        ${sqlLiteral(input.idempotency.requestHash)},
        ${sqlLiteral(input.idempotency.toolCallId)},
        ${sqlLiteral(input.idempotency.createdAt)}
      );
      INSERT INTO actionproxy_idempotency_result (created) VALUES (changes());
      ${toolCallInsertSql(input.toolCall, {
        conflict: 'none',
        condition: '(SELECT created FROM actionproxy_idempotency_result LIMIT 1) = 1',
      })}
      COMMIT;
      SELECT created FROM actionproxy_idempotency_result LIMIT 1;
    `)[0];
    const idempotency = await this.getIdempotencyRecord(
      input.idempotency.workspaceId,
      input.idempotency.route,
      input.idempotency.key,
    );
    if (!idempotency) throw new Error('Atomic idempotency reservation did not persist.');
    const toolCall = await this.getToolCall(idempotency.toolCallId);
    if (!toolCall) throw new Error(`Idempotency record references missing tool call: ${idempotency.toolCallId}`);
    return {
      idempotency,
      outcome:
        Number(marker?.created ?? 0) === 1
          ? 'created'
          : idempotency.requestHash === input.idempotency.requestHash
            ? 'replay'
            : 'conflict',
      toolCall,
    };
  }

  async updateToolCall(record: ToolCallRecord): Promise<ToolCallRecord> {
    await this.writeToolCall(record);
    return record;
  }

  async getToolCall(id: string): Promise<ToolCallRecord | undefined> {
    const rows = this.query(`SELECT * FROM tool_calls WHERE id = ${sqlLiteral(id)} LIMIT 1;`);
    const row = rows[0];
    return row ? toolCallFromRow(row) : undefined;
  }

  async listToolCalls(filters: ListToolCallsFilters = {}): Promise<ToolCallRecord[]> {
    const where = [
      filters.workspaceId ? `workspace_id = ${sqlLiteral(filters.workspaceId)}` : undefined,
      filters.sessionId
        ? `CASE
            WHEN decision_trace_json IS NULL OR decision_trace_json = '' OR json_valid(decision_trace_json) = 0
              THEN json_extract(metadata_json, '$.sessionId')
            WHEN json_type(decision_trace_json, '$.canonicalRequestEvidence.session.value.sessionId') = 'text'
              THEN json_extract(decision_trace_json, '$.canonicalRequestEvidence.session.value.sessionId')
            WHEN json_type(decision_trace_json, '$.canonicalRequestEvidence.session.value.sessionId') IS NOT NULL
              THEN NULL
            ELSE json_extract(metadata_json, '$.sessionId')
          END = ${sqlLiteral(filters.sessionId)}`
        : undefined,
      filters.runId
        ? `CASE
            WHEN decision_trace_json IS NULL OR decision_trace_json = '' OR json_valid(decision_trace_json) = 0
              THEN json_extract(metadata_json, '$.runId')
            WHEN json_type(decision_trace_json, '$.canonicalRequestEvidence.session.value.runId') = 'text'
              THEN json_extract(decision_trace_json, '$.canonicalRequestEvidence.session.value.runId')
            WHEN json_type(decision_trace_json, '$.canonicalRequestEvidence.session.value.runId') IS NOT NULL
              THEN NULL
            ELSE json_extract(metadata_json, '$.runId')
          END = ${sqlLiteral(filters.runId)}`
        : undefined,
      filters.status ? `status = ${sqlLiteral(filters.status)}` : undefined,
      filters.decision ? `decision = ${sqlLiteral(filters.decision)}` : undefined,
      filters.toolName ? `tool_name = ${sqlLiteral(filters.toolName)}` : undefined,
    ].filter(Boolean);
    const limit = filters.limit ?? 100;
    const sql = `
      SELECT * FROM tool_calls
      ${where.length > 0 ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY created_at DESC
      LIMIT ${Number.isFinite(limit) ? Math.max(1, Math.trunc(limit)) : 100};
    `;
    return this.query(sql).map(toolCallFromRow);
  }

  async recordContentExposure(record: ContentExposureRecord): Promise<'conflict' | 'created' | 'replay'> {
    const row = this.query(`CREATE TEMP TABLE actionproxy_content_exposure_result (outcome TEXT NOT NULL);
      BEGIN IMMEDIATE;
      INSERT OR IGNORE INTO content_exposure_scopes (workspace_id, influence_scope_id, revision)
      VALUES (${sqlLiteral(record.workspaceId)}, ${sqlLiteral(record.influenceScopeId)}, 0);
      INSERT INTO actionproxy_content_exposure_result (outcome)
      SELECT CASE
        WHEN EXISTS (
          SELECT 1 FROM content_exposures
          WHERE workspace_id = ${sqlLiteral(record.workspaceId)}
            AND influence_scope_id = ${sqlLiteral(record.influenceScopeId)}
            AND source_tool_call_id = ${sqlLiteral(record.sourceToolCallId)}
            AND integrity = ${sqlLiteral(record.integrity)}
            AND source_id IS ${sqlLiteral(record.sourceId)}
            AND policy_version_hash = ${sqlLiteral(record.policyVersionHash)}
        ) THEN 'replay'
        WHEN EXISTS (
          SELECT 1 FROM content_exposures
          WHERE workspace_id = ${sqlLiteral(record.workspaceId)}
            AND influence_scope_id = ${sqlLiteral(record.influenceScopeId)}
            AND source_tool_call_id = ${sqlLiteral(record.sourceToolCallId)}
        ) THEN 'conflict'
        ELSE 'created'
      END;
      INSERT INTO content_exposures (
        workspace_id, influence_scope_id, source_tool_call_id, integrity,
        source_id, policy_version_hash, observed_at
      )
      SELECT
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.influenceScopeId)},
        ${sqlLiteral(record.sourceToolCallId)},
        ${sqlLiteral(record.integrity)},
        ${sqlLiteral(record.sourceId)},
        ${sqlLiteral(record.policyVersionHash)},
        ${sqlLiteral(record.observedAt)}
      WHERE (SELECT outcome FROM actionproxy_content_exposure_result LIMIT 1) = 'created';
      UPDATE content_exposure_scopes
      SET revision = revision + 1
      WHERE workspace_id = ${sqlLiteral(record.workspaceId)}
        AND influence_scope_id = ${sqlLiteral(record.influenceScopeId)}
        AND (SELECT outcome FROM actionproxy_content_exposure_result LIMIT 1) = 'created';
      COMMIT;
      SELECT outcome FROM actionproxy_content_exposure_result LIMIT 1;
    `)[0];
    return String(row?.outcome ?? 'conflict') as 'conflict' | 'created' | 'replay';
  }

  async listContentExposures(input: ListContentExposuresInput): Promise<ListContentExposuresResult> {
    const limit = contentExposureLimit(input.limit);
    const rows = this.query(`
      WITH scope_revision AS (
        SELECT revision
        FROM content_exposure_scopes
        WHERE workspace_id = ${sqlLiteral(input.workspaceId)}
          AND influence_scope_id = ${sqlLiteral(input.influenceScopeId)}
        UNION ALL
        SELECT 0
        WHERE NOT EXISTS (
          SELECT 1 FROM content_exposure_scopes
          WHERE workspace_id = ${sqlLiteral(input.workspaceId)}
            AND influence_scope_id = ${sqlLiteral(input.influenceScopeId)}
        )
      ), bounded AS (
        SELECT * FROM content_exposures
        WHERE workspace_id = ${sqlLiteral(input.workspaceId)}
          AND influence_scope_id = ${sqlLiteral(input.influenceScopeId)}
        ORDER BY observed_at ASC, source_tool_call_id ASC
        LIMIT ${limit + 1}
      )
      SELECT bounded.*, scope_revision.revision AS scope_revision
      FROM scope_revision LEFT JOIN bounded ON 1 = 1
      ORDER BY bounded.observed_at ASC, bounded.source_tool_call_id ASC;
    `);
    const exposureRows = rows.filter((row) => typeof row.source_tool_call_id === 'string');
    return {
      overflow: exposureRows.length > limit,
      records: exposureRows.slice(0, limit).map(contentExposureFromRow),
      revision: Number(rows[0]?.scope_revision ?? 0),
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
    const rows = this.query(`SELECT * FROM approvals WHERE id = ${sqlLiteral(id)} LIMIT 1;`);
    const row = rows[0];
    return row ? approvalFromRow(row) : undefined;
  }

  async getApprovalByToolCallId(toolCallId: string): Promise<ApprovalRecord | undefined> {
    const rows = this.query(`SELECT * FROM approvals WHERE tool_call_id = ${sqlLiteral(toolCallId)} LIMIT 1;`);
    const row = rows[0];
    return row ? approvalFromRow(row) : undefined;
  }

  async listPendingApprovals(): Promise<ApprovalRecord[]> {
    return this.query("SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_at ASC;").map(approvalFromRow);
  }

  async recordApprovalDecisionAtomically(input: AtomicApprovalDecisionInput): Promise<AtomicApprovalDecisionResult> {
    if (!decisionInputIsSelfConsistent(input)) return { outcome: 'authorization_mismatch' };
    const authorization = input.authorization.authorization;
    const principalId = input.decision.auth?.principalId;
    const priorCount = `json_array_length(COALESCE(NULLIF(decisions_json, ''), '[]'))`;
    const finalized = `${priorCount} + 1 >= MAX(1, COALESCE(required_approvals, 1))`;
    const rows = this.query(`
      UPDATE approvals
      SET decisions_json = json_insert(
            COALESCE(NULLIF(decisions_json, ''), '[]'),
            '$[#]',
            json(${sqlJsonLiteral(input.decision)})
          ),
          status = CASE WHEN ${finalized} THEN 'approved' ELSE 'pending' END,
          approved_by = CASE WHEN ${finalized} THEN ${sqlLiteral(input.decision.actor)} ELSE approved_by END,
          edited_input_json = COALESCE(
            ${input.editedInput === undefined ? 'NULL' : sqlJsonLiteral(input.editedInput)},
            edited_input_json
          ),
          approved_input_hash = CASE
            WHEN ${finalized} THEN ${sqlLiteral(input.approvedInputHash)} ELSE approved_input_hash
          END,
          approved_envelope_hash = CASE
            WHEN ${finalized} THEN ${sqlLiteral(input.approvedEnvelopeHash)} ELSE approved_envelope_hash
          END,
          note = ${sqlLiteral(input.note)},
          review_hash = ${sqlLiteral(input.reviewHash)},
          authorization_consumed_at = CASE
            WHEN ${finalized} THEN ${sqlLiteral(input.updatedAt)} ELSE authorization_consumed_at
          END,
          authorization_consumed_reason = CASE
            WHEN ${finalized} THEN 'approved' ELSE authorization_consumed_reason
          END,
          finalized_at = CASE WHEN ${finalized} THEN ${sqlLiteral(input.updatedAt)} ELSE finalized_at END,
          updated_at = ${sqlLiteral(input.updatedAt)}
      WHERE id = ${sqlLiteral(input.approvalId)}
        AND status = 'pending'
        ${input.contentExposureRevision ? `AND COALESCE((
          SELECT revision FROM content_exposure_scopes
          WHERE workspace_id = approvals.workspace_id
            AND influence_scope_id = ${sqlLiteral(input.contentExposureRevision.influenceScopeId)}
        ), 0) = ${input.contentExposureRevision.revision}` : ''}
        AND ${sqliteAuthorizationGuardClause(input.authorization)}
        AND ${sqliteAuthorizationNotExpiredClause()}
        AND ${sqliteDecisionHistoryBindingClause(input)}
        AND NOT EXISTS (
          SELECT 1
          FROM json_each(COALESCE(NULLIF(decisions_json, ''), '[]')) AS prior
          WHERE json_extract(prior.value, '$.actor') = ${sqlLiteral(input.decision.actor)}
             OR (
               ${sqlLiteral(principalId)} IS NOT NULL
               AND json_extract(prior.value, '$.auth.principalId') = ${sqlLiteral(principalId)}
             )
        )
      RETURNING *;
    `);
    const updatedRow = rows[0];
    if (updatedRow) {
      const approval = approvalFromRow(updatedRow);
      return { approval, outcome: approval.status === 'approved' ? 'finalized' : 'recorded' };
    }

    const expiry = await this.expireApprovalAtomically({
      approvalId: input.approvalId,
      authorization,
      expiredAt: authorization.expiresAt,
    });
    if (expiry.outcome === 'expired') return expiry;
    const current = await this.getApproval(input.approvalId);
    if (!current) return { outcome: 'not_found' };
    if (current.authorizationConsumedAt && sameAuthorization(current.authorization, authorization)) {
      return { approval: current, outcome: 'replayed' };
    }
    if (current.status !== 'pending') return { approval: current, outcome: 'already_final' };
    if (input.contentExposureRevision) {
      const revision = this.query(`
        SELECT revision FROM content_exposure_scopes
        WHERE workspace_id = ${sqlLiteral(current.workspaceId)}
          AND influence_scope_id = ${sqlLiteral(input.contentExposureRevision.influenceScopeId)}
        LIMIT 1;
      `)[0];
      if (Number(revision?.revision ?? 0) !== input.contentExposureRevision.revision) {
        return { approval: current, outcome: 'content_influence_mismatch' };
      }
    }
    if (!sameAuthorization(current.authorization, authorization)) {
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
    const rows = this.query(`
      UPDATE approvals
      SET status = 'rejected',
          rejected_by = ${sqlLiteral(input.rejectedBy)},
          rejection_reason = ${sqlLiteral(input.reason)},
          authorization_consumed_at = CASE
            WHEN authorization_json IS NULL THEN NULL ELSE ${sqlLiteral(input.updatedAt)}
          END,
          authorization_consumed_reason = CASE
            WHEN authorization_json IS NULL THEN NULL ELSE 'rejected'
          END,
          finalized_at = ${sqlLiteral(input.updatedAt)},
          updated_at = ${sqlLiteral(input.updatedAt)}
      WHERE id = ${sqlLiteral(input.approvalId)}
        AND status = 'pending'
        AND ${sqliteOptionalAuthorizationGuardClause(input.authorization)}
        AND ${sqliteOptionalAuthorizationNotExpiredClause(input.authorization)}
      RETURNING *;
    `);
    if (rows[0]) return { approval: approvalFromRow(rows[0]), outcome: 'rejected' };
    return this.classifyTerminalTransitionFailure(input.approvalId, input.authorization);
  }

  async cancelApprovalAtomically(input: AtomicApprovalCancellationInput): Promise<AtomicApprovalCancellationResult> {
    if (input.authorization && !authorizationGuardIsSelfConsistent(input.authorization)) {
      return { outcome: 'authorization_mismatch' };
    }
    const rows = this.query(`
      UPDATE approvals
      SET status = 'cancelled',
          cancelled_at = ${sqlLiteral(input.updatedAt)},
          cancelled_by = ${sqlLiteral(input.cancelledBy)},
          cancellation_reason = ${sqlLiteral(input.reason)},
          authorization_consumed_at = CASE
            WHEN authorization_json IS NULL THEN NULL ELSE ${sqlLiteral(input.updatedAt)}
          END,
          authorization_consumed_reason = CASE
            WHEN authorization_json IS NULL THEN NULL ELSE 'cancelled'
          END,
          finalized_at = ${sqlLiteral(input.updatedAt)},
          updated_at = ${sqlLiteral(input.updatedAt)}
      WHERE id = ${sqlLiteral(input.approvalId)}
        AND status = 'pending'
        AND ${sqliteOptionalAuthorizationGuardClause(input.authorization)}
        AND ${sqliteOptionalAuthorizationNotExpiredClause(input.authorization)}
      RETURNING *;
    `);
    if (rows[0]) return { approval: approvalFromRow(rows[0]), outcome: 'cancelled' };
    return this.classifyTerminalTransitionFailure(input.approvalId, input.authorization);
  }

  async expireApprovalAtomically(input: AtomicApprovalExpiryInput): Promise<AtomicApprovalExpiryResult> {
    if (!authorizationIdentityIsUsable(input.authorization)) return { outcome: 'authorization_mismatch' };
    const rows = this.query(`
      UPDATE approvals
      SET status = 'expired',
          expired_at = ${sqlLiteral(input.expiredAt)},
          authorization_consumed_at = ${sqlLiteral(input.expiredAt)},
          authorization_consumed_reason = 'expired',
          finalized_at = ${sqlLiteral(input.expiredAt)},
          updated_at = ${sqlLiteral(input.expiredAt)}
      WHERE id = ${sqlLiteral(input.approvalId)}
        AND status = 'pending'
        AND authorization_consumed_at IS NULL
        AND authorization_json = ${sqlJsonLiteral(input.authorization)}
        AND json_valid(authorization_json)
        AND id = ${sqlLiteral(input.authorization.binding.approval.approvalId)}
        AND tool_call_id = ${sqlLiteral(input.authorization.binding.approval.toolCallId)}
        AND workspace_id = ${sqlLiteral(input.authorization.binding.approval.tenantId)}
        AND original_input_hash = ${sqlLiteral(input.authorization.binding.action.originalInputHash)}
        AND original_envelope_hash = ${sqlLiteral(input.authorization.binding.action.originalEnvelopeHash)}
        AND review_hash = ${sqlLiteral(input.authorization.binding.action.reviewHash)}
        AND julianday(json_extract(authorization_json, '$.expiresAt')) <= julianday('now')
      RETURNING *;
    `);
    if (rows[0]) return { approval: approvalFromRow(rows[0]), outcome: 'expired' };
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
    await this.writeApprovalDelivery(record);
    return record;
  }

  async updateApprovalDelivery(record: ApprovalDeliveryRecord): Promise<ApprovalDeliveryRecord> {
    await this.writeApprovalDelivery(record);
    return record;
  }

  async listApprovalDeliveries(approvalId: string): Promise<ApprovalDeliveryRecord[]> {
    return this.query(
      `SELECT * FROM approval_deliveries WHERE approval_id = ${sqlLiteral(approvalId)} ORDER BY created_at DESC;`,
    ).map(approvalDeliveryFromRow);
  }

  async upsertApproverUser(record: ApproverUserRecord): Promise<ApproverUserRecord> {
    this.exec(`
      INSERT OR REPLACE INTO approver_users (
        id, workspace_id, display_name, email, principal_id, slack_user_id, telegram_chat_id, telegram_username, telegram_user_id, groups_json,
        default_approver, enabled, created_at, updated_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.displayName)},
        ${sqlLiteral(record.email)},
        ${sqlLiteral(record.principalId)},
        ${sqlLiteral(record.slackUserId)},
        ${sqlLiteral(record.telegramChatId)},
        ${sqlLiteral(record.telegramUsername)},
        ${sqlLiteral(record.telegramUserId)},
        ${sqlJsonLiteral(record.groups)},
        ${record.defaultApprover ? 1 : 0},
        ${record.enabled ? 1 : 0},
        ${sqlLiteral(record.createdAt)},
        ${sqlLiteral(record.updatedAt)}
      );
    `);
    return record;
  }

  async getApproverUser(workspaceId: string, id: string): Promise<ApproverUserRecord | undefined> {
    const rows = this.query(`
      SELECT * FROM approver_users
      WHERE workspace_id = ${sqlLiteral(workspaceId)} AND id = ${sqlLiteral(id)}
      LIMIT 1;
    `);
    const row = rows[0];
    return row ? approverUserFromRow(row) : undefined;
  }

  async listApproverUsers(workspaceId: string): Promise<ApproverUserRecord[]> {
    return this.query(
      `SELECT * FROM approver_users WHERE workspace_id = ${sqlLiteral(workspaceId)} ORDER BY display_name ASC;`,
    ).map(approverUserFromRow);
  }

  async deleteApproverUser(workspaceId: string, id: string): Promise<boolean> {
    this.exec(`
      DELETE FROM approver_users
      WHERE workspace_id = ${sqlLiteral(workspaceId)} AND id = ${sqlLiteral(id)};
    `);
    return true;
  }

  async upsertApproverGroup(record: ApproverGroupRecord): Promise<ApproverGroupRecord> {
    this.exec(`
      INSERT OR REPLACE INTO approver_groups (
        id, workspace_id, display_name, description, enabled, created_at, updated_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.displayName)},
        ${sqlLiteral(record.description)},
        ${record.enabled ? 1 : 0},
        ${sqlLiteral(record.createdAt)},
        ${sqlLiteral(record.updatedAt)}
      );
    `);
    return record;
  }

  async getApproverGroup(workspaceId: string, id: string): Promise<ApproverGroupRecord | undefined> {
    const rows = this.query(`
      SELECT * FROM approver_groups
      WHERE workspace_id = ${sqlLiteral(workspaceId)} AND id = ${sqlLiteral(id)}
      LIMIT 1;
    `);
    const row = rows[0];
    return row ? approverGroupFromRow(row) : undefined;
  }

  async listApproverGroups(workspaceId: string): Promise<ApproverGroupRecord[]> {
    return this.query(
      `SELECT * FROM approver_groups WHERE workspace_id = ${sqlLiteral(workspaceId)} ORDER BY display_name ASC;`,
    ).map(approverGroupFromRow);
  }

  async deleteApproverGroup(workspaceId: string, id: string): Promise<boolean> {
    this.exec(`
      DELETE FROM approver_groups
      WHERE workspace_id = ${sqlLiteral(workspaceId)} AND id = ${sqlLiteral(id)};
    `);
    return true;
  }

  async createWorkspace(record: WorkspaceRecord): Promise<WorkspaceRecord> {
    this.exec(`
      INSERT OR REPLACE INTO workspaces (id, name, created_at)
      VALUES (${sqlLiteral(record.id)}, ${sqlLiteral(record.name)}, ${sqlLiteral(record.createdAt)});
    `);
    return record;
  }

  async getWorkspace(id: string): Promise<WorkspaceRecord | undefined> {
    const rows = this.query(`SELECT * FROM workspaces WHERE id = ${sqlLiteral(id)} LIMIT 1;`);
    const row = rows[0];
    return row ? workspaceFromRow(row) : undefined;
  }

  async upsertWorkspaceUser(record: WorkspaceUserRecord): Promise<WorkspaceUserRecord> {
    this.exec(`
      INSERT OR REPLACE INTO workspace_users (
        id, workspace_id, principal_id, display_name, email, created_at, updated_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.principalId)},
        ${sqlLiteral(record.displayName)},
        ${sqlLiteral(record.email)},
        ${sqlLiteral(record.createdAt)},
        ${sqlLiteral(record.updatedAt)}
      );
    `);
    return record;
  }

  async getWorkspaceUser(workspaceId: string, id: string): Promise<WorkspaceUserRecord | undefined> {
    const rows = this.query(`
      SELECT * FROM workspace_users
      WHERE workspace_id = ${sqlLiteral(workspaceId)} AND id = ${sqlLiteral(id)}
      LIMIT 1;
    `);
    const row = rows[0];
    return row ? workspaceUserFromRow(row) : undefined;
  }

  async getWorkspaceUserByPrincipal(workspaceId: string, principalId: string): Promise<WorkspaceUserRecord | undefined> {
    const rows = this.query(`
      SELECT * FROM workspace_users
      WHERE workspace_id = ${sqlLiteral(workspaceId)} AND principal_id = ${sqlLiteral(principalId)}
      LIMIT 1;
    `);
    const row = rows[0];
    return row ? workspaceUserFromRow(row) : undefined;
  }

  async listWorkspaceUsers(workspaceId: string): Promise<WorkspaceUserRecord[]> {
    return this.query(
      `SELECT * FROM workspace_users WHERE workspace_id = ${sqlLiteral(workspaceId)} ORDER BY display_name ASC;`,
    ).map(workspaceUserFromRow);
  }

  async createServiceAccount(record: ServiceAccountRecord): Promise<ServiceAccountRecord> {
    this.exec(`
      INSERT OR REPLACE INTO service_accounts (
        id, workspace_id, name, description, groups_json, scopes_json, created_at, updated_at, revoked_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.name)},
        ${sqlLiteral(record.description)},
        ${sqlJsonLiteral(record.groups)},
        ${sqlJsonLiteral(record.scopes)},
        ${sqlLiteral(record.createdAt)},
        ${sqlLiteral(record.updatedAt)},
        ${sqlLiteral(record.revokedAt)}
      );
    `);
    return record;
  }

  async getServiceAccount(id: string): Promise<ServiceAccountRecord | undefined> {
    const rows = this.query(`SELECT * FROM service_accounts WHERE id = ${sqlLiteral(id)} LIMIT 1;`);
    const row = rows[0];
    return row ? serviceAccountFromRow(row) : undefined;
  }

  async listServiceAccounts(workspaceId: string): Promise<ServiceAccountRecord[]> {
    return this.query(
      `SELECT * FROM service_accounts WHERE workspace_id = ${sqlLiteral(workspaceId)} ORDER BY created_at DESC;`,
    ).map(serviceAccountFromRow);
  }

  async createApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord> {
    return this.writeApiKey(record);
  }

  async getApiKeyByPrefix(keyPrefix: string): Promise<ApiKeyRecord | undefined> {
    const rows = this.query(`SELECT * FROM api_keys WHERE key_prefix = ${sqlLiteral(keyPrefix)} LIMIT 1;`);
    const row = rows[0];
    return row ? apiKeyFromRow(row) : undefined;
  }

  async updateApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord> {
    return this.writeApiKey(record);
  }

  async createExecutionGrant(record: ExecutionGrantRecord): Promise<ExecutionGrantRecord> {
    return this.writeExecutionGrant(record);
  }

  async getExecutionGrant(id: string): Promise<ExecutionGrantRecord | undefined> {
    const rows = this.query(`SELECT * FROM execution_grants WHERE id = ${sqlLiteral(id)} LIMIT 1;`);
    const row = rows[0];
    return row ? executionGrantFromRow(row) : undefined;
  }

  async listExecutionGrants(filters: { limit?: number; workspaceId?: string } = {}): Promise<ExecutionGrantRecord[]> {
    const where = filters.workspaceId ? `WHERE workspace_id = ${sqlLiteral(filters.workspaceId)}` : '';
    const limit = Math.max(1, Math.min(filters.limit ?? 100, 1000));
    const rows = this.query(`SELECT * FROM execution_grants ${where} ORDER BY created_at DESC LIMIT ${limit};`);
    return rows.map(executionGrantFromRow);
  }

  async updateExecutionGrant(record: ExecutionGrantRecord): Promise<ExecutionGrantRecord> {
    return this.writeExecutionGrant(record);
  }

  async consumeExecutionGrantAtomically(id: string, consumedAt: string): Promise<ExecutionGrantRecord | undefined> {
    const changes = this.query(`
      UPDATE execution_grants
      SET consumed_at = ${sqlLiteral(consumedAt)}
      WHERE id = ${sqlLiteral(id)} AND consumed_at IS NULL;
      SELECT changes() AS changed;
    `);
    if (Number(changes[0]?.changed ?? 0) !== 1) return undefined;
    const row = this.query(`SELECT * FROM execution_grants WHERE id = ${sqlLiteral(id)} LIMIT 1;`)[0];
    return row ? executionGrantFromRow(row) : undefined;
  }

  async reserveExecutionAttemptAtomically(
    record: ExecutionAttemptRecordV1,
    approvalAuthorization?: ApprovalAuthorizationV1,
  ): Promise<AtomicExecutionAttemptReservationResult> {
    const toolCall = await this.getToolCall(record.toolCallId);
    if (!toolCall || (toolCall.workspaceId ?? 'default') !== record.workspaceId) return { outcome: 'not_found' };
    const approvalAuthorizationValid = record.binding.approvalId === null
      ? approvalAuthorization === undefined
      : approvalAuthorization !== undefined && isValidApprovalAuthorization(approvalAuthorization);
    const structurallyValid = executionAttemptReservationIsStructurallyValid(record) &&
      approvalAuthorizationValid &&
      executionAttemptGovernanceBindingMatches(record, toolCall);
    const bindingClause = sqliteExecutionAttemptBindingClause(record, toolCall, approvalAuthorization);
    const rows = structurallyValid
      ? this.query(`${executionAttemptInsertSql(
          record,
          bindingClause,
        )} RETURNING *;`)
      : [];
    if (rows[0]) return { attempt: executionAttemptFromRow(rows[0]), outcome: 'reserved' };
    const bindingMatches = structurallyValid && Number(this.query(
      `SELECT CASE WHEN ${bindingClause} THEN 1 ELSE 0 END AS matches;`,
    )[0]?.matches ?? 0) === 1;
    if (!bindingMatches) return { outcome: 'binding_mismatch' };
    const existing = await this.getExecutionAttemptByToolCallId(record.workspaceId, record.toolCallId);
    if (existing) return { attempt: existing, outcome: 'existing' };
    return { outcome: 'binding_mismatch' };
  }

  async getExecutionAttempt(id: string): Promise<ExecutionAttemptRecordV1 | undefined> {
    const row = this.query(`SELECT * FROM execution_attempts WHERE id = ${sqlLiteral(id)} LIMIT 1;`)[0];
    return row ? executionAttemptFromRow(row) : undefined;
  }

  async getExecutionAttemptByToolCallId(
    workspaceId: string,
    toolCallId: string,
  ): Promise<ExecutionAttemptRecordV1 | undefined> {
    const row = this.query(`
      SELECT * FROM execution_attempts
      WHERE workspace_id = ${sqlLiteral(workspaceId)} AND tool_call_id = ${sqlLiteral(toolCallId)}
      LIMIT 1;
    `)[0];
    return row ? executionAttemptFromRow(row) : undefined;
  }

  async listExecutionAttempts(
    workspaceId: string,
    filters: { state?: ExecutionAttemptState; toolCallId?: string } = {},
  ): Promise<ExecutionAttemptRecordV1[]> {
    const conditions = [
      `workspace_id = ${sqlLiteral(workspaceId)}`,
      filters.state ? `state = ${sqlLiteral(filters.state)}` : undefined,
      filters.toolCallId ? `tool_call_id = ${sqlLiteral(filters.toolCallId)}` : undefined,
    ].filter(Boolean);
    return this.query(`
      SELECT * FROM execution_attempts
      WHERE ${conditions.join(' AND ')}
      ORDER BY reserved_at DESC;
    `).map(executionAttemptFromRow);
  }

  async transitionExecutionAttemptAtomically(
    input: AtomicExecutionAttemptTransitionInput,
  ): Promise<AtomicExecutionAttemptTransitionResult> {
    const valid = executionAttemptTransitionIsValid(input);
    const revision = input.contentExposureRevision;
    const guardedDispatch = valid && input.expectedState === 'reserved' && input.nextState === 'dispatched' && revision;
    let rows: SqliteRow[] = [];
    if (guardedDispatch) {
      const marker = this.query(`CREATE TEMP TABLE actionproxy_execution_transition_result (changed INTEGER NOT NULL);
          BEGIN IMMEDIATE;
          INSERT OR IGNORE INTO content_exposure_scopes (workspace_id, influence_scope_id, revision)
          VALUES (${sqlLiteral(input.workspaceId)}, ${sqlLiteral(revision.influenceScopeId)}, 0);
          UPDATE execution_attempts
          SET state = ${sqlLiteral(input.nextState)},
              dispatched_at = CASE
                WHEN ${sqlLiteral(input.nextState)} = 'dispatched' THEN ${sqlLiteral(input.transitionedAt)}
                ELSE dispatched_at
              END,
              completed_at = CASE
                WHEN ${sqlLiteral(input.nextState)} NOT IN ('reserved', 'dispatched') THEN ${sqlLiteral(input.transitionedAt)}
                ELSE completed_at
              END,
              outcome_json = ${input.outcome === undefined ? 'NULL' : sqlJsonLiteral(input.outcome)},
              updated_at = ${sqlLiteral(input.transitionedAt)}
          WHERE id = ${sqlLiteral(input.attemptId)}
            AND workspace_id = ${sqlLiteral(input.workspaceId)}
            AND reservation_owner = ${sqlLiteral(input.reservationOwner)}
            AND state = ${sqlLiteral(input.expectedState)}
            AND (
              SELECT revision FROM content_exposure_scopes
              WHERE workspace_id = ${sqlLiteral(input.workspaceId)}
                AND influence_scope_id = ${sqlLiteral(revision.influenceScopeId)}
            ) = ${revision.revision};
          INSERT INTO actionproxy_execution_transition_result (changed) VALUES (changes());
          COMMIT;
          SELECT changed FROM actionproxy_execution_transition_result LIMIT 1;
        `)[0];
      if (Number(marker?.changed ?? 0) === 1) {
        const transitioned = await this.getExecutionAttempt(input.attemptId);
        if (transitioned) return { attempt: transitioned, outcome: 'transitioned' };
        throw new Error('Atomic execution-attempt dispatch transition was not readable after commit.');
      }
    } else if (valid) {
      rows = this.query(`
        UPDATE execution_attempts
        SET state = ${sqlLiteral(input.nextState)},
            dispatched_at = CASE
              WHEN ${sqlLiteral(input.nextState)} = 'dispatched' THEN ${sqlLiteral(input.transitionedAt)}
              ELSE dispatched_at
            END,
            completed_at = CASE
              WHEN ${sqlLiteral(input.nextState)} NOT IN ('reserved', 'dispatched') THEN ${sqlLiteral(input.transitionedAt)}
              ELSE completed_at
            END,
            outcome_json = ${input.outcome === undefined ? 'NULL' : sqlJsonLiteral(input.outcome)},
            updated_at = ${sqlLiteral(input.transitionedAt)}
        WHERE id = ${sqlLiteral(input.attemptId)}
          AND workspace_id = ${sqlLiteral(input.workspaceId)}
          AND reservation_owner = ${sqlLiteral(input.reservationOwner)}
          AND state = ${sqlLiteral(input.expectedState)}
        RETURNING *;
      `);
    }
    if (rows[0]) return { attempt: executionAttemptFromRow(rows[0]), outcome: 'transitioned' };
    const current = await this.getExecutionAttempt(input.attemptId);
    if (!current || current.workspaceId !== input.workspaceId) return { outcome: 'not_found' };
    if (current.reservationOwner !== input.reservationOwner) return { attempt: current, outcome: 'owner_mismatch' };
    if (executionAttemptTransitionIsReplay(current, input)) return { attempt: current, outcome: 'replay' };
    if (executionAttemptIsTerminal(current.state)) return { attempt: current, outcome: 'already_terminal' };
    if (revision) {
      const currentRevision = this.query(`
        SELECT revision FROM content_exposure_scopes
        WHERE workspace_id = ${sqlLiteral(input.workspaceId)}
          AND influence_scope_id = ${sqlLiteral(revision.influenceScopeId)}
        LIMIT 1;
      `)[0];
      if (Number(currentRevision?.revision ?? 0) !== revision.revision) {
        return { attempt: current, outcome: 'content_influence_mismatch' };
      }
    }
    return { attempt: current, outcome: 'state_mismatch' };
  }

  async bindExecutionAttemptGrantAtomically(
    input: AtomicExecutionAttemptGrantBindingInput,
  ): Promise<AtomicExecutionAttemptGrantBindingResult> {
    const rows = this.query(`
      UPDATE execution_attempts
      SET grant_id = ${sqlLiteral(input.grantId)}, updated_at = ${sqlLiteral(input.updatedAt)}
      WHERE id = ${sqlLiteral(input.attemptId)}
        AND workspace_id = ${sqlLiteral(input.workspaceId)}
        AND reservation_owner = ${sqlLiteral(input.reservationOwner)}
        AND state = 'reserved'
        AND grant_id IS NULL
      RETURNING *;
    `);
    if (rows[0]) return { attempt: executionAttemptFromRow(rows[0]), outcome: 'bound' };
    const current = await this.getExecutionAttempt(input.attemptId);
    if (!current || current.workspaceId !== input.workspaceId) return { outcome: 'not_found' };
    if (current.reservationOwner !== input.reservationOwner) return { attempt: current, outcome: 'owner_mismatch' };
    if (current.state !== 'reserved') return { attempt: current, outcome: 'state_mismatch' };
    return { attempt: current, outcome: 'already_bound' };
  }

  async consumeExecutionGrantAndDispatchAttemptAtomically(
    input: AtomicGrantDispatchInput,
  ): Promise<AtomicGrantDispatchResult> {
    const revision = input.contentExposureRevision;
    const result = this.query(`CREATE TEMP TABLE actionproxy_grant_dispatch_result (outcome TEXT NOT NULL);
      BEGIN IMMEDIATE;
      ${revision ? `INSERT OR IGNORE INTO content_exposure_scopes (workspace_id, influence_scope_id, revision)
      VALUES (${sqlLiteral(input.workspaceId)}, ${sqlLiteral(revision.influenceScopeId)}, 0);` : ''}
      INSERT INTO actionproxy_grant_dispatch_result (outcome)
      SELECT CASE
        WHEN NOT EXISTS (
          SELECT 1 FROM execution_attempts
          WHERE id = ${sqlLiteral(input.attemptId)} AND workspace_id = ${sqlLiteral(input.workspaceId)}
        ) THEN 'attempt_not_found'
        WHEN NOT EXISTS (
          SELECT 1 FROM execution_grants
          WHERE id = ${sqlLiteral(input.grantId)} AND workspace_id = ${sqlLiteral(input.workspaceId)}
        ) THEN 'grant_not_found'
        WHEN EXISTS (
          SELECT 1 FROM execution_grants
          WHERE id = ${sqlLiteral(input.grantId)} AND consumed_at IS NOT NULL
        ) THEN 'grant_already_consumed'
        WHEN EXISTS (
          SELECT 1 FROM execution_attempts
          WHERE id = ${sqlLiteral(input.attemptId)} AND state != 'reserved'
        ) THEN 'attempt_state_mismatch'
        WHEN NOT EXISTS (
          SELECT 1
          FROM execution_attempts ea
          JOIN execution_grants eg ON eg.id = ${sqlLiteral(input.grantId)}
          WHERE ea.id = ${sqlLiteral(input.attemptId)}
            AND ea.workspace_id = ${sqlLiteral(input.workspaceId)}
            AND ea.reservation_owner = ${sqlLiteral(input.reservationOwner)}
            AND ea.grant_id = eg.id
            AND ea.tool_call_id = ${sqlLiteral(input.toolCallId)}
            AND eg.workspace_id = ea.workspace_id
            AND eg.tool_call_id = ea.tool_call_id
        ) THEN 'binding_mismatch'
        ${revision ? `WHEN NOT EXISTS (
          SELECT 1 FROM content_exposure_scopes
          WHERE workspace_id = ${sqlLiteral(input.workspaceId)}
            AND influence_scope_id = ${sqlLiteral(revision.influenceScopeId)}
            AND revision = ${revision.revision}
        ) THEN 'content_influence_mismatch'` : ''}
        ELSE 'dispatched'
      END;
      UPDATE execution_grants
      SET consumed_at = ${sqlLiteral(input.dispatchedAt)}
      WHERE id = ${sqlLiteral(input.grantId)}
        AND (SELECT outcome FROM actionproxy_grant_dispatch_result LIMIT 1) = 'dispatched';
      UPDATE execution_attempts
      SET state = 'dispatched',
          dispatched_at = ${sqlLiteral(input.dispatchedAt)},
          updated_at = ${sqlLiteral(input.dispatchedAt)}
      WHERE id = ${sqlLiteral(input.attemptId)}
        AND (SELECT outcome FROM actionproxy_grant_dispatch_result LIMIT 1) = 'dispatched';
      COMMIT;
      SELECT outcome FROM actionproxy_grant_dispatch_result LIMIT 1;
    `)[0];
    const outcome = String(result?.outcome ?? 'binding_mismatch') as AtomicGrantDispatchResult['outcome'];
    const attempt = await this.getExecutionAttempt(input.attemptId);
    const grant = await this.getExecutionGrant(input.grantId);
    return { attempt, grant, outcome };
  }

  async createActionReceipt(record: ActionReceiptRecord): Promise<ActionReceiptRecord> {
    return this.writeActionReceipt(record);
  }

  async getActionReceipt(id: string): Promise<ActionReceiptRecord | undefined> {
    const rows = this.query(`SELECT * FROM action_receipts WHERE id = ${sqlLiteral(id)} LIMIT 1;`);
    const row = rows[0];
    return row ? actionReceiptFromRow(row) : undefined;
  }

  async getActionReceiptByToolCallId(toolCallId: string): Promise<ActionReceiptRecord | undefined> {
    const rows = this.query(`SELECT * FROM action_receipts WHERE tool_call_id = ${sqlLiteral(toolCallId)} LIMIT 1;`);
    const row = rows[0];
    return row ? actionReceiptFromRow(row) : undefined;
  }

  async updateActionReceipt(record: ActionReceiptRecord): Promise<ActionReceiptRecord> {
    return this.writeActionReceipt(record);
  }

  async recordActionReceiptOutcomeAtomically(
    input: AtomicActionReceiptOutcomeInput,
  ): Promise<AtomicActionReceiptOutcomeResult> {
    const row = this.query(`
      UPDATE action_receipts
      SET outcome_json = ${sqlJsonLiteral(input.outcome)}
      WHERE id = ${sqlLiteral(input.receiptId)} AND outcome_json IS NULL
      RETURNING *;
    `)[0];
    if (row) return { outcome: 'recorded', receipt: actionReceiptFromRow(row) };
    const receipt = await this.getActionReceipt(input.receiptId);
    return receipt ? { outcome: 'existing', receipt } : { outcome: 'not_found' };
  }

  async createIdempotencyRecord(record: IdempotencyRecord): Promise<IdempotencyRecord> {
    this.exec(`
      INSERT OR IGNORE INTO idempotency_records (workspace_id, route, key, request_hash, tool_call_id, created_at)
      VALUES (
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.route)},
        ${sqlLiteral(record.key)},
        ${sqlLiteral(record.requestHash)},
        ${sqlLiteral(record.toolCallId)},
        ${sqlLiteral(record.createdAt)}
      );
    `);
    return record;
  }

  async getIdempotencyRecord(workspaceId: string, route: string, key: string): Promise<IdempotencyRecord | undefined> {
    const rows = this.query(`
      SELECT * FROM idempotency_records
      WHERE workspace_id = ${sqlLiteral(workspaceId)}
        AND route = ${sqlLiteral(route)}
        AND key = ${sqlLiteral(key)}
      LIMIT 1;
    `);
    const row = rows[0];
    return row ? idempotencyFromRow(row) : undefined;
  }

  async upsertObservedTool(record: ObservedToolRecord): Promise<ObservedToolRecord> {
    await this.writeObservedTool(record);
    return record;
  }

  async getObservedTool(id: string): Promise<ObservedToolRecord | undefined> {
    const rows = this.query(`SELECT * FROM observed_tools WHERE id = ${sqlLiteral(id)} LIMIT 1;`);
    const row = rows[0];
    return row ? observedToolFromRow(row) : undefined;
  }

  async getObservedToolByName(workspaceId: string, toolName: string): Promise<ObservedToolRecord | undefined> {
    const rows = this.query(`
      SELECT * FROM observed_tools
      WHERE workspace_id = ${sqlLiteral(workspaceId)} AND tool_name = ${sqlLiteral(toolName)}
      LIMIT 1;
    `);
    const row = rows[0];
    return row ? observedToolFromRow(row) : undefined;
  }

  async listObservedTools(workspaceId: string): Promise<ObservedToolRecord[]> {
    return this.query(
      `SELECT * FROM observed_tools WHERE workspace_id = ${sqlLiteral(workspaceId)} ORDER BY last_seen_at DESC;`,
    ).map(observedToolFromRow);
  }

  async append(event: AuditEvent): Promise<void> {
    this.exec(`
      INSERT OR IGNORE INTO audit_events (
        id, type, workspace_id, tool_call_id, approval_id, actor, auth_json, input_hash,
        policy_version_id, policy_version_hash, previous_event_hash, event_hash, timestamp, data_json
      ) VALUES (
        ${sqlLiteral(event.id)},
        ${sqlLiteral(event.type)},
        ${sqlLiteral(event.workspaceId)},
        ${sqlLiteral(event.toolCallId)},
        ${sqlLiteral(event.approvalId)},
        ${sqlLiteral(event.actor)},
        ${event.auth === undefined ? 'NULL' : sqlJsonLiteral(event.auth)},
        ${sqlLiteral(event.inputHash)},
        ${sqlLiteral(event.policyVersionId)},
        ${sqlLiteral(event.policyVersionHash)},
        ${sqlLiteral(event.previousEventHash)},
        ${sqlLiteral(event.eventHash)},
        ${sqlLiteral(event.timestamp)},
        ${sqlJsonLiteral(event.data)}
      );
    `);
  }

  async list(limit: AuditListLimit = 100, filters: AuditListFilters = {}): Promise<AuditEvent[]> {
    const safeLimit = limit === 'all' ? undefined : Number.isFinite(limit) ? Math.max(1, Math.trunc(limit)) : 100;
    const conditions = [
      filters.from ? `timestamp >= ${sqlLiteral(filters.from)}` : undefined,
      filters.to ? `timestamp <= ${sqlLiteral(filters.to)}` : undefined,
      filters.toolCallId ? `tool_call_id = ${sqlLiteral(filters.toolCallId)}` : undefined,
      filters.workspaceId ? `workspace_id = ${sqlLiteral(filters.workspaceId)}` : undefined,
    ].filter(Boolean);
    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const limitClause = safeLimit === undefined ? '' : `LIMIT ${safeLimit}`;
    return this.query(`SELECT * FROM audit_events ${whereClause} ORDER BY timestamp DESC ${limitClause};`).map(
      auditEventFromRow,
    );
  }

  async recordPolicyVersion(record: PolicyVersionRecord): Promise<void> {
    this.exec(`
      INSERT OR REPLACE INTO policy_versions (id, version, policy_json, created_at)
      VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.version)},
        ${sqlJsonLiteral(record.policy)},
        ${sqlLiteral(record.createdAt)}
      );
    `);
  }

  private async writeToolCall(record: ToolCallRecord): Promise<void> {
    this.exec(toolCallInsertSql(record, { conflict: 'replace' }));
  }

  private async writeApproval(record: ApprovalRecord): Promise<void> {
    this.exec(`
      INSERT OR REPLACE INTO approvals (
        id, workspace_id, tool_call_id, status, requested_by, requested_by_auth_json,
        authorization_json, authorization_consumed_at, authorization_consumed_reason, approved_by,
        cancelled_at, cancelled_by, cancellation_reason, expired_at, finalized_at,
        rejected_by, note, rejection_reason, original_input_json, original_input_hash, original_envelope_hash,
        edited_input_json, approved_input_hash, approved_envelope_hash, review_hash, approver_users_json,
        approver_groups_json, required_approvals, separation_of_duties, decisions_json, created_at, updated_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId ?? 'default')},
        ${sqlLiteral(record.toolCallId)},
        ${sqlLiteral(record.status)},
        ${sqlLiteral(record.requestedBy)},
        ${record.requestedByAuth === undefined ? 'NULL' : sqlJsonLiteral(record.requestedByAuth)},
        ${record.authorization === undefined ? 'NULL' : sqlJsonLiteral(record.authorization)},
        ${sqlLiteral(record.authorizationConsumedAt)},
        ${sqlLiteral(record.authorizationConsumedReason)},
        ${sqlLiteral(record.approvedBy)},
        ${sqlLiteral(record.cancelledAt)},
        ${sqlLiteral(record.cancelledBy)},
        ${sqlLiteral(record.cancellationReason)},
        ${sqlLiteral(record.expiredAt)},
        ${sqlLiteral(record.finalizedAt)},
        ${sqlLiteral(record.rejectedBy)},
        ${sqlLiteral(record.note)},
        ${sqlLiteral(record.rejectionReason)},
        ${sqlJsonLiteral(record.originalInput)},
        ${sqlLiteral(record.originalInputHash)},
        ${sqlLiteral(record.originalEnvelopeHash)},
        ${record.editedInput === undefined ? 'NULL' : sqlJsonLiteral(record.editedInput)},
        ${sqlLiteral(record.approvedInputHash)},
        ${sqlLiteral(record.approvedEnvelopeHash)},
        ${sqlLiteral(record.reviewHash)},
        ${record.approverUsers === undefined ? 'NULL' : sqlJsonLiteral(record.approverUsers)},
        ${record.approverGroups === undefined ? 'NULL' : sqlJsonLiteral(record.approverGroups)},
        ${record.requiredApprovals === undefined ? 'NULL' : Math.trunc(record.requiredApprovals)},
        ${record.separationOfDuties === undefined ? 'NULL' : record.separationOfDuties ? 1 : 0},
        ${record.decisions === undefined ? 'NULL' : sqlJsonLiteral(record.decisions)},
        ${sqlLiteral(record.createdAt)},
        ${sqlLiteral(record.updatedAt)}
      );
    `);
  }

  private async writeApprovalDelivery(record: ApprovalDeliveryRecord): Promise<void> {
    this.exec(`
      INSERT OR REPLACE INTO approval_deliveries (
        id, workspace_id, approval_id, tool_call_id, channel_id, provider, status,
        message_id, destination, error, recipient_user_id, recipient_email, recipient_slack_user_id,
        recipient_telegram_chat_id, recipient_telegram_user_id, data_json, created_at, updated_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId ?? 'default')},
        ${sqlLiteral(record.approvalId)},
        ${sqlLiteral(record.toolCallId)},
        ${sqlLiteral(record.channelId)},
        ${sqlLiteral(record.provider)},
        ${sqlLiteral(record.status)},
        ${sqlLiteral(record.messageId)},
        ${sqlLiteral(record.destination)},
        ${sqlLiteral(record.error)},
        ${sqlLiteral(record.recipientUserId)},
        ${sqlLiteral(record.recipientEmail)},
        ${sqlLiteral(record.recipientSlackUserId)},
        ${sqlLiteral(record.recipientTelegramChatId)},
        ${sqlLiteral(record.recipientTelegramUserId)},
        ${sqlJsonLiteral(record.data)},
        ${sqlLiteral(record.createdAt)},
        ${sqlLiteral(record.updatedAt)}
      );
    `);
  }

  private async writeApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord> {
    this.exec(`
      INSERT OR REPLACE INTO api_keys (
        id, workspace_id, service_account_id, key_prefix, key_hash, scopes_json, created_at, last_used_at, revoked_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.serviceAccountId)},
        ${sqlLiteral(record.keyPrefix)},
        ${sqlLiteral(record.keyHash)},
        ${sqlJsonLiteral(record.scopes)},
        ${sqlLiteral(record.createdAt)},
        ${sqlLiteral(record.lastUsedAt)},
        ${sqlLiteral(record.revokedAt)}
      );
    `);
    return record;
  }

  private async writeExecutionGrant(record: ExecutionGrantRecord): Promise<ExecutionGrantRecord> {
    this.exec(`
      INSERT OR REPLACE INTO execution_grants (
        id, workspace_id, tool_call_id, tool_name, input_hash, approved_input_hash,
        approved_envelope_hash, policy_version_hash, receipt_id, receipt_hash, actor,
        auth_json, expires_at, nonce, signature, consumed_at, created_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.toolCallId)},
        ${sqlLiteral(record.toolName)},
        ${sqlLiteral(record.inputHash)},
        ${sqlLiteral(record.approvedInputHash)},
        ${sqlLiteral(record.approvedEnvelopeHash)},
        ${sqlLiteral(record.policyVersionHash)},
        ${sqlLiteral(record.receiptId)},
        ${sqlLiteral(record.receiptHash)},
        ${sqlLiteral(record.actor)},
        ${record.auth === undefined ? 'NULL' : sqlJsonLiteral(record.auth)},
        ${sqlLiteral(record.expiresAt)},
        ${sqlLiteral(record.nonce)},
        ${sqlLiteral(record.signature)},
        ${sqlLiteral(record.consumedAt)},
        ${sqlLiteral(record.createdAt)}
      );
    `);
    return record;
  }

  private async writeActionReceipt(record: ActionReceiptRecord): Promise<ActionReceiptRecord> {
    this.exec(`
      INSERT OR REPLACE INTO action_receipts (
        id, workspace_id, tool_call_id, approval_id, decision_kind, decision_actor, decision_auth_json,
        tool_name, source_json, protocol, operation_json, original_input_hash, approved_input_hash,
        original_envelope_hash, approved_envelope_hash, review_hash, policy_version_id, policy_version_hash,
        policy_decision, policy_reason, policy_risk, execution_mode, issued_at, expires_at, receipt_hash,
        key_id, signature_alg, signature, outcome_json, created_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.toolCallId)},
        ${sqlLiteral(record.approvalId)},
        ${sqlLiteral(record.decisionKind)},
        ${sqlLiteral(record.decisionActor)},
        ${record.decisionAuth === undefined ? 'NULL' : sqlJsonLiteral(record.decisionAuth)},
        ${sqlLiteral(record.toolName)},
        ${sqlJsonLiteral(record.source)},
        ${sqlLiteral(record.protocol)},
        ${sqlJsonLiteral(record.operation)},
        ${sqlLiteral(record.originalInputHash)},
        ${sqlLiteral(record.approvedInputHash)},
        ${sqlLiteral(record.originalEnvelopeHash)},
        ${sqlLiteral(record.approvedEnvelopeHash)},
        ${sqlLiteral(record.reviewHash)},
        ${sqlLiteral(record.policyVersionId)},
        ${sqlLiteral(record.policyVersionHash)},
        ${sqlLiteral(record.policyDecision)},
        ${sqlLiteral(record.policyReason)},
        ${sqlLiteral(record.policyRisk)},
        ${sqlLiteral(record.executionMode)},
        ${sqlLiteral(record.issuedAt)},
        ${sqlLiteral(record.expiresAt)},
        ${sqlLiteral(record.receiptHash)},
        ${sqlLiteral(record.keyId)},
        ${sqlLiteral(record.signatureAlg)},
        ${sqlLiteral(record.signature)},
        ${record.outcome === undefined ? 'NULL' : sqlJsonLiteral(record.outcome)},
        ${sqlLiteral(record.createdAt)}
      );
    `);
    return record;
  }

  private async writeObservedTool(record: ObservedToolRecord): Promise<void> {
    this.exec(`
      INSERT OR REPLACE INTO observed_tools (
        id, workspace_id, tool_name, sources_json, source_ids_json, first_seen_at, last_seen_at,
        call_count, schema_hash, schema_change_json, coverage_json, status, suggestion_json, created_at, updated_at
      ) VALUES (
        ${sqlLiteral(record.id)},
        ${sqlLiteral(record.workspaceId)},
        ${sqlLiteral(record.toolName)},
        ${sqlJsonLiteral(record.sources)},
        ${sqlJsonLiteral(record.sourceIds)},
        ${sqlLiteral(record.firstSeenAt)},
        ${sqlLiteral(record.lastSeenAt)},
        ${Math.max(0, Math.trunc(record.callCount))},
        ${sqlLiteral(record.schemaHash)},
        ${record.schemaChange === undefined ? 'NULL' : sqlJsonLiteral(record.schemaChange)},
        ${sqlJsonLiteral(record.coverage)},
        ${sqlLiteral(record.status)},
        ${sqlJsonLiteral(record.suggestion)},
        ${sqlLiteral(record.createdAt)},
        ${sqlLiteral(record.updatedAt)}
      );
    `);
  }

  private exec(sql: string): void {
    runSqlite(this.databasePath, sql);
  }

  private query(sql: string): SqliteRow[] {
    return runSqlite(this.databasePath, sql, { json: true }) as SqliteRow[];
  }

}

function toolCallFromRow(row: SqliteRow): ToolCallRecord {
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

function contentExposureFromRow(row: SqliteRow): ContentExposureRecord {
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

function toolCallInsertSql(
  record: ToolCallRecord,
  options: { condition?: string; conflict: 'none' | 'replace' },
): string {
  const prefix = options.conflict === 'replace' ? 'INSERT OR REPLACE' : 'INSERT';
  const values = [
    sqlLiteral(record.id),
    sqlLiteral(record.workspaceId ?? 'default'),
    sqlLiteral(record.toolName),
    sqlJsonLiteral(record.input),
    sqlLiteral(record.inputHash),
    sqlLiteral(record.requestedBy),
    record.requestedByAuth === undefined ? 'NULL' : sqlJsonLiteral(record.requestedByAuth),
    record.actionEnvelope === undefined ? 'NULL' : sqlJsonLiteral(record.actionEnvelope),
    sqlLiteral(record.actionEnvelopeHash),
    sqlLiteral(record.canonicalActionRequestHash),
    sqlLiteral(record.canonicalActionRequestVersion),
    sqlLiteral(record.canonicalDecisionInputHash),
    record.canonicalPolicyContext === undefined ? 'NULL' : sqlJsonLiteral(record.canonicalPolicyContext),
    sqlLiteral(record.agentId),
    sqlLiteral(record.reason),
    sqlJsonLiteral(record.metadata),
    sqlLiteral(record.status),
    sqlLiteral(record.decision),
    record.decisionTrace === undefined ? 'NULL' : sqlJsonLiteral(record.decisionTrace),
    sqlJsonLiteral(toolCallGovernanceState(record)),
    sqlLiteral(record.policyReason),
    sqlLiteral(record.policyVersionId),
    sqlLiteral(record.policyVersionHash),
    sqlLiteral(record.risk),
    record.result === undefined ? 'NULL' : sqlJsonLiteral(record.result),
    sqlLiteral(record.error),
    sqlLiteral(record.createdAt),
    sqlLiteral(record.updatedAt),
  ];
  return `
    ${prefix} INTO tool_calls (
      id, workspace_id, tool_name, input_json, input_hash, requested_by, requested_by_auth_json,
      action_envelope_json, action_envelope_hash, canonical_action_request_hash,
      canonical_action_request_version, canonical_decision_input_hash, canonical_policy_context_json,
      agent_id, reason, metadata_json, status, decision,
      decision_trace_json, governance_state_json, policy_reason, policy_version_id, policy_version_hash, risk, result_json, error, created_at, updated_at
    )
    ${options.condition ? `SELECT ${values.join(', ')} WHERE ${options.condition}` : `VALUES (${values.join(', ')})`};
  `;
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

function executionAttemptInsertSql(record: ExecutionAttemptRecordV1, condition: string): string {
  return `
    INSERT INTO execution_attempts (
      id, workspace_id, tool_call_id, attempt_number, version, state, reservation_owner,
      execution_mode, executor_id, input_hash, provider_idempotency, retry_policy,
      binding_json, grant_id, outcome_json, reserved_at, dispatched_at, completed_at, updated_at
    )
    SELECT
      ${sqlLiteral(record.id)},
      ${sqlLiteral(record.workspaceId)},
      ${sqlLiteral(record.toolCallId)},
      ${Math.trunc(record.attemptNumber)},
      ${sqlLiteral(record.version)},
      ${sqlLiteral(record.state)},
      ${sqlLiteral(record.reservationOwner)},
      ${sqlLiteral(record.executionMode)},
      ${sqlLiteral(record.executorId)},
      ${sqlLiteral(record.inputHash)},
      ${sqlLiteral(record.providerIdempotency)},
      ${sqlLiteral(record.retryPolicy)},
      ${sqlJsonLiteral(record.binding)},
      ${sqlLiteral(record.grantId)},
      ${record.outcome === undefined ? 'NULL' : sqlJsonLiteral(record.outcome)},
      ${sqlLiteral(record.reservedAt)},
      ${sqlLiteral(record.dispatchedAt)},
      ${sqlLiteral(record.completedAt)},
      ${sqlLiteral(record.updatedAt)}
    WHERE ${condition}
    ON CONFLICT DO NOTHING
  `;
}

function sqliteExecutionAttemptBindingClause(
  record: ExecutionAttemptRecordV1,
  toolCall: ToolCallRecord,
  approvalAuthorization?: ApprovalAuthorizationV1,
): string {
  const binding = record.binding;
  const toolCallClause = `EXISTS (
    SELECT 1 FROM tool_calls tc
    WHERE tc.id = ${sqlLiteral(record.toolCallId)}
      AND tc.workspace_id = ${sqlLiteral(record.workspaceId)}
      AND tc.canonical_action_request_hash IS ${sqlLiteral(binding.canonicalActionRequestHash)}
      AND tc.canonical_action_request_version IS ${sqlLiteral(binding.canonicalActionRequestVersion)}
      AND tc.canonical_decision_input_hash IS ${sqlLiteral(binding.canonicalDecisionInputHash)}
      AND json_extract(tc.decision_trace_json, '$.decisionV1.decisionId') IS ${sqlLiteral(binding.decisionId)}
      AND json_extract(tc.decision_trace_json, '$.decisionV1.version') IS ${sqlLiteral(binding.decisionVersion)}
      AND tc.policy_version_hash IS ${sqlLiteral(binding.policyVersionHash)}
      AND json_extract(tc.governance_state_json, '$.contentInfluence') IS ${sqliteJsonValueLiteral(
        toolCall.contentInfluence,
      )}
      AND json_extract(tc.governance_state_json, '$.influenceScopeId') IS ${sqlLiteral(toolCall.influenceScopeId)}
      AND json_extract(tc.governance_state_json, '$.resultSource') IS ${sqliteJsonValueLiteral(
        toolCall.resultSource,
      )}
  )`;
  const approvalClause = binding.approvalId === null
    ? `${sqlLiteral(binding.approvalAuthorizationHash)} IS NULL AND ${sqlLiteral(binding.approvalAuthorizationNonce)} IS NULL`
    : `EXISTS (
        SELECT 1 FROM approvals a
        WHERE a.id = ${sqlLiteral(binding.approvalId)}
          AND a.workspace_id = ${sqlLiteral(record.workspaceId)}
          AND a.tool_call_id = ${sqlLiteral(record.toolCallId)}
          AND a.status = 'approved'
          AND a.authorization_json = ${sqlJsonLiteral(approvalAuthorization)}
          AND a.authorization_consumed_reason = 'approved'
          AND a.authorization_consumed_at IS NOT NULL
          AND a.approved_input_hash = ${sqlLiteral(record.inputHash)}
          AND a.approved_envelope_hash = ${sqlLiteral(binding.actionEnvelopeHash)}
          AND julianday(json_extract(a.authorization_json, '$.expiresAt')) > julianday('now')
          AND json_extract(a.authorization_json, '$.authorizationHash') IS ${sqlLiteral(binding.approvalAuthorizationHash)}
          AND json_extract(a.authorization_json, '$.nonce') IS ${sqlLiteral(binding.approvalAuthorizationNonce)}
      )`;
  const receiptClause = binding.receiptId === null
    ? `${sqlLiteral(binding.receiptHash)} IS NULL AND EXISTS (
        SELECT 1 FROM tool_calls tc
        WHERE tc.id = ${sqlLiteral(record.toolCallId)}
          AND tc.action_envelope_hash IS ${sqlLiteral(binding.actionEnvelopeHash)}
          AND tc.input_hash IS ${sqlLiteral(record.inputHash)}
      )`
    : `EXISTS (
        SELECT 1 FROM action_receipts ar
        WHERE ar.id = ${sqlLiteral(binding.receiptId)}
          AND ar.workspace_id = ${sqlLiteral(record.workspaceId)}
          AND ar.tool_call_id = ${sqlLiteral(record.toolCallId)}
          AND ar.receipt_hash = ${sqlLiteral(binding.receiptHash)}
          AND ar.approved_envelope_hash = ${sqlLiteral(binding.actionEnvelopeHash)}
          AND ar.approved_input_hash = ${sqlLiteral(record.inputHash)}
          AND ar.approval_id IS ${sqlLiteral(binding.approvalId)}
      )`;
  return `${toolCallClause} AND ${approvalClause} AND ${receiptClause}`;
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

function sqliteJsonValueLiteral(value: unknown): string {
  if (value === undefined || value === null) return 'NULL';
  return typeof value === 'string' ? sqlLiteral(value) : sqlJsonLiteral(value);
}

function executionAttemptReservationIsStructurallyValid(record: ExecutionAttemptRecordV1): boolean {
  return (
    record.version === 'actionproxy.execution-attempt.v1' &&
    record.attemptNumber === 1 &&
    record.state === 'reserved' &&
    record.outcome === undefined &&
    record.dispatchedAt === undefined &&
    record.completedAt === undefined &&
    record.grantId === undefined &&
    Boolean(record.id) &&
    Boolean(record.reservationOwner) &&
    record.providerIdempotency === 'none' &&
    record.retryPolicy === 'never_automatic' &&
    ((record.executionMode === 'local_mock' && record.executorId === 'actionproxy.local-tool-registry') ||
      (record.executionMode === 'external_grant' && record.executorId === 'actionproxy.external-runner'))
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

function executionAttemptFromRow(row: SqliteRow): ExecutionAttemptRecordV1 {
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

function approvalFromRow(row: SqliteRow): ApprovalRecord {
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

function approvalDeliveryFromRow(row: SqliteRow): ApprovalDeliveryRecord {
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

function approverUserFromRow(row: SqliteRow): ApproverUserRecord {
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

function approverGroupFromRow(row: SqliteRow): ApproverGroupRecord {
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

function auditEventFromRow(row: SqliteRow): AuditEvent {
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

function workspaceFromRow(row: SqliteRow): WorkspaceRecord {
  return {
    createdAt: stringValue(row.created_at),
    id: stringValue(row.id),
    name: stringValue(row.name),
  };
}

function workspaceUserFromRow(row: SqliteRow): WorkspaceUserRecord {
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

function serviceAccountFromRow(row: SqliteRow): ServiceAccountRecord {
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

function apiKeyFromRow(row: SqliteRow): ApiKeyRecord {
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

function executionGrantFromRow(row: SqliteRow): ExecutionGrantRecord {
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

function actionReceiptFromRow(row: SqliteRow): ActionReceiptRecord {
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

function idempotencyFromRow(row: SqliteRow): IdempotencyRecord {
  return {
    createdAt: stringValue(row.created_at),
    key: stringValue(row.key),
    requestHash: stringValue(row.request_hash),
    route: stringValue(row.route),
    toolCallId: stringValue(row.tool_call_id),
    workspaceId: stringValue(row.workspace_id),
  };
}

function observedToolFromRow(row: SqliteRow): ObservedToolRecord {
  return {
    callCount: optionalNumber(row.call_count) ?? 0,
    coverage: parseJsonObject(row.coverage_json) as unknown as ObservedToolRecord['coverage'],
    createdAt: stringValue(row.created_at),
    firstSeenAt: stringValue(row.first_seen_at),
    id: stringValue(row.id),
    lastSeenAt: stringValue(row.last_seen_at),
    schemaChange: parseOptionalJsonObject(row.schema_change_json) as ObservedToolRecord['schemaChange'],
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

function sqliteAuthorizationGuardClause(guard: ApprovalAuthorizationGuard): string {
  const authorization = guard.authorization;
  const binding = authorization.binding;
  const eligibleGroups = sqlJsonLiteral(binding.requirements.eligibleGroups);
  const eligibleUsers = binding.requirements.eligibleUsers;
  const requestedPrincipal = binding.approval.requestedByPrincipalId;
  return `
    authorization_json = ${sqlJsonLiteral(authorization)}
    AND json_valid(authorization_json)
    AND authorization_consumed_at IS NULL
    AND workspace_id = ${sqlLiteral(binding.approval.tenantId)}
    AND tool_call_id = ${sqlLiteral(binding.approval.toolCallId)}
    AND requested_by = ${sqlLiteral(binding.approval.requestedBy)}
    AND json_extract(requested_by_auth_json, '$.principalId') IS ${sqlLiteral(requestedPrincipal ?? undefined)}
    AND original_input_json = ${sqlJsonLiteral(guard.originalInput)}
    AND original_input_hash = ${sqlLiteral(binding.action.originalInputHash)}
    AND original_envelope_hash = ${sqlLiteral(binding.action.originalEnvelopeHash)}
    AND review_hash = ${sqlLiteral(binding.action.reviewHash)}
    AND COALESCE(required_approvals, 1) = ${Math.max(1, binding.requirements.requiredApprovals)}
    AND COALESCE(separation_of_duties, 0) = ${binding.requirements.separationOfDuties ? 1 : 0}
    AND COALESCE((
      SELECT json_group_array(value)
      FROM (SELECT DISTINCT value FROM json_each(COALESCE(approver_groups_json, '[]')) ORDER BY value)
    ), '[]') = ${eligibleGroups}
    AND ${
      eligibleUsers === null
        ? 'approver_users_json IS NULL'
        : `COALESCE((
            SELECT json_group_array(value)
            FROM (SELECT DISTINCT value FROM json_each(COALESCE(approver_users_json, '[]')) ORDER BY value)
          ), '[]') = ${sqlJsonLiteral(eligibleUsers)}`
    }
    AND EXISTS (
      SELECT 1
      FROM tool_calls AS tc
      WHERE tc.id = approvals.tool_call_id
        AND tc.id = ${sqlLiteral(binding.approval.toolCallId)}
        AND tc.workspace_id = ${sqlLiteral(binding.approval.tenantId)}
        AND tc.status = 'pending_approval'
        AND tc.decision = ${sqlLiteral(binding.decision.outcome)}
        AND tc.input_hash = ${sqlLiteral(binding.action.originalInputHash)}
        AND tc.action_envelope_hash = ${sqlLiteral(binding.action.originalEnvelopeHash)}
        AND tc.policy_version_hash = ${sqlLiteral(guard.activePolicyVersionHash)}
        AND tc.policy_version_hash = ${sqlLiteral(binding.policy.legacyVersionHash)}
        AND tc.policy_version_id IS ${sqlLiteral(binding.policy.legacyVersionId ?? undefined)}
        AND tc.canonical_action_request_hash IS ${sqlLiteral(binding.request.requestHash ?? undefined)}
        AND tc.canonical_action_request_version IS ${sqlLiteral(binding.request.version ?? undefined)}
        AND COALESCE(
          tc.canonical_decision_input_hash,
          json_extract(tc.decision_trace_json, '$.decisionV1.decisionInputHash')
        ) IS ${sqlLiteral(binding.request.decisionInputHash ?? undefined)}
        AND json_extract(tc.decision_trace_json, '$.decisionV1.version') IS ${sqlLiteral(
          binding.decision.version ?? undefined,
        )}
        AND json_extract(tc.decision_trace_json, '$.decisionV1.decisionId') IS ${sqlLiteral(
          binding.decision.decisionId ?? undefined,
        )}
        AND json_extract(tc.decision_trace_json, '$.decisionV1.policy.digest') IS ${sqlLiteral(
          binding.policy.digest ?? undefined,
        )}
        AND json_extract(tc.decision_trace_json, '$.decisionV1.policy.version') IS ${sqlLiteral(
          binding.policy.version ?? undefined,
        )}
        AND json_extract(tc.decision_trace_json, '$.decisionV1.policy.provider.id') IS ${sqlLiteral(
          binding.policy.providerId ?? undefined,
        )}
        AND json_extract(tc.decision_trace_json, '$.decisionV1.policy.provider.version') IS ${sqlLiteral(
          binding.policy.providerVersion ?? undefined,
        )}
        AND json_extract(tc.decision_trace_json, '$.decisionV1.evaluatorVersion') IS ${sqlLiteral(
          binding.policy.evaluatorVersion ?? undefined,
        )}
    )
  `;
}

function sqliteOptionalAuthorizationGuardClause(guard: ApprovalAuthorizationGuard | undefined): string {
  return guard ? sqliteAuthorizationGuardClause(guard) : 'authorization_json IS NULL';
}

function sqliteAuthorizationNotExpiredClause(): string {
  return `julianday(json_extract(authorization_json, '$.expiresAt')) > julianday('now')`;
}

function sqliteOptionalAuthorizationNotExpiredClause(guard: ApprovalAuthorizationGuard | undefined): string {
  return guard ? sqliteAuthorizationNotExpiredClause() : '1 = 1';
}

function sqliteDecisionHistoryBindingClause(input: AtomicApprovalDecisionInput): string {
  const authorization = input.authorization.authorization;
  return `NOT EXISTS (
    SELECT 1
    FROM json_each(COALESCE(NULLIF(decisions_json, ''), '[]')) AS prior
    WHERE json_extract(prior.value, '$.authorizationVersion') IS NOT ${sqlLiteral(authorization.version)}
       OR json_extract(prior.value, '$.authorizationHash') IS NOT ${sqlLiteral(authorization.authorizationHash)}
       OR json_extract(prior.value, '$.authorizationNonce') IS NOT ${sqlLiteral(authorization.nonce)}
       OR json_extract(prior.value, '$.decisionId') IS NOT ${sqlLiteral(
         authorization.binding.decision.decisionId ?? undefined,
       )}
       OR json_extract(prior.value, '$.reviewHash') IS NOT ${sqlLiteral(authorization.binding.action.reviewHash)}
       OR json_extract(prior.value, '$.approvedInputHash') IS NOT ${sqlLiteral(input.approvedInputHash)}
       OR json_extract(prior.value, '$.approvedEnvelopeHash') IS NOT ${sqlLiteral(input.approvedEnvelopeHash)}
  )`;
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
