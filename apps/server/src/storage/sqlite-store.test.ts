import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ActionReceiptRecord, ApproverUserRecord, ApprovalDecisionRecord, ApprovalRecord, AuditEvent, ExecutionGrantRecord, ObservedToolRecord, ToolCallRecord } from '../models';
import { SqliteStore } from './sqlite-store';
import { deriveCanonicalPolicyContext } from '../contracts/action-request';
import { buildApprovalAuthorization, type ApprovalAuthorizationV1 } from '../contracts/approval-authorization';
import { hashJson } from '../security/crypto';
import type { ApprovalAuthorizationGuard } from './store';
import { ApproverPrincipalConflictError } from './approver-principal-constraint';

const describeIfSqlite = hasSqliteCli() ? describe : describe.skip;

function dbPath(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-sqlite-store-test-')), 'actionproxy.sqlite');
}

function toolCall(overrides: Partial<ToolCallRecord> = {}): ToolCallRecord {
  return {
    agentId: 'demo-agent',
    createdAt: '2026-06-18T10:00:00.000Z',
    decision: 'require_approval',
    id: 'toolcall_default',
    input: { to: 'customer@example.com' },
    metadata: {},
    reason: 'Send email',
    requestedBy: 'dev@example.com',
    risk: 'external_communication',
    status: 'pending_approval',
    toolName: 'gmail.send_email',
    updatedAt: '2026-06-18T10:00:00.000Z',
    ...overrides,
  };
}

function approval(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return {
    createdAt: '2026-06-18T10:00:00.000Z',
    id: 'approval_default',
    originalInput: { to: 'customer@example.com' },
    requestedBy: 'dev@example.com',
    status: 'pending',
    toolCallId: 'toolcall_default',
    updatedAt: '2026-06-18T10:00:00.000Z',
    ...overrides,
  };
}

function auditEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    actor: 'dev@example.com',
    data: { provider: 'test' },
    id: 'audit_default',
    timestamp: '2026-06-18T10:00:00.000Z',
    toolCallId: 'toolcall_default',
    type: 'approval.created',
    ...overrides,
  };
}

function approverUser(id: string, principalId?: string): ApproverUserRecord {
  return {
    createdAt: '2026-08-09T10:00:00.000Z',
    defaultApprover: false,
    displayName: id,
    enabled: true,
    groups: [],
    id,
    principalId,
    updatedAt: '2026-08-09T10:00:00.000Z',
    workspaceId: 'workspace-a',
  };
}

describeIfSqlite('SqliteStore', () => {
  it('persists authenticated approver principal mappings across restart', async () => {
    const databasePath = dbPath();
    const first = new SqliteStore(databasePath);
    await first.upsertApproverUser({
      createdAt: '2026-07-16T10:00:00.000Z',
      defaultApprover: true,
      displayName: 'Alice',
      enabled: true,
      groups: [],
      id: 'u_alice',
      principalId: 'oidc|alice',
      updatedAt: '2026-07-16T10:00:00.000Z',
      workspaceId: 'workspace-a',
    });

    const restarted = new SqliteStore(databasePath);
    await expect(restarted.getApproverUser('workspace-a', 'u_alice')).resolves.toMatchObject({
      id: 'u_alice',
      principalId: 'oidc|alice',
    });
  });

  it('atomically accepts only one approver principal binding across store instances', async () => {
    const databasePath = dbPath();
    const stores = [new SqliteStore(databasePath), new SqliteStore(databasePath)];
    const results = await Promise.allSettled([
      stores[0]!.upsertApproverUser(approverUser('u_alice', 'oidc|shared')),
      stores[1]!.upsertApproverUser(approverUser('u_bob', 'oidc|shared')),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result): result is PromiseRejectedResult => result.status === 'rejected');
    expect(rejected?.reason).toBeInstanceOf(ApproverPrincipalConflictError);
    await expect(stores[0]!.listApproverUsers('workspace-a')).resolves.toEqual([
      expect.objectContaining({ principalId: 'oidc|shared' }),
    ]);
  });

  it('atomically rejects a principal colliding with another user id fallback', async () => {
    const databasePath = dbPath();
    const stores = [new SqliteStore(databasePath), new SqliteStore(databasePath)];
    const results = await Promise.allSettled([
      stores[0]!.upsertApproverUser(approverUser('u_mapped', 'oidc|operator')),
      stores[1]!.upsertApproverUser(approverUser('oidc|operator')),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result): result is PromiseRejectedResult => result.status === 'rejected');
    expect(rejected?.reason).toBeInstanceOf(ApproverPrincipalConflictError);
    await expect(stores[0]!.listApproverUsers('workspace-a')).resolves.toHaveLength(1);
  });

  it('persists tool calls, approvals, and audit events across store instances', async () => {
    const databasePath = dbPath();
    const first = new SqliteStore(databasePath);

    await first.createToolCall(
      toolCall({
        canonicalActionRequestHash: 'canonical_request_hash',
        canonicalActionRequestVersion: 'actionproxy.action-request.v1',
        canonicalDecisionInputHash: 'canonical_decision_hash',
        canonicalPolicyContext: deriveCanonicalPolicyContext('gmail.send_email', { to: 'customer@example.com' }),
        decisionTrace: {
          approverResolution: { status: 'resolved_empty' },
          decision: 'require_approval',
          fallbackPath: ['exact'],
          matchType: 'exact',
          matchedRule: 'gmail.send_email',
          policyReason: 'Email requires approval.',
          policyRisk: 'external_communication',
          ruleEvaluations: [],
          toolName: 'gmail.send_email',
          decisionV1: {
            decisionId: 'decision_persisted',
            outcome: 'require_approval',
            version: 'actionproxy.decision.v1',
          },
        },
        id: 'toolcall_1',
      }),
    );
    await first.createApproval(approval({ id: 'approval_1', toolCallId: 'toolcall_1' }));
    const persistedAudit = auditEvent({ approvalId: 'approval_1', id: 'audit_1', toolCallId: 'toolcall_1' });
    await first.append(persistedAudit);
    await first.append(persistedAudit);

    const second = new SqliteStore(databasePath);

    await expect(second.getToolCall('toolcall_1')).resolves.toMatchObject({
      decisionTrace: {
        decision: 'require_approval',
        decisionV1: {
          decisionId: 'decision_persisted',
          outcome: 'require_approval',
          version: 'actionproxy.decision.v1',
        },
        matchedRule: 'gmail.send_email',
      },
      id: 'toolcall_1',
      input: { to: 'customer@example.com' },
      canonicalActionRequestHash: 'canonical_request_hash',
      canonicalActionRequestVersion: 'actionproxy.action-request.v1',
      canonicalDecisionInputHash: 'canonical_decision_hash',
      canonicalPolicyContext: {
        customerVisible: { present: false },
        recipientDomain: { present: true, value: 'external' },
      },
      status: 'pending_approval',
    });
    await expect(second.listPendingApprovals()).resolves.toMatchObject([
      { id: 'approval_1', toolCallId: 'toolcall_1' },
    ]);
    await expect(second.list(10)).resolves.toMatchObject([{ id: 'audit_1', type: 'approval.created' }]);
    await expect(second.list(10)).resolves.toHaveLength(1);
  });

  it('lists recent tool calls with filters and limits', async () => {
    const store = new SqliteStore(dbPath());

    await store.createToolCall(
      toolCall({
        createdAt: '2026-06-18T10:00:00.000Z',
        decision: 'allow',
        id: 'toolcall_docs',
        status: 'executed',
        toolName: 'docs.search',
      }),
    );
    await store.createToolCall(
      toolCall({
        createdAt: '2026-06-18T10:01:00.000Z',
        decision: 'deny',
        id: 'toolcall_delete',
        status: 'blocked',
        toolName: 'dangerous.delete_customer',
      }),
    );

    await expect(store.listToolCalls({ limit: 1 })).resolves.toMatchObject([{ id: 'toolcall_delete' }]);
    await expect(store.listToolCalls({ decision: 'allow' })).resolves.toMatchObject([{ id: 'toolcall_docs' }]);
    await expect(store.listToolCalls({ status: 'blocked' })).resolves.toMatchObject([{ id: 'toolcall_delete' }]);
  });

  it('persists observed tools across store instances', async () => {
    const databasePath = dbPath();
    const first = new SqliteStore(databasePath);
    await first.upsertObservedTool(observedTool({ id: 'observed_1', toolName: 'crm.search_accounts' }));

    const second = new SqliteStore(databasePath);

    await expect(second.getObservedToolByName('default', 'crm.search_accounts')).resolves.toMatchObject({
      coverage: { status: 'uncovered' },
      suggestion: { approval: 'never', risk: 'read_only' },
      toolName: 'crm.search_accounts',
    });
    await expect(second.listObservedTools('default')).resolves.toMatchObject([{ id: 'observed_1' }]);
  });

  it('persists action receipts and recorded outcomes across store instances', async () => {
    const databasePath = dbPath();
    const first = new SqliteStore(databasePath);
    await first.createActionReceipt(actionReceipt({ id: 'receipt_1', toolCallId: 'toolcall_receipt' }));

    const second = new SqliteStore(databasePath);
    const fetched = await second.getActionReceipt('receipt_1');
    expect(fetched).toMatchObject({
      id: 'receipt_1',
      approvedInputHash: 'input_hash_approved',
      receiptHash: 'receipt_hash_1',
    });

    await second.updateActionReceipt({
      ...fetched!,
      outcome: {
        recordedAt: '2026-06-18T10:05:00.000Z',
        recordedBy: 'runner',
        result: { ok: true },
        status: 'succeeded',
      },
    });

    const third = new SqliteStore(databasePath);
    await expect(third.getActionReceiptByToolCallId('toolcall_receipt')).resolves.toMatchObject({
      id: 'receipt_1',
      outcome: { result: { ok: true }, status: 'succeeded' },
    });
  });

  it('lists execution grants with workspace filters and limits', async () => {
    const store = new SqliteStore(dbPath());
    await store.createExecutionGrant(executionGrant({ createdAt: '2026-06-18T10:00:00.000Z', id: 'grant_old' }));
    await store.createExecutionGrant(executionGrant({ createdAt: '2026-06-18T10:01:00.000Z', id: 'grant_new' }));
    await store.createExecutionGrant(
      executionGrant({ createdAt: '2026-06-18T10:02:00.000Z', id: 'grant_other', workspaceId: 'other' }),
    );

    await expect(store.listExecutionGrants({ limit: 2 })).resolves.toMatchObject([
      { id: 'grant_other' },
      { id: 'grant_new' },
    ]);
    await expect(store.listExecutionGrants({ workspaceId: 'default' })).resolves.toMatchObject([
      { id: 'grant_new' },
      { id: 'grant_old' },
    ]);
  });

  it('atomically finalizes one concurrent approval and consumes a grant once across store instances', async () => {
    const databasePath = dbPath();
    const stores = [new SqliteStore(databasePath), new SqliteStore(databasePath)];
    const fixture = authorizedApproval({ requiredApprovals: 1 });
    await stores[0]!.createToolCall(fixture.toolCall);
    await stores[0]!.createApproval(fixture.approval);
    await stores[0]!.createExecutionGrant(executionGrant());

    const approvalResults = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        stores[index % stores.length]!.recordApprovalDecisionAtomically({
          approvalId: 'approval_default',
          authorization: fixture.guard,
          approvedEnvelopeHash: 'approved_envelope_hash',
          approvedInputHash: 'approved_input_hash',
          decision: approvalDecision(`approver-${index}`, fixture.authorization),
          reviewHash: 'review_hash',
          updatedAt: `2026-06-18T10:00:${String(index).padStart(2, '0')}.000Z`,
        }),
      ),
    );
    const grantResults = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        stores[index % stores.length]!.consumeExecutionGrantAtomically(
          'grant_default',
          `2026-06-18T10:01:${String(index).padStart(2, '0')}.000Z`,
        ),
      ),
    );

    expect(approvalResults.filter((result) => result.outcome === 'finalized')).toHaveLength(1);
    expect(approvalResults.filter((result) => result.outcome === 'replayed')).toHaveLength(11);
    await expect(stores[1]!.getApproval('approval_default')).resolves.toMatchObject({
      decisions: [expect.objectContaining({ actor: expect.stringMatching(/^approver-/) })],
      status: 'approved',
    });
    expect(grantResults.filter(Boolean)).toHaveLength(1);
    await expect(stores[1]!.getExecutionGrant('grant_default')).resolves.toMatchObject({
      consumedAt: expect.any(String),
    });
  });

  it('persists authorization state and atomically rejects mutation, expiry, replay, and cancel races', async () => {
    const databasePath = dbPath();
    const stores = [new SqliteStore(databasePath), new SqliteStore(databasePath)];
    const fixture = authorizedApproval({ id: 'approval_secure', toolCallId: 'toolcall_secure' });
    await stores[0]!.createToolCall(fixture.toolCall);
    await stores[0]!.createApproval(fixture.approval);
    await expect(stores[1]!.getApproval(fixture.approval.id)).resolves.toMatchObject({
      authorization: {
        authorizationHash: fixture.authorization.authorizationHash,
        nonce: fixture.authorization.nonce,
        version: 'actionproxy.approval-authorization.v1',
      },
    });

    const input = approvalDecisionInput(fixture, 'approver-a');
    await expect(stores[0]!.recordApprovalDecisionAtomically(input)).resolves.toMatchObject({ outcome: 'finalized' });
    await expect(stores[1]!.recordApprovalDecisionAtomically(input)).resolves.toMatchObject({ outcome: 'replayed' });

    const mutated = authorizedApproval({ id: 'approval_mutated', toolCallId: 'toolcall_mutated' });
    await stores[0]!.createToolCall(mutated.toolCall);
    await stores[0]!.createApproval({ ...mutated.approval, originalInput: { to: 'attacker@example.com' } });
    await expect(
      stores[1]!.recordApprovalDecisionAtomically(approvalDecisionInput(mutated, 'approver-a')),
    ).resolves.toMatchObject({ outcome: 'authorization_mismatch' });

    const expired = authorizedApproval({
      expiresAt: '2001-01-01T00:00:00.000Z',
      id: 'approval_expired',
      issuedAt: '2000-01-01T00:00:00.000Z',
      toolCallId: 'toolcall_expired',
    });
    await stores[0]!.createToolCall(expired.toolCall);
    await stores[0]!.createApproval(expired.approval);
    await expect(
      stores[1]!.recordApprovalDecisionAtomically(approvalDecisionInput(expired, 'approver-a')),
    ).resolves.toMatchObject({ approval: { status: 'expired' }, outcome: 'expired' });

    const raced = authorizedApproval({ id: 'approval_race', toolCallId: 'toolcall_race' });
    await stores[0]!.createToolCall(raced.toolCall);
    await stores[0]!.createApproval(raced.approval);
    const results = await Promise.all([
      stores[0]!.recordApprovalDecisionAtomically(approvalDecisionInput(raced, 'approver-a')),
      stores[1]!.cancelApprovalAtomically({
        approvalId: raced.approval.id,
        authorization: raced.guard,
        cancelledBy: 'requester',
        updatedAt: '2026-07-11T10:00:01.000Z',
      }),
    ]);
    expect(results.filter((result) => result.outcome === 'finalized' || result.outcome === 'cancelled')).toHaveLength(1);
    await expect(stores[0]!.getApproval(raced.approval.id)).resolves.toMatchObject({
      status: expect.stringMatching(/^(approved|cancelled)$/),
    });
  });

  it('keeps approval pending when the guarded exposure revision changes', async () => {
    const databasePath = dbPath();
    const stores = [new SqliteStore(databasePath), new SqliteStore(databasePath)];
    const fixture = authorizedApproval({ id: 'approval_influence', toolCallId: 'toolcall_influence' });
    const scopeId = `influence_${'b'.repeat(64)}`;
    await stores[0]!.createToolCall(fixture.toolCall);
    await stores[0]!.createApproval(fixture.approval);
    for (const [index, integrity] of (['organization_managed', 'public_untrusted'] as const).entries()) {
      await stores[index]!.recordContentExposure({
        influenceScopeId: scopeId,
        integrity,
        observedAt: `2026-07-15T00:00:0${index}.000Z`,
        policyVersionHash: 'policy_hash',
        sourceToolCallId: `source_${index}`,
        workspaceId: 'default',
      });
    }

    await expect(stores[0]!.recordApprovalDecisionAtomically({
      ...approvalDecisionInput(fixture, 'approver-a'),
      contentExposureRevision: { influenceScopeId: scopeId, revision: 1 },
    })).resolves.toMatchObject({ approval: { status: 'pending' }, outcome: 'content_influence_mismatch' });
  });
});

function approvalDecision(actor: string, authorization: ApprovalAuthorizationV1): ApprovalDecisionRecord {
  return {
    actor,
    authorizationHash: authorization.authorizationHash,
    authorizationNonce: authorization.nonce,
    authorizationVersion: authorization.version,
    approvedEnvelopeHash: 'approved_envelope_hash',
    approvedInputHash: 'approved_input_hash',
    decisionId: authorization.binding.decision.decisionId ?? undefined,
    decidedAt: '2026-06-18T10:00:00.000Z',
    inputDecision: 'original',
    reviewHash: 'review_hash',
  };
}

function approvalDecisionInput(
  fixture: ReturnType<typeof authorizedApproval>,
  actor: string,
) {
  return {
    approvalId: fixture.approval.id,
    authorization: fixture.guard,
    approvedEnvelopeHash: 'approved_envelope_hash',
    approvedInputHash: 'approved_input_hash',
    decision: approvalDecision(actor, fixture.authorization),
    reviewHash: 'review_hash',
    updatedAt: '2026-07-11T10:00:00.000Z',
  };
}

function authorizedApproval(
  overrides: Partial<ApprovalRecord> & { expiresAt?: string; issuedAt?: string } = {},
): {
  approval: ApprovalRecord;
  authorization: ApprovalAuthorizationV1;
  guard: ApprovalAuthorizationGuard;
  toolCall: ToolCallRecord;
} {
  const {
    expiresAt = '2999-01-01T00:00:00.000Z',
    issuedAt = '2026-01-01T00:00:00.000Z',
    ...recordOverrides
  } = overrides;
  const originalInput = recordOverrides.originalInput ?? { to: 'customer@example.com' };
  const id = recordOverrides.id ?? 'approval_default';
  const toolCallId = recordOverrides.toolCallId ?? 'toolcall_default';
  const toolCallRecord = toolCall({
    actionEnvelopeHash: 'original_envelope_hash',
    id: toolCallId,
    input: originalInput,
    inputHash: hashJson(originalInput),
    policyVersionHash: 'policy_hash_1',
    status: 'pending_approval',
    workspaceId: 'default',
  });
  const baseApproval = approval({
    ...recordOverrides,
    id,
    originalEnvelopeHash: 'original_envelope_hash',
    originalInput,
    originalInputHash: hashJson(originalInput),
    reviewHash: 'review_hash',
    toolCallId,
    workspaceId: 'default',
  });
  const authorization = buildApprovalAuthorization({
    approvalId: id,
    approverGroups: baseApproval.approverGroups,
    approverUsers: baseApproval.approverUsers,
    expiresAt,
    issuedAt,
    nonce: `nonce_${id}`,
    originalEnvelopeHash: baseApproval.originalEnvelopeHash!,
    originalInputHash: baseApproval.originalInputHash!,
    requestedBy: baseApproval.requestedBy,
    requiredApprovals: baseApproval.requiredApprovals,
    reviewHash: baseApproval.reviewHash!,
    separationOfDuties: baseApproval.separationOfDuties,
    toolCall: toolCallRecord,
  });
  return {
    approval: { ...baseApproval, authorization },
    authorization,
    guard: { activePolicyVersionHash: 'policy_hash_1', authorization, originalInput },
    toolCall: toolCallRecord,
  };
}

function hasSqliteCli(): boolean {
  try {
    execFileSync('sqlite3', ['-version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function observedTool(overrides: Partial<ObservedToolRecord> = {}): ObservedToolRecord {
  return {
    callCount: 1,
    coverage: {
      approval: 'required',
      decision: 'require_approval',
      matchedRule: 'default',
      matchType: 'default',
      reason: 'Unknown tools require approval.',
      risk: 'unknown',
      status: 'uncovered',
    },
    createdAt: '2026-06-20T10:00:00.000Z',
    firstSeenAt: '2026-06-20T10:00:00.000Z',
    id: 'observed_default',
    lastSeenAt: '2026-06-20T10:00:00.000Z',
    schemaHash: 'schema_1',
    sourceIds: { agentIds: ['agent_1'] },
    sources: ['runtime'],
    status: 'unresolved',
    suggestion: {
      approval: 'never',
      confidence: 'medium',
      pattern: 'crm.search_accounts',
      patternType: 'exact',
      reason: 'Read-only tools can usually run without approval.',
      risk: 'read_only',
    },
    toolName: 'crm.search_accounts',
    updatedAt: '2026-06-20T10:00:00.000Z',
    workspaceId: 'default',
    ...overrides,
  };
}

function actionReceipt(overrides: Partial<ActionReceiptRecord> = {}): ActionReceiptRecord {
  return {
    approvedEnvelopeHash: 'envelope_hash_approved',
    approvedInputHash: 'input_hash_approved',
    createdAt: '2026-06-18T10:00:00.000Z',
    decisionActor: 'manager@example.com',
    decisionKind: 'human_approval',
    executionMode: 'external_grant',
    id: 'receipt_default',
    issuedAt: '2026-06-18T10:00:00.000Z',
    keyId: 'actionproxy-local-hmac-v1',
    operation: { kind: 'external_send', name: 'gmail.send_email' },
    originalEnvelopeHash: 'envelope_hash_original',
    originalInputHash: 'input_hash_original',
    policyDecision: 'require_approval',
    policyReason: 'Email requires approval.',
    policyRisk: 'external',
    policyVersionHash: 'policy_hash_1',
    protocol: 'actionproxy_http',
    receiptHash: 'receipt_hash_1',
    signature: 'signature_1',
    signatureAlg: 'HMAC-SHA256',
    source: { name: 'sdk', type: 'sdk' },
    toolCallId: 'toolcall_default',
    toolName: 'gmail.send_email',
    version: 'actionproxy.receipt.v1',
    workspaceId: 'default',
    ...overrides,
  };
}

function executionGrant(overrides: Partial<ExecutionGrantRecord> = {}): ExecutionGrantRecord {
  return {
    actor: 'dev@example.com',
    approvedEnvelopeHash: 'envelope_hash_approved',
    approvedInputHash: 'input_hash_approved',
    createdAt: '2026-06-18T10:00:00.000Z',
    expiresAt: '2999-06-18T10:00:00.000Z',
    id: 'grant_default',
    inputHash: 'input_hash_approved',
    nonce: 'nonce_1',
    policyVersionHash: 'policy_hash_1',
    receiptHash: 'receipt_hash_1',
    receiptId: 'receipt_1',
    signature: 'signature_1',
    toolCallId: 'toolcall_default',
    toolName: 'docs.search',
    workspaceId: 'default',
    ...overrides,
  };
}
