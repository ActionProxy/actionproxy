import { describe, expect, it } from 'vitest';
import type { ApproverUserRecord, ApprovalDecisionRecord, ApprovalRecord, ExecutionGrantRecord, ObservedToolRecord, ToolCallRecord } from '../models';
import { buildApprovalAuthorization, type ApprovalAuthorizationV1 } from '../contracts/approval-authorization';
import { hashJson } from '../security/crypto';
import { MemoryStore } from './memory-store';
import type { ApprovalAuthorizationGuard } from './store';
import { ApproverPrincipalConflictError } from './approver-principal-constraint';

function toolCall(overrides: Partial<ToolCallRecord>): ToolCallRecord {
  return {
    agentId: 'demo-agent',
    createdAt: '2026-06-17T10:00:00.000Z',
    id: 'toolcall_default',
    input: {},
    metadata: {},
    reason: 'Test call',
    requestedBy: 'dev@example.com',
    status: 'submitted',
    toolName: 'docs.search',
    updatedAt: '2026-06-17T10:00:00.000Z',
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

describe('MemoryStore', () => {
  it('preserves authenticated approver principal mappings', async () => {
    const store = new MemoryStore();
    await store.upsertApproverUser({
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

    await expect(store.getApproverUser('workspace-a', 'u_alice')).resolves.toMatchObject({
      id: 'u_alice',
      principalId: 'oidc|alice',
    });
  });

  it('atomically accepts only one concurrent approver principal binding', async () => {
    const store = new MemoryStore();
    const results = await Promise.allSettled([
      store.upsertApproverUser(approverUser('u_alice', 'oidc|shared')),
      store.upsertApproverUser(approverUser('u_bob', 'oidc|shared')),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result): result is PromiseRejectedResult => result.status === 'rejected');
    expect(rejected?.reason).toBeInstanceOf(ApproverPrincipalConflictError);
    await expect(store.listApproverUsers('workspace-a')).resolves.toEqual([
      expect.objectContaining({ principalId: 'oidc|shared' }),
    ]);
  });

  it('atomically rejects a principal colliding with another user id fallback', async () => {
    const store = new MemoryStore();
    const results = await Promise.allSettled([
      store.upsertApproverUser(approverUser('u_mapped', 'oidc|operator')),
      store.upsertApproverUser(approverUser('oidc|operator')),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result): result is PromiseRejectedResult => result.status === 'rejected');
    expect(rejected?.reason).toBeInstanceOf(ApproverPrincipalConflictError);
    await expect(store.listApproverUsers('workspace-a')).resolves.toHaveLength(1);
  });

  it('lists recent tool calls with filters and limits', async () => {
    const store = new MemoryStore();

    await store.createToolCall(
      toolCall({
        createdAt: '2026-06-17T10:00:00.000Z',
        decision: 'allow',
        id: 'toolcall_docs',
        status: 'executed',
        toolName: 'docs.search',
      }),
    );
    await store.createToolCall(
      toolCall({
        createdAt: '2026-06-17T10:01:00.000Z',
        decision: 'require_approval',
        id: 'toolcall_email',
        status: 'pending_approval',
        toolName: 'gmail.send_email',
      }),
    );
    await store.createToolCall(
      toolCall({
        createdAt: '2026-06-17T10:02:00.000Z',
        decision: 'deny',
        id: 'toolcall_delete',
        status: 'blocked',
        toolName: 'dangerous.delete_customer',
      }),
    );

    await expect(store.listToolCalls({ limit: 2 })).resolves.toMatchObject([
      { id: 'toolcall_delete' },
      { id: 'toolcall_email' },
    ]);
    await expect(store.listToolCalls({ status: 'executed' })).resolves.toMatchObject([{ id: 'toolcall_docs' }]);
    await expect(store.listToolCalls({ decision: 'deny' })).resolves.toMatchObject([{ id: 'toolcall_delete' }]);
    await expect(store.listToolCalls({ toolName: 'gmail.send_email' })).resolves.toMatchObject([{ id: 'toolcall_email' }]);
  });

  it('preserves stored decision traces on tool calls', async () => {
    const store = new MemoryStore();
    await store.createToolCall(
      toolCall({
        decision: 'require_approval',
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
        },
        id: 'toolcall_trace',
        toolName: 'gmail.send_email',
      }),
    );

    await expect(store.getToolCall('toolcall_trace')).resolves.toMatchObject({
      decisionTrace: {
        decision: 'require_approval',
        matchedRule: 'gmail.send_email',
      },
    });
  });

  it('upserts and lists observed tools by workspace', async () => {
    const store = new MemoryStore();
    await store.upsertObservedTool(observedTool({ toolName: 'crm.search_accounts' }));
    await store.upsertObservedTool(observedTool({ id: 'observed_other', toolName: 'crm.delete_customer', workspaceId: 'other' }));

    await expect(store.getObservedToolByName('default', 'crm.search_accounts')).resolves.toMatchObject({
      toolName: 'crm.search_accounts',
    });
    await expect(store.listObservedTools('default')).resolves.toMatchObject([{ toolName: 'crm.search_accounts' }]);
  });

  it('lists execution grants with workspace filters and limits', async () => {
    const store = new MemoryStore();
    await store.createExecutionGrant(executionGrant({ createdAt: '2026-06-17T10:00:00.000Z', id: 'grant_old' }));
    await store.createExecutionGrant(executionGrant({ createdAt: '2026-06-17T10:01:00.000Z', id: 'grant_new' }));
    await store.createExecutionGrant(
      executionGrant({ createdAt: '2026-06-17T10:02:00.000Z', id: 'grant_other', workspaceId: 'other' }),
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

  it('atomically finalizes one concurrent approval and consumes a grant once', async () => {
    const store = new MemoryStore();
    const fixture = authorizedApproval({ requiredApprovals: 1 });
    await store.createToolCall(fixture.toolCall);
    await store.createApproval(fixture.approval);
    await store.createExecutionGrant(executionGrant());

    const approvalResults = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        store.recordApprovalDecisionAtomically({
          approvalId: 'approval_default',
          authorization: fixture.guard,
          approvedEnvelopeHash: 'approved_envelope_hash',
          approvedInputHash: 'approved_input_hash',
          decision: approvalDecision(`approver-${index}`, fixture.authorization),
          reviewHash: 'review_hash',
          updatedAt: `2026-06-17T10:00:${String(index).padStart(2, '0')}.000Z`,
        }),
      ),
    );
    const grantResults = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        store.consumeExecutionGrantAtomically(
          'grant_default',
          `2026-06-17T10:01:${String(index).padStart(2, '0')}.000Z`,
        ),
      ),
    );

    expect(approvalResults.filter((result) => result.outcome === 'finalized')).toHaveLength(1);
    expect(approvalResults.filter((result) => result.outcome === 'replayed')).toHaveLength(11);
    await expect(store.getApproval('approval_default')).resolves.toMatchObject({
      decisions: [expect.objectContaining({ actor: expect.stringMatching(/^approver-/) })],
      status: 'approved',
    });
    expect(grantResults.filter(Boolean)).toHaveLength(1);
    await expect(store.getExecutionGrant('grant_default')).resolves.toMatchObject({
      consumedAt: expect.any(String),
    });
  });

  it('fails closed on replay, mutation, expiry, and an approve-cancel race', async () => {
    const store = new MemoryStore();
    const replay = authorizedApproval({ id: 'approval_replay', toolCallId: 'toolcall_replay' });
    await store.createToolCall(replay.toolCall);
    await store.createApproval(replay.approval);
    const decisionInput = {
      approvalId: replay.approval.id,
      authorization: replay.guard,
      approvedEnvelopeHash: 'approved_envelope_hash',
      approvedInputHash: 'approved_input_hash',
      decision: approvalDecision('approver-a', replay.authorization),
      reviewHash: 'review_hash',
      updatedAt: '2026-07-11T10:00:00.000Z',
    };
    await expect(store.recordApprovalDecisionAtomically(decisionInput)).resolves.toMatchObject({ outcome: 'finalized' });
    await expect(store.recordApprovalDecisionAtomically(decisionInput)).resolves.toMatchObject({ outcome: 'replayed' });

    const mutated = authorizedApproval({ id: 'approval_mutated', toolCallId: 'toolcall_mutated' });
    await store.createToolCall(mutated.toolCall);
    await store.createApproval({ ...mutated.approval, originalInput: { to: 'attacker@example.com' } });
    await expect(
      store.recordApprovalDecisionAtomically({
        ...decisionInput,
        approvalId: mutated.approval.id,
        authorization: mutated.guard,
        decision: approvalDecision('approver-a', mutated.authorization),
      }),
    ).resolves.toMatchObject({ outcome: 'authorization_mismatch' });

    const expired = authorizedApproval({
      expiresAt: '2001-01-01T00:00:00.000Z',
      id: 'approval_expired',
      issuedAt: '2000-01-01T00:00:00.000Z',
      toolCallId: 'toolcall_expired',
    });
    await store.createToolCall(expired.toolCall);
    await store.createApproval(expired.approval);
    await expect(
      store.recordApprovalDecisionAtomically({
        ...decisionInput,
        approvalId: expired.approval.id,
        authorization: expired.guard,
        decision: approvalDecision('approver-a', expired.authorization),
      }),
    ).resolves.toMatchObject({ approval: { status: 'expired' }, outcome: 'expired' });

    const raced = authorizedApproval({ id: 'approval_race', toolCallId: 'toolcall_race' });
    await store.createToolCall(raced.toolCall);
    await store.createApproval(raced.approval);
    const results = await Promise.all([
      store.recordApprovalDecisionAtomically({
        ...decisionInput,
        approvalId: raced.approval.id,
        authorization: raced.guard,
        decision: approvalDecision('approver-a', raced.authorization),
      }),
      store.cancelApprovalAtomically({
        approvalId: raced.approval.id,
        authorization: raced.guard,
        cancelledBy: 'requester',
        updatedAt: '2026-07-11T10:00:01.000Z',
      }),
    ]);
    expect(results.filter((result) => result.outcome === 'finalized' || result.outcome === 'cancelled')).toHaveLength(1);
    await expect(store.getApproval(raced.approval.id)).resolves.toMatchObject({
      status: expect.stringMatching(/^(approved|cancelled)$/),
    });
  });

  it('keeps approval pending when the guarded exposure revision changes', async () => {
    const store = new MemoryStore();
    const fixture = authorizedApproval({ id: 'approval_influence', toolCallId: 'toolcall_influence' });
    const scopeId = `influence_${'a'.repeat(64)}`;
    await store.createToolCall(fixture.toolCall);
    await store.createApproval(fixture.approval);
    await store.recordContentExposure({
      influenceScopeId: scopeId,
      integrity: 'organization_managed',
      observedAt: '2026-07-15T00:00:00.000Z',
      policyVersionHash: 'policy_hash',
      sourceToolCallId: 'source_1',
      workspaceId: 'default',
    });
    await store.recordContentExposure({
      influenceScopeId: scopeId,
      integrity: 'public_untrusted',
      observedAt: '2026-07-15T00:00:01.000Z',
      policyVersionHash: 'policy_hash',
      sourceToolCallId: 'source_2',
      workspaceId: 'default',
    });

    await expect(store.recordApprovalDecisionAtomically({
      approvalId: fixture.approval.id,
      authorization: fixture.guard,
      approvedEnvelopeHash: 'approved_envelope_hash',
      approvedInputHash: 'approved_input_hash',
      contentExposureRevision: { influenceScopeId: scopeId, revision: 1 },
      decision: approvalDecision('approver-a', fixture.authorization),
      reviewHash: 'review_hash',
      updatedAt: '2026-07-15T00:00:02.000Z',
    })).resolves.toMatchObject({ approval: { status: 'pending' }, outcome: 'content_influence_mismatch' });
  });
});

function approval(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return {
    createdAt: '2026-06-17T10:00:00.000Z',
    id: 'approval_default',
    originalInput: { to: 'customer@example.com' },
    requestedBy: 'dev@example.com',
    status: 'pending',
    toolCallId: 'toolcall_default',
    updatedAt: '2026-06-17T10:00:00.000Z',
    ...overrides,
  };
}

function approvalDecision(actor: string, authorization: ApprovalAuthorizationV1): ApprovalDecisionRecord {
  return {
    actor,
    authorizationHash: authorization.authorizationHash,
    authorizationNonce: authorization.nonce,
    authorizationVersion: authorization.version,
    approvedEnvelopeHash: 'approved_envelope_hash',
    approvedInputHash: 'approved_input_hash',
    decisionId: authorization.binding.decision.decisionId ?? undefined,
    decidedAt: '2026-06-17T10:00:00.000Z',
    inputDecision: 'original',
    reviewHash: 'review_hash',
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
  const { expiresAt = '2999-01-01T00:00:00.000Z', issuedAt = '2026-01-01T00:00:00.000Z', ...recordOverrides } = overrides;
  const originalInput = recordOverrides.originalInput ?? { to: 'customer@example.com' };
  const id = recordOverrides.id ?? 'approval_default';
  const toolCallId = recordOverrides.toolCallId ?? 'toolcall_default';
  const toolCallRecord = toolCall({
    actionEnvelopeHash: 'original_envelope_hash',
    decision: 'require_approval',
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
  const approvalRecord = { ...baseApproval, authorization };
  return {
    approval: approvalRecord,
    authorization,
    guard: { activePolicyVersionHash: 'policy_hash_1', authorization, originalInput },
    toolCall: toolCallRecord,
  };
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

function executionGrant(overrides: Partial<ExecutionGrantRecord> = {}): ExecutionGrantRecord {
  return {
    actor: 'dev@example.com',
    approvedEnvelopeHash: 'envelope_hash_approved',
    approvedInputHash: 'input_hash_approved',
    createdAt: '2026-06-17T10:00:00.000Z',
    expiresAt: '2999-06-17T10:00:00.000Z',
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
