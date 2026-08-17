import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type {
  ActionReceiptRecord,
  ApproverUserRecord,
  ApprovalDecisionRecord,
  ApprovalRecord,
  ExecutionGrantRecord,
  IdempotencyRecord,
  ToolCallRecord,
} from '../models';
import { PostgresStore } from './postgres-store';
import { deriveCanonicalPolicyContext } from '../contracts/action-request';
import { buildApprovalAuthorization, type ApprovalAuthorizationV1 } from '../contracts/approval-authorization';
import { buildContentInfluenceEvidence } from '../contracts/content-influence';
import { buildExecutionAttempt, executionAttemptOutcome } from '../contracts/execution-attempt';
import { createExecutionAuthorizationAuthority } from '../contracts/execution-authorization';
import { hashJson } from '../security/crypto';
import type { ApprovalAuthorizationGuard, Store } from './store';
import { ActionProxyService } from '../services/action-gate';
import { ToolRegistry } from '../services/tool-registry';
import type { AuditStore } from './audit-store';
import { ApproverPrincipalConflictError } from './approver-principal-constraint';

const databaseUrl = process.env.ACTIONPROXY_TEST_POSTGRES_URL;
const describeIfPostgres = databaseUrl ? describe : describe.skip;
const testExecutionAuthorizations = createExecutionAuthorizationAuthority();

function newTestToolRegistry(): ToolRegistry {
  return new ToolRegistry(testExecutionAuthorizations);
}

describeIfPostgres('PostgresStore atomicity contract', () => {
  const stores: PostgresStore[] = [];

  beforeAll(async () => {
    stores.push(await PostgresStore.connect(databaseUrl!), await PostgresStore.connect(databaseUrl!));
  });

  afterAll(async () => {
    await Promise.all(stores.map((store) => store.close()));
  });

  it('persists authenticated approver principal mappings across Postgres pools', async () => {
    const suffix = randomUUID();
    const id = `u_principal_${suffix}`;
    const workspaceId = `workspace_principal_${suffix}`;
    await stores[0]!.upsertApproverUser({
      createdAt: '2026-07-16T10:00:00.000Z',
      defaultApprover: true,
      displayName: 'Alice',
      enabled: true,
      groups: [],
      id,
      principalId: `oidc|alice|${suffix}`,
      updatedAt: '2026-07-16T10:00:00.000Z',
      workspaceId,
    });

    await expect(stores[1]!.getApproverUser(workspaceId, id)).resolves.toMatchObject({
      id,
      principalId: `oidc|alice|${suffix}`,
    });
  });

  it('atomically accepts only one approver principal binding across Postgres pools', async () => {
    const suffix = randomUUID();
    const workspaceId = `workspace_principal_race_${suffix}`;
    const principalId = `oidc|shared|${suffix}`;
    const results = await Promise.allSettled([
      stores[0]!.upsertApproverUser(approverUser('u_alice', workspaceId, principalId)),
      stores[1]!.upsertApproverUser(approverUser('u_bob', workspaceId, principalId)),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result): result is PromiseRejectedResult => result.status === 'rejected');
    expect(rejected?.reason).toBeInstanceOf(ApproverPrincipalConflictError);
    await expect(stores[0]!.listApproverUsers(workspaceId)).resolves.toEqual([
      expect.objectContaining({ principalId }),
    ]);
  });

  it('atomically rejects a principal colliding with another user id fallback', async () => {
    const suffix = randomUUID();
    const workspaceId = `workspace_effective_identity_race_${suffix}`;
    const effectiveIdentity = `oidc|operator|${suffix}`;
    const results = await Promise.allSettled([
      stores[0]!.upsertApproverUser(
        approverUser(`u_mapped_${suffix}`, workspaceId, effectiveIdentity),
      ),
      stores[1]!.upsertApproverUser(
        approverUser(effectiveIdentity, workspaceId),
      ),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result): result is PromiseRejectedResult => result.status === 'rejected');
    expect(rejected?.reason).toBeInstanceOf(ApproverPrincipalConflictError);
    await expect(stores[0]!.listApproverUsers(workspaceId)).resolves.toHaveLength(1);
  });

  it('produces one approval finalization and one grant consumption across store instances', async () => {
    const suffix = randomUUID();
    const approvalId = `approval_${suffix}`;
    const grantId = `grant_${suffix}`;
    const fixture = authorizedApproval({
      id: approvalId,
      requiredApprovals: 1,
      toolCallId: `toolcall_${suffix}`,
    });
    await stores[0]!.createToolCall(fixture.toolCall);
    await stores[0]!.createApproval(fixture.approval);
    await stores[0]!.createExecutionGrant(executionGrant({ id: grantId }));

    const approvalResults = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        stores[index % stores.length]!.recordApprovalDecisionAtomically({
          approvalId,
          authorization: fixture.guard,
          approvedEnvelopeHash: 'approved_envelope_hash',
          approvedInputHash: 'approved_input_hash',
          decision: decision(`approver-${index}`, fixture.authorization),
          reviewHash: 'review_hash',
          updatedAt: `2026-07-10T10:00:${String(index).padStart(2, '0')}.000Z`,
        }),
      ),
    );
    const grantResults = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        stores[index % stores.length]!.consumeExecutionGrantAtomically(
          grantId,
          `2026-07-10T10:01:${String(index).padStart(2, '0')}.000Z`,
        ),
      ),
    );

    expect(approvalResults.filter((result) => result.outcome === 'finalized')).toHaveLength(1);
    expect(approvalResults.filter((result) => result.outcome === 'replayed')).toHaveLength(11);
    await expect(stores[1]!.getApproval(approvalId)).resolves.toMatchObject({
      decisions: [expect.objectContaining({ actor: expect.stringMatching(/^approver-/) })],
      status: 'approved',
    });
    expect(grantResults.filter(Boolean)).toHaveLength(1);
  });

  it('records one immutable receipt outcome across Postgres pools', async () => {
    const id = `receipt_outcome_${randomUUID()}`;
    const receipt = actionReceipt(id);
    await stores[0]!.createActionReceipt(receipt);

    const results = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        stores[index % stores.length]!.recordActionReceiptOutcomeAtomically({
          outcome: {
            recordedAt: '2026-07-12T08:30:00.000Z',
            recordedBy: `runner-${index}`,
            result: { providerRequestId: 'provider_1' },
            status: 'succeeded',
          },
          receiptId: id,
        }),
      ),
    );

    expect(results.filter((result) => result.outcome === 'recorded')).toHaveLength(1);
    expect(results.filter((result) => result.outcome === 'existing')).toHaveLength(11);
    const stored = await stores[0]!.getActionReceipt(id);
    expect(stored?.outcome).toMatchObject({
      recordedBy: expect.stringMatching(/^runner-/u),
      result: { providerRequestId: 'provider_1' },
      status: 'succeeded',
    });
    await stores[1]!.recordActionReceiptOutcomeAtomically({
      outcome: {
        error: 'conflicting failure',
        recordedAt: '2026-07-12T08:31:00.000Z',
        recordedBy: 'attacker',
        status: 'failed',
      },
      receiptId: id,
    });
    await expect(stores[0]!.getActionReceipt(id)).resolves.toEqual(stored);
  });

  it('atomically records distinct approvers and emits one final transition at the threshold', async () => {
    const approvalId = `approval_multi_${randomUUID()}`;
    const fixture = authorizedApproval({
      id: approvalId,
      requiredApprovals: 2,
      toolCallId: `toolcall_multi_${randomUUID()}`,
    });
    await stores[0]!.createToolCall(fixture.toolCall);
    await stores[0]!.createApproval(fixture.approval);

    const results = await Promise.all([
      stores[0]!.recordApprovalDecisionAtomically({
        approvalId,
        authorization: fixture.guard,
        approvedEnvelopeHash: 'approved_envelope_hash',
        approvedInputHash: 'approved_input_hash',
        decision: decision('approver-a', fixture.authorization),
        reviewHash: 'review_hash',
        updatedAt: '2026-07-10T10:02:00.000Z',
      }),
      stores[1]!.recordApprovalDecisionAtomically({
        approvalId,
        authorization: fixture.guard,
        approvedEnvelopeHash: 'approved_envelope_hash',
        approvedInputHash: 'approved_input_hash',
        decision: decision('approver-b', fixture.authorization),
        reviewHash: 'review_hash',
        updatedAt: '2026-07-10T10:02:01.000Z',
      }),
    ]);

    expect(results.map((result) => result.outcome).sort()).toEqual(['finalized', 'recorded']);
    await expect(stores[0]!.getApproval(approvalId)).resolves.toMatchObject({
      decisions: [expect.any(Object), expect.any(Object)],
      status: 'approved',
    });
  });

  it('uses database time and rejects mutation while cancel and approval compete for one terminal state', async () => {
    const expired = authorizedApproval({
      expiresAt: '2001-01-01T00:00:00.000Z',
      id: `approval_expired_${randomUUID()}`,
      issuedAt: '2000-01-01T00:00:00.000Z',
      toolCallId: `toolcall_expired_${randomUUID()}`,
    });
    await stores[0]!.createToolCall(expired.toolCall);
    await stores[0]!.createApproval(expired.approval);
    const expiredResult = await stores[1]!.recordApprovalDecisionAtomically({
        approvalId: expired.approval.id,
        authorization: expired.guard,
        approvedEnvelopeHash: 'approved_envelope_hash',
        approvedInputHash: 'approved_input_hash',
        decision: decision('approver-expired', expired.authorization),
        reviewHash: 'review_hash',
        // This forged future application timestamp must not override database-time expiry.
        updatedAt: '2999-01-01T00:00:00.000Z',
      });
    expect(expiredResult).toMatchObject({ approval: { status: 'expired' }, outcome: 'expired' });
    expect(expiredResult.approval?.decisions ?? []).toEqual([]);

    const mutated = authorizedApproval({
      id: `approval_mutated_${randomUUID()}`,
      toolCallId: `toolcall_mutated_${randomUUID()}`,
    });
    await stores[0]!.createToolCall(mutated.toolCall);
    await stores[0]!.createApproval(mutated.approval);
    await stores[1]!.updateToolCall({
      ...mutated.toolCall,
      canonicalActionRequestHash: 'mutated_after_authorization',
    });
    const mutationResult = await stores[0]!.recordApprovalDecisionAtomically({
        approvalId: mutated.approval.id,
        authorization: mutated.guard,
        approvedEnvelopeHash: 'approved_envelope_hash',
        approvedInputHash: 'approved_input_hash',
        decision: decision('approver-mutated', mutated.authorization),
        reviewHash: 'review_hash',
        updatedAt: new Date().toISOString(),
      });
    expect(mutationResult).toMatchObject({ approval: { status: 'pending' }, outcome: 'authorization_mismatch' });
    expect(mutationResult.approval?.decisions ?? []).toEqual([]);

    const raced = authorizedApproval({
      id: `approval_race_${randomUUID()}`,
      toolCallId: `toolcall_race_${randomUUID()}`,
    });
    await stores[0]!.createToolCall(raced.toolCall);
    await stores[0]!.createApproval(raced.approval);
    const results = await Promise.all([
      stores[0]!.recordApprovalDecisionAtomically({
        approvalId: raced.approval.id,
        authorization: raced.guard,
        approvedEnvelopeHash: 'approved_envelope_hash',
        approvedInputHash: 'approved_input_hash',
        decision: decision('approver-race', raced.authorization),
        reviewHash: 'review_hash',
        updatedAt: new Date().toISOString(),
      }),
      stores[1]!.cancelApprovalAtomically({
        approvalId: raced.approval.id,
        authorization: raced.guard,
        cancelledBy: 'requester-race',
        updatedAt: new Date().toISOString(),
      }),
    ]);
    expect(results.filter((result) => result.outcome === 'cancelled' || result.outcome === 'finalized')).toHaveLength(1);
    await expect(stores[0]!.getApproval(raced.approval.id)).resolves.toMatchObject({
      authorizationConsumedAt: expect.any(String),
      status: expect.stringMatching(/^(approved|cancelled)$/),
    });
  });

  it('does not invoke execution after another Postgres pool cancels the authorization', async () => {
    const execute = vi.fn(async (input) => ({ ok: true, input }));
    const tools = newTestToolRegistry();
    tools.register('gmail.send_email', execute);
    const service = new ActionProxyService({
      auditStore: stores[0]!,
      policy: {
        default: { approval: 'required', risk: 'unknown' },
        tools: { 'gmail.send_email': { approval: 'required', risk: 'external' } },
        version: 1,
      },
      executionAuthorizations: testExecutionAuthorizations,
      store: stores[0]!,
      tools,
    });
    const submitted = await service.submitToolCall({
      agentId: 'postgres-test-agent',
      input: { to: 'customer@example.com' },
      reason: 'Prove cross-pool terminal state blocks execution',
      requestedBy: 'dev@example.com',
      toolName: 'gmail.send_email',
    });
    const authorization = submitted.approval!.authorization!;
    const cancellation = await stores[1]!.cancelApprovalAtomically({
      approvalId: submitted.approval!.id,
      authorization: {
        activePolicyVersionHash: submitted.toolCall.policyVersionHash!,
        authorization,
        originalInput: submitted.approval!.originalInput,
      },
      cancelledBy: 'requester@example.com',
      updatedAt: new Date().toISOString(),
    });
    expect(cancellation.outcome).toBe('cancelled');

    await expect(
      service.approveApproval(submitted.approval!.id, {
        approvalNonce: authorization.nonce,
        approvedBy: 'manager@example.com',
      }),
    ).rejects.toThrow('Approval is already cancelled');
    expect(execute).not.toHaveBeenCalled();
  });

  it('uses database time to reject an approval that expired before attempt reservation', async () => {
    const suffix = randomUUID();
    const fixture = authorizedApproval({
      expiresAt: '2001-01-01T00:00:00.000Z',
      id: `approval_attempt_expired_${suffix}`,
      issuedAt: '2000-01-01T00:00:00.000Z',
      toolCallId: `toolcall_attempt_expired_${suffix}`,
    });
    const toolCall = { ...fixture.toolCall, status: 'authorized' as const };
    const approvalRecord: ApprovalRecord = {
      ...fixture.approval,
      approvedEnvelopeHash: toolCall.actionEnvelopeHash,
      approvedInputHash: toolCall.inputHash,
      authorizationConsumedAt: '2000-01-01T00:00:01.000Z',
      authorizationConsumedReason: 'approved',
      status: 'approved',
    };
    await stores[0]!.createToolCall(toolCall);
    await stores[0]!.createApproval(approvalRecord);
    const attempt = buildExecutionAttempt({
      approval: approvalRecord,
      executionMode: 'local_mock',
      id: `attempt_expired_${suffix}`,
      inputHash: toolCall.inputHash!,
      now: '2000-01-01T00:00:02.000Z',
      toolCall,
    });

    await expect(
      stores[1]!.reserveExecutionAttemptAtomically(attempt, fixture.authorization),
    ).resolves.toEqual({ outcome: 'binding_mismatch' });
    await expect(stores[0]!.listExecutionAttempts('default', { toolCallId: toolCall.id })).resolves.toEqual([]);
  });

  it('atomically scopes keyed logical actions by tenant across Postgres pools', async () => {
    const suffix = randomUUID();
    const candidates = Array.from({ length: 12 }, (_, index) =>
      executionToolCall(`toolcall_idempotency_${suffix}_${index}`),
    );
    const results = await Promise.all(
      candidates.map((candidate, index) =>
        stores[index % stores.length]!.createToolCallIdempotentlyAtomically({
          idempotency: executionIdempotency(candidate, {
            key: `same-key-${suffix}`,
            requestHash: `same-request-${suffix}`,
          }),
          toolCall: candidate,
        }),
      ),
    );

    expect(results.filter((result) => result.outcome === 'created')).toHaveLength(1);
    expect(results.filter((result) => result.outcome === 'replay')).toHaveLength(11);
    const winner = results.find((result) => result.outcome === 'created')!;
    expect(new Set(results.map((result) => result.toolCall.id))).toEqual(new Set([winner.toolCall.id]));

    const conflict = executionToolCall(`toolcall_idempotency_conflict_${suffix}`);
    await expect(
      stores[1]!.createToolCallIdempotentlyAtomically({
        idempotency: executionIdempotency(conflict, {
          key: `same-key-${suffix}`,
          requestHash: `different-request-${suffix}`,
        }),
        toolCall: conflict,
      }),
    ).resolves.toMatchObject({ outcome: 'conflict', toolCall: { id: winner.toolCall.id } });
    await expect(stores[0]!.getToolCall(conflict.id)).resolves.toBeUndefined();

    const otherTenant = executionToolCall(`toolcall_idempotency_other_${suffix}`, `other-${suffix}`);
    await expect(
      stores[1]!.createToolCallIdempotentlyAtomically({
        idempotency: executionIdempotency(otherTenant, {
          key: `same-key-${suffix}`,
          requestHash: `same-request-${suffix}`,
        }),
        toolCall: otherTenant,
      }),
    ).resolves.toMatchObject({ outcome: 'created', toolCall: { id: otherTenant.id } });
  });

  it('allows one Postgres attempt reservation and keeps terminal outcomes immutable', async () => {
    const suffix = randomUUID();
    const toolCall = executionToolCall(`toolcall_attempt_${suffix}`);
    await stores[0]!.createToolCall(toolCall);
    const candidates = Array.from({ length: 12 }, (_, index) =>
      buildExecutionAttempt({
        executionMode: 'local_mock',
        id: `attempt_${suffix}_${index}`,
        inputHash: toolCall.inputHash!,
        now: '2026-07-12T08:00:00.000Z',
        reservationOwner: `owner_${suffix}_${index}`,
        toolCall,
      }),
    );
    const reservations = await Promise.all(
      candidates.map((candidate, index) =>
        stores[index % stores.length]!.reserveExecutionAttemptAtomically(candidate),
      ),
    );

    expect(reservations.filter((result) => result.outcome === 'reserved')).toHaveLength(1);
    expect(reservations.filter((result) => result.outcome === 'existing')).toHaveLength(11);
    const attempt = reservations.find((result) => result.outcome === 'reserved')!.attempt!;
    expect(new Set(reservations.map((result) => result.attempt?.id))).toEqual(new Set([attempt.id]));

    const dispatchedAt = '2026-07-12T08:00:01.000Z';
    const dispatches = await Promise.all(
      stores.map((store) =>
        store.transitionExecutionAttemptAtomically({
          attemptId: attempt.id,
          expectedState: 'reserved',
          nextState: 'dispatched',
          reservationOwner: attempt.reservationOwner,
          transitionedAt: dispatchedAt,
          workspaceId: attempt.workspaceId,
        }),
      ),
    );
    expect(dispatches.map((result) => result.outcome).sort()).toEqual(['replay', 'transitioned']);

    const completedAt = '2026-07-12T08:00:02.000Z';
    const outcome = executionAttemptOutcome('succeeded', { recordedAt: completedAt, result: { ok: true } });
    const completions = await Promise.all(
      stores.map((store) =>
        store.transitionExecutionAttemptAtomically({
          attemptId: attempt.id,
          expectedState: 'dispatched',
          nextState: 'succeeded',
          outcome,
          reservationOwner: attempt.reservationOwner,
          transitionedAt: completedAt,
          workspaceId: attempt.workspaceId,
        }),
      ),
    );
    expect(completions.map((result) => result.outcome).sort()).toEqual(['replay', 'transitioned']);
    await expect(
      stores[0]!.transitionExecutionAttemptAtomically({
        attemptId: attempt.id,
        expectedState: 'dispatched',
        nextState: 'failed_after_dispatch',
        outcome: executionAttemptOutcome('failed_after_dispatch', {
          errorMessage: 'conflicting terminal report',
          recordedAt: completedAt,
        }),
        reservationOwner: attempt.reservationOwner,
        transitionedAt: completedAt,
        workspaceId: attempt.workspaceId,
      }),
    ).resolves.toMatchObject({ outcome: 'already_terminal' });

    const forbiddenRetry = buildExecutionAttempt({
      executionMode: 'local_mock',
      id: `attempt_retry_${suffix}`,
      inputHash: toolCall.inputHash!,
      now: '2026-07-12T08:00:03.000Z',
      toolCall,
    });
    await expect(stores[1]!.reserveExecutionAttemptAtomically(forbiddenRetry)).resolves.toMatchObject({
      attempt: { id: attempt.id, state: 'succeeded' },
      outcome: 'existing',
    });
  });

  it('binds Postgres attempt reservation to content influence, scope, and result-source evidence', async () => {
    const suffix = randomUUID();
    const mutations = [
      { field: 'contentInfluenceBindingHash' as const, value: 'mutated_content_influence_hash' },
      { field: 'influenceScopeId' as const, value: `influence_${'b'.repeat(64)}` },
      { field: 'resultSourceHash' as const, value: 'mutated_result_source_hash' },
    ];

    for (const [index, mutation] of mutations.entries()) {
      const toolCall = governedExecutionToolCall(`toolcall_governance_binding_${suffix}_${index}`);
      await stores[0]!.createToolCall(toolCall);
      const attempt = buildExecutionAttempt({
        executionMode: 'local_mock',
        id: `attempt_governance_binding_${suffix}_${index}`,
        inputHash: toolCall.inputHash!,
        now: '2026-07-12T08:05:00.000Z',
        toolCall,
      });
      attempt.binding[mutation.field] = mutation.value;

      await expect(stores[1]!.reserveExecutionAttemptAtomically(attempt)).resolves.toEqual({
        outcome: 'binding_mismatch',
      });
      await expect(
        stores[0]!.listExecutionAttempts('default', { toolCallId: toolCall.id }),
      ).resolves.toEqual([]);
    }

    const toolCall = governedExecutionToolCall(`toolcall_governance_binding_exact_${suffix}`);
    await stores[0]!.createToolCall(toolCall);
    const attempt = buildExecutionAttempt({
      executionMode: 'local_mock',
      id: `attempt_governance_binding_exact_${suffix}`,
      inputHash: toolCall.inputHash!,
      now: '2026-07-12T08:05:01.000Z',
      toolCall,
    });
    await expect(stores[1]!.reserveExecutionAttemptAtomically(attempt)).resolves.toMatchObject({
      attempt: { id: attempt.id },
      outcome: 'reserved',
    });
  });

  it('rejects a reserved-to-dispatched transition when the content-exposure revision changed', async () => {
    const suffix = randomUUID();
    const workspaceId = `workspace_transition_influence_${suffix}`;
    const toolCall = governedExecutionToolCall(`toolcall_transition_influence_${suffix}`, workspaceId);
    await stores[0]!.createToolCall(toolCall);
    const attempt = buildExecutionAttempt({
      executionMode: 'local_mock',
      id: `attempt_transition_influence_${suffix}`,
      inputHash: toolCall.inputHash!,
      now: '2026-07-12T08:06:00.000Z',
      toolCall,
    });
    await expect(stores[0]!.reserveExecutionAttemptAtomically(attempt)).resolves.toMatchObject({ outcome: 'reserved' });
    await expect(stores[1]!.recordContentExposure({
      influenceScopeId: toolCall.influenceScopeId!,
      integrity: 'public_untrusted',
      observedAt: '2026-07-12T08:06:01.000Z',
      policyVersionHash: toolCall.policyVersionHash!,
      sourceId: 'public-web',
      sourceToolCallId: `toolcall_transition_source_${suffix}`,
      workspaceId,
    })).resolves.toBe('created');

    await expect(stores[0]!.transitionExecutionAttemptAtomically({
      attemptId: attempt.id,
      contentExposureRevision: {
        influenceScopeId: toolCall.influenceScopeId!,
        revision: toolCall.contentInfluence!.exposureRevision,
      },
      expectedState: 'reserved',
      nextState: 'dispatched',
      reservationOwner: attempt.reservationOwner,
      transitionedAt: '2026-07-12T08:06:02.000Z',
      workspaceId,
    })).resolves.toMatchObject({
      attempt: { id: attempt.id, state: 'reserved' },
      outcome: 'content_influence_mismatch',
    });
    await expect(stores[1]!.getExecutionAttempt(attempt.id)).resolves.toMatchObject({ state: 'reserved' });
  });

  it('does not consume a Postgres grant when the content-exposure revision changed', async () => {
    const suffix = randomUUID();
    const workspaceId = `workspace_grant_influence_${suffix}`;
    const toolCall = governedExecutionToolCall(`toolcall_grant_influence_${suffix}`, workspaceId);
    await stores[0]!.createToolCall(toolCall);
    const attempt = buildExecutionAttempt({
      executionMode: 'external_grant',
      id: `attempt_grant_influence_${suffix}`,
      inputHash: toolCall.inputHash!,
      now: '2026-07-12T08:07:00.000Z',
      reservationOwner: `owner_grant_influence_${suffix}`,
      toolCall,
    });
    await stores[0]!.reserveExecutionAttemptAtomically(attempt);
    const grant = executionGrant({
      id: `grant_influence_${suffix}`,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      toolCallId: toolCall.id,
      toolName: toolCall.toolName,
      workspaceId,
    });
    await stores[0]!.createExecutionGrant(grant);
    await expect(stores[1]!.bindExecutionAttemptGrantAtomically({
      attemptId: attempt.id,
      grantId: grant.id,
      reservationOwner: attempt.reservationOwner,
      updatedAt: '2026-07-12T08:07:01.000Z',
      workspaceId,
    })).resolves.toMatchObject({ outcome: 'bound' });
    await stores[0]!.recordContentExposure({
      influenceScopeId: toolCall.influenceScopeId!,
      integrity: 'unknown',
      observedAt: '2026-07-12T08:07:02.000Z',
      policyVersionHash: toolCall.policyVersionHash!,
      sourceToolCallId: `toolcall_grant_source_${suffix}`,
      workspaceId,
    });

    await expect(stores[1]!.consumeExecutionGrantAndDispatchAttemptAtomically({
      attemptId: attempt.id,
      contentExposureRevision: {
        influenceScopeId: toolCall.influenceScopeId!,
        revision: toolCall.contentInfluence!.exposureRevision,
      },
      dispatchedAt: '2026-07-12T08:07:03.000Z',
      grantId: grant.id,
      reservationOwner: attempt.reservationOwner,
      toolCallId: toolCall.id,
      workspaceId,
    })).resolves.toEqual({ outcome: 'content_influence_mismatch' });
    await expect(stores[0]!.getExecutionAttempt(attempt.id)).resolves.toMatchObject({ state: 'reserved' });
    expect((await stores[0]!.getExecutionGrant(grant.id))?.consumedAt).toBeUndefined();
  });

  it('atomically consumes one Postgres grant with its dispatch reservation', async () => {
    const suffix = randomUUID();
    const toolCall = executionToolCall(`toolcall_grant_${suffix}`);
    await stores[0]!.createToolCall(toolCall);
    const attempt = buildExecutionAttempt({
      executionMode: 'external_grant',
      id: `attempt_grant_${suffix}`,
      inputHash: toolCall.inputHash!,
      now: '2026-07-12T08:10:00.000Z',
      reservationOwner: `owner_grant_${suffix}`,
      toolCall,
    });
    await stores[0]!.reserveExecutionAttemptAtomically(attempt);
    const grant = executionGrant({
      id: `grant_dispatch_${suffix}`,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      toolCallId: toolCall.id,
      toolName: toolCall.toolName,
      workspaceId: toolCall.workspaceId,
    });
    await stores[0]!.createExecutionGrant(grant);
    await stores[1]!.bindExecutionAttemptGrantAtomically({
      attemptId: attempt.id,
      grantId: grant.id,
      reservationOwner: attempt.reservationOwner,
      updatedAt: '2026-07-12T08:10:01.000Z',
      workspaceId: attempt.workspaceId,
    });

    const dispatches = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        stores[index % stores.length]!.consumeExecutionGrantAndDispatchAttemptAtomically({
          attemptId: attempt.id,
          dispatchedAt: `2026-07-12T08:10:${String(index + 2).padStart(2, '0')}.000Z`,
          grantId: grant.id,
          reservationOwner: attempt.reservationOwner,
          toolCallId: toolCall.id,
          workspaceId: attempt.workspaceId,
        }),
      ),
    );
    expect(dispatches.filter((result) => result.outcome === 'dispatched')).toHaveLength(1);
    expect(dispatches.filter((result) => result.outcome === 'grant_already_consumed')).toHaveLength(11);
    await expect(stores[0]!.getExecutionAttempt(attempt.id)).resolves.toMatchObject({ state: 'dispatched' });
  });

  it('does not invoke or retry after a Postgres dispatch crash window', async () => {
    const suffix = randomUUID();
    const execute = vi.fn(async (input) => ({ input, ok: true }));
    const tools = newTestToolRegistry();
    tools.register('docs.search', execute);
    const crashStore = crashAfterDispatch(stores[0]!);
    const crashingService = executionService(crashStore, stores[0]!, tools);
    const request = {
      agentId: 'postgres-test-agent',
      input: { query: suffix },
      reason: 'Exercise Postgres dispatch crash seam',
      requestedBy: 'dev@example.com',
      toolName: 'docs.search',
    };

    await expect(
      crashingService.submitToolCall(request, { idempotencyKey: `dispatch-crash-${suffix}` }),
    ).rejects.toThrow('simulated Postgres crash after dispatch marker');
    const replayService = executionService(stores[1]!, stores[1]!, tools);
    const replay = await replayService.submitToolCall(request, { idempotencyKey: `dispatch-crash-${suffix}` });
    const attempts = await stores[1]!.listExecutionAttempts('default', { toolCallId: replay.toolCall.id });

    expect(execute).not.toHaveBeenCalled();
    expect(replay.toolCall.status).toBe('submitted');
    expect(attempts).toMatchObject([{ state: 'dispatched' }]);
  });

  it('does not duplicate a Postgres-backed side effect after post-invocation evidence failure', async () => {
    const suffix = randomUUID();
    const execute = vi.fn(async (input) => ({ input, ok: true }));
    const tools = newTestToolRegistry();
    tools.register('docs.search', execute);
    const failingAuditStore: AuditStore = {
      append: vi.fn(async (event) => {
        if (event.type === 'execution.attempt_dispatched') {
          throw new Error('simulated Postgres post-invocation evidence failure');
        }
      }),
      list: vi.fn(async () => []),
    };
    const service = executionService(stores[0]!, failingAuditStore, tools);
    const request = {
      agentId: 'postgres-test-agent',
      input: { query: suffix },
      reason: 'Exercise Postgres post-invocation crash seam',
      requestedBy: 'dev@example.com',
      toolName: 'docs.search',
    };

    await expect(
      service.submitToolCall(request, { idempotencyKey: `evidence-crash-${suffix}` }),
    ).rejects.toThrow('simulated Postgres post-invocation evidence failure');
    const replayService = executionService(stores[1]!, stores[1]!, tools);
    const replay = await replayService.submitToolCall(request, { idempotencyKey: `evidence-crash-${suffix}` });
    const attempts = await stores[1]!.listExecutionAttempts('default', { toolCallId: replay.toolCall.id });

    expect(execute).toHaveBeenCalledOnce();
    expect(replay.toolCall.status).toBe('submitted');
    expect(attempts).toMatchObject([{ state: 'dispatched' }]);
    expect(attempts[0]!.outcome).toBeUndefined();
  });

  it('persists canonical request hashes and policy provenance', async () => {
    const id = `toolcall_canonical_${randomUUID()}`;
    const record: ToolCallRecord = {
      agentId: 'asserted-agent',
      canonicalActionRequestHash: 'canonical_request_hash',
      canonicalActionRequestVersion: 'actionproxy.action-request.v1',
      canonicalDecisionInputHash: 'canonical_decision_hash',
      canonicalPolicyContext: deriveCanonicalPolicyContext('gmail.send_email', { to: 'customer@example.com' }),
      createdAt: '2026-07-11T00:00:00.000Z',
      decisionTrace: {
        decisionV1: {
          decisionId: 'decision_postgres_persisted',
          outcome: 'require_approval',
          version: 'actionproxy.decision.v1',
        },
      },
      id,
      input: { to: 'customer@example.com' },
      metadata: {},
      reason: 'Persistence contract',
      requestedBy: 'dev@example.com',
      status: 'pending_approval',
      toolName: 'gmail.send_email',
      updatedAt: '2026-07-11T00:00:00.000Z',
      workspaceId: 'default',
    };

    await stores[0]!.createToolCall(record);
    await expect(stores[1]!.getToolCall(id)).resolves.toMatchObject({
      canonicalActionRequestHash: 'canonical_request_hash',
      canonicalActionRequestVersion: 'actionproxy.action-request.v1',
      canonicalDecisionInputHash: 'canonical_decision_hash',
      canonicalPolicyContext: {
        customerVisible: { present: false },
        recipientDomain: { present: true, value: 'external' },
      },
      decisionTrace: {
        decisionV1: {
          decisionId: 'decision_postgres_persisted',
          outcome: 'require_approval',
          version: 'actionproxy.decision.v1',
        },
      },
    });
  });
});

function approval(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return {
    createdAt: '2026-07-10T10:00:00.000Z',
    id: `approval_${randomUUID()}`,
    originalInput: { to: 'customer@example.com' },
    requestedBy: 'dev@example.com',
    status: 'pending',
    toolCallId: `toolcall_${randomUUID()}`,
    updatedAt: '2026-07-10T10:00:00.000Z',
    workspaceId: 'default',
    ...overrides,
  };
}

function decision(actor: string, authorization: ApprovalAuthorizationV1): ApprovalDecisionRecord {
  return {
    actor,
    authorizationHash: authorization.authorizationHash,
    authorizationNonce: authorization.nonce,
    authorizationVersion: authorization.version,
    approvedEnvelopeHash: 'approved_envelope_hash',
    approvedInputHash: 'approved_input_hash',
    decisionId: authorization.binding.decision.decisionId ?? undefined,
    decidedAt: '2026-07-10T10:00:00.000Z',
    inputDecision: 'original',
    reviewHash: 'review_hash',
  };
}

function approverUser(id: string, workspaceId: string, principalId?: string): ApproverUserRecord {
  return {
    createdAt: '2026-08-09T10:00:00.000Z',
    defaultApprover: false,
    displayName: id,
    enabled: true,
    groups: [],
    id,
    principalId,
    updatedAt: '2026-08-09T10:00:00.000Z',
    workspaceId,
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
  const id = recordOverrides.id ?? `approval_${randomUUID()}`;
  const toolCallId = recordOverrides.toolCallId ?? `toolcall_${randomUUID()}`;
  const toolCallRecord: ToolCallRecord = {
    agentId: 'demo-agent',
    actionEnvelopeHash: 'original_envelope_hash',
    createdAt: '2026-07-10T10:00:00.000Z',
    decision: 'require_approval',
    id: toolCallId,
    input: originalInput,
    inputHash: hashJson(originalInput),
    metadata: {},
    policyVersionHash: 'policy_hash_1',
    reason: 'Send email',
    requestedBy: 'dev@example.com',
    status: 'pending_approval',
    toolName: 'gmail.send_email',
    updatedAt: '2026-07-10T10:00:00.000Z',
    workspaceId: 'default',
  };
  const baseApproval = approval({
    ...recordOverrides,
    id,
    originalEnvelopeHash: 'original_envelope_hash',
    originalInput,
    originalInputHash: hashJson(originalInput),
    reviewHash: 'review_hash',
    toolCallId,
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

function executionGrant(overrides: Partial<ExecutionGrantRecord> = {}): ExecutionGrantRecord {
  return {
    actor: 'dev@example.com',
    createdAt: '2026-07-10T10:00:00.000Z',
    expiresAt: '2999-07-10T10:00:00.000Z',
    id: `grant_${randomUUID()}`,
    inputHash: 'approved_input_hash',
    nonce: 'nonce',
    signature: 'signature',
    toolCallId: `toolcall_${randomUUID()}`,
    toolName: 'docs.search',
    workspaceId: 'default',
    ...overrides,
  };
}

function actionReceipt(id: string): ActionReceiptRecord {
  return {
    approvedEnvelopeHash: 'envelope_hash_approved',
    approvedInputHash: 'input_hash_approved',
    createdAt: '2026-07-12T08:30:00.000Z',
    decisionActor: 'policy',
    decisionKind: 'policy_allow',
    executionMode: 'external_grant',
    id,
    issuedAt: '2026-07-12T08:30:00.000Z',
    keyId: 'test-key',
    operation: { name: 'docs.search' },
    originalEnvelopeHash: 'envelope_hash_original',
    originalInputHash: 'input_hash_original',
    protocol: 'actionproxy_http',
    receiptHash: `hash_${id}`,
    signature: 'test-signature',
    signatureAlg: 'HMAC-SHA256',
    source: { name: 'storage-test', type: 'sdk' },
    toolCallId: `toolcall_${id}`,
    toolName: 'docs.search',
    version: 'actionproxy.receipt.v1',
    workspaceId: 'default',
  };
}

function executionToolCall(id: string, workspaceId = 'default'): ToolCallRecord {
  return {
    actionEnvelopeHash: `envelope_${id}`,
    agentId: 'postgres-execution-agent',
    canonicalActionRequestHash: `request_${id}`,
    canonicalActionRequestVersion: 'actionproxy.action-request.v1',
    canonicalDecisionInputHash: `decision_input_${id}`,
    createdAt: '2026-07-12T08:00:00.000Z',
    decision: 'allow',
    decisionTrace: {
      decisionV1: { decisionId: `decision_${id}`, version: 'actionproxy.decision.v1' },
    },
    id,
    input: { query: id },
    inputHash: `input_${id}`,
    metadata: {},
    policyVersionHash: 'policy_hash',
    reason: 'Postgres execution contract test',
    requestedBy: 'postgres-test',
    status: 'submitted',
    toolName: 'docs.search',
    updatedAt: '2026-07-12T08:00:00.000Z',
    workspaceId,
  };
}

function governedExecutionToolCall(id: string, workspaceId = 'default'): ToolCallRecord {
  const influenceScopeId = `influence_${'a'.repeat(64)}`;
  const toolCall = executionToolCall(id, workspaceId);
  return {
    ...toolCall,
    contentInfluence: buildContentInfluenceEvidence({
      evaluatedAt: '2026-07-12T08:04:00.000Z',
      evaluation: {
        baseDecision: 'allow',
        effectiveApproval: 'never',
        effectiveDecision: 'allow',
        observedSources: ['none'],
        reason: 'The verified scope has no classified external content.',
        restrictionApplied: false,
        sourcesAllowed: true,
      },
      exposureLookup: { overflow: false, records: [], revision: 0 },
      influenceScopeId,
      policyVersionHash: toolCall.policyVersionHash!,
      selectedRule: { allowFrom: ['none'], otherwise: 'required' },
    }),
    influenceScopeId,
    resultSource: { integrity: 'public_untrusted', sourceId: 'public-web' },
  };
}

function executionIdempotency(
  toolCall: ToolCallRecord,
  overrides: Partial<IdempotencyRecord> = {},
): IdempotencyRecord {
  return {
    createdAt: toolCall.createdAt,
    key: 'idempotency-key',
    requestHash: 'request-hash',
    route: 'POST /v1/tool-calls',
    toolCallId: toolCall.id,
    workspaceId: toolCall.workspaceId ?? 'default',
    ...overrides,
  };
}

function executionService(store: Store, auditStore: AuditStore, tools: ToolRegistry): ActionProxyService {
  return new ActionProxyService({
    auditStore,
    executionAuthorizations: testExecutionAuthorizations,
    policy: {
      default: { approval: 'required', risk: 'unknown' },
      tools: { 'docs.search': { approval: 'never', risk: 'low' } },
      version: 1,
    },
    store,
    tools,
  });
}

function crashAfterDispatch(store: PostgresStore): Store {
  return new Proxy(store, {
    get(target, property, receiver) {
      if (property === 'transitionExecutionAttemptAtomically') {
        return async (input: Parameters<Store['transitionExecutionAttemptAtomically']>[0]) => {
          const result = await target.transitionExecutionAttemptAtomically(input);
          if (input.nextState === 'dispatched' && result.outcome === 'transitioned') {
            throw new Error('simulated Postgres crash after dispatch marker');
          }
          return result;
        };
      }
      const value = Reflect.get(target, property, receiver) as unknown;
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as Store;
}
