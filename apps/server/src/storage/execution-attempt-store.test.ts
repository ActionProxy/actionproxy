import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildExecutionAttempt,
  executionAttemptOutcome,
} from '../contracts/execution-attempt';
import { buildApprovalAuthorization } from '../contracts/approval-authorization';
import { buildContentInfluenceEvidence } from '../contracts/content-influence';
import { hashJson } from '../security/crypto';
import type {
  ActionReceiptRecord,
  ApprovalRecord,
  ExecutionGrantRecord,
  IdempotencyRecord,
  ToolCallRecord,
} from '../models';
import { MemoryStore } from './memory-store';
import { SqliteStore } from './sqlite-store';
import type { Store } from './store';

interface StoreHarness {
  stores: Store[];
}

const harnesses: Array<{ make: () => StoreHarness; name: string }> = [
  { make: () => ({ stores: [new MemoryStore()] }), name: 'memory' },
  {
    make: () => {
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-execution-attempt-store-'));
      const databasePath = path.join(directory, 'actionproxy.db');
      return { stores: [new SqliteStore(databasePath), new SqliteStore(databasePath)] };
    },
    name: 'sqlite',
  },
];

describe.each(harnesses)('$name T4 storage invariants', ({ make }) => {
  it('atomically creates one tenant-scoped logical action and returns replay or conflict', async () => {
    const { stores } = make();
    const candidates = Array.from({ length: 12 }, (_, index) => toolCall(`toolcall_idempotent_${index}`));
    const results = await Promise.all(
      candidates.map((candidate, index) =>
        stores[index % stores.length]!.createToolCallIdempotentlyAtomically({
          idempotency: idempotency(candidate, { key: 'same-key', requestHash: 'request-hash' }),
          toolCall: candidate,
        }),
      ),
    );

    expect(results.filter((result) => result.outcome === 'created')).toHaveLength(1);
    expect(results.filter((result) => result.outcome === 'replay')).toHaveLength(11);
    const winner = results.find((result) => result.outcome === 'created')!;
    expect(new Set(results.map((result) => result.toolCall.id))).toEqual(new Set([winner.toolCall.id]));
    await expect(stores[0]!.listToolCalls()).resolves.toHaveLength(1);

    const conflictCandidate = toolCall('toolcall_conflict');
    await expect(
      stores[0]!.createToolCallIdempotentlyAtomically({
        idempotency: idempotency(conflictCandidate, { key: 'same-key', requestHash: 'different-hash' }),
        toolCall: conflictCandidate,
      }),
    ).resolves.toMatchObject({
      outcome: 'conflict',
      toolCall: { id: winner.toolCall.id },
    });
    await expect(stores[0]!.getToolCall(conflictCandidate.id)).resolves.toBeUndefined();

    const otherTenant = toolCall('toolcall_other_tenant', 'other-workspace');
    await expect(
      stores[0]!.createToolCallIdempotentlyAtomically({
        idempotency: idempotency(otherTenant, { key: 'same-key', requestHash: 'request-hash' }),
        toolCall: otherTenant,
      }),
    ).resolves.toMatchObject({ outcome: 'created', toolCall: { id: otherTenant.id } });
  });

  it('reserves one bound attempt and blocks a second attempt for the same logical action', async () => {
    const { stores } = make();
    const call = toolCall('toolcall_reservation');
    await stores[0]!.createToolCall(call);
    const candidates = Array.from({ length: 12 }, (_, index) =>
      buildExecutionAttempt({
        executionMode: 'local_mock',
        id: `attempt_reservation_${index}`,
        inputHash: call.inputHash!,
        now: '2026-07-12T08:00:00.000Z',
        reservationOwner: `owner_${index}`,
        toolCall: call,
      }),
    );

    const results = await Promise.all(
      candidates.map((candidate, index) =>
        stores[index % stores.length]!.reserveExecutionAttemptAtomically(candidate),
      ),
    );
    expect(results.filter((result) => result.outcome === 'reserved')).toHaveLength(1);
    expect(results.filter((result) => result.outcome === 'existing')).toHaveLength(11);
    const winner = results.find((result) => result.outcome === 'reserved')!.attempt!;
    expect(new Set(results.map((result) => result.attempt?.id))).toEqual(new Set([winner.id]));

    const mismatched = buildExecutionAttempt({
      executionMode: 'local_mock',
      id: 'attempt_bad_binding',
      inputHash: 'mutated-input-hash',
      now: '2026-07-12T08:00:01.000Z',
      toolCall: toolCall('toolcall_bad_binding'),
    });
    await stores[0]!.createToolCall(toolCall('toolcall_bad_binding'));
    await expect(stores[0]!.reserveExecutionAttemptAtomically(mismatched)).resolves.toEqual({
      outcome: 'binding_mismatch',
    });

    const malformedRetry = buildExecutionAttempt({
      executionMode: 'local_mock',
      id: 'attempt_retry_malformed',
      inputHash: 'mutated-retry-input-hash',
      now: '2026-07-12T08:00:02.000Z',
      toolCall: call,
    });
    await expect(stores[0]!.reserveExecutionAttemptAtomically(malformedRetry)).resolves.toEqual({
      outcome: 'binding_mismatch',
    });

    const second = buildExecutionAttempt({
      executionMode: 'local_mock',
      id: 'attempt_retry_forbidden',
      inputHash: call.inputHash!,
      now: '2026-07-12T08:00:03.000Z',
      toolCall: call,
    });
    await expect(stores[0]!.reserveExecutionAttemptAtomically(second)).resolves.toMatchObject({
      attempt: { id: winner.id },
      outcome: 'existing',
    });
  });

  it('binds attempt reservation to content influence, scope, and result-source evidence', async () => {
    const mutations = [
      { field: 'contentInfluenceBindingHash' as const, value: 'mutated_content_influence_hash' },
      { field: 'influenceScopeId' as const, value: `influence_${'b'.repeat(64)}` },
      { field: 'resultSourceHash' as const, value: 'mutated_result_source_hash' },
    ];

    for (const [index, mutation] of mutations.entries()) {
      const { stores } = make();
      const call = governedToolCall(`toolcall_governance_binding_${index}`);
      await stores[0]!.createToolCall(call);
      const attempt = buildExecutionAttempt({
        executionMode: 'local_mock',
        id: `attempt_governance_binding_${index}`,
        inputHash: call.inputHash!,
        now: '2026-07-12T08:05:00.000Z',
        toolCall: call,
      });
      attempt.binding[mutation.field] = mutation.value;

      await expect(stores[0]!.reserveExecutionAttemptAtomically(attempt)).resolves.toEqual({
        outcome: 'binding_mismatch',
      });
      await expect(stores[0]!.listExecutionAttempts('default')).resolves.toEqual([]);
    }

    const { stores } = make();
    const call = governedToolCall('toolcall_governance_binding_exact');
    await stores[0]!.createToolCall(call);
    const attempt = buildExecutionAttempt({
      executionMode: 'local_mock',
      id: 'attempt_governance_binding_exact',
      inputHash: call.inputHash!,
      now: '2026-07-12T08:05:01.000Z',
      toolCall: call,
    });
    await expect(stores[0]!.reserveExecutionAttemptAtomically(attempt)).resolves.toMatchObject({
      attempt: { id: attempt.id },
      outcome: 'reserved',
    });
  });

  it('enforces owner/state CAS and immutable terminal outcomes', async () => {
    const { stores } = make();
    const call = toolCall('toolcall_transition');
    await stores[0]!.createToolCall(call);
    const attempt = buildExecutionAttempt({
      executionMode: 'local_mock',
      id: 'attempt_transition',
      inputHash: call.inputHash!,
      now: '2026-07-12T08:10:00.000Z',
      reservationOwner: 'owner_transition',
      toolCall: call,
    });
    await stores[0]!.reserveExecutionAttemptAtomically(attempt);

    await expect(
      stores[0]!.transitionExecutionAttemptAtomically({
        attemptId: attempt.id,
        expectedState: 'reserved',
        nextState: 'dispatched',
        reservationOwner: 'wrong-owner',
        transitionedAt: '2026-07-12T08:10:01.000Z',
        workspaceId: attempt.workspaceId,
      }),
    ).resolves.toMatchObject({ outcome: 'owner_mismatch' });
    const dispatchedInput = {
      attemptId: attempt.id,
      expectedState: 'reserved' as const,
      nextState: 'dispatched' as const,
      reservationOwner: attempt.reservationOwner,
      transitionedAt: '2026-07-12T08:10:01.000Z',
      workspaceId: attempt.workspaceId,
    };
    await expect(stores[0]!.transitionExecutionAttemptAtomically(dispatchedInput)).resolves.toMatchObject({
      attempt: { state: 'dispatched' },
      outcome: 'transitioned',
    });
    await expect(stores[0]!.transitionExecutionAttemptAtomically(dispatchedInput)).resolves.toMatchObject({
      outcome: 'replay',
    });

    const completedAt = '2026-07-12T08:10:02.000Z';
    const outcome = executionAttemptOutcome('succeeded', { recordedAt: completedAt, result: { ok: true } });
    const terminalInput = {
      attemptId: attempt.id,
      expectedState: 'dispatched' as const,
      nextState: 'succeeded' as const,
      outcome,
      reservationOwner: attempt.reservationOwner,
      transitionedAt: completedAt,
      workspaceId: attempt.workspaceId,
    };
    await expect(stores[0]!.transitionExecutionAttemptAtomically(terminalInput)).resolves.toMatchObject({
      attempt: { outcome, state: 'succeeded' },
      outcome: 'transitioned',
    });
    await expect(stores[0]!.transitionExecutionAttemptAtomically(terminalInput)).resolves.toMatchObject({
      outcome: 'replay',
    });
    await expect(
      stores[0]!.transitionExecutionAttemptAtomically({
        ...terminalInput,
        nextState: 'failed_after_dispatch',
        outcome: executionAttemptOutcome('failed_after_dispatch', {
          errorMessage: 'conflicting outcome',
          recordedAt: completedAt,
        }),
      }),
    ).resolves.toMatchObject({ outcome: 'already_terminal' });
    await expect(stores[0]!.listExecutionAttempts('default', { state: 'succeeded' })).resolves.toMatchObject([
      { id: attempt.id, state: 'succeeded' },
    ]);
  });

  it('fails the guarded dispatch CAS on a newer exposure revision and replays exactly once', async () => {
    const { stores } = make();
    const scopeId = `influence_${'a'.repeat(64)}`;
    const call = toolCall('toolcall_guarded_dispatch');
    await stores[0]!.createToolCall(call);
    await stores[0]!.recordContentExposure({
      influenceScopeId: scopeId,
      integrity: 'organization_managed',
      observedAt: '2026-07-12T08:09:00.000Z',
      policyVersionHash: 'policy_hash',
      sourceToolCallId: 'toolcall_source_1',
      workspaceId: 'default',
    });
    const attempt = buildExecutionAttempt({
      executionMode: 'local_mock',
      id: 'attempt_guarded_dispatch',
      inputHash: call.inputHash!,
      now: '2026-07-12T08:10:00.000Z',
      reservationOwner: 'owner_guarded_dispatch',
      toolCall: call,
    });
    await stores[0]!.reserveExecutionAttemptAtomically(attempt);
    await stores[0]!.recordContentExposure({
      influenceScopeId: scopeId,
      integrity: 'public_untrusted',
      observedAt: '2026-07-12T08:09:30.000Z',
      policyVersionHash: 'policy_hash',
      sourceToolCallId: 'toolcall_source_2',
      workspaceId: 'default',
    });
    const dispatch = {
      attemptId: attempt.id,
      contentExposureRevision: { influenceScopeId: scopeId, revision: 1 },
      expectedState: 'reserved' as const,
      nextState: 'dispatched' as const,
      reservationOwner: attempt.reservationOwner,
      transitionedAt: '2026-07-12T08:10:01.000Z',
      workspaceId: attempt.workspaceId,
    };

    await expect(stores[0]!.transitionExecutionAttemptAtomically(dispatch)).resolves.toMatchObject({
      outcome: 'content_influence_mismatch',
    });
    await expect(stores[0]!.getExecutionAttempt(attempt.id)).resolves.toMatchObject({ state: 'reserved' });
    const currentDispatch = {
      ...dispatch,
      contentExposureRevision: { influenceScopeId: scopeId, revision: 2 },
    };
    await expect(stores[0]!.transitionExecutionAttemptAtomically(currentDispatch)).resolves.toMatchObject({
      outcome: 'transitioned',
    });
    await expect(stores[0]!.transitionExecutionAttemptAtomically(currentDispatch)).resolves.toMatchObject({
      outcome: 'replay',
    });
  });

  it('rejects expired, unconsumed, or integrity-mutated approval state before attempt reservation', async () => {
    const cases = [
      approvedAttemptFixture('expired', { expiresAt: '2000-01-02T00:00:00.000Z' }),
      approvedAttemptFixture('unconsumed', { authorizationConsumedReason: 'cancelled' }),
      approvedAttemptFixture('mutated', { mutateAuthorization: true }),
    ];

    for (const fixture of cases) {
      const { stores } = make();
      await stores[0]!.createToolCall(fixture.toolCall);
      await stores[0]!.createApproval(fixture.approval);

      await expect(
        stores[0]!.reserveExecutionAttemptAtomically(fixture.attempt, fixture.approval.authorization),
      ).resolves.toEqual({ outcome: 'binding_mismatch' });
      await expect(stores[0]!.listExecutionAttempts('default')).resolves.toEqual([]);
    }
  });

  it('atomically binds, consumes, and dispatches one external grant', async () => {
    const { stores } = make();
    const call = toolCall('toolcall_external');
    await stores[0]!.createToolCall(call);
    const attempt = buildExecutionAttempt({
      executionMode: 'external_grant',
      id: 'attempt_external',
      inputHash: call.inputHash!,
      now: '2026-07-12T08:20:00.000Z',
      reservationOwner: 'owner_external',
      toolCall: call,
    });
    await stores[0]!.reserveExecutionAttemptAtomically(attempt);
    const grant = executionGrant(call);
    await stores[0]!.createExecutionGrant(grant);
    await expect(
      stores[0]!.bindExecutionAttemptGrantAtomically({
        attemptId: attempt.id,
        grantId: grant.id,
        reservationOwner: attempt.reservationOwner,
        updatedAt: '2026-07-12T08:20:01.000Z',
        workspaceId: attempt.workspaceId,
      }),
    ).resolves.toMatchObject({ attempt: { grantId: grant.id }, outcome: 'bound' });

    const results = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        stores[index % stores.length]!.consumeExecutionGrantAndDispatchAttemptAtomically({
          attemptId: attempt.id,
          dispatchedAt: `2026-07-12T08:20:${String(index + 2).padStart(2, '0')}.000Z`,
          grantId: grant.id,
          reservationOwner: attempt.reservationOwner,
          toolCallId: call.id,
          workspaceId: attempt.workspaceId,
        }),
      ),
    );
    expect(results.filter((result) => result.outcome === 'dispatched')).toHaveLength(1);
    expect(results.filter((result) => result.outcome === 'grant_already_consumed')).toHaveLength(11);
    await expect(stores[0]!.getExecutionGrant(grant.id)).resolves.toMatchObject({ consumedAt: expect.any(String) });
    await expect(stores[0]!.getExecutionAttempt(attempt.id)).resolves.toMatchObject({
      dispatchedAt: expect.any(String),
      state: 'dispatched',
    });
  });

  it('records one immutable receipt outcome across concurrent reporters', async () => {
    const { stores } = make();
    const receipt = actionReceipt('receipt_outcome_cas');
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
          receiptId: receipt.id,
        }),
      ),
    );

    expect(results.filter((result) => result.outcome === 'recorded')).toHaveLength(1);
    expect(results.filter((result) => result.outcome === 'existing')).toHaveLength(11);
    const stored = await stores[0]!.getActionReceipt(receipt.id);
    expect(stored?.outcome).toMatchObject({
      recordedBy: expect.stringMatching(/^runner-/u),
      result: { providerRequestId: 'provider_1' },
      status: 'succeeded',
    });
    await stores[0]!.recordActionReceiptOutcomeAtomically({
      outcome: {
        error: 'conflicting failure',
        recordedAt: '2026-07-12T08:31:00.000Z',
        recordedBy: 'attacker',
        status: 'failed',
      },
      receiptId: receipt.id,
    });
    await expect(stores[0]!.getActionReceipt(receipt.id)).resolves.toEqual(stored);
  });

  it('atomically records a complete prepared-native terminal outcome under races', async () => {
    const { stores } = make();
    const fixture = preparedNativeOutcomeFixture('atomic_known_outcome');
    await stores[0]!.createToolCall(fixture.toolCall);
    await stores[0]!.createActionReceipt(fixture.receipt);
    await expect(stores[0]!.reserveExecutionAttemptAtomically(fixture.attempt))
      .resolves.toMatchObject({ outcome: 'reserved' });
    await stores[0]!.createExecutionGrant(fixture.grant);
    await expect(stores[0]!.bindExecutionAttemptGrantAtomically({
      attemptId: fixture.attempt.id,
      grantId: fixture.grant.id,
      reservationOwner: fixture.attempt.reservationOwner,
      updatedAt: '2026-07-12T08:40:00.500Z',
      workspaceId: 'default',
    })).resolves.toMatchObject({ outcome: 'bound' });
    await expect(stores[0]!.consumeExecutionGrantAndDispatchAttemptAtomically({
      attemptId: fixture.attempt.id,
      dispatchedAt: '2026-07-12T08:40:01.000Z',
      grantId: fixture.grant.id,
      reservationOwner: fixture.attempt.reservationOwner,
      toolCallId: fixture.toolCall.id,
      workspaceId: 'default',
    })).resolves.toMatchObject({ outcome: 'dispatched' });
    await expect(stores[0]!.recordKnownExternalExecutionOutcomeAtomically({
      ...fixture.recording,
      reservationOwner: 'wrong-owner',
    })).resolves.toMatchObject({ outcome: 'owner_mismatch' });
    await expect(stores[0]!.recordKnownExternalExecutionOutcomeAtomically({
      ...fixture.recording,
      toolCall: {
        ...fixture.recording.toolCall,
        actionEnvelope: {
          ...fixture.recording.toolCall.actionEnvelope!,
          preparedAction: {
            ...fixture.recording.toolCall.actionEnvelope!.preparedAction!,
            intentHash: 'tampered-intent-hash',
          },
        },
      },
    })).resolves.toMatchObject({ outcome: 'binding_mismatch' });
    await expect(stores[0]!.getExecutionAttempt(fixture.attempt.id))
      .resolves.toMatchObject({ state: 'dispatched' });
    expect((await stores[0]!.getActionReceipt(fixture.receipt.id))?.outcome).toBeUndefined();
    await expect(stores[0]!.getToolCall(fixture.toolCall.id))
      .resolves.toMatchObject({ status: 'authorized' });

    const results = await Promise.all(Array.from({ length: 12 }, (_, index) =>
      stores[index % stores.length]!.recordKnownExternalExecutionOutcomeAtomically(fixture.recording)));
    expect(results.filter(({ outcome }) => outcome === 'recorded')).toHaveLength(1);
    expect(results.filter(({ outcome }) => outcome === 'replay')).toHaveLength(11);
    await expect(stores[0]!.getExecutionAttempt(fixture.attempt.id))
      .resolves.toMatchObject({ outcome: fixture.recording.attemptOutcome, state: 'succeeded' });
    await expect(stores[0]!.getActionReceipt(fixture.receipt.id))
      .resolves.toMatchObject({ outcome: fixture.recording.receiptOutcome });
    await expect(stores[0]!.getToolCall(fixture.toolCall.id))
      .resolves.toMatchObject({ status: 'executed' });
  });
});

function toolCall(id: string, workspaceId = 'default'): ToolCallRecord {
  return {
    actionEnvelopeHash: `envelope_${id}`,
    agentId: 'storage-test-agent',
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
    reason: 'Storage contract test',
    requestedBy: 'storage-test',
    status: 'submitted',
    toolName: 'docs.search',
    updatedAt: '2026-07-12T08:00:00.000Z',
    workspaceId,
  };
}

function governedToolCall(id: string, workspaceId = 'default'): ToolCallRecord {
  const influenceScopeId = `influence_${'a'.repeat(64)}`;
  const call = toolCall(id, workspaceId);
  return {
    ...call,
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
      policyVersionHash: call.policyVersionHash!,
      selectedRule: { allowFrom: ['none'], otherwise: 'required' },
    }),
    influenceScopeId,
    resultSource: { integrity: 'public_untrusted', sourceId: 'public-web' },
  };
}

function idempotency(
  call: ToolCallRecord,
  overrides: Partial<IdempotencyRecord> = {},
): IdempotencyRecord {
  return {
    createdAt: call.createdAt,
    key: 'idempotency-key',
    requestHash: 'request-hash',
    route: 'POST /v1/tool-calls',
    toolCallId: call.id,
    workspaceId: call.workspaceId ?? 'default',
    ...overrides,
  };
}

function executionGrant(call: ToolCallRecord): ExecutionGrantRecord {
  return {
    actor: 'storage-test',
    createdAt: '2026-07-12T08:20:00.000Z',
    expiresAt: '2099-07-12T08:20:00.000Z',
    id: 'grant_external',
    inputHash: call.inputHash!,
    nonce: 'grant-nonce',
    policyVersionHash: call.policyVersionHash,
    signature: 'grant-signature',
    toolCallId: call.id,
    toolName: call.toolName,
    workspaceId: call.workspaceId ?? 'default',
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

function approvedAttemptFixture(
  suffix: string,
  options: {
    authorizationConsumedReason?: ApprovalRecord['authorizationConsumedReason'];
    expiresAt?: string;
    mutateAuthorization?: boolean;
  } = {},
) {
  const toolCallId = `toolcall_approval_${suffix}`;
  const approvalId = `approval_${suffix}`;
  const toolCallRecord: ToolCallRecord = {
    ...toolCall(toolCallId),
    decision: 'require_approval',
    status: 'authorized',
    toolName: 'gmail.send_email',
  };
  const authorization = buildApprovalAuthorization({
    approvalId,
    expiresAt: options.expiresAt ?? '2999-01-01T00:00:00.000Z',
    issuedAt: '2000-01-01T00:00:00.000Z',
    nonce: `nonce_${suffix}`,
    originalEnvelopeHash: toolCallRecord.actionEnvelopeHash!,
    originalInputHash: toolCallRecord.inputHash!,
    requestedBy: toolCallRecord.requestedBy,
    reviewHash: `review_${suffix}`,
    toolCall: { ...toolCallRecord, status: 'pending_approval' },
  });
  const storedAuthorization = options.mutateAuthorization
    ? {
        ...authorization,
        binding: {
          ...authorization.binding,
          action: { ...authorization.binding.action, originalInputHash: 'mutated_input_hash' },
        },
      }
    : authorization;
  const approval: ApprovalRecord = {
    approvedEnvelopeHash: toolCallRecord.actionEnvelopeHash,
    approvedInputHash: toolCallRecord.inputHash,
    authorization: storedAuthorization,
    authorizationConsumedAt: '2026-07-12T08:00:01.000Z',
    authorizationConsumedReason: options.authorizationConsumedReason ?? 'approved',
    createdAt: '2026-07-12T08:00:00.000Z',
    id: approvalId,
    originalEnvelopeHash: toolCallRecord.actionEnvelopeHash,
    originalInput: toolCallRecord.input,
    originalInputHash: toolCallRecord.inputHash,
    requestedBy: toolCallRecord.requestedBy,
    reviewHash: `review_${suffix}`,
    status: 'approved',
    toolCallId,
    updatedAt: '2026-07-12T08:00:01.000Z',
    workspaceId: 'default',
  };
  return {
    approval,
    attempt: buildExecutionAttempt({
      approval,
      executionMode: 'local_mock',
      id: `attempt_approval_${suffix}`,
      inputHash: toolCallRecord.inputHash!,
      now: '2026-07-12T08:00:02.000Z',
      toolCall: toolCallRecord,
    }),
    toolCall: toolCallRecord,
  };
}

function preparedNativeOutcomeFixture(suffix: string) {
  const input = { body: 'Exact body', subject: 'Exact subject', to: 'recipient@example.com' };
  const inputHash = hashJson(input);
  const envelopeHash = `envelope_hash_${suffix}`;
  const createdAt = '2026-07-12T08:40:00.000Z';
  const toolCallRecord: ToolCallRecord = {
    actionEnvelope: {
      actor: { id: 'storage-test', type: 'local' },
      agent: { id: 'storage-test-agent' },
      context: { reason: 'Prepared native atomic outcome test' },
      envelopeHash,
      executionMode: 'external_grant',
      input,
      inputHash,
      operation: { name: 'notifications.deliver' },
      preparedAction: {
        adapterId: 'google_workspace',
        adapterVersion: '1',
        contractHash: `contract_hash_${suffix}`,
        contractId: 'actionproxy.prepared-test.v1',
        contractVersion: '1',
        intentHash: `intent_hash_${suffix}`,
        intentId: `intent_${suffix}`,
        operationHash: `operation_hash_${suffix}`,
        serializerVersion: '1',
        version: 'actionproxy.prepared-action-binding.v1',
      },
      protocol: 'actionproxy_http',
      source: { name: 'storage-test', type: 'sdk' },
      toolName: 'notifications.deliver',
      version: 'actionproxy.action.v1',
    },
    actionEnvelopeHash: envelopeHash,
    agentId: 'storage-test-agent',
    createdAt,
    decision: 'require_approval',
    id: `toolcall_${suffix}`,
    input,
    inputHash,
    metadata: {},
    policyVersionHash: `policy_hash_${suffix}`,
    reason: 'Prepared native atomic outcome test',
    requestedBy: 'storage-test',
    result: { externalExecution: true },
    status: 'authorized',
    toolName: 'notifications.deliver',
    updatedAt: createdAt,
    workspaceId: 'default',
  };
  const receipt: ActionReceiptRecord = {
    approvedEnvelopeHash: envelopeHash,
    approvedInputHash: inputHash,
    createdAt,
    decisionActor: 'storage-test',
    decisionKind: 'human_approval',
    executionMode: 'external_grant',
    id: `receipt_${suffix}`,
    issuedAt: createdAt,
    keyId: 'test-key',
    operation: toolCallRecord.actionEnvelope!.operation,
    originalEnvelopeHash: envelopeHash,
    originalInputHash: inputHash,
    policyVersionHash: toolCallRecord.policyVersionHash,
    protocol: 'actionproxy_http',
    receiptHash: `receipt_hash_${suffix}`,
    signature: 'test-signature',
    signatureAlg: 'HMAC-SHA256',
    source: toolCallRecord.actionEnvelope!.source,
    toolCallId: toolCallRecord.id,
    toolName: toolCallRecord.toolName,
    version: 'actionproxy.receipt.v1',
    workspaceId: 'default',
  };
  const attempt = buildExecutionAttempt({
    executionMode: 'external_grant',
    id: `attempt_${suffix}`,
    inputHash,
    now: createdAt,
    receipt,
    reservationOwner: `owner_${suffix}`,
    toolCall: toolCallRecord,
  });
  const grant: ExecutionGrantRecord = {
    actor: 'storage-test',
    approvedEnvelopeHash: envelopeHash,
    approvedInputHash: inputHash,
    createdAt,
    expiresAt: '2099-07-12T08:40:00.000Z',
    id: `grant_${suffix}`,
    inputHash,
    nonce: 'grant-nonce',
    policyVersionHash: toolCallRecord.policyVersionHash,
    receiptHash: receipt.receiptHash,
    receiptId: receipt.id,
    signature: 'grant-signature',
    toolCallId: toolCallRecord.id,
    toolName: toolCallRecord.toolName,
    workspaceId: 'default',
  };
  const providerResult = { id: `provider_${suffix}` };
  const resultDelivery = {
    byteCount: 32,
    canonicalResultHash: hashJson(providerResult),
    modelVisible: true,
    version: 'actionproxy.result-delivery.v1' as const,
  };
  const completedAt = '2026-07-12T08:40:02.000Z';
  const receiptOutcome: NonNullable<ActionReceiptRecord['outcome']> = {
    recordedAt: completedAt,
    recordedBy: 'storage-test',
    result: providerResult,
    resultDelivery,
    status: 'succeeded',
  };
  return {
    attempt,
    grant,
    receipt,
    recording: {
      attemptId: attempt.id,
      attemptOutcome: executionAttemptOutcome('succeeded', {
        recordedAt: completedAt,
        result: providerResult,
        resultDelivery,
      }),
      receiptOutcome,
      reservationOwner: attempt.reservationOwner,
      toolCall: {
        ...toolCallRecord,
        result: {
          ...(toolCallRecord.result as Record<string, unknown>),
          externalExecutionOutcome: providerResult,
        },
        resultDelivery,
        resultWithheld: false,
        status: 'executed' as const,
        updatedAt: completedAt,
      },
      workspaceId: 'default',
    },
    toolCall: toolCallRecord,
  };
}
