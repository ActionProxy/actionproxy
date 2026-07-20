import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildApprovalAuthorization } from './approval-authorization';
import type { ExecutionAttemptRecordV1 } from './execution-attempt';
import type { ApprovalRecord, ToolCallRecord } from '../models';
import {
  buildExecutionAuthorizationBinding,
  CONSERVATIVE_EXECUTOR_CAPABILITIES_V1,
  createExecutionAuthorizationAuthority,
  DEFAULT_EXECUTION_AUTHORIZATION_TTL_MS,
  ExecutionAuthorizationError,
  EXECUTION_AUTHORIZATION_VERSION,
  EXECUTOR_CAPABILITIES_VERSION,
  type ExecutionAuthorization,
  type ExecutionAuthorizationBindingV1,
  type ExecutionAuthorizationProjectionV1,
  type ExecutorCapabilitiesV1,
} from './execution-authorization';

interface FixtureCorpus {
  binding: ExecutionAuthorizationBindingV1;
  capabilities: ExecutorCapabilitiesV1;
  projection: ExecutionAuthorizationProjectionV1;
  version: string;
}

const fixture = JSON.parse(
  fs.readFileSync(path.resolve(process.cwd(), '../../fixtures/contracts/execution-authorization-v1.json'), 'utf8'),
) as FixtureCorpus;

const ISSUED_AT = '2026-07-12T00:00:00.000Z';

describe('actionproxy.execution-authorization.v1', () => {
  it('matches the deterministic reusable projection fixture', () => {
    const authority = fixtureAuthority();
    const authorization = authority.issue({ binding: fixture.binding });

    expect(fixture.version).toBe(EXECUTION_AUTHORIZATION_VERSION);
    expect(authority.inspect(authorization)).toEqual(fixture.projection);

    const secondAuthority = fixtureAuthority();
    expect(secondAuthority.inspect(secondAuthority.issue({ binding: fixture.binding }))).toEqual(fixture.projection);
  });

  it('derives the shared binding from authoritative request, approval, and attempt records', () => {
    const { approval, attempt, toolCall } = authoritativeRecords();

    expect(buildExecutionAuthorizationBinding({ approval, attempt, toolCall })).toEqual(fixture.binding);
  });

  it('rejects fabricated, serialized, and foreign-authority tokens', () => {
    const authority = fixtureAuthority();
    const foreignAuthority = fixtureAuthority();
    const foreignToken = foreignAuthority.issue({ binding: fixture.binding });
    const fabricated = Object.freeze({}) as ExecutionAuthorization;
    const serialized = JSON.parse(JSON.stringify(foreignToken)) as ExecutionAuthorization;

    for (const token of [fabricated, serialized, foreignToken]) {
      expectAuthorizationError(
        () => authority.consume(token, fixture.binding),
        'execution_authorization_invalid',
      );
    }
    expect(JSON.stringify(foreignToken)).toBe('{}');
  });

  it('expires at the server-authoritative deadline', () => {
    let now = new Date(ISSUED_AT);
    const authority = createExecutionAuthorizationAuthority({
      clock: () => now,
      idFactory: () => 'execauth_fixture',
    });
    const authorization = authority.issue({ binding: fixture.binding });
    now = new Date('2026-07-12T00:01:00.000Z');

    expectAuthorizationError(
      () => authority.consume(authorization, fixture.binding),
      'execution_authorization_expired',
    );
  });

  it('consumes a valid authorization exactly once', () => {
    const authority = fixtureAuthority();
    const authorization = authority.issue({ binding: fixture.binding });

    expect(authority.consume(authorization, fixture.binding)).toEqual(fixture.projection);
    expectAuthorizationError(
      () => authority.consume(authorization, fixture.binding),
      'execution_authorization_replayed',
    );
  });

  it.each([
    ['tenant', (binding: ExecutionAuthorizationBindingV1) => { binding.tenant.workspaceId = 'tenant_forged'; }],
    ['input', (binding: ExecutionAuthorizationBindingV1) => { binding.action.inputHash = 'input_mutated'; }],
    ['policy', (binding: ExecutionAuthorizationBindingV1) => { binding.policy.versionHash = 'policy_mutated'; }],
    ['approval', (binding: ExecutionAuthorizationBindingV1) => { binding.approval.authorizationHash = 'approval_mutated'; }],
    ['content influence', (binding: ExecutionAuthorizationBindingV1) => {
      binding.contentInfluence.resultSourceHash = 'result_source_mutated';
    }],
    ['attempt', (binding: ExecutionAuthorizationBindingV1) => { binding.execution.attemptId = 'attempt_mutated'; }],
    ['executor', (binding: ExecutionAuthorizationBindingV1) => {
      binding.executor.id = 'actionproxy.external-runner';
    }],
  ] as const)('rejects %s binding mutation without consuming the capability', (_name, mutate) => {
    const authority = fixtureAuthority();
    const authorization = authority.issue({ binding: fixture.binding });
    const mutated = mutableBinding();
    mutate(mutated);

    expectAuthorizationError(
      () => authority.consume(authorization, mutated),
      'execution_authorization_binding_mismatch',
    );
    expect(authority.consume(authorization, fixture.binding)).toEqual(fixture.projection);
  });

  it('fails binding construction closed when authoritative records drift', () => {
    const cases: Array<{
      mutate: (records: ReturnType<typeof authoritativeRecords>) => void;
      name: string;
    }> = [
      {
        name: 'tenant',
        mutate: ({ attempt }) => { attempt.workspaceId = 'tenant_mutated'; },
      },
      {
        name: 'input',
        mutate: ({ attempt }) => { attempt.inputHash = 'input_mutated'; },
      },
      {
        name: 'policy',
        mutate: ({ attempt }) => { attempt.binding.policyVersionHash = 'policy_mutated'; },
      },
      {
        name: 'approval',
        mutate: ({ approval }) => { approval.authorization!.authorizationHash = 'approval_mutated'; },
      },
      {
        name: 'tool call identity',
        mutate: ({ attempt }) => { attempt.toolCallId = 'toolcall_mutated'; },
      },
      {
        name: 'content influence',
        mutate: ({ attempt }) => { attempt.binding.resultSourceHash = 'result_source_mutated'; },
      },
      {
        name: 'executor',
        mutate: ({ attempt }) => { attempt.executorId = 'actionproxy.external-runner'; },
      },
    ];

    for (const testCase of cases) {
      const records = authoritativeRecords();
      testCase.mutate(records);
      expectAuthorizationError(
        () => buildExecutionAuthorizationBinding(records),
        'execution_authorization_binding_mismatch',
      );
    }
  });

  it('uses an immutable, conservative, credential-free capability projection', () => {
    const authority = fixtureAuthority();
    const authorization = authority.issue({ binding: fixture.binding });
    const projection = authority.inspect(authorization);

    expect(DEFAULT_EXECUTION_AUTHORIZATION_TTL_MS).toBe(60_000);
    expect(CONSERVATIVE_EXECUTOR_CAPABILITIES_V1).toEqual(fixture.capabilities);
    expect(projection.capabilities).toEqual({
      automaticRetry: { supported: false },
      cancellation: { supported: false },
      credentialCustody: { acceptsRawCredentials: false, mode: 'executor_boundary_only' },
      providerIdempotency: { supported: false },
      reconciliation: { supported: false },
      timeout: { enforced: false, timeoutMs: null },
      version: EXECUTOR_CAPABILITIES_VERSION,
    });
    expect(Object.isFrozen(projection)).toBe(true);
    expect(Object.isFrozen(projection.binding)).toBe(true);
    expect(Object.isFrozen(projection.binding.action)).toBe(true);
    expect(Object.isFrozen(projection.capabilities)).toBe(true);
    expect(() => {
      (projection.binding.action as { inputHash: string }).inputHash = 'mutated';
    }).toThrow(TypeError);

    const serializedProjection = JSON.stringify(projection);
    expect(serializedProjection).not.toContain('credential-canary-t5');
    expect(serializedProjection).not.toContain('credentialReference');
    expect(serializedProjection).not.toContain('accessToken');
    expect(serializedProjection).not.toContain('refreshToken');
    expect(serializedProjection).not.toContain('password');
    expect(serializedProjection).not.toContain('reservationOwner');
    expect(JSON.stringify(authorization)).toBe('{}');
  });

});

function fixtureAuthority() {
  return createExecutionAuthorizationAuthority({
    clock: () => new Date(ISSUED_AT),
    idFactory: () => 'execauth_fixture',
  });
}

function mutableBinding(): ExecutionAuthorizationBindingV1 {
  return JSON.parse(JSON.stringify(fixture.binding)) as ExecutionAuthorizationBindingV1;
}

function authoritativeRecords(): {
  approval: ApprovalRecord;
  attempt: ExecutionAttemptRecordV1;
  toolCall: ToolCallRecord;
} {
  const toolCall: ToolCallRecord = {
    actionEnvelopeHash: fixture.binding.action.actionEnvelopeHash,
    agentId: 'agent_fixture',
    canonicalActionRequestHash: fixture.binding.request.canonicalActionRequestHash ?? undefined,
    canonicalActionRequestVersion: 'actionproxy.action-request.v1',
    canonicalDecisionInputHash: fixture.binding.decision.decisionInputHash ?? undefined,
    createdAt: ISSUED_AT,
    decision: 'require_approval',
    decisionTrace: {
      decisionV1: {
        decisionId: fixture.binding.decision.decisionId,
        decisionInputHash: fixture.binding.decision.decisionInputHash,
        evaluatorVersion: fixture.binding.policy.evaluatorVersion,
        policy: {
          digest: fixture.binding.policy.digest,
          provider: {
            id: fixture.binding.policy.providerId,
            version: fixture.binding.policy.providerVersion,
          },
          version: fixture.binding.policy.version,
        },
        version: 'actionproxy.decision.v1',
      },
    },
    id: fixture.binding.request.toolCallId,
    input: { subject: 'Launch', to: 'ops@example.com' },
    inputHash: fixture.binding.action.inputHash,
    metadata: {},
    policyVersionHash: fixture.binding.policy.versionHash,
    policyVersionId: fixture.binding.policy.version ?? undefined,
    reason: 'Fixture approval-bound action',
    requestedBy: 'actor_fixture',
    status: 'authorized',
    toolName: fixture.binding.action.toolName,
    updatedAt: ISSUED_AT,
    workspaceId: fixture.binding.tenant.workspaceId,
  };
  const approvalAuthorization = buildApprovalAuthorization({
    approvalId: fixture.binding.approval.approvalId!,
    expiresAt: '2999-07-13T00:00:00.000Z',
    issuedAt: ISSUED_AT,
    nonce: fixture.binding.approval.authorizationNonce!,
    originalEnvelopeHash: fixture.binding.action.actionEnvelopeHash,
    originalInputHash: fixture.binding.action.inputHash,
    requestedBy: toolCall.requestedBy,
    reviewHash: 'review_fixture_hash',
    toolCall,
  });
  const approval: ApprovalRecord = {
    approvedInputHash: fixture.binding.action.inputHash,
    authorization: approvalAuthorization,
    authorizationConsumedAt: '2026-07-12T00:00:01.000Z',
    authorizationConsumedReason: 'approved',
    createdAt: ISSUED_AT,
    id: fixture.binding.approval.approvalId!,
    originalEnvelopeHash: fixture.binding.action.actionEnvelopeHash,
    originalInput: toolCall.input,
    originalInputHash: fixture.binding.action.inputHash,
    requestedBy: toolCall.requestedBy,
    reviewHash: 'review_fixture_hash',
    status: 'approved',
    toolCallId: toolCall.id,
    updatedAt: ISSUED_AT,
    workspaceId: toolCall.workspaceId,
  };
  const attempt: ExecutionAttemptRecordV1 = {
    attemptNumber: fixture.binding.execution.attemptNumber,
    binding: {
      actionEnvelopeHash: fixture.binding.action.actionEnvelopeHash,
      approvalAuthorizationHash: fixture.binding.approval.authorizationHash,
      approvalAuthorizationNonce: fixture.binding.approval.authorizationNonce,
      approvalId: fixture.binding.approval.approvalId,
      canonicalActionRequestHash: fixture.binding.request.canonicalActionRequestHash,
      canonicalActionRequestVersion: fixture.binding.request.canonicalActionRequestVersion,
      canonicalDecisionInputHash: fixture.binding.decision.decisionInputHash,
      contentInfluenceBindingHash: fixture.binding.contentInfluence.bindingHash,
      decisionId: fixture.binding.decision.decisionId,
      decisionVersion: fixture.binding.decision.version,
      influenceScopeId: fixture.binding.contentInfluence.influenceScopeId,
      policyVersionHash: fixture.binding.policy.versionHash,
      receiptHash: fixture.binding.approval.receiptHash,
      receiptId: fixture.binding.approval.receiptId,
      resultSourceHash: fixture.binding.contentInfluence.resultSourceHash,
    },
    executionMode: fixture.binding.execution.mode,
    executorId: fixture.binding.executor.id,
    id: fixture.binding.execution.attemptId,
    inputHash: fixture.binding.action.inputHash,
    providerIdempotency: 'none',
    reservedAt: ISSUED_AT,
    reservationOwner: 'reservation_fixture',
    retryPolicy: 'never_automatic',
    state: 'reserved',
    toolCallId: fixture.binding.request.toolCallId,
    updatedAt: ISSUED_AT,
    version: 'actionproxy.execution-attempt.v1',
    workspaceId: fixture.binding.tenant.workspaceId,
  };
  return { approval, attempt, toolCall };
}

function expectAuthorizationError(
  action: () => unknown,
  code: ExecutionAuthorizationError['code'],
): void {
  try {
    action();
    throw new Error(`Expected ${code}.`);
  } catch (error) {
    expect(error).toBeInstanceOf(ExecutionAuthorizationError);
    expect((error as ExecutionAuthorizationError).code).toBe(code);
  }
}
