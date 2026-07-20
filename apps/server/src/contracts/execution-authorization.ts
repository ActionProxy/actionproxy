import { randomUUID } from 'node:crypto';
import type { ApprovalRecord, JsonObject, PolicyDecision, ToolCallRecord } from '../models';
import { hashJson } from '../security/crypto';
import { canonicalJsonStringify } from './action-request';
import {
  approvalAuthorizationExpired,
  approvalAuthorizationMismatch,
  isValidApprovalAuthorization,
} from './approval-authorization';
import type { ExecutionAttemptRecordV1 } from './execution-attempt';
import { validContentInfluenceBindingHash } from './content-influence';

export const EXECUTION_AUTHORIZATION_VERSION = 'actionproxy.execution-authorization.v1' as const;
export const EXECUTOR_CAPABILITIES_VERSION = 'actionproxy.executor-capabilities.v1' as const;
export const DEFAULT_EXECUTION_AUTHORIZATION_TTL_MS = 60_000;

export type ExecutionAuthorizationErrorCode =
  | 'execution_authorization_binding_mismatch'
  | 'execution_authorization_expired'
  | 'execution_authorization_invalid'
  | 'execution_authorization_replayed';

export class ExecutionAuthorizationError extends Error {
  constructor(
    readonly code: ExecutionAuthorizationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'ExecutionAuthorizationError';
  }
}

export interface ExecutorCapabilitiesV1 {
  automaticRetry: {
    supported: false;
  };
  cancellation: {
    supported: false;
  };
  credentialCustody: {
    acceptsRawCredentials: false;
    mode: 'executor_boundary_only';
  };
  providerIdempotency: {
    supported: false;
  };
  reconciliation: {
    supported: false;
  };
  timeout: {
    enforced: false;
    timeoutMs: null;
  };
  version: typeof EXECUTOR_CAPABILITIES_VERSION;
}

export interface ExecutionAuthorizationBindingV1 {
  action: {
    actionEnvelopeHash: string;
    inputHash: string;
    toolName: string;
  };
  approval: {
    approvalId: string | null;
    authorizationHash: string | null;
    authorizationNonce: string | null;
    receiptHash: string | null;
    receiptId: string | null;
  };
  contentInfluence: {
    bindingHash: string | null;
    influenceScopeId: string | null;
    resultSourceHash: string;
  };
  decision: {
    decisionId: string | null;
    decisionInputHash: string | null;
    outcome: PolicyDecision;
    version: 'actionproxy.decision.v1' | null;
  };
  execution: {
    attemptId: string;
    attemptNumber: number;
    grantId: string | null;
    mode: ExecutionAttemptRecordV1['executionMode'];
  };
  executor: {
    id: ExecutionAttemptRecordV1['executorId'];
  };
  policy: {
    digest: string | null;
    evaluatorVersion: string | null;
    providerId: string | null;
    providerVersion: string | null;
    version: string | null;
    versionHash: string;
  };
  request: {
    canonicalActionRequestHash: string | null;
    canonicalActionRequestVersion: 'actionproxy.action-request.v1' | null;
    toolCallId: string;
  };
  tenant: {
    workspaceId: string;
  };
}

export interface ExecutionAuthorizationProjectionV1 {
  authorizationId: string;
  binding: ExecutionAuthorizationBindingV1;
  capabilities: ExecutorCapabilitiesV1;
  expiresAt: string;
  issuedAt: string;
  version: typeof EXECUTION_AUTHORIZATION_VERSION;
}

declare const executionAuthorizationBrand: unique symbol;

/**
 * Process-local authority. The token deliberately has no serializable fields;
 * only the issuing authority's private WeakMap can resolve it.
 */
export type ExecutionAuthorization = Readonly<Record<never, never>> & {
  readonly [executionAuthorizationBrand]: true;
};

export interface AuthorizedExecutionInvocationV1 {
  authorization: ExecutionAuthorization;
  authorizationBinding: ExecutionAuthorizationBindingV1;
  input: JsonObject;
  toolName: string;
}

export interface ActionExecutor<TResult = unknown> {
  describe(): {
    capabilities: ExecutorCapabilitiesV1;
    executorId: ExecutionAttemptRecordV1['executorId'];
  };
  execute(invocation: AuthorizedExecutionInvocationV1): Promise<TResult>;
}

export interface ExecutionAuthorizationIssuer {
  inspect(authorization: ExecutionAuthorization): ExecutionAuthorizationProjectionV1;
  issue(input: {
    binding: ExecutionAuthorizationBindingV1;
    capabilities?: ExecutorCapabilitiesV1;
    ttlMs?: number;
  }): ExecutionAuthorization;
}

export interface ExecutionAuthorizationConsumer {
  consume(
    authorization: ExecutionAuthorization,
    expectedBinding: ExecutionAuthorizationBindingV1,
  ): ExecutionAuthorizationProjectionV1;
}

export type ExecutionAuthorizationAuthority = ExecutionAuthorizationConsumer & ExecutionAuthorizationIssuer;

export const CONSERVATIVE_EXECUTOR_CAPABILITIES_V1: ExecutorCapabilitiesV1 = deepFreeze({
  automaticRetry: { supported: false },
  cancellation: { supported: false },
  credentialCustody: { acceptsRawCredentials: false, mode: 'executor_boundary_only' },
  providerIdempotency: { supported: false },
  reconciliation: { supported: false },
  timeout: { enforced: false, timeoutMs: null },
  version: EXECUTOR_CAPABILITIES_VERSION,
});

export function createExecutionAuthorizationAuthority(options: {
  clock?: () => Date;
  defaultTtlMs?: number;
  idFactory?: () => string;
} = {}): ExecutionAuthorizationAuthority {
  const clock = options.clock ?? (() => new Date());
  const idFactory = options.idFactory ?? (() => `execauth_${randomUUID()}`);
  const defaultTtlMs = options.defaultTtlMs ?? DEFAULT_EXECUTION_AUTHORIZATION_TTL_MS;
  assertTtl(defaultTtlMs);

  const issued = new WeakMap<object, { consumed: boolean; projection: ExecutionAuthorizationProjectionV1 }>();

  function recordFor(authorization: ExecutionAuthorization): {
    consumed: boolean;
    projection: ExecutionAuthorizationProjectionV1;
  } {
    if (typeof authorization !== 'object' || authorization === null) {
      throw invalidAuthorization();
    }
    const record = issued.get(authorization);
    if (!record) throw invalidAuthorization();
    return record;
  }

  return Object.freeze({
    consume(
      authorization: ExecutionAuthorization,
      expectedBinding: ExecutionAuthorizationBindingV1,
    ): ExecutionAuthorizationProjectionV1 {
      const record = recordFor(authorization);
      if (record.consumed) {
        throw new ExecutionAuthorizationError(
          'execution_authorization_replayed',
          'Execution authorization has already been consumed.',
        );
      }
      if (clock().getTime() >= Date.parse(record.projection.expiresAt)) {
        throw new ExecutionAuthorizationError(
          'execution_authorization_expired',
          'Execution authorization has expired.',
        );
      }
      if (!sameCanonicalValue(record.projection.binding, expectedBinding)) {
        throw new ExecutionAuthorizationError(
          'execution_authorization_binding_mismatch',
          'Execution authorization does not match the current execution binding.',
        );
      }
      record.consumed = true;
      return record.projection;
    },

    inspect(authorization: ExecutionAuthorization): ExecutionAuthorizationProjectionV1 {
      return recordFor(authorization).projection;
    },

    issue(input: {
      binding: ExecutionAuthorizationBindingV1;
      capabilities?: ExecutorCapabilitiesV1;
      ttlMs?: number;
    }): ExecutionAuthorization {
      const ttlMs = input.ttlMs ?? defaultTtlMs;
      assertTtl(ttlMs);
      const now = clock();
      if (!Number.isFinite(now.getTime())) throw new Error('Execution authorization clock returned an invalid date.');
      const projection = deepFreeze({
        authorizationId: nonEmptyId(idFactory()),
        binding: canonicalClone(input.binding),
        capabilities: canonicalClone(input.capabilities ?? CONSERVATIVE_EXECUTOR_CAPABILITIES_V1),
        expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
        issuedAt: now.toISOString(),
        version: EXECUTION_AUTHORIZATION_VERSION,
      } satisfies ExecutionAuthorizationProjectionV1);
      const token = Object.freeze({}) as ExecutionAuthorization;
      issued.set(token, { consumed: false, projection });
      return token;
    },
  });
}

export function buildExecutionAuthorizationBinding(input: {
  approval?: ApprovalRecord;
  attempt: ExecutionAttemptRecordV1;
  toolCall: ToolCallRecord;
}): ExecutionAuthorizationBindingV1 {
  const { approval, attempt, toolCall } = input;
  const workspaceId = toolCall.workspaceId ?? 'default';
  const inputHash = toolCall.inputHash ?? hashJson(toolCall.input);
  const actionEnvelopeHash = toolCall.actionEnvelopeHash;
  const policyVersionHash = toolCall.policyVersionHash;

  if (attempt.state !== 'reserved' && attempt.state !== 'dispatched') {
    throw bindingError('Execution attempt must be reserved or dispatched for authorization.');
  }
  if (attempt.workspaceId !== workspaceId) throw bindingError('Execution attempt tenant does not match the tool call.');
  if (attempt.toolCallId !== toolCall.id) throw bindingError('Execution attempt does not match the tool call.');
  if (attempt.inputHash !== inputHash) throw bindingError('Execution attempt input does not match the tool call.');
  if (!actionEnvelopeHash || attempt.binding.actionEnvelopeHash !== actionEnvelopeHash) {
    throw bindingError('Execution attempt action envelope does not match the tool call.');
  }
  if (!policyVersionHash || attempt.binding.policyVersionHash !== policyVersionHash) {
    throw bindingError('Execution attempt policy does not match the tool call.');
  }
  if (!toolCall.decision) throw bindingError('Execution authorization requires a deterministic decision outcome.');
  if ((attempt.binding.canonicalActionRequestHash ?? null) !== (toolCall.canonicalActionRequestHash ?? null)) {
    throw bindingError('Execution attempt canonical request does not match the tool call.');
  }
  if ((attempt.binding.canonicalActionRequestVersion ?? null) !== (toolCall.canonicalActionRequestVersion ?? null)) {
    throw bindingError('Execution attempt canonical request version does not match the tool call.');
  }
  if ((attempt.binding.canonicalDecisionInputHash ?? null) !== (toolCall.canonicalDecisionInputHash ?? null)) {
    throw bindingError('Execution attempt decision input does not match the tool call.');
  }
  const contentInfluenceBindingHash = validContentInfluenceBindingHash(toolCall.contentInfluence);
  if (toolCall.contentInfluence && !contentInfluenceBindingHash) {
    throw bindingError('Tool-call content-influence evidence is invalid.');
  }
  if ((attempt.binding.contentInfluenceBindingHash ?? null) !== (contentInfluenceBindingHash ?? null)) {
    throw bindingError('Execution attempt content-influence evidence does not match the tool call.');
  }
  if ((attempt.binding.influenceScopeId ?? null) !== (toolCall.influenceScopeId ?? null)) {
    throw bindingError('Execution attempt influence scope does not match the tool call.');
  }
  const resultSourceHash = hashJson(toolCall.resultSource ?? null);
  if (attempt.binding.resultSourceHash !== resultSourceHash) {
    throw bindingError('Execution attempt result-source classification does not match the tool call.');
  }
  if (attempt.providerIdempotency !== 'none' || attempt.retryPolicy !== 'never_automatic') {
    throw bindingError('Execution attempt declares unsupported retry or provider-idempotency behavior.');
  }
  if (
    (attempt.executionMode === 'local_mock' && attempt.executorId !== 'actionproxy.local-tool-registry') ||
    (attempt.executionMode === 'external_grant' && attempt.executorId !== 'actionproxy.external-runner')
  ) {
    throw bindingError('Execution attempt executor does not match its execution mode.');
  }
  if (attempt.executionMode === 'external_grant' && !attempt.grantId) {
    throw bindingError('External execution authorization requires a bound grant.');
  }
  if (attempt.executionMode === 'local_mock' && attempt.grantId !== undefined) {
    throw bindingError('Local execution authorization cannot bind an external grant.');
  }

  assertApprovalBinding(approval, attempt, toolCall, inputHash);
  const decision = decisionIdentity(toolCall);
  if ((attempt.binding.decisionId ?? null) !== decision.decisionId) {
    throw bindingError('Execution attempt decision identity does not match the tool call.');
  }
  if ((attempt.binding.decisionVersion ?? null) !== decision.version) {
    throw bindingError('Execution attempt decision version does not match the tool call.');
  }

  return deepFreeze({
    action: {
      actionEnvelopeHash,
      inputHash,
      toolName: toolCall.toolName,
    },
    approval: {
      approvalId: attempt.binding.approvalId,
      authorizationHash: attempt.binding.approvalAuthorizationHash,
      authorizationNonce: attempt.binding.approvalAuthorizationNonce,
      receiptHash: attempt.binding.receiptHash,
      receiptId: attempt.binding.receiptId,
    },
    contentInfluence: {
      bindingHash: contentInfluenceBindingHash ?? null,
      influenceScopeId: toolCall.influenceScopeId ?? null,
      resultSourceHash,
    },
    decision: {
      decisionId: decision.decisionId,
      decisionInputHash: attempt.binding.canonicalDecisionInputHash,
      outcome: toolCall.decision,
      version: decision.version,
    },
    execution: {
      attemptId: attempt.id,
      attemptNumber: attempt.attemptNumber,
      grantId: attempt.grantId ?? null,
      mode: attempt.executionMode,
    },
    executor: { id: attempt.executorId },
    policy: {
      digest: decision.policyDigest,
      evaluatorVersion: decision.evaluatorVersion,
      providerId: decision.providerId,
      providerVersion: decision.providerVersion,
      version: decision.policyVersion,
      versionHash: policyVersionHash,
    },
    request: {
      canonicalActionRequestHash: toolCall.canonicalActionRequestHash ?? null,
      canonicalActionRequestVersion: toolCall.canonicalActionRequestVersion ?? null,
      toolCallId: toolCall.id,
    },
    tenant: { workspaceId },
  });
}

function assertApprovalBinding(
  approval: ApprovalRecord | undefined,
  attempt: ExecutionAttemptRecordV1,
  toolCall: ToolCallRecord,
  inputHash: string,
): void {
  const approvalId = attempt.binding.approvalId;
  if (!approvalId) {
    if (approval !== undefined) throw bindingError('Unexpected approval supplied for an unapproved execution.');
    if (attempt.binding.approvalAuthorizationHash || attempt.binding.approvalAuthorizationNonce) {
      throw bindingError('Unapproved execution carries approval authorization state.');
    }
    return;
  }

  if (!approval) throw bindingError('Approval-bound execution requires the current approval record.');
  if (approval.id !== approvalId || approval.toolCallId !== toolCall.id) {
    throw bindingError('Approval does not match the execution attempt.');
  }
  if ((approval.workspaceId ?? 'default') !== attempt.workspaceId) {
    throw bindingError('Approval tenant does not match the execution attempt.');
  }
  if (approval.status !== 'approved' || approval.authorizationConsumedReason !== 'approved') {
    throw bindingError('Approval is not in an executable terminal state.');
  }
  if (!approval.authorizationConsumedAt || !approval.authorization) {
    throw bindingError('Approval authorization has not been consumed.');
  }
  if (!isValidApprovalAuthorization(approval.authorization)) {
    throw bindingError('Approval authorization integrity is invalid.');
  }
  if (approvalAuthorizationExpired(approval.authorization)) {
    throw bindingError('Approval authorization has expired.');
  }
  if (approval.authorization.authorizationHash !== attempt.binding.approvalAuthorizationHash) {
    throw bindingError('Approval authorization hash does not match the execution attempt.');
  }
  if (approval.authorization.nonce !== attempt.binding.approvalAuthorizationNonce) {
    throw bindingError('Approval authorization nonce does not match the execution attempt.');
  }
  if ((approval.approvedInputHash ?? approval.originalInputHash ?? null) !== inputHash) {
    throw bindingError('Approved input does not match the execution attempt.');
  }
  const originalToolCall: ToolCallRecord = {
    ...toolCall,
    actionEnvelopeHash: approval.originalEnvelopeHash,
    input: approval.originalInput,
    inputHash: approval.originalInputHash,
    status: 'pending_approval',
  };
  const mismatch = approvalAuthorizationMismatch(approval.authorization, approval, originalToolCall);
  if (mismatch) throw bindingError(`Approval authorization is no longer current: ${mismatch}.`);
}

function decisionIdentity(toolCall: ToolCallRecord): {
  decisionId: string | null;
  evaluatorVersion: string | null;
  policyDigest: string | null;
  policyVersion: string | null;
  providerId: string | null;
  providerVersion: string | null;
  version: 'actionproxy.decision.v1' | null;
} {
  const candidate = toolCall.decisionTrace?.decisionV1;
  if (!isRecord(candidate) || candidate.version !== 'actionproxy.decision.v1') {
    return {
      decisionId: null,
      evaluatorVersion: null,
      policyDigest: null,
      policyVersion: null,
      providerId: null,
      providerVersion: null,
      version: null,
    };
  }
  const policy = isRecord(candidate.policy) ? candidate.policy : undefined;
  const provider = policy && isRecord(policy.provider) ? policy.provider : undefined;
  return {
    decisionId: stringOrNull(candidate.decisionId),
    evaluatorVersion: stringOrNull(candidate.evaluatorVersion),
    policyDigest: stringOrNull(policy?.digest),
    policyVersion: stringOrNull(policy?.version),
    providerId: stringOrNull(provider?.id),
    providerVersion: stringOrNull(provider?.version),
    version: 'actionproxy.decision.v1',
  };
}

function bindingError(message: string): ExecutionAuthorizationError {
  return new ExecutionAuthorizationError('execution_authorization_binding_mismatch', message);
}

function invalidAuthorization(): ExecutionAuthorizationError {
  return new ExecutionAuthorizationError(
    'execution_authorization_invalid',
    'Execution authorization was not issued by this authority.',
  );
}

function assertTtl(ttlMs: number): void {
  if (!Number.isFinite(ttlMs) || !Number.isInteger(ttlMs) || ttlMs <= 0) {
    throw new Error('Execution authorization TTL must be a positive integer number of milliseconds.');
  }
}

function nonEmptyId(value: string): string {
  if (!value.trim()) throw new Error('Execution authorization ID must not be empty.');
  return value;
}

function sameCanonicalValue(left: unknown, right: unknown): boolean {
  try {
    return canonicalJsonStringify(left) === canonicalJsonStringify(right);
  } catch {
    return false;
  }
}

function canonicalClone<T>(value: T): T {
  return JSON.parse(canonicalJsonStringify(value)) as T;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  return value;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
