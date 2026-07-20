import { randomUUID } from 'node:crypto';
import type {
  ActionReceiptRecord,
  ApprovalRecord,
  JsonObject,
  RemediationDescriptor,
  ResultDeliveryMetadataV1,
  ToolCallRecord,
} from '../models';
import { hashJson } from '../security/crypto';
import { validContentInfluenceBindingHash } from './content-influence';

export const EXECUTION_ATTEMPT_VERSION = 'actionproxy.execution-attempt.v1' as const;

export type ExecutionAttemptState =
  | 'reserved'
  | 'dispatched'
  | 'succeeded'
  | 'failed_before_dispatch'
  | 'failed_after_dispatch'
  | 'timed_out'
  | 'cancelled'
  | 'unknown_outcome';

export type ExecutionAttemptTerminalState = Exclude<ExecutionAttemptState, 'reserved' | 'dispatched'>;
export type ExecutionRetryDisposition =
  | 'none'
  | 'explicit_new_attempt_required'
  | 'manual_reconciliation_required';

export interface ExecutionAttemptBindingV1 {
  actionEnvelopeHash: string | null;
  approvalAuthorizationHash: string | null;
  approvalAuthorizationNonce: string | null;
  approvalId: string | null;
  canonicalActionRequestHash: string | null;
  canonicalActionRequestVersion: string | null;
  canonicalDecisionInputHash: string | null;
  contentInfluenceBindingHash?: string | null;
  decisionId: string | null;
  decisionVersion: string | null;
  influenceScopeId?: string | null;
  policyVersionHash: string | null;
  receiptHash: string | null;
  receiptId: string | null;
  resultSourceHash?: string;
}

export interface ExecutionAttemptOutcomeV1 {
  certainty: 'known' | 'unknown';
  errorClass: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  remediationHash: string | null;
  recordedAt: string;
  resultDeliveryHash: string | null;
  resultHash: string | null;
  retryDisposition: ExecutionRetryDisposition;
  status: ExecutionAttemptTerminalState;
}

export interface ExecutionAttemptRecordV1 {
  attemptNumber: number;
  binding: ExecutionAttemptBindingV1;
  completedAt?: string;
  dispatchedAt?: string;
  executionMode: 'external_grant' | 'local_mock';
  executorId: 'actionproxy.external-runner' | 'actionproxy.local-tool-registry';
  grantId?: string;
  id: string;
  inputHash: string;
  outcome?: ExecutionAttemptOutcomeV1;
  providerIdempotency: 'none';
  reservedAt: string;
  reservationOwner: string;
  retryPolicy: 'never_automatic';
  state: ExecutionAttemptState;
  toolCallId: string;
  updatedAt: string;
  version: typeof EXECUTION_ATTEMPT_VERSION;
  workspaceId: string;
}

export interface BuildExecutionAttemptInput {
  approval?: ApprovalRecord;
  executionMode: ExecutionAttemptRecordV1['executionMode'];
  id?: string;
  inputHash: string;
  now: string;
  receipt?: ActionReceiptRecord;
  reservationOwner?: string;
  toolCall: ToolCallRecord;
}

export function buildExecutionAttempt(input: BuildExecutionAttemptInput): ExecutionAttemptRecordV1 {
  const decision = decisionIdentity(input.toolCall);
  return {
    attemptNumber: 1,
    binding: {
      actionEnvelopeHash: input.toolCall.actionEnvelopeHash ?? null,
      approvalAuthorizationHash: input.approval?.authorization?.authorizationHash ?? null,
      approvalAuthorizationNonce: input.approval?.authorization?.nonce ?? null,
      approvalId: input.approval?.id ?? input.receipt?.approvalId ?? null,
      canonicalActionRequestHash: input.toolCall.canonicalActionRequestHash ?? null,
      canonicalActionRequestVersion: input.toolCall.canonicalActionRequestVersion ?? null,
      canonicalDecisionInputHash: input.toolCall.canonicalDecisionInputHash ?? null,
      contentInfluenceBindingHash:
        validContentInfluenceBindingHash(input.toolCall.contentInfluence) ??
        (input.toolCall.contentInfluence ? 'invalid' : null),
      decisionId: decision.decisionId,
      decisionVersion: decision.version,
      influenceScopeId: input.toolCall.influenceScopeId ?? null,
      policyVersionHash: input.toolCall.policyVersionHash ?? null,
      receiptHash: input.receipt?.receiptHash ?? null,
      receiptId: input.receipt?.id ?? null,
      resultSourceHash: hashJson(input.toolCall.resultSource ?? null),
    },
    executionMode: input.executionMode,
    executorId:
      input.executionMode === 'external_grant'
        ? 'actionproxy.external-runner'
        : 'actionproxy.local-tool-registry',
    id: input.id ?? `attempt_${randomUUID()}`,
    inputHash: input.inputHash,
    providerIdempotency: 'none',
    reservedAt: input.now,
    reservationOwner: input.reservationOwner ?? `reservation_${randomUUID()}`,
    retryPolicy: 'never_automatic',
    state: 'reserved',
    toolCallId: input.toolCall.id,
    updatedAt: input.now,
    version: EXECUTION_ATTEMPT_VERSION,
    workspaceId: input.toolCall.workspaceId ?? 'default',
  };
}

export function executionAttemptOutcome(
  status: ExecutionAttemptTerminalState,
  input: {
    errorClass?: string;
    errorCode?: string;
    errorMessage?: string;
    remediation?: RemediationDescriptor;
    recordedAt: string;
    result?: JsonObject;
    resultDelivery?: ResultDeliveryMetadataV1;
  },
): ExecutionAttemptOutcomeV1 {
  const uncertain = status === 'timed_out' || status === 'unknown_outcome';
  return {
    certainty: uncertain ? 'unknown' : 'known',
    errorClass: input.errorClass ?? null,
    errorCode: input.errorCode ?? null,
    errorMessage: input.errorMessage ?? null,
    remediationHash: input.remediation === undefined ? null : hashJson(input.remediation),
    recordedAt: input.recordedAt,
    resultDeliveryHash: input.resultDelivery === undefined ? null : hashJson(input.resultDelivery),
    resultHash: input.result === undefined ? null : hashJson(input.result),
    retryDisposition: uncertain
      ? 'manual_reconciliation_required'
      : status === 'failed_before_dispatch'
        ? 'explicit_new_attempt_required'
        : 'none',
    status,
  };
}

export function isExecutionAttemptTerminal(state: ExecutionAttemptState): state is ExecutionAttemptTerminalState {
  return state !== 'reserved' && state !== 'dispatched';
}

function decisionIdentity(toolCall: ToolCallRecord): { decisionId: string | null; version: string | null } {
  const decision = toolCall.decisionTrace?.decisionV1;
  if (!isRecord(decision)) return { decisionId: null, version: null };
  return {
    decisionId: typeof decision.decisionId === 'string' ? decision.decisionId : null,
    version: typeof decision.version === 'string' ? decision.version : null,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
