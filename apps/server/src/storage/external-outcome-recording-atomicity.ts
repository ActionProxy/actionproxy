import type { ExecutionAttemptOutcomeV1, ExecutionAttemptRecordV1 } from '../contracts/execution-attempt';
import { hashJson } from '../security/crypto';

interface PreparedActionBindingLike {
  intentHash: string;
  intentId: string;
}

interface ReceiptOutcomeLike {
  error?: string;
  recordedAt: string;
  remediation?: unknown;
  result?: unknown;
  resultDelivery?: unknown;
  status: string;
}

interface ReceiptLike {
  approvedEnvelopeHash: string;
  approvedInputHash: string;
  executionMode: string;
  id: string;
  outcome?: ReceiptOutcomeLike;
  receiptHash: string;
  toolCallId: string;
  toolName: string;
  workspaceId: string;
}

interface ToolCallLike {
  actionEnvelope?: { preparedAction?: PreparedActionBindingLike };
  actionEnvelopeHash?: string;
  error?: string;
  id: string;
  input: Record<string, unknown>;
  inputHash?: string;
  result?: unknown;
  resultDelivery?: unknown;
  resultWithheld?: boolean;
  status: string;
  toolName: string;
  updatedAt: string;
  workspaceId?: string;
}

interface GrantLike {
  approvedEnvelopeHash?: string;
  approvedInputHash?: string;
  consumedAt?: string;
  id: string;
  inputHash: string;
  receiptHash?: string;
  receiptId?: string;
  toolCallId: string;
  toolName: string;
  workspaceId: string;
}

export interface KnownExternalExecutionOutcomeRecordingLike {
  attemptId: string;
  attemptOutcome: ExecutionAttemptOutcomeV1;
  receiptOutcome: ReceiptOutcomeLike;
  reservationOwner: string;
  toolCall: ToolCallLike;
  workspaceId: string;
}

export function assertKnownExternalExecutionOutcomeRecordingCandidate(
  input: KnownExternalExecutionOutcomeRecordingLike,
): void {
  const succeeded = input.attemptOutcome.status === 'succeeded';
  const failed = input.attemptOutcome.status === 'failed_after_dispatch';
  const expectedReceiptStatus = succeeded ? 'succeeded' : 'failed';
  const expectedToolCallStatus = succeeded ? 'executed' : 'failed';
  const prepared = input.toolCall.actionEnvelope?.preparedAction;
  const mismatches = [
    !input.attemptId ? 'attempt_id' : undefined,
    !input.reservationOwner ? 'reservation_owner' : undefined,
    input.attemptOutcome.certainty !== 'known' ? 'attempt_certainty' : undefined,
    !succeeded && !failed ? 'attempt_status' : undefined,
    input.attemptOutcome.retryDisposition !== 'none' ? 'retry_disposition' : undefined,
    input.receiptOutcome.status !== expectedReceiptStatus ? 'receipt_status' : undefined,
    input.receiptOutcome.recordedAt !== input.attemptOutcome.recordedAt ? 'receipt_recorded_at' : undefined,
    input.toolCall.status !== expectedToolCallStatus ? 'tool_call_status' : undefined,
    input.toolCall.updatedAt !== input.attemptOutcome.recordedAt ? 'tool_call_updated_at' : undefined,
    (input.toolCall.workspaceId ?? 'default') !== input.workspaceId ? 'tool_call_workspace' : undefined,
    !input.toolCall.inputHash || hashJson(input.toolCall.input) !== input.toolCall.inputHash
      ? 'tool_call_input_hash'
      : undefined,
    !prepared?.intentId || !prepared.intentHash ? 'prepared_action' : undefined,
    input.attemptOutcome.resultDeliveryHash !== hashOptional(input.receiptOutcome.resultDelivery)
      ? 'result_delivery_hash'
      : undefined,
    input.attemptOutcome.remediationHash !== hashOptional(input.receiptOutcome.remediation)
      ? 'remediation_hash'
      : undefined,
    input.attemptOutcome.resultHash !== hashOptional(input.receiptOutcome.result)
      ? 'result_hash'
      : undefined,
    (input.attemptOutcome.errorMessage ?? null) !== (input.receiptOutcome.error ?? null)
      ? 'error_message'
      : undefined,
    succeeded && input.receiptOutcome.error !== undefined ? 'success_error' : undefined,
    failed && input.receiptOutcome.result !== undefined ? 'failure_result' : undefined,
    failed && input.receiptOutcome.remediation !== undefined ? 'failure_remediation' : undefined,
    input.toolCall.error !== (succeeded ? undefined : input.receiptOutcome.error) ? 'tool_call_error' : undefined,
    hashJson(input.toolCall.resultDelivery ?? null) !== hashJson(input.receiptOutcome.resultDelivery ?? null)
      ? 'tool_call_result_delivery'
      : undefined,
    succeeded && hashJson(externalExecutionOutcome(input.toolCall.result)) !== hashJson(input.receiptOutcome.result)
      ? 'tool_call_result'
      : undefined,
  ].filter((value): value is string => Boolean(value));
  if (mismatches.length) {
    throw new Error(`Known external execution outcome recording failed its integrity check: ${mismatches.join(', ')}.`);
  }
}

export function knownExternalOutcomeRecordingMatchesCurrent(
  input: KnownExternalExecutionOutcomeRecordingLike,
  current: {
    attempt: ExecutionAttemptRecordV1;
    grant: GrantLike;
    receipt: ReceiptLike;
    toolCall: ToolCallLike;
  },
): boolean {
  return knownExternalOutcomeRecordingBindingsMatch(input, current)
    && current.toolCall.status === 'authorized'
    && current.receipt.outcome === undefined;
}

export function knownExternalOutcomeRecordingBindingsMatch(
  input: KnownExternalExecutionOutcomeRecordingLike,
  current: {
    attempt: ExecutionAttemptRecordV1;
    grant: GrantLike;
    receipt: ReceiptLike;
    toolCall: ToolCallLike;
  },
): boolean {
  const { attempt, grant, receipt, toolCall } = current;
  const prepared = toolCall.actionEnvelope?.preparedAction;
  const candidatePrepared = input.toolCall.actionEnvelope?.preparedAction;
  return attempt.id === input.attemptId
    && attempt.workspaceId === input.workspaceId
    && attempt.toolCallId === input.toolCall.id
    && attempt.reservationOwner === input.reservationOwner
    && attempt.executionMode === 'external_grant'
    && attempt.executorId === 'actionproxy.external-runner'
    && attempt.providerIdempotency === 'none'
    && attempt.retryPolicy === 'never_automatic'
    && attempt.grantId === grant.id
    && grant.workspaceId === input.workspaceId
    && grant.toolCallId === input.toolCall.id
    && grant.toolName === input.toolCall.toolName
    && grant.consumedAt !== undefined
    && grant.inputHash === attempt.inputHash
    && grant.approvedInputHash === receipt.approvedInputHash
    && grant.approvedEnvelopeHash === receipt.approvedEnvelopeHash
    && grant.receiptId === receipt.id
    && grant.receiptHash === receipt.receiptHash
    && attempt.binding.receiptId === receipt.id
    && attempt.binding.receiptHash === receipt.receiptHash
    && attempt.binding.actionEnvelopeHash === (grant.approvedEnvelopeHash ?? null)
    && receipt.workspaceId === input.workspaceId
    && receipt.toolCallId === input.toolCall.id
    && receipt.toolName === input.toolCall.toolName
    && receipt.executionMode === 'external_grant'
    && receipt.approvedInputHash === attempt.inputHash
    && receipt.approvedEnvelopeHash === attempt.binding.actionEnvelopeHash
    && (toolCall.workspaceId ?? 'default') === input.workspaceId
    && toolCall.id === input.toolCall.id
    && toolCall.toolName === input.toolCall.toolName
    && toolCall.inputHash === attempt.inputHash
    && toolCall.actionEnvelopeHash === attempt.binding.actionEnvelopeHash
    && prepared !== undefined
    && candidatePrepared !== undefined
    && hashJson(prepared) === hashJson(candidatePrepared)
    && hashJson(toolCallImmutableOutcomeSemantics(toolCall))
      === hashJson(toolCallImmutableOutcomeSemantics(input.toolCall));
}

export function sameRecordedKnownExternalOutcomeProjection(
  input: KnownExternalExecutionOutcomeRecordingLike,
  attempt: ExecutionAttemptRecordV1,
  receipt: ReceiptLike,
  toolCall: ToolCallLike,
): boolean {
  return attempt.state === input.attemptOutcome.status
    && hashJson(attempt.outcome ?? null) === hashJson(input.attemptOutcome)
    && hashJson(receipt.outcome ?? null) === hashJson(input.receiptOutcome)
    && sameTerminalToolCallProjection(input.toolCall, toolCall);
}

export function knownExternalOutcomeRecordingConflictDisposition(
  attempt: ExecutionAttemptRecordV1,
): 'conflict' | 'reconciliation_required' | 'state_mismatch' {
  if (attempt.state === 'dispatched' || attempt.state === 'timed_out' || attempt.state === 'unknown_outcome') {
    return 'reconciliation_required';
  }
  if (attempt.state === 'reserved' || attempt.state === 'cancelled' || attempt.state === 'failed_before_dispatch') {
    return 'state_mismatch';
  }
  return 'conflict';
}

export function sameTerminalToolCallProjection(left: ToolCallLike, right: ToolCallLike): boolean {
  const resultWithheldCompatible = right.resultWithheld === left.resultWithheld
    || (left.resultWithheld === true && right.resultWithheld === false);
  return right.status === left.status
    && right.error === left.error
    && hashJson(right.result ?? null) === hashJson(left.result ?? null)
    && hashJson(right.resultDelivery ?? null) === hashJson(left.resultDelivery ?? null)
    && resultWithheldCompatible;
}

function toolCallImmutableOutcomeSemantics(toolCall: ToolCallLike): Record<string, unknown> {
  const {
    error: _error,
    result: _result,
    resultDelivery: _resultDelivery,
    resultWithheld: _resultWithheld,
    status: _status,
    updatedAt: _updatedAt,
    ...base
  } = toolCall;
  return base;
}

function externalExecutionOutcome(result: unknown): unknown {
  return isRecord(result) ? result.externalExecutionOutcome : undefined;
}

function hashOptional(value: unknown): string | null {
  return value === undefined ? null : hashJson(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
