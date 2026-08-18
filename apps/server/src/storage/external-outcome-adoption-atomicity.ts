import type { ExecutionAttemptRecordV1 } from '../contracts/execution-attempt';
import { hashJson } from '../security/crypto';

interface ReceiptLike {
  id: string;
  outcome?: {
    error?: string;
    recordedAt: string;
    remediation?: unknown;
    result?: unknown;
    resultDelivery?: unknown;
    status: string;
  };
  receiptHash: string;
  toolCallId: string;
  workspaceId: string;
}

interface ToolCallLike {
  actionEnvelopeHash?: string;
  error?: string;
  id: string;
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
  consumedAt?: string;
  id: string;
  inputHash: string;
  policyVersionHash?: string;
  receiptHash?: string;
  receiptId?: string;
  toolCallId: string;
  workspaceId: string;
}

export interface KnownExternalExecutionOutcomeAdoptionLike {
  attemptId: string;
  receipt: ReceiptLike;
  toolCall: ToolCallLike;
  workspaceId: string;
}

export function assertKnownExternalExecutionOutcomeAdoptionCandidate(
  input: KnownExternalExecutionOutcomeAdoptionLike,
): void {
  const mismatches = [
    !input.attemptId ? 'attempt_id' : undefined,
    !input.receipt.outcome ? 'receipt_outcome' : undefined,
    input.receipt.workspaceId !== input.workspaceId ? 'receipt_workspace' : undefined,
    input.receipt.toolCallId !== input.toolCall.id ? 'receipt_tool_call' : undefined,
    (input.toolCall.workspaceId ?? 'default') !== input.workspaceId ? 'tool_call_workspace' : undefined,
    input.toolCall.status !== 'executed' && input.toolCall.status !== 'failed' ? 'tool_call_status' : undefined,
  ].filter((value): value is string => Boolean(value));
  if (mismatches.length) {
    throw new Error(`Known external execution outcome adoption failed its integrity check: ${mismatches.join(', ')}.`);
  }
}

export function externalOutcomeAdoptionState(
  attempt: ExecutionAttemptRecordV1,
): 'adoptable' | 'reconciliation_required' | 'state_mismatch' {
  if (attempt.state === 'dispatched' || attempt.state === 'timed_out' || attempt.state === 'unknown_outcome') {
    return 'reconciliation_required';
  }
  if (attempt.state === 'reserved') return 'state_mismatch';
  return attempt.outcome?.certainty === 'known' && attempt.outcome.status === attempt.state
    ? 'adoptable'
    : 'state_mismatch';
}

export function knownExternalOutcomeMatchesCurrent(
  input: KnownExternalExecutionOutcomeAdoptionLike,
  current: {
    attempt: ExecutionAttemptRecordV1;
    grant: GrantLike;
    receipt: ReceiptLike;
    toolCall: ToolCallLike;
  },
): boolean {
  const { attempt, grant, receipt, toolCall } = current;
  const candidateOutcome = input.receipt.outcome!;
  const outcome = attempt.outcome;
  const succeeded = attempt.state === 'succeeded';
  if (!outcome || externalOutcomeAdoptionState(attempt) !== 'adoptable') return false;
  return attempt.id === input.attemptId
    && attempt.workspaceId === input.workspaceId
    && attempt.toolCallId === input.toolCall.id
    && attempt.executionMode === 'external_grant'
    && attempt.executorId === 'actionproxy.external-runner'
    && attempt.grantId === grant.id
    && grant.workspaceId === input.workspaceId
    && grant.toolCallId === input.toolCall.id
    && grant.consumedAt !== undefined
    && grant.inputHash === attempt.inputHash
    && grant.receiptId === receipt.id
    && grant.receiptHash === receipt.receiptHash
    && attempt.binding.receiptId === receipt.id
    && attempt.binding.receiptHash === receipt.receiptHash
    && attempt.binding.actionEnvelopeHash === (grant.approvedEnvelopeHash ?? null)
    && receipt.id === input.receipt.id
    && receipt.toolCallId === input.toolCall.id
    && receipt.workspaceId === input.workspaceId
    && hashJson(receiptWithoutOutcome(receipt)) === hashJson(receiptWithoutOutcome(input.receipt))
    && (toolCall.workspaceId ?? 'default') === input.workspaceId
    && toolCall.id === input.toolCall.id
    && toolCall.status === 'authorized'
    && toolCall.inputHash === attempt.inputHash
    && toolCall.actionEnvelopeHash === attempt.binding.actionEnvelopeHash
    && hashJson(toolCallImmutableOutcomeSemantics(toolCall))
      === hashJson(toolCallImmutableOutcomeSemantics(input.toolCall))
    && candidateOutcome.recordedAt === outcome.recordedAt
    && candidateOutcome.status === (succeeded ? 'succeeded' : 'failed')
    && outcome.resultDeliveryHash === hashOptional(candidateOutcome.resultDelivery)
    && outcome.remediationHash === hashOptional(succeeded ? candidateOutcome.remediation : undefined)
    && (!succeeded || outcome.resultHash === hashOptional(candidateOutcome.result))
    && (succeeded || (candidateOutcome.error ?? null) === outcome.errorMessage)
    && input.toolCall.status === (succeeded ? 'executed' : 'failed')
    && input.toolCall.error === (succeeded ? toolCall.error : candidateOutcome.error)
    && hashJson(input.toolCall.resultDelivery ?? null) === hashJson(candidateOutcome.resultDelivery ?? null)
    && (succeeded
      ? hashJson(externalExecutionOutcome(input.toolCall.result)) === hashJson(candidateOutcome.result)
      : hashJson(input.toolCall.result ?? null) === hashJson(toolCall.result ?? null));
}

export function sameKnownExternalOutcomeProjection(
  input: KnownExternalExecutionOutcomeAdoptionLike,
  receipt: ReceiptLike,
  toolCall: ToolCallLike,
): boolean {
  const resultWithheldCompatible = toolCall.resultWithheld === input.toolCall.resultWithheld
    || (input.toolCall.resultWithheld === true && toolCall.resultWithheld === false);
  return hashJson(receipt.outcome ?? null) === hashJson(input.receipt.outcome ?? null)
    && toolCall.status === input.toolCall.status
    && toolCall.error === input.toolCall.error
    && hashJson(toolCall.result ?? null) === hashJson(input.toolCall.result ?? null)
    && hashJson(toolCall.resultDelivery ?? null) === hashJson(input.toolCall.resultDelivery ?? null)
    && resultWithheldCompatible;
}

export function outcomeProjectionCanBeAdopted(
  input: KnownExternalExecutionOutcomeAdoptionLike,
  receipt: ReceiptLike,
  toolCall: ToolCallLike,
): boolean {
  const receiptCompatible = receipt.outcome === undefined
    || hashJson(receipt.outcome) === hashJson(input.receipt.outcome);
  const toolCallCompatible = toolCall.status === 'authorized'
    || sameKnownExternalOutcomeProjection(input, receipt.outcome ? receipt : input.receipt, toolCall);
  return receiptCompatible && toolCallCompatible;
}

function receiptWithoutOutcome(receipt: ReceiptLike): Omit<ReceiptLike, 'outcome'> {
  const { outcome: _outcome, ...base } = receipt;
  return base;
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
