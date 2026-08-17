import type { ExecutionAttemptRecordV1 } from '../contracts/execution-attempt';
import { hashJson } from '../security/crypto';

interface ApprovalLike {
  approvedEnvelopeHash?: string;
  approvedInputHash?: string;
  authorization?: { authorizationHash: string; nonce: string };
  authorizationConsumedAt?: string;
  authorizationConsumedReason?: string;
  id: string;
  originalEnvelopeHash?: string;
  originalInputHash?: string;
  reviewHash?: string;
  status: string;
  toolCallId: string;
  workspaceId?: string;
}

interface GrantLike {
  approvedEnvelopeHash?: string;
  approvedInputHash?: string;
  consumedAt?: string;
  id: string;
  inputHash: string;
  policyVersionHash?: string;
  receiptHash?: string;
  receiptId?: string;
  toolCallId: string;
  toolName: string;
  workspaceId: string;
}

interface ReceiptLike {
  approvalId?: string;
  approvedEnvelopeHash: string;
  approvedInputHash: string;
  decisionKind: string;
  executionMode: string;
  id: string;
  originalEnvelopeHash: string;
  originalInputHash: string;
  outcome?: unknown;
  policyVersionHash?: string;
  receiptHash: string;
  reviewHash?: string;
  toolCallId: string;
  toolName: string;
  workspaceId: string;
}

interface ToolCallLike {
  actionEnvelope?: unknown;
  actionEnvelopeHash?: string;
  canonicalActionRequestHash?: string;
  canonicalActionRequestVersion?: string;
  canonicalDecisionInputHash?: string;
  decision?: string;
  decisionTrace?: unknown;
  error?: string;
  id: string;
  input: Record<string, unknown>;
  inputHash?: string;
  policyVersionHash?: string;
  result?: unknown;
  status: string;
  toolName: string;
  updatedAt: string;
  workspaceId?: string;
}

export interface ApprovedExternalAuthorizationPublicationLike {
  approvalId: string;
  attempt: ExecutionAttemptRecordV1;
  grant: GrantLike;
  receipt: ReceiptLike;
  toolCall: ToolCallLike;
}

export function assertApprovedExternalAuthorizationPublicationCandidate(
  input: ApprovedExternalAuthorizationPublicationLike,
): void {
  const { attempt, grant, receipt, toolCall } = input;
  const workspaceId = toolCall.workspaceId ?? 'default';
  const actionEnvelope = isRecord(toolCall.actionEnvelope) ? toolCall.actionEnvelope : undefined;
  const result = isRecord(toolCall.result) ? toolCall.result : undefined;
  const resultGrant = isRecord(result?.grant) ? result.grant : undefined;
  const resultReceipt = isRecord(result?.receipt) ? result.receipt : undefined;
  const mismatches = [
    !input.approvalId ? 'approval_id' : undefined,
    toolCall.status !== 'authorized' ? 'tool_call_status' : undefined,
    toolCall.decision !== 'require_approval' ? 'policy_decision' : undefined,
    actionEnvelope?.executionMode !== 'external_grant' ? 'action_execution_mode' : undefined,
    !toolCall.inputHash || hashJson(toolCall.input) !== toolCall.inputHash ? 'tool_call_input_hash' : undefined,
    receipt.decisionKind !== 'human_approval' ? 'receipt_decision_kind' : undefined,
    receipt.executionMode !== 'external_grant' ? 'receipt_execution_mode' : undefined,
    receipt.outcome !== undefined ? 'receipt_outcome' : undefined,
    receipt.approvalId !== input.approvalId ? 'receipt_approval' : undefined,
    receipt.workspaceId !== workspaceId ? 'receipt_workspace' : undefined,
    receipt.toolCallId !== toolCall.id ? 'receipt_tool_call' : undefined,
    receipt.toolName !== toolCall.toolName ? 'receipt_tool_name' : undefined,
    receipt.approvedInputHash !== toolCall.inputHash ? 'receipt_input_hash' : undefined,
    receipt.approvedEnvelopeHash !== toolCall.actionEnvelopeHash ? 'receipt_envelope_hash' : undefined,
    grant.workspaceId !== workspaceId ? 'grant_workspace' : undefined,
    grant.toolCallId !== toolCall.id ? 'grant_tool_call' : undefined,
    grant.toolName !== toolCall.toolName ? 'grant_tool_name' : undefined,
    grant.inputHash !== toolCall.inputHash ? 'grant_input_hash' : undefined,
    grant.approvedInputHash !== receipt.approvedInputHash ? 'grant_approved_input_hash' : undefined,
    grant.approvedEnvelopeHash !== receipt.approvedEnvelopeHash ? 'grant_approved_envelope_hash' : undefined,
    grant.policyVersionHash !== receipt.policyVersionHash ? 'grant_policy_version' : undefined,
    grant.receiptId !== receipt.id ? 'grant_receipt_id' : undefined,
    grant.receiptHash !== receipt.receiptHash ? 'grant_receipt_hash' : undefined,
    grant.consumedAt !== undefined ? 'grant_consumed' : undefined,
    attempt.version !== 'actionproxy.execution-attempt.v1' ? 'attempt_version' : undefined,
    attempt.attemptNumber !== 1 ? 'attempt_number' : undefined,
    attempt.state !== 'reserved' ? 'attempt_state' : undefined,
    attempt.executionMode !== 'external_grant' ? 'attempt_execution_mode' : undefined,
    attempt.executorId !== 'actionproxy.external-runner' ? 'attempt_executor' : undefined,
    attempt.providerIdempotency !== 'none' ? 'provider_idempotency' : undefined,
    attempt.retryPolicy !== 'never_automatic' ? 'retry_policy' : undefined,
    attempt.outcome !== undefined || attempt.dispatchedAt !== undefined || attempt.completedAt !== undefined
      ? 'attempt_outcome'
      : undefined,
    attempt.workspaceId !== workspaceId ? 'attempt_workspace' : undefined,
    attempt.toolCallId !== toolCall.id ? 'attempt_tool_call' : undefined,
    attempt.inputHash !== toolCall.inputHash ? 'attempt_input_hash' : undefined,
    attempt.grantId !== grant.id ? 'attempt_grant' : undefined,
    attempt.binding.approvalId !== input.approvalId ? 'attempt_approval' : undefined,
    attempt.binding.receiptId !== receipt.id ? 'attempt_receipt_id' : undefined,
    attempt.binding.receiptHash !== receipt.receiptHash ? 'attempt_receipt_hash' : undefined,
    attempt.binding.actionEnvelopeHash !== (toolCall.actionEnvelopeHash ?? null) ? 'attempt_envelope_hash' : undefined,
    attempt.binding.canonicalActionRequestHash !== (toolCall.canonicalActionRequestHash ?? null)
      ? 'attempt_canonical_request_hash'
      : undefined,
    attempt.binding.canonicalActionRequestVersion !== (toolCall.canonicalActionRequestVersion ?? null)
      ? 'attempt_canonical_request_version'
      : undefined,
    attempt.binding.canonicalDecisionInputHash !== (toolCall.canonicalDecisionInputHash ?? null)
      ? 'attempt_decision_input_hash'
      : undefined,
    attempt.binding.policyVersionHash !== (toolCall.policyVersionHash ?? null) ? 'attempt_policy_version' : undefined,
    result?.externalExecution !== true ? 'tool_call_result_mode' : undefined,
    resultGrant?.id !== grant.id ? 'tool_call_result_grant' : undefined,
    resultReceipt?.id !== receipt.id || resultReceipt?.receiptHash !== receipt.receiptHash
      ? 'tool_call_result_receipt'
      : undefined,
  ].filter((value): value is string => Boolean(value));
  if (mismatches.length) {
    throw new Error(`Approved external authorization publication failed its integrity check: ${mismatches.join(', ')}.`);
  }
}

export function approvedExternalAuthorizationMatchesCurrent(
  input: ApprovedExternalAuthorizationPublicationLike,
  approval: ApprovalLike,
  currentToolCall: ToolCallLike,
): boolean {
  const { attempt, receipt, toolCall } = input;
  const workspaceId = toolCall.workspaceId ?? 'default';
  const decision = isRecord(toolCall.decisionTrace) && isRecord(toolCall.decisionTrace.decisionV1)
    ? toolCall.decisionTrace.decisionV1
    : undefined;
  return approval.id === input.approvalId
    && (approval.workspaceId ?? 'default') === workspaceId
    && approval.toolCallId === toolCall.id
    && approval.status === 'approved'
    && approval.authorizationConsumedReason === 'approved'
    && approval.authorizationConsumedAt !== undefined
    && approval.authorization !== undefined
    && approval.approvedInputHash === receipt.approvedInputHash
    && approval.approvedEnvelopeHash === receipt.approvedEnvelopeHash
    && approval.originalInputHash === receipt.originalInputHash
    && approval.originalEnvelopeHash === receipt.originalEnvelopeHash
    && approval.reviewHash === receipt.reviewHash
    && attempt.binding.approvalAuthorizationHash === approval.authorization.authorizationHash
    && attempt.binding.approvalAuthorizationNonce === approval.authorization.nonce
    && attempt.binding.decisionId === (typeof decision?.decisionId === 'string' ? decision.decisionId : null)
    && attempt.binding.decisionVersion === (typeof decision?.version === 'string' ? decision.version : null)
    && currentToolCall.id === toolCall.id
    && (currentToolCall.workspaceId ?? 'default') === workspaceId
    && currentToolCall.status === 'pending_approval'
    && currentToolCall.toolName === toolCall.toolName
    && currentToolCall.decision === toolCall.decision
    && currentToolCall.policyVersionHash === toolCall.policyVersionHash
    && hashJson(toolCallImmutablePublicationSemantics(currentToolCall))
      === hashJson(toolCallImmutablePublicationSemantics(toolCall));
}

export function sameApprovedExternalAuthorizationPublication(
  input: ApprovedExternalAuthorizationPublicationLike,
  current: {
    attempt?: ExecutionAttemptRecordV1;
    grant?: GrantLike;
    receipt?: ReceiptLike;
    toolCall?: ToolCallLike;
  },
): boolean {
  return current.attempt !== undefined
    && current.grant !== undefined
    && current.receipt !== undefined
    && current.toolCall !== undefined
    && hashJson(current.attempt) === hashJson(input.attempt)
    && hashJson(current.grant) === hashJson(input.grant)
    && hashJson(current.receipt) === hashJson(input.receipt)
    && hashJson(current.toolCall) === hashJson(input.toolCall);
}

function toolCallImmutablePublicationSemantics(toolCall: ToolCallLike): Record<string, unknown> {
  const {
    actionEnvelope: _actionEnvelope,
    actionEnvelopeHash: _actionEnvelopeHash,
    error: _error,
    input: _input,
    inputHash: _inputHash,
    result: _result,
    status: _status,
    updatedAt: _updatedAt,
    ...semantic
  } = toolCall;
  return semantic;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
