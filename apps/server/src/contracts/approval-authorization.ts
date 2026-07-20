import type { ApprovalRecord, PolicyDecision, ToolCallRecord } from '../models';
import { randomToken } from '../security/crypto';
import { hashCanonicalJson } from './action-request';

export const APPROVAL_AUTHORIZATION_VERSION = 'actionproxy.approval-authorization.v1' as const;
export const DEFAULT_APPROVAL_AUTHORIZATION_TTL_MS = 24 * 60 * 60 * 1000;

export interface ApprovalAuthorizationV1 {
  authorizationHash: string;
  binding: {
    action: {
      originalEnvelopeHash: string;
      originalInputHash: string;
      reviewHash: string;
    };
    approval: {
      approvalId: string;
      requestedBy: string;
      requestedByPrincipalId: string | null;
      tenantId: string;
      toolCallId: string;
    };
    decision: {
      decisionId: string | null;
      outcome: PolicyDecision;
      version: 'actionproxy.decision.v1' | null;
    };
    policy: {
      digest: string | null;
      evaluatorVersion: string | null;
      legacyVersionHash: string;
      legacyVersionId: string | null;
      providerId: string | null;
      providerVersion: string | null;
      version: string | null;
    };
    request: {
      decisionInputHash: string | null;
      requestHash: string | null;
      version: 'actionproxy.action-request.v1' | null;
    };
    requirements: {
      eligibleGroups: string[];
      eligibleUsers: string[] | null;
      requiredApprovals: number;
      separationOfDuties: boolean;
    };
  };
  expiresAt: string;
  issuedAt: string;
  nonce: string;
  version: typeof APPROVAL_AUTHORIZATION_VERSION;
}

export interface BuildApprovalAuthorizationInput {
  approvalId: string;
  approverGroups?: string[];
  approverUsers?: string[];
  expiresAt: string;
  issuedAt: string;
  nonce?: string;
  originalEnvelopeHash: string;
  originalInputHash: string;
  requestedBy: string;
  requestedByPrincipalId?: string;
  requiredApprovals?: number;
  reviewHash: string;
  separationOfDuties?: boolean;
  toolCall: ToolCallRecord;
}

export function buildApprovalAuthorization(input: BuildApprovalAuthorizationInput): ApprovalAuthorizationV1 {
  if (!input.toolCall.policyVersionHash) {
    throw new Error('Approval authorization requires an immutable policy version hash.');
  }
  assertIsoTimestamp(input.issuedAt, 'issuedAt');
  assertIsoTimestamp(input.expiresAt, 'expiresAt');
  if (Date.parse(input.expiresAt) <= Date.parse(input.issuedAt)) {
    throw new Error('Approval authorization expiry must be later than issuance.');
  }

  const decision = decisionIdentity(input.toolCall);
  const authorizationWithoutHash = {
    binding: {
      action: {
        originalEnvelopeHash: input.originalEnvelopeHash,
        originalInputHash: input.originalInputHash,
        reviewHash: input.reviewHash,
      },
      approval: {
        approvalId: input.approvalId,
        requestedBy: input.requestedBy,
        requestedByPrincipalId: input.requestedByPrincipalId ?? null,
        tenantId: input.toolCall.workspaceId ?? 'default',
        toolCallId: input.toolCall.id,
      },
      decision: {
        decisionId: decision?.decisionId ?? null,
        outcome: input.toolCall.decision ?? 'require_approval',
        version: decision?.version ?? null,
      },
      policy: {
        digest: decision?.policy.digest ?? null,
        evaluatorVersion: decision?.evaluatorVersion ?? null,
        legacyVersionHash: input.toolCall.policyVersionHash,
        legacyVersionId: input.toolCall.policyVersionId ?? null,
        providerId: decision?.policy.provider.id ?? null,
        providerVersion: decision?.policy.provider.version ?? null,
        version: decision?.policy.version ?? null,
      },
      request: {
        decisionInputHash: input.toolCall.canonicalDecisionInputHash ?? decision?.decisionInputHash ?? null,
        requestHash: input.toolCall.canonicalActionRequestHash ?? null,
        version: input.toolCall.canonicalActionRequestVersion ?? null,
      },
      requirements: {
        eligibleGroups: sortedUnique(input.approverGroups ?? []),
        eligibleUsers: input.approverUsers === undefined ? null : sortedUnique(input.approverUsers),
        requiredApprovals: Math.max(1, input.requiredApprovals ?? 1),
        separationOfDuties: input.separationOfDuties ?? false,
      },
    },
    expiresAt: input.expiresAt,
    issuedAt: input.issuedAt,
    nonce: input.nonce ?? randomToken(32),
    version: APPROVAL_AUTHORIZATION_VERSION,
  };

  return {
    ...authorizationWithoutHash,
    authorizationHash: hashCanonicalJson(authorizationWithoutHash),
  };
}

export function isValidApprovalAuthorization(value: unknown): value is ApprovalAuthorizationV1 {
  if (!isRecord(value)) return false;
  if (
    value.version !== APPROVAL_AUTHORIZATION_VERSION ||
    !isNonEmptyString(value.authorizationHash) ||
    !isNonEmptyString(value.nonce) ||
    !isNonEmptyString(value.issuedAt) ||
    !isNonEmptyString(value.expiresAt) ||
    !isRecord(value.binding)
  ) {
    return false;
  }
  if (!Number.isFinite(Date.parse(value.issuedAt)) || !Number.isFinite(Date.parse(value.expiresAt))) return false;
  const binding = value.binding;
  if (
    !isRecord(binding.action) ||
    !isRecord(binding.approval) ||
    !isRecord(binding.decision) ||
    !isRecord(binding.policy) ||
    !isRecord(binding.request) ||
    !isRecord(binding.requirements)
  ) {
    return false;
  }
  if (
    !isNonEmptyString(binding.action.originalEnvelopeHash) ||
    !isNonEmptyString(binding.action.originalInputHash) ||
    !isNonEmptyString(binding.action.reviewHash) ||
    !isNonEmptyString(binding.approval.approvalId) ||
    !isNonEmptyString(binding.approval.requestedBy) ||
    !isNonEmptyString(binding.approval.tenantId) ||
    !isNonEmptyString(binding.approval.toolCallId) ||
    !isPolicyDecision(binding.decision.outcome) ||
    !isNonEmptyString(binding.policy.legacyVersionHash) ||
    !isNullableString(binding.decision.decisionId) ||
    !isNullableString(binding.decision.version) ||
    !isNullableString(binding.policy.digest) ||
    !isNullableString(binding.policy.evaluatorVersion) ||
    !isNullableString(binding.policy.legacyVersionId) ||
    !isNullableString(binding.policy.providerId) ||
    !isNullableString(binding.policy.providerVersion) ||
    !isNullableString(binding.policy.version) ||
    !isNullableString(binding.request.decisionInputHash) ||
    !isNullableString(binding.request.requestHash) ||
    !isNullableString(binding.request.version) ||
    !isNullableString(binding.approval.requestedByPrincipalId) ||
    !isStringArray(binding.requirements.eligibleGroups) ||
    !(binding.requirements.eligibleUsers === null || isStringArray(binding.requirements.eligibleUsers)) ||
    !Number.isInteger(binding.requirements.requiredApprovals) ||
    (binding.requirements.requiredApprovals as number) < 1 ||
    typeof binding.requirements.separationOfDuties !== 'boolean'
  ) {
    return false;
  }
  const { authorizationHash: _authorizationHash, ...withoutHash } = value;
  try {
    return hashCanonicalJson(withoutHash) === value.authorizationHash;
  } catch {
    return false;
  }
}

export function approvalAuthorizationMismatch(
  authorization: ApprovalAuthorizationV1,
  approval: ApprovalRecord,
  toolCall: ToolCallRecord,
): string | undefined {
  if (!isValidApprovalAuthorization(authorization)) return 'authorization_hash_mismatch';
  const binding = authorization.binding;
  const decision = decisionIdentity(toolCall);
  const users = approval.approverUsers === undefined ? null : sortedUnique(approval.approverUsers);
  const groups = sortedUnique(approval.approverGroups ?? []);

  if (binding.approval.approvalId !== approval.id) return 'approval_id_mismatch';
  if (binding.approval.toolCallId !== approval.toolCallId || binding.approval.toolCallId !== toolCall.id) {
    return 'tool_call_id_mismatch';
  }
  if (binding.approval.tenantId !== (approval.workspaceId ?? 'default')) return 'approval_tenant_mismatch';
  if (binding.approval.tenantId !== (toolCall.workspaceId ?? 'default')) return 'tool_call_tenant_mismatch';
  if (binding.approval.requestedBy !== approval.requestedBy) return 'requester_mismatch';
  if (binding.approval.requestedBy !== toolCall.requestedBy) return 'tool_call_requester_mismatch';
  if ((binding.approval.requestedByPrincipalId ?? null) !== (approval.requestedByAuth?.principalId ?? null)) {
    return 'requester_principal_mismatch';
  }
  if (binding.action.originalInputHash !== approval.originalInputHash) return 'original_input_hash_mismatch';
  if (binding.action.originalInputHash !== toolCall.inputHash) return 'tool_call_input_hash_mismatch';
  if (binding.action.originalEnvelopeHash !== approval.originalEnvelopeHash) return 'original_envelope_hash_mismatch';
  if (binding.action.originalEnvelopeHash !== toolCall.actionEnvelopeHash) return 'tool_call_envelope_hash_mismatch';
  if (binding.action.reviewHash !== approval.reviewHash) return 'review_hash_mismatch';
  if (binding.request.requestHash !== (toolCall.canonicalActionRequestHash ?? null)) return 'request_hash_mismatch';
  if (binding.request.version !== (toolCall.canonicalActionRequestVersion ?? null)) return 'request_version_mismatch';
  if (
    binding.request.decisionInputHash !==
    (toolCall.canonicalDecisionInputHash ?? decision?.decisionInputHash ?? null)
  ) {
    return 'decision_input_hash_mismatch';
  }
  if (binding.decision.version !== (decision?.version ?? null)) return 'decision_version_mismatch';
  if (binding.decision.decisionId !== (decision?.decisionId ?? null)) return 'decision_id_mismatch';
  if (binding.decision.outcome !== toolCall.decision) return 'decision_outcome_mismatch';
  if (binding.policy.legacyVersionHash !== toolCall.policyVersionHash) return 'policy_hash_mismatch';
  if (binding.policy.legacyVersionId !== (toolCall.policyVersionId ?? null)) return 'policy_version_id_mismatch';
  if (binding.policy.digest !== (decision?.policy.digest ?? null)) return 'policy_digest_mismatch';
  if (binding.policy.version !== (decision?.policy.version ?? null)) return 'policy_version_mismatch';
  if (binding.policy.providerId !== (decision?.policy.provider.id ?? null)) return 'policy_provider_mismatch';
  if (binding.policy.providerVersion !== (decision?.policy.provider.version ?? null)) {
    return 'policy_provider_version_mismatch';
  }
  if (binding.policy.evaluatorVersion !== (decision?.evaluatorVersion ?? null)) return 'evaluator_version_mismatch';
  if (!sameArray(binding.requirements.eligibleGroups, groups)) return 'eligible_groups_mismatch';
  if (!sameNullableArray(binding.requirements.eligibleUsers, users)) return 'eligible_users_mismatch';
  if (binding.requirements.requiredApprovals !== Math.max(1, approval.requiredApprovals ?? 1)) {
    return 'quorum_mismatch';
  }
  if (binding.requirements.separationOfDuties !== (approval.separationOfDuties ?? false)) {
    return 'separation_of_duties_mismatch';
  }
  if (toolCall.status !== 'pending_approval') return 'tool_call_status_mismatch';
  return undefined;
}

export function approvalAuthorizationExpired(authorization: ApprovalAuthorizationV1, now = new Date()): boolean {
  return Date.parse(authorization.expiresAt) <= now.getTime();
}

interface DecisionIdentity {
  decisionId: string;
  decisionInputHash: string;
  evaluatorVersion: string | null;
  policy: {
    digest: string | null;
    provider: { id: string; version: string | null };
    version: string | null;
  };
  version: 'actionproxy.decision.v1';
}

function decisionIdentity(toolCall: ToolCallRecord): DecisionIdentity | undefined {
  const candidate = toolCall.decisionTrace?.decisionV1;
  if (!isRecord(candidate) || candidate.version !== 'actionproxy.decision.v1') return undefined;
  if (!isNonEmptyString(candidate.decisionId) || !isNonEmptyString(candidate.decisionInputHash)) return undefined;
  if (!isRecord(candidate.policy) || !isRecord(candidate.policy.provider)) return undefined;
  if (!isNonEmptyString(candidate.policy.provider.id)) return undefined;
  return {
    decisionId: candidate.decisionId,
    decisionInputHash: candidate.decisionInputHash,
    evaluatorVersion: typeof candidate.evaluatorVersion === 'string' ? candidate.evaluatorVersion : null,
    policy: {
      digest: typeof candidate.policy.digest === 'string' ? candidate.policy.digest : null,
      provider: {
        id: candidate.policy.provider.id,
        version: typeof candidate.policy.provider.version === 'string' ? candidate.policy.provider.version : null,
      },
      version: typeof candidate.policy.version === 'string' ? candidate.policy.version : null,
    },
    version: candidate.version,
  };
}

function assertIsoTimestamp(value: string, field: string): void {
  if (!Number.isFinite(Date.parse(value))) throw new Error(`Approval authorization ${field} must be an ISO timestamp.`);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string';
}

function isPolicyDecision(value: unknown): value is PolicyDecision {
  return value === 'allow' || value === 'deny' || value === 'require_approval';
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sameArray(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameNullableArray(left: string[] | null, right: string[] | null): boolean {
  if (left === null || right === null) return left === right;
  return sameArray(left, right);
}

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}
