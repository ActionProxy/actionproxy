import { hashCanonicalJson } from './action-request';
import type { PolicyProviderEvaluation, PolicyProviderFailureCode } from '../policy/policy-provider';
import type { PolicyRule, PolicyTraceMatchType } from '../policy/policy-types';
import type { ToolCallRecord } from '../models';

export const ACTIONPROXY_DECISION_VERSION = 'actionproxy.decision.v1' as const;

export type DecisionReasonCode =
  | 'policy_conditional_fallback'
  | 'policy_match_default'
  | 'policy_match_exact'
  | 'policy_match_wildcard'
  | 'policy_outcome_allow'
  | 'policy_outcome_deny'
  | 'policy_outcome_require_approval'
  | PolicyProviderFailureCode;

export type DecisionObligation =
  | 'do_not_execute'
  | 'record_decision_evidence'
  | 'require_human_approval'
  | 'revalidate_policy_before_execution';

export interface ActionProxyDecisionV1 {
  approvalRequirements: {
    eligibleGroups: string[];
    eligibleUsers: string[];
    expirationRequired: false;
    expiresAt: null;
    modificationBehavior: 'revalidate_and_rebind';
    rejectionBehavior: 'terminal';
    required: boolean;
    requiredApprovals: number;
    separationOfDuties: boolean;
  };
  decidedAt: string;
  decisionId: string;
  decisionInputHash: string;
  evaluatorVersion: string | null;
  matchedPolicies: Array<{
    digestAlgorithm: 'sha256';
    matchType: PolicyTraceMatchType;
    policyDigest: string;
    policyVersion: string;
    providerId: string;
    ruleId: string;
  }>;
  obligations: DecisionObligation[];
  outcome: 'allow' | 'deny' | 'require_approval';
  policy: {
    digest: string | null;
    digestAlgorithm: 'sha256' | null;
    provider: {
      id: string;
      status: 'failure' | 'ok';
      version: string | null;
    };
    schemaVersion: string | null;
    version: string | null;
  };
  reasonCodes: DecisionReasonCode[];
  requestId: string;
  tenantId: string;
  version: typeof ACTIONPROXY_DECISION_VERSION;
}

export interface BuildActionProxyDecisionInput {
  decidedAt: string;
  decisionInputHash: string;
  providerEvaluation: PolicyProviderEvaluation;
  requestId: string;
  tenantId: string;
}

export function buildActionProxyDecision(input: BuildActionProxyDecisionInput): ActionProxyDecisionV1 {
  const trace = input.providerEvaluation.trace;
  const descriptor = input.providerEvaluation.descriptor;
  const reasonCodes = decisionReasonCodes(input.providerEvaluation);
  const obligations = decisionObligations(trace.decision);
  const approvalRequirements = buildApprovalRequirements(trace.evaluation.rule, trace.decision);
  const matchedPolicies =
    input.providerEvaluation.status === 'ok' &&
    descriptor.policyDigest &&
    descriptor.policyVersion
      ? [
          {
            matchType: trace.matchType,
            digestAlgorithm: descriptor.policyDigestAlgorithm!,
            policyDigest: descriptor.policyDigest,
            policyVersion: descriptor.policyVersion,
            providerId: descriptor.providerId,
            ruleId: trace.matchedRule,
          },
        ]
      : [];
  const identityMaterial = decisionIdentityMaterial({
    approvalRequirements,
    decisionInputHash: input.decisionInputHash,
    matchedPolicies,
    obligations,
    outcome: trace.decision,
    policy: {
      digest: descriptor.policyDigest ?? null,
      digestAlgorithm: descriptor.policyDigestAlgorithm ?? null,
      providerId: descriptor.providerId,
      providerVersion: descriptor.providerVersion ?? null,
      schemaVersion: descriptor.policySchemaVersion ?? null,
      status: input.providerEvaluation.status,
      version: descriptor.policyVersion ?? null,
    },
    reasonCodes,
    requestId: input.requestId,
    tenantId: input.tenantId,
    version: ACTIONPROXY_DECISION_VERSION,
  });

  return {
    approvalRequirements,
    decidedAt: input.decidedAt,
    decisionId: `decision_${hashCanonicalJson(identityMaterial)}`,
    decisionInputHash: input.decisionInputHash,
    evaluatorVersion: descriptor.evaluatorVersion ?? null,
    matchedPolicies,
    obligations,
    outcome: trace.decision,
    policy: {
      digest: descriptor.policyDigest ?? null,
      digestAlgorithm: descriptor.policyDigestAlgorithm ?? null,
      provider: {
        id: descriptor.providerId,
        status: input.providerEvaluation.status,
        version: descriptor.providerVersion ?? null,
      },
      schemaVersion: descriptor.policySchemaVersion ?? null,
      version: descriptor.policyVersion ?? null,
    },
    reasonCodes,
    requestId: input.requestId,
    tenantId: input.tenantId,
    version: ACTIONPROXY_DECISION_VERSION,
  };
}

/**
 * Validates a persisted decision before it can authorize execution. This does not
 * change decision-v1 hashing; it recomputes the frozen identity material and
 * checks that the projection still agrees with the authoritative tool call.
 */
export function validatedActionProxyDecisionForToolCall(
  toolCall: ToolCallRecord,
): ActionProxyDecisionV1 | undefined {
  const candidate = toolCall.decisionTrace?.decisionV1;
  if (!isRecord(candidate) || candidate.version !== ACTIONPROXY_DECISION_VERSION) return undefined;
  if (
    !isNonEmptyString(candidate.decisionId) ||
    !isNonEmptyString(candidate.decisionInputHash) ||
    !isNonEmptyString(candidate.evaluatorVersion) ||
    !isNonEmptyString(candidate.requestId) ||
    !isNonEmptyString(candidate.tenantId) ||
    !isIsoTimestamp(candidate.decidedAt) ||
    !isDecisionOutcome(candidate.outcome) ||
    !Array.isArray(candidate.matchedPolicies) ||
    !Array.isArray(candidate.obligations) ||
    !candidate.obligations.every(isDecisionObligation) ||
    !Array.isArray(candidate.reasonCodes) ||
    !candidate.reasonCodes.every((value) => typeof value === 'string') ||
    !isRecord(candidate.approvalRequirements) ||
    !isRecord(candidate.policy) ||
    !isRecord(candidate.policy.provider)
  ) {
    return undefined;
  }
  const policy = candidate.policy;
  const provider = policy.provider as Record<string, unknown>;
  if (
    candidate.requestId !== toolCall.id ||
    candidate.tenantId !== (toolCall.workspaceId ?? 'default') ||
    candidate.decisionInputHash !== toolCall.canonicalDecisionInputHash ||
    candidate.outcome !== toolCall.decision ||
    candidate.policy.provider.status !== 'ok' ||
    candidate.policy.digest !== toolCall.policyVersionHash ||
    candidate.policy.version !== toolCall.policyVersionId ||
    candidate.policy.digestAlgorithm !== 'sha256' ||
    !isNonEmptyString(candidate.policy.provider.id) ||
    !isNonEmptyString(candidate.policy.provider.version) ||
    !isNonEmptyString(candidate.policy.schemaVersion)
  ) {
    return undefined;
  }
  const expectedObligations = decisionObligations(candidate.outcome);
  if (!sameStringArray(candidate.obligations, expectedObligations)) return undefined;
  if (!candidate.reasonCodes.includes(`policy_outcome_${candidate.outcome}`)) return undefined;
  const approvalRequired = candidate.outcome === 'require_approval';
  if (
    candidate.approvalRequirements.required !== approvalRequired ||
    candidate.approvalRequirements.expirationRequired !== false ||
    candidate.approvalRequirements.expiresAt !== null ||
    candidate.approvalRequirements.modificationBehavior !== 'revalidate_and_rebind' ||
    candidate.approvalRequirements.rejectionBehavior !== 'terminal' ||
    !Array.isArray(candidate.approvalRequirements.eligibleGroups) ||
    !candidate.approvalRequirements.eligibleGroups.every((value) => typeof value === 'string') ||
    !Array.isArray(candidate.approvalRequirements.eligibleUsers) ||
    !candidate.approvalRequirements.eligibleUsers.every((value) => typeof value === 'string') ||
    !Number.isInteger(candidate.approvalRequirements.requiredApprovals) ||
    candidate.approvalRequirements.requiredApprovals !== (approvalRequired
      ? Math.max(1, candidate.approvalRequirements.requiredApprovals as number)
      : 0) ||
    typeof candidate.approvalRequirements.separationOfDuties !== 'boolean'
  ) {
    return undefined;
  }
  if (
    !candidate.matchedPolicies.every((matched) =>
      isRecord(matched) &&
      matched.digestAlgorithm === 'sha256' &&
      matched.policyDigest === policy.digest &&
      matched.policyVersion === policy.version &&
      matched.providerId === provider.id &&
      isNonEmptyString(matched.ruleId) &&
      isPolicyTraceMatchType(matched.matchType),
    )
  ) {
    return undefined;
  }

  try {
    const identityMaterial = decisionIdentityMaterial({
      approvalRequirements: candidate.approvalRequirements,
      decisionInputHash: candidate.decisionInputHash,
      matchedPolicies: candidate.matchedPolicies,
      obligations: candidate.obligations,
      outcome: candidate.outcome,
      policy: {
        digest: candidate.policy.digest,
        digestAlgorithm: candidate.policy.digestAlgorithm,
        providerId: candidate.policy.provider.id,
        providerVersion: candidate.policy.provider.version,
        schemaVersion: candidate.policy.schemaVersion,
        status: candidate.policy.provider.status,
        version: candidate.policy.version,
      },
      reasonCodes: candidate.reasonCodes,
      requestId: candidate.requestId,
      tenantId: candidate.tenantId,
      version: candidate.version,
    });
    if (candidate.decisionId !== `decision_${hashCanonicalJson(identityMaterial)}`) return undefined;
  } catch {
    return undefined;
  }
  return candidate as unknown as ActionProxyDecisionV1;
}

function decisionIdentityMaterial(input: {
  approvalRequirements: unknown;
  decisionInputHash: unknown;
  matchedPolicies: unknown;
  obligations: unknown;
  outcome: unknown;
  policy: unknown;
  reasonCodes: unknown;
  requestId: unknown;
  tenantId: unknown;
  version: unknown;
}) {
  return input;
}

function decisionReasonCodes(evaluation: PolicyProviderEvaluation): DecisionReasonCode[] {
  if (evaluation.failureCode) return ['policy_outcome_deny', evaluation.failureCode];
  const codes: DecisionReasonCode[] = [`policy_outcome_${evaluation.trace.decision}`];
  if (evaluation.trace.matchType === 'exact') codes.push('policy_match_exact');
  if (evaluation.trace.matchType === 'wildcard') codes.push('policy_match_wildcard');
  if (evaluation.trace.matchType === 'default') codes.push('policy_match_default');
  if (evaluation.trace.fallbackPath.length > 1) codes.push('policy_conditional_fallback');
  return codes;
}

function decisionObligations(outcome: ActionProxyDecisionV1['outcome']): DecisionObligation[] {
  if (outcome === 'deny') return ['record_decision_evidence', 'do_not_execute'];
  if (outcome === 'require_approval') {
    return ['record_decision_evidence', 'require_human_approval', 'revalidate_policy_before_execution'];
  }
  return ['record_decision_evidence', 'revalidate_policy_before_execution'];
}

function buildApprovalRequirements(
  rule: PolicyRule,
  outcome: ActionProxyDecisionV1['outcome'],
): ActionProxyDecisionV1['approvalRequirements'] {
  const required = outcome === 'require_approval';
  return {
    eligibleGroups: required ? [...(rule.approvers?.groups ?? [])].sort() : [],
    eligibleUsers: required ? [...(rule.approvers?.users ?? [])].sort() : [],
    expirationRequired: false,
    expiresAt: null,
    modificationBehavior: 'revalidate_and_rebind',
    rejectionBehavior: 'terminal',
    required,
    requiredApprovals: required ? Math.max(1, rule.approvers?.requiredApprovals ?? 1) : 0,
    separationOfDuties: required ? (rule.approvers?.separationOfDuties ?? false) : false,
  };
}

function isDecisionOutcome(value: unknown): value is ActionProxyDecisionV1['outcome'] {
  return value === 'allow' || value === 'deny' || value === 'require_approval';
}

function isDecisionObligation(value: unknown): value is DecisionObligation {
  return (
    value === 'do_not_execute' ||
    value === 'record_decision_evidence' ||
    value === 'require_human_approval' ||
    value === 'revalidate_policy_before_execution'
  );
}

function isPolicyTraceMatchType(value: unknown): value is PolicyTraceMatchType {
  return (
    value === 'default' ||
    value === 'exact' ||
    value === 'provider_failure' ||
    value === 'wildcard'
  );
}

function isIsoTimestamp(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sameStringArray(left: unknown[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
