import { evaluatePolicyTrace } from './evaluate-policy';
import type { PolicyEvaluationContext } from './evaluate-policy';
import { contentIntegrityValues, type PolicyEvaluationTrace, type PolicyFile, type PolicyTraceMatchType } from './policy-types';
import { hashJson } from '../security/crypto';

export const YAML_POLICY_PROVIDER_ID = 'actionproxy.yaml' as const;
export const YAML_POLICY_PROVIDER_VERSION = 'actionproxy.yaml-provider.v1' as const;
export const POLICY_EVALUATOR_VERSION = 'actionproxy.policy-evaluator.v1' as const;

export type PolicyProviderFailureCode =
  | 'policy_provider_error'
  | 'policy_provider_invalid_output'
  | 'policy_provider_unavailable'
  | 'policy_provider_version_missing';

export interface PolicyProviderDescriptor {
  evaluatorVersion: string;
  policyDigest: string;
  policyDigestAlgorithm: 'sha256';
  policySchemaVersion: string;
  policyVersion: string;
  providerId: string;
  providerVersion: string;
}

export interface PolicyProviderInput {
  context: PolicyEvaluationContext;
  toolName: string;
}

export interface DeterministicPolicyProvider {
  readonly descriptor: PolicyProviderDescriptor;
  evaluate(input: PolicyProviderInput): PolicyEvaluationTrace;
}

export interface PolicyProviderEvaluation {
  descriptor: Partial<PolicyProviderDescriptor> & Pick<PolicyProviderDescriptor, 'providerId'>;
  failureCode?: PolicyProviderFailureCode;
  status: 'failure' | 'ok';
  trace: PolicyEvaluationTrace;
}

export function createYamlPolicyProvider(
  policy: PolicyFile,
  identity: { policyVersionHash?: string; policyVersionId?: string } = {},
): DeterministicPolicyProvider {
  const policyDigest = identity.policyVersionHash ?? hashJson(policy);
  return {
    descriptor: {
      evaluatorVersion: POLICY_EVALUATOR_VERSION,
      policyDigest,
      policyDigestAlgorithm: 'sha256',
      policySchemaVersion: String(policy.version),
      policyVersion: identity.policyVersionId ?? `policy_${policyDigest.slice(0, 16)}`,
      providerId: YAML_POLICY_PROVIDER_ID,
      providerVersion: YAML_POLICY_PROVIDER_VERSION,
    },
    evaluate: ({ context, toolName }) => evaluatePolicyTrace(policy, toolName, context),
  };
}

export function evaluatePolicyProvider(
  provider: DeterministicPolicyProvider | undefined,
  input: PolicyProviderInput,
): PolicyProviderEvaluation {
  if (!provider) return failedEvaluation('policy_provider_unavailable', { providerId: 'unavailable' });

  let rawDescriptor: unknown;
  try {
    rawDescriptor = provider.descriptor;
  } catch {
    return failedEvaluation('policy_provider_error', { providerId: 'unknown' });
  }
  if (!validDescriptor(rawDescriptor)) {
    return failedEvaluation('policy_provider_version_missing', {
      providerId: isRecord(rawDescriptor) ? (nonEmptyString(rawDescriptor.providerId) ?? 'unknown') : 'unknown',
    });
  }
  const descriptor: PolicyProviderDescriptor = { ...rawDescriptor };

  try {
    const trace = provider.evaluate(input);
    if (!validTrace(trace)) return failedEvaluation('policy_provider_invalid_output', descriptor);
    return { descriptor, status: 'ok', trace };
  } catch {
    return failedEvaluation('policy_provider_error', descriptor);
  }
}

function failedEvaluation(
  failureCode: PolicyProviderFailureCode,
  descriptor: Partial<PolicyProviderDescriptor> & Pick<PolicyProviderDescriptor, 'providerId'>,
): PolicyProviderEvaluation {
  const reason = failureReason(failureCode);
  return {
    descriptor,
    failureCode,
    status: 'failure',
    trace: {
      decision: 'deny',
      evaluation: {
        approval: 'deny',
        decision: 'deny',
        matchedRule: '__policy_provider_failure__',
        reason,
        risk: 'policy_provider_failure',
        rule: { approval: 'deny', reason, risk: 'policy_provider_failure' },
      },
      fallbackPath: [],
      matchedRule: '__policy_provider_failure__',
      matchType: 'provider_failure',
      ruleEvaluations: [],
    },
  };
}

function failureReason(code: PolicyProviderFailureCode): string {
  if (code === 'policy_provider_unavailable') return 'Policy provider is unavailable; execution is denied.';
  if (code === 'policy_provider_version_missing') return 'Policy provider version identity is missing; execution is denied.';
  if (code === 'policy_provider_invalid_output') return 'Policy provider returned invalid output; execution is denied.';
  return 'Policy provider evaluation failed; execution is denied.';
}

function validDescriptor(value: unknown): value is PolicyProviderDescriptor {
  if (!isRecord(value)) return false;
  return (
    nonEmptyString(value.evaluatorVersion) !== undefined &&
    typeof value.policyDigest === 'string' && /^[a-f0-9]{64}$/u.test(value.policyDigest) &&
    value.policyDigestAlgorithm === 'sha256' &&
    nonEmptyString(value.policySchemaVersion) !== undefined &&
    nonEmptyString(value.policyVersion) !== undefined &&
    nonEmptyString(value.providerId) !== undefined &&
    nonEmptyString(value.providerVersion) !== undefined
  );
}

function validTrace(value: unknown): value is PolicyEvaluationTrace {
  if (!isRecord(value) || !isRecord(value.evaluation)) return false;
  const decision = value.decision;
  const evaluation = value.evaluation;
  return (
    isDecision(decision) &&
    evaluation.decision === decision &&
    isApproval(evaluation.approval) &&
    decisionForApproval(evaluation.approval) === decision &&
    isPolicyRule(evaluation.rule) &&
    openWorldReadResultSourceValid(evaluation.risk, evaluation.rule) &&
    evaluation.rule.approval === evaluation.approval &&
    typeof evaluation.matchedRule === 'string' &&
    typeof evaluation.reason === 'string' &&
    typeof evaluation.risk === 'string' &&
    Array.isArray(value.fallbackPath) &&
    value.fallbackPath.every(isMatchType) &&
    typeof value.matchedRule === 'string' &&
    value.matchedRule === evaluation.matchedRule &&
    isMatchType(value.matchType) &&
    value.matchType !== 'provider_failure' &&
    Array.isArray(value.ruleEvaluations) &&
    value.ruleEvaluations.every(isRuleEvaluation)
  );
}

function isPolicyRule(value: unknown): value is PolicyFile['default'] {
  if (!isRecord(value) || !isApproval(value.approval)) return false;
  if (value.reason !== undefined && typeof value.reason !== 'string') return false;
  if (value.risk !== undefined && typeof value.risk !== 'string') return false;
  if (value.conditions !== undefined && !isRecord(value.conditions)) return false;
  if (value.approvers !== undefined) {
    if (!isRecord(value.approvers)) return false;
    if (!optionalStringArray(value.approvers.groups) || !optionalStringArray(value.approvers.users)) return false;
    if (
      value.approvers.requiredApprovals !== undefined &&
      (!Number.isInteger(value.approvers.requiredApprovals) || Number(value.approvers.requiredApprovals) < 1)
    ) return false;
    if (value.approvers.separationOfDuties !== undefined && typeof value.approvers.separationOfDuties !== 'boolean') {
      return false;
    }
  }
  if (value.externalExecution !== undefined) {
    if (!isRecord(value.externalExecution)) return false;
    if (
      value.externalExecution.grantTtlSeconds !== undefined &&
      (!Number.isInteger(value.externalExecution.grantTtlSeconds) || Number(value.externalExecution.grantTtlSeconds) < 1)
    ) return false;
    if (
      value.externalExecution.requireGrantConsumption !== undefined &&
      typeof value.externalExecution.requireGrantConsumption !== 'boolean'
    ) return false;
  }
  if (value.notify !== undefined) {
    if (!isRecord(value.notify) || !optionalStringArray(value.notify.channels)) return false;
  }
  if (value.resultSource !== undefined && !isResultSource(value.resultSource)) return false;
  if (!openWorldReadResultSourceValid(value.risk, value)) return false;
  if (value.influence !== undefined && !isInfluenceGuard(value.influence)) return false;
  if (value.redaction !== undefined) {
    if (!isRecord(value.redaction) || !optionalStringArray(value.redaction.fields)) return false;
    if (value.redaction.replacement !== undefined && typeof value.redaction.replacement !== 'string') return false;
  }
  return true;
}

function isResultSource(value: unknown): boolean {
  if (value === 'none') return true;
  if (!isRecord(value) || !isContentIntegrity(value.integrity)) return false;
  return value.sourceId === undefined || (
    typeof value.sourceId === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.sourceId)
  );
}

function isInfluenceGuard(value: unknown): boolean {
  if (!isRecord(value) || !Array.isArray(value.allowFrom) || value.allowFrom.length === 0) return false;
  if (value.otherwise !== 'required' && value.otherwise !== 'deny') return false;
  if (!value.allowFrom.every((source) => source === 'none' || isContentIntegrity(source))) return false;
  return new Set(value.allowFrom).size === value.allowFrom.length;
}

function isContentIntegrity(value: unknown): boolean {
  return typeof value === 'string' && (contentIntegrityValues as readonly string[]).includes(value);
}

function openWorldReadResultSourceValid(risk: unknown, rule: unknown): boolean {
  if (risk !== 'open_world_read') return true;
  return isRecord(rule) && isRecord(rule.resultSource) && rule.resultSource.integrity === 'public_untrusted';
}

function isRuleEvaluation(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    Array.isArray(value.conditions) &&
    value.conditions.every((condition) =>
      isRecord(condition) &&
      typeof condition.key === 'string' &&
      typeof condition.matched === 'boolean' &&
      Object.prototype.hasOwnProperty.call(condition, 'expected'),
    ) &&
    typeof value.conditionsMatched === 'boolean' &&
    typeof value.exists === 'boolean' &&
    isMatchType(value.matchType) &&
    typeof value.pattern === 'string' &&
    (value.prefixMatched === undefined || typeof value.prefixMatched === 'boolean') &&
    typeof value.selected === 'boolean'
  );
}

function optionalStringArray(value: unknown): boolean {
  return value === undefined || (Array.isArray(value) && value.every((item) => typeof item === 'string'));
}

function decisionForApproval(value: 'deny' | 'never' | 'required'): PolicyEvaluationTrace['decision'] {
  if (value === 'never') return 'allow';
  if (value === 'required') return 'require_approval';
  return 'deny';
}

function isDecision(value: unknown): value is PolicyEvaluationTrace['decision'] {
  return value === 'allow' || value === 'deny' || value === 'require_approval';
}

function isApproval(value: unknown): value is 'deny' | 'never' | 'required' {
  return value === 'deny' || value === 'never' || value === 'required';
}

function isMatchType(value: unknown): value is PolicyTraceMatchType {
  return value === 'default' || value === 'exact' || value === 'provider_failure' || value === 'wildcard';
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
