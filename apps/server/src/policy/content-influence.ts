import type {
  ApprovalMode,
  ContentInfluenceEvaluation,
  ContentInfluenceSource,
  ContentIntegrity,
  PolicyEvaluation,
  PolicyResultSource,
  PolicyRule,
} from './policy-types';
import { contentIntegrityValues } from './policy-types';

const sourceOrder: readonly ContentInfluenceSource[] = ['none', ...contentIntegrityValues];

/**
 * Intersects the normal policy decision with a rule's content-influence guard.
 * A missing or unverified scope is deliberately represented as `unknown`.
 */
export function evaluateContentInfluence(
  base: PolicyEvaluation,
  input: {
    observedIntegrities?: readonly ContentIntegrity[];
    scopeVerified: boolean;
  },
): ContentInfluenceEvaluation {
  const observedSources = normalizedObservedSources(input.observedIntegrities ?? [], input.scopeVerified);
  const guard = base.rule.influence;
  if (!guard) {
    return {
      baseDecision: base.decision,
      effectiveApproval: base.approval,
      effectiveDecision: base.decision,
      observedSources,
      reason: 'No content-influence guard is configured for the matched policy rule.',
      restrictionApplied: false,
      sourcesAllowed: true,
    };
  }

  const allowed = observedSources.every((source) => guard.allowFrom.includes(source));
  if (allowed) {
    return {
      baseDecision: base.decision,
      effectiveApproval: base.approval,
      effectiveDecision: base.decision,
      observedSources,
      reason: 'Observed content sources satisfy the matched policy rule.',
      restrictionApplied: false,
      sourcesAllowed: true,
    };
  }

  const effectiveApproval = stricterApproval(base.approval, guard.otherwise);
  return {
    baseDecision: base.decision,
    effectiveApproval,
    effectiveDecision: decisionForApproval(effectiveApproval),
    observedSources,
    reason: `Observed content sources are outside the rule allowFrom set; policy ${guard.otherwise === 'deny' ? 'denies execution' : 'requires approval'}.`,
    restrictionApplied: effectiveApproval !== base.approval,
    sourcesAllowed: false,
  };
}

/**
 * Resolves the result classification captured at authorization time. An
 * omitted classification is `unknown`; `none` means no exposure is recorded.
 */
export function resultSourceForPolicyRule(rule: PolicyRule): PolicyResultSource | undefined {
  if (rule.resultSource === 'none') return undefined;
  if (!rule.resultSource) return { integrity: 'unknown' };
  return { ...rule.resultSource };
}

function normalizedObservedSources(
  observedIntegrities: readonly ContentIntegrity[],
  scopeVerified: boolean,
): ContentInfluenceSource[] {
  if (!scopeVerified) return ['unknown'];
  const unique = new Set<ContentInfluenceSource>(observedIntegrities);
  if (unique.size === 0) unique.add('none');
  return sourceOrder.filter((source) => unique.has(source));
}

function stricterApproval(base: ApprovalMode, restriction: Exclude<ApprovalMode, 'never'>): ApprovalMode {
  return approvalStrictness(restriction) > approvalStrictness(base) ? restriction : base;
}

function approvalStrictness(approval: ApprovalMode): number {
  if (approval === 'deny') return 3;
  if (approval === 'required') return 2;
  return 1;
}

function decisionForApproval(approval: ApprovalMode): PolicyEvaluation['decision'] {
  if (approval === 'never') return 'allow';
  if (approval === 'required') return 'require_approval';
  return 'deny';
}
