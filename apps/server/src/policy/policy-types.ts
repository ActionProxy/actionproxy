export type ApprovalMode = 'never' | 'required' | 'deny';

/**
 * Integrity describes where model-visible tool output came from in ActionProxy
 * policy and evidence. It never grants instruction authority; child result
 * fields remain opaque assertions and cannot authorize an action.
 */
export const contentIntegrityValues = [
  'organization_managed',
  'verified_publisher',
  'authenticated_external',
  'public_untrusted',
  'unknown',
] as const;

export type ContentIntegrity = (typeof contentIntegrityValues)[number];
export type ContentInfluenceSource = ContentIntegrity | 'none';

export interface PolicyResultSource {
  integrity: ContentIntegrity;
  sourceId?: string;
}

export interface PolicyInfluenceGuard {
  allowFrom: ContentInfluenceSource[];
  /** A content-influence guard may only narrow the base policy. */
  otherwise: Exclude<ApprovalMode, 'never'>;
}

export interface PolicyRule {
  approval: ApprovalMode;
  approvers?: {
    groups?: string[];
    users?: string[];
    requiredApprovals?: number;
    separationOfDuties?: boolean;
  };
  conditions?: Record<string, unknown>;
  externalExecution?: {
    grantTtlSeconds?: number;
    requireGrantConsumption?: boolean;
  };
  notify?: {
    channels?: string[];
  };
  /**
   * Classification applied after this tool successfully returns model-visible
   * content. `none` is reserved for reviewed tools whose result cannot carry
   * content into the model.
   */
  resultSource?: 'none' | PolicyResultSource;
  /**
   * Additional source-to-action restriction. This is evaluated as an
   * intersection with the normal approval decision and can never loosen it.
   */
  influence?: PolicyInfluenceGuard;
  redaction?: {
    fields?: string[];
    replacement?: string;
  };
  risk?: string;
  reason?: string;
}

export interface PolicyFile {
  version: number;
  default: PolicyRule;
  tools: Record<string, PolicyRule>;
}

export interface PolicyEvaluation {
  decision: 'allow' | 'require_approval' | 'deny';
  approval: ApprovalMode;
  risk: string;
  reason: string;
  matchedRule: string;
  rule: PolicyRule;
}

export type PolicyTraceMatchType = 'default' | 'exact' | 'provider_failure' | 'wildcard';

export interface PolicyTraceConditionEvaluation {
  actual?: unknown;
  expected: unknown;
  key: string;
  matched: boolean;
}

export interface PolicyTraceRuleEvaluation {
  conditions: PolicyTraceConditionEvaluation[];
  conditionsMatched: boolean;
  exists: boolean;
  matchType: PolicyTraceMatchType;
  pattern: string;
  prefixMatched?: boolean;
  selected: boolean;
}

export interface PolicyEvaluationTrace {
  decision: PolicyEvaluation['decision'];
  evaluation: PolicyEvaluation;
  fallbackPath: PolicyTraceMatchType[];
  matchType: PolicyTraceMatchType;
  matchedRule: string;
  ruleEvaluations: PolicyTraceRuleEvaluation[];
}

export interface ContentInfluenceEvaluation {
  baseDecision: PolicyEvaluation['decision'];
  effectiveApproval: ApprovalMode;
  effectiveDecision: PolicyEvaluation['decision'];
  observedSources: ContentInfluenceSource[];
  reason: string;
  restrictionApplied: boolean;
  sourcesAllowed: boolean;
}
