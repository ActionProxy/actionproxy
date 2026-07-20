import type {
  PolicyEvaluation,
  PolicyEvaluationTrace,
  PolicyFile,
  PolicyRule,
  PolicyTraceConditionEvaluation,
  PolicyTraceRuleEvaluation,
} from './policy-types';

export interface PolicyEvaluationContext {
  amount?: number;
  approverGroup?: string;
  currency?: string;
  customerVisible?: boolean;
  input?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  operationKind?: string;
  recipientDomain?: string;
  risk?: string;
}

export function evaluatePolicy(policy: PolicyFile, toolName: string, context: PolicyEvaluationContext = {}): PolicyEvaluation {
  return evaluatePolicyTrace(policy, toolName, context).evaluation;
}

export function evaluatePolicyTrace(
  policy: PolicyFile,
  toolName: string,
  context: PolicyEvaluationContext = {},
): PolicyEvaluationTrace {
  const ruleEvaluations: PolicyTraceRuleEvaluation[] = [];
  const exactRuleMatch = findExactRule(policy, toolName);
  if (exactRuleMatch) {
    const conditions = evaluateConditions(exactRuleMatch.rule.conditions, toolName, context);
    const exactEvaluation: PolicyTraceRuleEvaluation = {
      conditions,
      conditionsMatched: conditions.every((condition) => condition.matched),
      exists: true,
      matchType: 'exact',
      pattern: exactRuleMatch.pattern,
      selected: false,
    };
    if (exactEvaluation.conditionsMatched) {
      exactEvaluation.selected = true;
      ruleEvaluations.push(exactEvaluation);
      const evaluation = toEvaluation(exactRuleMatch.rule, exactRuleMatch.pattern);
      return {
        decision: evaluation.decision,
        evaluation,
        fallbackPath: ['exact'],
        matchedRule: evaluation.matchedRule,
        matchType: 'exact',
        ruleEvaluations,
      };
    }
    ruleEvaluations.push(exactEvaluation);
  }

  const wildcardRule = findWildcardRule(policy, toolName, context, ruleEvaluations);
  if (wildcardRule) {
    wildcardRule.evaluation.selected = true;
    const evaluation = toEvaluation(wildcardRule.rule, wildcardRule.pattern);
    return {
      decision: evaluation.decision,
      evaluation,
      fallbackPath: exactRuleMatch ? ['exact', 'wildcard'] : ['wildcard'],
      matchedRule: evaluation.matchedRule,
      matchType: 'wildcard',
      ruleEvaluations,
    };
  }

  const defaultRule: PolicyTraceRuleEvaluation = {
    conditions: [],
    conditionsMatched: true,
    exists: true,
    matchType: 'default',
    pattern: 'default',
    selected: true,
  };
  ruleEvaluations.push(defaultRule);
  const evaluation = toEvaluation(policy.default, 'default');
  return {
    decision: evaluation.decision,
    evaluation,
    fallbackPath: [
      ...(exactRuleMatch ? ['exact' as const] : []),
      ...(ruleEvaluations.some((rule) => rule.matchType === 'wildcard') ? ['wildcard' as const] : []),
      'default',
    ],
    matchedRule: evaluation.matchedRule,
    matchType: 'default',
    ruleEvaluations,
  };
}

function findWildcardRule(
  policy: PolicyFile,
  toolName: string,
  context: PolicyEvaluationContext,
  ruleEvaluations: PolicyTraceRuleEvaluation[],
): { evaluation: PolicyTraceRuleEvaluation; pattern: string; rule: PolicyRule } | undefined {
  for (const [pattern, rule] of Object.entries(policy.tools)) {
    if (!pattern.endsWith('.*')) continue;
    const prefix = pattern.slice(0, -1);
    const prefixMatched = toolName.startsWith(prefix);
    if (!prefixMatched) continue;
    const conditions = evaluateConditions(rule.conditions, toolName, context);
    const evaluation: PolicyTraceRuleEvaluation = {
      conditions,
      conditionsMatched: conditions.every((condition) => condition.matched),
      exists: true,
      matchType: 'wildcard',
      pattern,
      prefixMatched,
      selected: false,
    };
    ruleEvaluations.push(evaluation);
    if (evaluation.conditionsMatched) {
      return { evaluation, pattern, rule };
    }
  }
  return undefined;
}

function evaluateConditions(
  conditions: Record<string, unknown> | undefined,
  toolName: string,
  context: PolicyEvaluationContext,
): PolicyTraceConditionEvaluation[] {
  if (!conditions || Object.keys(conditions).length === 0) return [];
  return Object.entries(conditions).map(([key, expected]) => {
    const evaluated = evaluateCondition(key, expected, toolName, context);
    return {
      actual: evaluated.actual,
      expected,
      key,
      matched: evaluated.matched,
    };
  });
}

function evaluateCondition(
  key: string,
  expected: unknown,
  toolName: string,
  context: PolicyEvaluationContext,
): { actual?: unknown; matched: boolean } {
    switch (key) {
      case 'actionId':
        return { actual: toolName, matched: matchesToolName(expected, toolName) };
      case 'approverGroup':
        return matchOneWithActual(expected, context.approverGroup ?? stringContext(context.metadata?.approverGroup));
      case 'amount':
      case 'amountThreshold':
        return matchAmountWithActual(expected, numberContext(context.amount ?? context.input?.amount ?? context.input?.amountCents));
      case 'currency':
        return matchOneWithActual(expected, context.currency ?? stringContext(context.input?.currency));
      case 'customerVisible':
        return matchBooleanWithActual(expected, context.customerVisible ?? booleanContext(context.metadata?.customerVisible));
      case 'operation':
      case 'operationKind':
        return matchOneWithActual(expected, context.operationKind ?? stringContext(context.metadata?.operationKind));
      case 'recipientDomain':
        return matchRecipientDomainWithActual(expected, context);
      case 'risk':
      case 'riskKind':
        return matchOneWithActual(expected, context.risk ?? stringContext(context.metadata?.riskKind));
      default:
        return { matched: false };
    }
}

function matchOneWithActual(expected: unknown, actual: string | undefined): { actual?: unknown; matched: boolean } {
  return { actual, matched: matchesOne(expected, actual) };
}

function matchBooleanWithActual(expected: unknown, actual: boolean | undefined): { actual?: unknown; matched: boolean } {
  return { actual, matched: matchesBoolean(expected, actual) };
}

function matchAmountWithActual(expected: unknown, actual: number | undefined): { actual?: unknown; matched: boolean } {
  return { actual, matched: matchesAmount(expected, actual) };
}

function matchRecipientDomainWithActual(
  expected: unknown,
  context: PolicyEvaluationContext,
): { actual?: unknown; matched: boolean } {
  const actual = recipientDomainContext(context);
  return { actual, matched: actual ? matchesOne(expected, actual) : false };
}

function matchesOne(expected: unknown, actual: string | undefined): boolean {
  if (!actual) return false;
  if (Array.isArray(expected)) return expected.some((candidate) => matchesOne(candidate, actual));
  return typeof expected === 'string' && expected === actual;
}

function matchesToolName(expected: unknown, actual: string | undefined): boolean {
  return matchesOne(expected, actual);
}

function findExactRule(policy: PolicyFile, toolName: string): { pattern: string; rule: PolicyRule } | undefined {
  const rule = policy.tools[toolName];
  return rule ? { pattern: toolName, rule } : undefined;
}

function matchesBoolean(expected: unknown, actual: boolean | undefined): boolean {
  return typeof expected === 'boolean' && actual === expected;
}

function matchesAmount(expected: unknown, actual: number | undefined): boolean {
  if (typeof actual !== 'number' || !Number.isFinite(actual)) return false;
  if (typeof expected === 'number') return actual === expected;
  if (!isRecord(expected)) return false;
  const gt = numberContext(expected.gt);
  const gte = numberContext(expected.gte);
  const lt = numberContext(expected.lt);
  const lte = numberContext(expected.lte);
  const eq = numberContext(expected.eq);
  if (gt !== undefined && actual <= gt) return false;
  if (gte !== undefined && actual < gte) return false;
  if (lt !== undefined && actual >= lt) return false;
  if (lte !== undefined && actual > lte) return false;
  if (eq !== undefined && actual !== eq) return false;
  return gt !== undefined || gte !== undefined || lt !== undefined || lte !== undefined || eq !== undefined;
}

function matchesRecipientDomain(expected: unknown, context: PolicyEvaluationContext): boolean {
  const actual = recipientDomainContext(context);
  return actual ? matchesOne(expected, actual) : false;
}

function recipientDomainContext(context: PolicyEvaluationContext): string | undefined {
  const explicit = context.recipientDomain;
  if (explicit) return explicit;
  const recipients = [
    ...stringList(context.input?.to),
    ...stringList(context.input?.cc),
    ...stringList(context.input?.bcc),
    ...stringList(context.input?.recipient),
  ];
  if (!recipients.length) return undefined;
  const internalDomain = stringContext(context.metadata?.internalDomain);
  if (!internalDomain) return 'external';
  const allInternal = recipients.every((recipient) => emailDomain(recipient) === internalDomain.toLowerCase());
  return allInternal ? 'internal' : 'external';
}

function stringList(value: unknown): string[] {
  if (typeof value === 'string') return value.split(',').map((item) => item.trim()).filter(Boolean);
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0);
  return [];
}

function emailDomain(value: string): string | undefined {
  const match = value.trim().toLowerCase().match(/@([^>\s,]+)>?$/);
  return match?.[1];
}

function stringContext(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function numberContext(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function booleanContext(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toEvaluation(rule: PolicyRule, matchedRule: string): PolicyEvaluation {
  if (rule.approval === 'never') {
    return {
      decision: 'allow',
      approval: rule.approval,
      risk: rule.risk ?? 'unknown',
      reason: rule.reason ?? 'Policy allowed this tool.',
      matchedRule,
      rule,
    };
  }

  if (rule.approval === 'required') {
    return {
      decision: 'require_approval',
      approval: rule.approval,
      risk: rule.risk ?? 'unknown',
      reason: rule.reason ?? 'Policy requires approval for this tool.',
      matchedRule,
      rule,
    };
  }

  return {
    decision: 'deny',
    approval: rule.approval,
    risk: rule.risk ?? 'unknown',
    reason: rule.reason ?? 'Policy denied this tool.',
    matchedRule,
    rule,
  };
}
