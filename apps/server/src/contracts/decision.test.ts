import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { PolicyEvaluationContext } from '../policy/evaluate-policy';
import type { PolicyFile, PolicyTraceMatchType } from '../policy/policy-types';
import type { ToolCallRecord } from '../models';
import {
  POLICY_EVALUATOR_VERSION,
  YAML_POLICY_PROVIDER_ID,
  YAML_POLICY_PROVIDER_VERSION,
  createYamlPolicyProvider,
  evaluatePolicyProvider,
  type DeterministicPolicyProvider,
  type PolicyProviderFailureCode,
} from '../policy/policy-provider';
import {
  buildActionProxyDecision,
  validatedActionProxyDecisionForToolCall,
  type ActionProxyDecisionV1,
  type DecisionObligation,
  type DecisionReasonCode,
} from './decision';

interface DecisionFixture {
  policy: PolicyFile;
  providerIdentity: { policyVersionHash: string; policyVersionId: string };
  scenarios: Array<{
    context: PolicyEvaluationContext;
    decidedAt: string;
    decisionInputHash: string;
    expected: {
      approvalRequired: boolean;
      decisionId: string;
      eligibleGroups?: string[];
      eligibleUsers?: string[];
      matchType: PolicyTraceMatchType;
      obligations: DecisionObligation[];
      outcome: 'allow' | 'deny' | 'require_approval';
      reasonCodes: DecisionReasonCode[];
      requiredApprovals: number;
      ruleId: string;
      separationOfDuties?: boolean;
    };
    name: string;
    requestId: string;
    tenantId: string;
    toolName: string;
  }>;
  version: string;
}

const fixture = JSON.parse(
  fs.readFileSync(path.resolve('../../fixtures/contracts/decision-v1.json'), 'utf8'),
) as DecisionFixture;

const descriptor = {
  evaluatorVersion: POLICY_EVALUATOR_VERSION,
  policyDigest: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  policyDigestAlgorithm: 'sha256' as const,
  policySchemaVersion: '1',
  policyVersion: 'policy_fixture_v1',
  providerId: YAML_POLICY_PROVIDER_ID,
  providerVersion: YAML_POLICY_PROVIDER_VERSION,
};

describe('actionproxy.decision.v1', () => {
  it('matches reusable allow, deny, approval, and conditional-fallback vectors', () => {
    const provider = createYamlPolicyProvider(fixture.policy, fixture.providerIdentity);

    for (const scenario of fixture.scenarios) {
      const providerEvaluation = evaluatePolicyProvider(provider, {
        context: scenario.context,
        toolName: scenario.toolName,
      });
      const decision = buildActionProxyDecision({
        decidedAt: scenario.decidedAt,
        decisionInputHash: scenario.decisionInputHash,
        providerEvaluation,
        requestId: scenario.requestId,
        tenantId: scenario.tenantId,
      });

      expect(decision, scenario.name).toMatchObject({
        approvalRequirements: {
          eligibleGroups: scenario.expected.eligibleGroups ?? [],
          eligibleUsers: scenario.expected.eligibleUsers ?? [],
          expirationRequired: false,
          expiresAt: null,
          required: scenario.expected.approvalRequired,
          requiredApprovals: scenario.expected.requiredApprovals,
          separationOfDuties: scenario.expected.separationOfDuties ?? false,
        },
        decidedAt: scenario.decidedAt,
        decisionId: scenario.expected.decisionId,
        decisionInputHash: scenario.decisionInputHash,
        evaluatorVersion: POLICY_EVALUATOR_VERSION,
        matchedPolicies: [
          {
            matchType: scenario.expected.matchType,
            digestAlgorithm: 'sha256',
            policyDigest: fixture.providerIdentity.policyVersionHash,
            policyVersion: fixture.providerIdentity.policyVersionId,
            providerId: YAML_POLICY_PROVIDER_ID,
            ruleId: scenario.expected.ruleId,
          },
        ],
        obligations: scenario.expected.obligations,
        outcome: scenario.expected.outcome,
        policy: {
          digest: fixture.providerIdentity.policyVersionHash,
          digestAlgorithm: 'sha256',
          provider: { id: YAML_POLICY_PROVIDER_ID, status: 'ok', version: YAML_POLICY_PROVIDER_VERSION },
          schemaVersion: '1',
          version: fixture.providerIdentity.policyVersionId,
        },
        reasonCodes: scenario.expected.reasonCodes,
        requestId: scenario.requestId,
        tenantId: scenario.tenantId,
        version: fixture.version,
      });
    }
  });

  it('keeps decision identity deterministic while leaving the decision timestamp explicit', () => {
    const provider = createYamlPolicyProvider(fixture.policy, fixture.providerIdentity);
    const scenario = fixture.scenarios[0]!;
    const providerEvaluation = evaluatePolicyProvider(provider, { context: {}, toolName: scenario.toolName });
    const first = buildActionProxyDecision({ ...scenario, providerEvaluation });
    const later = buildActionProxyDecision({
      ...scenario,
      decidedAt: '2026-07-12T00:00:00.000Z',
      providerEvaluation,
    });

    expect(later.decisionId).toBe(first.decisionId);
    expect(later.decidedAt).not.toBe(first.decidedAt);
  });

  it('rejects stale-id mutations of every authorization-relevant decision section', () => {
    const scenario = fixture.scenarios.find(({ expected }) => expected.outcome === 'allow')!;
    const provider = createYamlPolicyProvider(fixture.policy, fixture.providerIdentity);
    const decision = buildActionProxyDecision({
      decidedAt: scenario.decidedAt,
      decisionInputHash: scenario.decisionInputHash,
      providerEvaluation: evaluatePolicyProvider(provider, { context: scenario.context, toolName: scenario.toolName }),
      requestId: scenario.requestId,
      tenantId: scenario.tenantId,
    });
    const toolCall = toolCallForDecision(decision, scenario.toolName);

    expect(validatedActionProxyDecisionForToolCall(toolCall)).toEqual(decision);

    const mutations: Array<(candidate: ActionProxyDecisionV1) => void> = [
      (candidate) => { candidate.outcome = 'deny'; },
      (candidate) => { candidate.requestId = 'toolcall_forged'; },
      (candidate) => { candidate.tenantId = 'tenant_forged'; },
      (candidate) => { candidate.decisionInputHash = 'input_forged'; },
      (candidate) => { candidate.policy.provider.status = 'failure'; },
      (candidate) => { candidate.obligations = ['record_decision_evidence', 'do_not_execute']; },
      (candidate) => { candidate.reasonCodes = ['policy_outcome_deny']; },
      (candidate) => { candidate.matchedPolicies[0]!.ruleId = 'rule_forged'; },
      (candidate) => {
        (candidate.matchedPolicies[0] as { matchType: string }).matchType = 'business_action_default';
      },
      (candidate) => { candidate.approvalRequirements.required = true; },
    ];
    for (const mutate of mutations) {
      const candidate = JSON.parse(JSON.stringify(decision)) as ActionProxyDecisionV1;
      mutate(candidate);
      expect(
        validatedActionProxyDecisionForToolCall({
          ...toolCall,
          decisionTrace: { decisionV1: candidate },
        }),
      ).toBeUndefined();
    }
  });

  it.each([
    ['unavailable', undefined, 'policy_provider_unavailable'],
    [
      'throwing',
      { descriptor, evaluate: () => { throw new Error('secret provider diagnostic'); } },
      'policy_provider_error',
    ],
    [
      'malformed',
      { descriptor, evaluate: () => ({ decision: 'allow' }) },
      'policy_provider_invalid_output',
    ],
    [
      'versionless',
      { descriptor: { providerId: 'versionless' }, evaluate: () => { throw new Error('must not run'); } },
      'policy_provider_version_missing',
    ],
  ] as Array<[string, DeterministicPolicyProvider | undefined, PolicyProviderFailureCode]>) (
    'fails closed for a %s policy provider',
    (_name, provider, failureCode) => {
      const providerEvaluation = evaluatePolicyProvider(provider, { context: {}, toolName: 'docs.search' });
      const decision = buildActionProxyDecision({
        decidedAt: '2026-07-11T00:00:00.000Z',
        decisionInputHash: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        providerEvaluation,
        requestId: `request_${failureCode}`,
        tenantId: 'tenant_fixture',
      });

      expect(providerEvaluation.trace.decision).toBe('deny');
      expect(decision).toMatchObject({
        evaluatorVersion: failureCode === 'policy_provider_version_missing' || failureCode === 'policy_provider_unavailable'
          ? null
          : POLICY_EVALUATOR_VERSION,
        matchedPolicies: [],
        obligations: ['record_decision_evidence', 'do_not_execute'],
        outcome: 'deny',
        policy: { provider: { status: 'failure' } },
        reasonCodes: ['policy_outcome_deny', failureCode],
      });
      expect(JSON.stringify(decision)).not.toContain('secret provider diagnostic');
    },
  );

  it('fails closed before projection when a provider returns malformed nested rule data', () => {
    const provider = {
      descriptor,
      evaluate: () => ({
        decision: 'allow',
        evaluation: {
          approval: 'never',
          decision: 'allow',
          matchedRule: 'docs.search',
          reason: 'Malformed nested rule',
          risk: 'read_only',
          rule: { approval: 'never', approvers: { groups: 'administrators' } },
        },
        fallbackPath: ['exact'],
        matchedRule: 'docs.search',
        matchType: 'exact',
        ruleEvaluations: [],
      }),
    } as unknown as DeterministicPolicyProvider;

    const providerEvaluation = evaluatePolicyProvider(provider, { context: {}, toolName: 'docs.search' });
    const decision = buildActionProxyDecision({
      decidedAt: '2026-07-12T00:00:00.000Z',
      decisionInputHash: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      providerEvaluation,
      requestId: 'request_malformed_nested_rule',
      tenantId: 'tenant_fixture',
    });

    expect(providerEvaluation).toMatchObject({
      failureCode: 'policy_provider_invalid_output',
      status: 'failure',
      trace: { decision: 'deny' },
    });
    expect(decision).toMatchObject({
      obligations: ['record_decision_evidence', 'do_not_execute'],
      outcome: 'deny',
      reasonCodes: ['policy_outcome_deny', 'policy_provider_invalid_output'],
    });
  });

  it.each([
    ['an empty allowFrom set', { allowFrom: [], otherwise: 'required' }],
    ['an unknown integrity class', { allowFrom: ['well_known'], otherwise: 'required' }],
    ['a fallback that could allow', { allowFrom: ['none'], otherwise: 'never' }],
    ['duplicate integrity classes', { allowFrom: ['none', 'none'], otherwise: 'deny' }],
  ])('fails closed when a provider returns influence with %s', (_name, influence) => {
    const provider = {
      descriptor,
      evaluate: () => ({
        decision: 'allow',
        evaluation: {
          approval: 'never',
          decision: 'allow',
          matchedRule: 'research.notes.append',
          reason: 'Malformed provider influence guard',
          risk: 'low_risk_write',
          rule: { approval: 'never', influence, resultSource: 'none' },
        },
        fallbackPath: ['exact'],
        matchedRule: 'research.notes.append',
        matchType: 'exact',
        ruleEvaluations: [],
      }),
    } as unknown as DeterministicPolicyProvider;

    expect(evaluatePolicyProvider(provider, { context: {}, toolName: 'research.notes.append' })).toMatchObject({
      failureCode: 'policy_provider_invalid_output',
      status: 'failure',
      trace: { decision: 'deny' },
    });
  });

  it.each([
    ['missing', undefined, 'open_world_read'],
    ['none', 'none', 'open_world_read'],
    ['another integrity class', { integrity: 'unknown' }, 'open_world_read'],
    ['an unclassified nested rule', undefined, 'read_only'],
  ])('fails a provider with %s result-source evidence closed for open-world reads', (_name, resultSource, ruleRisk) => {
    const provider = {
      descriptor,
      evaluate: () => ({
        decision: 'require_approval',
        evaluation: {
          approval: 'required',
          decision: 'require_approval',
          matchedRule: 'web.fetch',
          reason: 'Open-world read',
          risk: 'open_world_read',
          rule: {
            approval: 'required',
            ...(resultSource === undefined ? {} : { resultSource }),
            risk: ruleRisk,
          },
        },
        fallbackPath: [],
        matchedRule: 'web.fetch',
        matchType: 'exact',
        ruleEvaluations: [],
      }),
    } as unknown as DeterministicPolicyProvider;

    expect(evaluatePolicyProvider(provider, { context: {}, toolName: 'web.fetch' })).toMatchObject({
      failureCode: 'policy_provider_invalid_output',
      status: 'failure',
      trace: { decision: 'deny' },
    });
  });
});

function toolCallForDecision(decision: ActionProxyDecisionV1, toolName: string): ToolCallRecord {
  return {
    agentId: 'decision-validator-agent',
    canonicalDecisionInputHash: decision.decisionInputHash,
    createdAt: decision.decidedAt,
    decision: decision.outcome,
    decisionTrace: { decisionV1: decision },
    id: decision.requestId,
    input: {},
    metadata: {},
    policyVersionHash: decision.policy.digest ?? undefined,
    policyVersionId: decision.policy.version ?? undefined,
    reason: 'Validate stored decision integrity',
    requestedBy: 'actor@example.com',
    status: 'submitted',
    toolName,
    updatedAt: decision.decidedAt,
    workspaceId: decision.tenantId,
  };
}
