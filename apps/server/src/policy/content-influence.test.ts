import { describe, expect, it } from 'vitest';
import { evaluateContentInfluence, resultSourceForPolicyRule } from './content-influence';
import type { PolicyEvaluation, PolicyRule } from './policy-types';

describe('content influence policy', () => {
  it('intersects every base decision with allowed, approval, and deny influence outcomes', () => {
    const strictness = { never: 0, required: 1, deny: 2 } as const;
    for (const baseApproval of ['never', 'required', 'deny'] as const) {
      for (const otherwise of ['required', 'deny'] as const) {
        for (const sourcesAllowed of [true, false]) {
          const result = evaluateContentInfluence(
            evaluation({
              approval: baseApproval,
              influence: { allowFrom: ['organization_managed'], otherwise },
            }),
            {
              observedIntegrities: [sourcesAllowed ? 'organization_managed' : 'public_untrusted'],
              scopeVerified: true,
            },
          );
          const expectedApproval = sourcesAllowed || strictness[baseApproval] >= strictness[otherwise]
            ? baseApproval
            : otherwise;
          expect(result.effectiveApproval, `${baseApproval}/${otherwise}/${sourcesAllowed}`).toBe(expectedApproval);
          expect(result.effectiveDecision).toBe(
            expectedApproval === 'never'
              ? 'allow'
              : expectedApproval === 'required'
                ? 'require_approval'
                : 'deny',
          );
          expect(strictness[result.effectiveApproval]).toBeGreaterThanOrEqual(strictness[baseApproval]);
        }
      }
    }
  });

  it('preserves the base decision when no guard is configured', () => {
    expect(evaluateContentInfluence(evaluation({ approval: 'never' }), {
      observedIntegrities: ['public_untrusted'],
      scopeVerified: true,
    })).toMatchObject({
      effectiveDecision: 'allow',
      observedSources: ['public_untrusted'],
      restrictionApplied: false,
      sourcesAllowed: true,
    });
  });

  it('allows an empty verified scope only when none is allowed', () => {
    expect(evaluateContentInfluence(evaluation(guardedRule('required')), {
      observedIntegrities: [],
      scopeVerified: true,
    })).toMatchObject({
      effectiveDecision: 'allow',
      observedSources: ['none'],
      sourcesAllowed: true,
    });
  });

  it('upgrades an allow to approval when any observed source is outside allowFrom', () => {
    expect(evaluateContentInfluence(evaluation(guardedRule('required')), {
      observedIntegrities: ['organization_managed', 'public_untrusted'],
      scopeVerified: true,
    })).toMatchObject({
      baseDecision: 'allow',
      effectiveApproval: 'required',
      effectiveDecision: 'require_approval',
      observedSources: ['organization_managed', 'public_untrusted'],
      restrictionApplied: true,
      sourcesAllowed: false,
    });
  });

  it('treats an unverified scope as unknown even when no exposure was supplied', () => {
    expect(evaluateContentInfluence(evaluation(guardedRule('required')), {
      observedIntegrities: [],
      scopeVerified: false,
    })).toMatchObject({
      effectiveDecision: 'require_approval',
      observedSources: ['unknown'],
      sourcesAllowed: false,
    });
  });

  it('can narrow approval-required to deny and never loosens a base deny', () => {
    const denyOnViolation = guardedRule('deny');
    expect(evaluateContentInfluence(evaluation({ ...denyOnViolation, approval: 'required' }), {
      observedIntegrities: ['unknown'],
      scopeVerified: true,
    }).effectiveDecision).toBe('deny');
    expect(evaluateContentInfluence(evaluation({ ...guardedRule('required'), approval: 'deny' }), {
      observedIntegrities: ['unknown'],
      scopeVerified: true,
    })).toMatchObject({
      effectiveApproval: 'deny',
      effectiveDecision: 'deny',
      restrictionApplied: false,
    });
  });

  it('defaults unclassified results to unknown and honors reviewed no-content results', () => {
    expect(resultSourceForPolicyRule({ approval: 'never' })).toEqual({ integrity: 'unknown' });
    expect(resultSourceForPolicyRule({ approval: 'never', resultSource: 'none' })).toBeUndefined();
    expect(resultSourceForPolicyRule({
      approval: 'never',
      resultSource: { integrity: 'organization_managed', sourceId: 'company-docs' },
    })).toEqual({ integrity: 'organization_managed', sourceId: 'company-docs' });
  });
});

function guardedRule(otherwise: 'deny' | 'required'): PolicyRule {
  return {
    approval: 'never',
    influence: {
      allowFrom: ['none', 'organization_managed', 'verified_publisher'],
      otherwise,
    },
  };
}

function evaluation(rule: PolicyRule): PolicyEvaluation {
  const decision = rule.approval === 'never' ? 'allow' : rule.approval === 'required' ? 'require_approval' : 'deny';
  return {
    approval: rule.approval,
    decision,
    matchedRule: 'test.tool',
    reason: 'Test policy rule.',
    risk: 'test',
    rule,
  };
}
