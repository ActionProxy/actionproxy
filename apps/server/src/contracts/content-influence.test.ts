import { describe, expect, it } from 'vitest';
import type { PolicyEvaluation } from '../policy/policy-types';
import { evaluateContentInfluence } from '../policy/content-influence';
import {
  buildContentInfluenceEvidence,
  sameContentInfluenceBinding,
  validContentInfluenceBindingHash,
  validatedContentExposureRevisionGuard,
} from './content-influence';

const base: PolicyEvaluation = {
  approval: 'never',
  decision: 'allow',
  matchedRule: 'notes.append',
  reason: 'Normally automatic.',
  risk: 'low_risk_write',
  rule: {
    approval: 'never',
    influence: { allowFrom: ['none', 'organization_managed'], otherwise: 'required' },
  },
};

describe('content influence evidence', () => {
  it('is deterministic, bounded, and changes when exposure evidence changes', () => {
    const influenceScopeId = `influence_${'a'.repeat(64)}`;
    const evaluation = evaluateContentInfluence(base, {
      observedIntegrities: ['public_untrusted'],
      scopeVerified: true,
    });
    const exposure = {
      influenceScopeId,
      integrity: 'public_untrusted' as const,
      observedAt: '2026-07-15T00:00:00.000Z',
      policyVersionHash: 'policy_hash',
      sourceId: 'public-web',
      sourceToolCallId: 'toolcall_read',
      workspaceId: 'workspace',
    };
    const first = buildContentInfluenceEvidence({
      evaluatedAt: '2026-07-15T00:00:01.000Z',
      evaluation,
      exposureLookup: { overflow: false, records: [exposure], revision: 1 },
      influenceScopeId,
      policyVersionHash: 'policy_hash',
      selectedRule: base.rule.influence!,
    });
    const replay = buildContentInfluenceEvidence({
      evaluatedAt: '2026-07-15T00:00:02.000Z',
      evaluation,
      exposureLookup: { overflow: false, records: [exposure], revision: 1 },
      influenceScopeId,
      policyVersionHash: 'policy_hash',
      selectedRule: base.rule.influence!,
    });
    expect(sameContentInfluenceBinding(first, replay)).toBe(true);
    expect(first.evaluatedAt).not.toBe(replay.evaluatedAt);
    expect(first.sourceReferences).toEqual([
      { integrity: 'public_untrusted', sourceId: 'public-web', sourceToolCallId: 'toolcall_read' },
    ]);

    const changed = buildContentInfluenceEvidence({
      evaluatedAt: replay.evaluatedAt,
      evaluation,
      exposureLookup: {
        overflow: false,
        records: [{ ...exposure, sourceToolCallId: 'toolcall_other' }],
        revision: 2,
      },
      influenceScopeId,
      policyVersionHash: 'policy_hash',
      selectedRule: base.rule.influence!,
    });
    expect(sameContentInfluenceBinding(first, changed)).toBe(false);
    const tampered = {
      ...first,
      exposureRevision: 0,
      influenceScope: { id: `influence_${'b'.repeat(64)}`, verified: true },
    };
    expect(validContentInfluenceBindingHash(tampered)).toBeUndefined();
    expect(sameContentInfluenceBinding(tampered, replay)).toBe(false);
    expect(validatedContentExposureRevisionGuard(tampered, `influence_${'b'.repeat(64)}`)).toBeUndefined();
    expect(validatedContentExposureRevisionGuard(first, influenceScopeId)).toEqual({
      influenceScopeId,
      revision: 1,
    });
    const unavailable = buildContentInfluenceEvidence({
      evaluatedAt: replay.evaluatedAt,
      evaluation,
      exposureLookup: { overflow: true, records: [], revision: -1 },
      influenceScopeId,
      policyVersionHash: 'policy_hash',
      selectedRule: base.rule.influence!,
    });
    expect(validContentInfluenceBindingHash(unavailable)).toBeUndefined();
  });
});
