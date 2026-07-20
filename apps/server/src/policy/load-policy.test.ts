import { describe, expect, it } from 'vitest';
import { hashJson } from '../security/crypto';
import { parsePolicy } from './load-policy';
import { contentIntegrityValues } from './policy-types';

describe('content-aware policy parsing', () => {
  it('round-trips every supported result source and influence source/outcome', () => {
    const influenceSources = ['none', ...contentIntegrityValues] as const;
    const policy = {
      default: { approval: 'required' as const, risk: 'unknown' },
      tools: {
        ...Object.fromEntries(contentIntegrityValues.map((integrity) => [
          `result.${integrity}`,
          {
            approval: 'never' as const,
            resultSource: { integrity, sourceId: `source:${integrity}` },
            risk: 'read',
          },
        ])),
        'result.none': { approval: 'never' as const, resultSource: 'none' as const, risk: 'no_content' },
        ...Object.fromEntries(influenceSources.flatMap((source) =>
          (['required', 'deny'] as const).map((otherwise) => [
            `influence.${source}.${otherwise}`,
            {
              approval: 'never' as const,
              influence: { allowFrom: [source], otherwise },
              resultSource: 'none' as const,
              risk: 'guarded',
            },
          ]))),
      },
      version: 1,
    };

    expect(parsePolicy(policy)).toEqual(policy);
  });

  it('strictly parses result sources and narrowing influence guards', () => {
    expect(parsePolicy({
      default: { approval: 'required', reason: 'Unknown tools require approval.', risk: 'unknown' },
      tools: {
        'company.docs.search': {
          approval: 'never',
          resultSource: { integrity: 'organization_managed', sourceId: 'company-docs' },
          risk: 'closed_world_read',
        },
        'research.notes.append': {
          approval: 'never',
          influence: {
            allowFrom: ['none', 'organization_managed', 'verified_publisher'],
            otherwise: 'required',
          },
          resultSource: 'none',
          risk: 'low_risk_write',
        },
      },
      version: 1,
    }).tools['research.notes.append']).toMatchObject({
      influence: {
        allowFrom: ['none', 'organization_managed', 'verified_publisher'],
        otherwise: 'required',
      },
      resultSource: 'none',
    });
  });

  it('requires every open-world-read rule to classify output as public untrusted', () => {
    const validRule = {
      approval: 'required' as const,
      resultSource: { integrity: 'public_untrusted' as const, sourceId: 'public-web' },
      risk: 'open_world_read',
    };
    expect(parsePolicy({ default: validRule, tools: { 'web.fetch': validRule }, version: 1 })).toMatchObject({
      default: validRule,
      tools: { 'web.fetch': validRule },
    });

    for (const resultSource of [
      undefined,
      'none',
      { integrity: 'unknown' },
      { integrity: 'verified_publisher' },
    ]) {
      const invalidRule = {
        approval: 'required',
        ...(resultSource === undefined ? {} : { resultSource }),
        risk: 'open_world_read',
      };
      expect(() => parsePolicy({ default: invalidRule, tools: {}, version: 1 }))
        .toThrow(/open_world_read requires resultSource\.integrity public_untrusted/u);
      expect(() => parsePolicy({
        default: { approval: 'required', risk: 'unknown' },
        tools: { 'web.fetch': invalidRule },
        version: 1,
      })).toThrow(/open_world_read requires resultSource\.integrity public_untrusted/u);
    }
  });

  it.each([
    ['unknown integrity', { resultSource: { integrity: 'well_known' } }],
    ['invalid source ID', { resultSource: { integrity: 'verified_publisher', sourceId: 'https://example.com' } }],
    ['unknown result source field', { resultSource: { integrity: 'verified_publisher', trusted: true } }],
    ['empty allowFrom', { influence: { allowFrom: [], otherwise: 'required' } }],
    ['duplicate allowFrom', { influence: { allowFrom: ['none', 'none'], otherwise: 'required' } }],
    ['loosening fallback', { influence: { allowFrom: ['none'], otherwise: 'never' } }],
    ['unknown nested field', { influence: { allowFrom: ['none'], otherwise: 'required', trustMe: true } }],
  ])('rejects %s', (_name, invalidFields) => {
    expect(() => parsePolicy({
      default: { approval: 'required' },
      tools: { 'test.tool': { approval: 'never', ...invalidFields } },
      version: 1,
    })).toThrow('Invalid policy file');
  });

  it('preserves legacy parsing behavior for unrelated unknown policy fields', () => {
    expect(parsePolicy({
      default: { approval: 'required', legacyIgnoredField: true },
      tools: {},
      legacyIgnoredTopLevel: true,
      version: 1,
    })).toEqual({
      default: { approval: 'required' },
      tools: {},
      version: 1,
    });
  });

  it('does not add fields or change hashes for legacy policies', () => {
    const legacy = {
      default: { approval: 'required' as const, reason: 'Unknown tools require approval.', risk: 'unknown' },
      tools: {
        'docs.search': { approval: 'never' as const, reason: 'Reviewed read.', risk: 'read_only' },
      },
      version: 1,
    };
    const parsed = parsePolicy(legacy);
    expect(parsed).toEqual(legacy);
    expect(hashJson(parsed)).toBe(hashJson(legacy));
  });
});
