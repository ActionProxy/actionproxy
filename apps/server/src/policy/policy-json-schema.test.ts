import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parsePolicy } from './load-policy';
import { contentIntegrityValues } from './policy-types';

type JsonSchema = {
  $schema: string;
  $id: string;
  additionalProperties: boolean;
  examples: unknown[];
  $defs: Record<string, any>;
};

const schema = JSON.parse(
  fs.readFileSync(
    new URL(
      '../../../../schemas/actionproxy.policy.v1.schema.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as JsonSchema;

describe('ActionProxy policy JSON Schema parity', () => {
  it('keeps runtime enums and numeric limits aligned with the public schema', () => {
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema.$id).toBe(
      'https://actionproxy.com/schemas/actionproxy.policy.v1.schema.json',
    );
    expect(schema.$defs.approvalMode.enum).toEqual([
      'never',
      'required',
      'deny',
    ]);
    expect(
      schema.$defs.resultSourceDescriptor.properties.integrity.enum,
    ).toEqual(contentIntegrityValues);
    expect(schema.$defs.influence.properties.allowFrom.items.enum).toEqual([
      'none',
      ...contentIntegrityValues,
    ]);
    expect(schema.$defs.influence.properties.allowFrom).toMatchObject({
      maxItems: 6,
      minItems: 1,
      uniqueItems: true,
    });
    expect(schema.$defs.approvers.properties.requiredApprovals).toMatchObject({
      maximum: 10,
      minimum: 1,
      type: 'integer',
    });
    expect(
      schema.$defs.externalExecution.properties.grantTtlSeconds,
    ).toMatchObject({
      maximum: 86400,
      minimum: 1,
      type: 'integer',
    });

    for (const approval of schema.$defs.approvalMode.enum as string[]) {
      expect(
        parsePolicy({ default: { approval }, tools: {}, version: 1 }).default
          .approval,
      ).toBe(approval);
    }
    for (const integrity of schema.$defs.resultSourceDescriptor.properties
      .integrity.enum as string[]) {
      expect(
        parsePolicy({
          default: { approval: 'required' },
          tools: { test: { approval: 'never', resultSource: { integrity } } },
          version: 1,
        }).tools.test?.resultSource,
      ).toEqual({ integrity });
    }
  });

  it('keeps additional-property compatibility strict only where the runtime is strict', () => {
    expect(schema.additionalProperties).toBe(true);
    expect(schema.$defs.policyRule.additionalProperties).toBe(true);
    expect(schema.$defs.approvers.additionalProperties).toBe(true);
    expect(schema.$defs.externalExecution.additionalProperties).toBe(true);
    expect(schema.$defs.notification.additionalProperties).toBe(true);
    expect(schema.$defs.redaction.additionalProperties).toBe(true);
    expect(schema.$defs.resultSourceDescriptor.additionalProperties).toBe(
      false,
    );
    expect(schema.$defs.influence.additionalProperties).toBe(false);

    expect(
      parsePolicy({
        default: {
          approval: 'required',
          approvers: { legacyRoutingHint: true },
          legacyRuleHint: true,
        },
        legacyTopLevelHint: true,
        tools: {},
        version: 1,
      }),
    ).toEqual({
      default: { approval: 'required', approvers: {} },
      tools: {},
      version: 1,
    });

    expect(() =>
      parsePolicy({
        default: { approval: 'required' },
        tools: {
          test: {
            approval: 'never',
            resultSource: { integrity: 'unknown', unreviewedField: true },
          },
        },
        version: 1,
      }),
    ).toThrow('Invalid policy file');
    expect(() =>
      parsePolicy({
        default: { approval: 'required' },
        tools: {
          test: {
            approval: 'never',
            influence: {
              allowFrom: ['none'],
              otherwise: 'required',
              unreviewedField: true,
            },
          },
        },
        version: 1,
      }),
    ).toThrow('Invalid policy file');
  });

  it('parses every checked-in schema example through the enforcement parser', () => {
    expect(schema.examples.length).toBeGreaterThan(0);
    for (const example of schema.examples) {
      expect(parsePolicy(example)).toEqual(example);
    }
  });

  it('matches boundary and conditional semantics represented by the schema', () => {
    for (const requiredApprovals of [1, 10]) {
      expect(
        parsePolicy({
          default: { approval: 'required', approvers: { requiredApprovals } },
          version: 1,
        }).default.approvers?.requiredApprovals,
      ).toBe(requiredApprovals);
    }
    for (const invalid of [0, 11, 1.5]) {
      expect(() =>
        parsePolicy({
          default: {
            approval: 'required',
            approvers: { requiredApprovals: invalid },
          },
          version: 1,
        }),
      ).toThrow('Invalid policy file');
    }

    for (const grantTtlSeconds of [1, 86400]) {
      expect(
        parsePolicy({
          default: {
            approval: 'required',
            externalExecution: { grantTtlSeconds },
          },
          version: 1,
        }).default.externalExecution?.grantTtlSeconds,
      ).toBe(grantTtlSeconds);
    }
    for (const invalid of [0, 86401, 1.5]) {
      expect(() =>
        parsePolicy({
          default: {
            approval: 'required',
            externalExecution: { grantTtlSeconds: invalid },
          },
          version: 1,
        }),
      ).toThrow('Invalid policy file');
    }

    expect(
      parsePolicy({
        default: {
          approval: 'required',
          resultSource: { integrity: 'public_untrusted' },
          risk: 'open_world_read',
        },
        version: 1,
      }).default.resultSource,
    ).toEqual({ integrity: 'public_untrusted' });
    expect(() =>
      parsePolicy({
        default: { approval: 'required', risk: 'open_world_read' },
        version: 1,
      }),
    ).toThrow(/public_untrusted/u);
  });
});
