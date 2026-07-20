import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { z } from 'zod';
import { contentIntegrityValues, type PolicyFile } from './policy-types';

const influenceSourceValues = ['none', ...contentIntegrityValues] as const;

const resultSourceSchema = z.union([
  z.literal('none'),
  z.object({
    integrity: z.enum(contentIntegrityValues),
    sourceId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u).optional(),
  }).strict(),
]);

const influenceSchema = z.object({
  allowFrom: z.array(z.enum(influenceSourceValues)).min(1).max(influenceSourceValues.length)
    .refine((values) => new Set(values).size === values.length, 'influence.allowFrom values must be unique.'),
  otherwise: z.enum(['required', 'deny']),
}).strict();

const ruleSchema = z.object({
  approval: z.enum(['never', 'required', 'deny']),
  approvers: z
    .object({
      groups: z.array(z.string().min(1)).optional(),
      users: z.array(z.string().min(1)).optional(),
      requiredApprovals: z.number().int().min(1).max(10).optional(),
      separationOfDuties: z.boolean().optional(),
    })
    .optional(),
  conditions: z.record(z.unknown()).optional(),
  externalExecution: z
    .object({
      grantTtlSeconds: z.number().int().min(1).max(86_400).optional(),
      requireGrantConsumption: z.boolean().optional(),
    })
    .optional(),
  influence: influenceSchema.optional(),
  notify: z
    .object({
      channels: z.array(z.string().min(1)).optional(),
    })
    .optional(),
  redaction: z
    .object({
      fields: z.array(z.string().min(1)).optional(),
      replacement: z.string().optional(),
    })
    .optional(),
  resultSource: resultSourceSchema.optional(),
  risk: z.string().optional(),
  reason: z.string().optional(),
}).superRefine((rule, context) => {
  if (
    rule.risk === 'open_world_read' &&
    (rule.resultSource === undefined ||
      rule.resultSource === 'none' ||
      rule.resultSource.integrity !== 'public_untrusted')
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'risk open_world_read requires resultSource.integrity public_untrusted.',
      path: ['resultSource'],
    });
  }
});

const policySchema = z.object({
  version: z.number(),
  default: ruleSchema,
  tools: z.record(ruleSchema).default({}),
});

export function loadPolicy(policyPath: string): PolicyFile {
  if (!fs.existsSync(policyPath)) {
    throw new Error(`Policy file not found: ${policyPath}`);
  }

  const raw = fs.readFileSync(policyPath, 'utf8');
  const parsed = YAML.parse(raw);
  return parsePolicy(parsed);
}

export function parsePolicy(parsed: unknown): PolicyFile {
  const result = policySchema.safeParse(parsed);

  if (!result.success) {
    throw new Error(`Invalid policy file: ${result.error.message}`);
  }

  return result.data;
}

export function writePolicy(policyPath: string, policy: PolicyFile): PolicyFile {
  const parsed = parsePolicy(policy);
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, YAML.stringify(parsed), 'utf8');
  return parsed;
}
