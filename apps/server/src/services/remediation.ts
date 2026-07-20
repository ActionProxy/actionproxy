import { z } from 'zod';
import type { JsonObject, RemediationDescriptor, ToolCallRecord } from '../models';

const remediationKindSchema = z.enum(['compensating_action', 'exact_revert', 'not_reversible', 'soft_revert']);
const remediationStatusSchema = z.enum(['available', 'unavailable']);

const remediationActionSchema = z
  .object({
    context: z.record(z.unknown()).optional(),
    executionMode: z.enum(['external_grant', 'local_mock']).optional(),
    operation: z
      .object({
        kind: z.enum(['custom', 'delete', 'external_send', 'financial', 'read', 'write']).optional(),
        name: z.string().min(1).optional(),
      })
      .optional(),
    protocol: z
      .enum([
        'actionproxy_http',
        'cli',
        'custom',
        'langgraph',
        'mcp',
        'n8n',
        'openai_tools',
        'webhook',
      ])
      .optional(),
    resources: z
      .array(
        z.object({
          id: z.string().optional(),
          metadata: z.record(z.unknown()).optional(),
          name: z.string().optional(),
          type: z.string().min(1),
          url: z.string().optional(),
        }),
      )
      .optional(),
    source: z
      .object({
        id: z.string().optional(),
        metadata: z.record(z.unknown()).optional(),
        name: z.string().optional(),
        type: z.string().min(1).optional(),
      })
      .optional(),
  })
  .optional();

export const remediationDescriptorSchema = z
  .object({
    action: remediationActionSchema,
    evidence: z.record(z.unknown()).optional(),
    input: z.record(z.unknown()).optional(),
    kind: remediationKindSchema,
    metadata: z.record(z.unknown()).optional(),
    reason: z.string().min(1),
    status: remediationStatusSchema,
    toolName: z.string().min(1).optional(),
  })
  .superRefine((value, context) => {
    if (value.status === 'available' && !value.toolName) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Available remediation requires toolName.',
        path: ['toolName'],
      });
    }

    if (value.status === 'available' && value.input === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Available remediation requires input.',
        path: ['input'],
      });
    }
  });

export function parseRemediationDescriptor(value: unknown): RemediationDescriptor {
  return remediationDescriptorSchema.parse(value) as RemediationDescriptor;
}

export function remediationFromToolResult(result: unknown): RemediationDescriptor | undefined {
  const productMetadata = productMetadataFrom(result);
  if (!productMetadata || productMetadata.remediation === undefined) return undefined;
  const parsed = remediationDescriptorSchema.safeParse(productMetadata.remediation);
  return parsed.success ? (parsed.data as RemediationDescriptor) : undefined;
}

export function unavailableRemediation(reason: string, kind: RemediationDescriptor['kind'] = 'not_reversible'): RemediationDescriptor {
  return {
    kind,
    reason,
    status: 'unavailable',
  };
}

export function metadataWithRemediationLink(input: {
  baseMetadata?: JsonObject;
  kind: RemediationDescriptor['kind'];
  originalReceiptHash?: string;
  originalReceiptId?: string;
  originalToolCallId: string;
}): JsonObject {
  const baseMetadata = input.baseMetadata ?? {};
  const existingActionProxy = isJsonObject(baseMetadata.actionproxy) ? baseMetadata.actionproxy : {};
  return {
    ...baseMetadata,
    actionproxy: {
      ...existingActionProxy,
      remediation: {
        kind: input.kind,
        originalReceiptHash: input.originalReceiptHash,
        originalReceiptId: input.originalReceiptId,
        originalToolCallId: input.originalToolCallId,
      },
    },
  };
}

export function isRemediationForToolCall(toolCall: ToolCallRecord, originalToolCallId: string): boolean {
  const remediation = productMetadataFrom(toolCall.metadata)?.remediation;
  return isJsonObject(remediation) && remediation.originalToolCallId === originalToolCallId;
}

function productMetadataFrom(value: unknown): JsonObject | undefined {
  if (!isJsonObject(value)) return undefined;
  if (isJsonObject(value.actionproxy)) return value.actionproxy;
  return undefined;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
