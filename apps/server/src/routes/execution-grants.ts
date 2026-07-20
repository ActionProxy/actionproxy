import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { ExecutionGrantService } from '../security/execution-grants';
import { requireScope } from '../security/scopes';
import { remediationDescriptorSchema } from '../services/remediation';
import { authContext, mapKnownError } from './route-utils';
import { headerValue } from './route-utils';
import { parseMcpWrapperSessionId } from '../security/influence-scope';

const consumeExecutionGrantSchema = z.object({
  input: z.record(z.unknown()),
  policyVersionHash: z.string().optional(),
  toolCallId: z.string().min(1),
  toolName: z.string().min(1),
});

const reportExecutionGrantOutcomeSchema = z.object({
  error: z.string().optional(),
  remediation: remediationDescriptorSchema.optional(),
  result: z.record(z.unknown()).optional(),
  resultDelivery: z.object({
    byteCount: z.number().int().min(0).max(16 * 1024 * 1024),
    canonicalResultHash: z.string().regex(/^[a-f0-9]{64}$/u),
    modelVisible: z.boolean(),
    version: z.literal('actionproxy.result-delivery.v1'),
  }).strict().optional(),
  status: z.enum(['cancelled', 'failed', 'succeeded', 'timed_out', 'unknown_outcome']),
});

export async function registerExecutionGrantRoutes(
  app: FastifyInstance,
  executionGrants: ExecutionGrantService,
): Promise<void> {
  app.post('/v1/execution-grants/:id/consume', async (request, reply) => {
    const auth = requireScope(authContext(request), 'execution_grant:consume');
    const params = z.object({ id: z.string().min(1) }).parse(request.params);
    const parsed = consumeExecutionGrantSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const wrapperSessionId = optionalWrapperSessionId(request.headers['x-actionproxy-mcp-session-id']);
      if (wrapperSessionId === null) {
        return reply.status(400).send({ error: 'invalid_request', message: 'Invalid X-ActionProxy-MCP-Session-Id UUID.' });
      }
      const grant = await executionGrants.consumeGrant(params.id, parsed.data, auth, { wrapperSessionId });
      return {
        grant: {
          consumedAt: grant.consumedAt,
          expiresAt: grant.expiresAt,
          id: grant.id,
          inputHash: grant.inputHash,
          policyVersionHash: grant.policyVersionHash,
          receiptHash: grant.receiptHash,
          receiptId: grant.receiptId,
          toolCallId: grant.toolCallId,
          toolName: grant.toolName,
        },
        ok: true,
      };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.post('/v1/execution-grants/:id/outcome', async (request, reply) => {
    const auth = requireScope(authContext(request), 'execution_grant:consume');
    const params = z.object({ id: z.string().min(1) }).parse(request.params);
    const parsed = reportExecutionGrantOutcomeSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const wrapperSessionId = optionalWrapperSessionId(request.headers['x-actionproxy-mcp-session-id']);
      if (wrapperSessionId === null) {
        return reply.status(400).send({ error: 'invalid_request', message: 'Invalid X-ActionProxy-MCP-Session-Id UUID.' });
      }
      const result = await executionGrants.reportOutcome(params.id, parsed.data, auth, { wrapperSessionId });
      return {
        grant: {
          consumedAt: result.grant.consumedAt,
          expiresAt: result.grant.expiresAt,
          id: result.grant.id,
          inputHash: result.grant.inputHash,
          policyVersionHash: result.grant.policyVersionHash,
          receiptHash: result.grant.receiptHash,
          receiptId: result.grant.receiptId,
          toolCallId: result.grant.toolCallId,
          toolName: result.grant.toolName,
        },
        ok: true,
        receipt: result.receipt,
        toolCall: result.toolCall,
      };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });
}

function optionalWrapperSessionId(value: string | string[] | undefined): string | null | undefined {
  const raw = headerValue(value);
  if (raw === undefined) return undefined;
  return parseMcpWrapperSessionId(raw) ?? null;
}
