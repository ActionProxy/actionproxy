import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { NotFoundError } from '../errors';
import type { Store } from '../storage/store';
import { requireScope } from '../security/scopes';
import { authContext, mapKnownError } from './route-utils';
import { WITHHELD_MODEL_RESULT_MESSAGE } from '../security/result-visibility';

export async function registerReceiptRoutes(app: FastifyInstance, store: Store): Promise<void> {
  app.get('/v1/receipts/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'audit:read');
    const params = z.object({ id: z.string().min(1) }).parse(request.params);

    try {
      const receipt = await store.getActionReceipt(params.id);
      if (!receipt) throw new NotFoundError(`Receipt not found: ${params.id}`);
      if (receipt.workspaceId !== auth.workspaceId && !auth.scopes.includes('*')) {
        return reply.status(403).send({ error: 'forbidden', message: 'Receipt is not in this workspace.' });
      }
      const toolCall = await store.getToolCall(receipt.toolCallId);
      const projectedReceipt = toolCall?.resultWithheld && receipt.outcome
        ? {
            ...receipt,
            outcome: {
              ...receipt.outcome,
              error: receipt.outcome.error ? WITHHELD_MODEL_RESULT_MESSAGE : undefined,
              result: undefined,
            },
          }
        : receipt;
      return { receipt: projectedReceipt };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });
}
