import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { PolicyManager } from '../policy/policy-manager';
import type { ApprovalMode } from '../policy/policy-types';
import { requireScope } from '../security/scopes';
import type { PolicyDetectorService } from '../services/policy-detector';
import type { ApproverDirectoryService } from '../services/approver-directory';
import { authContext, mapKnownError } from './route-utils';
import { summarizePolicy } from './policy';

const detectorParamsSchema = z.object({ id: z.string().min(1) });
const applySchema = z.object({
  approval: z.enum(['deny', 'never', 'required']).optional(),
  pattern: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*(?:\.\*)?$/)
    .optional(),
  reason: z.string().trim().optional(),
  risk: z.string().trim().optional(),
});

export async function registerPolicyDetectorRoutes(
  app: FastifyInstance,
  detector: PolicyDetectorService,
  policyManager: PolicyManager,
  options: { approverDirectory?: ApproverDirectoryService } = {},
): Promise<void> {
  app.get('/v1/policy/detector', async (request) => {
    const auth = requireScope(authContext(request), 'policy:read');
    return detector.list(auth.workspaceId, policyManager.getPolicy());
  });

  app.post('/v1/policy/detector/:id/apply', async (request, reply) => {
    const auth = requireScope(authContext(request), 'policy:write');
    const params = detectorParamsSchema.parse(request.params);
    const parsed = applySchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const currentPolicy = policyManager.getPolicy();
      const record = await detector.get(params.id, auth.workspaceId, currentPolicy);
      const { pattern, rule } = detector.buildRule(
        record,
        {
          ...parsed.data,
          approval: parsed.data.approval as ApprovalMode | undefined,
        },
        currentPolicy,
      );
      const nextPolicy = {
        ...currentPolicy,
        tools: {
          ...currentPolicy.tools,
          [pattern]: rule,
        },
      };
      await options.approverDirectory?.validatePolicy(nextPolicy, auth.workspaceId);
      const policy = policyManager.replacePolicy(nextPolicy);
      await detector.refreshPolicyCoverage(policy, auth.workspaceId);
      const observedTool = await detector.get(params.id, auth.workspaceId, policy);
      await detector.auditPolicyApply(auth, record, pattern, rule);
      return { observedTool, policy, summary: summarizePolicy(policy) };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.post('/v1/policy/detector/:id/dismiss', async (request, reply) => {
    const auth = requireScope(authContext(request), 'policy:write');
    const params = detectorParamsSchema.parse(request.params);
    try {
      return { observedTool: await detector.dismiss(params.id, auth, policyManager.getPolicy()) };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });
}
