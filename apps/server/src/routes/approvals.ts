import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { ActionProxyService } from '../services/action-gate';
import type { ActionEnvelope, ApprovalDecisionRecord, ApprovalDeliveryRecord, ApprovalRecord, ToolCallRecord } from '../models';
import { redactJsonObject, redactJsonObjectAtPath, type RedactionOptions } from '../security/redaction';
import { requireScope } from '../security/scopes';
import { isModelVisibleResultWithheld, WITHHELD_MODEL_RESULT_MESSAGE } from '../security/result-visibility';
import { authContext, mapKnownError } from './route-utils';

const approvalSlaMs = 4 * 60 * 60 * 1000;

const approveSchema = z.object({
  approvalNonce: z.string().min(1).optional(),
  approvedBy: z.string().min(1).optional(),
  note: z.string().optional(),
  reviewHash: z.string().min(1).optional(),
  inputDecision: z
    .discriminatedUnion('mode', [
      z.object({ mode: z.literal('original') }),
      z.object({ mode: z.literal('edited'), input: z.record(z.unknown()) }),
    ])
    .optional(),
  editedInput: z.record(z.unknown()).nullable().optional(),
});

const rejectSchema = z.object({
  approvalNonce: z.string().min(1).optional(),
  rejectedBy: z.string().min(1).optional(),
  reason: z.string().optional(),
});

const cancelSchema = z.object({
  approvalNonce: z.string().min(1).optional(),
  cancelledBy: z.string().min(1).optional(),
  reason: z.string().optional(),
});

export async function registerApprovalRoutes(
  app: FastifyInstance,
  actionProxy: ActionProxyService,
  redaction: RedactionOptions = {},
): Promise<void> {
  app.get('/v1/approvals/pending', async (request) => {
    const auth = requireScope(authContext(request), 'approval:read');
    const approvals = await actionProxy.listPendingApprovals(auth);
    return {
      approvals: await Promise.all(
        approvals.map(async (approval) => {
          const [deliveries, toolCall] = await Promise.all([
            actionProxy.listApprovalDeliveries(approval.id, auth),
            actionProxy.getToolCall(approval.toolCallId, auth),
          ]);
          return {
            ...redactApproval(approval, redaction),
            deliveries,
            operations: approvalOperations(approval, toolCall, deliveries),
          };
        }),
      ),
    };
  });

  app.get('/v1/approvals/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'approval:read');
    const params = z.object({ id: z.string() }).parse(request.params);
    try {
      const approval = await actionProxy.getApproval(params.id, auth);
      const [deliveries, toolCall] = await Promise.all([
        actionProxy.listApprovalDeliveries(approval.id, auth),
        actionProxy.getToolCall(approval.toolCallId, auth),
      ]);
      return {
        approval: {
          ...redactApproval(approval, redaction),
          deliveries,
          operations: approvalOperations(approval, toolCall, deliveries),
        },
        toolCall: redactToolCall(toolCall, redaction),
      };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.get('/v1/approvals/:id/review', async (request, reply) => {
    const auth = requireScope(authContext(request), 'approval:read');
    const params = z.object({ id: z.string() }).parse(request.params);
    try {
      const review = await actionProxy.getApprovalReview(params.id, auth);
      return {
        ...review,
        actionEnvelope: {
          ...review.actionEnvelope,
          input: redactJsonObjectAtPath(review.actionEnvelope.input, 'input', redaction),
        },
        approval: redactApproval(review.approval, redaction),
        toolCall: redactToolCall(review.toolCall, redaction),
      };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.post('/v1/approvals/:id/approve', async (request, reply) => {
    const auth = requireScope(authContext(request), 'approval:approve');
    const params = z.object({ id: z.string() }).parse(request.params);
    const parsed = approveSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const result = await actionProxy.approveApproval(params.id, parsed.data, auth);
      return { approval: redactApproval(result.approval, redaction), toolCall: redactToolCall(result.toolCall, redaction) };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.post('/v1/approvals/:id/reject', async (request, reply) => {
    const auth = requireScope(authContext(request), 'approval:reject');
    const params = z.object({ id: z.string() }).parse(request.params);
    const parsed = rejectSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const result = await actionProxy.rejectApproval(params.id, parsed.data, auth);
      return { approval: redactApproval(result.approval, redaction), toolCall: redactToolCall(result.toolCall, redaction) };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.post('/v1/approvals/:id/cancel', async (request, reply) => {
    const auth = requireScope(authContext(request), 'approval:reject');
    const params = z.object({ id: z.string() }).parse(request.params);
    const parsed = cancelSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const result = await actionProxy.cancelApproval(params.id, parsed.data, auth);
      return { approval: redactApproval(result.approval, redaction), toolCall: redactToolCall(result.toolCall, redaction) };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.post('/v1/approvals/:id/notifications/resend', async (request, reply) => {
    const auth = requireScope(authContext(request), 'approval:approve');
    const params = z.object({ id: z.string() }).parse(request.params);

    try {
      const deliveries = await actionProxy.resendApprovalNotifications(params.id, auth);
      return { deliveries, ok: true };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });
}

function redactApproval<T extends {
  decisions?: ApprovalDecisionRecord[];
  editedInput?: Record<string, unknown>;
  originalInput: Record<string, unknown>;
}>(
  approval: T,
  redaction: RedactionOptions,
): T {
  return {
    ...approval,
    decisions: Array.isArray(approval.decisions)
      ? approval.decisions.map((decision) => ({
          ...decision,
          editedInput: decision.editedInput
            ? redactJsonObjectAtPath(decision.editedInput, 'input', redaction)
            : decision.editedInput,
        }))
      : undefined,
    editedInput: approval.editedInput
      ? redactJsonObjectAtPath(approval.editedInput, 'input', redaction)
      : approval.editedInput,
    originalInput: redactJsonObjectAtPath(approval.originalInput, 'input', redaction),
  };
}

function redactToolCall<T extends ToolCallRecord>(
  toolCall: T,
  redaction: RedactionOptions,
): T {
  const withholdModelResult = isModelVisibleResultWithheld(toolCall);
  return {
    ...toolCall,
    actionEnvelope: toolCall.actionEnvelope
      ? {
          ...toolCall.actionEnvelope,
          input: redactJsonObjectAtPath(toolCall.actionEnvelope.input, 'input', redaction),
        }
      : undefined,
    input: redactJsonObjectAtPath(toolCall.input, 'input', redaction),
    metadata: redactJsonObject(toolCall.metadata, redaction),
    error: withholdModelResult ? WITHHELD_MODEL_RESULT_MESSAGE : toolCall.error,
    result: withholdModelResult
      ? undefined
      : isJsonObject(toolCall.result)
        ? redactJsonObject(toolCall.result, redaction)
        : toolCall.result,
  };
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function approvalOperations(
  approval: ApprovalRecord,
  toolCall: ToolCallRecord,
  deliveries: ApprovalDeliveryRecord[],
) {
  const now = Date.now();
  const created = new Date(approval.createdAt).getTime();
  const ageMs = Math.max(0, now - created);
  const failedDeliveries = deliveries.filter((delivery) => delivery.status === 'failed').length;
  const sentDeliveries = deliveries.filter((delivery) => delivery.status === 'sent').length;
  const dueAt = new Date(created + approvalSlaMs).toISOString();
  return {
    action: {
      app: appNameForToolCall(toolCall),
      customerVisible:
        toolCall.metadata.customerVisible === true ||
        toolCall.metadata.operationKind === 'external_send' ||
        toolCall.toolName.endsWith('.send_email'),
      operationKind: typeof toolCall.metadata.operationKind === 'string' ? toolCall.metadata.operationKind : undefined,
      recipient: recipientForToolCall(toolCall),
      risk: toolCall.risk ?? 'unknown',
      toolName: toolCall.toolName,
    },
    deliveries: {
      failed: failedDeliveries,
      sent: sentDeliveries,
      status: failedDeliveries > 0 && sentDeliveries === 0 ? 'failed' : sentDeliveries > 0 ? 'sent' : 'not_sent',
    },
    escalation: {
      recommended: approval.status === 'pending' && ageMs > approvalSlaMs,
      reason: ageMs > approvalSlaMs ? 'Approval is past the 4 hour operational SLA.' : undefined,
    },
    reminder: {
      available: approval.status === 'pending',
      suggestedAction: failedDeliveries > 0 || ageMs > approvalSlaMs / 2 ? 'resend' : 'wait',
    },
    sla: {
      ageMs,
      dueAt,
      status: ageMs > approvalSlaMs ? 'breached' : ageMs > approvalSlaMs / 2 ? 'at_risk' : 'on_track',
      targetMs: approvalSlaMs,
    },
  };
}

function appNameForToolCall(toolCall: ToolCallRecord): string {
  return toolCall.toolName.split('.')[0] ?? toolCall.toolName;
}

function recipientForToolCall(toolCall: ToolCallRecord): string | undefined {
  if (typeof toolCall.input.to === 'string') return toolCall.input.to;
  if (typeof toolCall.input.ticketId === 'string') return `Ticket ${toolCall.input.ticketId}`;
  if (typeof toolCall.input.channel === 'string') return toolCall.input.channel;
  if (typeof toolCall.input.customerId === 'string') return toolCall.input.customerId;
  return undefined;
}
