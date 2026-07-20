import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { ActionReceiptRecord, ApprovalRecord, AuthContext, ExecutionGrantRecord, ToolCallRecord } from '../models';
import { requireScope } from '../security/scopes';
import { isModelVisibleResultWithheld, WITHHELD_MODEL_RESULT_MESSAGE } from '../security/result-visibility';
import type { Store } from '../storage/store';
import { authContext } from './route-utils';

const authorizedActionStatuses = ['all', 'completed', 'consumed', 'expired', 'failed', 'waiting'] as const;
type AuthorizedActionFilter = (typeof authorizedActionStatuses)[number];
type AuthorizedActionStatus = Exclude<AuthorizedActionFilter, 'all'>;

const authorizedActionsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(1000).default(100),
  status: z.enum(authorizedActionStatuses).default('waiting'),
});

export async function registerAuthorizedActionRoutes(app: FastifyInstance, store: Store): Promise<void> {
  app.get('/v1/authorized-actions', async (request) => {
    const auth = requireScope(authContext(request), 'tool_call:read');
    const query = authorizedActionsQuerySchema.parse(request.query);
    const grants = await store.listExecutionGrants({
      limit: query.limit,
      workspaceId: auth.scopes.includes('*') ? undefined : auth.workspaceId,
    });

    const rows = await Promise.all(
      grants.map(async (grant) => {
        if (!visibleForWorkspace(grant.workspaceId, auth)) return undefined;
        const toolCall = await store.getToolCall(grant.toolCallId);
        if (!toolCall || !visibleForWorkspace(toolCall.workspaceId, auth)) return undefined;
        const [approval, receipt] = await Promise.all([
          store.getApprovalByToolCallId(grant.toolCallId),
          grant.receiptId ? store.getActionReceipt(grant.receiptId) : store.getActionReceiptByToolCallId(grant.toolCallId),
        ]);
        const status = authorizedActionStatus(grant, receipt, toolCall);
        if (query.status !== 'all' && status !== query.status) return undefined;
        return toAuthorizedActionSummary({ approval, grant, receipt, status, toolCall });
      }),
    );

    return {
      authorizedActions: rows.filter((row): row is NonNullable<typeof row> => Boolean(row)),
    };
  });
}

function authorizedActionStatus(
  grant: ExecutionGrantRecord,
  receipt: ActionReceiptRecord | undefined,
  toolCall: ToolCallRecord,
): AuthorizedActionStatus {
  if (receipt?.outcome?.status === 'failed' || toolCall.status === 'failed') return 'failed';
  if (receipt?.outcome?.status === 'succeeded' || toolCall.status === 'executed') return 'completed';
  if (grant.consumedAt) return 'consumed';
  if (Date.parse(grant.expiresAt) <= Date.now()) return 'expired';
  return 'waiting';
}

function toAuthorizedActionSummary(input: {
  approval?: ApprovalRecord;
  grant: ExecutionGrantRecord;
  receipt?: ActionReceiptRecord;
  status: AuthorizedActionStatus;
  toolCall: ToolCallRecord;
}) {
  const withholdModelResult = isModelVisibleResultWithheld(input.toolCall);
  return {
    approval: input.approval
      ? {
          approvedBy: input.approval.approvedBy,
          createdAt: input.approval.createdAt,
          id: input.approval.id,
          rejectedBy: input.approval.rejectedBy,
          status: input.approval.status,
          toolCallId: input.approval.toolCallId,
          updatedAt: input.approval.updatedAt,
        }
      : undefined,
    grant: {
      approvedEnvelopeHash: input.grant.approvedEnvelopeHash,
      approvedInputHash: input.grant.approvedInputHash,
      consumedAt: input.grant.consumedAt,
      createdAt: input.grant.createdAt,
      expiresAt: input.grant.expiresAt,
      id: input.grant.id,
      inputHash: input.grant.inputHash,
      policyVersionHash: input.grant.policyVersionHash,
      receiptHash: input.grant.receiptHash,
      receiptId: input.grant.receiptId,
      toolCallId: input.grant.toolCallId,
      toolName: input.grant.toolName,
    },
    receipt: input.receipt
      ? {
          approvedEnvelopeHash: input.receipt.approvedEnvelopeHash,
          approvedInputHash: input.receipt.approvedInputHash,
          decisionActor: input.receipt.decisionActor,
          decisionKind: input.receipt.decisionKind,
          id: input.receipt.id,
          issuedAt: input.receipt.issuedAt,
          originalEnvelopeHash: input.receipt.originalEnvelopeHash,
          originalInputHash: input.receipt.originalInputHash,
          outcome: input.receipt.outcome
            ? {
                error: input.toolCall.resultWithheld && input.receipt.outcome.error
                  ? WITHHELD_MODEL_RESULT_MESSAGE
                  : input.receipt.outcome.error,
                recordedAt: input.receipt.outcome.recordedAt,
                recordedBy: input.receipt.outcome.recordedBy,
                result: input.toolCall.resultWithheld ? undefined : input.receipt.outcome.result,
                status: input.receipt.outcome.status,
              }
            : undefined,
          policyVersionHash: input.receipt.policyVersionHash,
          receiptHash: input.receipt.receiptHash,
          reviewHash: input.receipt.reviewHash,
          toolCallId: input.receipt.toolCallId,
          toolName: input.receipt.toolName,
          version: input.receipt.version,
      }
      : undefined,
    status: input.status,
    toolCall: {
      actionEnvelopeHash: input.toolCall.actionEnvelopeHash,
      agentId: input.toolCall.agentId,
      createdAt: input.toolCall.createdAt,
      decision: input.toolCall.decision,
      error: withholdModelResult ? WITHHELD_MODEL_RESULT_MESSAGE : input.toolCall.error,
      id: input.toolCall.id,
      inputHash: input.toolCall.inputHash,
      policyReason: input.toolCall.policyReason,
      policyVersionHash: input.toolCall.policyVersionHash,
      requestedBy: input.toolCall.requestedBy,
      risk: input.toolCall.risk,
      status: input.toolCall.status,
      toolName: input.toolCall.toolName,
      updatedAt: input.toolCall.updatedAt,
    },
  };
}

function visibleForWorkspace(workspaceId: string | undefined, auth: AuthContext): boolean {
  return !workspaceId || workspaceId === auth.workspaceId || auth.scopes.includes('*');
}
