import { Readable } from 'node:stream';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { ActionProxyService } from '../services/action-gate';
import type { ActionEnvelope, ActionReceiptRecord, PolicyDecision, RemediationDescriptor, RemediationPlan, ToolCallRecord, ToolCallStatus } from '../models';
import {
  redactJsonObject,
  redactJsonObjectAtPath,
  redactReceiptSignature,
  redactToolCallResult,
  type RedactionOptions,
} from '../security/redaction';
import { requireScope } from '../security/scopes';
import { authContext, headerValue, mapKnownError } from './route-utils';
import { assertNoDuplicateJsonKeys, DuplicateJsonKeyError } from '../contracts/action-request';
import { sha256Hex } from '../security/crypto';
import { deriveInfluenceScopeId, parseMcpWrapperSessionId } from '../security/influence-scope';
import { isModelVisibleResultWithheld, WITHHELD_MODEL_RESULT_MESSAGE } from '../security/result-visibility';

const submitToolCallSchema = z.object({
  toolName: z.string().min(1),
  input: z.record(z.unknown()),
  requestedBy: z.string().min(1).default('authenticated-principal'),
  agentId: z.string().min(1),
  reason: z.string().min(1),
  action: z
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
    .optional(),
  metadata: z.record(z.unknown()).optional(),
}).strict();

const listToolCallsQuerySchema = z.object({
  decision: z.enum(['allow', 'require_approval', 'deny']).optional(),
  limit: z.coerce.number().int().min(1).max(1000).optional(),
  runId: z.string().min(1).optional(),
  sessionId: z.string().min(1).optional(),
  status: z.enum(['submitted', 'authorized', 'executed', 'pending_approval', 'blocked', 'rejected', 'failed']).optional(),
  toolName: z.string().min(1).optional(),
});

const submitRemediationSchema = z.object({
  agentId: z.string().min(1).optional(),
  input: z.record(z.unknown()).optional(),
  metadata: z.record(z.unknown()).optional(),
  reason: z.string().min(1).optional(),
  requestedBy: z.string().min(1).optional(),
});

export async function registerToolCallRoutes(
  app: FastifyInstance,
  actionProxy: ActionProxyService,
  redaction: RedactionOptions = {},
  options: { environment?: 'local' | 'self_hosted' } = {},
): Promise<void> {
  app.get('/v1/tool-calls', async (request) => {
    const auth = requireScope(authContext(request), 'tool_call:read');
    const query = listToolCallsQuerySchema.parse(request.query);
    const toolCalls = await actionProxy.listToolCalls({
      decision: query.decision as PolicyDecision | undefined,
      limit: query.limit ?? 100,
      runId: query.runId,
      sessionId: query.sessionId,
      status: query.status as ToolCallStatus | undefined,
      toolName: query.toolName,
    }, auth);
    return { toolCalls: toolCalls.map((toolCall) => redactToolCall(toolCall, redaction)) };
  });

  app.post('/v1/tool-calls', { preParsing: rejectAmbiguousJson }, async (request, reply) => {
    const auth = requireScope(authContext(request), 'tool_call:submit');
    const parsed = submitToolCallSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const result = await actionProxy.submitToolCall(parsed.data, {
        auth,
        idempotencyKey: headerValue(request.headers['idempotency-key']),
        ingress: {
          environment: options.environment ?? 'local',
          protocol: 'actionproxy_http',
          source: 'http',
        },
      });
      return toToolCallResponse(result, redaction);
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  // Authenticated stdio MCP wrappers enter the same authoritative lifecycle through
  // a server-owned adapter. Body hints remain assertions and cannot mint MCP
  // protocol, actor, tenant, agent verification, environment, or idempotency state.
  app.post('/v1/mcp/tool-calls', { preParsing: rejectAmbiguousJson }, async (request, reply) => {
    const auth = requireScope(authContext(request), 'tool_call:submit');
    const parsed = submitToolCallSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }
    const transportRequestId = headerValue(request.headers['idempotency-key']);
    if (!isHeaderSafeTransportRequestId(transportRequestId)) {
      return reply.status(400).send({
        error: 'invalid_request',
        message: 'Authenticated MCP submissions require a non-empty, header-safe Idempotency-Key of at most 512 bytes.',
      });
    }
    const wrapperSessionId = parseMcpWrapperSessionId(
      headerValue(request.headers['x-actionproxy-mcp-session-id']),
    );
    if (!wrapperSessionId) {
      return reply.status(400).send({
        error: 'invalid_request',
        message: 'Authenticated MCP submissions require a canonical X-ActionProxy-MCP-Session-Id UUID.',
      });
    }

    const adapterId = `mcp-stdio:${auth.clientId ?? auth.principalId}`;
    const influenceScopeId = deriveInfluenceScopeId({
      adapterId,
      principalId: auth.principalId,
      protocol: 'mcp',
      transport: 'stdio',
      transportSessionId: wrapperSessionId,
      workspaceId: auth.workspaceId,
    });
    const idempotencyKey = `mcp-stdio-v1:${sha256Hex(`${influenceScopeId}\u0000${transportRequestId}`)}`;
    const adaptedRequest = {
      ...parsed.data,
      action: {
        context: parsed.data.action?.context,
        executionMode: 'external_grant' as const,
        operation: { name: parsed.data.toolName },
        protocol: 'mcp' as const,
        resources: [{ name: parsed.data.toolName, type: 'mcp.tool' }],
        source: { id: adapterId, name: 'ActionProxy stdio MCP adapter', type: 'mcp' },
      },
      agentId: `mcp:${auth.clientId ?? auth.principalId}`,
      metadata: {
        ...(parsed.data.metadata ?? {}),
        actionproxyExecution: 'external',
        actionproxyMcp: { adapterId, transport: 'stdio' },
      },
      requestedBy: auth.email ?? auth.principalId,
    };

    try {
      const result = await actionProxy.submitToolCall(adaptedRequest, {
        auth,
        idempotencyKey,
        ingress: {
          adapterId,
          adapterSource: 'auth.principal+mcp-stdio-adapter',
          adapterTrust: 'derived',
          agent: {
            id: adaptedRequest.agentId,
            name: 'Authenticated stdio MCP adapter',
            source: 'auth.principal+mcp-stdio-adapter',
            trust: 'derived',
          },
          environment: options.environment ?? 'local',
          idempotency: { source: 'mcp.authenticated-adapter+jsonrpc-id', trust: 'derived' },
          protocol: 'mcp',
          session: {
            sessionId: influenceScopeId,
            source: 'actionproxy.verified-mcp-influence-scope',
            trust: 'derived',
          },
          source: 'mcp',
        },
      });
      return toToolCallResponse(result, redaction);
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.get('/v1/mcp/tool-calls/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'tool_call:read');
    const params = z.object({ id: z.string().min(1) }).parse(request.params);
    const wrapperSessionId = parseMcpWrapperSessionId(
      headerValue(request.headers['x-actionproxy-mcp-session-id']),
    );
    if (!wrapperSessionId) {
      return reply.status(400).send({
        error: 'invalid_request',
        message: 'Authenticated MCP status reads require a canonical X-ActionProxy-MCP-Session-Id UUID.',
      });
    }
    try {
      const toolCall = await actionProxy.getToolCall(params.id, auth);
      const adapterId = `mcp-stdio:${auth.clientId ?? auth.principalId}`;
      const influenceScopeId = deriveInfluenceScopeId({
        adapterId,
        principalId: auth.principalId,
        protocol: 'mcp',
        transport: 'stdio',
        transportSessionId: wrapperSessionId,
        workspaceId: auth.workspaceId,
      });
      const canonicalSource = canonicalMcpSource(toolCall.decisionTrace);
      const originating = toolCall.requestedByAuth;
      const samePrincipal = originating?.principalId === auth.principalId;
      const sameClient = !originating?.clientId || originating.clientId === auth.clientId;
      if (
        canonicalSource?.type !== 'mcp' ||
        canonicalSource.adapterId !== adapterId ||
        toolCall.influenceScopeId !== influenceScopeId ||
        !canonicalMcpSessionMatches(toolCall, adapterId, influenceScopeId) ||
        !samePrincipal ||
        !sameClient
      ) {
        return reply.status(403).send({ error: 'forbidden', message: 'MCP action belongs to another authenticated adapter.' });
      }
      return redactToolCall(toolCall, redaction);
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.get('/v1/tool-calls/:id/execution-attempts', async (request, reply) => {
    const auth = requireScope(authContext(request), 'tool_call:read');
    const params = z.object({ id: z.string().min(1) }).parse(request.params);
    try {
      return { attempts: await actionProxy.listExecutionAttemptsForToolCall(params.id, auth) };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.get('/v1/tool-calls/:id/remediation-plan', async (request, reply) => {
    const auth = requireScope(authContext(request), 'tool_call:read');
    const params = z.object({ id: z.string().min(1) }).parse(request.params);
    try {
      return redactRemediationPlan(await actionProxy.getRemediationPlan(params.id, auth), redaction);
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.get('/v1/tool-calls/:id/decision-trace', async (request, reply) => {
    const auth = requireScope(authContext(request), 'tool_call:read');
    const params = z.object({ id: z.string().min(1) }).parse(request.params);
    try {
      return await actionProxy.getDecisionTrace(params.id, auth);
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.post('/v1/tool-calls/:id/remediation', async (request, reply) => {
    const auth = requireScope(authContext(request), 'tool_call:submit');
    const params = z.object({ id: z.string().min(1) }).parse(request.params);
    const parsed = submitRemediationSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const result = await actionProxy.submitRemediation(params.id, parsed.data, {
        auth,
        idempotencyKey: headerValue(request.headers['idempotency-key']),
      });
      return {
        ...toToolCallResponse(result, redaction),
        plan: redactRemediationPlan(result.plan, redaction),
      };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.get('/v1/tool-calls/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'tool_call:read');
    const params = z.object({ id: z.string() }).parse(request.params);
    try {
      return redactToolCall(await actionProxy.getToolCall(params.id, auth), redaction);
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });
}

export async function rejectAmbiguousJson(request: { headers: Record<string, unknown> }, _reply: unknown, payload: AsyncIterable<unknown>) {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of payload) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    length += buffer.byteLength;
    if (length > 1024 * 1024) throw httpBodyError(413, 'Request body is too large.');
    chunks.push(buffer);
  }
  const body = Buffer.concat(chunks);
  const contentType = String(request.headers['content-type'] ?? '').toLowerCase();
  if (contentType.includes('application/json')) {
    try {
      assertNoDuplicateJsonKeys(body.toString('utf8'));
    } catch (error) {
      if (error instanceof DuplicateJsonKeyError) throw httpBodyError(400, error.message);
      // Fastify's JSON parser remains authoritative for ordinary syntax errors.
    }
  }
  const replacement = Readable.from([body]) as Readable & { receivedEncodedLength?: number };
  replacement.receivedEncodedLength = body.byteLength;
  return replacement;
}

function isHeaderSafeTransportRequestId(value: string | undefined): value is string {
  return Boolean(
    value &&
    value.trim() === value &&
    Buffer.byteLength(value, 'utf8') <= 512 &&
    !/[\u0000-\u001f\u007f]/u.test(value),
  );
}

function httpBodyError(statusCode: number, message: string): Error {
  return Object.assign(new Error(message), { statusCode });
}

function toToolCallResponse(result: Awaited<ReturnType<ActionProxyService['submitToolCall']>>, redaction: RedactionOptions) {
  const toolCall = redactToolCall(result.toolCall, redaction);
  return {
    id: toolCall.id,
    status: toolCall.status,
    decision: toolCall.authorizationDecision ?? toolCall.decision,
    reason: toolCall.authorizationReason ?? toolCall.policyReason,
    risk: toolCall.risk,
    result: toolCall.result,
    error: toolCall.error,
    approval: result.approval
      ? {
          id: result.approval.id,
          status: result.approval.status,
        }
      : undefined,
    toolCall,
  };
}

function redactToolCall<T extends ToolCallRecord>(
  toolCall: T,
  redaction: RedactionOptions,
): T {
  const withholdModelResult = isModelVisibleResultWithheld(toolCall);
  return {
    ...toolCall,
    actionEnvelope: redactActionEnvelope(toolCall, redaction),
    input: redactJsonObjectAtPath(toolCall.input, 'input', redaction),
    metadata: redactJsonObject(toolCall.metadata, redaction),
    error: withholdModelResult ? WITHHELD_MODEL_RESULT_MESSAGE : toolCall.error,
    result: withholdModelResult
      ? undefined
      : isJsonObject(toolCall.result)
        ? redactToolCallResult(toolCall.result, redaction)
        : toolCall.result,
  };
}

function redactActionEnvelope(
  toolCall: { actionEnvelope?: { input: Record<string, unknown> } },
  redaction: RedactionOptions,
) {
  if (!toolCall.actionEnvelope) return undefined;
  return {
    ...toolCall.actionEnvelope,
    input: redactJsonObjectAtPath(toolCall.actionEnvelope.input, 'input', redaction),
  };
}

function redactRemediationPlan(plan: RemediationPlan, redaction: RedactionOptions): RemediationPlan {
  return {
    ...plan,
    originalToolCall: redactToolCall(plan.originalToolCall, redaction),
    receipt: plan.receipt ? redactReceipt(plan.receipt, redaction, plan.originalToolCall.resultWithheld) : undefined,
    relatedToolCalls: plan.relatedToolCalls.map((toolCall) => redactToolCall(toolCall, redaction)),
    remediation: redactRemediation(plan.remediation, redaction),
  };
}

function redactReceipt(
  receipt: ActionReceiptRecord,
  redaction: RedactionOptions,
  resultWithheld = false,
): ActionReceiptRecord {
  const safeReceipt = redactReceiptSignature(receipt, redaction);
  if (!receipt.outcome) return safeReceipt;
  return {
    ...safeReceipt,
    outcome: {
      ...receipt.outcome,
      error: resultWithheld && receipt.outcome.error ? WITHHELD_MODEL_RESULT_MESSAGE : receipt.outcome.error,
      remediation: receipt.outcome.remediation ? redactRemediation(receipt.outcome.remediation, redaction) : undefined,
      result: resultWithheld
        ? undefined
        : receipt.outcome.result
          ? redactJsonObject(receipt.outcome.result, redaction)
          : undefined,
    },
  };
}

function redactRemediation(remediation: RemediationDescriptor, redaction: RedactionOptions): RemediationDescriptor {
  return {
    ...remediation,
    evidence: remediation.evidence ? redactJsonObject(remediation.evidence, redaction) : undefined,
    input: remediation.input ? redactJsonObject(remediation.input, redaction) : undefined,
    metadata: remediation.metadata ? redactJsonObject(remediation.metadata, redaction) : undefined,
  };
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function canonicalMcpSource(decisionTrace: unknown): { adapterId?: string; type?: string } | undefined {
  if (!isJsonObject(decisionTrace) || !isJsonObject(decisionTrace.canonicalRequestEvidence)) return undefined;
  const sourceField = decisionTrace.canonicalRequestEvidence.source;
  if (!isJsonObject(sourceField) || !isJsonObject(sourceField.value)) return undefined;
  return {
    adapterId: typeof sourceField.value.adapterId === 'string' ? sourceField.value.adapterId : undefined,
    type: typeof sourceField.value.type === 'string' ? sourceField.value.type : undefined,
  };
}

function canonicalMcpSessionMatches(
  toolCall: ToolCallRecord,
  adapterId: string,
  influenceScopeId: string,
): boolean {
  const evidence = isJsonObject(toolCall.decisionTrace) && isJsonObject(toolCall.decisionTrace.canonicalRequestEvidence)
    ? toolCall.decisionTrace.canonicalRequestEvidence
    : undefined;
  const protocol = evidence && isJsonObject(evidence.sourceProtocol) ? evidence.sourceProtocol.value : undefined;
  const tenant = evidence && isJsonObject(evidence.tenant) && isJsonObject(evidence.tenant.value)
    ? evidence.tenant.value
    : undefined;
  const session = evidence && isJsonObject(evidence.session) ? evidence.session : undefined;
  const provenance = session && isJsonObject(session.provenance) ? session.provenance : undefined;
  const value = session && isJsonObject(session.value) ? session.value : undefined;
  return Boolean(
    protocol === 'mcp' &&
    tenant?.id === (toolCall.workspaceId ?? 'default') &&
    session?.present === true &&
    provenance?.source === 'actionproxy.verified-mcp-influence-scope' &&
    ['derived', 'externally_verified', 'trusted'].includes(String(provenance?.trust)) &&
    value?.sessionId === influenceScopeId &&
    toolCall.actionEnvelope?.protocol === 'mcp' &&
    toolCall.actionEnvelope.source.type === 'mcp' &&
    toolCall.actionEnvelope.source.id === adapterId,
  );
}
