import { Readable } from 'node:stream';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { ResolvedAppConfig } from '../config';
import {
  assertNoDuplicateJsonKeys,
  DuplicateJsonKeyError,
  hashCanonicalJson,
  type McpActionIngress,
} from '../contracts/action-request';
import { ConflictError, ForbiddenError, McpInsufficientScopeError, NotFoundError, UnauthorizedError } from '../errors';
import type { ApprovalRecord, AuthContext, JsonObject, ToolCallRecord } from '../models';
import { redactJsonObject, type RedactionOptions } from '../security/redaction';
import {
  McpSessionAuthority,
  McpSessionError,
  type McpJsonRpcId,
  type McpSessionBinding,
} from '../security/mcp-session';
import { deriveInfluenceScopeId } from '../security/influence-scope';
import {
  assertMcpAuthenticatedPrincipal,
  presentsMcpOAuth,
  type McpRequestAuthentication,
} from '../security/http-security';
import { isModelVisibleResultWithheld, WITHHELD_MODEL_RESULT_MESSAGE } from '../security/result-visibility';
import type { ActionProxyService } from '../services/action-gate';
import type { Store } from '../storage/store';

export const MCP_PROTOCOL_VERSION = '2025-06-18' as const;

const MCP_MAX_REQUEST_BYTES = 256 * 1024;
const CORE_MCP_SCOPES = ['tool_call:read', 'tool_call:submit'] as const;
const FORBIDDEN_RESULT_KEY_FRAGMENTS = [
  'authorization',
  'bearer',
  'credential',
  'credentials',
  'executionauthorization',
  'grant',
  'nonce',
  'secret',
  'session',
  'signature',
  'token',
];
const SAFE_RESULT_KEYS_WITH_SENSITIVE_FRAGMENTS = new Set([
  'accesstokenexpiresat',
  'storedauthorizationstatus',
]);

type McpActionProxy = Pick<ActionProxyService, 'getToolCall' | 'submitToolCall'>;
type McpStore = Pick<Store, 'getApprovalByToolCallId' | 'getExecutionAttemptByToolCallId'>;

export interface McpAdditionalToolContext {
  /** Server-derived adapter id bound into the verified MCP session. */
  adapterId: string;
  /** Server-derived agent id for ActionProxy submissions from this adapter. */
  agentId: string;
  auth: AuthContext & { clientId: string };
  /** Deterministic revision of the exact MCP catalog bound into this signed session. */
  catalogRevision: string;
  /** Stable for one signed MCP session + JSON-RPC id; safe for durable replay protection. */
  idempotencyKey: string;
  /** Canonical, transport-owned MCP ingress provenance for ActionProxy submissions. */
  ingress: McpActionIngress;
  /** Server-derived ActionEnvelope source for this authenticated MCP adapter. */
  source: { id: string; name: string; type: 'mcp' };
}

export interface McpAdditionalToolResult {
  /** Keep this static and non-sensitive; structuredContent is redacted again by the transport. */
  contentText: string;
  isError?: boolean;
  structuredContent: JsonObject;
}

export interface McpAdditionalTool {
  annotations: {
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
    readOnlyHint: boolean;
  };
  description: string;
  inputSchema: JsonObject;
  invoke: (input: JsonObject, context: McpAdditionalToolContext) => Promise<McpAdditionalToolResult>;
  name: string;
  requiredScope: string;
  title: string;
}

export interface McpRetiredTool {
  refreshInstruction: string;
  replacement: string;
}

export interface McpExtensionErrorProjection {
  code: number;
  data?: JsonObject;
  message: string;
}

export interface McpRouteExtensionOptions {
  additionalTools?: readonly McpAdditionalTool[];
  /** Platform mode disables Community mock tools and supplies a reviewed catalog instead. */
  includeBuiltinTools?: boolean;
  /** Scope required to enumerate the selected catalog after MCP request authentication. */
  listToolsScope?: string;
  /** Maps only failures thrown by injected additional tools. */
  projectAdditionalToolError?: (error: unknown) => McpExtensionErrorProjection | undefined;
  /** Server-owned request authentication; omitted means Community OAuth bearer validation. */
  requestAuthentication?: McpRequestAuthentication;
  /** Known historical names that must return actionable diagnostics but never be advertised. */
  retiredTools?: Readonly<Record<string, McpRetiredTool>>;
}

export interface McpRouteOptions extends McpRouteExtensionOptions {
  actionProxy: McpActionProxy;
  config: ResolvedAppConfig;
  redaction?: RedactionOptions;
  sessionAuthority?: McpSessionAuthority;
  store: McpStore;
}

type JsonRpcId = McpJsonRpcId | null;

interface JsonRpcRequest {
  id?: McpJsonRpcId;
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
}

interface JsonRpcResponse {
  error?: { code: number; data?: JsonObject; message: string };
  id: JsonRpcId;
  jsonrpc: '2.0';
  result?: unknown;
}

interface McpToolResult {
  content: Array<{ text: string; type: 'text' }>;
  isError?: boolean;
  structuredContent: JsonObject;
}

const jsonRpcRequestSchema = z.object({
  id: z.union([z.string().min(1).max(512), z.number().int().safe()]).optional(),
  jsonrpc: z.literal('2.0'),
  method: z.string().min(1).max(256),
  params: z.unknown().optional(),
}).strict();

const initializeParamsSchema = z.object({
  capabilities: z.record(z.unknown()),
  clientInfo: z.object({
    name: z.string().min(1).max(256),
    title: z.string().min(1).max(256).optional(),
    version: z.string().min(1).max(128),
  }).passthrough(),
  protocolVersion: z.string().min(1).max(64),
}).strict();

const listToolsParamsSchema = z.object({ cursor: z.string().max(1024).optional() }).strict();

const callToolParamsSchema = z.object({
  _meta: z.record(z.unknown()).optional(),
  arguments: z.record(z.unknown()).optional(),
  name: z.string().min(1).max(256),
}).strict();

const docsSearchInputSchema = z.object({ query: z.string().min(1).max(16_384) }).strict();
const sendEmailInputSchema = z.object({
  body: z.string().min(1).max(128 * 1024),
  subject: z.string().min(1).max(4096),
  to: z.string().min(1).max(4096),
}).strict();
const deleteCustomerInputSchema = z.object({
  customerId: z.string().min(1).max(4096),
  reason: z.string().min(1).max(16_384),
}).strict();
const statusInputSchema = z.object({ toolCallId: z.string().min(1).max(512) }).strict();

export async function registerMcpRoutes(app: FastifyInstance, options: McpRouteOptions): Promise<void> {
  const transport = options.config.mcp.streamableHttp;
  const sessionAuthority = options.sessionAuthority ?? createSessionAuthority(options.config);
  const additionalTools = validateAdditionalTools(options.additionalTools ?? [], options.includeBuiltinTools !== false);
  const catalogRevision = mcpCatalogRevision(options.includeBuiltinTools !== false, [...additionalTools.values()]);
  const retiredTools = validateRetiredTools(options.retiredTools ?? {}, additionalTools, options.includeBuiltinTools !== false);

  app.get('/.well-known/oauth-protected-resource', async (_request, reply) => {
    if (!transport.enabled) return disabled(reply);
    if (!presentsMcpOAuth(options.requestAuthentication)) return oauthMetadataDisabled(reply);
    return reply
      .header('cache-control', 'public, max-age=300')
      .send(protectedResourceMetadata(options.config, options, additionalTools));
  });

  app.get('/.well-known/oauth-protected-resource/mcp', async (_request, reply) => {
    if (!transport.enabled) return disabled(reply);
    if (!presentsMcpOAuth(options.requestAuthentication)) return oauthMetadataDisabled(reply);
    return reply
      .header('cache-control', 'public, max-age=300')
      .send(protectedResourceMetadata(options.config, options, additionalTools));
  });

  app.get('/mcp', async (request, reply) => {
    if (!transport.enabled) return disabled(reply);
    requireMcpPrincipal(request, options.requestAuthentication);
    assertAllowedOrigin(request, transport.allowedOrigins);
    return reply.header('allow', 'POST').status(405).send({ error: 'mcp_sse_not_supported' });
  });

  app.delete('/mcp', async (request, reply) => {
    if (!transport.enabled) return disabled(reply);
    requireMcpPrincipal(request, options.requestAuthentication);
    assertAllowedOrigin(request, transport.allowedOrigins);
    return reply.header('allow', 'POST').status(405).send({ error: 'mcp_session_deletion_not_supported' });
  });

  app.post(
    '/mcp',
    { bodyLimit: MCP_MAX_REQUEST_BYTES, preParsing: rejectAmbiguousMcpJson },
    async (request, reply) => {
      if (!transport.enabled) return disabled(reply);
      const auth = requireMcpPrincipal(request, options.requestAuthentication);
      assertAllowedOrigin(request, transport.allowedOrigins);
      if (!isJsonContentType(headerValue(request.headers['content-type']))) {
        return reply.status(415).send({ error: 'unsupported_media_type', message: 'MCP requests require application/json.' });
      }
      if (!acceptsStreamableHttp(headerValue(request.headers.accept))) {
        return reply.status(406).send({
          error: 'not_acceptable',
          message: 'MCP requests must accept both application/json and text/event-stream.',
        });
      }
      const contentEncoding = headerValue(request.headers['content-encoding']);
      if (contentEncoding && contentEncoding.toLowerCase() !== 'identity') {
        return reply.status(415).send({ error: 'unsupported_content_encoding' });
      }

      const parsed = jsonRpcRequestSchema.safeParse(request.body);
      if (!parsed.success || Array.isArray(request.body)) {
        return sendRpc(reply, rpcError(null, -32600, 'Invalid JSON-RPC request.'), transport.maxResponseBytes);
      }
      const message = parsed.data as JsonRpcRequest;

      if (message.method === 'initialize') {
        if (message.id === undefined || headerValue(request.headers['mcp-session-id'])) {
          return sendRpc(reply, rpcError(message.id ?? null, -32600, 'Initialize requires an id and no existing session.'), transport.maxResponseBytes);
        }
        const initialize = initializeParamsSchema.safeParse(message.params);
        if (!initialize.success) {
          return sendRpc(reply, rpcError(message.id, -32602, 'Invalid initialize params.'), transport.maxResponseBytes);
        }
        // MCP version negotiation requires the server to return a version it
        // supports when the client proposes a different one. The client can
        // then continue with this version or disconnect if it does not support
        // it. ActionProxy currently implements the 2025-06-18 feature set.
        const issued = sessionAuthority.issue({
          adapterId: auth.clientId!,
          catalogRevision,
          principalId: auth.principalId,
          protocolVersion: MCP_PROTOCOL_VERSION,
          resource: requiredResourceUrl(options.config),
          tenantId: auth.workspaceId,
        });
        reply.header('mcp-session-id', issued.token);
        reply.header('mcp-protocol-version', MCP_PROTOCOL_VERSION);
        return sendRpc(
          reply,
          rpcResult(message.id, {
            _meta: { 'actionproxy/catalogRevision': catalogRevision },
            capabilities: { tools: { listChanged: false } },
            protocolVersion: MCP_PROTOCOL_VERSION,
            serverInfo: { name: 'actionproxy', version: '0.1.1' },
          }),
          transport.maxResponseBytes,
        );
      }

      let session: McpSessionBinding;
      try {
        session = verifyRequestSession(request, auth, options.config, sessionAuthority, catalogRevision);
      } catch (error) {
        if (error instanceof McpSessionError) {
          reply.status(error.code === 'mcp_session_expired' ? 404 : 400);
          return sendRpc(
            reply,
            rpcError(message.id ?? null, -32001, 'MCP session is invalid.', { code: error.code, retrySafe: false }),
            transport.maxResponseBytes,
          );
        }
        throw error;
      }
      reply.header('mcp-protocol-version', session.protocolVersion);

      if (message.id === undefined) {
        if (!message.method.startsWith('notifications/')) {
          return sendRpc(reply, rpcError(null, -32600, 'JSON-RPC requests require an id.'), transport.maxResponseBytes);
        }
        return reply.status(202).send();
      }

      try {
        const result = await withTimeout(
          handleRequest(
            { ...message, id: message.id },
            auth,
            session,
            options,
            sessionAuthority,
            additionalTools,
            retiredTools,
            catalogRevision,
          ),
          transport.requestTimeoutMs,
        );
        return sendRpc(reply, result, transport.maxResponseBytes);
      } catch (error) {
        if (error instanceof McpInsufficientScopeError) throw error;
        if (error instanceof McpRequestTimeoutError) {
          return sendRpc(
            reply,
            rpcError(message.id, -32002, 'MCP request timed out; the execution outcome may be unknown.', {
              code: 'mcp_request_timeout',
              retrySafe: false,
            }),
            transport.maxResponseBytes,
          );
        }
        if (error instanceof ConflictError) {
          return sendRpc(
            reply,
            rpcResult(message.id, mcpError('The request conflicts with an existing MCP action.', 'idempotency_conflict')),
            transport.maxResponseBytes,
          );
        }
        if (error instanceof NotFoundError) {
          return sendRpc(
            reply,
            rpcResult(message.id, mcpError('The requested ActionProxy resource was not found.', 'not_found')),
            transport.maxResponseBytes,
          );
        }
        if (error instanceof ForbiddenError) {
          return sendRpc(
            reply,
            rpcResult(message.id, mcpError('The requested MCP action is not available to this adapter.', 'forbidden')),
            transport.maxResponseBytes,
          );
        }
        request.log.error({ err: error, method: message.method }, 'MCP request failed');
        return sendRpc(
          reply,
          rpcError(message.id, -32603, 'Internal MCP error.', { code: 'internal_error', retrySafe: false }),
          transport.maxResponseBytes,
        );
      }
    },
  );
}

async function handleRequest(
  message: JsonRpcRequest & { id: McpJsonRpcId },
  auth: AuthContext & { clientId: string },
  session: McpSessionBinding,
  options: McpRouteOptions,
  sessions: McpSessionAuthority,
  additionalTools: ReadonlyMap<string, McpAdditionalTool>,
  retiredTools: ReadonlyMap<string, McpRetiredTool>,
  catalogRevision: string,
): Promise<JsonRpcResponse> {
  if (message.method === 'ping') return rpcResult(message.id, {});

  if (message.method === 'tools/list') {
    requireMcpScope(auth, options.listToolsScope ?? 'tool_call:read');
    const parsed = listToolsParamsSchema.safeParse(message.params ?? {});
    if (!parsed.success) return rpcError(message.id, -32602, 'Invalid tools/list params.');
    return rpcResult(message.id, {
      _meta: { 'actionproxy/catalogRevision': catalogRevision },
      tools: toolDescriptors(
        options.includeBuiltinTools !== false,
        [...additionalTools.values()],
        presentsMcpOAuth(options.requestAuthentication),
        catalogRevision,
      ),
    });
  }

  if (message.method !== 'tools/call') {
    return rpcError(message.id, -32601, `Method not found: ${message.method}`);
  }
  const parsed = callToolParamsSchema.safeParse(message.params);
  if (!parsed.success) return rpcError(message.id, -32602, 'Invalid tools/call params.');

  const name = parsed.data.name;
  const rawArguments = parsed.data.arguments ?? {};
  const actionContext = mcpActionContext(auth, session, options.config, sessions, message.id, catalogRevision);
  const additionalTool = additionalTools.get(name);
  if (additionalTool) {
    requireMcpScope(auth, additionalTool.requiredScope);
    try {
      const result = await additionalTool.invoke(rawArguments, actionContext);
      return rpcResult(message.id, projectAdditionalToolResult(result, options.redaction));
    } catch (error) {
      if (error instanceof McpInvalidToolInputError) {
        return rpcError(message.id, -32602, `Invalid ${name} input.`);
      }
      const projected = options.projectAdditionalToolError?.(error);
      if (projected) {
        return rpcError(message.id, projected.code, projected.message, projected.data);
      }
      throw error;
    }
  }

  const retiredTool = retiredTools.get(name);
  if (retiredTool) {
    return rpcError(message.id, -32602, `Platform tool retired: ${name}`, {
      catalogRevision,
      code: 'tool_retired',
      refreshInstruction: retiredTool.refreshInstruction,
      replacement: retiredTool.replacement,
      retrySafe: false,
    });
  }

  if (options.includeBuiltinTools === false) {
    return rpcError(message.id, -32602, `Unknown platform tool: ${name}`);
  }
  if (name === 'actionproxy.get_action_status' || name === 'actionproxy.resume_approved_action') {
    requireMcpScope(auth, 'tool_call:read');
    const status = statusInputSchema.safeParse(rawArguments);
    if (!status.success) return rpcError(message.id, -32602, `Invalid ${name} input.`);
    const toolCall = await options.actionProxy.getToolCall(status.data.toolCallId, auth);
    assertOriginatingAdapter(toolCall, auth, session);
    return rpcResult(message.id, await projectToolCall(toolCall, options));
  }

  requireMcpScope(auth, 'tool_call:submit');
  const input = parseGovernedInput(name, rawArguments);
  if (!input) return rpcError(message.id, -32602, `Unknown or invalid governed tool: ${name}`);

  const result = await options.actionProxy.submitToolCall(
    {
      action: {
        executionMode: 'local_mock',
        operation: { kind: operationKind(name), name },
        protocol: 'mcp',
        resources: [{ name, type: 'mcp.tool' }],
        source: actionContext.source,
      },
      agentId: actionContext.agentId,
      input,
      metadata: { adapter: 'mcp-streamable-http' },
      reason: `Authenticated MCP client requested ${name}`,
      requestedBy: auth.email ?? auth.principalId,
      toolName: name,
    },
    {
      auth,
      idempotencyKey: actionContext.idempotencyKey,
      ingress: actionContext.ingress,
    },
  );
  assertOriginatingAdapter(result.toolCall, auth, session);
  return rpcResult(message.id, await projectToolCall(result.toolCall, options, result.approval));
}

function mcpActionContext(
  auth: AuthContext & { clientId: string },
  session: McpSessionBinding,
  config: ResolvedAppConfig,
  sessions: McpSessionAuthority,
  messageId: McpJsonRpcId,
  catalogRevision: string,
): McpAdditionalToolContext {
  const adapterIdentity = mcpAdapterIdentity(auth);
  const adapterId = auth.clientId;
  const agentId = `mcp-client:${adapterId}`;
  const influenceScopeId = deriveInfluenceScopeId({
    adapterId: session.adapterId,
    principalId: session.principalId,
    protocol: 'mcp',
    transport: 'streamable_http',
    transportSessionId: session.sessionId,
    workspaceId: session.tenantId,
  });
  const source = { id: adapterId, name: adapterIdentity.sourceName, type: 'mcp' as const };
  const ingress: McpActionIngress = {
    adapterId,
    adapterSource: adapterIdentity.provenance,
    adapterTrust: adapterIdentity.trust,
    agent: {
      id: agentId,
      name: adapterIdentity.agentName,
      source: adapterIdentity.provenance,
      trust: 'derived',
    },
    environment: config.deployment?.mode ?? 'self_hosted',
    idempotency: { source: 'mcp.signed-session+jsonrpc-id', trust: 'derived' },
    protocol: 'mcp',
    session: {
      sessionId: influenceScopeId,
      source: 'actionproxy.verified-mcp-influence-scope',
      trust: 'trusted',
    },
    source: 'mcp',
  };
  return {
    adapterId,
    agentId,
    auth,
    catalogRevision,
    idempotencyKey: sessions.idempotencyKey(session, messageId),
    ingress,
    source,
  };
}

function mcpAdapterIdentity(auth: AuthContext): {
  agentName: string;
  provenance: string;
  sourceName: string;
  trust: McpActionIngress['adapterTrust'];
} {
  if (auth.authProvider === 'tunnel_single_user') {
    return {
      agentName: 'Server-authenticated single-user MCP tunnel client',
      provenance: 'actionproxy.mcp-request-authentication.tunnel-single-user',
      sourceName: 'Authenticated Single-User MCP Tunnel',
      trust: 'trusted',
    };
  }
  return {
    agentName: 'Authenticated MCP OAuth client',
    provenance: 'oauth.access-token.client-id',
    sourceName: 'MCP Streamable HTTP',
    trust: 'externally_verified',
  };
}

function parseGovernedInput(name: string, input: JsonObject): JsonObject | undefined {
  const schema = name === 'docs.search'
    ? docsSearchInputSchema
    : name === 'gmail.send_email'
      ? sendEmailInputSchema
      : name === 'dangerous.delete_customer'
        ? deleteCustomerInputSchema
        : undefined;
  if (!schema) return undefined;
  const parsed = schema.safeParse(input);
  return parsed.success ? parsed.data : undefined;
}

async function projectToolCall(
  toolCall: ToolCallRecord,
  options: McpRouteOptions,
  suppliedApproval?: ApprovalRecord,
): Promise<McpToolResult> {
  if (isModelVisibleResultWithheld(toolCall)) {
    return mcpError(
      WITHHELD_MODEL_RESULT_MESSAGE,
      'result_withheld',
    );
  }
  const workspaceId = toolCall.workspaceId ?? 'default';
  const [approval, attempt] = await Promise.all([
    suppliedApproval ?? options.store.getApprovalByToolCallId(toolCall.id),
    options.store.getExecutionAttemptByToolCallId(workspaceId, toolCall.id),
  ]);
  const decisionV1 = isRecord(toolCall.decisionTrace?.decisionV1) ? toolCall.decisionTrace?.decisionV1 : undefined;
  const structuredContent: JsonObject = {
    actionproxy: {
      approval: approval ? { id: approval.id, status: approval.status } : undefined,
      decision: toolCall.authorizationDecision ?? toolCall.decision,
      decisionId: typeof decisionV1?.decisionId === 'string' ? decisionV1.decisionId : undefined,
      reasonCodes: Array.isArray(decisionV1?.reasonCodes) ? decisionV1.reasonCodes : undefined,
      status: toolCall.status,
      toolCallId: toolCall.id,
      toolName: toolCall.toolName,
    },
    executionAttempt: attempt
      ? {
          attemptNumber: attempt.attemptNumber,
          certainty: attempt.outcome?.certainty,
          id: attempt.id,
          retryDisposition: attempt.outcome?.retryDisposition,
          retryPolicy: attempt.retryPolicy,
          state: attempt.state,
        }
      : undefined,
    nextAction: nextAction(toolCall.status),
    result: toolCall.status === 'executed' ? safeResult(toolCall.result, options.redaction) : undefined,
  };
  return {
    content: [{ text: statusText(toolCall), type: 'text' }],
    isError: ['blocked', 'failed', 'rejected'].includes(toolCall.status) || undefined,
    structuredContent,
  };
}

function assertOriginatingAdapter(
  toolCall: ToolCallRecord,
  auth: AuthContext & { clientId: string },
  session: McpSessionBinding,
): void {
  if ((toolCall.workspaceId ?? 'default') !== auth.workspaceId) {
    throw new ForbiddenError('MCP action is not in the authenticated tenant.');
  }
  const evidence = isRecord(toolCall.decisionTrace?.canonicalRequestEvidence)
    ? toolCall.decisionTrace?.canonicalRequestEvidence
    : undefined;
  const source = isRecord(evidence?.source) && isRecord(evidence.source.value) ? evidence.source.value : undefined;
  const tenant = isRecord(evidence?.tenant) && isRecord(evidence.tenant.value) ? evidence.tenant.value : undefined;
  const protocol = isRecord(evidence?.sourceProtocol) ? evidence.sourceProtocol.value : undefined;
  const sessionEvidence = isRecord(evidence?.session) ? evidence.session : undefined;
  const sessionProvenance = isRecord(sessionEvidence?.provenance) ? sessionEvidence.provenance : undefined;
  const sessionValue = isRecord(sessionEvidence?.value) ? sessionEvidence.value : undefined;
  const influenceScopeId = deriveInfluenceScopeId({
    adapterId: session.adapterId,
    principalId: session.principalId,
    protocol: 'mcp',
    transport: 'streamable_http',
    transportSessionId: session.sessionId,
    workspaceId: session.tenantId,
  });
  if (
    source?.type !== 'mcp' ||
    source.adapterId !== auth.clientId ||
    tenant?.id !== auth.workspaceId ||
    protocol !== 'mcp' ||
    sessionEvidence?.present !== true ||
    sessionProvenance?.source !== 'actionproxy.verified-mcp-influence-scope' ||
    !['derived', 'externally_verified', 'trusted'].includes(String(sessionProvenance?.trust)) ||
    sessionValue?.sessionId !== influenceScopeId ||
    toolCall.actionEnvelope?.protocol !== 'mcp' ||
    toolCall.actionEnvelope.source.type !== 'mcp' ||
    toolCall.actionEnvelope.source.id !== auth.clientId ||
    toolCall.requestedByAuth?.clientId !== auth.clientId ||
    toolCall.requestedByAuth?.principalId !== auth.principalId ||
    toolCall.influenceScopeId !== influenceScopeId
  ) {
    throw new ForbiddenError('MCP action is not bound to the authenticated adapter.');
  }
}

function verifyRequestSession(
  request: FastifyRequest,
  auth: AuthContext & { clientId: string },
  config: ResolvedAppConfig,
  sessions: McpSessionAuthority,
  catalogRevision: string,
): McpSessionBinding {
  const token = headerValue(request.headers['mcp-session-id']);
  const protocolVersion = headerValue(request.headers['mcp-protocol-version']);
  if (!token || !protocolVersion) throw new McpSessionError('mcp_session_invalid', 'MCP session headers are required.');
  if (protocolVersion !== MCP_PROTOCOL_VERSION) {
    throw new McpSessionError('mcp_session_binding_mismatch', 'MCP protocol version does not match.');
  }
  return sessions.verify(token, {
    adapterId: auth.clientId,
    catalogRevision,
    principalId: auth.principalId,
    protocolVersion,
    resource: requiredResourceUrl(config),
    tenantId: auth.workspaceId,
  });
}

function protectedResourceMetadata(
  config: ResolvedAppConfig,
  options: McpRouteExtensionOptions,
  additionalTools: ReadonlyMap<string, McpAdditionalTool>,
): JsonObject {
  const transport = config.mcp.streamableHttp;
  const authorizationServer = transport.authorizationServer ?? config.auth.oidc.issuer;
  return {
    authorization_servers: authorizationServer ? [authorizationServer] : [],
    bearer_methods_supported: ['header'],
    resource: requiredResourceUrl(config),
    scopes_supported: supportedScopes(options, additionalTools),
  };
}

function createSessionAuthority(config: ResolvedAppConfig): McpSessionAuthority {
  const transport = config.mcp.streamableHttp;
  if (!transport.enabled) {
    // The disabled endpoint never uses this authority. A valid ephemeral value
    // avoids making registration itself conditional and creates no live token.
    return new McpSessionAuthority('disabled-mcp-session-secret-32-bytes', 1);
  }
  if (!transport.sessionSecret) throw new Error('MCP session secret is required.');
  return new McpSessionAuthority(transport.sessionSecret, transport.sessionTtlMs);
}

function requireMcpPrincipal(
  request: FastifyRequest,
  requestAuthentication: McpRequestAuthentication | undefined,
): AuthContext & { clientId: string } {
  const auth = assertMcpAuthenticatedPrincipal(request.authContext);
  if (!requestAuthentication && auth.authProvider !== 'oidc_jwt') {
    throw new UnauthorizedError('MCP requires an OAuth bearer with a verified client identity.');
  }
  return auth;
}

function requireMcpScope(auth: AuthContext, scope: string): void {
  if (!auth.scopes.includes('*') && !auth.scopes.includes(scope)) throw new McpInsufficientScopeError(scope);
}

function assertAllowedOrigin(request: FastifyRequest, allowedOrigins: string[]): void {
  const origin = headerValue(request.headers.origin);
  if (origin && !allowedOrigins.includes(origin)) throw new ForbiddenError('MCP request origin is not allowed.');
}

function sendRpc(reply: FastifyReply, response: JsonRpcResponse, maxBytes: number): FastifyReply {
  let serialized = JSON.stringify(response);
  if (Buffer.byteLength(serialized, 'utf8') > maxBytes) {
    serialized = JSON.stringify(rpcError(response.id, -32003, 'MCP response exceeded the configured output bound.', {
      code: 'response_too_large',
      retrySafe: false,
    }));
  }
  reply.header('cache-control', 'no-store');
  return reply.type('application/json; charset=utf-8').send(serialized);
}

function rpcResult(id: McpJsonRpcId, result: unknown): JsonRpcResponse {
  return { id, jsonrpc: '2.0', result };
}

function rpcError(id: JsonRpcId, code: number, message: string, data?: JsonObject): JsonRpcResponse {
  return { error: { code, data, message }, id, jsonrpc: '2.0' };
}

function mcpError(message: string, code: string): McpToolResult {
  return {
    content: [{ text: message, type: 'text' }],
    isError: true,
    structuredContent: { actionproxy: { code, retrySafe: false } },
  };
}

function toolDescriptors(
  includeBuiltinTools: boolean,
  additionalTools: readonly McpAdditionalTool[],
  oauthPresented = true,
  catalogRevision?: string,
): JsonObject[] {
  const submitSecurity = toolSecuritySchemes(oauthPresented, 'tool_call:submit');
  const readSecurity = toolSecuritySchemes(oauthPresented, 'tool_call:read');
  const builtins = includeBuiltinTools ? [
    {
      _meta: descriptorMeta(submitSecurity, catalogRevision),
      annotations: {
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
        readOnlyHint: true,
      },
      description: 'Search the local demo documentation through ActionProxy governance.',
      inputSchema: {
        additionalProperties: false,
        properties: { query: { maxLength: 16_384, minLength: 1, type: 'string' } },
        required: ['query'],
        type: 'object',
      },
      name: 'docs.search',
      securitySchemes: submitSecurity,
      title: 'Search Docs',
    },
    {
      _meta: descriptorMeta(submitSecurity, catalogRevision),
      annotations: {
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
        readOnlyHint: false,
      },
      description: 'Submit a demo email action to ActionProxy for policy and human approval. Community mock execution sends no real email.',
      inputSchema: {
        additionalProperties: false,
        properties: {
          body: { maxLength: 128 * 1024, minLength: 1, type: 'string' },
          subject: { maxLength: 4096, minLength: 1, type: 'string' },
          to: { maxLength: 4096, minLength: 1, type: 'string' },
        },
        required: ['to', 'subject', 'body'],
        type: 'object',
      },
      name: 'gmail.send_email',
      securitySchemes: submitSecurity,
      title: 'Send Email',
    },
    {
      _meta: descriptorMeta(submitSecurity, catalogRevision),
      annotations: {
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
        readOnlyHint: false,
      },
      description: 'Demonstrate a destructive action that ActionProxy policy denies.',
      inputSchema: {
        additionalProperties: false,
        properties: {
          customerId: { maxLength: 4096, minLength: 1, type: 'string' },
          reason: { maxLength: 16_384, minLength: 1, type: 'string' },
        },
        required: ['customerId', 'reason'],
        type: 'object',
      },
      name: 'dangerous.delete_customer',
      securitySchemes: submitSecurity,
      title: 'Delete Customer Demo',
    },
    {
      _meta: descriptorMeta(readSecurity, catalogRevision),
      annotations: {
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
        readOnlyHint: true,
      },
      description: 'Read status for an action created by this authenticated MCP adapter.',
      inputSchema: toolCallIdSchema(),
      name: 'actionproxy.get_action_status',
      securitySchemes: readSecurity,
      title: 'Get Action Status',
    },
    {
      _meta: descriptorMeta(readSecurity, catalogRevision),
      annotations: {
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
        readOnlyHint: true,
      },
      description: 'Reload an approved action after ActionProxy has completed authoritative finalization.',
      inputSchema: toolCallIdSchema(),
      name: 'actionproxy.resume_approved_action',
      securitySchemes: readSecurity,
      title: 'Resume Approved Action',
    },
  ] : [];
  return [
    ...builtins,
    ...additionalTools.map((tool) => additionalToolDescriptor(tool, oauthPresented, catalogRevision)),
  ];
}

function additionalToolDescriptor(
  tool: McpAdditionalTool,
  oauthPresented: boolean,
  catalogRevision?: string,
): JsonObject {
  const securitySchemes = toolSecuritySchemes(oauthPresented, tool.requiredScope);
  return {
    _meta: descriptorMeta(securitySchemes, catalogRevision),
    annotations: tool.annotations,
    description: tool.description,
    inputSchema: tool.inputSchema,
    name: tool.name,
    securitySchemes,
    title: tool.title,
  };
}

function descriptorMeta(securitySchemes: JsonObject[], catalogRevision?: string): JsonObject {
  return {
    ...(catalogRevision ? { 'actionproxy/catalogRevision': catalogRevision } : {}),
    securitySchemes,
  };
}

function toolSecuritySchemes(oauthPresented: boolean, scope: string): JsonObject[] {
  return oauthPresented ? [{ scopes: [scope], type: 'oauth2' }] : [{ type: 'noauth' }];
}

function validateAdditionalTools(
  tools: readonly McpAdditionalTool[],
  includeBuiltinTools: boolean,
): ReadonlyMap<string, McpAdditionalTool> {
  const registrations = new Map<string, McpAdditionalTool>();
  const reserved = new Set(
    includeBuiltinTools
      ? toolDescriptors(true, []).map((descriptor) => String(descriptor.name))
      : [],
  );
  for (const tool of tools) {
    if (!/^[a-z0-9][a-z0-9._-]{0,255}$/u.test(tool.name)) {
      throw new Error(`Invalid additional MCP tool name: ${tool.name}`);
    }
    if (reserved.has(tool.name) || registrations.has(tool.name)) {
      throw new Error(`Duplicate MCP tool registration: ${tool.name}`);
    }
    registrations.set(tool.name, tool);
  }
  return registrations;
}

function validateRetiredTools(
  tools: Readonly<Record<string, McpRetiredTool>>,
  additionalTools: ReadonlyMap<string, McpAdditionalTool>,
  includeBuiltinTools: boolean,
): ReadonlyMap<string, McpRetiredTool> {
  const advertised = new Set(
    toolDescriptors(includeBuiltinTools, [...additionalTools.values()])
      .map((descriptor) => String(descriptor.name)),
  );
  const retired = new Map<string, McpRetiredTool>();
  for (const [name, detail] of Object.entries(tools)) {
    if (!/^[a-z0-9][a-z0-9._-]{0,255}$/u.test(name)) {
      throw new Error(`Invalid retired MCP tool name: ${name}`);
    }
    if (advertised.has(name)) throw new Error(`Retired MCP tool is still advertised: ${name}`);
    if (!detail.replacement.trim() || !detail.refreshInstruction.trim()) {
      throw new Error(`Retired MCP tool requires replacement and refresh instructions: ${name}`);
    }
    if (!advertised.has(detail.replacement)) {
      throw new Error(`Retired MCP tool replacement is not advertised: ${name} -> ${detail.replacement}`);
    }
    retired.set(name, detail);
  }
  return retired;
}

/**
 * Deterministic deployment revision for the effective catalog. Invocation
 * handlers and OAuth/no-auth presentation are intentionally excluded.
 */
export function mcpCatalogRevision(
  includeBuiltinTools: boolean,
  additionalTools: readonly McpAdditionalTool[],
): string {
  const tools = toolDescriptors(includeBuiltinTools, additionalTools, true)
    .map((descriptor) => {
      const securitySchemes = Array.isArray(descriptor.securitySchemes)
        ? descriptor.securitySchemes.filter(isRecord)
        : [];
      return {
        annotations: descriptor.annotations,
        description: descriptor.description,
        inputSchema: descriptor.inputSchema,
        name: descriptor.name,
        scopes: securitySchemes
          .flatMap((scheme) => Array.isArray(scheme.scopes) ? scheme.scopes : [])
          .filter((scope): scope is string => typeof scope === 'string')
          .sort(),
      };
    })
    .sort((left, right) => {
      const leftName = String(left.name);
      const rightName = String(right.name);
      return leftName === rightName ? 0 : leftName < rightName ? -1 : 1;
    });
  return `mcp_catalog_${hashCanonicalJson({ tools, version: 'actionproxy.mcp-catalog.v1' })}`;
}

function supportedScopes(
  options: McpRouteExtensionOptions,
  additionalTools: ReadonlyMap<string, McpAdditionalTool>,
): string[] {
  const scopes = new Set<string>();
  if (options.includeBuiltinTools !== false) {
    CORE_MCP_SCOPES.forEach((scope) => scopes.add(scope));
  }
  scopes.add(options.listToolsScope ?? 'tool_call:read');
  additionalTools.forEach((tool) => scopes.add(tool.requiredScope));
  return [...scopes];
}

function projectAdditionalToolResult(
  result: McpAdditionalToolResult,
  redaction: RedactionOptions = {},
): McpToolResult {
  return {
    content: [{ text: result.contentText.slice(0, 4096), type: 'text' }],
    isError: result.isError || undefined,
    structuredContent: safeResult(result.structuredContent, redaction) ?? {},
  };
}

export class McpInvalidToolInputError extends Error {
  constructor() {
    super('Invalid additional MCP tool input.');
    this.name = 'McpInvalidToolInputError';
  }
}

function toolCallIdSchema(): JsonObject {
  return {
    additionalProperties: false,
    properties: { toolCallId: { maxLength: 512, minLength: 1, type: 'string' } },
    required: ['toolCallId'],
    type: 'object',
  };
}

function operationKind(name: string): 'delete' | 'external_send' | 'read' {
  if (name === 'dangerous.delete_customer') return 'delete';
  if (name === 'gmail.send_email') return 'external_send';
  return 'read';
}

function nextAction(status: ToolCallRecord['status']): string {
  if (status === 'pending_approval') return 'human_approval_required';
  if (status === 'executed') return 'complete';
  return 'do_not_execute';
}

function statusText(toolCall: ToolCallRecord): string {
  if (toolCall.status === 'pending_approval') return `ActionProxy requires human approval before ${toolCall.toolName} can execute.`;
  if (toolCall.status === 'blocked') return `ActionProxy denied ${toolCall.toolName}.`;
  if (toolCall.status === 'executed') return `ActionProxy executed ${toolCall.toolName}.`;
  return `ActionProxy status for ${toolCall.toolName}: ${toolCall.status}.`;
}

function safeResult(result: unknown, redaction: RedactionOptions = {}): JsonObject | undefined {
  if (result === undefined) return undefined;
  const projected = scrubSensitiveResult(result);
  const object = isRecord(projected) ? projected : { value: projected };
  return redactJsonObject(object, redaction);
}

function scrubSensitiveResult(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(scrubSensitiveResult);
  if (!isRecord(value)) return value;
  const output: JsonObject = {};
  for (const [key, item] of Object.entries(value)) {
    const normalized = key.replaceAll(/[-_\s]/gu, '').toLowerCase();
    if (
      !SAFE_RESULT_KEYS_WITH_SENSITIVE_FRAGMENTS.has(normalized)
      && FORBIDDEN_RESULT_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment))
    ) continue;
    output[key] = scrubSensitiveResult(item);
  }
  return output;
}

function acceptsStreamableHttp(value: string | undefined): boolean {
  if (!value) return false;
  const media = value
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter((item) => !/(?:^|;)\s*q=0(?:\.0*)?(?:;|$)/u.test(item))
    .map((item) => item.split(';', 1)[0]);
  return media.includes('application/json') && media.includes('text/event-stream');
}

function isJsonContentType(value: string | undefined): boolean {
  return value?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json';
}

function requiredResourceUrl(config: ResolvedAppConfig): string {
  const resource = config.mcp.streamableHttp.resourceUrl;
  if (!resource) throw new Error('MCP resource URL is required.');
  return resource;
}

function disabled(reply: FastifyReply): FastifyReply {
  return reply.status(404).send({ error: 'mcp_streamable_http_disabled' });
}

function oauthMetadataDisabled(reply: FastifyReply): FastifyReply {
  return reply.status(404).send({ error: 'mcp_oauth_metadata_disabled' });
}

async function rejectAmbiguousMcpJson(
  request: { headers: Record<string, unknown> },
  _reply: unknown,
  payload: AsyncIterable<unknown>,
) {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of payload) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    length += buffer.byteLength;
    if (length > MCP_MAX_REQUEST_BYTES) throw httpBodyError(413, 'MCP request body is too large.');
    chunks.push(buffer);
  }
  const body = Buffer.concat(chunks);
  if (isJsonContentType(String(request.headers['content-type'] ?? ''))) {
    try {
      assertNoDuplicateJsonKeys(body.toString('utf8'));
    } catch (error) {
      if (error instanceof DuplicateJsonKeyError) throw httpBodyError(400, error.message);
      // Fastify remains authoritative for ordinary JSON syntax errors.
    }
  }
  const replacement = Readable.from([body]) as Readable & { receivedEncodedLength?: number };
  replacement.receivedEncodedLength = body.byteLength;
  return replacement;
}

function httpBodyError(statusCode: number, message: string): Error {
  return Object.assign(new Error(message), { statusCode });
}

class McpRequestTimeoutError extends Error {
  constructor() {
    super('MCP request timed out.');
    this.name = 'McpRequestTimeoutError';
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new McpRequestTimeoutError()), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
