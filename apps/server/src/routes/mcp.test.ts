import fs from 'node:fs';
import path from 'node:path';
import Fastify, { type FastifyInstance, type InjectOptions, type LightMyRequestResponse } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { withConfigDefaults, type ResolvedAppConfig } from '../config';
import { ConflictError, ForbiddenError } from '../errors';
import type { ApprovalRecord, AuthContext, JsonObject, ToolCallRecord } from '../models';
import type { ExecutionAttemptRecordV1 } from '../contracts/execution-attempt';
import type { AuthService } from '../security/auth-service';
import { registerSecurityHooks, type McpRequestAuthentication } from '../security/http-security';
import type { ActionProxyService } from '../services/action-gate';
import type { Store } from '../storage/store';
import {
  MCP_PROTOCOL_VERSION,
  mcpCatalogRevision,
  registerMcpRoutes,
  type McpAdditionalTool,
  type McpAdditionalToolContext,
  type McpExtensionErrorProjection,
} from './mcp';

const fixture = JSON.parse(
  fs.readFileSync(path.resolve('../../fixtures/contracts/mcp-conformance-v1.json'), 'utf8'),
) as {
  authoritativeContext: string[];
  clientAssertionsNeverAuthoritative: string[];
  protocolVersion: string;
  scenarios: Array<{ id: string }>;
  version: string;
};

const sessionSecret = 'mcp-route-test-session-secret-with-at-least-32-bytes';
const accept = 'application/json, text/event-stream';
let apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.map((app) => app.close()));
  apps = [];
});

describe('Streamable HTTP MCP route', () => {
  it('consumes the frozen fixture, serves protected-resource discovery, and performs a strict session handshake', async () => {
    const harness = await makeHarness();
    const metadata = await harness.app.inject({ method: 'GET', url: '/.well-known/oauth-protected-resource/mcp' });

    expect(fixture).toMatchObject({
      protocolVersion: MCP_PROTOCOL_VERSION,
      version: 'actionproxy.mcp-conformance.v1',
    });
    expect(fixture.authoritativeContext).toEqual(
      expect.arrayContaining(['tenant', 'actor', 'adapterId', 'sourceProtocol', 'environment', 'idempotencyKey']),
    );
    expect(fixture.clientAssertionsNeverAuthoritative).toContain('executionAuthorization');
    expect(fixture.scenarios.map((scenario) => scenario.id)).toEqual(
      expect.arrayContaining(['allow', 'deny', 'require-approval', 'same-request-replay', 'payload-conflict']),
    );
    expect(metadata.statusCode).toBe(200);
    expect(metadata.json()).toEqual({
      authorization_servers: ['https://issuer.example/'],
      bearer_methods_supported: ['header'],
      resource: 'https://proxy.example/mcp',
      scopes_supported: ['tool_call:read', 'tool_call:submit'],
    });

    const initialized = await initialize(harness.app);
    expect(initialized.response.statusCode).toBe(200);
    expect(initialized.response.headers['mcp-protocol-version']).toBe(MCP_PROTOCOL_VERSION);
    expect(initialized.session).toBeTruthy();
    expect(initialized.response.json()).toMatchObject({
      id: 'initialize_1',
      result: {
        capabilities: { tools: { listChanged: false } },
        protocolVersion: MCP_PROTOCOL_VERSION,
      },
    });
    const initializedRevision = initialized.response.json().result._meta['actionproxy/catalogRevision'];
    expect(initializedRevision).toMatch(/^mcp_catalog_[a-f0-9]{64}$/u);
    expect(initialized.response.body).not.toContain(sessionSecret);

    const negotiated = await harness.app.inject({
      headers: { ...authHeaders(), accept, 'content-type': 'application/json' },
      method: 'POST',
      payload: {
        id: 'initialize_newer',
        jsonrpc: '2.0',
        method: 'initialize',
        params: { capabilities: {}, clientInfo: { name: 'newer-client', version: '1' }, protocolVersion: '2025-11-25' },
      },
      url: '/mcp',
    });
    expect(negotiated.statusCode).toBe(200);
    expect(negotiated.headers['mcp-session-id']).toBeTruthy();
    expect(negotiated.headers['mcp-protocol-version']).toBe(MCP_PROTOCOL_VERSION);
    expect(negotiated.json()).toMatchObject({
      id: 'initialize_newer',
      result: { protocolVersion: MCP_PROTOCOL_VERSION },
    });

    const notification = await mcpRequest(harness.app, initialized.session, {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
      params: {},
    });
    expect(notification.statusCode).toBe(202);
    expect(notification.body).toBe('');

    const listed = await callRpc(harness.app, initialized.session, 'list_1', 'tools/list', {});
    const tools = listed.result.tools as Array<{
      _meta: { 'actionproxy/catalogRevision': string; securitySchemes: unknown[] };
      annotations: Record<string, boolean>;
      description: string;
      inputSchema: Record<string, unknown>;
      name: string;
      securitySchemes: unknown[];
    }>;
    expect(listed.result._meta['actionproxy/catalogRevision']).toBe(initializedRevision);
    expect(tools.every((tool) => tool._meta['actionproxy/catalogRevision'] === initializedRevision)).toBe(true);
    expect(tools.map((tool) => tool.name)).toEqual([
      'docs.search',
      'gmail.send_email',
      'dangerous.delete_customer',
      'actionproxy.get_action_status',
      'actionproxy.resume_approved_action',
    ]);
    expect(tools.find((tool) => tool.name === 'docs.search')?.securitySchemes).toEqual([
      { scopes: ['tool_call:submit'], type: 'oauth2' },
    ]);
    expect(tools.find((tool) => tool.name === 'docs.search')?._meta.securitySchemes).toEqual(
      tools.find((tool) => tool.name === 'docs.search')?.securitySchemes,
    );
    expect(tools.find((tool) => tool.name === 'actionproxy.get_action_status')?.securitySchemes).toEqual([
      { scopes: ['tool_call:read'], type: 'oauth2' },
    ]);
    expect(tools.find((tool) => tool.name === 'actionproxy.get_action_status')?._meta.securitySchemes).toEqual(
      tools.find((tool) => tool.name === 'actionproxy.get_action_status')?.securitySchemes,
    );
    expect(tools.find((tool) => tool.name === 'docs.search')?.annotations).toEqual({
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
      readOnlyHint: true,
    });
    expect(tools.find((tool) => tool.name === 'gmail.send_email')?.annotations).toEqual({
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
      readOnlyHint: false,
    });
    expect(tools.find((tool) => tool.name === 'gmail.send_email')?.description).toContain('sends no real email');
    expect(tools.find((tool) => tool.name === 'dangerous.delete_customer')?.annotations).toEqual({
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
      readOnlyHint: false,
    });
    for (const name of ['actionproxy.get_action_status', 'actionproxy.resume_approved_action']) {
      expect(tools.find((tool) => tool.name === name)?.annotations).toEqual({
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
        readOnlyHint: true,
      });
    }
    expect(tools.find((tool) => tool.name === 'docs.search')?.inputSchema).toMatchObject({
      additionalProperties: false,
      properties: { query: { maxLength: 16_384, minLength: 1, type: 'string' } },
    });
    expect(tools.map((tool) => tool.name)).not.toEqual(
      expect.arrayContaining(['actionproxy.approve_action', 'actionproxy.reject_action']),
    );

    expect((await harness.app.inject({ headers: authHeaders(), method: 'GET', url: '/mcp' })).statusCode).toBe(405);
    expect((await harness.app.inject({ headers: authHeaders(), method: 'DELETE', url: '/mcp' })).statusCode).toBe(405);
  });

  it('rate-limits both public protected-resource metadata routes', async () => {
    const harness = await makeHarness({ rateLimitMax: 1 });

    for (const url of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
      const first = await harness.app.inject({ method: 'GET', url });
      const limited = await harness.app.inject({ method: 'GET', url });

      expect(first.statusCode, url).toBe(200);
      expect(limited.statusCode, url).toBe(429);
      expect(limited.json(), url).toMatchObject({ error: 'rate_limited' });
    }
  });

  it('derives a stable catalog revision from names, schemas, scopes, descriptions, and annotations', () => {
    const first = testAdditionalTool();
    const second: McpAdditionalTool = {
      ...testAdditionalTool(),
      name: 'actionproxy.test.second',
      title: 'Second Test Read',
    };
    const baseline = mcpCatalogRevision(false, [first, second]);

    expect(mcpCatalogRevision(false, [second, first])).toBe(baseline);
    for (const changed of [
      { ...first, name: 'actionproxy.test.renamed' },
      { ...first, description: 'Changed description.' },
      { ...first, inputSchema: { additionalProperties: false, properties: { id: { type: 'string' } }, type: 'object' } },
      { ...first, requiredScope: 'approval:read' as const },
      { ...first, annotations: { ...first.annotations, readOnlyHint: false } },
    ]) {
      expect(mcpCatalogRevision(false, [changed, second])).not.toBe(baseline);
    }
  });

  it('returns a redacted structured MCP error produced by an injected tool projector', async () => {
    const error = new Error('secret extension detail');
    const tool = testAdditionalTool();
    const harness = await makeHarness({
      additionalTools: [{
        ...tool,
        invoke: async () => {
          throw error;
        },
      }],
      projectAdditionalToolError: (thrown) => thrown === error
        ? {
            code: -32009,
            data: {
              code: 'extension_action_unavailable',
              retrySafe: false,
            },
            message: 'The injected action could not be completed.',
          }
        : undefined,
    });
    const { session } = await initialize(harness.app);

    const response = await callTool(harness.app, session, 'extension_failure', tool.name, {});

    expect(response.error).toMatchObject({
      code: -32009,
      data: { code: 'extension_action_unavailable', retrySafe: false },
    });
    expect(JSON.stringify(response)).not.toContain('secret');
  });

  it('does not apply an extension error projector to built-in governed tools', async () => {
    const marker = new Error('built-in-secret');
    const harness = await makeHarness({
      projectAdditionalToolError: () => ({
        code: -32009,
        data: { code: 'extension_projection', retrySafe: false },
        message: 'Extension projection.',
      }),
      submitError: marker,
    });
    const { session } = await initialize(harness.app);

    const response = await callTool(harness.app, session, 'built_in_projection_scope', 'docs.search', {
      query: 'x',
    });

    expect(response.error).toMatchObject({
      code: -32603,
      data: { code: 'internal_error', retrySafe: false },
    });
    expect(JSON.stringify(response)).not.toContain('built-in-secret');
    expect(JSON.stringify(response)).not.toContain('extension_projection');
  });

  it('maps allow, deny, pending approval, edited approval status, and canonical trusted ingress', async () => {
    let additionalContext: McpAdditionalToolContext | undefined;
    const harness = await makeHarness({
      additionalTools: [testAdditionalTool((context) => {
        additionalContext = context;
      })],
    });
    const { session } = await initialize(harness.app);

    const additional = await callTool(harness.app, session, 'additional_context', 'actionproxy.test.read', {});
    expect(additional.result).toMatchObject({ structuredContent: { ok: true } });
    expect(additionalContext).toMatchObject({
      adapterId: 'client_a',
      agentId: 'mcp-client:client_a',
      auth: {
        authProvider: 'oidc_jwt',
        clientId: 'client_a',
        principalId: 'user_a',
        workspaceId: 'tenant_a',
      },
      idempotencyKey: expect.stringMatching(/^mcp_[a-f0-9]{64}$/u),
      ingress: {
        adapterId: 'client_a',
        adapterSource: 'oauth.access-token.client-id',
        adapterTrust: 'externally_verified',
        agent: {
          id: 'mcp-client:client_a',
          name: 'Authenticated MCP OAuth client',
          source: 'oauth.access-token.client-id',
          trust: 'derived',
        },
        environment: 'self_hosted',
        idempotency: { source: 'mcp.signed-session+jsonrpc-id', trust: 'derived' },
        protocol: 'mcp',
        session: {
          sessionId: expect.stringMatching(/^influence_[a-f0-9]{64}$/u),
          source: 'actionproxy.verified-mcp-influence-scope',
          trust: 'trusted',
        },
        source: 'mcp',
      },
      source: { id: 'client_a', name: 'MCP Streamable HTTP', type: 'mcp' },
    });
    expect(additionalContext?.ingress.session?.sessionId).not.toBe(session);

    const allowed = await callTool(harness.app, session, 'allow_1', 'docs.search', { query: 'refunds' });
    expect(allowed.result).toMatchObject({
      structuredContent: {
        actionproxy: { decision: 'allow', status: 'executed', toolName: 'docs.search' },
        nextAction: 'complete',
      },
    });
    expect(JSON.stringify(allowed)).not.toMatch(/signature|nonce|executionAuthorization|sessionSecret/u);

    const denied = await callTool(harness.app, session, 'deny_1', 'dangerous.delete_customer', {
      customerId: 'cus_1',
      reason: 'test',
    });
    expect(denied.result).toMatchObject({
      isError: true,
      structuredContent: { actionproxy: { decision: 'deny', status: 'blocked' } },
    });

    const pending = await callTool(harness.app, session, 'approval_1', 'gmail.send_email', {
      body: 'Original',
      subject: 'Original',
      to: 'first@example.com',
    });
    expect(pending.result).toMatchObject({
      structuredContent: {
        actionproxy: { decision: 'require_approval', status: 'pending_approval' },
        nextAction: 'human_approval_required',
      },
    });
    const toolCallId = pending.result.structuredContent.actionproxy.toolCallId as string;
    harness.service.approveWithEditedInput(toolCallId, { body: 'Edited', subject: 'Edited', to: 'edited@example.com' });

    const status = await callTool(harness.app, session, 'status_1', 'actionproxy.get_action_status', { toolCallId });
    const resumed = await callTool(harness.app, session, 'resume_1', 'actionproxy.resume_approved_action', { toolCallId });
    expect(status.result).toMatchObject({
      structuredContent: {
        actionproxy: { status: 'executed' },
        result: { to: 'edited@example.com' },
      },
    });
    expect(resumed.result).toEqual(status.result);

    expect(harness.service.dispatches).toBe(2);
    expect(harness.service.lastSubmission?.options.ingress).toEqual(additionalContext?.ingress);
    expect(harness.service.lastSubmission?.request.agentId).toBe(additionalContext?.agentId);
    expect(harness.service.lastSubmission?.request.action).toMatchObject({ source: additionalContext?.source });
    expect(harness.service.lastSubmission).toMatchObject({
      options: {
        idempotencyKey: expect.stringMatching(/^mcp_[a-f0-9]{64}$/u),
        ingress: {
          adapterId: 'client_a',
          environment: 'self_hosted',
          protocol: 'mcp',
          session: {
            sessionId: expect.stringMatching(/^influence_[a-f0-9]{64}$/u),
            source: 'actionproxy.verified-mcp-influence-scope',
            trust: 'trusted',
          },
          source: 'mcp',
        },
      },
      request: {
        action: { executionMode: 'local_mock', protocol: 'mcp', source: { id: 'client_a', type: 'mcp' } },
        agentId: 'mcp-client:client_a',
        requestedBy: 'user_a@example.com',
      },
    });
  });

  it('makes replay stable, conflicts on changed payload, and binds status to tenant and adapter', async () => {
    const harness = await makeHarness();
    const clientA = await initialize(harness.app, { clientId: 'client_a', tenantId: 'tenant_a' });
    const clientANewSession = await initialize(harness.app, { clientId: 'client_a', tenantId: 'tenant_a' });
    const clientB = await initialize(harness.app, { clientId: 'client_b', tenantId: 'tenant_a' });
    const principalB = await initialize(harness.app, {
      clientId: 'client_a', principalId: 'user_b', tenantId: 'tenant_a',
    });
    const tenantB = await initialize(harness.app, { clientId: 'client_a', tenantId: 'tenant_b' });

    const first = await callTool(harness.app, clientA.session, 'same_1', 'docs.search', { query: 'same' }, {
      clientId: 'client_a', tenantId: 'tenant_a',
    });
    const replay = await callTool(harness.app, clientA.session, 'same_1', 'docs.search', { query: 'same' }, {
      clientId: 'client_a', tenantId: 'tenant_a',
    });
    const conflict = await callTool(harness.app, clientA.session, 'same_1', 'docs.search', { query: 'changed' }, {
      clientId: 'client_a', tenantId: 'tenant_a',
    });
    const toolCallId = first.result.structuredContent.actionproxy.toolCallId as string;

    expect(replay.result.structuredContent.actionproxy.toolCallId).toBe(toolCallId);
    expect(conflict.result).toMatchObject({ isError: true, structuredContent: { actionproxy: { code: 'idempotency_conflict' } } });
    expect(harness.service.dispatches).toBe(1);

    const crossAdapter = await callTool(harness.app, clientB.session, 'status_b', 'actionproxy.get_action_status', { toolCallId }, {
      clientId: 'client_b', tenantId: 'tenant_a',
    });
    const crossSession = await callTool(
      harness.app,
      clientANewSession.session,
      'status_session',
      'actionproxy.get_action_status',
      { toolCallId },
      { clientId: 'client_a', tenantId: 'tenant_a' },
    );
    const crossPrincipal = await callTool(
      harness.app,
      principalB.session,
      'status_principal',
      'actionproxy.get_action_status',
      { toolCallId },
      { clientId: 'client_a', principalId: 'user_b', tenantId: 'tenant_a' },
    );
    const crossTenant = await callTool(harness.app, tenantB.session, 'status_tenant', 'actionproxy.get_action_status', { toolCallId }, {
      clientId: 'client_a', tenantId: 'tenant_b',
    });
    expect(crossAdapter.result).toMatchObject({ isError: true, structuredContent: { actionproxy: { code: 'forbidden' } } });
    expect(crossSession.result).toMatchObject({ isError: true, structuredContent: { actionproxy: { code: 'forbidden' } } });
    expect(crossPrincipal.result).toMatchObject({ isError: true, structuredContent: { actionproxy: { code: 'forbidden' } } });
    expect(crossTenant.result).toMatchObject({ isError: true, structuredContent: { actionproxy: { code: 'forbidden' } } });
    expect(harness.service.dispatches).toBe(1);
  });

  it.each([
    {
      label: 'session evidence',
      mutate: (toolCall: any) => {
        toolCall.decisionTrace.canonicalRequestEvidence.session.value.sessionId = `influence_${'0'.repeat(64)}`;
      },
    },
    {
      label: 'tenant evidence',
      mutate: (toolCall: any) => {
        toolCall.decisionTrace.canonicalRequestEvidence.tenant.value.id = 'tenant_forged';
      },
    },
    {
      label: 'action envelope',
      mutate: (toolCall: any) => {
        toolCall.actionEnvelope.source.id = 'client_forged';
      },
    },
  ])('denies streamable status when canonical $label is corrupted', async ({ mutate }) => {
    const harness = await makeHarness();
    const { session } = await initialize(harness.app);
    const submitted = await callTool(harness.app, session, 'corrupt_submit', 'docs.search', { query: 'same' });
    const toolCallId = submitted.result.structuredContent.actionproxy.toolCallId as string;
    const stored = harness.service.toolCalls.get(toolCallId);
    expect(stored).toBeDefined();
    mutate(stored!);

    const status = await callTool(
      harness.app,
      session,
      'corrupt_status',
      'actionproxy.get_action_status',
      { toolCallId },
    );

    expect(status.result).toMatchObject({
      isError: true,
      structuredContent: { actionproxy: { code: 'forbidden' } },
    });
  });

  it('rejects forged metadata, ambiguous framing, bad media/session/origin, and missing scopes before dispatch', async () => {
    const harness = await makeHarness();
    const { session } = await initialize(harness.app);
    const baseline = harness.service.submitCount;

    const forged = await callTool(harness.app, session, 'forged_1', 'docs.search', {
      _chatgptWork: { workspaceId: 'forged' },
      actor: 'admin',
      agentVerification: 'externally_verified',
      environment: 'hosted',
      query: 'refunds',
      sourceProtocol: 'custom',
      trustedPolicyContext: { risk: 'safe' },
    });
    expect(forged.error).toMatchObject({ code: -32602 });
    expect(harness.service.submitCount).toBe(baseline);

    const duplicate = await harness.app.inject({
      headers: mcpHeaders(session),
      method: 'POST',
      payload: '{"jsonrpc":"2.0","id":"dup","method":"tools/list","method":"tools/call"}',
      url: '/mcp',
    });
    expect(duplicate.statusCode).toBe(400);

    const batch = await harness.app.inject({
      headers: mcpHeaders(session),
      method: 'POST',
      payload: [{ id: 'batch', jsonrpc: '2.0', method: 'tools/list' }],
      url: '/mcp',
    });
    expect(batch.json()).toMatchObject({ error: { code: -32600 } });
    expect((await harness.app.inject({ headers: authHeaders(), method: 'POST', payload: {}, url: '/mcp' })).statusCode).toBe(406);
    expect((await harness.app.inject({
      headers: { ...authHeaders(), accept, 'content-type': 'text/plain' }, method: 'POST', payload: '{}', url: '/mcp',
    })).statusCode).toBe(415);

    const badSessionResponse = await mcpRequest(
      harness.app,
      `${session}tampered`,
      { id: 'bad_session', jsonrpc: '2.0', method: 'tools/list', params: {} },
    );
    expect(badSessionResponse.statusCode).toBe(400);
    expect(badSessionResponse.json().error).toMatchObject({ code: -32001, data: { retrySafe: false } });
    const missingSession = await harness.app.inject({
      headers: { ...authHeaders(), accept, 'content-type': 'application/json', 'mcp-protocol-version': MCP_PROTOCOL_VERSION },
      method: 'POST',
      payload: { id: 'missing_session', jsonrpc: '2.0', method: 'tools/list', params: {} },
      url: '/mcp',
    });
    expect(missingSession.statusCode).toBe(400);

    const badOrigin = await harness.app.inject({
      headers: { ...mcpHeaders(session), origin: 'https://evil.example' },
      method: 'POST',
      payload: { id: 'origin', jsonrpc: '2.0', method: 'tools/list', params: {} },
      url: '/mcp',
    });
    expect(badOrigin.statusCode).toBe(403);

    const readOnly = await initialize(harness.app, { scopes: ['tool_call:read'] });
    const insufficient = await mcpRequest(
      harness.app,
      readOnly.session,
      { id: 'scope', jsonrpc: '2.0', method: 'tools/call', params: { arguments: { query: 'x' }, name: 'docs.search' } },
      { scopes: ['tool_call:read'] },
    );
    expect(insufficient.statusCode).toBe(403);
    expect(insufficient.json()).toMatchObject({ error: 'insufficient_scope', scope: 'tool_call:submit' });
    expect(harness.service.submitCount).toBe(baseline);
  });

  it('bounds output, fails closed on provider failure, and reports timeout as non-retryable without adapter retry', async () => {
    const huge = await makeHarness({ hugeResult: true, maxResponseBytes: 1024 });
    const hugeSession = await initialize(huge.app);
    const oversized = await callTool(huge.app, hugeSession.session, 'huge_1', 'docs.search', { query: 'large' });
    expect(oversized.error).toMatchObject({ code: -32003, data: { code: 'response_too_large', retrySafe: false } });
    expect(huge.service.dispatches).toBe(1);

    const failed = await makeHarness({ providerFailure: true });
    const failedSession = await initialize(failed.app);
    const providerFailure = await callTool(failed.app, failedSession.session, 'provider_1', 'docs.search', { query: 'x' });
    expect(providerFailure.result).toMatchObject({
      isError: true,
      structuredContent: { actionproxy: { decision: 'deny', status: 'blocked' } },
    });
    expect(failed.service.dispatches).toBe(0);

    const slow = await makeHarness({ delayMs: 30, requestTimeoutMs: 5, providerFailure: true });
    const slowSession = await initialize(slow.app);
    const timedOut = await callTool(slow.app, slowSession.session, 'timeout_1', 'docs.search', { query: 'x' });
    expect(timedOut.error).toMatchObject({ code: -32002, data: { code: 'mcp_request_timeout', retrySafe: false } });
    expect(slow.service.submitCount).toBe(1);
    expect(slow.service.dispatches).toBe(0);
  });

  it('uses a server-injected tunnel principal without OAuth presentation or caller-header identity', async () => {
    let additionalContext: McpAdditionalToolContext | undefined;
    let resolvedPrincipal = {
      ...auth({
        clientId: 'tunnel_client',
        principalId: 'tunnel_user',
        scopes: ['tool_call:read', 'tool_call:submit'],
        tenantId: 'tenant_a',
      }),
      authProvider: 'tunnel_single_user',
    } as AuthContext & { clientId: string };
    const requestAuthentication: McpRequestAuthentication = {
      oauthPresentation: 'none',
      resolvePrincipal: () => resolvedPrincipal,
    };
    const harness = await makeHarness({
      additionalTools: [testAdditionalTool((context) => {
        additionalContext = context;
      })],
      requestAuthentication,
    });

    for (const url of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
      const metadata = await harness.app.inject({ method: 'GET', url });
      expect(metadata.statusCode, url).toBe(404);
      expect(metadata.headers['www-authenticate'], url).toBeUndefined();
    }

    const initialized = await initialize(harness.app, {
      clientId: 'caller-forged-client',
      principalId: 'caller-forged-principal',
      tenantId: 'caller-forged-tenant',
    });
    expect(initialized.response.statusCode).toBe(200);

    const listed = await callRpc(harness.app, initialized.session, 'tunnel_list', 'tools/list', {});
    expect(listed.result.tools).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'docs.search', securitySchemes: [{ type: 'noauth' }] }),
      expect.objectContaining({ name: 'actionproxy.test.read', securitySchemes: [{ type: 'noauth' }] }),
    ]));
    const additional = await callTool(
      harness.app,
      initialized.session,
      'tunnel_additional',
      'actionproxy.test.read',
      {},
      {
        clientId: 'caller-forged-client',
        principalId: 'caller-forged-principal',
        tenantId: 'caller-forged-tenant',
      },
    );
    expect(additional.result).toMatchObject({ structuredContent: { ok: true } });
    expect(additionalContext).toMatchObject({
      adapterId: 'tunnel_client',
      agentId: 'mcp-client:tunnel_client',
      auth: {
        authProvider: 'tunnel_single_user',
        clientId: 'tunnel_client',
        principalId: 'tunnel_user',
        workspaceId: 'tenant_a',
      },
      idempotencyKey: expect.stringMatching(/^mcp_[a-f0-9]{64}$/u),
      ingress: {
        adapterId: 'tunnel_client',
        adapterSource: 'actionproxy.mcp-request-authentication.tunnel-single-user',
        adapterTrust: 'trusted',
        agent: {
          id: 'mcp-client:tunnel_client',
          name: 'Server-authenticated single-user MCP tunnel client',
          source: 'actionproxy.mcp-request-authentication.tunnel-single-user',
          trust: 'derived',
        },
        session: {
          sessionId: expect.stringMatching(/^influence_[a-f0-9]{64}$/u),
          source: 'actionproxy.verified-mcp-influence-scope',
          trust: 'trusted',
        },
      },
      source: { id: 'tunnel_client', name: 'Authenticated Single-User MCP Tunnel', type: 'mcp' },
    });
    expect(additionalContext?.ingress.session?.sessionId).not.toBe(initialized.session);
    const submitted = await callTool(
      harness.app,
      initialized.session,
      'tunnel_submit',
      'docs.search',
      { query: 'trusted tunnel' },
      {
        clientId: 'caller-forged-client',
        principalId: 'caller-forged-principal',
        tenantId: 'caller-forged-tenant',
      },
    );
    expect(submitted.result).toMatchObject({ structuredContent: { actionproxy: { status: 'executed' } } });
    expect(harness.service.lastSubmission?.options.ingress).toEqual(additionalContext?.ingress);
    expect(harness.service.lastSubmission?.request.agentId).toBe(additionalContext?.agentId);
    expect(harness.service.lastSubmission?.request.action).toMatchObject({ source: additionalContext?.source });
    expect(harness.service.lastSubmission).toMatchObject({
      options: {
        auth: { clientId: 'tunnel_client', principalId: 'tunnel_user', workspaceId: 'tenant_a' },
        ingress: {
          adapterId: 'tunnel_client',
          adapterSource: 'actionproxy.mcp-request-authentication.tunnel-single-user',
          adapterTrust: 'trusted',
          agent: {
            name: 'Server-authenticated single-user MCP tunnel client',
            source: 'actionproxy.mcp-request-authentication.tunnel-single-user',
          },
        },
      },
      request: {
        action: {
          source: { id: 'tunnel_client', name: 'Authenticated Single-User MCP Tunnel', type: 'mcp' },
        },
        requestedBy: 'user_a@example.com',
      },
    });

    resolvedPrincipal = { ...resolvedPrincipal, clientId: 'different_tunnel_client' };
    const rebound = await mcpRequest(harness.app, initialized.session, {
      id: 'rebound',
      jsonrpc: '2.0',
      method: 'tools/list',
      params: {},
    });
    expect(rebound.statusCode).toBe(400);
    expect(rebound.json().error).toMatchObject({
      code: -32001,
      data: { code: 'mcp_session_binding_mismatch' },
    });
  });

  it('fails closed on invalid injected principals without OAuth bearer challenges', async () => {
    const invalid = await makeHarness({
      requestAuthentication: {
        oauthPresentation: 'none',
        resolvePrincipal: () => ({
          ...auth({ clientId: 'client', principalId: 'principal', scopes: [], tenantId: 'tenant' }),
          authProvider: 'tunnel_single_user',
        }) as AuthContext & { clientId: string },
      },
    });
    const invalidResponse = await initialize(invalid.app);
    expect(invalidResponse.response.statusCode).toBe(401);
    expect(invalidResponse.response.headers['www-authenticate']).toBeUndefined();

    const malformedIdentity = await makeHarness({
      requestAuthentication: {
        oauthPresentation: 'none',
        resolvePrincipal: () => ({
          ...auth({
            clientId: 'client',
            principalId: 'principal',
            scopes: ['tool_call:read', 'tool_call:submit'],
            tenantId: 'tenant',
          }),
          authProvider: 'caller_header',
          groups: ['group-a', 'group-a'],
        }) as unknown as AuthContext & { clientId: string },
      },
    });
    const malformedResponse = await initialize(malformedIdentity.app);
    expect(malformedResponse.response.statusCode).toBe(401);
    expect(malformedResponse.response.headers['www-authenticate']).toBeUndefined();

    const readOnly = await makeHarness({
      requestAuthentication: {
        oauthPresentation: 'none',
        resolvePrincipal: () => ({
          ...auth({ clientId: 'client', principalId: 'principal', scopes: ['tool_call:read'], tenantId: 'tenant_a' }),
          authProvider: 'tunnel_single_user',
        }) as AuthContext & { clientId: string },
      },
    });
    const initialized = await initialize(readOnly.app);
    const insufficient = await mcpRequest(readOnly.app, initialized.session, {
      id: 'insufficient',
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { arguments: { query: 'x' }, name: 'docs.search' },
    });
    expect(insufficient.statusCode).toBe(403);
    expect(insufficient.headers['www-authenticate']).toBeUndefined();
    expect(insufficient.json()).toMatchObject({ error: 'insufficient_scope', scope: 'tool_call:submit' });
  });
});

interface HarnessOptions {
  additionalTools?: readonly McpAdditionalTool[];
  delayMs?: number;
  hugeResult?: boolean;
  maxResponseBytes?: number;
  providerFailure?: boolean;
  projectAdditionalToolError?: (error: unknown) => McpExtensionErrorProjection | undefined;
  rateLimitMax?: number;
  requestAuthentication?: McpRequestAuthentication;
  requestTimeoutMs?: number;
  submitError?: unknown;
}

async function makeHarness(options: HarnessOptions = {}) {
  const config = testConfig(options);
  const service = new FakeActionProxy(options);
  const app = Fastify({ bodyLimit: 1024 * 1024, logger: false });
  const securityAuthentication = options.requestAuthentication ?? {
    oauthPresentation: 'protected-resource',
    resolvePrincipal: (request) => {
      const clientId = header(request, 'x-test-client-id') ?? 'client_a';
      const principalId = header(request, 'x-test-principal-id') ?? 'user_a';
      const tenantId = header(request, 'x-test-tenant-id') ?? 'tenant_a';
      const scopes = (header(request, 'x-test-scopes') ?? 'tool_call:read tool_call:submit').split(' ').filter(Boolean);
      return auth({ clientId, principalId, scopes, tenantId }) as AuthContext & { clientId: string };
    },
  } satisfies McpRequestAuthentication;
  registerSecurityHooks(app, config, {} as AuthService, {
    mcpRequestAuthentication: securityAuthentication,
  });
  await registerMcpRoutes(app, {
    actionProxy: service as unknown as Pick<ActionProxyService, 'getToolCall' | 'submitToolCall'>,
    additionalTools: options.additionalTools,
    config,
    redaction: {},
    projectAdditionalToolError: options.projectAdditionalToolError,
    requestAuthentication: options.requestAuthentication,
    store: service as unknown as Pick<Store, 'getApprovalByToolCallId' | 'getExecutionAttemptByToolCallId'>,
  });
  apps.push(app);
  return { app, service };
}

function testAdditionalTool(onInvoke?: (context: McpAdditionalToolContext) => void): McpAdditionalTool {
  return {
    annotations: { destructiveHint: false, idempotentHint: true, openWorldHint: false, readOnlyHint: true },
    description: 'Read a deterministic test value.',
    inputSchema: { additionalProperties: false, properties: {}, type: 'object' },
    invoke: async (_input, context) => {
      onInvoke?.(context);
      return { contentText: 'ok', structuredContent: { ok: true } };
    },
    name: 'actionproxy.test.read',
    requiredScope: 'tool_call:read',
    title: 'Test Read',
  };
}

class FakeActionProxy {
  readonly attempts = new Map<string, ExecutionAttemptRecordV1>();
  readonly approvals = new Map<string, ApprovalRecord>();
  readonly reservations = new Map<string, { request: string; toolCall: ToolCallRecord }>();
  readonly toolCalls = new Map<string, ToolCallRecord>();
  dispatches = 0;
  lastSubmission?: { options: Record<string, unknown>; request: Record<string, unknown> };
  submitCount = 0;

  constructor(private readonly options: HarnessOptions) {}

  async submitToolCall(request: any, options: any): Promise<{ approval?: ApprovalRecord; toolCall: ToolCallRecord }> {
    if (this.options.submitError) throw this.options.submitError;
    this.submitCount += 1;
    this.lastSubmission = { options, request };
    if (this.options.delayMs) await new Promise((resolve) => setTimeout(resolve, this.options.delayMs));
    const key = options.idempotencyKey as string;
    const requestIdentity = JSON.stringify(request);
    const existing = this.reservations.get(key);
    if (existing) {
      if (existing.request !== requestIdentity) throw new ConflictError('Idempotency conflict.');
      const approval = this.approvals.get(existing.toolCall.id);
      return approval ? { approval, toolCall: existing.toolCall } : { toolCall: existing.toolCall };
    }

    const id = `toolcall_${this.toolCalls.size + 1}`;
    const decision = this.options.providerFailure
      ? 'deny'
      : request.toolName === 'dangerous.delete_customer'
        ? 'deny'
        : request.toolName === 'gmail.send_email'
          ? 'require_approval'
          : 'allow';
    const status = decision === 'deny' ? 'blocked' : decision === 'require_approval' ? 'pending_approval' : 'executed';
    if (status === 'executed') this.dispatches += 1;
    const toolCall = fakeToolCall({
      auth: options.auth,
      decision,
      id,
      influenceScopeId: options.ingress.session.sessionId,
      input: request.input,
      status,
      toolName: request.toolName,
    });
    if (status === 'executed') {
      toolCall.result = this.options.hugeResult
        ? { content: 'x'.repeat(20_000), grant: { nonce: 'do-not-expose', signature: 'do-not-expose' } }
        : { grant: { nonce: 'do-not-expose', signature: 'do-not-expose' }, ok: true, query: request.input.query };
      this.attempts.set(id, fakeAttempt(id));
    }
    let approval: ApprovalRecord | undefined;
    if (status === 'pending_approval') {
      approval = { id: `approval_${id}`, status: 'pending', toolCallId: id, workspaceId: options.auth.workspaceId } as ApprovalRecord;
      this.approvals.set(id, approval);
    }
    this.toolCalls.set(id, toolCall);
    this.reservations.set(key, { request: requestIdentity, toolCall });
    return approval ? { approval, toolCall } : { toolCall };
  }

  async getToolCall(id: string, authContext: AuthContext): Promise<ToolCallRecord> {
    const toolCall = this.toolCalls.get(id);
    if (!toolCall || toolCall.workspaceId !== authContext.workspaceId) throw new ForbiddenError('Foreign tenant.');
    return toolCall;
  }

  async getApprovalByToolCallId(toolCallId: string): Promise<ApprovalRecord | undefined> {
    return this.approvals.get(toolCallId);
  }

  async getExecutionAttemptByToolCallId(_workspaceId: string, toolCallId: string): Promise<ExecutionAttemptRecordV1 | undefined> {
    return this.attempts.get(toolCallId);
  }

  approveWithEditedInput(toolCallId: string, input: JsonObject): void {
    const toolCall = this.toolCalls.get(toolCallId)!;
    toolCall.input = input;
    toolCall.status = 'executed';
    toolCall.result = { ok: true, ...input };
    this.dispatches += 1;
    const approval = this.approvals.get(toolCallId)!;
    approval.status = 'approved';
    this.attempts.set(toolCallId, fakeAttempt(toolCallId));
  }
}

function fakeToolCall(input: {
  auth: AuthContext & { clientId: string };
  decision: 'allow' | 'deny' | 'require_approval';
  id: string;
  influenceScopeId: string;
  input: JsonObject;
  status: ToolCallRecord['status'];
  toolName: string;
}): ToolCallRecord {
  return {
    actionEnvelope: {
      actor: { id: input.auth.principalId, type: 'user' },
      agent: { id: `mcp-client:${input.auth.clientId}` },
      context: { reason: 'MCP test' },
      envelopeHash: 'envelope_hash',
      executionMode: 'local_mock',
      input: input.input,
      inputHash: 'input_hash',
      operation: { name: input.toolName },
      protocol: 'mcp',
      source: { id: input.auth.clientId, type: 'mcp' },
      toolName: input.toolName,
      version: 'actionproxy.action.v1',
    },
    agentId: `mcp-client:${input.auth.clientId}`,
    createdAt: '2026-07-12T00:00:00.000Z',
    decision: input.decision,
    decisionTrace: {
      canonicalRequestEvidence: {
        session: {
          present: true,
          provenance: { source: 'actionproxy.verified-mcp-influence-scope', trust: 'trusted' },
          value: { sessionId: input.influenceScopeId },
        },
        source: { present: true, value: { adapterId: input.auth.clientId, type: 'mcp' } },
        sourceProtocol: { present: true, value: 'mcp' },
        tenant: { present: true, value: { id: input.auth.workspaceId } },
      },
      decisionV1: { decisionId: `decision_${input.id}`, reasonCodes: [`policy_outcome_${input.decision}`] },
    },
    id: input.id,
    influenceScopeId: input.influenceScopeId,
    input: input.input,
    metadata: {},
    reason: 'MCP test',
    requestedBy: input.auth.principalId,
    requestedByAuth: input.auth,
    status: input.status,
    toolName: input.toolName,
    updatedAt: '2026-07-12T00:00:00.000Z',
    workspaceId: input.auth.workspaceId,
  };
}

function fakeAttempt(toolCallId: string): ExecutionAttemptRecordV1 {
  return {
    attemptNumber: 1,
    binding: {
      actionEnvelopeHash: 'envelope_hash', approvalAuthorizationHash: null, approvalAuthorizationNonce: null,
      approvalId: null, canonicalActionRequestHash: 'canonical_hash', canonicalActionRequestVersion: 'actionproxy.action-request.v1',
      canonicalDecisionInputHash: 'decision_hash', decisionId: `decision_${toolCallId}`, decisionVersion: 'actionproxy.decision.v1',
      policyVersionHash: 'policy_hash', receiptHash: 'receipt_hash', receiptId: 'receipt_id',
    },
    completedAt: '2026-07-12T00:00:00.000Z',
    dispatchedAt: '2026-07-12T00:00:00.000Z',
    executionMode: 'local_mock',
    executorId: 'actionproxy.local-tool-registry',
    id: `attempt_${toolCallId}`,
    inputHash: 'input_hash',
    outcome: {
      certainty: 'known', errorClass: null, errorCode: null, errorMessage: null, recordedAt: '2026-07-12T00:00:00.000Z',
      remediationHash: null, resultDeliveryHash: null, resultHash: 'result_hash', retryDisposition: 'none', status: 'succeeded',
    },
    providerIdempotency: 'none',
    reservedAt: '2026-07-12T00:00:00.000Z',
    reservationOwner: 'owner',
    retryPolicy: 'never_automatic',
    state: 'succeeded',
    toolCallId,
    updatedAt: '2026-07-12T00:00:00.000Z',
    version: 'actionproxy.execution-attempt.v1',
    workspaceId: 'tenant_a',
  };
}

function testConfig(options: HarnessOptions): ResolvedAppConfig {
  return withConfigDefaults({
    auth: {
      allowedCorsOrigins: [],
      mode: 'oidc_jwt',
      oidc: {
        audience: 'https://proxy.example/mcp', emailClaim: 'email', groupsClaim: 'groups', issuer: 'https://issuer.example/',
        jwksJson: '{"keys":[]}', nameClaim: 'name', scopesClaim: 'scope',
      },
      rateLimit: { max: options.rateLimitMax ?? 1000, windowMs: 60_000 },
      slackUserMap: {},
      workspaceId: 'tenant_a',
    },
    dataDir: '/tmp/actionproxy-mcp-route-test',
    deployment: { mode: 'self_hosted' },
    host: '127.0.0.1',
    logLevel: 'silent',
    mcp: {
      stdioDiscoveryEnabled: false,
      streamableHttp: {
        allowedOrigins: ['https://chatgpt.com'],
        authorizationServer: 'https://issuer.example/',
        enabled: true,
        maxResponseBytes: options.maxResponseBytes ?? 256 * 1024,
        requestTimeoutMs: options.requestTimeoutMs ?? 1_000,
        resourceUrl: 'https://proxy.example/mcp',
        sessionSecret,
        sessionTtlMs: 60_000,
      },
    },
    policyPath: path.resolve('src/policies/default.policy.yaml'),
    port: 0,
  });
}

async function initialize(
  app: FastifyInstance,
  identity: TestIdentity = {},
): Promise<{ response: LightMyRequestResponse; session: string }> {
  const response = await app.inject({
    headers: {
      ...authHeaders(identity),
      accept,
      'content-type': 'application/json',
    },
    method: 'POST',
    payload: {
      id: 'initialize_1',
      jsonrpc: '2.0',
      method: 'initialize',
      params: {
        capabilities: {},
        clientInfo: { name: 'MCP test client', version: '1.0.0' },
        protocolVersion: MCP_PROTOCOL_VERSION,
      },
    },
    url: '/mcp',
  });
  return { response, session: String(response.headers['mcp-session-id'] ?? '') };
}

async function callTool(
  app: FastifyInstance,
  session: string,
  id: string,
  name: string,
  args: JsonObject,
  identity: TestIdentity = {},
): Promise<any> {
  return callRpc(app, session, id, 'tools/call', { arguments: args, name }, identity);
}

async function callRpc(
  app: FastifyInstance,
  session: string,
  id: string,
  method: string,
  params: unknown,
  identity: TestIdentity = {},
): Promise<any> {
  const response = await mcpRequest(app, session, { id, jsonrpc: '2.0', method, params }, identity);
  return response.json();
}

async function mcpRequest(
  app: FastifyInstance,
  session: string,
  payload: unknown,
  identity: TestIdentity = {},
): Promise<LightMyRequestResponse> {
  return app.inject({
    headers: mcpHeaders(session, identity),
    method: 'POST',
    payload: payload as InjectOptions['payload'],
    url: '/mcp',
  });
}

function mcpHeaders(session: string, identity: TestIdentity = {}) {
  return {
    ...authHeaders(identity),
    accept,
    'content-type': 'application/json',
    'mcp-protocol-version': MCP_PROTOCOL_VERSION,
    'mcp-session-id': session,
  };
}

function authHeaders(identity: TestIdentity = {}) {
  return {
    'x-test-client-id': identity.clientId ?? 'client_a',
    'x-test-principal-id': identity.principalId ?? 'user_a',
    'x-test-scopes': (identity.scopes ?? ['tool_call:read', 'tool_call:submit']).join(' '),
    'x-test-tenant-id': identity.tenantId ?? 'tenant_a',
  };
}

function auth(input: { clientId: string; principalId: string; scopes: string[]; tenantId: string }): AuthContext {
  return {
    authProvider: 'oidc_jwt',
    clientId: input.clientId,
    displayName: 'MCP User',
    email: 'user_a@example.com',
    groups: [],
    principalId: input.principalId,
    principalType: 'user',
    scopes: input.scopes,
    workspaceId: input.tenantId,
  };
}

interface TestIdentity {
  clientId?: string;
  principalId?: string;
  scopes?: string[];
  tenantId?: string;
}

function header(request: { headers: Record<string, unknown> }, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? String(value[0]) : value === undefined ? undefined : String(value);
}
