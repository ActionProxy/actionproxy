import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';

let app: FastifyInstance | undefined;

const policyPath = path.resolve('src/policies/default.policy.yaml');

async function makeApp(options: { localExecutionMode?: 'disabled' | 'mock'; policyPath?: string } = {}) {
  app = await buildApp({
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-route-test-')),
    host: '127.0.0.1',
    localExecution: { mode: options.localExecutionMode ?? 'mock' },
    logLevel: 'silent',
    policyPath: options.policyPath ?? policyPath,
    port: 0,
  });
  return app;
}

async function submit(server: FastifyInstance, toolName: string, input: Record<string, unknown>, reason: string) {
  return server.inject({
    method: 'POST',
    payload: {
      agentId: 'demo-agent',
      input,
      reason,
      requestedBy: 'dev@example.com',
      toolName,
    },
    url: '/v1/tool-calls',
  });
}

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('tool call routes', () => {
  it('adds decision v1 while preserving legacy allow, approval, and deny response fields', async () => {
    const server = await makeApp();
    const scenarios = [
      { decision: 'allow', status: 'executed', toolName: 'docs.search', input: { query: 'refund' } },
      {
        decision: 'require_approval',
        status: 'pending_approval',
        toolName: 'gmail.send_email',
        input: { to: 'customer@example.com' },
      },
      { decision: 'deny', status: 'blocked', toolName: 'dangerous.delete_customer', input: { customerId: 'cus_1' } },
    ] as const;

    for (const scenario of scenarios) {
      const response = await submit(server, scenario.toolName, scenario.input, `Exercise ${scenario.decision}`);
      const body = response.json();

      expect(response.statusCode).toBe(200);
      expect(body).toMatchObject({
        decision: scenario.decision,
        id: expect.any(String),
        reason: expect.any(String),
        risk: expect.any(String),
        status: scenario.status,
      });
      expect(body.toolCall.decisionTrace.decisionV1).toMatchObject({
        decisionId: expect.stringMatching(/^decision_[a-f0-9]{64}$/u),
        decisionInputHash: body.toolCall.canonicalDecisionInputHash,
        outcome: scenario.decision,
        policy: {
          digest: body.toolCall.policyVersionHash,
          provider: { id: 'actionproxy.yaml', status: 'ok', version: 'actionproxy.yaml-provider.v1' },
          version: body.toolCall.policyVersionId,
        },
        requestId: body.id,
        tenantId: 'default',
        version: 'actionproxy.decision.v1',
      });
      expect(body.toolCall.decision).toBe(scenario.decision);
      expect(body.toolCall.actionEnvelopeHash).toEqual(expect.any(String));
    }
  });

  it('exposes additive execution attempts without changing the tool-call response contract', async () => {
    const server = await makeApp();
    const submitted = await submit(server, 'docs.search', { query: 'attempt evidence' }, 'Read attempt evidence');
    const body = submitted.json();

    expect(submitted.statusCode).toBe(200);
    expect(body).toMatchObject({
      decision: 'allow',
      id: expect.any(String),
      status: 'executed',
      toolCall: { id: expect.any(String), status: 'executed' },
    });
    expect(body).not.toHaveProperty('attempt');
    expect(body.toolCall).not.toHaveProperty('executionAttempt');

    const response = await server.inject({
      method: 'GET',
      url: `/v1/tool-calls/${body.id}/execution-attempts`,
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      attempts: [
        {
          attemptNumber: 1,
          binding: {
            canonicalActionRequestHash: body.toolCall.canonicalActionRequestHash,
            canonicalDecisionInputHash: body.toolCall.canonicalDecisionInputHash,
            decisionId: body.toolCall.decisionTrace.decisionV1.decisionId,
          },
          executionMode: 'local_mock',
          inputHash: body.toolCall.inputHash,
          outcome: { certainty: 'known', retryDisposition: 'none', status: 'succeeded' },
          state: 'succeeded',
          toolCallId: body.id,
          version: 'actionproxy.execution-attempt.v1',
          workspaceId: 'default',
        },
      ],
    });
  });

  it.each([
    {
      actionExecutionMode: 'external_grant' as const,
      expectedAttemptMode: 'external_grant',
      expectedAttemptState: 'reserved',
      expectedStatus: 'authorized',
      metadata: undefined,
      name: 'explicit external mode without legacy metadata',
    },
    {
      actionExecutionMode: 'local_mock' as const,
      expectedAttemptMode: 'local_mock',
      expectedAttemptState: 'succeeded',
      expectedStatus: 'executed',
      metadata: { actionproxyExecution: 'external' },
      name: 'explicit local mode over conflicting legacy metadata',
    },
  ])('keeps canonical evidence and allow-path dispatch aligned for $name', async (scenario) => {
    const server = await makeApp();
    const response = await server.inject({
      method: 'POST',
      payload: {
        action: { executionMode: scenario.actionExecutionMode },
        agentId: 'mode-precedence-agent',
        input: { query: scenario.name },
        metadata: scenario.metadata,
        reason: 'Prove execution-mode precedence',
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });
    const body = response.json();

    expect(response.statusCode).toBe(200);
    expect(body.toolCall).toMatchObject({
      actionEnvelope: { executionMode: scenario.actionExecutionMode },
      status: scenario.expectedStatus,
    });
    const attempts = await server.inject({
      method: 'GET',
      url: `/v1/tool-calls/${body.id}/execution-attempts`,
    });
    expect(attempts.json().attempts).toMatchObject([
      { executionMode: scenario.expectedAttemptMode, state: scenario.expectedAttemptState },
    ]);
  });

  it.each([
    {
      actionExecutionMode: 'external_grant' as const,
      expectedAttemptMode: 'external_grant',
      expectedAttemptState: 'reserved',
      expectedStatus: 'authorized',
      metadata: undefined,
      name: 'explicit external mode without legacy metadata',
    },
    {
      actionExecutionMode: 'local_mock' as const,
      expectedAttemptMode: 'local_mock',
      expectedAttemptState: 'succeeded',
      expectedStatus: 'executed',
      metadata: { actionproxyExecution: 'external' },
      name: 'explicit local mode over conflicting legacy metadata',
    },
  ])('keeps canonical evidence and post-approval dispatch aligned for $name', async (scenario) => {
    const server = await makeApp();
    const submitted = await server.inject({
      method: 'POST',
      payload: {
        action: { executionMode: scenario.actionExecutionMode },
        agentId: 'mode-precedence-agent',
        input: { body: 'Body', subject: 'Subject', to: 'customer@example.com' },
        metadata: scenario.metadata,
        reason: 'Prove approved execution-mode precedence',
        requestedBy: 'dev@example.com',
        toolName: 'gmail.send_email',
      },
      url: '/v1/tool-calls',
    });
    const submittedBody = submitted.json();
    expect(submittedBody.status).toBe('pending_approval');

    const approved = await server.inject({
      method: 'POST',
      payload: { approvedBy: 'manager@example.com' },
      url: `/v1/approvals/${submittedBody.approval.id}/approve`,
    });
    expect(approved.statusCode).toBe(200);
    expect(approved.json().toolCall).toMatchObject({
      actionEnvelope: { executionMode: scenario.actionExecutionMode },
      status: scenario.expectedStatus,
    });
    const attempts = await server.inject({
      method: 'GET',
      url: `/v1/tool-calls/${submittedBody.id}/execution-attempts`,
    });
    expect(attempts.json().attempts).toMatchObject([
      { executionMode: scenario.expectedAttemptMode, state: scenario.expectedAttemptState },
    ]);
  });

  it('atomically replays concurrent keyed HTTP submissions and conflicts on another payload', async () => {
    const server = await makeApp();
    const payload = {
      agentId: 'idempotency-agent',
      input: { query: 'one logical action' },
      reason: 'Prove atomic keyed submission',
      requestedBy: 'dev@example.com',
      toolName: 'docs.search',
    };
    const responses = await Promise.all(
      Array.from({ length: 12 }, () =>
        server.inject({
          headers: { 'idempotency-key': 'http-concurrent-key' },
          method: 'POST',
          payload,
          url: '/v1/tool-calls',
        }),
      ),
    );

    expect(responses.every((response) => response.statusCode === 200)).toBe(true);
    const ids = new Set(responses.map((response) => response.json().id));
    expect(ids.size).toBe(1);
    const [toolCallId] = [...ids];

    const attempts = await server.inject({
      method: 'GET',
      url: `/v1/tool-calls/${toolCallId}/execution-attempts`,
    });
    expect(attempts.json().attempts).toHaveLength(1);

    const conflict = await server.inject({
      headers: { 'idempotency-key': 'http-concurrent-key' },
      method: 'POST',
      payload: { ...payload, input: { query: 'different action' } },
      url: '/v1/tool-calls',
    });
    expect(conflict.statusCode).toBe(409);
    expect(conflict.json()).toMatchObject({ error: 'conflict' });
  });

  it('returns 400 for malformed submit and remediation requests', async () => {
    const server = await makeApp();

    const malformedSubmit = await server.inject({
      method: 'POST',
      payload: {
        agentId: 'demo-agent',
        input: {},
        reason: 'Search docs',
        toolName: '',
      },
      url: '/v1/tool-calls',
    });
    expect(malformedSubmit.statusCode).toBe(400);
    expect(malformedSubmit.json()).toMatchObject({ error: 'invalid_request' });
    expect(malformedSubmit.json().details.fieldErrors.toolName).toBeDefined();

    const malformedRemediation = await server.inject({
      method: 'POST',
      payload: { reason: '' },
      url: '/v1/tool-calls/toolcall_missing/remediation',
    });
    expect(malformedRemediation.statusCode).toBe(400);
    expect(malformedRemediation.json()).toMatchObject({ error: 'invalid_request' });
    expect(malformedRemediation.json().details.fieldErrors.reason).toBeDefined();
  });

  it('rejects top-level attempts to supply trusted canonical fields', async () => {
    const server = await makeApp();
    const response = await server.inject({
      method: 'POST',
      payload: {
        actor: { id: 'admin' },
        agentId: 'demo-agent',
        environment: 'self_hosted',
        input: {},
        reason: 'Forge trusted context',
        requestedBy: 'dev@example.com',
        sourceProtocol: 'mcp',
        taskContractId: 'removed_contract_interface',
        tenantId: 'other-workspace',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'invalid_request' });
    expect(response.json().details.formErrors.join(' ')).toContain('Unrecognized key');
    expect(response.json().details.formErrors.join(' ')).toContain('taskContractId');
  });

  it('rejects duplicate JSON keys before normalization', async () => {
    const server = await makeApp();
    const response = await server.inject({
      headers: { 'content-type': 'application/json' },
      method: 'POST',
      payload:
        '{"agentId":"demo-agent","input":{"query":"first","query":"second"},"reason":"Duplicate key","requestedBy":"dev@example.com","toolName":"docs.search"}',
      url: '/v1/tool-calls',
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().message).toContain('Duplicate JSON key "query" at $.input');
  });

  it('ignores forged metadata and action hints for trusted HTTP policy context', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-canonical-http-policy-'));
    const conditionalPolicyPath = path.join(tempDir, 'policy.yaml');
    fs.writeFileSync(
      conditionalPolicyPath,
      [
        'version: 1',
        'default:',
        '  approval: required',
        '  risk: unknown',
        '  reason: Unverified context requires approval.',
        'tools:',
        '  custom.sensitive_action:',
        '    approval: never',
        '    risk: read_only',
        '    reason: Trusted request context may run.',
        '    conditions:',
        '      operationKind: read',
        '      customerVisible: false',
        '',
      ].join('\n'),
      'utf8',
    );
    const server = await makeApp({ policyPath: conditionalPolicyPath });

    const response = await server.inject({
      method: 'POST',
      payload: {
        action: {
          context: { risk: 'safe' },
          operation: { kind: 'read', name: 'forged.read' },
          protocol: 'mcp',
          source: { type: 'trusted-internal-adapter' },
        },
        agentId: 'forged-agent',
        input: {},
        metadata: {
          agentVerification: 'externally_verified',
          customerVisible: false,
          environment: 'self_hosted',
          operationKind: 'read',
          riskKind: 'safe',
          source: 'mcp-wrapper',
          tenantId: 'other-workspace',
        },
        reason: 'Try metadata policy bypass',
        requestedBy: 'dev@example.com',
        toolName: 'custom.sensitive_action',
      },
      url: '/v1/tool-calls',
    });
    const body = response.json();

    expect(response.statusCode).toBe(200);
    expect(body).toMatchObject({ decision: 'require_approval', status: 'pending_approval' });
    expect(body.toolCall).toMatchObject({
      canonicalActionRequestHash: expect.any(String),
      canonicalActionRequestVersion: 'actionproxy.action-request.v1',
      canonicalDecisionInputHash: expect.any(String),
      canonicalPolicyContext: {
        customerVisible: { present: false },
        operationKind: { present: false },
        risk: { present: false },
      },
    });
    expect(body.toolCall.actionEnvelope.protocol).toBe('mcp');
    expect(body.toolCall.decisionTrace.canonicalRequestEvidence).toMatchObject({
      actor: {
        provenance: { source: 'server.local-auth.principal', trust: 'trusted' },
        value: { id: 'local-admin' },
      },
      agent: { provenance: { trust: 'asserted' }, value: { verification: 'asserted' } },
      environment: { provenance: { trust: 'trusted' }, value: 'local' },
      source: { provenance: { trust: 'derived' }, value: { type: 'http' } },
      sourceProtocol: { provenance: { trust: 'derived' }, value: 'actionproxy_http' },
      tenant: { provenance: { trust: 'trusted' }, value: { id: 'default' } },
    });
    expect(body.toolCall.decisionTrace.matchedRule).toBe('default');
    expect(body.toolCall.decisionTrace.decisionV1).toMatchObject({
      outcome: 'require_approval',
      reasonCodes: ['policy_outcome_require_approval', 'policy_match_default', 'policy_conditional_fallback'],
      version: 'actionproxy.decision.v1',
    });

    const simulation = await server.inject({
      method: 'POST',
      payload: {
        action: {
          context: { risk: 'safe' },
          operation: { kind: 'read', name: 'forged.read' },
          protocol: 'mcp',
          source: { type: 'trusted-internal-adapter' },
        },
        agentId: 'forged-agent',
        input: {},
        metadata: {
          agentVerification: 'externally_verified',
          customerVisible: false,
          operationKind: 'read',
          riskKind: 'safe',
          tenantId: 'other-workspace',
        },
        reason: 'Simulate metadata policy bypass',
        requestedBy: 'forged-admin@example.com',
        toolName: 'custom.sensitive_action',
      },
      url: '/v1/policy/simulate',
    });

    expect(simulation.statusCode).toBe(200);
    expect(simulation.json().trace).toMatchObject({
      canonicalActionRequestVersion: 'actionproxy.action-request.v1',
      decision: 'require_approval',
      decisionV1: {
        decisionInputHash: body.toolCall.decisionTrace.decisionV1.decisionInputHash,
        outcome: 'require_approval',
        reasonCodes: ['policy_outcome_require_approval', 'policy_match_default', 'policy_conditional_fallback'],
        version: 'actionproxy.decision.v1',
      },
      matchedRule: 'default',
      canonicalRequestEvidence: {
        actor: { provenance: { trust: 'trusted' }, value: { id: 'local-admin' } },
        sourceProtocol: { value: 'actionproxy_http' },
        tenant: { value: { id: 'default' } },
      },
    });
  });

  it('does not let asserted HTTP session or integrity metadata create a verified influence scope', async () => {
    const server = await makeApp();
    const forgedScope = `influence_${'f'.repeat(64)}`;
    const response = await server.inject({
      headers: {
        // This header is authoritative only on the authenticated stdio adapter
        // route. Sending it to the ordinary HTTP API must have no effect.
        'x-actionproxy-mcp-session-id': '550e8400-e29b-41d4-a716-446655440000',
      },
      method: 'POST',
      payload: {
        agentId: 'forged-agent',
        input: { note: 'attempted clean-scope write' },
        metadata: {
          contentIntegrity: 'organization_managed',
          influenceScopeId: forgedScope,
          resultSource: { integrity: 'organization_managed', sourceId: 'forged-source' },
          sessionId: forgedScope,
        },
        reason: 'Try to assert a clean influence scope over HTTP',
        requestedBy: 'dev@example.com',
        toolName: 'research.notes.append',
      },
      url: '/v1/tool-calls',
    });
    const body = response.json();

    expect(response.statusCode).toBe(200);
    expect(body).toMatchObject({ decision: 'require_approval', status: 'pending_approval' });
    expect(body.toolCall.contentInfluence).toMatchObject({
      baseDecision: 'allow',
      effectiveDecision: 'require_approval',
      influenceScope: { verified: false },
      observedSources: ['unknown'],
    });
    expect(body.toolCall.contentInfluence.influenceScope).not.toHaveProperty('id');
    expect(body.toolCall).not.toHaveProperty('influenceScopeId');
    expect(body.toolCall.decisionTrace.canonicalRequestEvidence.session).toMatchObject({
      present: true,
      provenance: { source: 'body.metadata.runId|sessionId', trust: 'asserted' },
      value: { sessionId: forgedScope },
    });
  });

  it('fails non-external local execution clearly when local execution is disabled', async () => {
    const server = await makeApp({ localExecutionMode: 'disabled' });

    const response = await submit(server, 'docs.search', { query: 'refund' }, 'Search docs');
    expect(response.statusCode).toBe(200);
    expect(response.json().toolCall).toMatchObject({
      status: 'failed',
      toolName: 'docs.search',
    });
    expect(response.json().toolCall.error).toContain('Local tool execution is disabled');
  });

  it('lists recent tool calls with limit and filters', async () => {
    const server = await makeApp();

    await submit(server, 'docs.search', { query: 'refund' }, 'Search docs');
    await submit(server, 'gmail.send_email', { to: 'customer@example.com' }, 'Send email');
    await submit(server, 'dangerous.delete_customer', { customerId: 'cus_123' }, 'Test block');

    const limited = await server.inject({ method: 'GET', url: '/v1/tool-calls?limit=2' });
    expect(limited.statusCode).toBe(200);
    expect(limited.json().toolCalls).toHaveLength(2);

    const executed = await server.inject({ method: 'GET', url: '/v1/tool-calls?status=executed' });
    expect(executed.json().toolCalls).toMatchObject([{ status: 'executed', toolName: 'docs.search' }]);

    const denied = await server.inject({ method: 'GET', url: '/v1/tool-calls?decision=deny' });
    expect(denied.json().toolCalls).toMatchObject([{ decision: 'deny', status: 'blocked' }]);

    const email = await server.inject({ method: 'GET', url: '/v1/tool-calls?toolName=gmail.send_email' });
    expect(email.json().toolCalls).toMatchObject([{ decision: 'require_approval', status: 'pending_approval' }]);
  });

  it('filters tool calls by exact asserted session and run before applying limits', async () => {
    const server = await makeApp();
    const submitWithSession = (
      idempotencyKey: string,
      reason: string,
      runId: string,
      sessionId: string,
    ) => server.inject({
      headers: { 'idempotency-key': idempotencyKey },
      method: 'POST',
      payload: {
        agentId: 'forensic-filter-agent',
        input: { query: reason },
        metadata: { runId, sessionId },
        reason,
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });

    const target = await submitWithSession(
      'forensic-target',
      'target session and run',
      'run/target',
      'session target',
    );
    await submitWithSession(
      'forensic-other-session',
      'same run, other session',
      'run/target',
      'session other',
    );
    await submitWithSession(
      'forensic-other-run',
      'same session, other run',
      'run/other',
      'session target',
    );
    await submitWithSession(
      'forensic-newest-unrelated',
      'newest unrelated call',
      'run/newest',
      'session newest',
    );

    const filtered = await server.inject({
      method: 'GET',
      url: '/v1/tool-calls?limit=1&runId=run%2Ftarget&sessionId=session+target',
    });
    const runOnly = await server.inject({
      method: 'GET',
      url: '/v1/tool-calls?runId=run%2Ftarget',
    });
    const sessionOnly = await server.inject({
      method: 'GET',
      url: '/v1/tool-calls?sessionId=session+target',
    });

    expect(filtered.statusCode).toBe(200);
    expect(filtered.json().toolCalls).toEqual([
      expect.objectContaining({ id: target.json().id, reason: 'target session and run' }),
    ]);
    expect(runOnly.json().toolCalls).toHaveLength(2);
    expect(runOnly.json().toolCalls.map((toolCall: { reason: string }) => toolCall.reason)).toEqual(
      expect.arrayContaining(['target session and run', 'same run, other session']),
    );
    expect(sessionOnly.json().toolCalls).toHaveLength(2);
    expect(sessionOnly.json().toolCalls.map((toolCall: { reason: string }) => toolCall.reason)).toEqual(
      expect.arrayContaining(['target session and run', 'same session, other run']),
    );
  });

  it('returns a policy decision trace for an existing tool call without raw secret payloads', async () => {
    const server = await makeApp();

    const submitted = await submit(
      server,
      'gmail.send_email',
      { apiToken: 'super-secret-token', subject: 'Update', to: 'customer@example.com' },
      'Send email',
    );
    const trace = await server.inject({
      method: 'GET',
      url: `/v1/tool-calls/${submitted.json().id}/decision-trace`,
    });

    expect(trace.statusCode).toBe(200);
    expect(trace.json()).toMatchObject({
      actionEnvelopeHash: expect.any(String),
      decision: 'require_approval',
      fallbackPath: ['exact'],
      inputHash: expect.any(String),
      matchType: 'exact',
      matchedRule: 'gmail.send_email',
      storedDecision: 'require_approval',
      toolCallId: submitted.json().id,
      toolName: 'gmail.send_email',
    });
    expect(trace.json().approverResolution).toMatchObject({
      defaultApproversUsed: true,
      requiredApprovals: 1,
      status: 'resolved_empty',
    });
    expect(JSON.stringify(trace.json())).not.toContain('super-secret-token');
  });

  it('redacts nested action-envelope credentials from tool-call responses', async () => {
    const server = await makeApp();
    const secret = 'nested-action-envelope-secret';

    const submitted = await submit(
      server,
      'gmail.send_email',
      { nested: { accessToken: secret }, subject: 'Update', to: 'customer@example.com' },
      'Send email',
    );
    const fetched = await server.inject({ method: 'GET', url: `/v1/tool-calls/${submitted.json().id}` });

    expect(JSON.stringify(submitted.json())).not.toContain(secret);
    expect(JSON.stringify(fetched.json())).not.toContain(secret);
    expect(fetched.json().actionEnvelope.input.nested.accessToken).toBe('[REDACTED]');
  });

  it('renders unavailable remediation plans for non-executed and failed tool calls', async () => {
    const server = await makeApp();

    const pending = await submit(server, 'gmail.send_email', { to: 'customer@example.com' }, 'Send email');
    const pendingPlan = await server.inject({
      method: 'GET',
      url: `/v1/tool-calls/${pending.json().id}/remediation-plan`,
    });

    expect(pendingPlan.statusCode).toBe(200);
    expect(pendingPlan.json().remediation).toMatchObject({
      kind: 'not_reversible',
      status: 'unavailable',
    });
    expect(pendingPlan.json().remediation.reason).toContain('Only executed tool calls');

    await server.close();
    app = undefined;
    const disabledServer = await makeApp({ localExecutionMode: 'disabled' });
    const failed = await submit(disabledServer, 'docs.search', { query: 'refund' }, 'Search docs');
    const failedPlan = await disabledServer.inject({
      method: 'GET',
      url: `/v1/tool-calls/${failed.json().id}/remediation-plan`,
    });

    expect(failedPlan.statusCode).toBe(200);
    expect(failedPlan.json().remediation).toMatchObject({
      kind: 'not_reversible',
      status: 'unavailable',
    });
    expect(failedPlan.json().remediation.reason).toContain('Only executed tool calls');
  });

  it('submits mock Salesforce remediation as a linked approval-gated tool call', async () => {
    const server = await makeApp();

    const submitted = await submit(
      server,
      'salesforce.update_opportunity',
      { fields: { nextStep: 'Schedule procurement review', stageName: 'Negotiation' }, opportunityId: '006DEMO123' },
      'Update opportunity',
    );
    expect(submitted.json()).toMatchObject({ decision: 'require_approval', status: 'pending_approval' });

    const approved = await server.inject({
      method: 'POST',
      payload: { approvedBy: 'manager@example.com' },
      url: `/v1/approvals/${submitted.json().approval.id}/approve`,
    });
    expect(approved.statusCode).toBe(200);
    expect(approved.json().toolCall).toMatchObject({ status: 'executed', toolName: 'salesforce.update_opportunity' });

    const originalToolCallId = approved.json().toolCall.id;
    const plan = await server.inject({ method: 'GET', url: `/v1/tool-calls/${originalToolCallId}/remediation-plan` });
    expect(plan.statusCode).toBe(200);
    expect(plan.json().remediation).toMatchObject({
      input: {
        fields: {
          nextStep: 'Review current contract terms',
          stageName: 'Qualification',
        },
        opportunityId: '006DEMO123',
      },
      kind: 'exact_revert',
      status: 'available',
      toolName: 'salesforce.restore_opportunity',
    });

    const firstRemediation = await server.inject({
      headers: { 'Idempotency-Key': 'restore-salesforce-once' },
      method: 'POST',
      payload: {},
      url: `/v1/tool-calls/${originalToolCallId}/remediation`,
    });
    expect(firstRemediation.statusCode).toBe(200);
    expect(firstRemediation.json()).toMatchObject({
      decision: 'require_approval',
      status: 'pending_approval',
      toolCall: {
        metadata: {
          actionproxy: {
            remediation: {
              kind: 'exact_revert',
              originalToolCallId,
            },
          },
        },
        status: 'pending_approval',
        toolName: 'salesforce.restore_opportunity',
      },
    });

    const repeatedRemediation = await server.inject({
      headers: { 'Idempotency-Key': 'restore-salesforce-once' },
      method: 'POST',
      payload: {},
      url: `/v1/tool-calls/${originalToolCallId}/remediation`,
    });
    expect(repeatedRemediation.statusCode).toBe(200);
    expect(repeatedRemediation.json().id).toBe(firstRemediation.json().id);

    const remediationApprovalId = firstRemediation.json().approval.id;
    const approvedRemediation = await server.inject({
      method: 'POST',
      payload: { approvedBy: 'manager@example.com' },
      url: `/v1/approvals/${remediationApprovalId}/approve`,
    });
    expect(approvedRemediation.statusCode).toBe(200);
    expect(approvedRemediation.json().toolCall).toMatchObject({
      result: {
        restoredFields: {
          nextStep: 'Review current contract terms',
          stageName: 'Qualification',
        },
      },
      status: 'executed',
      toolName: 'salesforce.restore_opportunity',
    });

    const audit = await server.inject({ method: 'GET', url: '/v1/audit?limit=50' });
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ toolCallId: originalToolCallId, type: 'remediation.plan_rendered' }),
        expect.objectContaining({
          toolCallId: firstRemediation.json().id,
          type: 'remediation.submitted',
          data: expect.objectContaining({ originalToolCallId }),
        }),
      ]),
    );
  });
});
