import { describe, expect, it, vi } from 'vitest';
import {
  ActionProxyApiError,
  ActionProxyClient,
  ActionProxyExternalActionError,
  gatedTool,
  runExternalAction,
} from './index';
import type {
  ActionEnvelope,
  ActionProxyFetch,
  ActionProxyFetchResponse,
  ApprovalRecord,
  JsonObject,
  RunExternalActionClient,
  SubmitToolCallResponse,
  ToolCallRecord,
} from './types';

const now = '2026-06-18T10:00:00.000Z';

function jsonResponse(body: unknown, status = 200): ActionProxyFetchResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}

function toolCall(overrides: Partial<ToolCallRecord> = {}): ToolCallRecord {
  return {
    agentId: 'demo-agent',
    createdAt: now,
    decision: 'allow',
    id: 'toolcall_1',
    input: { query: 'refund' },
    metadata: {},
    reason: 'Search docs',
    requestedBy: 'dev@example.com',
    risk: 'read_only',
    status: 'executed',
    toolName: 'docs.search',
    updatedAt: now,
    ...overrides,
  };
}

function submitResponse(overrides: Partial<SubmitToolCallResponse> = {}): SubmitToolCallResponse {
  const record = toolCall(overrides.toolCall);
  return {
    decision: record.decision,
    id: record.id,
    reason: record.policyReason,
    result: record.result,
    risk: record.risk,
    status: record.status,
    toolCall: record,
    ...overrides,
  };
}

function approval(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return {
    createdAt: now,
    id: 'approval_1',
    originalInput: { to: 'customer@example.com' },
    requestedBy: 'dev@example.com',
    status: 'pending',
    toolCallId: 'toolcall_2',
    updatedAt: now,
    ...overrides,
  };
}

describe('ActionProxyClient', () => {
  it('submits a tool call with typed headers and payload', async () => {
    const fetchMock = vi.fn<ActionProxyFetch>(async () => jsonResponse(submitResponse()));
    const client = new ActionProxyClient({
      apiKey: 'test-key',
      baseUrl: 'http://127.0.0.1:8787/',
      fetch: fetchMock,
    });

    const input = {
      agentId: 'demo-agent',
      input: { query: 'refund' },
      reason: 'Search docs',
      requestedBy: 'dev@example.com',
      toolName: 'docs.search',
    };
    const result = await client.submitToolCall(input);

    expect(result.status).toBe('executed');
    expect(fetchMock).toHaveBeenCalledWith('http://127.0.0.1:8787/v1/tool-calls', {
      body: JSON.stringify(input),
      headers: {
        authorization: 'Bearer test-key',
        'content-type': 'application/json',
      },
      method: 'POST',
    });
  });

  it('sends a caller-supplied Idempotency-Key without changing the request body', async () => {
    const fetchMock = vi.fn<ActionProxyFetch>(async () => jsonResponse(submitResponse()));
    const client = new ActionProxyClient({
      baseUrl: 'http://127.0.0.1:8787',
      fetch: fetchMock,
    });
    const input = {
      agentId: 'demo-agent',
      input: { query: 'refund' },
      reason: 'Search docs',
      requestedBy: 'dev@example.com',
      toolName: 'docs.search',
    };

    await client.submitToolCall(input, { idempotencyKey: 'run-123:docs-search' });

    expect(fetchMock).toHaveBeenCalledWith('http://127.0.0.1:8787/v1/tool-calls', {
      body: JSON.stringify(input),
      headers: {
        'content-type': 'application/json',
        'idempotency-key': 'run-123:docs-search',
      },
      method: 'POST',
    });
  });

  it.each(['', '   ', ' leading', 'trailing ', 'line\nbreak', 'carriage\rreturn', 'nul\0byte'])(
    'rejects the non-header-safe idempotency key %j before fetch',
    async (idempotencyKey) => {
      const fetchMock = vi.fn<ActionProxyFetch>();
      const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

      await expect(
        client.submitToolCall(
          {
            agentId: 'demo-agent',
            input: { query: 'refund' },
            reason: 'Search docs',
            requestedBy: 'dev@example.com',
            toolName: 'docs.search',
          },
          { idempotencyKey },
        ),
      ).rejects.toThrow('idempotencyKey must be a non-empty, header-safe string');
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it('fetches tool-call status, recent tool calls, and pending approvals', async () => {
    const fetchedToolCall = toolCall({ id: 'toolcall/special' });
    const pendingApproval = approval();
    const fetchMock = vi
      .fn<ActionProxyFetch>()
      .mockResolvedValueOnce(jsonResponse(fetchedToolCall))
      .mockResolvedValueOnce(jsonResponse({ toolCalls: [fetchedToolCall] }))
      .mockResolvedValueOnce(jsonResponse({ approvals: [pendingApproval] }));
    const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

    await expect(client.getToolCall('toolcall/special')).resolves.toEqual(fetchedToolCall);
    await expect(
      client.listToolCalls({
        limit: 5,
        runId: 'run/one',
        sessionId: 'session one',
        status: 'pending_approval',
        toolName: 'gmail.send_email',
      }),
    ).resolves.toEqual([fetchedToolCall]);
    await expect(client.listPendingApprovals()).resolves.toEqual([pendingApproval]);

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'http://127.0.0.1:8787/v1/tool-calls/toolcall%2Fspecial',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'http://127.0.0.1:8787/v1/tool-calls?limit=5&runId=run%2Fone&sessionId=session+one&status=pending_approval&toolName=gmail.send_email',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      'http://127.0.0.1:8787/v1/approvals/pending',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('lists audit events with forensic correlation filters', async () => {
    const event = {
      data: { outcome: 'allow' },
      id: 'audit_1',
      timestamp: now,
      toolCallId: 'toolcall/special',
      type: 'policy.allow' as const,
      workspaceId: 'default',
    };
    const fetchMock = vi.fn<ActionProxyFetch>(async () => jsonResponse({ events: [event] }));
    const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

    await expect(
      client.listAuditEvents({
        from: '2026-06-18T09:00:00.000Z',
        limit: 25,
        to: '2026-06-18T11:00:00.000Z',
        toolCallId: 'toolcall/special',
      }),
    ).resolves.toEqual([event]);

    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:8787/v1/audit?from=2026-06-18T09%3A00%3A00.000Z&limit=25&to=2026-06-18T11%3A00%3A00.000Z&toolCallId=toolcall%2Fspecial',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('exports audit events with the exact tool-call correlation filter', async () => {
    const exported = {
      count: 1,
      events: [{
        data: {},
        id: 'audit_1',
        timestamp: now,
        toolCallId: 'toolcall/special',
        type: 'content.exposure_recorded' as const,
      }],
      exportedAt: now,
      filters: { toolCallId: 'toolcall/special' },
    };
    const fetchMock = vi.fn<ActionProxyFetch>(async () => jsonResponse(exported));
    const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

    await expect(client.exportAuditEvents({ toolCallId: 'toolcall/special' })).resolves.toEqual(exported);
    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:8787/v1/audit/export?toolCallId=toolcall%2Fspecial',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('reads server-authored decision and execution-attempt evidence', async () => {
    const decisionTrace = {
      approverResolution: {
        configuredGroups: [],
        configuredUsers: [],
        defaultApproversUsed: true,
        notificationChannels: [],
        requiredApprovals: 1,
        separationOfDuties: false,
        status: 'not_required',
      },
      decision: 'allow',
      decisionV1: {
        approvalRequirements: {
          eligibleGroups: [],
          eligibleUsers: [],
          expirationRequired: false,
          expiresAt: null,
          modificationBehavior: 'revalidate_and_rebind',
          rejectionBehavior: 'terminal',
          required: false,
          requiredApprovals: 0,
          separationOfDuties: false,
        },
        decidedAt: now,
        decisionId: 'decision_fixture',
        decisionInputHash: 'decision_input_fixture_hash',
        evaluatorVersion: 'actionproxy.policy-evaluator.v1',
        matchedPolicies: [],
        obligations: ['record_decision_evidence', 'revalidate_policy_before_execution'],
        outcome: 'allow',
        policy: {
          digest: 'policy_digest_fixture',
          digestAlgorithm: 'sha256',
          provider: { id: 'actionproxy.yaml', status: 'ok', version: 'actionproxy.yaml-provider.v1' },
          schemaVersion: '1',
          version: 'policy_fixture_v1',
        },
        reasonCodes: ['policy_outcome_allow', 'policy_match_exact'],
        requestId: 'toolcall_1',
        tenantId: 'default',
        version: 'actionproxy.decision.v1',
      },
      fallbackPath: ['exact'],
      matchType: 'exact',
      matchedRule: 'docs.search',
      policyReason: 'Search is read-only.',
      policyRisk: 'read_only',
      ruleEvaluations: [],
      toolName: 'docs.search',
    };
    const attempt = {
      attemptNumber: 1,
      binding: {
        actionEnvelopeHash: 'envelope_hash',
        approvalAuthorizationHash: null,
        approvalAuthorizationNonce: null,
        approvalId: null,
        canonicalActionRequestHash: 'request_hash',
        canonicalActionRequestVersion: 'actionproxy.action-request.v1',
        canonicalDecisionInputHash: 'decision_input_fixture_hash',
        decisionId: 'decision_fixture',
        decisionVersion: 'actionproxy.decision.v1',
        policyVersionHash: 'policy_hash',
        receiptHash: null,
        receiptId: null,
      },
      executionMode: 'local_mock',
      executorId: 'actionproxy.local-tool-registry',
      id: 'attempt_fixture',
      inputHash: 'input_hash',
      providerIdempotency: 'none',
      reservedAt: now,
      reservationOwner: 'reservation_fixture',
      retryPolicy: 'never_automatic',
      state: 'reserved',
      toolCallId: 'toolcall_1',
      updatedAt: now,
      version: 'actionproxy.execution-attempt.v1',
      workspaceId: 'default',
    };
    const fetchMock = vi
      .fn<ActionProxyFetch>()
      .mockResolvedValueOnce(jsonResponse(decisionTrace))
      .mockResolvedValueOnce(jsonResponse({ attempts: [attempt] }));
    const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

    await expect(client.getDecisionTrace('toolcall/special')).resolves.toEqual(decisionTrace);
    await expect(client.listExecutionAttempts('toolcall/special')).resolves.toEqual([attempt]);

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'http://127.0.0.1:8787/v1/tool-calls/toolcall%2Fspecial/decision-trace',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'http://127.0.0.1:8787/v1/tool-calls/toolcall%2Fspecial/execution-attempts',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('echoes approval nonces and supports the additive cancellation endpoint', async () => {
    const pending = approval();
    const fetchMock = vi
      .fn<ActionProxyFetch>()
      .mockResolvedValueOnce(jsonResponse({ approval: { ...pending, status: 'approved' }, toolCall: toolCall() }))
      .mockResolvedValueOnce(jsonResponse({ approval: { ...pending, status: 'rejected' }, toolCall: toolCall() }))
      .mockResolvedValueOnce(jsonResponse({ approval: { ...pending, status: 'cancelled' }, toolCall: toolCall() }));
    const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

    await client.approveApproval('approval/special', {
      approvalNonce: 'nonce_approve',
      approvedBy: 'manager@example.com',
      inputDecision: { mode: 'original' },
    });
    await client.rejectApproval('approval/special', {
      approvalNonce: 'nonce_reject',
      reason: 'Not authorized',
      rejectedBy: 'manager@example.com',
    });
    await client.cancelApproval('approval/special', {
      approvalNonce: 'nonce_cancel',
      cancelledBy: 'manager@example.com',
      reason: 'No longer needed',
    });

    expect(fetchMock).toHaveBeenNthCalledWith(1, 'http://127.0.0.1:8787/v1/approvals/approval%2Fspecial/approve', {
      body: JSON.stringify({
        approvalNonce: 'nonce_approve',
        approvedBy: 'manager@example.com',
        inputDecision: { mode: 'original' },
      }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    });
    expect(fetchMock).toHaveBeenNthCalledWith(2, 'http://127.0.0.1:8787/v1/approvals/approval%2Fspecial/reject', {
      body: JSON.stringify({
        approvalNonce: 'nonce_reject',
        reason: 'Not authorized',
        rejectedBy: 'manager@example.com',
      }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    });
    expect(fetchMock).toHaveBeenNthCalledWith(3, 'http://127.0.0.1:8787/v1/approvals/approval%2Fspecial/cancel', {
      body: JSON.stringify({
        approvalNonce: 'nonce_cancel',
        cancelledBy: 'manager@example.com',
        reason: 'No longer needed',
      }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    });
  });

  it('consumes an external execution grant before downstream execution', async () => {
    const fetchMock = vi.fn<ActionProxyFetch>(async () =>
      jsonResponse({
        grant: {
          consumedAt: now,
          expiresAt: '2026-06-18T10:05:00.000Z',
          id: 'grant_1',
          inputHash: 'hash_1',
          policyVersionHash: 'policy_hash_1',
          toolCallId: 'toolcall_1',
          toolName: 'docs.search',
        },
        ok: true,
      }),
    );
    const client = new ActionProxyClient({
      apiKey: 'runner-key',
      baseUrl: 'http://127.0.0.1:8787',
      fetch: fetchMock,
    });

    await expect(
      client.consumeExecutionGrant('grant/1', {
        input: { query: 'refund' },
        policyVersionHash: 'policy_hash_1',
        toolCallId: 'toolcall_1',
        toolName: 'docs.search',
      }),
    ).resolves.toMatchObject({ ok: true, grant: { id: 'grant_1' } });

    expect(fetchMock).toHaveBeenCalledWith('http://127.0.0.1:8787/v1/execution-grants/grant%2F1/consume', {
      body: JSON.stringify({
        input: { query: 'refund' },
        policyVersionHash: 'policy_hash_1',
        toolCallId: 'toolcall_1',
        toolName: 'docs.search',
      }),
      headers: {
        authorization: 'Bearer runner-key',
        'content-type': 'application/json',
      },
      method: 'POST',
    });
  });

  it('reports external execution outcomes after downstream execution', async () => {
    const fetchMock = vi.fn<ActionProxyFetch>(async () =>
      jsonResponse({
        grant: {
          consumedAt: now,
          expiresAt: '2026-06-18T10:05:00.000Z',
          id: 'grant_1',
          inputHash: 'hash_1',
          policyVersionHash: 'policy_hash_1',
          receiptHash: 'receipt_hash_1',
          receiptId: 'receipt_1',
          toolCallId: 'toolcall_1',
          toolName: 'docs.search',
        },
        ok: true,
        receipt: {
          approvedEnvelopeHash: 'approved_envelope_hash',
          approvedInputHash: 'approved_input_hash',
          createdAt: now,
          decisionActor: 'policy',
          decisionKind: 'policy_allow',
          executionMode: 'external_grant',
          id: 'receipt_1',
          issuedAt: now,
          keyId: 'actionproxy-local-hmac-v1',
          operation: { kind: 'read', name: 'docs.search' },
          originalEnvelopeHash: 'original_envelope_hash',
          originalInputHash: 'original_input_hash',
          outcome: {
            recordedAt: now,
            recordedBy: 'runner',
            remediation: {
              input: { snapshotId: 'snapshot_1' },
              kind: 'soft_revert',
              reason: 'Restore downstream snapshot.',
              status: 'available',
              toolName: 'docs.restore_snapshot',
            },
            result: { rows: 1 },
            status: 'succeeded',
          },
          policyDecision: 'allow',
          policyVersionHash: 'policy_hash_1',
          protocol: 'mcp',
          receiptHash: 'receipt_hash_1',
          signature: 'signature_1',
          signatureAlg: 'HMAC-SHA256',
          source: { name: 'mcp-wrapper', type: 'mcp' },
          toolCallId: 'toolcall_1',
          toolName: 'docs.search',
          version: 'actionproxy.receipt.v1',
          workspaceId: 'default',
        },
        toolCall: toolCall({ result: { externalExecutionOutcome: { rows: 1 } }, status: 'executed' }),
      }),
    );
    const client = new ActionProxyClient({
      apiKey: 'runner-key',
      baseUrl: 'http://127.0.0.1:8787',
      fetch: fetchMock,
    });

    await expect(
      client.reportExecutionGrantOutcome('grant/1', {
        remediation: {
          input: { snapshotId: 'snapshot_1' },
          kind: 'soft_revert',
          reason: 'Restore downstream snapshot.',
          status: 'available',
          toolName: 'docs.restore_snapshot',
        },
        result: { rows: 1 },
        status: 'succeeded',
      }),
    ).resolves.toMatchObject({
      ok: true,
      receipt: { outcome: { result: { rows: 1 }, status: 'succeeded' } },
      toolCall: { status: 'executed' },
    });

    expect(fetchMock).toHaveBeenCalledWith('http://127.0.0.1:8787/v1/execution-grants/grant%2F1/outcome', {
      body: JSON.stringify({
        remediation: {
          input: { snapshotId: 'snapshot_1' },
          kind: 'soft_revert',
          reason: 'Restore downstream snapshot.',
          status: 'available',
          toolName: 'docs.restore_snapshot',
        },
        result: { rows: 1 },
        status: 'succeeded',
      }),
      headers: {
        authorization: 'Bearer runner-key',
        'content-type': 'application/json',
      },
      method: 'POST',
    });
  });

  it('reports an unknown outcome once and does not retry the request', async () => {
    const response = {
      grant: {
        consumedAt: now,
        expiresAt: '2026-06-18T10:05:00.000Z',
        id: 'grant_1',
        inputHash: 'hash_1',
        toolCallId: 'toolcall_1',
        toolName: 'docs.search',
      },
      ok: true,
      toolCall: toolCall({ error: 'Execution outcome is unknown.', status: 'failed' }),
    };
    const fetchMock = vi.fn<ActionProxyFetch>(async () => jsonResponse(response));
    const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

    await expect(
      client.reportExecutionGrantOutcome('grant_1', {
        error: 'Runner disconnected after dispatch',
        status: 'unknown_outcome',
      }),
    ).resolves.toEqual(response);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith('http://127.0.0.1:8787/v1/execution-grants/grant_1/outcome', {
      body: JSON.stringify({
        error: 'Runner disconnected after dispatch',
        status: 'unknown_outcome',
      }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    });
  });

  it('fetches remediation plans and submits governed remediation calls', async () => {
    const remediationPlan = {
      originalToolCall: toolCall({ id: 'toolcall_original', status: 'executed', toolName: 'salesforce.update_opportunity' }),
      relatedToolCalls: [],
      remediation: {
        evidence: { objectType: 'Opportunity' },
        input: { fields: { stageName: 'Qualification' }, opportunityId: '006DEMO123' },
        kind: 'exact_revert',
        reason: 'Restore CRM fields.',
        status: 'available',
        toolName: 'salesforce.restore_opportunity',
      },
    };
    const fetchMock = vi
      .fn<ActionProxyFetch>()
      .mockResolvedValueOnce(jsonResponse(remediationPlan))
      .mockResolvedValueOnce(
        jsonResponse({
          approval: { id: 'approval_restore', status: 'pending' },
          decision: 'require_approval',
          id: 'toolcall_restore',
          plan: remediationPlan,
          status: 'pending_approval',
          toolCall: toolCall({ id: 'toolcall_restore', status: 'pending_approval', toolName: 'salesforce.restore_opportunity' }),
        }),
      );
    const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

    await expect(client.getRemediationPlan('toolcall/original')).resolves.toMatchObject({
      remediation: { kind: 'exact_revert', status: 'available' },
    });
    await expect(
      client.submitRemediation('toolcall/original', {
        reason: 'Restore approved CRM fields',
      }),
    ).resolves.toMatchObject({
      approval: { id: 'approval_restore' },
      status: 'pending_approval',
      toolCall: { toolName: 'salesforce.restore_opportunity' },
    });

    expect(fetchMock).toHaveBeenNthCalledWith(1, 'http://127.0.0.1:8787/v1/tool-calls/toolcall%2Foriginal/remediation-plan', {
      body: undefined,
      headers: { 'content-type': 'application/json' },
      method: 'GET',
    });
    expect(fetchMock).toHaveBeenNthCalledWith(2, 'http://127.0.0.1:8787/v1/tool-calls/toolcall%2Foriginal/remediation', {
      body: JSON.stringify({ reason: 'Restore approved CRM fields' }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    });
  });

  it('polls tool-call status until a terminal state is reached', async () => {
    const fetchMock = vi
      .fn<ActionProxyFetch>()
      .mockResolvedValueOnce(jsonResponse(toolCall({ status: 'pending_approval' })))
      .mockResolvedValueOnce(jsonResponse(toolCall({ result: { ok: true }, status: 'executed' })));
    const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

    const result = await client.waitForToolCall('toolcall_1', { intervalMs: 0, timeoutMs: 100 });

    expect(result.status).toBe('executed');
    expect(result.result).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('surfaces API failures with status and parsed body', async () => {
    const fetchMock = vi.fn<ActionProxyFetch>(async () => jsonResponse({ error: 'not_found' }, 404));
    const client = new ActionProxyClient({ baseUrl: 'http://127.0.0.1:8787', fetch: fetchMock });

    await expect(client.getToolCall('missing')).rejects.toMatchObject({
      body: { error: 'not_found' },
      status: 404,
    } satisfies Partial<ActionProxyApiError>);
  });
});

describe('gatedTool', () => {
  it('submits a configured tool call without running local execution callbacks', async () => {
    type EmailInput = JsonObject & { subject: string; to: string };
    const response = submitResponse({
      approval: { id: 'approval_1', status: 'pending' },
      status: 'pending_approval',
      toolCall: toolCall({
        decision: 'require_approval',
        id: 'toolcall_2',
        status: 'pending_approval',
        toolName: 'gmail.send_email',
      }),
    }) as SubmitToolCallResponse<EmailInput>;
    const execute = vi.fn();
    const client = {
      submitToolCall: vi.fn(async () => response),
      waitForToolCall: vi.fn(async () => response.toolCall),
    };
    const sendEmail = gatedTool<EmailInput>({
      agentId: 'demo-agent',
      client: client as unknown as RunExternalActionClient,
      execute,
      metadata: (input) => ({ recipient: input.to }),
      reason: (input) => `Email ${input.to}`,
      requestedBy: 'dev@example.com',
      toolName: 'gmail.send_email',
    });

    const result = await sendEmail({ subject: 'Update', to: 'customer@example.com' });

    expect(result.status).toBe('pending_approval');
    expect(client.submitToolCall).toHaveBeenCalledWith({
      agentId: 'demo-agent',
      input: { subject: 'Update', to: 'customer@example.com' },
      metadata: { recipient: 'customer@example.com' },
      reason: 'Email customer@example.com',
      requestedBy: 'dev@example.com',
      toolName: 'gmail.send_email',
    });
    expect(execute).not.toHaveBeenCalled();
  });

  it('forwards a caller key from config and lets a per-call key override it', async () => {
    const response = submitResponse();
    const client = {
      submitToolCall: vi.fn(async () => response),
      waitForToolCall: vi.fn(async () => response.toolCall),
    };
    const searchDocs = gatedTool({
      agentId: 'demo-agent',
      client: client as unknown as RunExternalActionClient,
      idempotencyKey: (input) => `search:${String(input.query)}`,
      requestedBy: 'dev@example.com',
      toolName: 'docs.search',
    });

    await searchDocs({ query: 'refund' });
    await searchDocs({ query: 'refund' }, { idempotencyKey: 'run-override' });

    expect(client.submitToolCall).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ input: { query: 'refund' } }),
      { idempotencyKey: 'search:refund' },
    );
    expect(client.submitToolCall).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ input: { query: 'refund' } }),
      { idempotencyKey: 'run-override' },
    );
  });

  it('can wait for the final tool-call state and merge the latest status', async () => {
    const response = submitResponse({
      status: 'pending_approval',
      toolCall: toolCall({
        decision: 'require_approval',
        id: 'toolcall_2',
        status: 'pending_approval',
        toolName: 'gmail.send_email',
      }),
    });
    const finalToolCall = toolCall({
      decision: 'require_approval',
      id: 'toolcall_2',
      result: { sent: true },
      status: 'executed',
      toolName: 'gmail.send_email',
    });
    const client = {
      submitToolCall: vi.fn(async () => response),
      waitForToolCall: vi.fn(async () => finalToolCall),
    };
    const sendEmail = gatedTool({
      agentId: 'demo-agent',
      client: client as unknown as RunExternalActionClient,
      requestedBy: 'dev@example.com',
      toolName: 'gmail.send_email',
      waitForFinalStatus: true,
    });

    const result = await sendEmail({ to: 'customer@example.com' });

    expect(client.waitForToolCall).toHaveBeenCalledWith('toolcall_2', undefined);
    expect(result.status).toBe('executed');
    expect(result.result).toEqual({ sent: true });
    expect(result.toolCall).toEqual(finalToolCall);
  });
});

describe('runExternalAction', () => {
  it('submits an external action, consumes the grant, executes downstream, and reports success', async () => {
    const submitted = submitResponse({
      status: 'pending_approval',
      toolCall: toolCall({ id: 'toolcall_external', status: 'pending_approval', toolName: 'crm.update_account' }),
    });
    const authorized = toolCall({
      id: 'toolcall_external',
      input: { accountId: 'acct_1', fields: { tier: 'gold' } },
      policyVersionHash: 'policy_hash_1',
      result: { grant: { id: 'grant_1' }, receipt: { id: 'receipt_1' } },
      status: 'authorized',
      toolName: 'crm.update_account',
    });
    const consumed = {
      grant: {
        consumedAt: now,
        expiresAt: '2026-06-18T10:05:00.000Z',
        id: 'grant_1',
        inputHash: 'hash_1',
        policyVersionHash: 'policy_hash_1',
        toolCallId: 'toolcall_external',
        toolName: 'crm.update_account',
      },
      ok: true as const,
    };
    const executed = toolCall({
      id: 'toolcall_external',
      result: { externalExecutionOutcome: { ok: true, recordId: 'acct_1' } },
      status: 'executed',
      toolName: 'crm.update_account',
    });
    const client = {
      consumeExecutionGrant: vi.fn(async () => consumed),
      reportExecutionGrantOutcome: vi.fn(async () => ({
        grant: consumed.grant,
        ok: true as const,
        toolCall: executed,
      })),
      submitToolCall: vi.fn(async () => submitted),
      waitForToolCall: vi.fn(async () => authorized),
    };
    const execute = vi.fn(async () => ({ ok: true, recordId: 'acct_1' }));

    const result = await runExternalAction({
      agentId: 'external-runner',
      client: client as unknown as RunExternalActionClient,
      execute,
      idempotencyKey: 'run-external-account-update',
      input: { accountId: 'acct_1', fields: { tier: 'gold' } },
      metadata: { source: 'sdk-test' },
      reason: 'Update account after approval',
      requestedBy: 'runner@example.com',
      toolName: 'crm.update_account',
      wait: { intervalMs: 0, timeoutMs: 100 },
    });

    expect(client.submitToolCall).toHaveBeenCalledWith(
      {
        action: { executionMode: 'external_grant' },
        agentId: 'external-runner',
        input: { accountId: 'acct_1', fields: { tier: 'gold' } },
        metadata: { actionproxyExecution: 'external', source: 'sdk-test' },
        reason: 'Update account after approval',
        requestedBy: 'runner@example.com',
        toolName: 'crm.update_account',
      },
      { idempotencyKey: 'run-external-account-update' },
    );
    expect(client.consumeExecutionGrant).toHaveBeenCalledWith('grant_1', {
      input: authorized.input,
      policyVersionHash: 'policy_hash_1',
      toolCallId: 'toolcall_external',
      toolName: 'crm.update_account',
    });
    expect(execute).toHaveBeenCalledWith(authorized.input, { consumed, toolCall: authorized });
    expect(client.reportExecutionGrantOutcome).toHaveBeenCalledWith('grant_1', {
      result: { ok: true, recordId: 'acct_1' },
      status: 'succeeded',
    });
    expect(result.toolCall.status).toBe('executed');
  });

  it('does not consume or execute again when a keyed replay is already terminal', async () => {
    const submitted = submitResponse({
      id: 'toolcall_replay',
      status: 'authorized',
      toolCall: toolCall({
        id: 'toolcall_replay',
        result: { grant: { id: 'grant_replay' } },
        status: 'authorized',
        toolName: 'docs.search',
      }),
    });
    const authorized = submitted.toolCall;
    const executed = toolCall({
      id: 'toolcall_replay',
      result: { externalExecutionOutcome: { rows: 1 } },
      status: 'executed',
      toolName: 'docs.search',
    });
    const client = {
      consumeExecutionGrant: vi.fn(async () => ({
        grant: {
          consumedAt: now,
          expiresAt: '2026-06-18T10:05:00.000Z',
          id: 'grant_replay',
          inputHash: 'hash_1',
          toolCallId: 'toolcall_replay',
          toolName: 'docs.search',
        },
        ok: true as const,
      })),
      reportExecutionGrantOutcome: vi.fn(async () => ({
        grant: {
          consumedAt: now,
          expiresAt: '2026-06-18T10:05:00.000Z',
          id: 'grant_replay',
          inputHash: 'hash_1',
          toolCallId: 'toolcall_replay',
          toolName: 'docs.search',
        },
        ok: true as const,
        toolCall: executed,
      })),
      submitToolCall: vi.fn(async () => submitted),
      waitForToolCall: vi
        .fn()
        .mockResolvedValueOnce(authorized)
        .mockResolvedValueOnce(executed),
    };
    const execute = vi.fn(async () => ({ rows: 1 }));
    const request = {
      agentId: 'external-runner',
      client: client as unknown as RunExternalActionClient,
      execute,
      idempotencyKey: 'same-logical-action',
      input: { query: 'refund' },
      reason: 'Search once',
      requestedBy: 'runner@example.com',
      toolName: 'docs.search',
    };

    await expect(runExternalAction(request)).resolves.toMatchObject({
      submitted: { id: 'toolcall_replay' },
      toolCall: { id: 'toolcall_replay', status: 'executed' },
    });
    await expect(runExternalAction(request)).rejects.toBeInstanceOf(ActionProxyExternalActionError);

    expect(client.submitToolCall).toHaveBeenCalledTimes(2);
    expect(client.submitToolCall).toHaveBeenNthCalledWith(
      1,
      expect.any(Object),
      { idempotencyKey: 'same-logical-action' },
    );
    expect(client.submitToolCall).toHaveBeenNthCalledWith(
      2,
      expect.any(Object),
      { idempotencyKey: 'same-logical-action' },
    );
    expect(client.consumeExecutionGrant).toHaveBeenCalledTimes(1);
    expect(client.reportExecutionGrantOutcome).toHaveBeenCalledTimes(1);
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it('does not consume grants when ActionProxy blocks or rejects the action', async () => {
    const submitted = submitResponse({
      status: 'blocked',
      toolCall: toolCall({ decision: 'deny', id: 'toolcall_blocked', status: 'blocked', toolName: 'crm.delete_customer' }),
    });
    const client = {
      consumeExecutionGrant: vi.fn(),
      reportExecutionGrantOutcome: vi.fn(),
      submitToolCall: vi.fn(async () => submitted),
      waitForToolCall: vi.fn(async () => submitted.toolCall),
    };

    await expect(
      runExternalAction({
        agentId: 'external-runner',
        client: client as unknown as RunExternalActionClient,
        execute: vi.fn(),
        input: { customerId: 'cus_1' },
        reason: 'Delete customer',
        requestedBy: 'runner@example.com',
        toolName: 'crm.delete_customer',
      }),
    ).rejects.toBeInstanceOf(ActionProxyExternalActionError);

    expect(client.consumeExecutionGrant).not.toHaveBeenCalled();
    expect(client.reportExecutionGrantOutcome).not.toHaveBeenCalled();
  });

  it('does not execute downstream when grant consumption is rejected as a replay', async () => {
    const submitted = submitResponse({
      status: 'authorized',
      toolCall: toolCall({
        id: 'toolcall_external',
        result: { grant: { id: 'grant_replayed' } },
        status: 'authorized',
        toolName: 'crm.update_account',
      }),
    });
    const client = {
      consumeExecutionGrant: vi.fn(async () => {
        throw new ActionProxyApiError('Execution grant has already been consumed.', 409, { error: 'conflict' });
      }),
      reportExecutionGrantOutcome: vi.fn(),
      submitToolCall: vi.fn(async () => submitted),
      waitForToolCall: vi.fn(async () => submitted.toolCall),
    };
    const execute = vi.fn();

    await expect(
      runExternalAction({
        agentId: 'external-runner',
        client: client as unknown as RunExternalActionClient,
        execute,
        input: { accountId: 'acct_1' },
        reason: 'Update account',
        requestedBy: 'runner@example.com',
        toolName: 'crm.update_account',
      }),
    ).rejects.toMatchObject({ status: 409 });

    expect(execute).not.toHaveBeenCalled();
    expect(client.reportExecutionGrantOutcome).not.toHaveBeenCalled();
  });

  it('reports unknown outcomes without retrying when downstream execution throws after grant consumption', async () => {
    const submitted = submitResponse({
      status: 'authorized',
      toolCall: toolCall({ id: 'toolcall_external', status: 'authorized', toolName: 'crm.update_account' }),
    });
    const authorized = toolCall({
      id: 'toolcall_external',
      result: { grant: { id: 'grant_1' } },
      status: 'authorized',
      toolName: 'crm.update_account',
    });
    const client = {
      consumeExecutionGrant: vi.fn(async () => ({
        grant: {
          consumedAt: now,
          expiresAt: '2026-06-18T10:05:00.000Z',
          id: 'grant_1',
          inputHash: 'hash_1',
          toolCallId: 'toolcall_external',
          toolName: 'crm.update_account',
        },
        ok: true as const,
      })),
      reportExecutionGrantOutcome: vi.fn(async () => ({
        grant: {
          expiresAt: '2026-06-18T10:05:00.000Z',
          id: 'grant_1',
          inputHash: 'hash_1',
          toolCallId: 'toolcall_external',
          toolName: 'crm.update_account',
        },
        ok: true as const,
        toolCall: toolCall({ status: 'failed' }),
      })),
      submitToolCall: vi.fn(async () => submitted),
      waitForToolCall: vi.fn(async () => authorized),
    };

    await expect(
      runExternalAction({
        agentId: 'external-runner',
        client: client as unknown as RunExternalActionClient,
        execute: async () => {
          throw new Error('CRM unavailable');
        },
        input: { accountId: 'acct_1' },
        reason: 'Update account',
        requestedBy: 'runner@example.com',
        toolName: 'crm.update_account',
      }),
    ).rejects.toMatchObject({ causeError: expect.any(Error) });

    expect(client.reportExecutionGrantOutcome).toHaveBeenCalledWith('grant_1', {
      error: 'CRM unavailable',
      status: 'unknown_outcome',
    });
  });
});
