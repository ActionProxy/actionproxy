import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import type { ActionReceiptRecord, AuthContext, ExecutionGrantRecord, ToolCallRecord } from '../models';
import { MemoryStore } from '../storage/memory-store';
import { registerAuthorizedActionRoutes } from './authorized-actions';

const now = '2026-06-21T10:00:00.000Z';
const future = '2999-06-21T10:00:00.000Z';
const past = '2000-06-21T10:00:00.000Z';

describe('authorized action routes', () => {
  it('lists authorized actions by status, filters workspaces, and sanitizes grant and receipt internals', async () => {
    const store = new MemoryStore();
    const app = Fastify({ logger: false });
    const auth: AuthContext = {
      authProvider: 'api_key',
      displayName: 'Read-only service account',
      groups: ['readers'],
      principalId: 'reader',
      principalType: 'service_account',
      scopes: ['tool_call:read'],
      workspaceId: 'default',
    };
    app.addHook('onRequest', async (request) => {
      request.authContext = auth;
    });
    await registerAuthorizedActionRoutes(app, store);

    await createAuthorizedFixture(store, 'waiting');
    await createAuthorizedFixture(store, 'expired');
    await createAuthorizedFixture(store, 'consumed');
    await createAuthorizedFixture(store, 'completed');
    await createAuthorizedFixture(store, 'failed');
    await createAuthorizedFixture(store, 'other_workspace', { workspaceId: 'other' });

    const all = await app.inject({ method: 'GET', url: '/v1/authorized-actions?status=all&limit=100' });
    expect(all.statusCode).toBe(200);
    const allBody = all.json();
    expect(allBody.authorizedActions.map((action: { status: string }) => action.status).sort()).toEqual([
      'completed',
      'consumed',
      'expired',
      'failed',
      'waiting',
    ]);
    expect(JSON.stringify(allBody)).not.toContain('signature_');
    expect(JSON.stringify(allBody)).not.toContain('nonce_');
    expect(JSON.stringify(allBody)).not.toContain('other_workspace');
    expect(allBody.authorizedActions[0].grant).not.toHaveProperty('signature');
    expect(allBody.authorizedActions[0].grant).not.toHaveProperty('nonce');
    expect(allBody.authorizedActions[0].receipt).not.toHaveProperty('signature');

    const failed = await app.inject({ method: 'GET', url: '/v1/authorized-actions?status=failed' });
    expect(failed.statusCode).toBe(200);
    expect(failed.json().authorizedActions).toMatchObject([{ status: 'failed', toolCall: { id: 'toolcall_failed' } }]);

    await app.close();
  });

  it('does not expose private workflow continuation metadata', async () => {
    const store = new MemoryStore();
    const app = Fastify({ logger: false });
    const auth: AuthContext = {
      authProvider: 'api_key',
      displayName: 'Read-only service account',
      groups: ['readers'],
      principalId: 'reader',
      principalType: 'service_account',
      scopes: ['tool_call:read'],
      workspaceId: 'default',
    };
    app.addHook('onRequest', async (request) => {
      request.authContext = auth;
    });
    await registerAuthorizedActionRoutes(app, store);

    await store.createToolCall(
      toolCall({
        id: 'toolcall_plan',
        metadata: {
          actionproxyExecution: 'external',
          agentRunId: 'run_scheduler_123',
          hiddenInternalNote: 'do-not-return',
          purpose: 'agent_plan_authorization',
        },
        policyReason: 'Unknown tool behavior should require approval until reviewed.',
        toolName: 'planning.authorize_plan',
      }),
    );
    await store.createExecutionGrant(
      executionGrant({
        id: 'grant_plan',
        receiptId: 'receipt_plan',
        toolCallId: 'toolcall_plan',
        toolName: 'planning.authorize_plan',
      }),
    );
    await store.createActionReceipt(
      actionReceipt({
        id: 'receipt_plan',
        toolCallId: 'toolcall_plan',
        toolName: 'planning.authorize_plan',
      }),
    );

    const response = await app.inject({ method: 'GET', url: '/v1/authorized-actions' });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.authorizedActions).toMatchObject([
      {
        status: 'waiting',
        toolCall: { id: 'toolcall_plan', toolName: 'planning.authorize_plan' },
      },
    ]);
    expect(body.authorizedActions[0]).not.toHaveProperty('continuation');
    expect(body.authorizedActions[0].toolCall).not.toHaveProperty('metadata');
    expect(JSON.stringify(body)).not.toContain('do-not-return');

    await app.close();
  });
});

async function createAuthorizedFixture(
  store: MemoryStore,
  suffix: string,
  options: { workspaceId?: string } = {},
): Promise<void> {
  const workspaceId = options.workspaceId ?? 'default';
  const toolCallStatus = suffix === 'completed' ? 'executed' : suffix === 'failed' ? 'failed' : 'authorized';
  await store.createToolCall(
    toolCall({
      id: `toolcall_${suffix}`,
      status: toolCallStatus,
      workspaceId,
    }),
  );
  await store.createExecutionGrant(
    executionGrant({
      consumedAt: suffix === 'consumed' || suffix === 'completed' || suffix === 'failed' ? now : undefined,
      expiresAt: suffix === 'expired' ? past : future,
      id: `grant_${suffix}`,
      receiptId: `receipt_${suffix}`,
      toolCallId: `toolcall_${suffix}`,
      workspaceId,
    }),
  );
  await store.createActionReceipt(
    actionReceipt({
      id: `receipt_${suffix}`,
      outcome:
        suffix === 'completed'
          ? { recordedAt: now, recordedBy: 'runner', result: { ok: true }, status: 'succeeded' }
          : suffix === 'failed'
            ? { error: 'Downstream failed', recordedAt: now, recordedBy: 'runner', status: 'failed' }
            : undefined,
      toolCallId: `toolcall_${suffix}`,
      workspaceId,
    }),
  );
}

function toolCall(overrides: Partial<ToolCallRecord>): ToolCallRecord {
  return {
    agentId: 'runner-demo',
    createdAt: now,
    decision: 'allow',
    id: 'toolcall_default',
    input: { query: 'refund' },
    inputHash: 'input_hash_original',
    metadata: { actionproxyExecution: 'external' },
    policyReason: 'Allowed external read.',
    policyVersionHash: 'policy_hash_1',
    reason: 'Search docs',
    requestedBy: 'dev@example.com',
    risk: 'read_only',
    status: 'authorized',
    toolName: 'docs.search',
    updatedAt: now,
    workspaceId: 'default',
    ...overrides,
  };
}

function executionGrant(overrides: Partial<ExecutionGrantRecord>): ExecutionGrantRecord {
  return {
    actor: 'dev@example.com',
    auth: {
      authProvider: 'api_key',
      displayName: 'External runner',
      groups: [],
      principalId: 'runner',
      principalType: 'service_account',
      scopes: ['execution_grant:consume'],
      workspaceId: 'default',
    },
    approvedEnvelopeHash: 'envelope_hash_approved',
    approvedInputHash: 'input_hash_approved',
    createdAt: now,
    expiresAt: future,
    id: 'grant_default',
    inputHash: 'input_hash_approved',
    nonce: 'nonce_secret',
    policyVersionHash: 'policy_hash_1',
    receiptHash: 'receipt_hash_1',
    receiptId: 'receipt_default',
    signature: 'signature_secret',
    toolCallId: 'toolcall_default',
    toolName: 'docs.search',
    workspaceId: 'default',
    ...overrides,
  };
}

function actionReceipt(overrides: Partial<ActionReceiptRecord>): ActionReceiptRecord {
  return {
    approvedEnvelopeHash: 'envelope_hash_approved',
    approvedInputHash: 'input_hash_approved',
    createdAt: now,
    decisionActor: 'dev@example.com',
    decisionKind: 'policy_allow',
    executionMode: 'external_grant',
    id: 'receipt_default',
    issuedAt: now,
    keyId: 'actionproxy-local-hmac-v1',
    operation: { kind: 'read', name: 'docs.search' },
    originalEnvelopeHash: 'envelope_hash_original',
    originalInputHash: 'input_hash_original',
    policyDecision: 'allow',
    policyReason: 'Allowed external read.',
    policyRisk: 'read_only',
    policyVersionHash: 'policy_hash_1',
    protocol: 'actionproxy_http',
    receiptHash: 'receipt_hash_1',
    signature: 'signature_secret',
    signatureAlg: 'HMAC-SHA256',
    source: { name: 'test', type: 'sdk' },
    toolCallId: 'toolcall_default',
    toolName: 'docs.search',
    version: 'actionproxy.receipt.v1',
    workspaceId: 'default',
    ...overrides,
  };
}
