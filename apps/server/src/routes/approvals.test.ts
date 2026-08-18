import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildApp } from '../app';

let app: FastifyInstance | undefined;

describe('approval routes', () => {
  afterEach(async () => {
    await app?.close();
    app = undefined;
    vi.useRealTimers();
  });

  it('fetches pending, approved, and rejected approvals by id', async () => {
    app = await makeApp();

    const pending = await submitEmailApproval(app, 'Pending email');
    const pendingApprovalId = pending.json().approval.id as string;
    const fetchedPending = await app.inject({ method: 'GET', url: `/v1/approvals/${pendingApprovalId}` });
    expect(fetchedPending.statusCode).toBe(200);
    expect(fetchedPending.json()).toMatchObject({
      approval: {
        authorization: {
          authorizationHash: expect.stringMatching(/^[a-f0-9]{64}$/),
          expiresAt: expect.any(String),
          nonce: expect.any(String),
          version: 'actionproxy.approval-authorization.v1',
        },
        id: pendingApprovalId,
        operations: {
          action: {
            app: 'gmail',
            customerVisible: true,
            recipient: 'customer@example.com',
          },
          reminder: { available: true },
          sla: { status: 'on_track' },
        },
        status: 'pending',
      },
      toolCall: { status: 'pending_approval', toolName: 'gmail.send_email' },
    });

    const review = await app.inject({ method: 'GET', url: `/v1/approvals/${pendingApprovalId}/review` });
    expect(review.statusCode).toBe(200);
    expect(review.json().freshness).toMatchObject({ state: 'fresh', warnings: [] });
    expect(Date.parse(review.json().freshness.renderedAt)).toBeGreaterThan(0);
    expect(Date.parse(review.json().freshness.expiresAt)).toBeGreaterThan(Date.parse(review.json().freshness.renderedAt));

    const approved = await submitEmailApproval(app, 'Approved email');
    const approvedApprovalId = approved.json().approval.id as string;
    const approveResponse = await app.inject({
      method: 'POST',
      payload: { approvedBy: 'manager@example.com' },
      url: `/v1/approvals/${approvedApprovalId}/approve`,
    });
    expect(approveResponse.statusCode).toBe(200);
    const fetchedApproved = await app.inject({ method: 'GET', url: `/v1/approvals/${approvedApprovalId}` });
    expect(fetchedApproved.statusCode).toBe(200);
    expect(fetchedApproved.json()).toMatchObject({
      approval: { approvedBy: 'manager@example.com', id: approvedApprovalId, status: 'approved' },
      toolCall: { toolName: 'gmail.send_email' },
    });

    const rejected = await submitEmailApproval(app, 'Rejected email');
    const rejectedApprovalId = rejected.json().approval.id as string;
    const rejectResponse = await app.inject({
      method: 'POST',
      payload: { reason: 'Not needed', rejectedBy: 'manager@example.com' },
      url: `/v1/approvals/${rejectedApprovalId}/reject`,
    });
    expect(rejectResponse.statusCode).toBe(200);
    const fetchedRejected = await app.inject({ method: 'GET', url: `/v1/approvals/${rejectedApprovalId}` });
    expect(fetchedRejected.statusCode).toBe(200);
    expect(fetchedRejected.json()).toMatchObject({
      approval: { id: rejectedApprovalId, rejectedBy: 'manager@example.com', status: 'rejected' },
      toolCall: { status: 'rejected', toolName: 'gmail.send_email' },
    });
  });

  it.each([
    {
      label: 'modern inputDecision',
      payload: (secret: string) => ({
        approvedBy: 'manager@example.com',
        inputDecision: {
          input: { body: 'Hello', nested: { refreshToken: secret }, subject: 'Edited', to: 'customer@example.com' },
          mode: 'edited',
        },
      }),
    },
    {
      label: 'legacy editedInput',
      payload: (secret: string) => ({
        approvedBy: 'manager@example.com',
        editedInput: {
          body: 'Hello',
          nested: { refreshToken: secret },
          subject: 'Edited',
          to: 'customer@example.com',
        },
      }),
    },
    {
      label: 'matching modern and legacy representations',
      payload: (secret: string) => {
        const editedInput = {
          body: 'Hello',
          nested: { refreshToken: secret },
          subject: 'Edited',
          to: 'customer@example.com',
        };
        return {
          approvedBy: 'manager@example.com',
          editedInput,
          inputDecision: { input: editedInput, mode: 'edited' as const },
        };
      },
    },
  ])('executes Community edits through the $label form without reflecting secrets', async ({ payload }) => {
    app = await makeApp();
    const pending = await submitEmailApproval(app, 'Edited secret email');
    const approvalId = pending.json().approval.id as string;
    const secret = 'approval-decision-secret';

    const approved = await app.inject({
      method: 'POST',
      payload: payload(secret),
      url: `/v1/approvals/${approvalId}/approve`,
    });
    const fetched = await app.inject({ method: 'GET', url: `/v1/approvals/${approvalId}` });

    expect(approved.statusCode).toBe(200);
    expect(JSON.stringify(approved.json())).not.toContain(secret);
    expect(JSON.stringify(fetched.json())).not.toContain(secret);
    expect(fetched.json()).toMatchObject({
      approval: {
        decisions: [{ inputDecision: 'edited' }],
        editedInput: { subject: 'Edited', to: 'customer@example.com' },
        status: 'approved',
      },
      toolCall: { status: 'executed' },
    });
  });

  it.each([
    {
      label: 'original decision with legacy edited input',
      payload: {
        approvedBy: 'manager@example.com',
        editedInput: { subject: 'Legacy edit', to: 'customer@example.com' },
        inputDecision: { mode: 'original' },
      },
    },
    {
      label: 'different modern and legacy edits',
      payload: {
        approvedBy: 'manager@example.com',
        editedInput: { subject: 'Legacy edit', to: 'customer@example.com' },
        inputDecision: {
          input: { subject: 'Modern edit', to: 'customer@example.com' },
          mode: 'edited',
        },
      },
    },
    {
      label: 'modern edit with legacy original marker',
      payload: {
        approvedBy: 'manager@example.com',
        editedInput: null,
        inputDecision: {
          input: { subject: 'Modern edit', to: 'customer@example.com' },
          mode: 'edited',
        },
      },
    },
  ])('rejects conflicting approval input representations before mutation: $label', async ({ label, payload }) => {
    app = await makeApp();
    const pending = await submitEmailApproval(app, `Conflicting representations: ${label}`);
    const approvalId = pending.json().approval.id as string;

    const response = await app.inject({
      method: 'POST',
      payload,
      url: `/v1/approvals/${approvalId}/approve`,
    });
    const fetched = await app.inject({ method: 'GET', url: `/v1/approvals/${approvalId}` });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'invalid_request' });
    expect(fetched.json()).toMatchObject({
      approval: { decisions: [], status: 'pending' },
      toolCall: { status: 'pending_approval' },
    });
  });

  it('rejects fields that do not belong to the selected inputDecision variant', async () => {
    app = await makeApp();
    const pending = await submitEmailApproval(app, 'Strict original decision');
    const approvalId = pending.json().approval.id as string;

    const response = await app.inject({
      method: 'POST',
      payload: {
        approvedBy: 'manager@example.com',
        inputDecision: {
          input: { subject: 'Must not be stripped', to: 'customer@example.com' },
          mode: 'original',
        },
      },
      url: `/v1/approvals/${approvalId}/approve`,
    });
    const fetched = await app.inject({ method: 'GET', url: `/v1/approvals/${approvalId}` });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'invalid_request' });
    expect(fetched.json()).toMatchObject({
      approval: { decisions: [], status: 'pending' },
      toolCall: { status: 'pending_approval' },
    });
  });

  it('does not register the private prepared-action revision route in Community', async () => {
    app = await makeApp();

    const response = await app.inject({
      method: 'POST',
      payload: { input: { subject: 'Revised' } },
      url: '/v1/approvals/approval_missing/revise',
    });

    expect(response.statusCode).toBe(404);
    expect(app.printRoutes()).not.toContain('/revise');
  });

  it('rejects a stale nonce while preserving legacy approve payload compatibility', async () => {
    app = await makeApp();
    const pending = await submitEmailApproval(app, 'Nonce compatibility');
    const approvalId = pending.json().approval.id as string;

    const stale = await app.inject({
      method: 'POST',
      payload: { approvalNonce: 'stale-nonce', approvedBy: 'manager@example.com' },
      url: `/v1/approvals/${approvalId}/approve`,
    });
    expect(stale.statusCode).toBe(409);
    expect(stale.json()).toMatchObject({ error: 'conflict', message: expect.stringContaining('nonce') });

    const unchangedPayload = await app.inject({
      method: 'POST',
      payload: { approvedBy: 'manager@example.com' },
      url: `/v1/approvals/${approvalId}/approve`,
    });
    expect(unchangedPayload.statusCode).toBe(200);
    expect(unchangedPayload.json()).toMatchObject({
      approval: { status: 'approved' },
      toolCall: { status: 'executed' },
    });
  });

  it('cancels through the additive endpoint and blocks every later terminal replay', async () => {
    app = await makeApp();
    const pending = await submitEmailApproval(app, 'Cancel lifecycle');
    const approvalId = pending.json().approval.id as string;
    const fetched = await app.inject({ method: 'GET', url: `/v1/approvals/${approvalId}` });
    const nonce = fetched.json().approval.authorization.nonce as string;

    const cancelled = await app.inject({
      method: 'POST',
      payload: { approvalNonce: nonce, cancelledBy: 'requester@example.com', reason: 'No longer needed' },
      url: `/v1/approvals/${approvalId}/cancel`,
    });
    expect(cancelled.statusCode).toBe(200);
    expect(cancelled.json()).toMatchObject({
      approval: {
        authorizationConsumedReason: 'cancelled',
        cancelledBy: 'requester@example.com',
        cancellationReason: 'No longer needed',
        status: 'cancelled',
      },
      toolCall: { status: 'rejected' },
    });

    for (const action of ['approve', 'reject', 'cancel']) {
      const replay = await app.inject({
        method: 'POST',
        payload:
          action === 'approve'
            ? { approvalNonce: nonce, approvedBy: 'manager@example.com' }
            : action === 'reject'
              ? { approvalNonce: nonce, rejectedBy: 'manager@example.com' }
              : { approvalNonce: nonce, cancelledBy: 'requester@example.com' },
        url: `/v1/approvals/${approvalId}/${action}`,
      });
      expect(replay.statusCode, action).toBe(409);
      expect(replay.json(), action).toMatchObject({ error: 'conflict', message: expect.stringContaining('cancelled') });
    }
  });
});

async function makeApp(): Promise<FastifyInstance> {
  return buildApp({
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-approval-route-test-')),
    host: '127.0.0.1',
    localExecution: { mode: 'mock' },
    logLevel: 'silent',
    policyPath: path.resolve('src/policies/default.policy.yaml'),
    port: 0,
  });
}

async function submitEmailApproval(server: FastifyInstance, subject: string) {
  return server.inject({
    method: 'POST',
    payload: {
      agentId: 'demo-agent',
      input: { body: 'Hello', subject, to: 'customer@example.com' },
      reason: 'Send customer email',
      requestedBy: 'dev@example.com',
      toolName: 'gmail.send_email',
    },
    url: '/v1/tool-calls',
  });
}
