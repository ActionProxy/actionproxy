import { createHmac } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import { SLACK_APPROVE_ACTION_ID, SLACK_REJECT_ACTION_ID } from './slack-blocks';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('Slack interaction routes', () => {
  it('approves pending approvals through the existing approval path', async () => {
    app = await makeApp();
    const submitted = await submitPendingApproval(app);
    const approvalId = submitted.approval.id as string;

    const response = await slackAction(app, SLACK_APPROVE_ACTION_ID, approvalId);
    const pending = await app.inject({ method: 'GET', url: '/v1/approvals/pending' });
    const toolCall = await app.inject({ method: 'GET', url: `/v1/tool-calls/${submitted.id}` });
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=20' });

    expect(response.statusCode).toBe(200);
    expect(response.json().text).toContain('Approved gmail.send_email');
    expect(pending.json().approvals).toEqual([]);
    expect(toolCall.json()).toMatchObject({
      status: 'executed',
      result: { ok: true, tool: 'gmail.send_email', to: 'customer@example.com' },
    });
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor: 'slack:U123',
          approvalId,
          type: 'slack.interaction.approved',
        }),
        expect.objectContaining({
          actor: 'slack:U123',
          approvalId,
          type: 'approval.approved',
        }),
      ]),
    );
  });

  it('rejects pending approvals through the existing approval path', async () => {
    app = await makeApp();
    const submitted = await submitPendingApproval(app);
    const approvalId = submitted.approval.id as string;

    const response = await slackAction(app, SLACK_REJECT_ACTION_ID, approvalId);
    const toolCall = await app.inject({ method: 'GET', url: `/v1/tool-calls/${submitted.id}` });
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=20' });

    expect(response.statusCode).toBe(200);
    expect(response.json().text).toContain('Rejected gmail.send_email');
    expect(toolCall.json()).toMatchObject({ status: 'rejected' });
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor: 'slack:U123',
          approvalId,
          type: 'slack.interaction.rejected',
        }),
      ]),
    );
  });

  it('authorizes Slack callbacks through the approver directory', async () => {
    app = await makeApp(directoryPolicyYaml());
    await app.inject({
      method: 'POST',
      payload: {
        displayName: 'Alice',
        email: 'alice@example.com',
        principalId: 'oidc|alice',
        slackUserId: 'U123',
      },
      url: '/v1/approvers/users',
    });
    const submitted = await submitPendingApproval(app);
    const approvalId = submitted.approval.id as string;
    const pending = await app.inject({ method: 'GET', url: '/v1/approvals/pending' });

    const response = await slackAction(app, SLACK_APPROVE_ACTION_ID, approvalId);
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=20' });

    expect(pending.json().approvals[0].approverUsers).toEqual(['oidc|alice']);
    expect(response.statusCode).toBe(200);
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor: 'alice@example.com',
          approvalId,
          auth: expect.objectContaining({ principalId: 'oidc|alice' }),
          type: 'approval.approved',
        }),
      ]),
    );
  });

  it('rejects Slack requests with invalid signatures', async () => {
    app = await makeApp();
    const response = await app.inject({
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'x-slack-request-timestamp': currentTimestamp(),
        'x-slack-signature': 'v0=invalid',
      },
      method: 'POST',
      payload: new URLSearchParams({ payload: JSON.stringify({ type: 'block_actions' }) }).toString(),
      url: '/v1/slack/interactions',
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: 'invalid_slack_signature' });
  });
});

async function makeApp(policyYaml = defaultPolicyYaml()): Promise<FastifyInstance> {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-slack-route-test-'));
  const policyPath = path.join(dataDir, 'policy.yaml');
  fs.writeFileSync(policyPath, policyYaml, 'utf8');
  return buildApp({
    dataDir,
    host: '127.0.0.1',
    localExecution: { mode: 'mock' },
    logLevel: 'silent',
    policyPath,
    port: 0,
    slack: {
      signingSecret: 'slack_test_secret',
    },
  });
}

function directoryPolicyYaml(): string {
  return [
    'version: 1',
    'default:',
    '  approval: required',
    '  risk: unknown',
    'tools:',
    '  gmail.send_email:',
    '    approval: required',
    '    risk: external',
    '    approvers:',
    '      users:',
    '        - u_alice',
    '',
  ].join('\n');
}

function defaultPolicyYaml(): string {
  return [
    'version: 1',
    'default:',
    '  approval: required',
    '  risk: unknown',
    'tools:',
    '  docs.search:',
    '    approval: never',
    '    risk: read_only',
    '  gmail.send_email:',
    '    approval: required',
    '    risk: external_communication',
    '  dangerous.delete_customer:',
    '    approval: deny',
    '    risk: destructive',
    '',
  ].join('\n');
}

async function submitPendingApproval(server: FastifyInstance) {
  const response = await server.inject({
    method: 'POST',
    payload: {
      agentId: 'demo-agent',
      input: { to: 'customer@example.com', subject: 'Update', body: 'Thanks' },
      reason: 'Send email',
      requestedBy: 'dev@example.com',
      toolName: 'gmail.send_email',
    },
    url: '/v1/tool-calls',
  });
  return response.json();
}

async function slackAction(server: FastifyInstance, actionId: string, approvalId: string) {
  const payload = new URLSearchParams({
    payload: JSON.stringify({
      actions: [{ action_id: actionId, value: approvalId }],
      channel: { id: 'C123' },
      message: { ts: '1710000000.000100' },
      type: 'block_actions',
      user: { id: 'U123', username: 'manager' },
    }),
  }).toString();
  const timestamp = currentTimestamp();

  return server.inject({
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'x-slack-request-timestamp': timestamp,
      'x-slack-signature': sign('slack_test_secret', timestamp, payload),
    },
    method: 'POST',
    payload,
    url: '/v1/slack/interactions',
  });
}

function currentTimestamp(): string {
  return String(Math.floor(Date.now() / 1000));
}

function sign(secret: string, timestamp: string, body: string): string {
  return `v0=${createHmac('sha256', secret).update(`v0:${timestamp}:${body}`).digest('hex')}`;
}
