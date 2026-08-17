import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';
import type { TelegramFetch } from './telegram-service';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('Telegram webhook routes', () => {
  it('approves pending approvals through the existing approval path', async () => {
    const fetchMock = stubTelegramFetch();
    app = await makeApp();
    const submitted = await submitPendingApproval(app);
    const approvalId = submitted.approval.id as string;

    const response = await telegramCallback(app, 'approve', approvalId);
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
    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.telegram.org/bot123456:test-token/answerCallbackQuery',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor: 'telegram:111',
          approvalId,
          type: 'telegram.interaction.approved',
        }),
        expect.objectContaining({
          actor: 'telegram:111',
          approvalId,
          type: 'approval.approved',
        }),
      ]),
    );
  });

  it('rejects directly from Telegram and replaces the approval controls with terminal status', async () => {
    const fetchMock = stubTelegramFetch();
    app = await makeApp(directoryPolicyYaml(), { publicBaseUrl: 'https://actionproxy.example' });
    await app.inject({
      method: 'POST',
      payload: {
        displayName: 'Alice',
        email: 'alice@example.com',
        principalId: 'oidc|alice',
        telegramChatId: '222',
        telegramUserId: '111',
      },
      url: '/v1/approvers/users',
    });
    const submitted = await submitPendingApproval(app, {}, {
      body: 'Thanks',
      password: 'telegram-secret-value',
      subject: 'Update',
      to: 'customer@example.com',
    });
    const approvalId = submitted.approval.id as string;

    const response = await telegramCallback(app, 'reject', approvalId);
    const approval = await app.inject({ method: 'GET', url: `/v1/approvals/${approvalId}` });
    const toolCall = await app.inject({ method: 'GET', url: `/v1/tool-calls/${submitted.id}` });
    const editRequest = telegramRequestBodies(fetchMock, 'editMessageText').at(-1);

    expect(response.statusCode).toBe(200);
    expect(response.json().text).toContain('Rejected gmail.send_email');
    expect(approval.json().approval).toMatchObject({
      rejectedBy: 'alice@example.com',
      rejectionReason: 'Rejected from Telegram',
      status: 'rejected',
    });
    expect(toolCall.json()).toMatchObject({ status: 'rejected' });
    expect(editRequest).toMatchObject({
      chat_id: '222',
      message_id: 42,
      reply_markup: {
        inline_keyboard: [[{
          text: 'View status in ActionProxy',
          url: `https://actionproxy.example/#/approvals/${approvalId}`,
        }]],
      },
    });
    expect(editRequest?.text).toContain('❌ Rejected');
    expect(editRequest?.text).toContain('Alice');
    expect(editRequest?.text).toContain('Telegram');
    expect(editRequest?.text).toContain('customer@example.com');
    expect(editRequest?.text).toContain('[redacted]');
    expect(editRequest?.text).not.toContain('telegram-secret-value');
    expect(JSON.stringify(editRequest?.reply_markup)).not.toContain('callback_data');
  });

  it('answers a stale Telegram callback with the authoritative Web decision and repairs the card once', async () => {
    const fetchMock = stubTelegramFetch({ failFirstEdit: true });
    app = await makeApp(defaultPolicyYaml(), {
      publicBaseUrl: 'https://actionproxy.example',
    });
    await app.inject({
      method: 'POST',
      payload: {
        defaultApprover: true,
        displayName: 'Alice',
        email: 'alice@example.com',
        telegramChatId: '222',
        telegramUserId: '111',
      },
      url: '/v1/approvers/users',
    });
    const submitted = await submitPendingApproval(app);
    const approvalId = submitted.approval.id as string;

    const webApproval = await app.inject({
      method: 'POST',
      payload: { approvedBy: 'web-reviewer@example.com' },
      url: `/v1/approvals/${approvalId}/approve`,
    });
    const staleCallback = await telegramCallback(app, 'approve', approvalId);
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=100' });
    const editRequests = telegramRequestBodies(fetchMock, 'editMessageText');
    const callbackAnswers = telegramRequestBodies(fetchMock, 'answerCallbackQuery');
    const authoritativeReviewerLabel = 'web-reviewer@example.com';

    expect(webApproval.statusCode).toBe(200);
    expect(webApproval.json().approval.status).toBe('approved');
    expect(webApproval.json().approval.approvedBy).toBe('web-reviewer@example.com');
    expect(staleCallback.statusCode).toBe(200);
    expect(staleCallback.json().text).toContain('Already approved');
    expect(staleCallback.json().text).toContain(authoritativeReviewerLabel);
    expect(staleCallback.json().text).toContain('ActionProxy');
    expect(callbackAnswers.at(-1)?.text).toBe(staleCallback.json().text);
    expect(editRequests).toHaveLength(2);
    expect(editRequests.at(-1)?.text).toContain('✅ Approved');
    expect(editRequests.at(-1)?.text).toContain(authoritativeReviewerLabel);
    expect(editRequests.at(-1)?.text).toContain('ActionProxy');
    expect(JSON.stringify(editRequests.at(-1)?.reply_markup)).not.toContain('callback_data');
    expect(
      audit.json().events.filter(
        (event: { toolCallId?: string; type?: string }) =>
          event.toolCallId === submitted.id && event.type === 'tool_call.executed',
      ),
    ).toHaveLength(1);
  });

  it('converges Telegram cards on the atomic winner of concurrent Web approval and Telegram rejection', async () => {
    const fetchMock = stubTelegramFetch();
    app = await makeApp(defaultPolicyYaml(), {
      publicBaseUrl: 'https://actionproxy.example',
    });
    await app.inject({
      method: 'POST',
      payload: {
        defaultApprover: true,
        displayName: 'Alice',
        email: 'alice@example.com',
        telegramChatId: '222',
        telegramUserId: '111',
      },
      url: '/v1/approvers/users',
    });
    const submitted = await submitPendingApproval(app);
    const approvalId = submitted.approval.id as string;

    const [webApproval, telegramRejection] = await Promise.all([
      app.inject({
        method: 'POST',
        payload: { approvedBy: 'web-reviewer@example.com' },
        url: `/v1/approvals/${approvalId}/approve`,
      }),
      telegramCallback(app, 'reject', approvalId),
    ]);
    const approval = await app.inject({ method: 'GET', url: `/v1/approvals/${approvalId}` });
    const toolCall = await app.inject({ method: 'GET', url: `/v1/tool-calls/${submitted.id}` });
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=100' });
    const events = audit.json().events as Array<{
      approvalId?: string;
      data: { source?: string };
      toolCallId?: string;
      type: string;
    }>;
    const terminalEvents = events.filter((event) =>
      event.approvalId === approvalId &&
      (event.type === 'approval.approved' || event.type === 'approval.rejected'));
    const executedEvents = events.filter((event) =>
      event.toolCallId === submitted.id && event.type === 'tool_call.executed');
    const winner = terminalEvents[0]!;
    const winningStatus = winner.type === 'approval.approved' ? 'approved' : 'rejected';
    const winningSource = winner.data.source;
    const editRequests = telegramRequestBodies(fetchMock, 'editMessageText');

    expect(telegramRejection.statusCode).toBe(200);
    expect(webApproval.statusCode).toBe(winningStatus === 'approved' ? 200 : 409);
    expect(terminalEvents).toHaveLength(1);
    expect(winningSource).toBe(winningStatus === 'approved' ? 'actionproxy' : 'telegram');
    expect(approval.json().approval.status).toBe(winningStatus);
    expect(toolCall.json().status).toBe(winningStatus === 'approved' ? 'executed' : 'rejected');
    expect(executedEvents).toHaveLength(winningStatus === 'approved' ? 1 : 0);
    expect(executedEvents.length).toBeLessThanOrEqual(1);
    expect(editRequests.length).toBeGreaterThanOrEqual(1);
    for (const edit of editRequests) {
      expect(edit.text).toContain(winningStatus === 'approved' ? '✅ Approved' : '❌ Rejected');
      expect(edit.text).toContain(
        `Decision source: ${winningSource === 'telegram' ? 'Telegram' : 'ActionProxy'}`,
      );
      expect(JSON.stringify(edit.reply_markup)).not.toContain('callback_data');
    }
  });

  it('does not reveal terminal reviewer metadata to an approver outside the frozen route', async () => {
    const fetchMock = stubTelegramFetch();
    app = await makeApp(directoryPolicyYaml(), {
      authMode: 'api_key',
      publicBaseUrl: 'https://actionproxy.example',
    });
    const adminHeaders = { authorization: 'Bearer telegram-route-bootstrap-key' };
    await app.inject({
      headers: adminHeaders,
      method: 'POST',
      payload: {
        displayName: 'Alice',
        email: 'alice@example.com',
        principalId: 'oidc|alice',
        telegramChatId: '222',
        telegramUserId: '111',
      },
      url: '/v1/approvers/users',
    });
    await app.inject({
      headers: adminHeaders,
      method: 'POST',
      payload: {
        displayName: 'Mallory Reviewer',
        email: 'mallory@example.com',
        principalId: 'oidc|mallory',
        telegramChatId: '333',
        telegramUserId: '333',
      },
      url: '/v1/approvers/users',
    });
    const submitted = await submitPendingApproval(app, adminHeaders);
    const approvalId = submitted.approval.id as string;

    const approved = await telegramCallback(app, 'approve', approvalId, 111);
    const editsBeforeUnauthorizedClick = telegramRequestBodies(fetchMock, 'editMessageText').length;
    const unauthorizedStale = await telegramCallback(app, 'approve', approvalId, 333);
    const editRequests = telegramRequestBodies(fetchMock, 'editMessageText');

    expect(approved.statusCode).toBe(200);
    expect(approved.json().text).toContain('Approved gmail.send_email');
    expect(unauthorizedStale.statusCode).toBe(200);
    expect(unauthorizedStale.json().text).toContain('Principal is not an allowed approver');
    expect(unauthorizedStale.json().text).not.toContain('Alice');
    expect(unauthorizedStale.json().text).not.toContain('alice@example.com');
    expect(editRequests).toHaveLength(editsBeforeUnauthorizedClick);
  });

  it('answers an expiry-observing click after the single reconciliation already performed', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-08-13T10:00:00.000Z'));
    const fetchMock = stubTelegramFetch();
    app = await makeApp(defaultPolicyYaml(), {
      publicBaseUrl: 'https://actionproxy.example',
    });
    await app.inject({
      method: 'POST',
      payload: {
        defaultApprover: true,
        displayName: 'Alice',
        email: 'alice@example.com',
        telegramChatId: '222',
        telegramUserId: '111',
      },
      url: '/v1/approvers/users',
    });
    const submitted = await submitPendingApproval(app);
    const approvalId = submitted.approval.id as string;
    vi.setSystemTime(new Date('2026-08-14T10:00:00.001Z'));

    const response = await telegramCallback(app, 'approve', approvalId);
    const edits = telegramRequestBodies(fetchMock, 'editMessageText');

    expect(response.statusCode).toBe(200);
    expect(response.json().text).toBe('Already expired via ActionProxy.');
    expect(edits).toHaveLength(1);
    expect(edits[0]?.message_id).toBe(42);
    expect(edits[0]?.text).toContain('⌛ Expired');
    expect(edits[0]?.text).not.toContain('Resolved by: Alice');
    expect(edits[0]?.text).not.toContain('actionproxy:approval-expiry');
  });

  it('repairs an untracked clicked card after expiry without repeating the stored-card repair', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-08-13T10:00:00.000Z'));
    const fetchMock = stubTelegramFetch();
    app = await makeApp(defaultPolicyYaml(), {
      publicBaseUrl: 'https://actionproxy.example',
    });
    await app.inject({
      method: 'POST',
      payload: {
        defaultApprover: true,
        displayName: 'Alice',
        email: 'alice@example.com',
        telegramChatId: '222',
        telegramUserId: '111',
      },
      url: '/v1/approvers/users',
    });
    const submitted = await submitPendingApproval(app);
    const approvalId = submitted.approval.id as string;
    vi.setSystemTime(new Date('2026-08-14T10:00:00.001Z'));

    const response = await telegramCallback(app, 'approve', approvalId, 111, 99);
    const edits = telegramRequestBodies(fetchMock, 'editMessageText');

    expect(response.statusCode).toBe(200);
    expect(response.json().text).toBe('Already expired via ActionProxy.');
    expect(edits).toHaveLength(2);
    expect(edits.map((edit) => edit.message_id)).toEqual([42, 99]);
    expect(edits.filter((edit) => edit.message_id === 42)).toHaveLength(1);
    expect(edits.filter((edit) => edit.message_id === 99)).toHaveLength(1);
    for (const edit of edits) {
      expect(edit.text).toContain('⌛ Expired');
      expect(JSON.stringify(edit.reply_markup)).not.toContain('callback_data');
    }
  });

  it('authorizes Telegram callbacks through the approver directory', async () => {
    stubTelegramFetch();
    app = await makeApp(directoryPolicyYaml());
    await app.inject({
      method: 'POST',
      payload: {
        displayName: 'Alice',
        email: 'alice@example.com',
        principalId: 'oidc|alice',
        telegramChatId: '222',
        telegramUserId: '111',
      },
      url: '/v1/approvers/users',
    });
    const submitted = await submitPendingApproval(app);
    const approvalId = submitted.approval.id as string;
    const pending = await app.inject({ method: 'GET', url: '/v1/approvals/pending' });

    const response = await telegramCallback(app, 'approve', approvalId);
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=30' });

    expect(pending.json().approvals[0].approverUsers).toEqual(['oidc|alice']);
    expect(response.statusCode).toBe(200);
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor: 'alice@example.com',
          approvalId,
          auth: expect.objectContaining({ authProvider: 'telegram', principalId: 'oidc|alice' }),
          type: 'approval.approved',
        }),
        expect.objectContaining({
          approvalId,
          data: expect.objectContaining({ recipientTelegramChatId: '222', recipientTelegramUserId: '111' }),
          type: 'approval_notification.sent',
        }),
      ]),
    );
  });

  it('connects an approver user from a Telegram deep link start message', async () => {
    stubTelegramFetch();
    app = await makeApp(directoryPolicyYaml());
    await app.inject({
      method: 'POST',
      payload: {
        displayName: 'Alice',
        email: 'alice@example.com',
      },
      url: '/v1/approvers/users',
    });

    const linkResponse = await app.inject({
      method: 'POST',
      url: '/v1/approvers/users/u_alice/telegram-connect',
    });
    const token = new URL(linkResponse.json().startLink).searchParams.get('start');
    const connectResponse = await app.inject({
      headers: {
        'x-telegram-bot-api-secret-token': 'telegram_test_secret',
      },
      method: 'POST',
      payload: {
        message: {
          chat: { id: 222 },
          from: { first_name: 'Alice', id: 111, username: 'alice' },
          text: `/start ${token}`,
        },
      },
      url: '/v1/telegram/webhook',
    });
    const directory = await app.inject({ method: 'GET', url: '/v1/approvers' });

    expect(linkResponse.statusCode).toBe(200);
    expect(linkResponse.json()).toMatchObject({
      botUsername: 'ActionProxyApprovalsBot',
      userId: 'u_alice',
    });
    expect(connectResponse.statusCode).toBe(200);
    expect(connectResponse.json().text).toContain('Connected Telegram for Alice');
    expect(directory.json().users[0]).toMatchObject({
      id: 'u_alice',
      telegramChatId: '222',
      telegramUsername: 'alice',
      telegramUserId: '111',
    });
  });

  it('connects an approver user by saved Telegram username from a plain start message', async () => {
    stubTelegramFetch();
    app = await makeApp(directoryPolicyYaml());
    await app.inject({
      method: 'POST',
      payload: {
        displayName: 'Alice',
        email: 'alice@example.com',
        telegramUsername: '@Alice_Manager',
      },
      url: '/v1/approvers/users',
    });

    const connectResponse = await app.inject({
      headers: {
        'x-telegram-bot-api-secret-token': 'telegram_test_secret',
      },
      method: 'POST',
      payload: {
        message: {
          chat: { id: 222 },
          from: { first_name: 'Alice', id: 111, username: 'alice_manager' },
          text: '/start',
        },
      },
      url: '/v1/telegram/webhook',
    });
    const directory = await app.inject({ method: 'GET', url: '/v1/approvers' });

    expect(connectResponse.statusCode).toBe(200);
    expect(connectResponse.json().text).toContain('Connected Telegram for Alice');
    expect(directory.json().users[0]).toMatchObject({
      id: 'u_alice',
      telegramChatId: '222',
      telegramUsername: 'alice_manager',
      telegramUserId: '111',
    });
  });

  it('does not connect a plain start message when no saved Telegram username matches', async () => {
    stubTelegramFetch();
    app = await makeApp(directoryPolicyYaml());
    await app.inject({
      method: 'POST',
      payload: {
        displayName: 'Alice',
        email: 'alice@example.com',
        telegramUsername: '@alice',
      },
      url: '/v1/approvers/users',
    });

    const connectResponse = await app.inject({
      headers: {
        'x-telegram-bot-api-secret-token': 'telegram_test_secret',
      },
      method: 'POST',
      payload: {
        message: {
          chat: { id: 222 },
          from: { first_name: 'Mallory', id: 333, username: 'mallory' },
          text: '/start',
        },
      },
      url: '/v1/telegram/webhook',
    });
    const directory = await app.inject({ method: 'GET', url: '/v1/approvers' });

    expect(connectResponse.statusCode).toBe(200);
    expect(connectResponse.json().text).toContain('No enabled ActionProxy approver user is configured');
    expect(directory.json().users[0]).toMatchObject({
      telegramUsername: 'alice',
    });
    expect(directory.json().users[0].telegramChatId).toBeUndefined();
    expect(directory.json().users[0].telegramUserId).toBeUndefined();
  });

  it('explains plain start username setup when Telegram does not report a public username', async () => {
    stubTelegramFetch();
    app = await makeApp(directoryPolicyYaml());
    await app.inject({
      method: 'POST',
      payload: {
        displayName: 'Alice',
        email: 'alice@example.com',
        telegramUsername: '@alice',
      },
      url: '/v1/approvers/users',
    });

    const connectResponse = await app.inject({
      headers: {
        'x-telegram-bot-api-secret-token': 'telegram_test_secret',
      },
      method: 'POST',
      payload: {
        message: {
          chat: { id: 222 },
          from: { first_name: 'Alice', id: 111 },
          text: '/start',
        },
      },
      url: '/v1/telegram/webhook',
    });
    const directory = await app.inject({ method: 'GET', url: '/v1/approvers' });

    expect(connectResponse.statusCode).toBe(200);
    expect(connectResponse.json().text).toContain('Telegram did not report a public username');
    expect(directory.json().users[0]).toMatchObject({
      telegramUsername: 'alice',
    });
    expect(directory.json().users[0].telegramChatId).toBeUndefined();
    expect(directory.json().users[0].telegramUserId).toBeUndefined();
  });

  it('connects a Telegram setup link when the saved username was stale', async () => {
    stubTelegramFetch();
    app = await makeApp(directoryPolicyYaml());
    await app.inject({
      method: 'POST',
      payload: {
        displayName: 'Alice',
        email: 'alice@example.com',
        telegramUsername: '@alice',
      },
      url: '/v1/approvers/users',
    });

    const linkResponse = await app.inject({
      method: 'POST',
      url: '/v1/approvers/users/u_alice/telegram-connect',
    });
    const token = new URL(linkResponse.json().startLink).searchParams.get('start');
    const connectResponse = await app.inject({
      headers: {
        'x-telegram-bot-api-secret-token': 'telegram_test_secret',
      },
      method: 'POST',
      payload: {
        message: {
          chat: { id: 222 },
          from: { first_name: 'Mallory', id: 333, username: 'mallory' },
          text: `/start ${token}`,
        },
      },
      url: '/v1/telegram/webhook',
    });
    const directory = await app.inject({ method: 'GET', url: '/v1/approvers' });

    expect(connectResponse.statusCode).toBe(200);
    expect(connectResponse.json().text).toContain('Connected Telegram for Alice');
    expect(directory.json().users[0]).toMatchObject({
      telegramChatId: '222',
      telegramUsername: 'mallory',
      telegramUserId: '333',
    });
  });

  it('rejects Telegram webhook requests with an invalid secret token', async () => {
    stubTelegramFetch();
    app = await makeApp();

    const response = await app.inject({
      headers: {
        'x-telegram-bot-api-secret-token': 'invalid',
      },
      method: 'POST',
      payload: telegramUpdate('approve', 'approval_missing'),
      url: '/v1/telegram/webhook',
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toEqual({ error: 'invalid_telegram_secret' });
  });

  it.each(['api_key', 'oidc_jwt'] as const)(
    'keeps the webhook bearer-exempt but enforces Telegram secret and approver authorization in %s mode',
    async (authMode) => {
      stubTelegramFetch();
      app = await makeApp(directoryPolicyYaml(), { authMode });
      const adminHeaders = { authorization: 'Bearer telegram-route-bootstrap-key' };
      await app.inject({
        headers: adminHeaders,
        method: 'POST',
        payload: {
          displayName: 'Alice',
          email: 'alice@example.com',
          telegramChatId: '222',
          telegramUserId: '111',
        },
        url: '/v1/approvers/users',
      });
      const submitted = await submitPendingApproval(app, adminHeaders);

      const invalid = await app.inject({
        headers: { 'x-telegram-bot-api-secret-token': 'invalid' },
        method: 'POST',
        payload: telegramUpdate('approve', submitted.approval.id),
        url: '/v1/telegram/webhook',
      });
      const valid = await telegramCallback(app, 'approve', submitted.approval.id);

      expect(invalid.statusCode).toBe(401);
      expect(invalid.json()).toEqual({ error: 'invalid_telegram_secret' });
      expect(valid.statusCode).toBe(200);
      expect(valid.json().text).toContain('Approved gmail.send_email');
    },
  );
});

async function makeApp(
  policyYaml = defaultPolicyYaml(),
  options: { authMode?: 'api_key' | 'oidc_jwt'; publicBaseUrl?: string } = {},
): Promise<FastifyInstance> {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-telegram-route-test-'));
  const policyPath = path.join(dataDir, 'policy.yaml');
  fs.writeFileSync(policyPath, policyYaml, 'utf8');
  return buildApp({
    auth: options.authMode
      ? {
          allowedCorsOrigins: [],
          bootstrapAdminApiKey: 'telegram-route-bootstrap-key',
          mode: options.authMode,
          oidc: {
            emailClaim: 'email',
            groupsClaim: 'groups',
            nameClaim: 'name',
            scopesClaim: 'scope',
          },
          rateLimit: { max: 1000, windowMs: 60_000 },
          slackUserMap: {},
          workspaceId: 'default',
        }
      : undefined,
    dataDir,
    host: '127.0.0.1',
    localExecution: { mode: 'mock' },
    logLevel: 'silent',
    policyPath,
    port: 0,
    telegram: {
      botToken: '123456:test-token',
      publicBaseUrl: options.publicBaseUrl,
      webhookSecret: 'telegram_test_secret',
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
    '',
  ].join('\n');
}

async function submitPendingApproval(
  server: FastifyInstance,
  headers: Record<string, string> = {},
  input: Record<string, unknown> = {
    body: 'Thanks',
    subject: 'Update',
    to: 'customer@example.com',
  },
) {
  const response = await server.inject({
    headers,
    method: 'POST',
    payload: {
      agentId: 'demo-agent',
      input,
      reason: 'Send email',
      requestedBy: 'dev@example.com',
      toolName: 'gmail.send_email',
    },
    url: '/v1/tool-calls',
  });
  return response.json();
}

async function telegramCallback(
  server: FastifyInstance,
  action: 'approve' | 'reject',
  approvalId: string,
  telegramUserId = 111,
  messageId = 42,
) {
  return server.inject({
    headers: {
      'x-telegram-bot-api-secret-token': 'telegram_test_secret',
    },
    method: 'POST',
    payload: telegramUpdate(action, approvalId, telegramUserId, messageId),
    url: '/v1/telegram/webhook',
  });
}

function telegramUpdate(
  action: 'approve' | 'reject',
  approvalId: string,
  telegramUserId = 111,
  messageId = 42,
) {
  return {
    callback_query: {
      data: `${action}:${approvalId}`,
      from: { first_name: 'Manager', id: telegramUserId, username: 'manager' },
      id: 'callback_1',
      message: {
        chat: { id: 222 },
        message_id: messageId,
      },
    },
  };
}

function stubTelegramFetch(options: { failFirstEdit?: boolean } = {}) {
  let editAttempts = 0;
  const fetchMock = vi.fn<TelegramFetch>(async (url) => {
    if (url.endsWith('/editMessageText') && options.failFirstEdit && editAttempts++ === 0) {
      return {
        ok: false,
        status: 400,
        text: async () => JSON.stringify({ description: 'message cannot be edited', ok: false }),
      };
    }
    return {
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify(
          url.endsWith('/getMe')
            ? { ok: true, result: { username: 'ActionProxyApprovalsBot' } }
            : url.endsWith('/sendMessage')
            ? { ok: true, result: { chat: { id: 222 }, message_id: 42 } }
            : { ok: true, result: true },
        ),
    };
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function telegramRequestBodies(fetchMock: ReturnType<typeof stubTelegramFetch>, method: string) {
  return fetchMock.mock.calls
    .filter(([url]) => url.endsWith(`/${method}`))
    .map(([, init]) => JSON.parse(init.body) as {
      callback_query_id?: string;
      chat_id?: string;
      message_id?: number;
      reply_markup?: { inline_keyboard?: Array<Array<Record<string, string>>> };
      text?: string;
    });
}
