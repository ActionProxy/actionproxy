import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../../app';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
  vi.unstubAllGlobals();
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
  options: { authMode?: 'api_key' | 'oidc_jwt' } = {},
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

async function submitPendingApproval(server: FastifyInstance, headers: Record<string, string> = {}) {
  const response = await server.inject({
    headers,
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

async function telegramCallback(
  server: FastifyInstance,
  action: 'approve' | 'reject',
  approvalId: string,
) {
  return server.inject({
    headers: {
      'x-telegram-bot-api-secret-token': 'telegram_test_secret',
    },
    method: 'POST',
    payload: telegramUpdate(action, approvalId),
    url: '/v1/telegram/webhook',
  });
}

function telegramUpdate(action: 'approve' | 'reject', approvalId: string) {
  return {
    callback_query: {
      data: `${action}:${approvalId}`,
      from: { first_name: 'Manager', id: 111, username: 'manager' },
      id: 'callback_1',
      message: {
        chat: { id: 222 },
        message_id: 42,
      },
    },
  };
}

function stubTelegramFetch() {
  const fetchMock = vi.fn(async (url: string) => ({
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
  }));
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}
