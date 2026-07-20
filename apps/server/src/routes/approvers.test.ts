import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { registerApproverRoutes } from './approvers';
import type { TelegramFetch, TelegramServiceConfig } from '../integrations/telegram/telegram-service';
import { ApproverDirectoryService } from '../services/approver-directory';
import { JsonlAuditStore } from '../storage/jsonl-audit-store';
import { MemoryStore } from '../storage/memory-store';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('approver routes', () => {
  it('creates, edits, and deletes approver users and groups', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    app = await makeApp(auditStore);

    const groupResponse = await app.inject({
      method: 'POST',
      payload: { description: 'Support leads', displayName: 'Support managers' },
      url: '/v1/approvers/groups',
    });
    const groupId = groupResponse.json().group.id as string;
    const userResponse = await app.inject({
      method: 'POST',
      payload: {
        defaultApprover: true,
        displayName: 'Alice',
        email: 'alice@example.com',
        groups: [groupId],
        principalId: 'oidc|alice',
        slackUserId: 'U_ALICE',
      },
      url: '/v1/approvers/users',
    });
    const userId = userResponse.json().user.id as string;
    const editedUserResponse = await app.inject({
      method: 'PUT',
      payload: {
        defaultApprover: false,
        displayName: 'Alice Manager',
        email: 'alice.manager@example.com',
        groups: [groupId],
      },
      url: `/v1/approvers/users/${userId}`,
    });
    const editedGroupResponse = await app.inject({
      method: 'PUT',
      payload: { description: 'Escalated support leads', displayName: 'Escalation managers' },
      url: `/v1/approvers/groups/${groupId}`,
    });
    const deleteGroupResponse = await app.inject({ method: 'DELETE', url: `/v1/approvers/groups/${groupId}` });
    const afterGroupDeleteResponse = await app.inject({ method: 'GET', url: '/v1/approvers' });
    const deleteResponse = await app.inject({ method: 'DELETE', url: `/v1/approvers/users/${userId}` });
    const listResponse = await app.inject({ method: 'GET', url: '/v1/approvers' });
    const events = await auditStore.list(30);

    expect(groupResponse.statusCode).toBe(201);
    expect(groupResponse.json().group).toMatchObject({ id: 'g_support_managers' });
    expect(userResponse.statusCode).toBe(201);
    expect(userResponse.json().user).toMatchObject({
      groups: ['g_support_managers'],
      id: 'u_alice',
      principalId: 'oidc|alice',
    });
    expect(editedUserResponse.statusCode).toBe(200);
    expect(editedUserResponse.json().user).toMatchObject({
      defaultApprover: false,
      displayName: 'Alice Manager',
        email: 'alice.manager@example.com',
        id: userId,
        principalId: 'oidc|alice',
    });
    expect(editedGroupResponse.statusCode).toBe(200);
    expect(editedGroupResponse.json().group).toMatchObject({
      description: 'Escalated support leads',
      displayName: 'Escalation managers',
      id: groupId,
    });
    expect(deleteGroupResponse.statusCode).toBe(200);
    expect(deleteGroupResponse.json()).toMatchObject({ deleted: true, group: { id: groupId } });
    expect(afterGroupDeleteResponse.json()).toMatchObject({
      groups: [],
      users: [expect.objectContaining({ groups: [], id: userId })],
    });
    expect(deleteResponse.statusCode).toBe(200);
    expect(deleteResponse.json()).toMatchObject({ deleted: true, user: { id: userId } });
    expect(listResponse.json()).toMatchObject({
      groups: [],
      users: [],
    });
    expect(events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'approver_directory.updated' }),
        expect.objectContaining({ data: expect.objectContaining({ action: 'create_group', groupId: 'g_support_managers' }) }),
        expect.objectContaining({ data: expect.objectContaining({ action: 'create_user', userId: 'u_alice' }) }),
        expect.objectContaining({ data: expect.objectContaining({ action: 'update_user', userId }) }),
        expect.objectContaining({ data: expect.objectContaining({ action: 'update_group', groupId }) }),
        expect.objectContaining({ data: expect.objectContaining({ action: 'delete_group', groupId }) }),
        expect.objectContaining({ data: expect.objectContaining({ action: 'delete_user', userId }) }),
      ]),
    );
  });

  it('does not let update endpoints create approver users or groups', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    app = await makeApp(auditStore);

    const userResponse = await app.inject({
      method: 'PUT',
      payload: { displayName: 'Alice' },
      url: '/v1/approvers/users/u_alice',
    });
    const groupResponse = await app.inject({
      method: 'PUT',
      payload: { displayName: 'Support managers' },
      url: '/v1/approvers/groups/support-managers',
    });
    const listResponse = await app.inject({ method: 'GET', url: '/v1/approvers' });

    expect(userResponse.statusCode).toBe(404);
    expect(groupResponse.statusCode).toBe(404);
    expect(listResponse.json()).toEqual({ groups: [], users: [] });
  });

  it('disconnects Telegram while keeping the approver user and saved username', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    const directory = new ApproverDirectoryService(new MemoryStore());
    app = await makeApp(auditStore, { directory });
    await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      telegramChatId: '222',
      telegramUsername: '@alice',
      telegramUserId: '111',
    });

    const disconnectResponse = await app.inject({
      method: 'DELETE',
      url: '/v1/approvers/users/u_alice/telegram-connection',
    });
    const listResponse = await app.inject({ method: 'GET', url: '/v1/approvers' });
    const events = await auditStore.list(20);

    expect(disconnectResponse.statusCode).toBe(200);
    expect(disconnectResponse.json().user).toMatchObject({
      id: 'u_alice',
      telegramUsername: 'alice',
    });
    expect(disconnectResponse.json().user).not.toHaveProperty('telegramChatId');
    expect(disconnectResponse.json().user).not.toHaveProperty('telegramUserId');
    expect(listResponse.json().users[0]).toMatchObject({
      id: 'u_alice',
      telegramUsername: 'alice',
    });
    expect(listResponse.json().users[0]).not.toHaveProperty('telegramChatId');
    expect(listResponse.json().users[0]).not.toHaveProperty('telegramUserId');
    expect(events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          data: expect.objectContaining({ action: 'telegram_disconnected', userId: 'u_alice' }),
          type: 'approver_directory.updated',
        }),
      ]),
    );
  });

  it('polls Telegram updates and connects a pending username user without a public webhook', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    const directory = new ApproverDirectoryService(new MemoryStore());
    const telegramFetch: TelegramFetch = async () => ({
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          ok: true,
          result: [
            {
              message: {
                chat: { id: 222 },
                from: { id: 111, username: 'alice' },
                text: '/start',
              },
              update_id: 10,
            },
          ],
        }),
    });
    app = await makeApp(auditStore, {
      directory,
      telegram: {
        configProvider: () => ({
          botToken: '123456:test-token',
          webhookSecret: 'telegram-secret',
        }),
        fetch: telegramFetch,
      },
    });
    await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      telegramUsername: '@alice',
    });

    const pollResponse = await app.inject({
      method: 'POST',
      url: '/v1/approvers/users/u_alice/telegram-connect/poll',
    });
    const listResponse = await app.inject({ method: 'GET', url: '/v1/approvers' });
    const events = await auditStore.list(20);

    expect(pollResponse.statusCode).toBe(200);
    expect(pollResponse.json()).toMatchObject({
      connected: true,
      user: {
        id: 'u_alice',
        telegramChatId: '222',
        telegramUserId: '111',
        telegramUsername: 'alice',
      },
    });
    expect(listResponse.json().users[0]).toMatchObject({
      telegramChatId: '222',
      telegramUserId: '111',
    });
    expect(events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          data: expect.objectContaining({
            action: 'telegram_connected',
            method: 'poll_username_start',
            userId: 'u_alice',
          }),
          type: 'approver_directory.updated',
        }),
      ]),
    );
  });

  it('connects a queued Telegram start after the saved username is corrected', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    const directory = new ApproverDirectoryService(new MemoryStore());
    const telegramFetch: TelegramFetch = async (_url, init) => {
      const body = JSON.parse(init.body) as { offset?: number };
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            result: body.offset
              ? []
              : [
                  {
                    message: {
                      chat: { id: 222 },
                      from: { id: 111, username: 'alice' },
                      text: '/start',
                    },
                    update_id: 10,
                  },
                ],
          }),
      };
    };
    app = await makeApp(auditStore, {
      directory,
      telegram: {
        configProvider: () => ({
          botToken: '123456:test-token',
          webhookSecret: 'telegram-secret',
        }),
        fetch: telegramFetch,
      },
    });
    await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      telegramUsername: '@wrong_username',
    });

    const waitingResponse = await app.inject({
      method: 'POST',
      url: '/v1/approvers/users/u_alice/telegram-connect/poll',
    });
    await directory.upsertUser('default', 'u_alice', { telegramUsername: '@alice' });
    const connectedResponse = await app.inject({
      method: 'POST',
      url: '/v1/approvers/users/u_alice/telegram-connect/poll',
    });

    expect(waitingResponse.statusCode).toBe(200);
    expect(waitingResponse.json()).toMatchObject({ connected: false });
    expect(connectedResponse.statusCode).toBe(200);
    expect(connectedResponse.json()).toMatchObject({
      connected: true,
      user: {
        id: 'u_alice',
        telegramChatId: '222',
        telegramUserId: '111',
        telegramUsername: 'alice',
      },
    });
  });

  it('treats concurrent Telegram getUpdates conflicts as retryable pending state', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    const directory = new ApproverDirectoryService(new MemoryStore());
    const telegramFetch: TelegramFetch = async () => ({
      ok: false,
      status: 409,
      text: async () =>
        JSON.stringify({
          description:
            'Conflict: terminated by other getUpdates request; make sure that only one bot instance is running',
          ok: false,
        }),
    });
    app = await makeApp(auditStore, {
      directory,
      telegram: {
        configProvider: () => ({
          botToken: '123456:test-token',
          webhookSecret: 'telegram-secret',
        }),
        fetch: telegramFetch,
      },
    });
    await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      telegramUsername: '@alice',
    });

    const pollResponse = await app.inject({
      method: 'POST',
      url: '/v1/approvers/users/u_alice/telegram-connect/poll',
    });

    expect(pollResponse.statusCode).toBe(200);
    expect(pollResponse.json()).toMatchObject({
      connected: false,
      message: expect.stringContaining('Another Telegram poll is already running'),
      user: { id: 'u_alice' },
    });
  });

  it('polls Telegram updates and connects a signed setup link when the saved username was stale', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    const directory = new ApproverDirectoryService(new MemoryStore());
    let startText = '/start';
    const telegramFetch: TelegramFetch = async (url, init) => {
      if (url.endsWith('/getMe')) {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ ok: true, result: { username: 'ActionProxyApprovalsBot' } }),
        };
      }

      const body = JSON.parse(init.body) as { offset?: number };
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            result: body.offset
              ? []
              : [
                  {
                    message: {
                      chat: { id: 222 },
                      from: { id: 111, username: 'alice' },
                      text: startText,
                    },
                    update_id: 10,
                  },
                ],
          }),
      };
    };
    app = await makeApp(auditStore, {
      directory,
      telegram: {
        configProvider: () => ({
          botToken: '123456:test-token',
          webhookSecret: 'telegram-secret',
        }),
        fetch: telegramFetch,
      },
    });
    await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      telegramUsername: '@wrong_alice',
    });
    const linkResponse = await app.inject({
      method: 'POST',
      url: '/v1/approvers/users/u_alice/telegram-connect',
    });
    const token = new URL(linkResponse.json().startLink).searchParams.get('start');
    startText = `/start ${token}`;

    const pollResponse = await app.inject({
      method: 'POST',
      url: '/v1/approvers/users/u_alice/telegram-connect/poll',
    });

    expect(pollResponse.statusCode).toBe(200);
    expect(pollResponse.json()).toMatchObject({
      connected: true,
      user: {
        id: 'u_alice',
        telegramChatId: '222',
        telegramUserId: '111',
        telegramUsername: 'alice',
      },
    });
  });
});

async function makeApp(
  auditStore: JsonlAuditStore,
  options: {
    directory?: ApproverDirectoryService;
    telegram?: {
      configProvider: () =>
        | Promise<(TelegramServiceConfig & { webhookSecret?: string }) | undefined>
        | (TelegramServiceConfig & { webhookSecret?: string })
        | undefined;
      fetch?: TelegramFetch;
    };
  } = {},
): Promise<FastifyInstance> {
  const server = Fastify({ logger: false });
  await registerApproverRoutes(
    server,
    options.directory ?? new ApproverDirectoryService(new MemoryStore()),
    auditStore,
    { telegram: options.telegram },
  );
  return server;
}

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-approvers-route-test-'));
}
