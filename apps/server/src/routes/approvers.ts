import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  createTelegramConnectToken,
  isTelegramStartCommand,
  parseTelegramConnectToken,
  telegramStartTokenFromText,
} from '../integrations/telegram/telegram-connect';
import { telegramMethodUrl, type TelegramFetch, type TelegramServiceConfig } from '../integrations/telegram/telegram-service';
import type { ApproverUserRecord } from '../models';
import type { AuditStore } from '../storage/audit-store';
import { requireScope } from '../security/scopes';
import { normalizeTelegramUsername, type ApproverDirectoryService } from '../services/approver-directory';
import { authContext, mapKnownError } from './route-utils';

const approverIdSchema = z.string().min(1).max(120).regex(/^[A-Za-z0-9._@-]+$/);

const userBodySchema = z.object({
  defaultApprover: z.boolean().optional(),
  displayName: z.string().optional(),
  email: z.string().email().optional().or(z.literal('')),
  enabled: z.boolean().optional(),
  groups: z.array(z.string().min(1)).optional(),
  principalId: z.string().trim().min(1).max(512).optional(),
  slackUserId: z.string().optional(),
  telegramChatId: z.string().optional(),
  telegramUsername: z.string().optional(),
  telegramUserId: z.string().optional(),
});

const groupBodySchema = z.object({
  description: z.string().optional(),
  displayName: z.string().optional(),
  enabled: z.boolean().optional(),
});

export async function registerApproverRoutes(
  app: FastifyInstance,
  approverDirectory: ApproverDirectoryService,
  auditStore: AuditStore,
  options: {
    telegram?: {
      configProvider: () => Promise<(TelegramServiceConfig & { webhookSecret?: string }) | undefined> | (TelegramServiceConfig & { webhookSecret?: string }) | undefined;
      fetch?: TelegramFetch;
    };
  } = {},
): Promise<void> {
  app.get('/v1/approvers', async (request) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    return approverDirectory.list(auth.workspaceId);
  });

  app.post('/v1/approvers/users', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    const parsed = userBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const user = await approverDirectory.createUser(auth.workspaceId, parsed.data);
      await appendApproverAudit(auditStore, auth, {
        action: 'create_user',
        defaultApprover: user.defaultApprover,
        enabled: user.enabled,
        groups: user.groups,
        principalId: user.principalId ?? null,
        userId: user.id,
      });
      return reply.status(201).send({ user });
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.put('/v1/approvers/users/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    const params = z.object({ id: approverIdSchema }).safeParse(request.params);
    const parsed = userBodySchema.safeParse(request.body);
    if (!params.success || !parsed.success) {
      return reply.status(400).send({
        error: 'invalid_request',
        details: {
          params: params.success ? undefined : params.error.flatten(),
          body: parsed.success ? undefined : parsed.error.flatten(),
        },
      });
    }

    const existing = await approverDirectory.getUser(auth.workspaceId, params.data.id);
    if (!existing) {
      return reply.status(404).send({ error: 'approver_not_found', message: `Approver user not found: ${params.data.id}` });
    }

    const user = await approverDirectory.upsertUser(auth.workspaceId, params.data.id, parsed.data);
    await appendApproverAudit(auditStore, auth, {
      action: 'update_user',
      defaultApprover: user.defaultApprover,
      enabled: user.enabled,
      groups: user.groups,
      principalId: user.principalId ?? null,
      userId: user.id,
    });
    return { user };
  });

  app.post('/v1/approvers/users/:id/telegram-connect', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    const params = z.object({ id: approverIdSchema }).safeParse(request.params);
    if (!params.success) {
      return reply.status(400).send({ error: 'invalid_request', details: params.error.flatten() });
    }

    const user = await approverDirectory.getUser(auth.workspaceId, params.data.id);
    if (!user) {
      return reply.status(404).send({ error: 'approver_not_found', message: `Approver user not found: ${params.data.id}` });
    }

    const config = await options.telegram?.configProvider();
    if (!config?.botToken || !config.webhookSecret) {
      return reply.status(409).send({
        error: 'telegram_not_ready',
        message: 'Telegram bot token and webhook secret must be configured before creating connect links.',
      });
    }

    let botUsername: string;
    try {
      botUsername = await fetchTelegramBotUsername(config.botToken, options.telegram?.fetch);
    } catch (error) {
      return reply.status(502).send({
        error: 'telegram_bot_lookup_failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }

    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    let token: string;
    try {
      token = createTelegramConnectToken({
        expiresAt,
        secret: config.webhookSecret,
        userId: user.id,
      });
    } catch (error) {
      return reply.status(400).send({
        error: 'telegram_connect_link_failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }

    const startLink = `https://t.me/${botUsername}?start=${encodeURIComponent(token)}`;
    await appendApproverAudit(auditStore, auth, {
      action: 'telegram_connect_link_created',
      expiresAt: expiresAt.toISOString(),
      userId: user.id,
    });

    return {
      botUsername,
      expiresAt: expiresAt.toISOString(),
      startLink,
      userId: user.id,
    };
  });

  app.post('/v1/approvers/users/:id/telegram-connect/poll', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    const params = z.object({ id: approverIdSchema }).safeParse(request.params);
    if (!params.success) {
      return reply.status(400).send({ error: 'invalid_request', details: params.error.flatten() });
    }

    const user = await approverDirectory.getUser(auth.workspaceId, params.data.id);
    if (!user) {
      return reply.status(404).send({ error: 'approver_not_found', message: `Approver user not found: ${params.data.id}` });
    }

    if (user.telegramChatId && user.telegramUserId) {
      return { connected: true, user };
    }

    const config = await options.telegram?.configProvider();
    if (!config?.botToken || !config.webhookSecret) {
      return reply.status(409).send({
        connected: false,
        error: 'telegram_not_ready',
        message: 'Telegram bot token and webhook secret must be configured before polling connect updates.',
        user,
      });
    }

    try {
      const match = await pollTelegramConnectUpdate(config, user, options.telegram?.fetch);
      if (!match) {
        return {
          connected: false,
          message: 'Waiting for the user to start the ActionProxy Telegram bot.',
          user,
        };
      }

      const connectedUser = await approverDirectory.connectTelegramUser(auth.workspaceId, user.id, {
        telegramChatId: match.telegramChatId,
        telegramUsername: match.telegramUsername,
        telegramUserId: match.telegramUserId,
      });
      await appendApproverAudit(auditStore, auth, {
        action: 'telegram_connected',
        method: match.method,
        telegramChatId: match.telegramChatId,
        telegramUsername: match.telegramUsername ? `@${match.telegramUsername}` : null,
        telegramUserId: match.telegramUserId,
        updateId: match.updateId,
        userId: connectedUser.id,
      });
      await acknowledgeTelegramUpdate(config.botToken, match.updateId, options.telegram?.fetch);
      return { connected: true, user: connectedUser };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('getUpdates') && message.toLowerCase().includes('webhook')) {
        return {
          connected: false,
          message: 'Waiting for Telegram webhook delivery.',
          user,
        };
      }
      if (message.includes('getUpdates') && message.toLowerCase().includes('terminated by other getupdates request')) {
        return {
          connected: false,
          message:
            'Another Telegram poll is already running for this bot. Wait a few seconds, then check again; stop any other local ActionProxy server using the same bot token if this keeps happening.',
          user,
        };
      }

      return reply.status(502).send({
        connected: false,
        error: 'telegram_poll_failed',
        message,
        user,
      });
    }
  });

  app.delete('/v1/approvers/users/:id/telegram-connection', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    const params = z.object({ id: approverIdSchema }).safeParse(request.params);
    if (!params.success) {
      return reply.status(400).send({ error: 'invalid_request', details: params.error.flatten() });
    }

    try {
      const user = await approverDirectory.disconnectTelegramUser(auth.workspaceId, params.data.id);
      await appendApproverAudit(auditStore, auth, {
        action: 'telegram_disconnected',
        userId: user.id,
      });
      return { user };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.delete('/v1/approvers/users/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    const params = z.object({ id: approverIdSchema }).safeParse(request.params);
    if (!params.success) {
      return reply.status(400).send({ error: 'invalid_request', details: params.error.flatten() });
    }

    try {
      const user = await approverDirectory.deleteUser(auth.workspaceId, params.data.id);
      await appendApproverAudit(auditStore, auth, { action: 'delete_user', userId: user.id });
      return { deleted: true, user };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.post('/v1/approvers/groups', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    const parsed = groupBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const group = await approverDirectory.createGroup(auth.workspaceId, parsed.data);
      await appendApproverAudit(auditStore, auth, {
        action: 'create_group',
        enabled: group.enabled,
        groupId: group.id,
      });
      return reply.status(201).send({ group });
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.put('/v1/approvers/groups/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    const params = z.object({ id: approverIdSchema }).safeParse(request.params);
    const parsed = groupBodySchema.safeParse(request.body);
    if (!params.success || !parsed.success) {
      return reply.status(400).send({
        error: 'invalid_request',
        details: {
          params: params.success ? undefined : params.error.flatten(),
          body: parsed.success ? undefined : parsed.error.flatten(),
        },
      });
    }

    const existing = await approverDirectory.getGroup(auth.workspaceId, params.data.id);
    if (!existing) {
      return reply.status(404).send({ error: 'approver_not_found', message: `Approver group not found: ${params.data.id}` });
    }

    const group = await approverDirectory.upsertGroup(auth.workspaceId, params.data.id, parsed.data);
    await appendApproverAudit(auditStore, auth, {
      action: 'update_group',
      enabled: group.enabled,
      groupId: group.id,
    });
    return { group };
  });

  app.delete('/v1/approvers/groups/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:approvers');
    const params = z.object({ id: approverIdSchema }).safeParse(request.params);
    if (!params.success) {
      return reply.status(400).send({ error: 'invalid_request', details: params.error.flatten() });
    }

    try {
      const group = await approverDirectory.deleteGroup(auth.workspaceId, params.data.id);
      await appendApproverAudit(auditStore, auth, { action: 'delete_group', groupId: group.id });
      return { deleted: true, group };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });
}

async function fetchTelegramBotUsername(botToken: string, fetchFn: TelegramFetch | undefined): Promise<string> {
  const fetch = fetchFn ?? getGlobalFetch();
  const response = await fetch(telegramMethodUrl(botToken, 'getMe'), {
    body: '{}',
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    method: 'POST',
  });
  const text = await response.text();
  const body = parseTelegramGetMeBody(text);
  if (!response.ok || !body.ok || !body.result?.username) {
    throw new Error(`Telegram getMe failed: ${body.description ?? response.status}`);
  }
  return body.result.username;
}

function getGlobalFetch(): TelegramFetch {
  if (typeof fetch !== 'function') {
    throw new Error('No global fetch implementation is available for Telegram bot lookup.');
  }

  return fetch as TelegramFetch;
}

function parseTelegramGetMeBody(text: string): {
  description?: string;
  ok: boolean;
  result?: { username?: string };
} {
  if (!text) return { description: 'empty_response', ok: false };
  try {
    return JSON.parse(text) as { description?: string; ok: boolean; result?: { username?: string } };
  } catch {
    return { description: 'invalid_json_response', ok: false };
  }
}

interface TelegramUpdateResponse {
  description?: string;
  ok: boolean;
  result?: TelegramUpdate[];
}

interface TelegramUpdate {
  message?: {
    chat?: { id?: number | string };
    from?: { id?: number | string; username?: string };
    text?: string;
  };
  update_id?: number;
}

interface TelegramConnectUpdateMatch {
  method: 'poll_setup_link' | 'poll_username_start';
  telegramChatId: string;
  telegramUserId: string;
  telegramUsername?: string;
  updateId: number;
}

async function pollTelegramConnectUpdate(
  config: TelegramServiceConfig & { webhookSecret?: string },
  user: ApproverUserRecord,
  fetchFn: TelegramFetch | undefined,
): Promise<TelegramConnectUpdateMatch | undefined> {
  const updates = await fetchTelegramUpdates(config.botToken, fetchFn);
  for (const update of updates) {
    const match = telegramConnectUpdateMatch(config, user, update);
    if (match) return match;
  }
  return undefined;
}

function telegramConnectUpdateMatch(
  config: TelegramServiceConfig & { webhookSecret?: string },
  user: ApproverUserRecord,
  update: TelegramUpdate,
): TelegramConnectUpdateMatch | undefined {
  const text = update.message?.text;
  const updateId = update.update_id;
  if (updateId === undefined || !isTelegramStartCommand(text)) return undefined;

  const telegramChatId = update.message?.chat?.id === undefined ? undefined : String(update.message.chat.id);
  const telegramUserId = update.message?.from?.id === undefined ? undefined : String(update.message.from.id);
  const telegramUsername = normalizeTelegramUsername(update.message?.from?.username);
  if (!telegramChatId || !telegramUserId) return undefined;

  const token = telegramStartTokenFromText(text);
  if (token) {
    const parsed = parseTelegramConnectToken(token, config.webhookSecret ?? '');
    if (!parsed || parsed.userId !== user.id) return undefined;
    return {
      method: 'poll_setup_link',
      telegramChatId,
      telegramUserId,
      telegramUsername,
      updateId,
    };
  }

  const expectedUsername = normalizeTelegramUsername(user.telegramUsername);
  if (!expectedUsername || expectedUsername !== telegramUsername) return undefined;

  return {
    method: 'poll_username_start',
    telegramChatId,
    telegramUserId,
    telegramUsername,
    updateId,
  };
}

async function fetchTelegramUpdates(botToken: string, fetchFn: TelegramFetch | undefined): Promise<TelegramUpdate[]> {
  const fetch = fetchFn ?? getGlobalFetch();
  const response = await fetch(telegramMethodUrl(botToken, 'getUpdates'), {
    body: JSON.stringify({
      allowed_updates: ['message'],
      timeout: 0,
    }),
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    method: 'POST',
  });
  const text = await response.text();
  const body = parseTelegramUpdateBody(text);
  if (!response.ok || !body.ok) {
    throw new Error(`Telegram getUpdates failed: ${body.description ?? response.status}`);
  }
  return body.result ?? [];
}

async function acknowledgeTelegramUpdate(
  botToken: string,
  updateId: number,
  fetchFn: TelegramFetch | undefined,
): Promise<void> {
  const fetch = fetchFn ?? getGlobalFetch();
  await fetch(telegramMethodUrl(botToken, 'getUpdates'), {
    body: JSON.stringify({
      allowed_updates: ['message'],
      offset: updateId + 1,
      timeout: 0,
    }),
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    method: 'POST',
  });
}

function parseTelegramUpdateBody(text: string): TelegramUpdateResponse {
  if (!text) return { description: 'empty_response', ok: false };
  try {
    return JSON.parse(text) as TelegramUpdateResponse;
  } catch {
    return { description: 'invalid_json_response', ok: false };
  }
}

function appendApproverAudit(
  auditStore: AuditStore,
  auth: ReturnType<typeof authContext>,
  data: Record<string, unknown>,
): Promise<void> {
  return auditStore.append({
    actor: auth.email ?? auth.principalId,
    auth,
    data,
    id: `audit_${randomUUID()}`,
    timestamp: new Date().toISOString(),
    type: 'approver_directory.updated',
    workspaceId: auth.workspaceId,
  });
}
