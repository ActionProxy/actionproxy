import type { FastifyInstance } from 'fastify';
import { ConflictError, ForbiddenError, NotFoundError } from '../../errors';
import type { AuthService } from '../../security/auth-service';
import { safeEqual } from '../../security/crypto';
import { normalizeTelegramUsername, type ApproverDirectoryService } from '../../services/approver-directory';
import type { ActionProxyService } from '../../services/action-gate';
import { isTelegramStartCommand, parseTelegramConnectToken, telegramStartTokenFromText } from './telegram-connect';
import {
  parseTelegramCallbackData,
  TELEGRAM_APPROVE_ACTION,
  TELEGRAM_REJECT_ACTION,
  telegramMethodUrl,
  type TelegramFetch,
  type TelegramServiceConfig,
} from './telegram-service';

export interface TelegramWebhookRouteOptions {
  approverDirectory?: ApproverDirectoryService;
  authService: AuthService;
  configProvider: () => Promise<(TelegramServiceConfig & { webhookSecret?: string }) | undefined> | (TelegramServiceConfig & { webhookSecret?: string }) | undefined;
  fetch?: TelegramFetch;
}

interface TelegramUpdatePayload {
  callback_query?: {
    data?: string;
    from?: {
      first_name?: string;
      id?: number;
      last_name?: string;
      username?: string;
    };
    id?: string;
    message?: {
      chat?: {
        id?: number | string;
      };
      message_id?: number;
    };
  };
  message?: {
    chat?: {
      id?: number | string;
    };
    from?: {
      first_name?: string;
      id?: number;
      last_name?: string;
      username?: string;
    };
    text?: string;
  };
}

export async function registerTelegramWebhookRoutes(
  app: FastifyInstance,
  actionProxy: ActionProxyService,
  options: TelegramWebhookRouteOptions,
): Promise<void> {
  app.post('/v1/telegram/webhook', async (request, reply) => {
    const config = await options.configProvider();
    if (!config?.webhookSecret || !config.botToken) {
      return reply.status(503).send({ error: 'telegram_not_configured' });
    }

    const providedSecret = headerValue(request.headers['x-telegram-bot-api-secret-token']);
    if (!providedSecret || !safeEqual(providedSecret, config.webhookSecret)) {
      return reply.status(401).send({ error: 'invalid_telegram_secret' });
    }

    const payload = isRecord(request.body) ? (request.body as TelegramUpdatePayload) : {};
    const connected = await handleTelegramConnectMessage(payload, config, actionProxy, options);
    if (connected) return reply.send({ ok: true, text: connected });

    const callback = payload.callback_query;
    const parsed = parseTelegramCallbackData(callback?.data);
    const telegramUserId = callback?.from?.id === undefined ? undefined : String(callback.from.id);

    if (!callback?.id || !parsed || !telegramUserId) {
      if (callback?.id) {
        await answerCallbackQuery(config.botToken, callback.id, 'ActionProxy could not process this Telegram action.', options.fetch);
      }
      return reply.send({ ok: true });
    }

    const directoryUser = await options.approverDirectory?.findEnabledUserByTelegramUserId(
      options.authService.workspaceId(),
      telegramUserId,
    );
    const auth = directoryUser
      ? options.approverDirectory!.telegramAuthContext(directoryUser)
      : await options.authService.telegramContext(telegramUserId);
    const actor = auth.email ?? auth.principalId;

    try {
      if (parsed.action === TELEGRAM_APPROVE_ACTION) {
        await actionProxy.recordAuditEvent('telegram.interaction.approved', {
          approvalId: parsed.approvalId,
          actor,
          auth,
          data: interactionAuditData(payload, parsed.action),
          workspaceId: auth.workspaceId,
        });
        const result = await actionProxy.approveApproval(parsed.approvalId, {
          approvedBy: actor,
          note: 'Approved from Telegram',
        }, auth);
        await answerCallbackQuery(config.botToken, callback.id, `Approved ${result.toolCall.toolName}.`, options.fetch);
        return reply.send({ ok: true, text: `Approved ${result.toolCall.toolName}.` });
      }

      if (parsed.action === TELEGRAM_REJECT_ACTION) {
        await actionProxy.recordAuditEvent('telegram.interaction.rejected', {
          approvalId: parsed.approvalId,
          actor,
          auth,
          data: interactionAuditData(payload, parsed.action),
          workspaceId: auth.workspaceId,
        });
        const result = await actionProxy.rejectApproval(parsed.approvalId, {
          rejectedBy: actor,
          reason: 'Rejected from Telegram',
        }, auth);
        await answerCallbackQuery(config.botToken, callback.id, `Rejected ${result.toolCall.toolName}.`, options.fetch);
        return reply.send({ ok: true, text: `Rejected ${result.toolCall.toolName}.` });
      }

      await answerCallbackQuery(config.botToken, callback.id, 'ActionProxy ignored an unsupported Telegram action.', options.fetch);
      return reply.send({ ok: true });
    } catch (error) {
      await actionProxy.recordAuditEvent('telegram.interaction.failed', {
        approvalId: parsed.approvalId,
        actor,
        auth,
        data: {
          ...interactionAuditData(payload, parsed.action),
          error: error instanceof Error ? error.message : String(error),
        },
        workspaceId: auth.workspaceId,
      });

      if (error instanceof NotFoundError || error instanceof ConflictError || error instanceof ForbiddenError) {
        await answerCallbackQuery(config.botToken, callback.id, error.message, options.fetch);
        return reply.send({ ok: true, text: error.message });
      }

      throw error;
    }
  });
}

async function handleTelegramConnectMessage(
  payload: TelegramUpdatePayload,
  config: TelegramServiceConfig & { webhookSecret?: string },
  actionProxy: ActionProxyService,
  options: TelegramWebhookRouteOptions,
): Promise<string | undefined> {
  const message = payload.message;
  if (!message || !isTelegramStartCommand(message.text)) return undefined;

  const chatId = message.chat?.id === undefined ? undefined : String(message.chat.id);
  const telegramUsername = normalizeTelegramUsername(message.from?.username);
  const telegramUserId = message.from?.id === undefined ? undefined : String(message.from.id);
  const token = telegramStartTokenFromText(message.text);
  const hasToken = token !== undefined;
  const parsed = parseTelegramConnectToken(token, config.webhookSecret ?? '');

  if ((hasToken && !parsed) || !chatId || !telegramUserId) {
    if (chatId) {
      await sendTelegramMessage(config.botToken, chatId, 'This ActionProxy Telegram connect link is invalid or expired.', options.fetch);
    }
    return 'Invalid or expired Telegram connect link.';
  }

  try {
    const approverDirectory = options.approverDirectory;
    if (!approverDirectory) throw new NotFoundError('Approver directory is not configured.');

    const workspaceId = options.authService.workspaceId();
    const existingUser = parsed
      ? await approverDirectory.getUser(workspaceId, parsed.userId)
      : telegramUsername
        ? await approverDirectory.findEnabledUserByTelegramUsername(workspaceId, telegramUsername)
        : undefined;
    if (!existingUser) {
      throw new NotFoundError(
        parsed
          ? `Approver user not found: ${parsed.userId}`
          : telegramUsername
            ? 'No enabled ActionProxy approver user is configured for this Telegram username. Ask an admin for a Telegram setup link.'
            : 'Telegram did not report a public username for this account. Ask an admin for a Telegram setup link.',
      );
    }

    const user = await approverDirectory.connectTelegramUser(
      workspaceId,
      existingUser.id,
      {
        telegramChatId: chatId,
        telegramUsername,
        telegramUserId,
      },
    );

    const actor = `telegram:${telegramUserId}`;
    await actionProxy.recordAuditEvent('approver_directory.updated', {
      actor,
      data: {
        action: 'telegram_connected',
        method: parsed ? 'setup_link' : 'username_start',
        telegramChatId: chatId,
        telegramUsername: telegramUsername ? `@${telegramUsername}` : null,
        telegramUserId,
        userId: user.id,
      },
      workspaceId: user.workspaceId,
    });
    await sendTelegramMessage(config.botToken, chatId, `Telegram is connected to ActionProxy approvals for ${user.displayName}.`, options.fetch);
    return `Connected Telegram for ${user.displayName}.`;
  } catch (error) {
    if (chatId) {
      await sendTelegramMessage(
        config.botToken,
        chatId,
        error instanceof Error ? error.message : 'ActionProxy could not connect this Telegram account.',
        options.fetch,
      );
    }
    return error instanceof Error ? error.message : 'ActionProxy could not connect this Telegram account.';
  }
}

async function sendTelegramMessage(
  botToken: string,
  chatId: string,
  text: string,
  fetchFn: TelegramFetch | undefined,
): Promise<void> {
  const fetch = fetchFn ?? getGlobalFetch();
  const response = await fetch(telegramMethodUrl(botToken, 'sendMessage'), {
    body: JSON.stringify({
      chat_id: chatId,
      text,
    }),
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    method: 'POST',
  });
  const body = await response.text();
  if (!response.ok || !telegramOk(body)) {
    throw new Error(`Telegram sendMessage failed: ${telegramError(body) ?? response.status}`);
  }
}

async function answerCallbackQuery(
  botToken: string,
  callbackQueryId: string,
  text: string,
  fetchFn: TelegramFetch | undefined,
): Promise<void> {
  const fetch = fetchFn ?? getGlobalFetch();
  const response = await fetch(telegramMethodUrl(botToken, 'answerCallbackQuery'), {
    body: JSON.stringify({
      callback_query_id: callbackQueryId,
      text,
    }),
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    method: 'POST',
  });
  const body = await response.text();
  if (!response.ok || !telegramOk(body)) {
    throw new Error(`Telegram answerCallbackQuery failed: ${telegramError(body) ?? response.status}`);
  }
}

function interactionAuditData(payload: TelegramUpdatePayload, action: string): Record<string, unknown> {
  const callback = payload.callback_query;
  return {
    action,
    chatId: callback?.message?.chat?.id ?? null,
    callbackQueryId: callback?.id ?? null,
    messageId: callback?.message?.message_id ?? null,
    telegramUser: callback?.from ?? null,
  };
}

function telegramOk(body: string): boolean {
  if (!body) return false;
  try {
    return (JSON.parse(body) as { ok?: boolean }).ok === true;
  } catch {
    return false;
  }
}

function telegramError(body: string): string | undefined {
  if (!body) return 'empty_response';
  try {
    return (JSON.parse(body) as { description?: string }).description;
  } catch {
    return 'invalid_json_response';
  }
}

function getGlobalFetch(): TelegramFetch {
  if (typeof fetch !== 'function') {
    throw new Error('No global fetch implementation is available for Telegram callbacks.');
  }

  return fetch as TelegramFetch;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
