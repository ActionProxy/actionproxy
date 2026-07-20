import type { ApprovalNotificationChannel, ApprovalNotificationResult } from '../approval-notifications';
import type { ApprovalRecord, JsonObject, ToolCallRecord } from '../../models';
import type { ApprovalNotificationRecipient } from '../../services/approver-directory';
import { redactJsonObject } from '../../security/redaction';

export const TELEGRAM_APPROVE_ACTION = 'approve';
export const TELEGRAM_REJECT_ACTION = 'reject';

export interface TelegramServiceConfig {
  approvalChatId?: string;
  botToken: string;
  publicBaseUrl?: string;
}

export type TelegramServiceConfigProvider =
  | (() => Promise<TelegramServiceConfig | undefined> | TelegramServiceConfig | undefined)
  | TelegramServiceConfig;

export interface TelegramTestRecipient {
  chatId: string;
  displayName?: string;
  telegramUserId?: string;
  userId?: string;
}

export type TelegramFetch = (
  url: string,
  init: {
    body: string;
    headers: Record<string, string>;
    method: 'POST';
  },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface TelegramSendMessageResponse {
  ok: boolean;
  description?: string;
  result?: {
    chat?: {
      id?: number | string;
    };
    message_id?: number;
  };
}

export class TelegramService implements ApprovalNotificationChannel {
  readonly channelId = 'telegram.default';
  readonly description = 'Direct Telegram approval messages with inline bot callbacks.';
  readonly displayName = 'Telegram approvals';
  readonly isDefault = true;
  readonly provider = 'telegram' as const;

  private readonly fetchFn: TelegramFetch;
  private readonly getConfig: () => Promise<TelegramServiceConfig | undefined> | TelegramServiceConfig | undefined;

  constructor(config: TelegramServiceConfigProvider, options: { fetch?: TelegramFetch } = {}) {
    this.getConfig = typeof config === 'function' ? config : () => config;
    this.fetchFn = options.fetch ?? getGlobalFetch();
  }

  async isEnabled(): Promise<boolean> {
    return Boolean(await this.getConfig());
  }

  async notifyApprovalRequired(context: {
    approval: ApprovalRecord;
    recipients?: ApprovalNotificationRecipient[];
    toolCall: ToolCallRecord;
  }): Promise<Array<Omit<ApprovalNotificationResult, 'channelId' | 'provider'>>> {
    const config = await this.getConfig();
    if (!config) throw new Error('Telegram is not fully configured.');

    if (context.recipients !== undefined) {
      if (context.recipients.length === 0) {
        return [{ error: 'No enabled approval recipients resolved.', status: 'failed' }];
      }
      return Promise.all(context.recipients.map((recipient) => this.notifyRecipient(config, context, recipient)));
    }

    if (!config.approvalChatId) {
      return [{ error: 'Telegram approval chat ID is not configured.', status: 'failed' }];
    }

    const approvalUrl = approvalUrlFor(config, context.approval.id);
    const delivery = await this.sendMessage(config, {
      chatId: config.approvalChatId,
      text: buildApprovalMessage(context.approval, context.toolCall, approvalUrl),
      replyMarkup: approvalReplyMarkup(context.approval.id, approvalUrl),
    });
    return [{ ...delivery, data: { ...(delivery.data ?? {}), approvalUrl }, status: 'sent' }];
  }

  async sendTestMessage(recipient?: TelegramTestRecipient): Promise<ApprovalNotificationResult> {
    const config = await this.getConfig();
    if (!config) throw new Error('Telegram is not fully configured.');
    const chatId = recipient?.chatId ?? config.approvalChatId;
    if (!chatId) throw new Error('Telegram test recipient is not configured.');

    const delivery = await this.sendMessage(config, {
      chatId,
      text: 'ActionProxy Telegram integration test message.',
    });
    return {
      ...delivery,
      channelId: this.channelId,
      data: {
        ...(delivery.data ?? {}),
        recipientUserId: recipient?.userId ?? null,
        telegramUserId: recipient?.telegramUserId ?? null,
      },
      provider: this.provider,
      recipientTelegramChatId: recipient?.chatId,
      recipientTelegramUserId: recipient?.telegramUserId,
      recipientUserId: recipient?.userId,
      status: 'sent',
    };
  }

  private async notifyRecipient(
    config: TelegramServiceConfig,
    context: { approval: ApprovalRecord; toolCall: ToolCallRecord },
    recipient: ApprovalNotificationRecipient,
  ): Promise<Omit<ApprovalNotificationResult, 'channelId' | 'provider'>> {
    if (!recipient.telegramChatId) {
      return {
        error: `Approver ${recipient.displayName} has no Telegram chat ID.`,
        recipientTelegramUserId: recipient.telegramUserId,
        recipientUserId: recipient.userId,
        status: 'failed',
      };
    }

    try {
      const approvalUrl = approvalUrlFor(config, context.approval.id);
      const delivery = await this.sendMessage(config, {
        chatId: recipient.telegramChatId,
        text: buildApprovalMessage(context.approval, context.toolCall, approvalUrl),
        replyMarkup: approvalReplyMarkup(context.approval.id, approvalUrl),
      });
      return {
        ...delivery,
        data: {
          ...(delivery.data ?? {}),
          approvalUrl,
          recipientUserId: recipient.userId,
          telegramChatId: recipient.telegramChatId,
          telegramUserId: recipient.telegramUserId ?? null,
        },
        recipientTelegramChatId: recipient.telegramChatId,
        recipientTelegramUserId: recipient.telegramUserId,
        recipientUserId: recipient.userId,
        status: 'sent',
      };
    } catch (error) {
      return {
        error: error instanceof Error ? error.message : String(error),
        recipientTelegramChatId: recipient.telegramChatId,
        recipientTelegramUserId: recipient.telegramUserId,
        recipientUserId: recipient.userId,
        status: 'failed',
      };
    }
  }

  private async sendMessage(
    config: TelegramServiceConfig,
    input: {
      chatId: string;
      replyMarkup?: JsonObject;
      text: string;
    },
  ): Promise<Omit<ApprovalNotificationResult, 'channelId' | 'provider' | 'status'>> {
    const response = await this.fetchFn(telegramMethodUrl(config.botToken, 'sendMessage'), {
      body: JSON.stringify({
        chat_id: input.chatId,
        reply_markup: input.replyMarkup,
        text: input.text,
      }),
      headers: {
        'content-type': 'application/json; charset=utf-8',
      },
      method: 'POST',
    });
    const text = await response.text();
    const body = parseTelegramSendMessageBody(text);

    if (!response.ok || !body.ok) {
      throw new Error(`Telegram sendMessage failed: ${body.description ?? response.status}`);
    }

    const chatId = body.result?.chat?.id === undefined ? input.chatId : String(body.result.chat.id);
    const messageId = body.result?.message_id === undefined ? undefined : String(body.result.message_id);

    return {
      data: { telegramChatId: chatId },
      destination: chatId,
      messageId,
    };
  }
}

export function telegramCallbackData(action: typeof TELEGRAM_APPROVE_ACTION | typeof TELEGRAM_REJECT_ACTION, approvalId: string): string {
  return `${action}:${approvalId}`;
}

export function parseTelegramCallbackData(
  value: string | undefined,
): { action: typeof TELEGRAM_APPROVE_ACTION | typeof TELEGRAM_REJECT_ACTION; approvalId: string } | undefined {
  const [action, ...rest] = (value ?? '').split(':');
  const approvalId = rest.join(':');
  if ((action !== TELEGRAM_APPROVE_ACTION && action !== TELEGRAM_REJECT_ACTION) || !approvalId) return undefined;
  return { action, approvalId };
}

export function telegramMethodUrl(botToken: string, method: string): string {
  return `https://api.telegram.org/bot${botToken}/${method}`;
}

function approvalReplyMarkup(approvalId: string, approvalUrl: string): JsonObject {
  return {
    inline_keyboard: [
      [
        { callback_data: telegramCallbackData(TELEGRAM_APPROVE_ACTION, approvalId), text: 'Approve' },
        { callback_data: telegramCallbackData(TELEGRAM_REJECT_ACTION, approvalId), text: 'Reject' },
      ],
      [
        { text: 'Open Web UI', url: approvalUrl },
      ],
    ],
  };
}

function buildApprovalMessage(approval: ApprovalRecord, toolCall: ToolCallRecord, approvalUrl: string): string {
  const payload = JSON.stringify(redactForNotification(toolCall.input), null, 2);
  return truncateTelegramMessage(
    [
      'ActionProxy approval required',
      '',
      `Tool: ${toolCall.toolName}`,
      `Risk: ${toolCall.risk ?? 'unknown'}`,
      `Requested by: ${toolCall.requestedBy}`,
      `Agent: ${toolCall.agentId}`,
      `Reason: ${toolCall.reason}`,
      '',
      `Approval ID: ${approval.id}`,
      `Tool call ID: ${toolCall.id}`,
      `Web UI fallback: ${approvalUrl}`,
      '',
      'Payload:',
      payload,
    ].join('\n'),
  );
}

function approvalUrlFor(config: TelegramServiceConfig, approvalId: string): string {
  const baseUrl = (config.publicBaseUrl ?? 'http://127.0.0.1:5173').replace(/\/+$/, '');
  return `${baseUrl}/#/approvals/${encodeURIComponent(approvalId)}`;
}

function truncateTelegramMessage(value: string): string {
  if (value.length <= 3900) return value;
  return `${value.slice(0, 3860)}\n...[truncated]`;
}

function redactForNotification(input: JsonObject): JsonObject {
  return redactJsonObject(input, { replacement: '[redacted]' });
}

function getGlobalFetch(): TelegramFetch {
  if (typeof fetch !== 'function') {
    throw new Error('No global fetch implementation is available for Telegram delivery.');
  }

  return fetch as TelegramFetch;
}

function parseTelegramSendMessageBody(text: string): TelegramSendMessageResponse {
  if (!text) return { description: 'empty_response', ok: false };

  try {
    return JSON.parse(text) as TelegramSendMessageResponse;
  } catch {
    return { description: 'invalid_json_response', ok: false };
  }
}
