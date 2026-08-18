import type {
  ApprovalNotificationChannel,
  ApprovalNotificationResult,
  ApprovalPresentationRequest,
  ApprovalPresentationResult,
} from '../approval-notifications';
import type { ApprovalDeliveryRecord, ApprovalRecord, JsonObject, ToolCallRecord } from '../../models';
import type { ApprovalNotificationRecipient } from '../../services/approver-directory';
import { redactJsonObject } from '../../security/redaction';

export const TELEGRAM_APPROVE_ACTION = 'approve';
export const TELEGRAM_REJECT_ACTION = 'reject';
export const TELEGRAM_PRESENTATION_TIMEOUT_MS = 3_000;

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
    signal?: AbortSignal;
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

interface TelegramEditTarget {
  approvalUrl?: string;
  chatId: string;
  deliveries: ApprovalDeliveryRecord[];
  messageId: number;
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
    return [{
      ...delivery,
      data: { ...(delivery.data ?? {}), ...(approvalUrl ? { approvalUrl } : {}) },
      status: 'sent',
    }];
  }

  async syncApprovalPresentation(context: ApprovalPresentationRequest): Promise<ApprovalPresentationResult[]> {
    const deliveries = context.deliveries.filter(
      (delivery) => delivery.provider === this.provider && delivery.status === 'sent',
    );
    if (deliveries.length === 0 || context.approval.status === 'pending') return [];

    const results = new Map<string, ApprovalPresentationResult>();
    const targets = new Map<string, TelegramEditTarget>();
    for (const delivery of deliveries) {
      const coordinates = telegramDeliveryCoordinates(delivery);
      if (!coordinates) {
        results.set(delivery.id, {
          deliveryId: delivery.id,
          error: 'Telegram presentation update skipped: delivery has missing or malformed message coordinates.',
          status: 'failed',
        });
        continue;
      }

      const key = JSON.stringify([coordinates.chatId, coordinates.messageId]);
      const existing = targets.get(key);
      if (existing) {
        existing.deliveries.push(delivery);
        if (!existing.approvalUrl) existing.approvalUrl = approvalUrlFromDelivery(delivery);
        continue;
      }
      targets.set(key, {
        ...coordinates,
        approvalUrl: approvalUrlFromDelivery(delivery),
        deliveries: [delivery],
      });
    }

    if (targets.size === 0) return presentationResultsInDeliveryOrder(deliveries, results);

    const controller = new AbortController();
    const completed = new Set<string>();
    let resolveTimeout!: (completedBeforeTimeout: false) => void;
    const timeoutResult = new Promise<false>((resolve) => {
      resolveTimeout = resolve;
    });
    const timeout = setTimeout(() => {
      controller.abort();
      resolveTimeout(false);
    }, TELEGRAM_PRESENTATION_TIMEOUT_MS);
    const configResult = Promise.resolve()
      .then(() => this.getConfig())
      .then(
        (config) => ({ config, kind: 'resolved' as const }),
        (error: unknown) => ({ error, kind: 'failed' as const }),
      );
    const configOutcome = await Promise.race([configResult, timeoutResult]);
    if (configOutcome === false) {
      for (const target of targets.values()) {
        setTargetPresentationResult(
          results,
          target,
          'failed',
          `Telegram presentation update timed out after ${TELEGRAM_PRESENTATION_TIMEOUT_MS}ms.`,
        );
      }
      return presentationResultsInDeliveryOrder(deliveries, results);
    }
    if (configOutcome.kind === 'failed') {
      clearTimeout(timeout);
      const message = sanitizeTelegramError(configOutcome.error);
      for (const target of targets.values()) {
        setTargetPresentationResult(results, target, 'failed', message);
      }
      return presentationResultsInDeliveryOrder(deliveries, results);
    }
    const config = configOutcome.config;
    if (!config) {
      clearTimeout(timeout);
      for (const target of targets.values()) {
        setTargetPresentationResult(results, target, 'failed', 'Telegram is not fully configured.');
      }
      return presentationResultsInDeliveryOrder(deliveries, results);
    }

    const editTasks = [...targets.entries()].map(async ([key, target]) => {
      try {
        await this.editApprovalMessage(config, context, target, controller.signal);
        setTargetPresentationResult(results, target, 'updated');
      } catch (error) {
        setTargetPresentationResult(
          results,
          target,
          'failed',
          isAbortError(error)
            ? `Telegram editMessageText timed out after ${TELEGRAM_PRESENTATION_TIMEOUT_MS}ms.`
            : sanitizeTelegramError(error, config.botToken),
        );
      } finally {
        completed.add(key);
      }
    });
    const allEdits = Promise.all(editTasks).then(() => true);
    const completedBeforeTimeout = await Promise.race([allEdits, timeoutResult]);
    clearTimeout(timeout);

    if (!completedBeforeTimeout) {
      for (const [key, target] of targets) {
        if (completed.has(key)) continue;
        setTargetPresentationResult(
          results,
          target,
          'failed',
          `Telegram editMessageText timed out after ${TELEGRAM_PRESENTATION_TIMEOUT_MS}ms.`,
        );
      }
    }

    return presentationResultsInDeliveryOrder(deliveries, results);
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
          ...(approvalUrl ? { approvalUrl } : {}),
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

  private async editApprovalMessage(
    config: TelegramServiceConfig,
    context: ApprovalPresentationRequest,
    target: TelegramEditTarget,
    signal: AbortSignal,
  ): Promise<void> {
    const response = await this.fetchFn(telegramMethodUrl(config.botToken, 'editMessageText'), {
      body: JSON.stringify({
        chat_id: target.chatId,
        message_id: target.messageId,
        reply_markup: terminalReplyMarkup(target.approvalUrl),
        text: buildTerminalApprovalMessage(context),
      }),
      headers: {
        'content-type': 'application/json; charset=utf-8',
      },
      method: 'POST',
      signal,
    });
    const text = await response.text();
    const body = parseTelegramSendMessageBody(text);

    if ((!response.ok || !body.ok) && !isMessageNotModified(body.description)) {
      throw new Error(`Telegram editMessageText failed: ${body.description ?? response.status}`);
    }
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

function approvalReplyMarkup(approvalId: string, approvalUrl: string | undefined): JsonObject {
  const inlineKeyboard: JsonObject[][] = [
    [
      { callback_data: telegramCallbackData(TELEGRAM_APPROVE_ACTION, approvalId), text: 'Approve' },
      { callback_data: telegramCallbackData(TELEGRAM_REJECT_ACTION, approvalId), text: 'Reject' },
    ],
  ];
  if (approvalUrl) inlineKeyboard.push([{ text: 'Open Web UI', url: approvalUrl }]);
  return {
    inline_keyboard: inlineKeyboard,
  };
}

function terminalReplyMarkup(approvalUrl: string | undefined): JsonObject {
  return {
    inline_keyboard: approvalUrl
      ? [[{ text: 'View status in ActionProxy', url: approvalUrl }]]
      : [],
  };
}

function buildApprovalMessage(
  approval: ApprovalRecord,
  toolCall: ToolCallRecord,
  approvalUrl: string | undefined,
): string {
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
      ...(approvalUrl ? [`Web UI fallback: ${approvalUrl}`] : []),
      '',
      'Payload:',
      payload,
    ].join('\n'),
  );
}

function buildTerminalApprovalMessage(context: ApprovalPresentationRequest): string {
  const { approval, resolution, toolCall } = context;
  const presentation = terminalPresentationFor(approval);
  const reviewer = resolutionReviewer(context);
  const reason = terminalReason(context);
  const payload = JSON.stringify(redactForNotification(toolCall.input), null, 2);

  return truncateTelegramMessage(
    [
      presentation.heading,
      presentation.description,
      '',
      ...(reviewer ? [`Resolved by: ${reviewer}`] : []),
      `Decision source: ${decisionSourceLabel(resolution.source)}`,
      `Decision time (UTC): ${utcTimestamp(resolution.decidedAt)}`,
      ...(reason ? [`Resolution reason: ${reason}`] : []),
      ...(approval.status === 'superseded' && approval.supersededByApprovalId
        ? [`Replacement approval ID: ${approval.supersededByApprovalId}`]
        : []),
      '',
      'Request details',
      `Tool: ${toolCall.toolName}`,
      `Risk: ${toolCall.risk ?? 'unknown'}`,
      `Requested by: ${toolCall.requestedBy}`,
      `Agent: ${toolCall.agentId}`,
      `Request reason: ${toolCall.reason}`,
      '',
      `Approval ID: ${approval.id}`,
      `Tool call ID: ${toolCall.id}`,
      '',
      'Payload:',
      payload,
    ].join('\n'),
  );
}

function terminalPresentationFor(approval: ApprovalRecord): { description: string; heading: string } {
  switch (approval.status) {
    case 'approved':
      return {
        description: 'Approval is closed. Execution status is tracked separately in ActionProxy.',
        heading: '✅ Approved',
      };
    case 'rejected':
      return {
        description: 'This action will not run from this approval.',
        heading: '❌ Rejected',
      };
    case 'cancelled':
      return {
        description: 'This approval was cancelled. This action will not run from this approval.',
        heading: '🚫 Cancelled',
      };
    case 'expired':
      return {
        description: 'This approval expired before a decision was completed.',
        heading: '⌛ Expired',
      };
    case 'superseded':
      return {
        description: approval.supersededByApprovalId
          ? `This approval was replaced by ${approval.supersededByApprovalId}.`
          : 'This approval was replaced by a newer approval.',
        heading: '↪ Replaced',
      };
    case 'pending':
      return {
        description: 'This approval is still pending.',
        heading: 'ActionProxy approval required',
      };
  }
}

function resolutionReviewer(context: ApprovalPresentationRequest): string | undefined {
  const trustedAuth = context.resolution.source === 'system' || context.resolution.auth?.authProvider === 'none'
    ? undefined
    : context.resolution.auth;
  const displayName = trustedAuth?.displayName?.trim();
  if (displayName) return displayName;
  const email = trustedAuth?.email?.trim();
  if (email) return email;
  const actor = context.resolution.actor?.trim();
  if (actor && !actor.startsWith('actionproxy:')) return actor;

  const recordedActor = context.approval.status === 'approved'
    ? context.approval.approvedBy
    : context.approval.status === 'rejected'
      ? context.approval.rejectedBy
      : context.approval.status === 'cancelled'
        ? context.approval.cancelledBy
        : undefined;
  const normalizedRecordedActor = recordedActor?.trim();
  return normalizedRecordedActor && !normalizedRecordedActor.startsWith('actionproxy:')
    ? normalizedRecordedActor
    : undefined;
}

function decisionSourceLabel(source: ApprovalPresentationRequest['resolution']['source']): string {
  if (source === 'telegram') return 'Telegram';
  if (source === 'slack') return 'Slack';
  return 'ActionProxy';
}

function terminalReason(context: ApprovalPresentationRequest): string | undefined {
  const reason = context.resolution.reason
    ?? (context.approval.status === 'rejected'
      ? context.approval.rejectionReason
      : context.approval.status === 'cancelled'
        ? context.approval.cancellationReason
        : undefined);
  return reason?.trim() || undefined;
}

function utcTimestamp(value: string): string {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? value : timestamp.toISOString();
}

function telegramDeliveryCoordinates(
  delivery: ApprovalDeliveryRecord,
): { chatId: string; messageId: number } | undefined {
  const dataChatId = delivery.data.telegramChatId;
  const chatId = stringCoordinate(dataChatId)
    ?? stringCoordinate(delivery.recipientTelegramChatId)
    ?? stringCoordinate(delivery.destination);
  const rawMessageId = delivery.messageId?.trim();
  if (!chatId || !rawMessageId || !/^[1-9]\d*$/.test(rawMessageId)) return undefined;
  const messageId = Number(rawMessageId);
  if (!Number.isSafeInteger(messageId)) return undefined;
  return { chatId, messageId };
}

function stringCoordinate(value: unknown): string | undefined {
  if (typeof value !== 'string' && typeof value !== 'number') return undefined;
  const normalized = String(value).trim();
  return normalized || undefined;
}

function approvalUrlFromDelivery(delivery: ApprovalDeliveryRecord): string | undefined {
  const value = delivery.data.approvalUrl;
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim();
  return normalized || undefined;
}

function setTargetPresentationResult(
  results: Map<string, ApprovalPresentationResult>,
  target: TelegramEditTarget,
  status: ApprovalPresentationResult['status'],
  error?: string,
): void {
  for (const delivery of target.deliveries) {
    results.set(delivery.id, {
      deliveryId: delivery.id,
      ...(error ? { error } : {}),
      status,
    });
  }
}

function presentationResultsInDeliveryOrder(
  deliveries: ApprovalDeliveryRecord[],
  results: Map<string, ApprovalPresentationResult>,
): ApprovalPresentationResult[] {
  return deliveries.flatMap((delivery) => {
    const result = results.get(delivery.id);
    return result ? [result] : [];
  });
}

function isMessageNotModified(description: string | undefined): boolean {
  return description?.toLowerCase().includes('message is not modified') ?? false;
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

function sanitizeTelegramError(error: unknown, botToken?: string): string {
  const raw = error instanceof Error ? error.message : String(error);
  const withoutToken = botToken ? raw.replaceAll(botToken, '[redacted]') : raw;
  const normalized = withoutToken
    .replace(/\b(?:bot)?\d{5,}:[A-Za-z0-9_-]{10,}\b/gu, 'bot[redacted]')
    .replaceAll(/[\r\n\t]+/g, ' ')
    .trim();
  return (normalized || 'Telegram presentation update failed.').slice(0, 500);
}

function approvalUrlFor(config: TelegramServiceConfig, approvalId: string): string | undefined {
  const baseUrl = config.publicBaseUrl?.trim().replace(/\/+$/, '');
  if (!baseUrl) return undefined;
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
    const body: unknown = JSON.parse(text);
    if (!body || typeof body !== 'object' || typeof (body as { ok?: unknown }).ok !== 'boolean') {
      return { description: 'invalid_json_response', ok: false };
    }
    return body as TelegramSendMessageResponse;
  } catch {
    return { description: 'invalid_json_response', ok: false };
  }
}
