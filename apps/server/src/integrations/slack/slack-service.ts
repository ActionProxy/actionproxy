import type { ApprovalNotificationChannel, ApprovalNotificationResult } from '../approval-notifications';
import type { ApprovalRecord, ToolCallRecord } from '../../models';
import { buildApprovalBlocks } from './slack-blocks';

export interface SlackServiceConfig {
  botToken: string;
  approvalChannelId?: string;
}

export type SlackServiceConfigProvider = () => Promise<SlackServiceConfig | undefined> | SlackServiceConfig | undefined;

export type SlackFetch = (
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

interface SlackPostMessageResponse {
  ok: boolean;
  error?: string;
  channel?: string;
  ts?: string;
}

interface SlackOpenConversationResponse {
  ok: boolean;
  error?: string;
  channel?: {
    id?: string;
  };
}

export class SlackService implements ApprovalNotificationChannel {
  readonly channelId = 'slack.default';
  readonly description = 'Direct Slack approval cards with signed interactive callbacks.';
  readonly displayName = 'Slack approvals';
  readonly isDefault = true;
  readonly provider = 'slack' as const;
  private readonly fetchFn: SlackFetch;
  private readonly getConfig: SlackServiceConfigProvider;

  constructor(
    config: SlackServiceConfig | SlackServiceConfigProvider,
    options: { fetch?: SlackFetch } = {},
  ) {
    this.getConfig = typeof config === 'function' ? config : () => config;
    this.fetchFn = options.fetch ?? getGlobalFetch();
  }

  async isEnabled(): Promise<boolean> {
    return Boolean(await this.getConfig());
  }

  async notifyApprovalRequired(context: {
    approval: ApprovalRecord;
    recipients?: Array<{ displayName: string; slackUserId?: string; userId: string }>;
    toolCall: ToolCallRecord;
  }): Promise<Array<Omit<ApprovalNotificationResult, 'channelId' | 'provider'>>> {
    const config = await this.getConfig();
    if (!config) throw new Error('Slack is not fully configured.');

    if (context.recipients !== undefined) {
      if (context.recipients.length === 0) {
        return [{ error: 'No enabled approval recipients resolved.', status: 'failed' }];
      }
      return Promise.all(context.recipients.map((recipient) => this.notifyRecipient(config, context, recipient)));
    }

    if (!config.approvalChannelId) {
      return [{ error: 'Slack approval channel is not configured.', status: 'failed' }];
    }

    const delivery = await this.postMessage(config, {
      blocks: buildApprovalBlocks(context),
      channel: config.approvalChannelId,
      text: `ActionProxy approval required for ${context.toolCall.toolName}`,
    });
    return [{ ...delivery, status: 'sent' }];
  }

  async sendTestMessage(): Promise<ApprovalNotificationResult> {
    const config = await this.getConfig();
    if (!config) throw new Error('Slack is not fully configured.');
    if (!config.approvalChannelId) throw new Error('Slack approval channel is not configured.');

    const delivery = await this.postMessage(config, {
      channel: config.approvalChannelId,
      text: 'ActionProxy Slack integration test message.',
    });
    return {
      ...delivery,
      channelId: delivery.destination ?? this.channelId,
      provider: this.provider,
      status: 'sent',
    };
  }

  private async notifyRecipient(
    config: SlackServiceConfig,
    context: { approval: ApprovalRecord; toolCall: ToolCallRecord },
    recipient: { displayName: string; slackUserId?: string; userId: string },
  ): Promise<Omit<ApprovalNotificationResult, 'channelId' | 'provider'>> {
    if (!recipient.slackUserId) {
      return {
        error: `Approver ${recipient.displayName} has no Slack user ID.`,
        recipientUserId: recipient.userId,
        status: 'failed',
      };
    }

    try {
      const dmChannel = await this.openDirectMessage(config, recipient.slackUserId);
      const delivery = await this.postMessage(config, {
        blocks: buildApprovalBlocks(context),
        channel: dmChannel,
        text: `ActionProxy approval required for ${context.toolCall.toolName}`,
      });
      return {
        ...delivery,
        data: {
          ...(delivery.data ?? {}),
          recipientUserId: recipient.userId,
          slackUserId: recipient.slackUserId,
        },
        recipientSlackUserId: recipient.slackUserId,
        recipientUserId: recipient.userId,
        status: 'sent',
      };
    } catch (error) {
      return {
        error: error instanceof Error ? error.message : String(error),
        recipientSlackUserId: recipient.slackUserId,
        recipientUserId: recipient.userId,
        status: 'failed',
      };
    }
  }

  private async openDirectMessage(config: SlackServiceConfig, slackUserId: string): Promise<string> {
    const response = await this.fetchFn('https://slack.com/api/conversations.open', {
      body: JSON.stringify({ users: slackUserId }),
      headers: {
        authorization: `Bearer ${config.botToken}`,
        'content-type': 'application/json; charset=utf-8',
      },
      method: 'POST',
    });
    const text = await response.text();
    const body = parseSlackOpenBody(text);

    if (!response.ok || !body.ok || !body.channel?.id) {
      throw new Error(`Slack conversations.open failed: ${body.error ?? response.status}`);
    }

    return body.channel.id;
  }

  private async postMessage(
    config: SlackServiceConfig,
    input: {
      blocks?: unknown[];
      channel: string;
      text: string;
    },
  ): Promise<Omit<ApprovalNotificationResult, 'channelId' | 'provider' | 'status'>> {
    const response = await this.fetchFn('https://slack.com/api/chat.postMessage', {
      body: JSON.stringify({
        blocks: input.blocks,
        channel: input.channel,
        text: input.text,
      }),
      headers: {
        authorization: `Bearer ${config.botToken}`,
        'content-type': 'application/json; charset=utf-8',
      },
      method: 'POST',
    });
    const text = await response.text();
    const body = parseSlackBody(text);

    if (!response.ok || !body.ok) {
      throw new Error(`Slack chat.postMessage failed: ${body.error ?? response.status}`);
    }

    return {
      data: { slackChannelId: body.channel ?? input.channel },
      destination: body.channel ?? input.channel,
      messageId: body.ts,
      messageTs: body.ts,
    };
  }
}

function getGlobalFetch(): SlackFetch {
  if (typeof fetch !== 'function') {
    throw new Error('No global fetch implementation is available for Slack delivery.');
  }

  return fetch as SlackFetch;
}

function parseSlackBody(text: string): SlackPostMessageResponse {
  if (!text) return { error: 'empty_response', ok: false };

  try {
    return JSON.parse(text) as SlackPostMessageResponse;
  } catch {
    return { error: 'invalid_json_response', ok: false };
  }
}

function parseSlackOpenBody(text: string): SlackOpenConversationResponse {
  if (!text) return { error: 'empty_response', ok: false };

  try {
    return JSON.parse(text) as SlackOpenConversationResponse;
  } catch {
    return { error: 'invalid_json_response', ok: false };
  }
}
