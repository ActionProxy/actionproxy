import type {
  ApprovalDeliveryRecord,
  ApprovalDecisionSource,
  ApprovalNotificationProvider,
  ApprovalRecord,
  ApprovalDeliveryStatus,
  AuthContext,
  JsonObject,
  ToolCallRecord,
} from '../models';
import type { ApprovalNotificationRecipient } from '../services/approver-directory';

export interface ApprovalNotificationRequest {
  approval: ApprovalRecord;
  channels?: string[];
  recipients?: ApprovalNotificationRecipient[];
  toolCall: ToolCallRecord;
}

export interface ApprovalNotificationResult {
  channelId: string;
  data?: JsonObject;
  destination?: string;
  error?: string;
  messageId?: string;
  messageTs?: string;
  provider: ApprovalNotificationProvider;
  recipientEmail?: string;
  recipientSlackUserId?: string;
  recipientTelegramChatId?: string;
  recipientTelegramUserId?: string;
  recipientUserId?: string;
  status: ApprovalDeliveryStatus;
}

export interface ApprovalNotifier {
  notifyApprovalRequired(context: ApprovalNotificationRequest): Promise<ApprovalNotificationResult[]>;
  syncApprovalPresentation?(context: ApprovalPresentationRequest): Promise<ApprovalPresentationResult[]>;
}

export interface ApprovalResolutionContext {
  actor?: string;
  auth?: AuthContext;
  decidedAt: string;
  reason?: string;
  source: ApprovalDecisionSource;
}

export interface ApprovalPresentationRequest {
  approval: ApprovalRecord;
  deliveries: ApprovalDeliveryRecord[];
  resolution: ApprovalResolutionContext;
  toolCall: ToolCallRecord;
}

export interface ApprovalPresentationResult {
  deliveryId: string;
  error?: string;
  status: 'failed' | 'updated';
}

export interface ApprovalNotificationChannel {
  channelId: string;
  description: string;
  displayName: string;
  isDefault: boolean;
  isEnabled(): Promise<boolean> | boolean;
  notifyApprovalRequired(context: ApprovalNotificationRequest): Promise<Array<Omit<ApprovalNotificationResult, 'channelId' | 'provider'>>>;
  provider: ApprovalNotificationProvider;
  syncApprovalPresentation?(context: ApprovalPresentationRequest): Promise<ApprovalPresentationResult[]>;
}

export class ApprovalNotificationFanout implements ApprovalNotifier {
  private readonly channels: Map<string, ApprovalNotificationChannel>;

  constructor(channels: ApprovalNotificationChannel[]) {
    this.channels = new Map(channels.map((channel) => [channel.channelId, channel]));
  }

  async notifyApprovalRequired(context: ApprovalNotificationRequest): Promise<ApprovalNotificationResult[]> {
    const explicitChannels = context.channels?.map((channel) => channel.trim()).filter(Boolean);
    const targets = explicitChannels?.length ? await this.explicitTargets(explicitChannels) : await this.defaultTargets();
    const results: ApprovalNotificationResult[] = [];

    for (const target of targets) {
      if ('result' in target) {
        results.push(target.result);
        continue;
      }

      try {
        const deliveries = await target.channel.notifyApprovalRequired(context);
        results.push(
          ...deliveries.map((delivery) => ({
            ...delivery,
            channelId: target.channel.channelId,
            provider: target.channel.provider,
          })),
        );
      } catch (error) {
        results.push({
          channelId: target.channel.channelId,
          error: error instanceof Error ? error.message : String(error),
          provider: target.channel.provider,
          status: 'failed',
        });
      }
    }

    return results;
  }

  async syncApprovalPresentation(context: ApprovalPresentationRequest): Promise<ApprovalPresentationResult[]> {
    const byChannel = new Map<string, ApprovalDeliveryRecord[]>();
    for (const delivery of context.deliveries) {
      const deliveries = byChannel.get(delivery.channelId) ?? [];
      deliveries.push(delivery);
      byChannel.set(delivery.channelId, deliveries);
    }

    const results: ApprovalPresentationResult[] = [];
    await Promise.all(
      [...byChannel.entries()].map(async ([channelId, deliveries]) => {
        const channel = this.channels.get(channelId);
        if (!channel?.syncApprovalPresentation) return;

        try {
          results.push(
            ...(await channel.syncApprovalPresentation({
              ...context,
              deliveries,
            })),
          );
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          results.push(...deliveries.filter((delivery) => delivery.status === 'sent').map((delivery) => ({
            deliveryId: delivery.id,
            error: message,
            status: 'failed' as const,
          })));
        }
      }),
    );
    return results;
  }

  private async defaultTargets(): Promise<Array<{ channel: ApprovalNotificationChannel }>> {
    const targets: Array<{ channel: ApprovalNotificationChannel }> = [];
    for (const channel of this.channels.values()) {
      if (!channel.isDefault) continue;
      if (await channel.isEnabled()) targets.push({ channel });
    }
    return targets;
  }

  private async explicitTargets(
    channelIds: string[],
  ): Promise<Array<{ channel: ApprovalNotificationChannel } | { result: ApprovalNotificationResult }>> {
    const targets: Array<{ channel: ApprovalNotificationChannel } | { result: ApprovalNotificationResult }> = [];
    for (const channelId of channelIds) {
      const channel = this.channels.get(channelId);
      if (!channel) {
        targets.push({
          result: {
            channelId,
            error: `Unknown approval notification channel: ${channelId}`,
            provider: providerFromChannelId(channelId),
            status: 'failed',
          },
        });
        continue;
      }
      if (!(await channel.isEnabled())) {
        targets.push({
          result: {
            channelId,
            error: `Approval notification channel is disabled or not fully configured: ${channelId}`,
            provider: channel.provider,
            status: 'failed',
          },
        });
        continue;
      }
      targets.push({ channel });
    }
    return targets;
  }
}

function providerFromChannelId(channelId: string): ApprovalNotificationProvider {
  if (channelId.startsWith('email.')) return 'email';
  if (channelId.startsWith('telegram.')) return 'telegram';
  return 'slack';
}
