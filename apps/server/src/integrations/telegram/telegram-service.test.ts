import { describe, expect, it, vi } from 'vitest';
import { TelegramService, type TelegramFetch } from './telegram-service';
import type { ApprovalRecord, ToolCallRecord } from '../../models';

const now = '2026-06-22T10:00:00.000Z';

function toolCall(overrides: Partial<ToolCallRecord> = {}): ToolCallRecord {
  return {
    agentId: 'demo-agent',
    createdAt: now,
    decision: 'require_approval',
    id: 'toolcall_1',
    input: { to: 'customer@example.com', subject: 'Update' },
    metadata: {},
    reason: 'Send customer email',
    requestedBy: 'dev@example.com',
    risk: 'external_communication',
    status: 'pending_approval',
    toolName: 'gmail.send_email',
    updatedAt: now,
    ...overrides,
  };
}

function approval(overrides: Partial<ApprovalRecord> = {}): ApprovalRecord {
  return {
    createdAt: now,
    id: 'approval_1',
    originalInput: { to: 'customer@example.com', subject: 'Update' },
    requestedBy: 'dev@example.com',
    status: 'pending',
    toolCallId: 'toolcall_1',
    updatedAt: now,
    ...overrides,
  };
}

describe('TelegramService', () => {
  it('sends approval messages with inline approve and reject callbacks', async () => {
    const fetchMock = vi.fn<TelegramFetch>(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true, result: { chat: { id: 12345 }, message_id: 42 } }),
    }));
    const service = new TelegramService(
      {
        approvalChatId: '12345',
        botToken: '123456:test-token',
        publicBaseUrl: 'https://actionproxy.example',
      },
      { fetch: fetchMock },
    );

    const result = await service.notifyApprovalRequired({ approval: approval(), toolCall: toolCall() });
    const requestBody = JSON.parse(fetchMock.mock.calls[0]![1].body) as {
      chat_id: string;
      reply_markup: { inline_keyboard: Array<Array<{ callback_data?: string; text: string; url?: string }>> };
      text: string;
    };

    expect(result).toEqual([
      {
        data: { approvalUrl: 'https://actionproxy.example/#/approvals/approval_1', telegramChatId: '12345' },
        destination: '12345',
        messageId: '42',
        status: 'sent',
      },
    ]);
    expect(fetchMock.mock.calls[0]![0]).toBe('https://api.telegram.org/bot123456:test-token/sendMessage');
    expect(requestBody.chat_id).toBe('12345');
    expect(requestBody.text).toContain('gmail.send_email');
    expect(requestBody.text).toContain('Web UI fallback: https://actionproxy.example/#/approvals/approval_1');
    expect(requestBody.reply_markup.inline_keyboard[0]).toEqual([
      { callback_data: 'approve:approval_1', text: 'Approve' },
      { callback_data: 'reject:approval_1', text: 'Reject' },
    ]);
    expect(requestBody.reply_markup.inline_keyboard[1]).toEqual([
      { text: 'Open Web UI', url: 'https://actionproxy.example/#/approvals/approval_1' },
    ]);
  });

  it('sends per resolved Telegram recipient', async () => {
    const fetchMock = vi.fn<TelegramFetch>(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true, result: { chat: { id: '67890' }, message_id: 43 } }),
    }));
    const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });

    const result = await service.notifyApprovalRequired({
      approval: approval(),
      recipients: [
        {
          displayName: 'Alice',
          groups: [],
          principalId: 'u_alice',
          telegramChatId: '67890',
          telegramUserId: '111',
          userId: 'u_alice',
        },
      ],
      toolCall: toolCall(),
    });

    expect(result).toEqual([
      expect.objectContaining({
        destination: '67890',
        messageId: '43',
        recipientTelegramChatId: '67890',
        recipientTelegramUserId: '111',
        recipientUserId: 'u_alice',
        status: 'sent',
      }),
    ]);
  });

  it('records failed Telegram delivery when a recipient has no chat ID', async () => {
    const fetchMock = vi.fn<TelegramFetch>();
    const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });

    await expect(
      service.notifyApprovalRequired({
        approval: approval(),
        recipients: [
          { displayName: 'Alice', groups: [], principalId: 'u_alice', telegramUserId: '111', userId: 'u_alice' },
        ],
        toolCall: toolCall(),
      }),
    ).resolves.toEqual([
      {
        error: 'Approver Alice has no Telegram chat ID.',
        recipientTelegramUserId: '111',
        recipientUserId: 'u_alice',
        status: 'failed',
      },
    ]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
