import { describe, expect, it, vi } from 'vitest';
import { SlackService, type SlackFetch } from './slack-service';
import type { ApprovalRecord, ToolCallRecord } from '../../models';

const now = '2026-06-18T10:00:00.000Z';

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

describe('SlackService', () => {
  it('posts approval cards to chat.postMessage', async () => {
    const fetchMock = vi.fn<SlackFetch>(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true, channel: 'C123', ts: '1710000000.000100' }),
    }));
    const service = new SlackService(
      {
        approvalChannelId: 'C123',
        botToken: 'xoxb-test',
      },
      { fetch: fetchMock },
    );

    const result = await service.notifyApprovalRequired({ approval: approval(), toolCall: toolCall() });
    const requestBody = JSON.parse(fetchMock.mock.calls[0]![1].body) as {
      blocks: Array<Record<string, unknown>>;
      channel: string;
      text: string;
    };

    expect(result).toEqual([
      {
        data: { slackChannelId: 'C123' },
        destination: 'C123',
        messageId: '1710000000.000100',
        messageTs: '1710000000.000100',
        status: 'sent',
      },
    ]);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://slack.com/api/chat.postMessage',
      expect.objectContaining({
        headers: expect.objectContaining({ authorization: 'Bearer xoxb-test' }),
        method: 'POST',
      }),
    );
    expect(requestBody.channel).toBe('C123');
    expect(JSON.stringify(requestBody.blocks)).toContain('gmail.send_email');
    expect(JSON.stringify(requestBody.blocks)).toContain('approval_1');
  });

  it('throws when Slack reports an API error', async () => {
    const fetchMock = vi.fn<SlackFetch>(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: false, error: 'channel_not_found' }),
    }));
    const service = new SlackService(
      {
        approvalChannelId: 'C_missing',
        botToken: 'xoxb-test',
      },
      { fetch: fetchMock },
    );

    await expect(service.notifyApprovalRequired({ approval: approval(), toolCall: toolCall() })).rejects.toThrow(
      'Slack chat.postMessage failed: channel_not_found',
    );
  });

  it('opens DMs and posts per resolved Slack recipient', async () => {
    const fetchMock = vi.fn<SlackFetch>(async (url) => ({
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify(
          url.endsWith('/conversations.open')
            ? { ok: true, channel: { id: 'D123' } }
            : { ok: true, channel: 'D123', ts: '1710000000.000200' },
        ),
    }));
    const service = new SlackService({ botToken: 'xoxb-test' }, { fetch: fetchMock });

    const result = await service.notifyApprovalRequired({
      approval: approval(),
      recipients: [{ displayName: 'Alice', slackUserId: 'U_ALICE', userId: 'u_alice' }],
      toolCall: toolCall(),
    });
    const openBody = JSON.parse(fetchMock.mock.calls[0]![1].body) as { users: string };
    const postBody = JSON.parse(fetchMock.mock.calls[1]![1].body) as { channel: string };

    expect(result).toEqual([
      expect.objectContaining({
        destination: 'D123',
        messageTs: '1710000000.000200',
        recipientSlackUserId: 'U_ALICE',
        recipientUserId: 'u_alice',
        status: 'sent',
      }),
    ]);
    expect(fetchMock.mock.calls[0]![0]).toBe('https://slack.com/api/conversations.open');
    expect(openBody.users).toBe('U_ALICE');
    expect(fetchMock.mock.calls[1]![0]).toBe('https://slack.com/api/chat.postMessage');
    expect(postBody.channel).toBe('D123');
  });

  it('records failed Slack delivery when a recipient has no Slack user ID', async () => {
    const fetchMock = vi.fn<SlackFetch>();
    const service = new SlackService({ botToken: 'xoxb-test' }, { fetch: fetchMock });

    await expect(
      service.notifyApprovalRequired({
        approval: approval(),
        recipients: [{ displayName: 'Alice', userId: 'u_alice' }],
        toolCall: toolCall(),
      }),
    ).resolves.toEqual([
      {
        error: 'Approver Alice has no Slack user ID.',
        recipientUserId: 'u_alice',
        status: 'failed',
      },
    ]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
