import { describe, expect, it, vi } from 'vitest';
import {
  TELEGRAM_PRESENTATION_TIMEOUT_MS,
  TelegramService,
  type TelegramFetch,
} from './telegram-service';
import type { ApprovalDeliveryRecord, ApprovalRecord, AuthContext, ToolCallRecord } from '../../models';
import type { ApprovalPresentationRequest } from '../approval-notifications';

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

function delivery(overrides: Partial<ApprovalDeliveryRecord> = {}): ApprovalDeliveryRecord {
  return {
    approvalId: 'approval_1',
    channelId: 'telegram.default',
    createdAt: now,
    data: { telegramChatId: '12345' },
    destination: '12345',
    id: 'delivery_1',
    messageId: '42',
    provider: 'telegram',
    status: 'sent',
    toolCallId: 'toolcall_1',
    updatedAt: now,
    ...overrides,
  };
}

function auth(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    authProvider: 'oidc_jwt',
    displayName: 'Alice Reviewer',
    email: 'alice@example.com',
    groups: [],
    principalId: 'u_alice',
    principalType: 'user',
    scopes: ['approvals:decide'],
    workspaceId: 'default',
    ...overrides,
  };
}

function presentation(overrides: {
  approval?: Partial<ApprovalRecord>;
  deliveries?: ApprovalDeliveryRecord[];
  resolution?: Partial<ApprovalPresentationRequest['resolution']>;
  toolCall?: Partial<ToolCallRecord>;
} = {}): ApprovalPresentationRequest {
  return {
    approval: approval({ finalizedAt: '2026-06-22T10:05:00.000Z', status: 'approved', ...overrides.approval }),
    deliveries: overrides.deliveries ?? [delivery()],
    resolution: {
      actor: 'alice@example.com',
      auth: auth(),
      decidedAt: '2026-06-22T10:05:00.000Z',
      source: 'actionproxy',
      ...overrides.resolution,
    },
    toolCall: toolCall(overrides.toolCall),
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
    const requestBody = JSON.parse(fetchMock.mock.calls[0]![1].body) as {
      reply_markup: { inline_keyboard: Array<Array<{ text: string; url?: string }>> };
      text: string;
    };
    expect(requestBody.text).not.toContain('Web UI fallback:');
    expect(requestBody.reply_markup.inline_keyboard.flat()).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ text: 'Open Web UI' })]),
    );
    expect(JSON.stringify(requestBody)).not.toContain('127.0.0.1:5173');
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

  it('uses the configured Web UI origin and port without substituting a fixed port', async () => {
    const fetchMock = vi.fn<TelegramFetch>(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true, result: { message_id: 44 } }),
    }));
    const service = new TelegramService(
      {
        botToken: '123456:test-token',
        publicBaseUrl: 'http://127.0.0.1:9417/',
      },
      { fetch: fetchMock },
    );

    await service.notifyApprovalRequired({
      approval: approval(),
      recipients: [
        {
          displayName: 'Alice',
          groups: [],
          principalId: 'u_alice',
          telegramChatId: '67890',
          userId: 'u_alice',
        },
      ],
      toolCall: toolCall(),
    });

    const requestBody = JSON.parse(fetchMock.mock.calls[0]![1].body) as {
      reply_markup: { inline_keyboard: Array<Array<{ text: string; url?: string }>> };
      text: string;
    };
    const expectedUrl = 'http://127.0.0.1:9417/#/approvals/approval_1';
    expect(requestBody.text).toContain(`Web UI fallback: ${expectedUrl}`);
    expect(requestBody.reply_markup.inline_keyboard.flat()).toContainEqual({
      text: 'Open Web UI',
      url: expectedUrl,
    });
    expect(JSON.stringify(requestBody)).not.toContain('127.0.0.1:5173');
    expect(JSON.stringify(requestBody)).not.toContain('127.0.0.1:8787');
  });

  it('replaces an approved card with redacted request context, decision metadata, and a status-only link', async () => {
    const fetchMock = vi.fn<TelegramFetch>(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true, result: { message_id: 42 } }),
    }));
    const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });
    const result = await service.syncApprovalPresentation(presentation({
      deliveries: [delivery({ data: {
        approvalUrl: 'https://actionproxy.example/#/approvals/approval_1',
        telegramChatId: '12345',
      } })],
      resolution: { source: 'telegram' },
      toolCall: { input: {
        password: 'never-show-this',
        subject: 'Update',
        to: 'customer@example.com',
      } },
    }));
    const requestBody = JSON.parse(fetchMock.mock.calls[0]![1].body) as {
      chat_id: string;
      message_id: number;
      reply_markup: { inline_keyboard: Array<Array<{ callback_data?: string; text: string; url?: string }>> };
      text: string;
    };

    expect(result).toEqual([{ deliveryId: 'delivery_1', status: 'updated' }]);
    expect(fetchMock.mock.calls[0]![0]).toBe('https://api.telegram.org/bot123456:test-token/editMessageText');
    expect(fetchMock.mock.calls[0]![1].signal).toBeInstanceOf(AbortSignal);
    expect(requestBody).toMatchObject({ chat_id: '12345', message_id: 42 });
    expect(requestBody.text).toContain('✅ Approved');
    expect(requestBody.text).toContain('Approval is closed. Execution status is tracked separately in ActionProxy.');
    expect(requestBody.text).toContain('Resolved by: Alice Reviewer');
    expect(requestBody.text).toContain('Decision source: Telegram');
    expect(requestBody.text).toContain('Decision time (UTC): 2026-06-22T10:05:00.000Z');
    expect(requestBody.text).toContain('Tool: gmail.send_email');
    expect(requestBody.text).toContain('"password": "[redacted]"');
    expect(requestBody.text).not.toContain('never-show-this');
    expect(requestBody.reply_markup.inline_keyboard).toEqual([[
      {
        text: 'View status in ActionProxy',
        url: 'https://actionproxy.example/#/approvals/approval_1',
      },
    ]]);
    expect(JSON.stringify(requestBody.reply_markup)).not.toContain('callback_data');
  });

  it.each([
    {
      approval: { rejectedBy: 'bob@example.com', rejectionReason: 'Recipient is incorrect', status: 'rejected' as const },
      description: 'This action will not run from this approval.',
      heading: '❌ Rejected',
      reason: 'Recipient is incorrect',
    },
    {
      approval: { cancellationReason: 'Request withdrawn', cancelledBy: 'requester@example.com', status: 'cancelled' as const },
      description: 'This approval was cancelled. This action will not run from this approval.',
      heading: '🚫 Cancelled',
      reason: 'Request withdrawn',
    },
    {
      approval: { expiredAt: '2026-06-22T10:05:00.000Z', status: 'expired' as const },
      description: 'This approval expired before a decision was completed.',
      heading: '⌛ Expired',
      reason: undefined,
    },
    {
      approval: { status: 'superseded' as const, supersededByApprovalId: 'approval_2' },
      description: 'This approval was replaced by approval_2.',
      heading: '↪ Replaced',
      reason: undefined,
    },
  ])('renders a terminal $approval.status card without decision callbacks', async ({ approval: approvalState, description, heading, reason }) => {
    const fetchMock = vi.fn<TelegramFetch>(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true }),
    }));
    const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });

    await service.syncApprovalPresentation(presentation({
      approval: approvalState,
      resolution: { actor: undefined, auth: undefined, source: 'system' },
    }));
    const requestBody = JSON.parse(fetchMock.mock.calls[0]![1].body) as {
      reply_markup: { inline_keyboard: unknown[] };
      text: string;
    };

    expect(requestBody.text).toContain(heading);
    expect(requestBody.text).toContain(description);
    expect(requestBody.text).toContain('Decision source: ActionProxy');
    if (reason) expect(requestBody.text).toContain(`Resolution reason: ${reason}`);
    if (approvalState.status === 'superseded') {
      expect(requestBody.text).toContain('Replacement approval ID: approval_2');
    }
    expect(requestBody.text).not.toContain('actionproxy:approval-expiry');
    expect(requestBody.reply_markup).toEqual({ inline_keyboard: [] });
  });

  it('falls back from reviewer display name to email and actor', async () => {
    const requestBodies: Array<{ text: string }> = [];
    const fetchMock = vi.fn<TelegramFetch>(async (_url, init) => {
      requestBodies.push(JSON.parse(init.body) as { text: string });
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true }) };
    });
    const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });

    await service.syncApprovalPresentation(presentation({
      resolution: { auth: auth({ displayName: '' }) },
    }));
    await service.syncApprovalPresentation(presentation({
      resolution: { actor: 'principal:reviewer', auth: undefined },
    }));

    expect(requestBodies[0]!.text).toContain('Resolved by: alice@example.com');
    expect(requestBodies[1]!.text).toContain('Resolved by: principal:reviewer');
  });

  it('edits unique Telegram messages concurrently and returns a result for every deduplicated delivery', async () => {
    const resolvers: Array<() => void> = [];
    const fetchMock = vi.fn<TelegramFetch>(async () => {
      await new Promise<void>((resolve) => resolvers.push(resolve));
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true }) };
    });
    const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });
    const sync = service.syncApprovalPresentation(presentation({
      deliveries: [
        delivery({ id: 'delivery_1' }),
        delivery({ id: 'delivery_duplicate' }),
        delivery({ data: { telegramChatId: '67890' }, destination: '67890', id: 'delivery_2', messageId: '43' }),
        delivery({ id: 'delivery_failed_send', status: 'failed' }),
      ],
    }));

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    resolvers.forEach((resolve) => resolve());

    await expect(sync).resolves.toEqual([
      { deliveryId: 'delivery_1', status: 'updated' },
      { deliveryId: 'delivery_duplicate', status: 'updated' },
      { deliveryId: 'delivery_2', status: 'updated' },
    ]);
  });

  it('treats Telegram message-is-not-modified responses as idempotent success', async () => {
    const fetchMock = vi.fn<TelegramFetch>(async () => ({
      ok: false,
      status: 400,
      text: async () => JSON.stringify({
        description: 'Bad Request: message is not modified: specified new message content and reply markup are exactly the same',
        ok: false,
      }),
    }));
    const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });

    await expect(service.syncApprovalPresentation(presentation())).resolves.toEqual([
      { deliveryId: 'delivery_1', status: 'updated' },
    ]);
  });

  it.each([
    {
      body: JSON.stringify({ description: 'Bad Request: message to edit not found', ok: false }),
      expected: 'Telegram editMessageText failed: Bad Request: message to edit not found',
      name: 'deleted messages',
      status: 400,
    },
    {
      body: 'not-json',
      expected: 'Telegram editMessageText failed: invalid_json_response',
      name: 'invalid JSON provider responses',
      status: 200,
    },
    {
      body: 'null',
      expected: 'Telegram editMessageText failed: invalid_json_response',
      name: 'malformed JSON provider responses',
      status: 200,
    },
    {
      body: '',
      expected: 'Telegram editMessageText failed: empty_response',
      name: 'empty provider responses',
      status: 502,
    },
  ])('returns a per-delivery failure for $name', async ({ body, expected, status }) => {
    const fetchMock = vi.fn<TelegramFetch>(async () => ({
      ok: status >= 200 && status < 300,
      status,
      text: async () => body,
    }));
    const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });

    await expect(service.syncApprovalPresentation(presentation())).resolves.toEqual([
      { deliveryId: 'delivery_1', error: expected, status: 'failed' },
    ]);
  });

  it('reports missing coordinates and disabled configuration without attempting provider edits', async () => {
    const fetchMock = vi.fn<TelegramFetch>();
    const service = new TelegramService(() => undefined, { fetch: fetchMock });

    await expect(service.syncApprovalPresentation(presentation({
      deliveries: [
        delivery({ data: {}, destination: undefined, id: 'missing_chat' }),
        delivery({ id: 'invalid_message', messageId: 'not-a-number' }),
        delivery({ id: 'valid_message' }),
      ],
    }))).resolves.toEqual([
      {
        deliveryId: 'missing_chat',
        error: 'Telegram presentation update skipped: delivery has missing or malformed message coordinates.',
        status: 'failed',
      },
      {
        deliveryId: 'invalid_message',
        error: 'Telegram presentation update skipped: delivery has missing or malformed message coordinates.',
        status: 'failed',
      },
      { deliveryId: 'valid_message', error: 'Telegram is not fully configured.', status: 'failed' },
    ]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('sanitizes Telegram tokens exposed by configuration-provider failures', async () => {
    const fetchMock = vi.fn<TelegramFetch>();
    const service = new TelegramService(() => {
      throw new Error('Could not load token 123456789:super_secret_token_value from configuration.');
    }, { fetch: fetchMock });

    const results = await service.syncApprovalPresentation(presentation());

    expect(results).toEqual([{
      deliveryId: 'delivery_1',
      error: 'Could not load token bot[redacted] from configuration.',
      status: 'failed',
    }]);
    expect(JSON.stringify(results)).not.toContain('super_secret_token_value');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('bounds configuration lookup and never starts a late edit after timeout', async () => {
    vi.useFakeTimers();
    try {
      let resolveConfig!: (config: { botToken: string }) => void;
      const config = new Promise<{ botToken: string }>((resolve) => {
        resolveConfig = resolve;
      });
      const fetchMock = vi.fn<TelegramFetch>();
      const service = new TelegramService(() => config, { fetch: fetchMock });
      const sync = service.syncApprovalPresentation(presentation());
      await Promise.resolve();

      await vi.advanceTimersByTimeAsync(TELEGRAM_PRESENTATION_TIMEOUT_MS);

      await expect(sync).resolves.toEqual([{
        deliveryId: 'delivery_1',
        error: `Telegram presentation update timed out after ${TELEGRAM_PRESENTATION_TIMEOUT_MS}ms.`,
        status: 'failed',
      }]);
      resolveConfig({ botToken: '123456:test-token' });
      await Promise.resolve();
      await Promise.resolve();
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('bounds the concurrent edit batch with a shared three-second AbortController timeout', async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn<TelegramFetch>(async (_url, init) => new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          reject(new DOMException('This operation was aborted', 'AbortError'));
        });
      }));
      const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });
      const sync = service.syncApprovalPresentation(presentation({
        deliveries: [
          delivery({ id: 'delivery_1' }),
          delivery({ data: { telegramChatId: '67890' }, destination: '67890', id: 'delivery_2', messageId: '43' }),
        ],
      }));
      await Promise.resolve();

      await vi.advanceTimersByTimeAsync(TELEGRAM_PRESENTATION_TIMEOUT_MS);

      await expect(sync).resolves.toEqual([
        {
          deliveryId: 'delivery_1',
          error: `Telegram editMessageText timed out after ${TELEGRAM_PRESENTATION_TIMEOUT_MS}ms.`,
          status: 'failed',
        },
        {
          deliveryId: 'delivery_2',
          error: `Telegram editMessageText timed out after ${TELEGRAM_PRESENTATION_TIMEOUT_MS}ms.`,
          status: 'failed',
        },
      ]);
      expect(fetchMock.mock.calls[0]![1].signal).toBe(fetchMock.mock.calls[1]![1].signal);
      expect(fetchMock.mock.calls[0]![1].signal?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not edit cards while a multi-approver request remains pending', async () => {
    const fetchMock = vi.fn<TelegramFetch>();
    const service = new TelegramService({ botToken: '123456:test-token' }, { fetch: fetchMock });

    await expect(service.syncApprovalPresentation(presentation({
      approval: { decisions: [{ actor: 'first@example.com', decidedAt: now }], status: 'pending' },
    }))).resolves.toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
