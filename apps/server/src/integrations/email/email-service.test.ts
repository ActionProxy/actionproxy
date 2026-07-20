import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { EmailService } from './email-service';
import type { ApprovalRecord, ToolCallRecord } from '../../models';

const now = '2026-06-19T10:00:00.000Z';

describe('EmailService', () => {
  it('writes approval notifications to the local outbox with a redacted payload', async () => {
    const outboxDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-email-outbox-test-'));
    const service = new EmailService({
      approvalRecipient: 'approvals@example.com',
      from: 'actionproxy@example.com',
      outboxDir,
      publicBaseUrl: 'https://actionproxy.example/console',
      transport: 'outbox',
    });

    const [result] = await service.notifyApprovalRequired({
      approval: approval(),
      toolCall: toolCall(),
    });
    if (!result || result.status !== 'sent') throw new Error('Expected sent delivery');
    const outboxPath = (result.data as { outboxPath?: string }).outboxPath;
    if (!outboxPath) throw new Error('Expected outbox path');
    const message = JSON.parse(fs.readFileSync(outboxPath, 'utf8')) as { text: string; to: string };

    expect(result).toMatchObject({
      destination: 'approvals@example.com',
      messageId: expect.stringContaining('approval_1'),
    });
    expect(message.to).toBe('approvals@example.com');
    expect(message.text).toContain('https://actionproxy.example/console/#/approvals/approval_1');
    expect(message.text).not.toContain('127.0.0.1:5173');
    expect(message.text).toContain('"apiToken": "[redacted]"');
    expect(message.text).not.toContain('secret-token');
  });

});

function toolCall(overrides: Partial<ToolCallRecord> = {}): ToolCallRecord {
  return {
    agentId: 'demo-agent',
    createdAt: now,
    decision: 'require_approval',
    id: 'toolcall_1',
    input: { apiToken: 'secret-token', to: 'customer@example.com' },
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
    originalInput: { apiToken: 'secret-token', to: 'customer@example.com' },
    requestedBy: 'dev@example.com',
    status: 'pending',
    toolCallId: 'toolcall_1',
    updatedAt: now,
    ...overrides,
  };
}
