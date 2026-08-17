import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ApproverUserRecord, ToolCallRecord } from '../models';
import { LocalDevStore } from './local-dev-store';
import { ApproverPrincipalConflictError } from './approver-principal-constraint';

describe('LocalDevStore', () => {
  it('persists approver users and groups to a private local file', async () => {
    const directoryPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-local-dev-store-test-')), 'approvers.json');
    const firstStore = new LocalDevStore(directoryPath);

    await firstStore.upsertApproverGroup({
      createdAt: '2026-06-29T10:00:00.000Z',
      description: 'Support leads',
      displayName: 'Support managers',
      enabled: true,
      id: 'support-managers',
      updatedAt: '2026-06-29T10:00:00.000Z',
      workspaceId: 'default',
    });
    await firstStore.upsertApproverUser({
      createdAt: '2026-06-29T10:00:00.000Z',
      defaultApprover: true,
      displayName: 'Alice',
      email: 'alice@example.com',
      enabled: true,
      groups: ['support-managers'],
      id: 'u_alice',
      principalId: 'oidc|alice',
      slackUserId: 'U_ALICE',
      telegramChatId: '222',
      telegramUsername: 'alice',
      telegramUserId: '111',
      updatedAt: '2026-06-29T10:00:00.000Z',
      workspaceId: 'default',
    });
    await firstStore.createToolCall(toolCall({ id: 'toolcall_memory_only' }));

    const secondStore = new LocalDevStore(directoryPath);

    await expect(secondStore.listApproverGroups('default')).resolves.toMatchObject([
      { displayName: 'Support managers', id: 'support-managers' },
    ]);
    await expect(secondStore.listApproverUsers('default')).resolves.toMatchObject([
      {
        defaultApprover: true,
        email: 'alice@example.com',
        groups: ['support-managers'],
        id: 'u_alice',
        principalId: 'oidc|alice',
        slackUserId: 'U_ALICE',
        telegramChatId: '222',
        telegramUserId: '111',
      },
    ]);
    await expect(secondStore.getToolCall('toolcall_memory_only')).resolves.toBeUndefined();

    if (process.platform !== 'win32') {
      expect(fs.statSync(directoryPath).mode & 0o777).toBe(0o600);
    }
  });

  it('atomically rejects a mapped principal colliding with a fallback id', async () => {
    const directoryPath = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-local-dev-effective-identity-test-')),
      'approvers.json',
    );
    const store = new LocalDevStore(directoryPath);
    const results = await Promise.allSettled([
      store.upsertApproverUser(approverUser('u_mapped', 'oidc|operator')),
      store.upsertApproverUser(approverUser('oidc|operator')),
    ]);

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result): result is PromiseRejectedResult => result.status === 'rejected');
    expect(rejected?.reason).toBeInstanceOf(ApproverPrincipalConflictError);
    await expect(store.listApproverUsers('default')).resolves.toHaveLength(1);
  });
});

function approverUser(id: string, principalId?: string): ApproverUserRecord {
  return {
    createdAt: '2026-08-09T10:00:00.000Z',
    defaultApprover: false,
    displayName: id,
    enabled: true,
    groups: [],
    id,
    principalId,
    updatedAt: '2026-08-09T10:00:00.000Z',
    workspaceId: 'default',
  };
}

function toolCall(overrides: Partial<ToolCallRecord>): ToolCallRecord {
  return {
    agentId: 'demo-agent',
    createdAt: '2026-06-29T10:00:00.000Z',
    id: 'toolcall_default',
    input: {},
    metadata: {},
    reason: 'Test call',
    requestedBy: 'dev@example.com',
    status: 'submitted',
    toolName: 'docs.search',
    updatedAt: '2026-06-29T10:00:00.000Z',
    ...overrides,
  };
}
