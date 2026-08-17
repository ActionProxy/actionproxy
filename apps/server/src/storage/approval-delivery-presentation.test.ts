import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ApprovalDeliveryRecord } from '../models';
import { MemoryStore } from './memory-store';
import { PostgresStore } from './postgres-store';
import { SqliteStore } from './sqlite-store';
import type { Store } from './store';

type ApprovalDeliveryStore = Pick<
  Store,
  'createApprovalDelivery' | 'listApprovalDeliveries' | 'updateApprovalDelivery'
>;

const describeIfSqlite = hasSqliteCli() ? describe : describe.skip;
const describeIfPostgres = process.env.ACTIONPROXY_TEST_POSTGRES_URL ? describe : describe.skip;

describe('approval delivery presentation metadata persistence', () => {
  it('round-trips the latest Telegram presentation through MemoryStore', async () => {
    const store = new MemoryStore();
    await expectPresentationMetadataRoundTrip(store, 'memory');
  });
});

describeIfSqlite('approval delivery presentation metadata persistence in SQLite', () => {
  it('round-trips the latest Telegram presentation across store instances', async () => {
    const databasePath = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-delivery-presentation-')),
      'actionproxy.sqlite',
    );
    const first = new SqliteStore(databasePath);
    const initial = delivery('sqlite');
    await first.createApprovalDelivery(initial);

    const updated = withTerminalPresentation(initial);
    await new SqliteStore(databasePath).updateApprovalDelivery(updated);

    await expect(new SqliteStore(databasePath).listApprovalDeliveries(initial.approvalId))
      .resolves.toEqual([updated]);
  });
});

describeIfPostgres('approval delivery presentation metadata persistence in Postgres', () => {
  it('round-trips the latest Telegram presentation across pools', async () => {
    const databaseUrl = process.env.ACTIONPROXY_TEST_POSTGRES_URL!;
    const stores = [await PostgresStore.connect(databaseUrl), await PostgresStore.connect(databaseUrl)];
    try {
      const initial = delivery(`postgres_${randomUUID()}`);
      await stores[0]!.createApprovalDelivery(initial);

      const updated = withTerminalPresentation(initial);
      await stores[1]!.updateApprovalDelivery(updated);

      await expect(stores[0]!.listApprovalDeliveries(initial.approvalId)).resolves.toEqual([updated]);
    } finally {
      await Promise.all(stores.map((store) => store.close()));
    }
  });
});

async function expectPresentationMetadataRoundTrip(
  store: ApprovalDeliveryStore,
  suffix: string,
): Promise<void> {
  const initial = delivery(suffix);
  await store.createApprovalDelivery(initial);
  const updated = withTerminalPresentation(initial);
  await store.updateApprovalDelivery(updated);
  await expect(store.listApprovalDeliveries(initial.approvalId)).resolves.toEqual([updated]);
}

function delivery(suffix: string): ApprovalDeliveryRecord {
  return {
    approvalId: `approval_${suffix}`,
    channelId: 'telegram.default',
    createdAt: '2026-08-13T10:00:00.000Z',
    data: {
      approvalUrl: `https://actionproxy.example/#/approvals/approval_${suffix}`,
      messageTs: null,
      telegramChatId: '222',
    },
    destination: '222',
    id: `delivery_${suffix}`,
    messageId: '42',
    provider: 'telegram',
    recipientTelegramChatId: '222',
    recipientTelegramUserId: '333',
    recipientUserId: 'approver_1',
    status: 'sent',
    toolCallId: `toolcall_${suffix}`,
    updatedAt: '2026-08-13T10:00:00.000Z',
    workspaceId: 'default',
  };
}

function withTerminalPresentation(record: ApprovalDeliveryRecord): ApprovalDeliveryRecord {
  return {
    ...record,
    data: {
      ...record.data,
      telegramPresentation: {
        attemptedAt: '2026-08-13T10:01:00.000Z',
        result: 'updated',
        syncedAt: '2026-08-13T10:01:00.050Z',
        targetStatus: 'approved',
        version: 1,
      },
    },
    status: 'sent',
    updatedAt: '2026-08-13T10:01:00.050Z',
  };
}

function hasSqliteCli(): boolean {
  try {
    execFileSync('sqlite3', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
