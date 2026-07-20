import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { AuditEvent } from '../models';
import type { AuditListFilters, AuditListLimit, AuditStore } from '../storage/audit-store';
import { JsonlAuditStore } from '../storage/jsonl-audit-store';
import { ChainedAuditStore, verifyAuditStore } from './audit-chain';

describe('ChainedAuditStore', () => {
  it('serializes concurrent appends into a valid chain', async () => {
    const inner = new JsonlAuditStore(fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-audit-race-')));
    const auditStore = new ChainedAuditStore(inner);

    await Promise.all(
      Array.from({ length: 40 }, (_, index) => auditStore.append(auditEvent(index))),
    );

    await expect(verifyAuditStore(auditStore)).resolves.toMatchObject({
      checked: 40,
      errors: [],
      valid: true,
    });
  });

  it('keeps deterministic event-id replays idempotent across JSONL restarts', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-audit-idempotent-'));
    const event = auditEvent(1);
    const first = new JsonlAuditStore(directory);
    await first.append(event);
    await first.append(event);
    const second = new JsonlAuditStore(directory);
    await second.append(event);

    await expect(second.list('all')).resolves.toEqual([event]);
  });

  it('keeps one durable chain when later appends carry equal or backdated occurrence times', async () => {
    const inner = new TimestampOrderedAuditStore();
    const auditStore = new ChainedAuditStore(inner);

    await auditStore.append({ ...auditEvent(1), timestamp: '2026-07-10T10:00:00.005Z' });
    await auditStore.append({ ...auditEvent(2), timestamp: '2026-07-10T10:00:00.001Z' });
    await auditStore.append({ ...auditEvent(3), timestamp: '2026-07-10T10:00:00.001Z' });

    await expect(verifyAuditStore(auditStore)).resolves.toMatchObject({
      checked: 3,
      errors: [],
      valid: true,
    });
    await expect(inner.list('all')).resolves.toMatchObject([
      { id: 'audit-race-3', timestamp: '2026-07-10T10:00:00.007Z' },
      { id: 'audit-race-2', timestamp: '2026-07-10T10:00:00.006Z' },
      { id: 'audit-race-1', timestamp: '2026-07-10T10:00:00.005Z' },
    ]);
  });
});

class TimestampOrderedAuditStore implements AuditStore {
  private readonly events: AuditEvent[] = [];

  async append(event: AuditEvent): Promise<void> {
    if (!this.events.some((candidate) => candidate.id === event.id)) this.events.push(event);
  }

  async list(limit: AuditListLimit = 100, filters: AuditListFilters = {}): Promise<AuditEvent[]> {
    const matching = this.events
      .filter((event) => !filters.from || event.timestamp >= filters.from)
      .filter((event) => !filters.to || event.timestamp <= filters.to)
      .filter((event) => !filters.toolCallId || event.toolCallId === filters.toolCallId)
      .filter((event) => !filters.workspaceId || event.workspaceId === filters.workspaceId)
      .sort((left, right) => right.timestamp.localeCompare(left.timestamp));
    return limit === 'all' ? matching : matching.slice(0, limit);
  }
}

function auditEvent(index: number): AuditEvent {
  return {
    actor: `actor-${index}`,
    data: { index },
    id: `audit-race-${index}`,
    timestamp: `2026-07-10T10:00:${String(index).padStart(2, '0')}.000Z`,
    type: 'tool_call.submitted',
    workspaceId: 'default',
  };
}
