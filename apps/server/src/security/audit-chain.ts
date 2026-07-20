import type { AuditEvent } from '../models';
import type { AuditListFilters, AuditListLimit, AuditStore } from '../storage/audit-store';
import { stableStringify, sha256Hex } from './crypto';

export interface AuditVerificationResult {
  checked: number;
  firstEventHash?: string;
  lastEventHash?: string;
  valid: boolean;
  errors: Array<{
    eventId: string;
    index: number;
    reason: string;
  }>;
}

export class ChainedAuditStore implements AuditStore {
  private appendQueue: Promise<void> = Promise.resolve();

  constructor(private readonly inner: AuditStore) {}

  async append(event: AuditEvent): Promise<void> {
    const append = this.appendQueue.then(() => this.appendChained(event));
    this.appendQueue = append.catch(() => undefined);
    return append;
  }

  private async appendChained(event: AuditEvent): Promise<void> {
    const previous = (await this.inner.list(1))[0];
    const chained: AuditEvent = {
      ...event,
      previousEventHash: previous?.eventHash,
      // Durable stores order audit reads by timestamp. Some lifecycle events
      // intentionally carry an occurrence time that predates evidence already
      // appended (for example, terminal outcome evidence written after a
      // content-exposure record), and several events may share one millisecond.
      // Keep the append order total so the persisted hash chain has one stable
      // head across SQLite/Postgres reads and process restarts.
      timestamp: nextAuditTimestamp(event.timestamp, previous?.timestamp),
    };
    await this.inner.append({
      ...chained,
      eventHash: auditEventHash(chained),
    });
  }

  list(limit?: AuditListLimit, filters?: AuditListFilters): Promise<AuditEvent[]> {
    return this.inner.list(limit, filters);
  }
}

function nextAuditTimestamp(candidate: string, previous: string | undefined): string {
  if (!previous) return candidate;
  const candidateMillis = Date.parse(candidate);
  const previousMillis = Date.parse(previous);
  if (!Number.isFinite(previousMillis) || (Number.isFinite(candidateMillis) && candidateMillis > previousMillis)) {
    return candidate;
  }
  return new Date(previousMillis + 1).toISOString();
}

export async function verifyAuditStore(auditStore: AuditStore, limit = 10_000): Promise<AuditVerificationResult> {
  const events = (await auditStore.list(limit)).slice().reverse();
  return verifyAuditEvents(events);
}

export function verifyAuditEvents(events: AuditEvent[]): AuditVerificationResult {
  const errors: AuditVerificationResult['errors'] = [];
  let previousEventHash: string | undefined;

  events.forEach((event, index) => {
    if (event.previousEventHash !== previousEventHash) {
      errors.push({
        eventId: event.id,
        index,
        reason: 'previous_event_hash_mismatch',
      });
    }

    if (!event.eventHash) {
      errors.push({ eventId: event.id, index, reason: 'missing_event_hash' });
    } else {
      const expected = auditEventHash({ ...event, eventHash: undefined });
      if (event.eventHash !== expected) {
        errors.push({ eventId: event.id, index, reason: 'event_hash_mismatch' });
      }
    }

    previousEventHash = event.eventHash;
  });

  return {
    checked: events.length,
    errors,
    firstEventHash: events[0]?.eventHash,
    lastEventHash: events[events.length - 1]?.eventHash,
    valid: errors.length === 0,
  };
}

function auditEventHash(event: AuditEvent): string {
  const hashInput = {
    actor: event.actor,
    approvalId: event.approvalId,
    auth: event.auth,
    data: event.data,
    id: event.id,
    inputHash: event.inputHash,
    policyVersionHash: event.policyVersionHash,
    policyVersionId: event.policyVersionId,
    previousEventHash: event.previousEventHash,
    timestamp: event.timestamp,
    toolCallId: event.toolCallId,
    type: event.type,
    workspaceId: event.workspaceId,
  };
  return sha256Hex(stableStringify(stripUndefined(hashInput)));
}

function stripUndefined(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripUndefined);
  if (value === null || typeof value !== 'object') return value;

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .map(([key, entry]) => [key, stripUndefined(entry)]),
  );
}
