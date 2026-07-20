import fs from 'node:fs';
import path from 'node:path';
import type { AuditEvent } from '../models';
import type { AuditListFilters, AuditListLimit, AuditStore } from './audit-store';

export class JsonlAuditStore implements AuditStore {
  private auditPath: string;
  private readonly eventIds = new Set<string>();

  constructor(dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.auditPath = path.join(dataDir, 'audit.jsonl');
    if (!fs.existsSync(this.auditPath)) {
      fs.writeFileSync(this.auditPath, '', 'utf8');
    }
    const existing = fs.readFileSync(this.auditPath, 'utf8').trim();
    if (existing) {
      for (const line of existing.split('\n')) {
        try {
          const event = JSON.parse(line) as Pick<AuditEvent, 'id'>;
          if (event.id) this.eventIds.add(event.id);
        } catch {
          // Preserve the existing append-only file. Verification surfaces an
          // invalid row; initialization must not silently rewrite it.
        }
      }
    }
  }

  async append(event: AuditEvent): Promise<void> {
    if (this.eventIds.has(event.id)) return;
    fs.appendFileSync(this.auditPath, `${JSON.stringify(event)}\n`, 'utf8');
    this.eventIds.add(event.id);
  }

  async list(limit: AuditListLimit = 100, filters: AuditListFilters = {}): Promise<AuditEvent[]> {
    if (!fs.existsSync(this.auditPath)) return [];
    const raw = fs.readFileSync(this.auditPath, 'utf8').trim();
    if (!raw) return [];
    const safeLimit = limit === 'all' ? undefined : Number.isFinite(limit) ? Math.max(1, Math.trunc(limit)) : 100;

    const events = raw
      .split('\n')
      .map((line) => JSON.parse(line) as AuditEvent)
      .filter((event) => auditEventInRange(event, filters));

    return (safeLimit === undefined ? events : events.slice(-safeLimit)).reverse();
  }
}

function auditEventInRange(event: AuditEvent, filters: AuditListFilters): boolean {
  if (filters.from && event.timestamp < filters.from) return false;
  if (filters.to && event.timestamp > filters.to) return false;
  if (filters.toolCallId && event.toolCallId !== filters.toolCallId) return false;
  if (filters.workspaceId && event.workspaceId !== filters.workspaceId) return false;
  return true;
}
