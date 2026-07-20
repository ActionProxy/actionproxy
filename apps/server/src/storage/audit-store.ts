import type { AuditEvent } from '../models';

export interface AuditListFilters {
  from?: string;
  to?: string;
  toolCallId?: string;
  workspaceId?: string;
}

export type AuditListLimit = number | 'all';

export interface AuditStore {
  /** Append once by event id; an exact id replay is an idempotent no-op. */
  append(event: AuditEvent): Promise<void>;
  list(limit?: AuditListLimit, filters?: AuditListFilters): Promise<AuditEvent[]>;
}
