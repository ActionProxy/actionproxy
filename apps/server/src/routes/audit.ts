import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { AuditEvent } from '../models';
import { verifyAuditStore } from '../security/audit-chain';
import { redactJsonObject, type RedactionOptions } from '../security/redaction';
import { requireScope } from '../security/scopes';
import type { AuditStore } from '../storage/audit-store';
import { noopTelemetry, type TelemetryRecorder } from '../telemetry/telemetry';
import { authContext } from './route-utils';

export async function registerAuditRoutes(
  app: FastifyInstance,
  auditStore: AuditStore,
  redaction: RedactionOptions = {},
  telemetry: TelemetryRecorder = noopTelemetry,
): Promise<void> {
  app.get('/v1/audit', async (request, reply) => {
    const auth = requireScope(authContext(request), 'audit:read');
    const query = auditQuerySchema.parse(request.query);
    const events = await auditStore.list(query.limit ?? 100, {
      from: query.from,
      to: query.to,
      toolCallId: query.toolCallId,
      workspaceId: auth.scopes.includes('*') ? undefined : auth.workspaceId,
    });
    const visibleEvents = visibleAuditEvents(events, auth.workspaceId, auth.scopes, redaction);

    if (query.format === 'siem') {
      reply.header('content-type', 'application/x-ndjson');
      return visibleEvents.map((event) => JSON.stringify(toSiemEvent(event))).join('\n');
    }

    return { events: visibleEvents };
  });

  app.get('/v1/audit/export', async (request, reply) => {
    const auth = requireScope(authContext(request), 'audit:read');
    const query = auditExportQuerySchema.parse(request.query);
    const events = await auditStore.list('all', {
      from: query.from,
      to: query.to,
      toolCallId: query.toolCallId,
      workspaceId: auth.scopes.includes('*') ? undefined : auth.workspaceId,
    });
    const visibleEvents = visibleAuditEvents(events, auth.workspaceId, auth.scopes, redaction);
    const exportedAt = new Date().toISOString();
    const format = query.format ?? 'json';
    const extension = format === 'siem' ? 'ndjson' : 'json';
    reply.header('content-disposition', `attachment; filename="${auditExportFilename(exportedAt, extension)}"`);

    if (format === 'siem') {
      reply.header('content-type', 'application/x-ndjson');
      return visibleEvents.map((event) => JSON.stringify(toSiemEvent(event))).join('\n');
    }

    return {
      count: visibleEvents.length,
      events: visibleEvents,
      exportedAt,
      filters: {
        from: query.from,
        toolCallId: query.toolCallId,
        to: query.to,
      },
    };
  });

  app.get('/v1/audit/verify', async (request) => {
    const auth = requireScope(authContext(request), 'audit:read');
    const query = z.object({ limit: z.coerce.number().min(1).max(10000).optional() }).parse(request.query);
    const result = await verifyAuditStore(auditStore, query.limit ?? 10_000);
    void telemetry.recordLifecycle('audit.verify', {
      'audit.checked': result.checked,
      'audit.error_count': result.errors.length,
      'audit.valid': result.valid,
      'workspace.id': auth.workspaceId,
    }).catch(() => undefined);
    return result;
  });
}

const isoDateStringSchema = z.string().refine((value) => !Number.isNaN(Date.parse(value)), {
  message: 'Expected an ISO date string.',
});

const auditQueryBaseSchema = z.object({
  format: z.enum(['json', 'siem']).optional(),
  from: isoDateStringSchema.optional(),
  limit: z.coerce.number().min(1).max(5000).optional(),
  toolCallId: z.string().min(1).optional(),
  to: isoDateStringSchema.optional(),
});

const validAuditRange = {
  message: '`from` must be before or equal to `to`.',
  path: ['from'],
};

const auditQuerySchema = auditQueryBaseSchema.refine((input) => !input.from || !input.to || input.from <= input.to, validAuditRange);

const auditExportQuerySchema = auditQueryBaseSchema
  .omit({ limit: true })
  .refine((input) => !input.from || !input.to || input.from <= input.to, validAuditRange);

function visibleAuditEvents(
  events: AuditEvent[],
  workspaceId: string,
  scopes: string[],
  redaction: RedactionOptions,
): AuditEvent[] {
  return events
    .filter((event) => !event.workspaceId || event.workspaceId === workspaceId || scopes.includes('*'))
    .map((event) => redactAuditEvent(event, redaction));
}

function auditExportFilename(exportedAt: string, extension: 'json' | 'ndjson'): string {
  return `actionproxy-audit-${exportedAt.replace(/[:.]/g, '-')}.${extension}`;
}

function redactAuditEvent(event: AuditEvent, redaction: RedactionOptions): AuditEvent {
  return {
    ...event,
    data: redactJsonObject(event.data, redaction),
  };
}

function toSiemEvent(event: AuditEvent): Record<string, unknown> {
  return {
    actionproxy_event_hash: event.eventHash,
    actionproxy_previous_event_hash: event.previousEventHash,
    actionproxy_type: event.type,
    actor: event.actor,
    approval_id: event.approvalId,
    event_id: event.id,
    input_hash: event.inputHash,
    policy_version_hash: event.policyVersionHash,
    policy_version_id: event.policyVersionId,
    timestamp: event.timestamp,
    tool_call_id: event.toolCallId,
    workspace_id: event.workspaceId,
    ...event.data,
  };
}
