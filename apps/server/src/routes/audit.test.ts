import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '../models';
import { JsonlAuditStore } from '../storage/jsonl-audit-store';
import { registerAuditRoutes } from './audit';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('audit routes', () => {
  it('lists audit events inside the requested date range', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    await auditStore.append(auditEvent('evt_old', 'policy.allow', '2026-06-20T08:00:00.000Z'));
    await auditStore.append(auditEvent('evt_in_range', 'tool_call.submitted', '2026-06-20T09:00:00.000Z'));
    await auditStore.append(auditEvent('evt_new', 'policy.deny', '2026-06-20T10:00:00.000Z'));

    app = Fastify({ logger: false });
    await registerAuditRoutes(app, auditStore);

    const response = await app.inject({
      method: 'GET',
      url: '/v1/audit?from=2026-06-20T08:30:00.000Z&to=2026-06-20T09:30:00.000Z&limit=10',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().events).toEqual([expect.objectContaining({ id: 'evt_in_range' })]);
  });

  it('exports all matching audit events without the screen limit', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    await auditStore.append(auditEvent('evt_old', 'policy.allow', '2026-06-20T08:00:00.000Z'));
    await auditStore.append(auditEvent('evt_middle', 'tool_call.submitted', '2026-06-20T09:00:00.000Z'));
    await auditStore.append(auditEvent('evt_new', 'policy.deny', '2026-06-20T10:00:00.000Z'));

    app = Fastify({ logger: false });
    await registerAuditRoutes(app, auditStore);

    const visible = await app.inject({ method: 'GET', url: '/v1/audit?limit=2' });
    const exported = await app.inject({ method: 'GET', url: '/v1/audit/export?format=json' });

    expect(visible.statusCode).toBe(200);
    expect(visible.json().events).toHaveLength(2);
    expect(exported.statusCode).toBe(200);
    expect(exported.headers['content-disposition']).toContain('attachment; filename="actionproxy-audit-');
    expect(exported.json()).toMatchObject({
      count: 3,
      events: [
        expect.objectContaining({ id: 'evt_new' }),
        expect.objectContaining({ id: 'evt_middle' }),
        expect.objectContaining({ id: 'evt_old' }),
      ],
    });
  });

  it('filters list and export by exact tool call before applying limits', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    await auditStore.append(auditEvent(
      'evt_target_old',
      'content.influence_evaluated',
      '2026-06-20T08:00:00.000Z',
      'toolcall/target',
    ));
    await auditStore.append(auditEvent(
      'evt_unrelated_new',
      'tool_call.submitted',
      '2026-06-20T10:00:00.000Z',
      'toolcall_unrelated',
    ));

    app = Fastify({ logger: false });
    await registerAuditRoutes(app, auditStore);

    const encodedToolCallId = encodeURIComponent('toolcall/target');
    const visible = await app.inject({
      method: 'GET',
      url: `/v1/audit?limit=1&toolCallId=${encodedToolCallId}`,
    });
    const exported = await app.inject({
      method: 'GET',
      url: `/v1/audit/export?format=json&toolCallId=${encodedToolCallId}`,
    });

    expect(visible.statusCode).toBe(200);
    expect(visible.json().events).toEqual([
      expect.objectContaining({ id: 'evt_target_old', toolCallId: 'toolcall/target' }),
    ]);
    expect(exported.statusCode).toBe(200);
    expect(exported.json()).toMatchObject({
      count: 1,
      events: [expect.objectContaining({ id: 'evt_target_old', toolCallId: 'toolcall/target' })],
    });
  });

  it('redacts authorization material from legacy audit rows while preserving provider evidence', async () => {
    const auditStore = new JsonlAuditStore(tempDir());
    const legacyAuthorized = auditEvent('evt_legacy_authorized', 'tool_call.authorized', '2026-06-20T09:00:00.000Z');
    legacyAuthorized.data = {
      result: {
        externalExecutionOutcome: {
          nonce: 'provider-nonce',
          signature: 'provider-signature',
        },
        grant: {
          id: 'grant_legacy',
          nonce: 'raw-grant-nonce',
          signature: 'raw-grant-signature',
        },
        receipt: {
          id: 'receipt_legacy',
          signature: 'raw-receipt-signature',
        },
      },
    };
    await auditStore.append(legacyAuthorized);

    app = Fastify({ logger: false });
    await registerAuditRoutes(app, auditStore);

    const responses = await Promise.all([
      app.inject({ method: 'GET', url: '/v1/audit?limit=10' }),
      app.inject({ method: 'GET', url: '/v1/audit?format=siem&limit=10' }),
      app.inject({ method: 'GET', url: '/v1/audit/export?format=json' }),
      app.inject({ method: 'GET', url: '/v1/audit/export?format=siem' }),
    ]);

    for (const response of responses) {
      expect(response.statusCode).toBe(200);
      expect(response.body).not.toMatch(/raw-(?:grant-nonce|grant-signature|receipt-signature)/u);
      expect(response.body).toContain('provider-nonce');
      expect(response.body).toContain('provider-signature');
    }
    expect(responses[0].json().events[0].data.result).toMatchObject({
      externalExecutionOutcome: {
        nonce: 'provider-nonce',
        signature: 'provider-signature',
      },
      grant: {
        id: 'grant_legacy',
        nonce: '[REDACTED]',
        signature: '[REDACTED]',
      },
      receipt: {
        id: 'receipt_legacy',
        signature: '[REDACTED]',
      },
    });
  });
});

function auditEvent(
  id: string,
  type: AuditEvent['type'],
  timestamp: string,
  toolCallId?: string,
): AuditEvent {
  return {
    actor: 'audit-test@example.com',
    data: { reason: id, toolName: 'docs.search' },
    id,
    timestamp,
    ...(toolCallId === undefined ? {} : { toolCallId }),
    type,
  };
}

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-audit-route-test-'));
}
