import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { IntegrationConfigService } from '../integrations/integration-config';
import type { ApprovalDeliveryRecord, ApprovalRecord, AuditEvent, ObservedToolRecord, ToolCallRecord } from '../models';
import { PolicyManager } from '../policy/policy-manager';
import type { PolicyFile } from '../policy/policy-types';
import { ChainedAuditStore } from '../security/audit-chain';
import { JsonlAuditStore } from '../storage/jsonl-audit-store';
import { MemoryStore } from '../storage/memory-store';
import type { AuditStore } from '../storage/audit-store';
import { registerDashboardRoutes } from './dashboard';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('dashboard routes', () => {
  it('returns an evidence-backed empty CISO overview', async () => {
    const context = await testContext();

    app = Fastify({ logger: false });
    await registerDashboardRoutes(app, context);

    const response = await app.inject({ method: 'GET', url: '/v1/dashboard/overview' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      auditIntegrity: {
        checked: 0,
        valid: true,
      },
      controlCoverage: {
        coveragePercent: 100,
        explicitRuleCount: 2,
        unresolvedDetectorFindings: 0,
      },
      counts: {
        highRiskPendingApprovals: 0,
        notificationFailures: 0,
        pendingApprovals: 0,
        totalToolCalls: 0,
      },
      environment: {
        authMode: 'none',
        deploymentMode: 'local',
        localExecutionMode: 'disabled',
        storageMode: 'memory',
        workspaceId: 'default',
      },
      policy: {
        defaultApproval: 'required',
        redactionEnabled: true,
        ruleCount: 2,
        version: 1,
      },
    });
    expect(response.json().policy.hash).toHaveLength(64);
  });

  it('surfaces high-risk queue, policy gaps, failed delivery, audit verification, and edited decisions', async () => {
    const context = await testContext();
    await context.store.createToolCall(toolCall({
      decision: 'require_approval',
      id: 'toolcall_delete_pending',
      risk: 'destructive',
      status: 'pending_approval',
      toolName: 'dangerous.delete_customer',
    }));
    await context.store.createApproval(approval({
      createdAt: '2000-01-01T00:00:00.000Z',
      id: 'approval_delete_pending',
      toolCallId: 'toolcall_delete_pending',
    }));
    await context.store.createApprovalDelivery(delivery({
      approvalId: 'approval_delete_pending',
      id: 'delivery_failed',
      status: 'failed',
      toolCallId: 'toolcall_delete_pending',
    }));
    await context.store.createToolCall(toolCall({
      decision: 'deny',
      id: 'toolcall_blocked',
      risk: 'destructive',
      status: 'blocked',
      toolName: 'dangerous.delete_customer',
    }));
    await context.store.createToolCall(toolCall({
      decision: 'require_approval',
      id: 'toolcall_email_approved',
      risk: 'external_communication',
      status: 'executed',
      toolName: 'gmail.send_email',
    }));
    await context.store.upsertObservedTool(observedTool());
    await context.auditStore.append(auditEvent('audit_policy_update', 'policy.updated', '2026-06-20T08:00:00.000Z', {
      actor: 'security@example.com',
      data: { ruleCount: 2 },
    }));
    await context.auditStore.append(auditEvent('audit_email_approved', 'approval.approved', '2026-06-20T08:10:00.000Z', {
      data: { editedInput: { body: 'Approved shorter response' } },
      toolCallId: 'toolcall_email_approved',
    }));
    await context.auditStore.append(auditEvent('audit_email_failure', 'email.approval_notification.failed', '2026-06-20T08:20:00.000Z', {
      data: { error: 'SMTP unavailable' },
    }));

    app = Fastify({ logger: false });
    await registerDashboardRoutes(app, context);

    const response = await app.inject({ method: 'GET', url: '/v1/dashboard/overview?window=7d' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      approvalHealth: {
        failedDeliveries: 1,
        pendingCount: 1,
        slaBreaches: 1,
      },
      auditIntegrity: {
        checked: 3,
        errorCount: 0,
        latestEventType: 'email.approval_notification.failed',
        valid: true,
      },
      controlCoverage: {
        coveredObservedTools: 0,
        defaultOnlyObservedTools: 1,
        totalObservedTools: 1,
        unresolvedDetectorFindings: 1,
      },
      counts: {
        deniedDestructiveAttempts: 1,
        highRiskPendingApprovals: 1,
        notificationFailures: 1,
        pendingApprovals: 1,
        totalToolCalls: 3,
        uniqueAgents: 1,
        uniqueTools: 2,
      },
      integrations: {
        lastFailure: {
          message: 'SMTP unavailable',
          type: 'email.approval_notification.failed',
        },
        summary: {
          failing: 1,
        },
      },
      policy: {
        lastUpdatedAt: '2026-06-20T08:00:00.000Z',
        lastUpdatedBy: 'security@example.com',
      },
    });
    expect(response.json().highRiskQueue[0]).toMatchObject({
      approvalId: 'approval_delete_pending',
      risk: 'destructive',
      toolCallId: 'toolcall_delete_pending',
      toolName: 'dangerous.delete_customer',
    });
    expect(response.json().policyGaps[0]).toMatchObject({
      matchedRule: 'default',
      suggestedApproval: 'required',
      toolName: 'crm.update_account',
    });
    expect(response.json().recentSensitiveDecisions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          editedPayload: true,
          status: 'executed',
          toolCallId: 'toolcall_email_approved',
        }),
      ]),
    );
  });

  it('reports the full policy detector gap count while capping the overview preview list', async () => {
    const context = await testContext();

    for (let index = 0; index < 10; index += 1) {
      const toolName = `crm.update_account_${index}`;
      const base = observedTool();
      await context.store.upsertObservedTool(observedTool({
        id: `observed_${index}`,
        suggestion: {
          ...base.suggestion,
          pattern: toolName,
        },
        toolName,
      }));
    }

    app = Fastify({ logger: false });
    await registerDashboardRoutes(app, context);

    const response = await app.inject({ method: 'GET', url: '/v1/dashboard/overview' });

    expect(response.statusCode).toBe(200);
    expect(response.json().controlCoverage.unresolvedDetectorFindings).toBe(10);
    expect(response.json().policyGaps).toHaveLength(8);
  });

});

async function testContext() {
  const dataDir = tempDir();
  const policy = defaultPolicy();
  const store = new MemoryStore();
  const auditStore = new ChainedAuditStore(new JsonlAuditStore(dataDir));
  return {
    auditStore,
    config: {
      auth: {
        allowedCorsOrigins: [],
        mode: 'none',
        oidc: {
          emailClaim: 'email',
          groupsClaim: 'groups',
          nameClaim: 'name',
          scopesClaim: 'scope',
        },
        rateLimit: {
          max: 600,
          windowMs: 60_000,
        },
        slackUserMap: {},
        workspaceId: 'default',
      },
      dataDir,
      executionGrants: {
        secret: 'test-secret',
        ttlSeconds: 300,
      },
      host: '127.0.0.1',
      localExecution: {
        mode: 'disabled',
      },
      logLevel: 'silent',
      policyPath: path.join(dataDir, 'policy.yaml'),
      port: 8787,
      storage: {
        mode: 'memory',
        sqlitePath: path.join(dataDir, 'actionproxy.sqlite'),
      },
    },
    integrationConfig: new IntegrationConfigService({
      dataDir,
      host: '127.0.0.1',
      logLevel: 'silent',
      policyPath: path.join(dataDir, 'policy.yaml'),
      port: 8787,
    }),
    policyManager: new PolicyManager(path.join(dataDir, 'policy.yaml'), policy),
    redaction: { fields: ['input.body'], replacement: '[REDACTED]' },
    store,
  } satisfies {
    auditStore: AuditStore;
    config: Parameters<typeof registerDashboardRoutes>[1]['config'];
    integrationConfig: IntegrationConfigService;
    policyManager: PolicyManager;
    redaction: Parameters<typeof registerDashboardRoutes>[1]['redaction'];
    store: MemoryStore;
  };
}

function defaultPolicy(): PolicyFile {
  return {
    default: {
      approval: 'required',
      reason: 'Unknown tools require approval by default.',
      risk: 'unknown',
    },
    tools: {
      'dangerous.delete_customer': {
        approval: 'deny',
        reason: 'Customer deletion is blocked.',
        risk: 'destructive',
      },
      'docs.search': {
        approval: 'never',
        reason: 'Search is read-only.',
        risk: 'read_only',
      },
    },
    version: 1,
  };
}

function toolCall(input: Partial<ToolCallRecord>): ToolCallRecord {
  const now = '2026-06-20T08:00:00.000Z';
  return {
    agentId: 'support-agent',
    createdAt: now,
    id: 'toolcall_default',
    input: {},
    metadata: {},
    reason: 'Test request',
    requestedBy: 'dev@example.com',
    status: 'submitted',
    toolName: 'docs.search',
    updatedAt: now,
    workspaceId: 'default',
    ...input,
  };
}

function approval(input: Partial<ApprovalRecord>): ApprovalRecord {
  const now = '2026-06-20T08:00:00.000Z';
  return {
    createdAt: now,
    id: 'approval_default',
    originalInput: {},
    requestedBy: 'dev@example.com',
    status: 'pending',
    toolCallId: 'toolcall_default',
    updatedAt: now,
    workspaceId: 'default',
    ...input,
  };
}

function delivery(input: Partial<ApprovalDeliveryRecord>): ApprovalDeliveryRecord {
  const now = '2026-06-20T08:00:00.000Z';
  return {
    approvalId: 'approval_default',
    channelId: 'email.default',
    createdAt: now,
    data: {},
    id: 'delivery_default',
    provider: 'email',
    status: 'sent',
    toolCallId: 'toolcall_default',
    updatedAt: now,
    workspaceId: 'default',
    ...input,
  };
}

function observedTool(input: Partial<ObservedToolRecord> = {}): ObservedToolRecord {
  const now = '2026-06-20T08:00:00.000Z';
  return {
    callCount: 2,
    coverage: {
      approval: 'required',
      decision: 'require_approval',
      matchedRule: 'default',
      matchType: 'default',
      reason: 'Unknown tools require approval by default.',
      risk: 'unknown',
      status: 'uncovered',
    },
    createdAt: now,
    firstSeenAt: now,
    id: 'observed_crm_update_account',
    lastSeenAt: now,
    sourceIds: { agentIds: ['support-agent'] },
    sources: ['runtime'],
    status: 'unresolved',
    suggestion: {
      approval: 'required',
      confidence: 'high',
      pattern: 'crm.update_account',
      patternType: 'exact',
      reason: 'Observed CRM mutation should require approval.',
      risk: 'data_mutation',
    },
    toolName: 'crm.update_account',
    updatedAt: now,
    workspaceId: 'default',
    ...input,
  };
}

function auditEvent(
  id: string,
  type: AuditEvent['type'],
  timestamp: string,
  input: Partial<AuditEvent> = {},
): AuditEvent {
  return {
    actor: 'dev@example.com',
    data: {},
    id,
    timestamp,
    type,
    workspaceId: 'default',
    ...input,
  };
}

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-dashboard-route-test-'));
}
