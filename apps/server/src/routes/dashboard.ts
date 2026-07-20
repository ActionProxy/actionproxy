import { createHash } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { AppConfig, AuthMode, DeploymentMode, LocalExecutionMode, StorageMode } from '../config';
import type { IntegrationConfigService, IntegrationStatus, IntegrationStatusResponse } from '../integrations/integration-config';
import type {
  ApprovalDeliveryRecord,
  ApprovalRecord,
  AuditEvent,
  PolicyDecision,
  ToolCallRecord,
  ToolCallStatus,
} from '../models';
import type { PolicyManager } from '../policy/policy-manager';
import type { ApprovalMode } from '../policy/policy-types';
import { verifyAuditStore } from '../security/audit-chain';
import type { RedactionOptions } from '../security/redaction';
import { requireScope } from '../security/scopes';
import type { AuditStore } from '../storage/audit-store';
import type { Store } from '../storage/store';
import { summarizePolicy } from './policy';
import { authContext } from './route-utils';

type DashboardWindow = '24h' | '7d' | '30d';

interface DashboardOverviewOptions {
  auditStore: AuditStore;
  config: AppConfig & {
    auth: NonNullable<AppConfig['auth']>;
    executionGrants: NonNullable<AppConfig['executionGrants']>;
  };
  integrationConfig: IntegrationConfigService;
  policyManager: PolicyManager;
  redaction: RedactionOptions;
  store: Store;
}

const dashboardOverviewQuerySchema = z.object({
  window: z.enum(['24h', '7d', '30d']).default('24h'),
});

const statusKeys: ToolCallStatus[] = ['submitted', 'authorized', 'executed', 'pending_approval', 'blocked', 'rejected', 'failed'];
const decisionKeys: PolicyDecision[] = ['allow', 'require_approval', 'deny'];
const approvalSlaMs = 4 * 60 * 60 * 1000;

export async function registerDashboardRoutes(
  app: FastifyInstance,
  options: DashboardOverviewOptions,
): Promise<void> {
  app.get('/v1/dashboard/overview', async (request) => {
    const auth = requireScope(authContext(request), 'tool_call:read');
    requireScope(auth, 'approval:read');
    requireScope(auth, 'audit:read');
    requireScope(auth, 'policy:read');
    requireScope(auth, 'admin:integrations');

    const query = dashboardOverviewQuerySchema.parse(request.query);
    const now = new Date();
    const windowStart = new Date(now.getTime() - windowMs(query.window));
    const policy = options.policyManager.getPolicy();
    const policySummary = summarizePolicy(policy);
    const policyHash = hashJson(policy);
    const integrations = options.integrationConfig.getStatus(policy);
    const [toolCalls, pendingApprovals, auditEvents, observedTools, auditVerification] = await Promise.all([
      options.store.listToolCalls({ limit: 1000 }),
      options.store.listPendingApprovals(),
      options.auditStore.list(1000),
      options.store.listObservedTools(auth.workspaceId),
      verifyAuditStore(options.auditStore, 10_000),
    ]);

    const visibleToolCalls = toolCalls.filter((toolCall) => visibleForWorkspace(toolCall.workspaceId, auth.workspaceId, auth.scopes));
    const visiblePendingApprovals = pendingApprovals.filter((approval) =>
      visibleForWorkspace(approval.workspaceId, auth.workspaceId, auth.scopes),
    );
    const visibleAuditEvents = auditEvents
      .filter((event) => visibleForWorkspace(event.workspaceId, auth.workspaceId, auth.scopes))
      .sort((left, right) => right.timestamp.localeCompare(left.timestamp));
    const toolCallById = new Map(visibleToolCalls.map((toolCall) => [toolCall.id, toolCall]));
    const deliveries = await pendingApprovalDeliveries(options.store, visiblePendingApprovals);
    const windowToolCalls = visibleToolCalls.filter((toolCall) => new Date(toolCall.createdAt) >= windowStart);
    const statusCounts = countBy(statusKeys, visibleToolCalls, (toolCall) => toolCall.status);
    const decisionCounts = countBy(decisionKeys, visibleToolCalls, (toolCall) => toolCall.decision);
    const riskCounts = visibleToolCalls.reduce<Record<string, number>>((counts, toolCall) => {
      const risk = toolCall.risk ?? 'unknown';
      counts[risk] = (counts[risk] ?? 0) + 1;
      return counts;
    }, {});
    const highRiskPendingQueue = highRiskQueue(visiblePendingApprovals, toolCallById, now);
    const unresolvedPolicyGapTools = observedTools.filter((tool) => tool.status === 'unresolved' && tool.coverage.status === 'uncovered');
    const unresolvedPolicyGaps = unresolvedPolicyGapTools
      .map((tool) => ({
        callCount: tool.callCount,
        lastSeenAt: tool.lastSeenAt,
        matchedRule: tool.coverage.matchedRule,
        risk: tool.coverage.risk,
        suggestedApproval: tool.suggestion.approval,
        suggestedPattern: tool.suggestion.pattern,
        toolName: tool.toolName,
      }))
      .slice(0, 8);
    const coveredObservedTools = observedTools.filter((tool) => tool.coverage.status === 'covered').length;
    const defaultOnlyObservedTools = observedTools.filter((tool) => tool.coverage.matchedRule === 'default').length;
    const latestPolicyUpdate = visibleAuditEvents.find((event) => event.type === 'policy.updated');
    const latestIntegrationFailure = visibleAuditEvents.find(isIntegrationFailureEvent);
    const latestEvent = visibleAuditEvents[0];
    return {
      window: {
        from: windowStart.toISOString(),
        key: query.window,
        to: now.toISOString(),
      },
      environment: {
        authMode: options.config.auth.mode,
        deploymentMode: options.config.deployment?.mode ?? (options.config.auth.mode === 'none' ? 'local' : 'self_hosted'),
        localExecutionMode: options.config.localExecution?.mode ?? 'disabled',
        storageMode: options.config.storage?.mode ?? 'memory',
        workspaceId: auth.workspaceId,
      } satisfies {
        authMode: AuthMode;
        deploymentMode: DeploymentMode;
        localExecutionMode: LocalExecutionMode;
        storageMode: StorageMode;
        workspaceId: string;
      },
      counts: {
        blockedCount: statusCounts.blocked,
        deniedDestructiveAttempts: visibleToolCalls.filter(
          (toolCall) => toolCall.decision === 'deny' && (toolCall.risk ?? 'unknown') === 'destructive',
        ).length,
        decisionCounts,
        failedExecutions: statusCounts.failed,
        highRiskPendingApprovals: highRiskPendingQueue.length,
        notificationFailures: deliveries.filter((delivery) => delivery.status === 'failed').length,
        pendingApprovals: visiblePendingApprovals.length,
        riskCounts,
        statusCounts,
        totalToolCalls: visibleToolCalls.length,
        uniqueAgents: new Set(visibleToolCalls.map((toolCall) => toolCall.agentId)).size,
        uniqueTools: new Set(visibleToolCalls.map((toolCall) => toolCall.toolName)).size,
        windowToolCalls: windowToolCalls.length,
      },
      approvalHealth: {
        failedDeliveries: deliveries.filter((delivery) => delivery.status === 'failed').length,
        oldestPendingAgeMs: highRiskPendingQueue[0]?.ageMs ?? oldestPendingAge(visiblePendingApprovals, now),
        oldestPendingApproval: oldestPendingApproval(visiblePendingApprovals),
        pendingCount: visiblePendingApprovals.length,
        slaBreaches: visiblePendingApprovals.filter((approval) => now.getTime() - new Date(approval.createdAt).getTime() > approvalSlaMs)
          .length,
        slaTargetMs: approvalSlaMs,
      },
      controlCoverage: {
        coveragePercent: observedTools.length ? Math.round((coveredObservedTools / observedTools.length) * 100) : 100,
        coveredObservedTools,
        defaultOnlyObservedTools,
        explicitRuleCount: policySummary.rules.length,
        totalObservedTools: observedTools.length,
        unresolvedDetectorFindings: unresolvedPolicyGapTools.length,
      },
      auditIntegrity: {
        checked: auditVerification.checked,
        errorCount: auditVerification.errors.length,
        errorsByReason: countAuditErrorsByReason(auditVerification.errors),
        lastEventHash: auditVerification.lastEventHash,
        latestEventAt: latestEvent?.timestamp,
        latestEventType: latestEvent?.type,
        siemExportAvailable: true,
        valid: auditVerification.valid,
      },
      policy: {
        defaultApproval: policy.default.approval,
        hash: policyHash,
        lastUpdatedAt: latestPolicyUpdate?.timestamp,
        lastUpdatedBy: latestPolicyUpdate?.actor,
        redactionEnabled: true,
        redactionFieldsCount: options.redaction.fields?.length ?? 0,
        ruleCount: policySummary.rules.length,
        version: policy.version,
      } satisfies {
        defaultApproval: ApprovalMode;
        hash: string;
        lastUpdatedAt?: string;
        lastUpdatedBy?: string;
        redactionEnabled: boolean;
        redactionFieldsCount: number;
        ruleCount: number;
        version: number;
      },
      integrations: summarizeIntegrations(integrations, latestIntegrationFailure),
      highRiskQueue: highRiskPendingQueue.slice(0, 5),
      policyGaps: unresolvedPolicyGaps,
      recentSensitiveDecisions: recentSensitiveDecisions(visibleToolCalls, visibleAuditEvents).slice(0, 8),
    };
  });
}

function countAuditErrorsByReason(errors: Array<{ reason: string }>): Record<string, number> {
  return errors.reduce<Record<string, number>>((counts, error) => {
    counts[error.reason] = (counts[error.reason] ?? 0) + 1;
    return counts;
  }, {});
}

function windowMs(window: DashboardWindow): number {
  if (window === '7d') return 7 * 24 * 60 * 60 * 1000;
  if (window === '30d') return 30 * 24 * 60 * 60 * 1000;
  return 24 * 60 * 60 * 1000;
}

function visibleForWorkspace(workspaceId: string | undefined, authWorkspaceId: string, scopes: string[]): boolean {
  return !workspaceId || workspaceId === authWorkspaceId || scopes.includes('*');
}

function countBy<K extends string, T>(keys: K[], items: T[], getKey: (item: T) => K | undefined): Record<K, number> {
  const counts = Object.fromEntries(keys.map((key) => [key, 0])) as Record<K, number>;
  for (const item of items) {
    const key = getKey(item);
    if (key) counts[key] += 1;
  }
  return counts;
}

async function pendingApprovalDeliveries(store: Store, approvals: ApprovalRecord[]): Promise<ApprovalDeliveryRecord[]> {
  const deliveries = await Promise.all(approvals.map((approval) => store.listApprovalDeliveries(approval.id)));
  return deliveries.flat();
}

function highRiskQueue(approvals: ApprovalRecord[], toolCallById: Map<string, ToolCallRecord>, now: Date) {
  return approvals
    .map((approval) => {
      const toolCall = toolCallById.get(approval.toolCallId);
      const ageMs = now.getTime() - new Date(approval.createdAt).getTime();
      return {
        ageMs,
        approvalId: approval.id,
        createdAt: approval.createdAt,
        reason: toolCall?.reason,
        requestedBy: approval.requestedBy,
        risk: toolCall?.risk ?? 'unknown',
        toolCallId: approval.toolCallId,
        toolName: toolCall?.toolName ?? approval.toolCallId,
      };
    })
    .filter((item) => isHighRisk(item.risk))
    .sort((left, right) => riskRank(right.risk) - riskRank(left.risk) || right.ageMs - left.ageMs);
}

function oldestPendingAge(approvals: ApprovalRecord[], now: Date): number {
  return approvals.reduce((oldest, approval) => Math.max(oldest, now.getTime() - new Date(approval.createdAt).getTime()), 0);
}

function oldestPendingApproval(approvals: ApprovalRecord[]) {
  const approval = [...approvals].sort((left, right) => left.createdAt.localeCompare(right.createdAt))[0];
  return approval
    ? {
        approvalId: approval.id,
        createdAt: approval.createdAt,
        toolCallId: approval.toolCallId,
      }
    : undefined;
}

function recentSensitiveDecisions(toolCalls: ToolCallRecord[], auditEvents: AuditEvent[]) {
  const auditEventsByToolCall = auditEvents.reduce<Map<string, AuditEvent[]>>((groups, event) => {
    if (!event.toolCallId) return groups;
    groups.set(event.toolCallId, [...(groups.get(event.toolCallId) ?? []), event]);
    return groups;
  }, new Map());

  return toolCalls
    .filter(
      (toolCall) =>
        isHighRisk(toolCall.risk ?? 'unknown') ||
        toolCall.decision === 'deny' ||
        toolCall.status === 'blocked' ||
        toolCall.status === 'rejected' ||
        toolCall.status === 'failed',
    )
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
    .map((toolCall) => {
      const events = auditEventsByToolCall.get(toolCall.id) ?? [];
      const approvalEvent = events.find((event) =>
        ['approval.approved', 'approval.cancelled', 'approval.expired', 'approval.rejected'].includes(event.type),
      );
      const editedPayload = events.some((event) => {
        const editedInput = event.data.editedInput;
        return editedInput !== undefined && editedInput !== null;
      });
      return {
        actor: approvalEvent?.actor ?? toolCall.requestedBy,
        decision: toolCall.decision,
        editedPayload,
        policyVersionHash: toolCall.policyVersionHash,
        risk: toolCall.risk ?? 'unknown',
        status: toolCall.status,
        timestamp: toolCall.updatedAt,
        toolCallId: toolCall.id,
        toolName: toolCall.toolName,
      };
    });
}

function summarizeIntegrations(integrations: IntegrationStatusResponse, latestFailure: AuditEvent | undefined) {
  const approvalChannels = integrations.approvalChannels.items.map((channel) => ({
    displayName: channel.displayName,
    enabled: channel.enabled,
    id: channel.id,
    provider: channel.provider,
    status: channel.status,
  }));
  const localDemoTools = integrations.localDemoTools.map((tool) => ({
    displayName: tool.displayName,
    enabled: tool.enabled,
    id: tool.id,
    status: tool.status,
  }));
  const statuses = [...approvalChannels.map((channel) => channel.status), ...localDemoTools.map((tool) => tool.status)];
  const discoveredToolCount = integrations.downstreamToolSources.mcpWrapper.profiles.reduce(
    (count, profile) => count + profile.discoveredTools.length,
    0,
  );

  return {
    approvalChannels,
    downstreamToolSources: {
      discoveredToolCount,
      mcpProfileCount: integrations.downstreamToolSources.mcpWrapper.profiles.length,
    },
    lastFailure: latestFailure
      ? {
          actor: latestFailure.actor,
          at: latestFailure.timestamp,
          message: typeof latestFailure.data.error === 'string' ? latestFailure.data.error : latestFailure.type,
          type: latestFailure.type,
        }
      : undefined,
    localDemoTools,
    summary: {
      disabled: statuses.filter((status) => status === 'disabled').length,
      failing: latestFailure ? 1 : 0,
      partial: statuses.filter((status) => status === 'partial').length,
      ready: statuses.filter((status) => status === 'ready').length,
    } satisfies Record<IntegrationStatus | 'failing', number>,
  };
}

function isIntegrationFailureEvent(event: AuditEvent): boolean {
  return (
    event.type === 'approval_notification.failed' ||
    event.type === 'slack.approval_notification.failed' ||
    event.type === 'email.approval_notification.failed' ||
    event.type === 'telegram.approval_notification.failed' ||
    event.type === 'slack.interaction.failed' ||
    event.type === 'telegram.interaction.failed' ||
    event.type === 'integration.slack.test_failed' ||
    event.type === 'integration.telegram.test_failed' ||
    event.type === 'integration.email.test_failed'
  );
}

function isHighRisk(risk: string): boolean {
  return risk !== 'read_only';
}

function riskRank(risk: string): number {
  if (risk === 'destructive') return 5;
  if (risk === 'data_mutation') return 4;
  if (risk === 'external_communication') return 3;
  if (risk === 'unknown') return 2;
  return 1;
}

function hashJson(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}
