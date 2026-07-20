import { describe, expect, it, vi } from 'vitest';
import type { CanonicalActionIngress } from '../contracts/action-request';
import { createExecutionAuthorizationAuthority } from '../contracts/execution-authorization';
import type { AuditEvent } from '../models';
import type { PolicyFile } from '../policy/policy-types';
import type { AuditListFilters, AuditListLimit, AuditStore } from '../storage/audit-store';
import { MemoryStore } from '../storage/memory-store';
import { ActionProxyService } from './action-gate';
import { ToolRegistry } from './tool-registry';

describe('content-influence policy selection lifecycle', () => {
  it('treats authenticated external content according to each action allowFrom set', async () => {
    const policy: PolicyFile = {
      default: { approval: 'required', risk: 'unknown' },
      tools: {
        'partner.records.read': {
          approval: 'never',
          resultSource: { integrity: 'authenticated_external', sourceId: 'partner-records' },
          risk: 'authenticated_read',
        },
        'records.safe_update': {
          approval: 'never',
          influence: { allowFrom: ['none', 'authenticated_external'], otherwise: 'required' },
          resultSource: 'none',
          risk: 'low_risk_write',
        },
        'records.org_only_update': {
          approval: 'never',
          influence: { allowFrom: ['none', 'organization_managed'], otherwise: 'required' },
          resultSource: 'none',
          risk: 'low_risk_write',
        },
      },
      version: 1,
    };
    const safeUpdate = vi.fn(async () => ({ updated: true }));
    const orgOnlyUpdate = vi.fn(async () => ({ updated: true }));
    const { service, store, tools } = makeHarness(policy);
    tools.register('partner.records.read', async () => ({ records: [{ id: 'record_1' }] }));
    tools.register('records.safe_update', safeUpdate);
    tools.register('records.org_only_update', orgOnlyUpdate);
    const scopeId = influenceScope('a');

    const read = await submit(service, 'partner.records.read', scopeId);

    expect(read.toolCall).toMatchObject({
      resultSource: { integrity: 'authenticated_external', sourceId: 'partner-records' },
      resultWithheld: false,
      status: 'executed',
    });
    await expect(store.listContentExposures({ influenceScopeId: scopeId, limit: 10, workspaceId: 'default' }))
      .resolves.toMatchObject({
        records: [expect.objectContaining({
          integrity: 'authenticated_external',
          sourceId: 'partner-records',
          sourceToolCallId: read.toolCall.id,
        })],
        revision: 1,
      });

    const allowed = await submit(service, 'records.safe_update', scopeId);

    expect(allowed.toolCall).toMatchObject({
      contentInfluence: {
        effectiveDecision: 'allow',
        observedSources: ['authenticated_external'],
        selectedRule: { allowFrom: ['none', 'authenticated_external'], otherwise: 'required' },
      },
      decision: 'allow',
      status: 'executed',
    });
    expect(safeUpdate).toHaveBeenCalledTimes(1);

    const narrowed = await submit(service, 'records.org_only_update', scopeId);

    expect(narrowed.toolCall).toMatchObject({
      contentInfluence: {
        baseDecision: 'allow',
        effectiveDecision: 'require_approval',
        observedSources: ['authenticated_external'],
        selectedRule: { allowFrom: ['none', 'organization_managed'], otherwise: 'required' },
      },
      decision: 'require_approval',
      status: 'pending_approval',
    });
    expect(orgOnlyUpdate).not.toHaveBeenCalled();

    const approved = await service.approveApproval(narrowed.approval!.id, { approvedBy: 'reviewer@example.com' });

    expect(approved.toolCall).toMatchObject({ decision: 'require_approval', status: 'executed' });
    expect(orgOnlyUpdate).toHaveBeenCalledTimes(1);
  });

  it('freezes resultSource and influence from the selected wildcard rule before execution', async () => {
    const originalInfluence = {
      allowFrom: ['none', 'authenticated_external'] as const,
      otherwise: 'required' as const,
    };
    const policy: PolicyFile = {
      default: { approval: 'required', risk: 'unknown' },
      tools: {
        'partner.*': {
          approval: 'never',
          influence: { allowFrom: [...originalInfluence.allowFrom], otherwise: originalInfluence.otherwise },
          resultSource: { integrity: 'authenticated_external', sourceId: 'selected-wildcard' },
          risk: 'authenticated_read',
        },
      },
      version: 1,
    };
    const { service, store, tools } = makeHarness(policy);
    const scopeId = influenceScope('b');
    await store.recordContentExposure({
      influenceScopeId: scopeId,
      integrity: 'authenticated_external',
      observedAt: '2026-07-15T00:00:00.000Z',
      policyVersionHash: 'prior-policy',
      sourceId: 'prior-partner-result',
      sourceToolCallId: 'toolcall_prior_partner_result',
      workspaceId: 'default',
    });
    tools.register('partner.lookup', async () => {
      policy.tools['partner.*'] = {
        approval: 'never',
        influence: { allowFrom: ['none'], otherwise: 'deny' },
        resultSource: { integrity: 'public_untrusted', sourceId: 'mutated-after-dispatch' },
        risk: 'mutated',
      };
      return { value: 'partner result' };
    });

    const result = await submit(service, 'partner.lookup', scopeId);

    expect(result.toolCall).toMatchObject({
      contentInfluence: {
        effectiveDecision: 'allow',
        observedSources: ['authenticated_external'],
        selectedRule: { allowFrom: [...originalInfluence.allowFrom], otherwise: originalInfluence.otherwise },
      },
      decisionTrace: { matchedRule: 'partner.*', matchType: 'wildcard' },
      resultSource: { integrity: 'authenticated_external', sourceId: 'selected-wildcard' },
      resultWithheld: false,
      status: 'executed',
    });
    const exposures = await store.listContentExposures({ influenceScopeId: scopeId, limit: 10, workspaceId: 'default' });
    expect(exposures.records).toEqual(expect.arrayContaining([
      expect.objectContaining({
        integrity: 'authenticated_external',
        sourceId: 'selected-wildcard',
        sourceToolCallId: result.toolCall.id,
      }),
    ]));
    expect(exposures.records).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ sourceId: 'mutated-after-dispatch' }),
    ]));
  });

  it('freezes resultSource and influence from the selected default rule before execution', async () => {
    const originalInfluence = {
      allowFrom: ['none', 'verified_publisher'] as const,
      otherwise: 'deny' as const,
    };
    const policy: PolicyFile = {
      default: {
        approval: 'never',
        influence: { allowFrom: [...originalInfluence.allowFrom], otherwise: originalInfluence.otherwise },
        resultSource: { integrity: 'verified_publisher', sourceId: 'selected-default' },
        risk: 'known_public_read',
      },
      tools: {},
      version: 1,
    };
    const { service, store, tools } = makeHarness(policy);
    const scopeId = influenceScope('c');
    await store.recordContentExposure({
      influenceScopeId: scopeId,
      integrity: 'verified_publisher',
      observedAt: '2026-07-15T00:00:00.000Z',
      policyVersionHash: 'prior-policy',
      sourceId: 'prior-official-docs',
      sourceToolCallId: 'toolcall_prior_official_docs',
      workspaceId: 'default',
    });
    tools.register('unlisted.official_lookup', async () => {
      policy.default = {
        approval: 'never',
        influence: { allowFrom: ['none'], otherwise: 'required' },
        resultSource: { integrity: 'public_untrusted', sourceId: 'mutated-default-after-dispatch' },
        risk: 'mutated',
      };
      return { value: 'official result' };
    });

    const result = await submit(service, 'unlisted.official_lookup', scopeId);

    expect(result.toolCall).toMatchObject({
      contentInfluence: {
        effectiveDecision: 'allow',
        observedSources: ['verified_publisher'],
        selectedRule: { allowFrom: [...originalInfluence.allowFrom], otherwise: originalInfluence.otherwise },
      },
      decisionTrace: { matchedRule: 'default', matchType: 'default' },
      resultSource: { integrity: 'verified_publisher', sourceId: 'selected-default' },
      resultWithheld: false,
      status: 'executed',
    });
    const exposures = await store.listContentExposures({ influenceScopeId: scopeId, limit: 10, workspaceId: 'default' });
    expect(exposures.records).toEqual(expect.arrayContaining([
      expect.objectContaining({
        integrity: 'verified_publisher',
        sourceId: 'selected-default',
        sourceToolCallId: result.toolCall.id,
      }),
    ]));
    expect(exposures.records).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ sourceId: 'mutated-default-after-dispatch' }),
    ]));
  });
});

function makeHarness(policy: PolicyFile) {
  const executionAuthorizations = createExecutionAuthorizationAuthority();
  const tools = new ToolRegistry(executionAuthorizations);
  const store = new MemoryStore();
  const auditStore = new CapturingAuditStore();
  const service = new ActionProxyService({
    auditStore,
    executionAuthorizations,
    policy,
    store,
    tools,
  });
  return { auditStore, service, store, tools };
}

function submit(service: ActionProxyService, toolName: string, scopeId: string) {
  return service.submitToolCall({
    action: {
      executionMode: 'local_mock',
      operation: { name: toolName },
      protocol: 'mcp',
      resources: [{ name: toolName, type: 'mcp.tool' }],
      source: { id: 'mcp-stdio:test-adapter', type: 'mcp' },
    },
    agentId: 'mcp:test-adapter',
    input: {},
    reason: `Exercise ${toolName}`,
    requestedBy: 'test-adapter',
    toolName,
  }, { ingress: verifiedInfluenceIngress(scopeId) });
}

function verifiedInfluenceIngress(scopeId: string): CanonicalActionIngress {
  return {
    adapterId: 'mcp-stdio:test-adapter',
    adapterSource: 'test.authenticated-adapter',
    adapterTrust: 'derived',
    agent: { id: 'mcp:test-adapter', source: 'test.authenticated-adapter', trust: 'derived' },
    environment: 'local',
    idempotency: { source: 'test.idempotency', trust: 'derived' },
    protocol: 'mcp',
    session: {
      sessionId: scopeId,
      source: 'actionproxy.verified-mcp-influence-scope',
      trust: 'derived',
    },
    source: 'mcp',
  };
}

function influenceScope(character: string): string {
  return `influence_${character.repeat(64)}`;
}

class CapturingAuditStore implements AuditStore {
  readonly events: AuditEvent[] = [];

  async append(event: AuditEvent): Promise<void> {
    if (this.events.some((existing) => existing.id === event.id)) return;
    this.events.push(event);
  }

  async list(_limit?: AuditListLimit, _filters?: AuditListFilters): Promise<AuditEvent[]> {
    return [...this.events].reverse();
  }
}
