import { createHash, randomUUID } from 'node:crypto';
import { ConflictError, NotFoundError } from '../errors';
import type {
  AuthContext,
  AuditEvent,
  JsonObject,
  ObservedToolCoverage,
  ObservedToolRecord,
  ObservedToolSource,
  ObservedToolSuggestion,
} from '../models';
import { evaluatePolicy } from '../policy/evaluate-policy';
import type { ApprovalMode, PolicyFile, PolicyRule } from '../policy/policy-types';
import type { AuditStore } from '../storage/audit-store';
import type { Store } from '../storage/store';

export interface ObserveToolInput {
  agentId?: string;
  auth?: AuthContext;
  input?: JsonObject;
  mcpProfileId?: string;
  mcpServerName?: string;
  policy: PolicyFile;
  schemaHash?: string;
  source: ObservedToolSource;
  toolName: string;
  workspaceId: string;
}

export interface ApplyDetectorPolicyInput {
  approval?: ApprovalMode;
  pattern?: string;
  reason?: string;
  risk?: string;
}

export interface PolicyDetectorList {
  tools: ObservedToolRecord[];
  unresolvedCount: number;
}

export class PolicyDetectorService {
  constructor(
    private readonly store: Store,
    private readonly auditStore: AuditStore,
  ) {}

  async observeTool(input: ObserveToolInput): Promise<ObservedToolRecord> {
    const now = new Date().toISOString();
    const existing = await this.store.getObservedToolByName(input.workspaceId, input.toolName);
    const schemaHash = input.schemaHash ?? (input.input ? schemaHashForJsonShape(input.input) : undefined);
    const coverage = coverageForPolicy(input.policy, input.toolName);
    const baseSuggestion = suggestionForToolName(input.toolName);
    const schemaChanged = Boolean(existing?.schemaHash && schemaHash && existing.schemaHash !== schemaHash);
    const schemaChange = schemaChanged && existing?.schemaHash && schemaHash
      ? {
          currentSchemaHash: schemaHash,
          previousSchemaHash: existing.schemaHash,
          reviewState: 'needs_review' as const,
        }
      : existing?.schemaChange;
    const status =
      schemaChanged || schemaChange?.reviewState === 'needs_review'
        ? 'unresolved'
        : coverage.status === 'covered'
          ? 'resolved'
          : existing?.status === 'dismissed'
            ? 'dismissed'
            : 'unresolved';

    const record: ObservedToolRecord = {
      id: existing?.id ?? observedToolId(input.workspaceId, input.toolName),
      workspaceId: input.workspaceId,
      toolName: input.toolName,
      sources: mergeStrings(existing?.sources ?? [], [input.source]) as ObservedToolRecord['sources'],
      sourceIds: {
        agentIds: mergeOptional(existing?.sourceIds.agentIds, input.agentId),
        mcpProfileIds: mergeOptional(existing?.sourceIds.mcpProfileIds, input.mcpProfileId),
        mcpServerNames: mergeOptional(existing?.sourceIds.mcpServerNames, input.mcpServerName),
      },
      firstSeenAt: existing?.firstSeenAt ?? now,
      lastSeenAt: now,
      callCount: (existing?.callCount ?? 0) + (input.source === 'runtime' || input.source === 'local_demo' ? 1 : 0),
      schemaChange,
      schemaHash: schemaHash ?? existing?.schemaHash,
      coverage,
      status,
      suggestion: baseSuggestion,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };

    await this.store.upsertObservedTool(record);

    if (!existing) {
      await this.audit('policy_detector.tool_observed', {
        auth: input.auth,
        data: {
          coverage,
          schemaHash: record.schemaHash ?? null,
          source: input.source,
          suggestion: baseSuggestion,
          toolName: input.toolName,
        },
        workspaceId: input.workspaceId,
      });
    } else if (schemaChanged) {
      await this.audit('policy_detector.schema_changed', {
        auth: input.auth,
        data: {
          newSchemaHash: schemaHash,
          previousSchemaHash: existing.schemaHash,
          toolName: input.toolName,
        },
        workspaceId: input.workspaceId,
      });
    }

    return record;
  }

  async list(workspaceId: string, policy: PolicyFile): Promise<PolicyDetectorList> {
    const records = await this.store.listObservedTools(workspaceId);
    const enriched = withWildcardSuggestions(records.map((record) => refreshRecordView(record, policy)), policy);
    return {
      tools: enriched,
      unresolvedCount: enriched.filter((record) => record.status === 'unresolved').length,
    };
  }

  async get(id: string, workspaceId: string, policy: PolicyFile): Promise<ObservedToolRecord> {
    const record = await this.store.getObservedTool(id);
    if (!record || record.workspaceId !== workspaceId) throw new NotFoundError(`Observed tool not found: ${id}`);
    const records = await this.store.listObservedTools(workspaceId);
    const [enriched] = withWildcardSuggestions([refreshRecordView(record, policy)], policy, records);
    if (!enriched) throw new NotFoundError(`Observed tool not found: ${id}`);
    return enriched;
  }

  async dismiss(id: string, auth: AuthContext, policy: PolicyFile): Promise<ObservedToolRecord> {
    const record = await this.get(id, auth.workspaceId, policy);
    const updated: ObservedToolRecord = {
      ...record,
      schemaChange: reviewedSchemaChange(record.schemaChange),
      status: 'dismissed',
      updatedAt: new Date().toISOString(),
    };
    await this.store.upsertObservedTool(updated);
    await this.audit('policy_detector.dismissed', {
      auth,
      data: {
        toolName: updated.toolName,
      },
      workspaceId: auth.workspaceId,
    });
    return updated;
  }

  async refreshPolicyCoverage(policy: PolicyFile, workspaceId: string): Promise<void> {
    const records = await this.store.listObservedTools(workspaceId);
    for (const record of records) {
      await this.store.upsertObservedTool(refreshRecordView(record, policy, { resolveCovered: true }));
    }
  }

  buildRule(record: ObservedToolRecord, input: ApplyDetectorPolicyInput = {}, policy: PolicyFile): { pattern: string; rule: PolicyRule } {
    const suggestion = record.suggestion;
    const pattern = input.pattern?.trim() || suggestion.pattern;
    if (policy.tools[pattern]) {
      throw new ConflictError(`Policy rule already exists for ${pattern}.`);
    }
    return {
      pattern,
      rule: {
        approval: input.approval ?? suggestion.approval,
        reason: input.reason?.trim() || suggestion.reason,
        ...(suggestion.resultSource ? { resultSource: suggestion.resultSource } : {}),
        risk: input.risk?.trim() || suggestion.risk,
      },
    };
  }

  async auditPolicyApply(auth: AuthContext, record: ObservedToolRecord, pattern: string, rule: PolicyRule): Promise<void> {
    await this.audit('policy.updated', {
      auth,
      data: {
        addedRules: [pattern],
        detectorToolId: record.id,
        detectorToolName: record.toolName,
        rule,
        source: 'policy_detector',
      },
      workspaceId: auth.workspaceId,
    });
  }

  private async audit(
    type: Extract<
      AuditEvent['type'],
      'policy.updated' | 'policy_detector.dismissed' | 'policy_detector.schema_changed' | 'policy_detector.tool_observed'
    >,
    payload: { auth?: AuthContext; data: JsonObject; workspaceId: string },
  ): Promise<void> {
    await this.auditStore.append({
      actor: payload.auth?.email ?? payload.auth?.principalId ?? 'system',
      auth: payload.auth,
      data: payload.data,
      id: `audit_${randomUUID()}`,
      timestamp: new Date().toISOString(),
      type,
      workspaceId: payload.workspaceId,
    });
  }
}

export function coverageForPolicy(policy: PolicyFile, toolName: string): ObservedToolCoverage {
  const evaluation = evaluatePolicy(policy, toolName);
  const matchType = evaluation.matchedRule === 'default' ? 'default' : evaluation.matchedRule.endsWith('.*') ? 'wildcard' : 'exact';
  return {
    approval: evaluation.approval,
    decision: evaluation.decision,
    matchedRule: evaluation.matchedRule,
    matchType,
    reason: evaluation.reason,
    risk: evaluation.risk,
    status: evaluation.matchedRule === 'default' ? 'uncovered' : 'covered',
  };
}

export function suggestionForToolName(toolName: string): ObservedToolSuggestion {
  const tokens = tokenizeToolName(toolName);
  const exact = {
    pattern: toolName,
    patternType: 'exact' as const,
  };

  if (tokens.some((token) => ['credential', 'credentials', 'secret', 'secrets', 'token', 'tokens'].includes(token))) {
    return {
      ...exact,
      approval: 'deny',
      confidence: 'high',
      reason: 'Credential-sensitive tools should be blocked until reviewed explicitly.',
      risk: 'credential_sensitive',
    };
  }

  if (tokens.some((token) => ['delete', 'destroy', 'drop', 'purge', 'remove'].includes(token))) {
    return {
      ...exact,
      approval: 'deny',
      confidence: 'high',
      reason: 'Destructive tools should be denied by default.',
      risk: 'destructive',
    };
  }

  if (tokens.some((token) => ['email', 'message', 'post', 'send'].includes(token))) {
    return {
      ...exact,
      approval: 'required',
      confidence: 'high',
      reason: 'External communication should require human approval.',
      risk: 'external_communication',
    };
  }

  if (tokens.some((token) => ['create', 'modify', 'update', 'write'].includes(token))) {
    return {
      ...exact,
      approval: 'required',
      confidence: 'medium',
      reason: 'Data-changing tools should require human approval.',
      risk: 'data_change',
    };
  }

  if (tokens.some((token) => ['browse', 'browser', 'fetch', 'http', 'url', 'web'].includes(token))) {
    return {
      ...exact,
      approval: 'required',
      confidence: 'medium',
      reason: 'Open-world reads can return untrusted content and should require review until their source handling is configured.',
      resultSource: { integrity: 'public_untrusted' },
      risk: 'open_world_read',
    };
  }

  if (tokens.some((token) => ['get', 'list', 'lookup', 'query', 'read', 'search'].includes(token))) {
    return {
      ...exact,
      approval: 'required',
      confidence: 'medium',
      reason: 'Read-like tools should require review until their source integrity is classified.',
      resultSource: { integrity: 'unknown' },
      risk: 'unreviewed_read',
    };
  }

  return {
    ...exact,
    approval: 'required',
    confidence: 'low',
    reason: 'Unknown tool behavior should require approval until reviewed.',
    resultSource: { integrity: 'unknown' },
    risk: 'unknown',
  };
}

export function schemaHashForJsonShape(input: JsonObject): string {
  return stableHash(shapeOf(input));
}

export function schemaHashForSchema(schema: Record<string, unknown>): string {
  return stableHash(schema);
}

function refreshRecordView(
  record: ObservedToolRecord,
  policy: PolicyFile,
  options: { resolveCovered?: boolean } = {},
): ObservedToolRecord {
  const coverage = coverageForPolicy(policy, record.toolName);
  const schemaChange = options.resolveCovered && coverage.status === 'covered'
    ? reviewedSchemaChange(record.schemaChange)
    : record.schemaChange;
  const schemaReviewNeeded = record.status !== 'dismissed' && schemaChange?.reviewState === 'needs_review';
  return {
    ...record,
    coverage,
    schemaChange,
    status: schemaReviewNeeded
      ? 'unresolved'
      : options.resolveCovered && coverage.status === 'covered'
        ? 'resolved'
        : record.status,
    suggestion: suggestionForToolName(record.toolName),
  };
}

function reviewedSchemaChange(schemaChange: ObservedToolRecord['schemaChange']): ObservedToolRecord['schemaChange'] {
  return schemaChange ? { ...schemaChange, reviewState: 'reviewed' } : undefined;
}

function withWildcardSuggestions(records: ObservedToolRecord[], policy: PolicyFile, allRecords = records): ObservedToolRecord[] {
  const candidates = allRecords
    .map((record) => refreshRecordView(record, policy))
    .filter((record) => record.status === 'unresolved' && record.coverage.status === 'uncovered');

  return records.map((record) => {
    const prefix = providerPrefix(record.toolName);
    if (!prefix || record.status !== 'unresolved' || record.coverage.status !== 'uncovered') return record;
    const base = suggestionForToolName(record.toolName);
    const group = candidates.filter((candidate) => {
      const candidateSuggestion = suggestionForToolName(candidate.toolName);
      return (
        providerPrefix(candidate.toolName) === prefix &&
        candidateSuggestion.approval === base.approval &&
        candidateSuggestion.risk === base.risk
      );
    });
    const hasConflictingExplicitRule = Object.entries(policy.tools).some(
      ([pattern, rule]) => pattern.startsWith(`${prefix}.`) && (pattern !== `${prefix}.*` || rule.approval !== base.approval),
    );
    if (group.length < 3 || hasConflictingExplicitRule) return record;

    return {
      ...record,
      suggestion: {
        ...base,
        confidence: base.confidence === 'low' ? 'medium' : base.confidence,
        pattern: `${prefix}.*`,
        patternType: 'wildcard',
        reason: `Three or more uncovered ${prefix} tools share the same recommendation.`,
      },
    };
  });
}

function providerPrefix(toolName: string): string | undefined {
  const [prefix, rest] = toolName.split('.', 2);
  return prefix && rest ? prefix : undefined;
}

function observedToolId(workspaceId: string, toolName: string): string {
  return `observed_${createHash('sha256').update(`${workspaceId}:${toolName}`).digest('hex').slice(0, 16)}`;
}

function tokenizeToolName(toolName: string): string[] {
  return toolName
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function mergeOptional(values: string[] | undefined, value: string | undefined): string[] | undefined {
  const merged = mergeStrings(values ?? [], value ? [value] : []);
  return merged.length ? merged : undefined;
}

function mergeStrings(left: string[], right: string[]): string[] {
  return [...new Set([...left, ...right].filter(Boolean))].sort();
}

function shapeOf(value: unknown): unknown {
  if (Array.isArray(value)) return value.length ? [shapeOf(value[0])] : [];
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, shapeOf(nested)]),
    );
  }
  return typeof value;
}

function stableHash(value: unknown): string {
  return createHash('sha256').update(stableStringify(value)).digest('hex').slice(0, 16);
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableStringify(nested)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}
