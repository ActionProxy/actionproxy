import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AuditEvent, ToolCallRecord } from '../models';
import type { AuditStore } from './audit-store';
import { JsonlAuditStore } from './jsonl-audit-store';
import { MemoryStore } from './memory-store';
import { PostgresStore } from './postgres-store';
import { SqliteStore } from './sqlite-store';
import type { ContentExposureRecord, Store } from './store';

interface ForensicStoreHarness {
  auditStore: AuditStore;
  stores: Store[];
}

const localHarnesses: Array<{ make: () => ForensicStoreHarness; name: string }> = [
  {
    make: () => ({
      auditStore: new JsonlAuditStore(tempDir('actionproxy-forensic-jsonl-')),
      stores: [new MemoryStore()],
    }),
    name: 'memory/JSONL',
  },
  ...(hasSqliteCli()
    ? [
        {
          make: () => {
            const databasePath = path.join(tempDir('actionproxy-forensic-sqlite-'), 'actionproxy.sqlite');
            const stores = [new SqliteStore(databasePath), new SqliteStore(databasePath)];
            return { auditStore: stores[0]!, stores };
          },
          name: 'SQLite',
        },
      ]
    : []),
];

describe.each(localHarnesses)('$name forensic-query storage conformance', ({ make }) => {
  it('records minimized content exposure once and reports bounded lookup overflow', async () => {
    await exerciseContentExposureContract(make().stores);
  });

  it('atomically advances one revision per concurrently inserted distinct exposure', async () => {
    await exerciseConcurrentDistinctExposureContract(make().stores);
  });

  it('persists server-owned content-governance state across store instances', async () => {
    await exerciseContentGovernancePersistence(make().stores);
  });

  it('applies workspace, session, and run filters before the tool-call limit', async () => {
    await exerciseToolCallFilterContract(make().stores[0]!);
  });

  it('applies workspace and tool-call filters before the audit limit', async () => {
    await exerciseAuditFilterContract(make().auditStore);
  });
});

const databaseUrl = process.env.ACTIONPROXY_TEST_POSTGRES_URL;
const describeIfPostgres = databaseUrl ? describe : describe.skip;

describeIfPostgres('Postgres forensic-query storage conformance', () => {
  const stores: PostgresStore[] = [];

  beforeAll(async () => {
    stores.push(await PostgresStore.connect(databaseUrl!), await PostgresStore.connect(databaseUrl!));
  });

  afterAll(async () => {
    await Promise.all(stores.map((store) => store.close()));
  });

  it('records minimized content exposure once and reports bounded lookup overflow', async () => {
    await exerciseContentExposureContract(stores);
  });

  it('atomically advances one revision per concurrently inserted distinct exposure', async () => {
    await exerciseConcurrentDistinctExposureContract(stores);
  });

  it('persists server-owned content-governance state across store instances', async () => {
    await exerciseContentGovernancePersistence(stores);
  });

  it('applies workspace, session, and run filters before the tool-call limit', async () => {
    await exerciseToolCallFilterContract(stores[0]!);
  });

  it('applies workspace and tool-call filters before the audit limit', async () => {
    await exerciseAuditFilterContract(stores[0]!);
  });
});

async function exerciseContentExposureContract(stores: Store[]): Promise<void> {
  const suffix = randomUUID();
  const workspaceId = `workspace_${suffix}`;
  const influenceScopeId = `scope_${suffix}`;
  const first = exposure({
    influenceScopeId,
    observedAt: '2026-07-15T10:00:00.000Z',
    sourceId: 'knowledge-base:refunds',
    sourceToolCallId: `toolcall_source_first_${suffix}`,
    workspaceId,
  });
  const minimizedCanaries = {
    modelOutput: 'model-output-must-not-be-stored',
    prompt: 'prompt-must-not-be-stored',
    queryString: 'query-string-must-not-be-stored',
    rawContent: 'raw-content-must-not-be-stored',
    rawUrl: 'https://evil.example/secret?token=must-not-be-stored',
    sessionNonce: 'session-nonce-must-not-be-stored',
  };
  const minimizedInput = { ...first, ...minimizedCanaries } as ContentExposureRecord;
  const results = await Promise.all(
    Array.from({ length: 12 }, (_, index) => stores[index % stores.length]!.recordContentExposure(minimizedInput)),
  );

  expect(results.filter((result) => result === 'created')).toHaveLength(1);
  expect(results.filter((result) => result === 'replay')).toHaveLength(11);
  await expect(stores[0]!.recordContentExposure({ ...first, observedAt: '2026-07-15T10:00:30.000Z' }))
    .resolves.toBe('replay');
  await expect(
    stores[0]!.recordContentExposure({
      ...first,
      integrity: 'organization_managed',
      policyVersionHash: 'mutated-policy-hash',
    }),
  ).resolves.toBe('conflict');

  await stores[0]!.recordContentExposure(
    exposure({
      influenceScopeId,
      integrity: 'authenticated_external',
      observedAt: '2026-07-15T10:01:00.000Z',
      sourceToolCallId: `toolcall_source_second_${suffix}`,
      workspaceId,
    }),
  );
  await stores[0]!.recordContentExposure(
    exposure({
      influenceScopeId,
      integrity: 'unknown',
      observedAt: '2026-07-15T10:02:00.000Z',
      sourceToolCallId: `toolcall_source_third_${suffix}`,
      workspaceId,
    }),
  );
  await stores[0]!.recordContentExposure(
    exposure({
      influenceScopeId: `other_scope_${suffix}`,
      observedAt: '2026-07-15T10:03:00.000Z',
      sourceToolCallId: `toolcall_other_scope_${suffix}`,
      workspaceId,
    }),
  );
  await stores[0]!.recordContentExposure(
    exposure({
      influenceScopeId,
      observedAt: '2026-07-15T10:04:00.000Z',
      sourceToolCallId: `toolcall_other_workspace_${suffix}`,
      workspaceId: `other_workspace_${suffix}`,
    }),
  );

  const listed = await stores[stores.length - 1]!.listContentExposures({ influenceScopeId, limit: 2, workspaceId });
  expect(listed).toMatchObject({
    overflow: true,
    revision: 3,
    records: [
      { integrity: 'public_untrusted', sourceToolCallId: first.sourceToolCallId },
      { integrity: 'authenticated_external', sourceToolCallId: `toolcall_source_second_${suffix}` },
    ],
  });
  expect(listed.records[0]).not.toHaveProperty('rawContent');
  expect(listed.records[0]).not.toHaveProperty('content');
  for (const canary of Object.values(minimizedCanaries)) {
    expect(JSON.stringify(listed.records)).not.toContain(canary);
  }
  expect(Object.keys(listed.records[0]!).sort()).toEqual(
    [
      'influenceScopeId',
      'integrity',
      'observedAt',
      'policyVersionHash',
      'sourceId',
      'sourceToolCallId',
      'workspaceId',
    ].sort(),
  );
}

async function exerciseConcurrentDistinctExposureContract(stores: Store[]): Promise<void> {
  const suffix = randomUUID();
  const workspaceId = `workspace_distinct_${suffix}`;
  const influenceScopeId = `scope_distinct_${suffix}`;
  const records = Array.from({ length: 24 }, (_, index) => exposure({
    influenceScopeId,
    observedAt: `2026-07-15T11:00:${String(index).padStart(2, '0')}.000Z`,
    sourceToolCallId: `toolcall_distinct_${String(index).padStart(2, '0')}_${suffix}`,
    workspaceId,
  }));

  const inserted = await Promise.all(records.map((record, index) =>
    stores[index % stores.length]!.recordContentExposure(record)));
  expect(inserted).toEqual(Array.from({ length: records.length }, () => 'created'));

  const afterInsert = await stores[stores.length - 1]!.listContentExposures({
    influenceScopeId,
    limit: 100,
    workspaceId,
  });
  expect(afterInsert).toMatchObject({ overflow: false, revision: records.length });
  expect(afterInsert.records).toHaveLength(records.length);
  expect(new Set(afterInsert.records.map((record) => record.sourceToolCallId)).size).toBe(records.length);

  const replayed = await Promise.all(records.map((record, index) =>
    stores[(index + 1) % stores.length]!.recordContentExposure(record)));
  expect(replayed).toEqual(Array.from({ length: records.length }, () => 'replay'));
  await expect(stores[0]!.listContentExposures({ influenceScopeId, limit: 100, workspaceId }))
    .resolves.toMatchObject({ overflow: false, revision: records.length });
}

it('bounds a large same-scope memory lookup while retaining the monotonic revision', async () => {
  const store = new MemoryStore();
  const influenceScopeId = `influence_${'f'.repeat(64)}`;
  for (let index = 0; index < 1_200; index += 1) {
    await store.recordContentExposure(exposure({
      influenceScopeId,
      observedAt: '2026-07-15T10:00:00.000Z',
      sourceToolCallId: `toolcall_${String(index).padStart(4, '0')}`,
      workspaceId: 'bounded-memory',
    }));
  }

  await expect(store.listContentExposures({
    influenceScopeId,
    limit: 256,
    workspaceId: 'bounded-memory',
  })).resolves.toMatchObject({ overflow: true, records: expect.any(Array), revision: 1_200 });
  expect((await store.listContentExposures({
    influenceScopeId,
    limit: 256,
    workspaceId: 'bounded-memory',
  })).records).toHaveLength(256);
});

async function exerciseContentGovernancePersistence(stores: Store[]): Promise<void> {
  const suffix = randomUUID();
  const record = toolCall({
    authorizationDecision: 'require_approval',
    authorizationReason: 'Content influence requires approval.',
    contentInfluence: {
      baseDecision: 'allow',
      bindingHash: 'a'.repeat(64),
      effectiveDecision: 'require_approval',
      evaluatedAt: '2026-07-15T10:00:00.000Z',
      exposureRevision: 1,
      exposureSnapshotHash: 'b'.repeat(64),
      influenceScope: { id: `influence_${'c'.repeat(64)}`, verified: true },
      observedSources: ['public_untrusted'],
      policy: { versionHash: 'policy_hash_v1', versionId: 'policy_version_v1' },
      selectedRule: { allowFrom: ['none', 'organization_managed'], otherwise: 'required' },
      sourceCount: 1,
      sourceCountIsLowerBound: false,
      sourceReferences: [{
        integrity: 'public_untrusted',
        sourceId: 'public-web',
        sourceToolCallId: `toolcall_source_${suffix}`,
      }],
      version: 'actionproxy.content-influence.v1',
    },
    decision: 'require_approval',
    id: `toolcall_governance_${suffix}`,
    influenceScopeId: `influence_${'c'.repeat(64)}`,
    resultDelivery: {
      byteCount: 42,
      canonicalResultHash: 'd'.repeat(64),
      modelVisible: true,
      version: 'actionproxy.result-delivery.v1',
    },
    resultSource: { integrity: 'public_untrusted', sourceId: 'public-web' },
    resultWithheld: false,
    workspaceId: `workspace_${suffix}`,
  });

  await stores[0]!.createToolCall(record);
  const reloaded = await stores[stores.length - 1]!.getToolCall(record.id);
  expect(reloaded).toMatchObject({
    authorizationDecision: record.authorizationDecision,
    authorizationReason: record.authorizationReason,
    contentInfluence: record.contentInfluence,
    influenceScopeId: record.influenceScopeId,
    resultDelivery: record.resultDelivery,
    resultSource: record.resultSource,
    resultWithheld: false,
  });

  await stores[stores.length - 1]!.updateToolCall({ ...reloaded!, resultWithheld: true });
  await expect(stores[0]!.getToolCall(record.id)).resolves.toMatchObject({ resultWithheld: true });
}

async function exerciseToolCallFilterContract(store: Store): Promise<void> {
  const suffix = randomUUID();
  const workspaceId = `workspace_${suffix}`;
  const sessionId = `session_${suffix}`;
  const runId = `run_${suffix}`;
  const forgedSessionId = `forged_session_${suffix}`;
  const forgedRunId = `forged_run_${suffix}`;
  const target = toolCall({
    createdAt: '2026-07-15T10:00:00.000Z',
    decisionTrace: canonicalSessionEvidence(runId, sessionId),
    id: `toolcall_target_${suffix}`,
    metadata: { runId: forgedRunId, sessionId: forgedSessionId },
    workspaceId,
  });
  const legacySessionId = `legacy_session_${suffix}`;
  const legacyRunId = `legacy_run_${suffix}`;
  const legacyTarget = toolCall({
    createdAt: '2026-07-15T09:59:00.000Z',
    id: `toolcall_legacy_target_${suffix}`,
    metadata: { runId: legacyRunId, sessionId: legacySessionId },
    workspaceId,
  });
  const partialSessionId = `partial_session_${suffix}`;
  const partialRunId = `partial_run_${suffix}`;
  const partialCanonicalTarget = toolCall({
    createdAt: '2026-07-15T09:58:00.000Z',
    decisionTrace: canonicalSessionEvidence(undefined, partialSessionId),
    id: `toolcall_partial_canonical_target_${suffix}`,
    metadata: { runId: partialRunId, sessionId: forgedSessionId },
    workspaceId,
  });
  const malformedCanonicalSessionId = `malformed_session_${suffix}`;
  const malformedCanonicalRunId = `malformed_run_${suffix}`;
  const malformedCanonicalTarget = toolCall({
    createdAt: '2026-07-15T09:57:00.000Z',
    decisionTrace: {
      canonicalRequestEvidence: {
        session: {
          present: true,
          provenance: { source: 'malformed-test-session', trust: 'asserted' },
          value: { runId: 42, sessionId: null },
        },
        version: 'actionproxy.action-request.v1',
      },
    } as unknown as ToolCallRecord['decisionTrace'],
    id: `toolcall_malformed_canonical_target_${suffix}`,
    metadata: { runId: malformedCanonicalRunId, sessionId: malformedCanonicalSessionId },
    workspaceId,
  });
  const distractors = [
    toolCall({
      createdAt: '2026-07-15T10:03:00.000Z',
      decisionTrace: canonicalSessionEvidence(runId, sessionId),
      id: `toolcall_wrong_workspace_${suffix}`,
      metadata: { runId, sessionId },
      workspaceId: `other_workspace_${suffix}`,
    }),
    toolCall({
      createdAt: '2026-07-15T10:02:00.000Z',
      decisionTrace: canonicalSessionEvidence(runId, `other_session_${suffix}`),
      id: `toolcall_wrong_session_${suffix}`,
      metadata: { runId, sessionId },
      workspaceId,
    }),
    toolCall({
      createdAt: '2026-07-15T10:01:00.000Z',
      decisionTrace: canonicalSessionEvidence(`other_run_${suffix}`, sessionId),
      id: `toolcall_wrong_run_${suffix}`,
      metadata: { runId, sessionId },
      workspaceId,
    }),
  ];
  await store.createToolCall(target);
  await store.createToolCall(legacyTarget);
  await store.createToolCall(partialCanonicalTarget);
  await store.createToolCall(malformedCanonicalTarget);
  for (const distractor of distractors) await store.createToolCall(distractor);

  await expect(store.listToolCalls({ limit: 1, runId, sessionId, workspaceId })).resolves.toMatchObject([
    { id: target.id },
  ]);
  await expect(
    store.listToolCalls({ runId: forgedRunId, sessionId: forgedSessionId, workspaceId }),
  ).resolves.toEqual([]);
  await expect(
    store.listToolCalls({ limit: 1, runId: legacyRunId, sessionId: legacySessionId, workspaceId }),
  ).resolves.toMatchObject([{ id: legacyTarget.id }]);
  await expect(
    store.listToolCalls({ limit: 1, runId: partialRunId, sessionId: partialSessionId, workspaceId }),
  ).resolves.toMatchObject([{ id: partialCanonicalTarget.id }]);
  await expect(
    store.listToolCalls({ sessionId: malformedCanonicalSessionId, workspaceId }),
  ).resolves.toEqual([]);
  await expect(
    store.listToolCalls({ runId: malformedCanonicalRunId, workspaceId }),
  ).resolves.toEqual([]);
}

function canonicalSessionEvidence(
  runId: string | undefined,
  sessionId: string | undefined,
): ToolCallRecord['decisionTrace'] {
  return {
    canonicalRequestEvidence: {
      session: {
        present: true,
        provenance: { source: 'verified-test-session', trust: 'derived' },
        value: {
          ...(runId === undefined ? {} : { runId }),
          ...(sessionId === undefined ? {} : { sessionId }),
        },
      },
      version: 'actionproxy.action-request.v1',
    },
  };
}

async function exerciseAuditFilterContract(auditStore: AuditStore): Promise<void> {
  const suffix = randomUUID();
  const workspaceId = `workspace_${suffix}`;
  const toolCallId = `toolcall_${suffix}`;
  const target = auditEvent({
    id: `audit_target_${suffix}`,
    timestamp: '2026-07-15T10:00:00.000Z',
    toolCallId,
    workspaceId,
  });
  await auditStore.append(target);
  await auditStore.append(
    auditEvent({
      id: `audit_wrong_workspace_${suffix}`,
      timestamp: '2026-07-15T10:01:00.000Z',
      toolCallId,
      workspaceId: `other_workspace_${suffix}`,
    }),
  );
  await auditStore.append(
    auditEvent({
      id: `audit_wrong_tool_call_${suffix}`,
      timestamp: '2026-07-15T10:02:00.000Z',
      toolCallId: `other_toolcall_${suffix}`,
      workspaceId,
    }),
  );

  await expect(auditStore.list(1, { toolCallId, workspaceId })).resolves.toMatchObject([{ id: target.id }]);
}

function exposure(overrides: Partial<ContentExposureRecord> = {}): ContentExposureRecord {
  return {
    influenceScopeId: 'scope_default',
    integrity: 'public_untrusted',
    observedAt: '2026-07-15T10:00:00.000Z',
    policyVersionHash: 'policy_hash_v1',
    sourceToolCallId: 'toolcall_source_default',
    workspaceId: 'default',
    ...overrides,
  };
}

function toolCall(overrides: Partial<ToolCallRecord> = {}): ToolCallRecord {
  return {
    agentId: 'forensic-query-test',
    createdAt: '2026-07-15T10:00:00.000Z',
    id: `toolcall_${randomUUID()}`,
    input: {},
    metadata: {},
    reason: 'Exercise bounded forensic query filters',
    requestedBy: 'tester@example.com',
    status: 'submitted',
    toolName: 'docs.search',
    updatedAt: '2026-07-15T10:00:00.000Z',
    workspaceId: 'default',
    ...overrides,
  };
}

function auditEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    data: {},
    id: `audit_${randomUUID()}`,
    timestamp: '2026-07-15T10:00:00.000Z',
    type: 'tool_call.submitted',
    ...overrides,
  };
}

function tempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function hasSqliteCli(): boolean {
  try {
    execFileSync('sqlite3', ['-version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
