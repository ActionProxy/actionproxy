import { performance } from 'node:perf_hooks';
import { MAX_INFLUENCE_EXPOSURES } from '../contracts/content-influence';
import { evaluateContentInfluence } from '../policy/content-influence';
import type { PolicyEvaluation } from '../policy/policy-types';
import { MemoryStore } from '../storage/memory-store';

const POLICY_EVALUATIONS = 100_000;
const EXPOSURE_LOOKUPS = 2_000;
const WORKSPACE_ID = 'benchmark-workspace';
const INFLUENCE_SCOPE_ID = `influence_${'b'.repeat(64)}`;

const guardedAllow: PolicyEvaluation = {
  approval: 'never',
  decision: 'allow',
  matchedRule: 'benchmark.action',
  reason: 'Benchmark base allow.',
  risk: 'benchmark',
  rule: {
    approval: 'never',
    influence: {
      allowFrom: ['none', 'organization_managed', 'verified_publisher'],
      otherwise: 'required',
    },
  },
};

const startedAt = performance.now();

let restrictedEvaluations = 0;
const policyStartedAt = performance.now();
for (let index = 0; index < POLICY_EVALUATIONS; index += 1) {
  const evaluation = evaluateContentInfluence(guardedAllow, {
    observedIntegrities: ['organization_managed', 'public_untrusted'],
    scopeVerified: true,
  });
  if (evaluation.effectiveDecision === 'require_approval') restrictedEvaluations += 1;
}
const policyDurationMs = performance.now() - policyStartedAt;
assert(restrictedEvaluations === POLICY_EVALUATIONS, 'Pure influence evaluation widened or skipped the guard.');

const store = new MemoryStore();
let exposureRowsCreated = 0;
const insertStartedAt = performance.now();
for (let index = 0; index <= MAX_INFLUENCE_EXPOSURES; index += 1) {
  const outcome = await store.recordContentExposure({
    influenceScopeId: INFLUENCE_SCOPE_ID,
    integrity: index % 2 === 0 ? 'organization_managed' : 'public_untrusted',
    observedAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
    policyVersionHash: 'benchmark-policy-v1',
    sourceId: index % 2 === 0 ? 'benchmark-managed' : 'benchmark-public',
    sourceToolCallId: `benchmark-source-${String(index).padStart(4, '0')}`,
    workspaceId: WORKSPACE_ID,
  });
  if (outcome === 'created') exposureRowsCreated += 1;
}
const replayOutcome = await store.recordContentExposure({
  influenceScopeId: INFLUENCE_SCOPE_ID,
  integrity: 'organization_managed',
  observedAt: '2030-01-01T00:00:00.000Z',
  policyVersionHash: 'benchmark-policy-v1',
  sourceId: 'benchmark-managed',
  sourceToolCallId: 'benchmark-source-0000',
  workspaceId: WORKSPACE_ID,
});
const insertDurationMs = performance.now() - insertStartedAt;

assert(exposureRowsCreated === MAX_INFLUENCE_EXPOSURES + 1, 'Unexpected exposure insert count.');
assert(replayOutcome === 'replay', 'Exposure insert was not idempotent.');

let overflowLookups = 0;
let returnedRows = 0;
const lookupStartedAt = performance.now();
for (let index = 0; index < EXPOSURE_LOOKUPS; index += 1) {
  const lookup = await store.listContentExposures({
    influenceScopeId: INFLUENCE_SCOPE_ID,
    limit: MAX_INFLUENCE_EXPOSURES,
    workspaceId: WORKSPACE_ID,
  });
  if (lookup.overflow) overflowLookups += 1;
  returnedRows += lookup.records.length;
}
const lookupDurationMs = performance.now() - lookupStartedAt;

assert(overflowLookups === EXPOSURE_LOOKUPS, 'Bounded lookup did not report overflow.');
assert(
  returnedRows === EXPOSURE_LOOKUPS * MAX_INFLUENCE_EXPOSURES,
  'Bounded lookup returned an unexpected number of rows.',
);

const report = {
  disclaimer: 'Non-gating local measurement; CI asserts operation counts and bounded inputs, not elapsed time.',
  environment: {
    architecture: process.arch,
    node: process.version,
    platform: process.platform,
  },
  operations: {
    embeddingCalls: 0,
    exposureInsertCalls: MAX_INFLUENCE_EXPOSURES + 2,
    exposureLookups: EXPOSURE_LOOKUPS,
    exposureReplayCalls: 1,
    exposureRowsCreated,
    lookupLimit: MAX_INFLUENCE_EXPOSURES,
    lookupOverflowResults: overflowLookups,
    lookupRowsReturned: returnedRows,
    modelCalls: 0,
    networkLookups: 0,
    policyEvaluations: POLICY_EVALUATIONS,
    reputationLookups: 0,
  },
  timingsMs: {
    exposureInserts: rounded(insertDurationMs),
    exposureLookups: rounded(lookupDurationMs),
    policyEvaluation: rounded(policyDurationMs),
    total: rounded(performance.now() - startedAt),
  },
  version: 'actionproxy.content-influence-benchmark.v1',
};

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function rounded(value: number): number {
  return Math.round(value * 100) / 100;
}
