# Content-influence local performance report

## Purpose

`corepack pnpm benchmark:content-influence` is a small, non-gating local
measurement for the source-aware policy path. It exercises only:

- the pure `evaluateContentInfluence` function;
- idempotent `MemoryStore.recordContentExposure` inserts; and
- bounded `MemoryStore.listContentExposures` lookups at the enforced 256-row
  limit, including overflow-to-`unknown` input shape.

It does not start Fastify, a model, an MCP child, a database, DNS, a reputation
service, or another network client. It is not a production capacity claim and
does not benchmark SQLite/Postgres query planning, audit I/O, approval delivery,
or downstream tool latency.

## Gating policy

Elapsed time is intentionally informational. CI has no wall-clock threshold:
shared and virtualized runners make such thresholds noisy and easy to
misinterpret. The normal test suite instead asserts stable work bounds:

- unguarded actions perform no exposure lookup;
- a guarded action performs one lookup with
  `MAX_INFLUENCE_EXPOSURES = 256`;
- a classified result performs one minimized insert independent of raw result
  size; and
- storage conformance returns at most the requested limit plus an overflow bit,
  with workspace/scope filters applied before the limit.

Those operation-count and bounded-input assertions live in
`apps/server/src/services/action-gate.test.ts` and
`apps/server/src/storage/forensic-query-store.test.ts`. The benchmark command is
not part of `pnpm test` or a release pass/fail gate.

## Workload

The versioned `actionproxy.content-influence-benchmark.v1` report performs:

- 100,000 pure influence evaluations whose base allow is narrowed by an
  observed `public_untrusted` source;
- 257 unique exposure inserts, one idempotent replay, and no raw content;
- 2,000 bounded lookups with `limit: 256` over a 257-row scope; and
- zero model, embedding, reputation, or network calls.

The executable verifies these operation counts before printing timing data.

## Sample local run

Recorded on 2026-07-19 using Node.js v24.11.0 on macOS arm64. This is a sample,
not a regression threshold:

```json
{
  "disclaimer": "Non-gating local measurement; CI asserts operation counts and bounded inputs, not elapsed time.",
  "environment": {
    "architecture": "arm64",
    "node": "v24.11.0",
    "platform": "darwin"
  },
  "operations": {
    "embeddingCalls": 0,
    "exposureInsertCalls": 258,
    "exposureLookups": 2000,
    "exposureReplayCalls": 1,
    "exposureRowsCreated": 257,
    "lookupLimit": 256,
    "lookupOverflowResults": 2000,
    "lookupRowsReturned": 512000,
    "modelCalls": 0,
    "networkLookups": 0,
    "policyEvaluations": 100000,
    "reputationLookups": 0
  },
  "timingsMs": {
    "exposureInserts": 8.16,
    "exposureLookups": 14.98,
    "policyEvaluation": 12.25,
    "total": 35.46
  },
  "version": "actionproxy.content-influence-benchmark.v1"
}
```

Use a fresh local run when comparing implementation alternatives, record the
machine/runtime, and compare operation counts before interpreting timings.
