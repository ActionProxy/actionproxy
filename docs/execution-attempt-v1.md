# Execution attempt v1

## Status and scope

`actionproxy.execution-attempt.v1` is the additive durable execution-state contract for the HTTP/core lifecycle. It records a reservation before ActionProxy crosses a local or forwarded execution boundary and makes uncertain provider outcomes explicit.

The implementation is in `apps/server/src/contracts/execution-attempt.ts`; reusable state fixtures are in `fixtures/contracts/execution-attempt-v1.json`. The separate process-local `ActionExecutor` authorization contract is described in `docs/execution-authorization-v1.md`. This attempt contract does not change SDK or adapter wire formats, add automatic recovery, or change the YAML policy language.

The canonical action-request, decision-v1, approval-authorization, `ActionEnvelope`, approval review, receipt, execution-grant, and existing idempotency request hashes are unchanged. Attempt fields only reference those identities and never enter their signed or hashed material.

## Atomic submission idempotency

For keyed `POST /v1/tool-calls` submissions, the tenant/route/key reservation and initial tool-call row are committed together. The request hash is `hashJson({ input: request, route: "POST /v1/tool-calls" })`.

The atomic operation has three outcomes:

- `created`: the caller owns the new logical action and may continue policy evidence, approval, and execution processing;
- `replay`: the same tenant/route/key and request hash already identify an authoritative tool call, which is returned without rerunning lifecycle side effects;
- `conflict`: the key is bound to a different request hash and the request fails.

The scope is the server/auth-derived workspace plus route and caller-provided key. The same key in another tenant is independent. Requests without a key retain existing behavior and create independent actions.

## Attempt record

Each v1 attempt record contains:

- version, attempt ID, tenant, tool-call ID, and attempt number;
- opaque server reservation owner;
- local-mock or external-grant execution mode and executor ID;
- exact approved input hash;
- references to canonical request, canonical decision input, decision-v1, policy, action envelope, approval authorization, receipt, and grant identities where present;
- provider-idempotency capability and retry policy;
- reservation, dispatch, completion, and update timestamps;
- current state and a normalized terminal outcome, including separate result
  and remediation hashes so concurrent reports cannot substitute different
  remediation evidence while reusing the same provider result.

The additive `resultHash` and `remediationHash` use the repository's existing
`hashJson` operation (SHA-256 over `stableStringify`) without changing any
any pre-existing hash input. Exact outputs are frozen in the attempt-v1 fixture. Changing
their serialization or digest semantics requires a new attempt contract
version; they must never be substituted into the existing envelope, approval,
receipt, or grant hash material.

This contract permits exactly one attempt (`attemptNumber: 1`) per tenant/tool call. No lease expiry, owner takeover, or second attempt is implemented. Any retry contract must be separately versioned and supported by explicit provider idempotency or reconciliation evidence.

## State model

```text
reserved
  -> failed_before_dispatch
  -> dispatched
       -> succeeded
       -> failed_after_dispatch
       -> timed_out
       -> cancelled
       -> unknown_outcome
```

- `reserved` means durable execution authority exists but the executor boundary has not been crossed.
- `dispatched` means retry is unsafe without more evidence. For external execution it is committed atomically with one-time grant consumption.
- `failed_before_dispatch` proves the executor was not invoked. ActionProxy does not retry it automatically.
- `failed_after_dispatch` is used only when the executor/runner reports a known failure after invocation.
- `timed_out` records a timeout without claiming provider non-acceptance; reconciliation is required.
- `cancelled` is valid only when dispatch did not occur or provider cancellation is positively confirmed.
- `unknown_outcome` means ActionProxy cannot prove whether the side effect completed.

Terminal transitions are owner/state guarded and immutable. Repeating the exact same outcome is an idempotent replay; a different outcome conflicts. An untyped local executor exception or SDK/MCP transport exception after grant consumption is conservatively `unknown_outcome`, not a retry-safe failure. A structured downstream MCP error response remains a known `failed_after_dispatch` result.

## Forwarded execution

External authorization first reserves an attempt, then creates the existing unchanged signed grant and binds its ID to the attempt. Grant consumption validates all existing signatures, hashes, tenant, input, tool, policy, and expiry checks before atomically changing both:

- grant: unconsumed to consumed;
- attempt: `reserved` to `dispatched`.

The runner then reports an outcome. `succeeded` and `failed` bodies keep their defined behavior. `timed_out`, `cancelled`, and `unknown_outcome` values write the richer attempt state while mapping to the current receipt/tool-call projection. No missing or uncertain outcome is silently retried.

Approval-bound reservation additionally compares the exact valid approval
authorization supplied by the finalizer with locked/current store state,
requires consumed-for-approval status and approved input/envelope hashes, and
uses authoritative current time for expiry. An approval that expires or mutates
after vote finalization therefore cannot reserve an attempt or cause grant
issuance.

## Crash and recovery posture

The recovery posture is deliberately fail closed:

- committed idempotent submission but unfinished lifecycle: replay returns the same partial tool call; it does not start another logical action;
- approved action or receipt with no attempt: no executor may run; automatic resubmission or recovery is not implemented;
- `reserved` with no dispatch: safe but stuck; there is no automatic takeover;
- `dispatched` with no terminal outcome: provider result is unresolved and retry is prohibited;
- provider returned but the tool-call projection or audit write failed: the attempt is authoritative; the error is not rewritten as a known retry-safe provider failure.

Automatic stale-attempt recovery, provider reconciliation hooks, attempt-number allocation beyond one, and retry of unknown/timed-out actions require maintainer and provider-specific review.

## Persistence and queryability

Memory, SQLite, and Postgres implement the same reservation and compare-and-set contract. SQLite provides same-process/local durable semantics; Postgres is the production multi-process target. Attempt rows are queryable through the tool-call execution-attempt read endpoint, while existing tool-call, grant, receipt, and authorized-action response shapes remain compatible.
