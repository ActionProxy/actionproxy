# Execution authorization and executor capabilities v1

## Status and scope

`actionproxy.execution-authorization.v1` is the server/core authorization passed across the final executor boundary. It is created only after the current request, deterministic decision, approval where required, policy, exact input, and durable execution attempt have been validated. `ToolRegistry` and the external-grant dispatch boundary consume it immediately before dispatch.

For an action with `actionproxy.content-influence.v1` evidence, current scope,
exposure snapshot, selected source rule, effective decision, and policy identity
are also revalidated immediately before this boundary. They remain a separate
additive binding and do not change the frozen execution-authorization
projection.

The implementation is in `apps/server/src/contracts/execution-authorization.ts`. The deterministic, credential-free projection corpus is `fixtures/contracts/execution-authorization-v1.json`.

This contract is additive. It does not replace or change canonical request, decision-v1, approval authorization, approval review, execution-grant, execution-attempt, idempotency, or signature/hash semantics. The JavaScript SDK is a conformant client of the authoritative HTTP boundary and exposes this contract only as read-only evidence types. Authenticated stdio MCP and the standard OAuth-protected `/mcp` adapter follow the same executor boundary. The opaque capability remains server-only. This structural-conformance claim applies only to those documented Community adapters.

## Opaque runtime authority

An `ExecutionAuthorization` is an empty, frozen, process-local object. The issuing `ExecutionAuthorizationAuthority` stores its authoritative projection and consumed state in a private `WeakMap` keyed by object identity. Consequently:

- constructing another empty object does not create authority;
- serializing a token produces `{}` and cannot transfer or recreate authority;
- a token issued by another authority instance is invalid;
- a successful consume is one-use and a second consume is rejected;
- expiry is evaluated with the authority's server clock, not a caller timestamp; and
- binding validation happens before the token is marked consumed, so a mismatched invocation cannot accidentally authorize dispatch.

The default lifetime is 60 seconds. A caller may choose a shorter positive lifetime, for example so a just-in-time external capability cannot outlive its existing signed execution grant. Equality at the expiry instant is expired.

This process-local object is not a network bearer credential or a durable recovery token. Forwarded execution retains the existing signed, expiring, one-use execution grant; the server mints and consumes this opaque capability while authorizing the grant's atomic dispatch transition.

## Deterministic projection

`inspect()` and successful `consume()` return the same deeply frozen `ExecutionAuthorizationProjectionV1`:

| Field | Meaning |
|---|---|
| `version` | Constant `actionproxy.execution-authorization.v1` |
| `authorizationId` | Server-created correlation identity; it is not a hash, signature, nonce, or credential |
| `issuedAt` / `expiresAt` | Server issuance and exclusive authorization deadline |
| `binding` | Exact policy-relevant execution identities described below |
| `capabilities` | Immutable executor capability declaration bound to this authorization |

With an injected clock and ID factory, the same binding and capabilities produce the same canonical JSON projection. No projection hash is introduced: existing hashes are referenced as values and retain their original meanings.

The projection intentionally excludes raw action input, approval payloads, request metadata, reservation ownership, credentials, credential references, provider tokens, and secret-provider results. It is suitable for minimized audit correlation, subject to the repository's ordinary evidence controls.

## Binding

The binding is constructed centrally by `buildExecutionAuthorizationBinding()` from the authoritative `ToolCallRecord`, its reserved `ExecutionAttemptRecordV1`, and the current `ApprovalRecord` when approval applies.

| Section | Bound fields |
|---|---|
| `tenant` | Server/auth-derived `workspaceId` |
| `request` | Tool-call ID plus nullable canonical action-request version and hash |
| `action` | Tool name, existing exact input hash, and existing `ActionEnvelope` hash |
| `decision` | Outcome plus nullable decision-v1 ID, version, and canonical decision-input hash |
| `policy` | Existing immutable policy version hash plus nullable decision-v1 digest, policy version, provider ID/version, and evaluator version |
| `approval` | Nullable approval ID, approval-authorization hash/nonce, and receipt ID/hash |
| `execution` | Attempt ID, attempt number, local/external mode, and nullable external grant ID |
| `executor` | Exact executor identity selected by the durable attempt |

Canonical request and decision-v1 identities remain nullable only for recognized pre-release core records that predate those projections. An executable action still requires its exact-action binding, exact input hash, immutable policy version hash, deterministic outcome, and durable attempt.

The builder fails closed unless all currently duplicated identities agree. It checks tenant, tool-call ID, input, envelope, canonical request, canonical decision input, decision identity, policy, executor/mode, grant posture, approval terminal/consumed state, approval authorization hash/nonce, and approved input. It accepts only a `reserved` or `dispatched` v1 attempt with `attemptNumber: 1`, `providerIdempotency: "none"`, and `retryPolicy: "never_automatic"`; issuance uses `reserved`, while the local registry reconstructs the binding from reloaded `dispatched` state immediately before invocation.

After issuance, the consumer reconstructs or receives the expected binding from current authoritative state. Any tenant, input, policy, approval, attempt, grant, tool, decision, or executor difference rejects the capability. Approval for one normalized action therefore cannot authorize a materially different action.

The service performs the same fail-closed check for content influence just
before a local registry call and in the external grant's pre-dispatch callback.
New exposure, changed source classification/policy, missing or overflowed
evidence, or a workspace/adapter/scope mismatch stops before the provider
closure or grant dispatch transition. An existing run authorization cannot
satisfy an approval introduced by that influence guard.

## Executor interface and credential custody

The core `ActionExecutor` surface is deliberately small:

```ts
interface ActionExecutor<TResult = unknown> {
  describe(): {
    executorId: ExecutionAttemptRecordV1['executorId'];
    capabilities: ExecutorCapabilitiesV1;
  };
  execute(invocation: AuthorizedExecutionInvocationV1): Promise<TResult>;
}
```

`AuthorizedExecutionInvocationV1` contains the tool name, normalized action input, opaque authorization, and expected authorization binding. It has no credential, token, password, API key, or credential-reference parameter. Provider credentials must be resolved inside a registered executor/provider closure and must not be returned in its result or copied into requests, attempts, grants, receipts, logs, or evidence.

Executor dispatch compares the authorization's executor identity and capability projection with `describe()` and consumes the capability before invoking the provider closure. Missing, fabricated, expired, replayed, or mismatched authority never reaches that closure.

## Conservative capability declaration

Version 1 defines `actionproxy.executor-capabilities.v1` with all uncertain provider behavior disabled:

| Capability | v1 value | Consequence |
|---|---|---|
| timeout | `enforced: false`, `timeoutMs: null` | No executor-enforced deadline is claimed; an uncertain timeout is not retry-safe |
| cancellation | `supported: false` | Cancellation cannot be claimed without affirmative provider evidence |
| provider idempotency | `supported: false` | No provider-side duplicate suppression is assumed |
| reconciliation | `supported: false` | No automatic provider lookup or recovery is available |
| automatic retry | `supported: false` | The gateway never retries this authorization automatically |
| credential custody | `executor_boundary_only`, no raw-credential parameter | Credential material is resolved inside the executor/provider closure rather than carried by the authorization interface |

These declarations are authorization-relevant and immutable. An executor may advertise stronger behavior only through a separately reviewed capability contract and conformance tests. In particular, no capability declaration alone makes an unknown provider outcome safe to retry.

## Failure semantics

The authority exposes stable machine-readable errors:

- `execution_authorization_invalid`: absent, fabricated, serialized, or foreign-authority token;
- `execution_authorization_expired`: server time reached the exclusive deadline;
- `execution_authorization_replayed`: the same capability already authorized a dispatch; and
- `execution_authorization_binding_mismatch`: current binding differs or authoritative records cannot form a valid binding.

Every error is fail closed. The error does not include raw input, credentials, tokens, or differing field values.

## Upgrade behavior and limitations

- The existing YAML language, evaluator, `ActionProxyService` lifecycle, HTTP endpoints, mock tools, response projections, and public hash/signature inputs remain unchanged.
- The capability authorizes one existing v1 attempt; it does not allocate another attempt, recover a stuck reservation, or retry any dispatched or unknown outcome.
- The capability is intentionally process-local and short-lived. It is minted just in time from durable state, not persisted for restart recovery.
- This boundary prevents the authorization/invocation contract from carrying credentials. Repository-wide pre-persistence secret classification and rejection of caller-supplied secrets embedded in ordinary action arguments are outside this contract and are not claimed.
- Timeout enforcement, confirmed cancellation, provider idempotency, reconciliation, and automatic recovery are not implemented.
- JavaScript SDK-over-HTTP, authenticated stdio MCP, and the standard OAuth-protected `/mcp` adapter conform without exposing, serializing, or recreating the opaque capability. Adapters outside the documented Community surfaces are not covered by this structural-conformance claim.
