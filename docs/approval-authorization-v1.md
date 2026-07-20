# Approval authorization v1

## Status and scope

`actionproxy.approval-authorization.v1` is the additive authorization state for an approval created under this version. It binds the stored approval to the exact request, policy decision, review, and eligibility state that produced it, gives that authorization a finite lifetime and nonce, and supports terminal approval, rejection, cancellation, and expiration.

The contract is implemented in `apps/server/src/contracts/approval-authorization.ts` and stored as part of `ApprovalRecord`. It does not replace the existing approval record, vote history, `ActionEnvelope`, or policy evaluator. SDK, adapter, receipt, grant, and executor contract identities remain unchanged.

When source-aware policy applies, the tool call and approval review also carry
separate `actionproxy.content-influence.v1` evidence. That additive binding does
not change this authorization hash, but it is mandatory current-state evidence
for finalization and dispatch.

The contract has its own `authorizationHash`. It does **not** change the canonical action-request hash, canonical decision-input hash, decision-v1 identity, `ActionEnvelope` hash, approval review hash, input hash, receipt hash, execution-grant hash, or idempotency hash.

## Authorization record

The server issues the record when a `require_approval` decision creates an approval under this contract version:

| Field | Meaning |
|---|---|
| `version` | Constant `actionproxy.approval-authorization.v1` |
| `authorizationHash` | SHA-256 canonical JSON hash of every other field in the authorization record |
| `nonce` | Cryptographically random, server-issued replay identifier |
| `issuedAt` | Server issuance time |
| `expiresAt` | Authorization deadline; the default is 24 hours after `issuedAt` |
| `binding.approval` | Approval ID, tool-call/request ID, tenant, requester, and requester principal identity |
| `binding.action` | Existing original-input, `ActionEnvelope`, and approval-review hashes |
| `binding.request` | Canonical action-request version/hash and decision-input hash when present |
| `binding.decision` | Decision-v1 version/ID and authoritative policy outcome when present |
| `binding.policy` | Existing policy version/hash plus decision-v1 provider, policy digest/version, and evaluator identity when present |
| `binding.requirements` | Canonically sorted eligible users/groups, quorum, and separation-of-duties requirement |

Canonical-request or decision-v1 bindings are nullable only for recognized pre-release core records that predate those projections. An approval still requires the immutable policy version hash and all action/review hashes. Every new request through a documented Community adapter populates the available v1 identities.

`authorizationHash` uses the repository's canonical JSON v1 hashing function. Arrays whose order is not semantic, specifically eligible users and groups, are sorted and deduplicated before hashing. This creates a separate authorization identity without changing any previously public hash vector.

The nonce is an integrity/replay identifier, not a secret bearer credential. Authorization still depends on authenticated principal, tenant, scopes, eligibility, separation of duties, current policy, quorum, and the stored binding.

## Time domains

These three time values have distinct purposes:

- **24-hour authorization lifetime:** a server default for new `actionproxy.approval-authorization.v1` records. At or after `expiresAt`, the approval cannot accept a vote, be rejected/cancelled as though still pending, reserve execution, or execute.
- **Four-hour operational SLA:** queue-health metadata used for reminder/escalation presentation. Breaching it does not itself authorize or expire an action.
- **Five-minute review freshness:** limits how long a rendered review representation is considered fresh. It does not extend the underlying authorization lifetime.

Checks use authoritative server/database time supplied to the atomic state transition. Client clocks do not determine validity.

## State and replay model

The approval state machine is:

```text
pending
  -> approved   (quorum reached; authorization consumed)
  -> rejected   (terminal; authorization consumed)
  -> cancelled  (terminal; authorization consumed)
  -> expired    (terminal; authorization consumed)
```

Terminal state is irreversible. `authorizationConsumedAt` and `authorizationConsumedReason` record why the nonce was consumed. A second use of the same nonce/hash, a stale concurrent request, or an operation after any terminal transition fails closed and cannot invoke an executor or issue an execution grant.

Every vote records the authorization version, hash, and nonce in addition to the existing approver, review, input, and envelope bindings. Duplicate votes by the same decision maker remain rejected. Votes for another nonce/hash cannot contribute to quorum.

Clients may echo `approvalNonce` on approval, rejection, or cancellation requests. If supplied, it must equal the authoritative record's `nonce`. The field is optional in the current wire contract; when absent, the service uses the nonce reloaded from trusted storage and still supplies it to the atomic compare-and-set. Replay safety therefore does not depend on a client returning the nonce.

## Approval, rejection, and cancellation authorization

Approval preserves the existing `approval:approve` scope, eligible-user/group checks, quorum, separation of duties, rejection behavior, original payload, decision history, and notification behavior.

Rejection and cancellation use `approval:reject`. Cancellation is restricted to an authenticated decision maker eligible for that approval; it is not an unrestricted requester-controlled delete. Cancellation records the actor, time, and optional reason, maps the associated tool call to the existing compatible `rejected` status, and does not erase evidence.

The single-party edit path retains, re-evaluates, and records the edited payload with its approved input and envelope hashes. Multi-party approvals cannot accept an edited payload because votes over different payloads cannot safely accumulate. Earlier votes are not retained across a modification, and this contract does not define a consensus protocol for edits.

## Finalization boundary

Before a vote or terminal transition, `ActionProxyService` reloads the authoritative approval and tool call and validates:

1. tenant, authenticated decision-maker eligibility, and separation of duties;
2. pending status, nonce, authorization hash, and expiration;
3. stored original input, envelope, review, canonical request, decision-v1, policy, requester, and approval-requirement bindings;
4. current policy identity and the policy result for the effective input;
5. the exact verified influence scope, exposure snapshot/binding hash, source
   references, and effective content-influence decision when present;
6. review and approved-input/envelope hashes.

The storage compare-and-set then reloads the row in a transaction and atomically enforces terminal status, nonce/hash, expiry, binding, duplicate-vote handling, and quorum. It compares the service's expected active policy hash with the authorization's stored policy identity. Only the winning transition can consume the authorization.

The active YAML policy is managed in process rather than in the approval transaction. Consequently, the database cannot itself prove that no process-local policy reload occurred during the transaction. The service revalidates the active policy immediately before the compare-and-set and again after finalization, before local execution or grant issuance. A mismatch fails closed. Policy and configuration state are not globally atomic with the database transaction.

Content-influence state is likewise reloaded before finalization and again
immediately before local dispatch or external grant consumption. New exposure,
scope/workspace/adapter mismatch, policy or source-classification change,
lookup overflow, or missing evidence makes the stored binding stale. The action
fails closed and the executor is not called; another authorization cannot
satisfy an approval introduced by influence.

Expiration may be materialized lazily when an approval is read, listed, or acted on. The atomic expiration transition wins or loses against approval/cancellation through the same terminal-state compare-and-set. The associated tool call uses the existing `rejected` status; approval evidence distinguishes `expired` from `cancelled` and `rejected`.

## Records without v1 authorization

No security-sensitive authorization identity is synthesized or backfilled for records that lack a valid v1 authorization:

- recognized pre-release terminal approvals remain readable as historical evidence;
- a pending approval without a valid v1 authorization fails closed and requires the action to be submitted again;
- no legacy vote can be attached to a newly generated nonce;
- schema changes may preserve nullable columns/JSON for readability, but runtime authorization does not grandfather an unbound pending record.

## Upgrade behavior and limitations

- Existing approval endpoints and response fields remain; authorization data, optional `approvalNonce` request fields, and `POST /v1/approvals/:id/cancel` are additive.
- Existing YAML policy, policy evaluator, approval notifications, stored decision traces, and all pre-existing hashes remain authoritative for their existing purposes.
- `actionproxy.decision.v1.approvalRequirements.expirationRequired` remains `false` and `expiresAt` remains `null`. Those frozen values participate in decision identity and are not reinterpreted. Runtime expiry is represented by this separate authorization contract.
- Cancellation and expiry intentionally reuse the existing tool-call `rejected` status to avoid changing the v1 tool-call status contract.
- The compare-and-set implementation must be validated independently for SQLite and Postgres. Passing one backend's tests is not evidence for the other.
- The core executor capability boundary is described in `execution-authorization-v1.md`. Canonical HTTP, SDK-over-HTTP, authenticated stdio MCP, and standard `/mcp` paths use that boundary. Adapters outside the documented Community surfaces are outside this structural-conformance claim.
