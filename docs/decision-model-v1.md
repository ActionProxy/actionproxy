# Decision model v1

## Status and scope

`actionproxy.decision.v1` is the additive deterministic decision projection implemented for the HTTP/core canonical request, authenticated MCP adapters, and HTTP policy simulation. The contract is in `apps/server/src/contracts/decision.ts`, the fail-closed provider boundary is in `apps/server/src/policy/policy-provider.ts`, and reusable vectors are in `fixtures/contracts/decision-v1.json`.

The JavaScript SDK consumes this projection through the canonical HTTP boundary,
and approval authorization references it as immutable evidence. Grant, receipt,
and executor contracts remain separate. Existing response fields and all
existing hash/binding semantics remain authoritative for their defined
purposes.

## Projection

| Field | Meaning |
|---|---|
| `version` | Constant `actionproxy.decision.v1` |
| `decisionId` | `decision_` plus SHA-256 of canonical identity material described below |
| `requestId` | Canonical request identity; the submitted HTTP tool-call ID |
| `tenantId` | Canonical server/auth-derived workspace identity |
| `decisionInputHash` | `actionproxy.action-request.v1` decision-input hash |
| `outcome` | `allow`, `deny`, or `require_approval` |
| `policy.provider` | Provider ID, provider contract version, and `ok`/`failure` status |
| `policy.version` | Immutable policy-version identifier, or `null` on missing/unavailable provider identity |
| `policy.digest` | SHA-256 policy digest, or `null` on missing/unavailable provider identity |
| `policy.digestAlgorithm` | `sha256` for a valid provider, otherwise `null` |
| `policy.schemaVersion` | YAML policy schema version for the built-in provider |
| `evaluatorVersion` | Deterministic evaluator implementation version; nullable only for unavailable/versionless failures |
| `matchedPolicies` | Ordered selected rules with provider, policy version/digest, rule ID, and match type; empty on provider failure |
| `reasonCodes` | Stable machine reason codes; human `policyReason` remains a display field |
| `obligations` | Deterministic controls already required by the current lifecycle |
| `approvalRequirements` | Current eligibility, quorum, separation, rejection, edit, and expiration capability facts |
| `decidedAt` | Explicit server decision time; it is evidence and is not included in `decisionId` |

`decisionId` hashes canonical JSON v1 identity material containing request/tenant/input identity, outcome, provider and policy identity, matched rules, reason codes, obligations, and approval requirements. It deliberately excludes `decidedAt`, display reason text, risk labels, raw context, and model output. Re-evaluating the same request input under the same policy contract produces the same decision ID; the timestamp still records when each projection was made.

The decision-ID algorithm does not replace or modify `ActionEnvelope.envelopeHash`, approval review hashes, receipt hashes, grant hashes, input hashes, idempotency request hashes, or canonical request hashes.

## Stable reason codes

- Outcomes: `policy_outcome_allow`, `policy_outcome_deny`, `policy_outcome_require_approval`.
- Selected match: `policy_match_exact`, `policy_match_wildcard`, `policy_match_default`.
- Conditional fallthrough: `policy_conditional_fallback`.
- Provider failures: `policy_provider_unavailable`, `policy_provider_error`, `policy_provider_invalid_output`, `policy_provider_version_missing`.

Human policy reasons remain deterministic YAML rule text but are not stable machine identifiers. LLM explanations are not accepted as provider decisions and cannot become authoritative reason codes. Existing `risk` remains policy metadata/signal; it is not included in decision identity and cannot independently authorize an allow.

## Obligations

| Outcome | Obligations |
|---|---|
| allow | `record_decision_evidence`, `revalidate_policy_before_execution` |
| deny | `record_decision_evidence`, `do_not_execute` |
| require approval | `record_decision_evidence`, `require_human_approval`, `revalidate_policy_before_execution` |

These describe core lifecycle requirements; they do not create a new workflow engine. The separate `actionproxy.execution-authorization.v1` contract makes authorization structurally mandatory at the local-registry and external grant-dispatch boundaries on covered paths. Its limitations section states where that structural guarantee stops.

## Approval requirements

For `require_approval`, the projection sorts and records configured eligible users/groups, quorum, and separation of duties. It records terminal rejection and the single-party edit behavior as `revalidate_and_rebind`.

`expirationRequired` remains `false` and `expiresAt` remains `null`. These values were frozen into the published decision-v1 identity before runtime authorization expiry was represented by a separate contract, so this version does not reinterpret or mutate them. They are not permission to treat an approval as timeless.

Pending approvals created under `actionproxy.approval-authorization.v1` carry a separate `authorizationHash` that binds the decision ID/input hash and concrete 24-hour runtime expiry. Cancellation, nonce, replay, vote, and terminal-state semantics also live in that authorization contract. Any decision contract that projects expiration capability must use a new version rather than change decision-v1 identity.

## Built-in YAML provider and failure semantics

The only implementation is `actionproxy.yaml` version `actionproxy.yaml-provider.v1`, using `actionproxy.policy-evaluator.v1`. It delegates to the existing pure YAML evaluator and uses the existing policy hash/version identifiers.

The safe provider boundary validates mandatory version/digest identity and structural consistency between approval mode, outcome, selected rule, and trace. An unavailable provider, thrown exception, malformed output, or missing version identity produces a synthetic deny with no matched policy, a stable failure reason code, and `do_not_execute`. Exception details are not copied into the decision or policy reason.

Immediately before core execution, canonical HTTP records also validate the
complete stored projection against the frozen decision-ID material and the
authoritative request, tenant, decision input, outcome, policy, rules, reason
codes, obligations, and approval requirements. Final policy evaluation must
still be `allow` for an action that never received human/run authorization; an
`allow` that changes to `require_approval` fails closed instead of dispatching.
The provider descriptor must also match the stored provider/policy and
evaluator identity. These checks do not change decision-v1 hash semantics.

External providers such as OPA, Cedar, and Cerbos are not implemented. ActionProxy does not replace those systems or define a new policy language.

## Content-influence intersection

For a selected YAML rule with `influence`, ActionProxy first retains the base
provider evaluation, then intersects it with verified, bounded exposure state.
The effective evaluation is projected into decision v1 so its outcome matches
the tool-call decision. Separate `actionproxy.content-influence.v1` evidence
retains both base and effective decisions, the selected guard, opaque scope,
exposure snapshot/binding hashes, policy identity, and bounded source
references.

This intersection can only preserve or narrow the base outcome. It cannot turn
deny or require-approval into allow. A missing verified scope or unavailable/
overflowed exposure lookup is `unknown`. Policies without `influence` retain
the existing decision identity behavior.

## Persistence and upgrade behavior

Canonical HTTP tool calls store `decisionV1` inside the existing `decisionTrace` JSON and include it in `tool_call.submitted` evidence. SQLite and Postgres therefore round-trip the projection without a separate decision column. HTTP policy simulation returns the same projection without persistence or side effects. Approval authorization stores a reference to this immutable identity; it does not rewrite the projection.

The documented Community adapters receive decision v1. Recognized pre-release core trace rows remain readable so upgrades preserve tool-call, approval, and audit evidence.
