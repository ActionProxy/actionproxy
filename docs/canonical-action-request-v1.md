# Canonical action request v1

## Status and scope

`actionproxy.action-request.v1` is the versioned enforcement input implemented
for the HTTP `POST /v1/tool-calls` adapter, the authenticated stdio
`POST /v1/mcp/tool-calls` adapter, and the standard Streamable HTTP `POST /mcp`
adapter. The implementation is in
`apps/server/src/contracts/action-request.ts`; reusable golden vectors are in
`fixtures/contracts/action-request-v1.json` and MCP scenario coverage is in
`fixtures/contracts/mcp-conformance-v1.json`.

Its additive deterministic decision projection is specified separately in `docs/decision-model-v1.md` and uses `fixtures/contracts/decision-v1.json`.

The JavaScript SDK is a conformant client of the HTTP boundary. The authenticated
stdio wrapper and standard `/mcp` resource are canonical adapters and do not
change the frozen decision-input hash rules. Verified MCP adapters include
additive server-derived influence-scope provenance in the request evidence;
`session` remains excluded from `decisionInputHash`. The existing
`ActionEnvelope` hash, approval review hash, receipt binding, execution grant
binding, response shape, and YAML policy syntax remain authoritative for their
defined purposes.

## Trust vocabulary

| Classification | Meaning |
|---|---|
| `trusted` | Supplied by ActionProxy server configuration or a local server-created context. This is authoritative only within that deployment posture. |
| `externally_verified` | Bound to authenticated material verified by an identity provider or ActionProxy credential verifier. |
| `derived` | Deterministically computed by an ActionProxy adapter or normalizer from named inputs. Its source assertions may still be untrusted. |
| `asserted` | Supplied by the caller and not independently verified. It must not be promoted merely because it appears in metadata. |

Every sourced field has `present`, `provenance.source`, `provenance.trust`, and, when present, `value`. Explicit absence participates in canonical hashing; it is not silently equivalent to a supplied `null` value.

## Field contract

| Field | HTTP v1 source and classification | Current use |
|---|---|---|
| `version` | normalizer constant; derived | Schema dispatch |
| `requestId` | generated tool-call ID; derived | Correlation and request hash |
| `receivedAt` | server clock; derived | Evidence and request hash |
| `tenant` | `AuthContext.workspaceId`; externally verified for authenticated modes, trusted local server state for auth-none | Policy/evidence boundary; request metadata is ignored |
| `actor` | `AuthContext.principal`; externally verified for authenticated modes, trusted implicit `local-admin` for auth-none | Policy/evidence boundary; `requestedBy` remains only a non-authoritative assertion |
| `agent` | body `agentId` and optional metadata name; asserted; verification is fixed to `asserted` | Evidence and decision input; metadata cannot claim verification |
| `session` | metadata `sessionId`/`runId`; asserted | Correlation only; cannot establish an authoritative influence scope |
| `source` | HTTP route adapter; derived | Fixed to `{type: "http"}` |
| `sourceProtocol` | HTTP route adapter; derived | Fixed to `actionproxy_http`; body hints cannot override it |
| `tool` | body `toolName`; asserted | Policy lookup and decision input |
| `operation` | tool name mapped to operation name; derived | Decision input; caller operation kind is not trusted |
| `arguments` | body `input`; asserted and canonical-JSON validated | Policy-derived facts, execution, and decision input |
| `resources` | body `action.resources`; asserted | Decision input; not independently verified |
| `environment` | deployment configuration; trusted | Decision input; metadata cannot override it |
| `credentialReference` | absent; no trusted credential resolver supplies it | Decision input; raw credentials are not a canonical field |
| `context.rationale` | body `reason`; asserted | Human/evidence context, not authoritative policy input |
| `context.action` | body action context; asserted | Retained as evidence, not authoritative policy input |
| `context.metadata` | body metadata; asserted | Retained as evidence, not authoritative policy input |
| `context.policy` | fixed sourced-field projection described below | Sole HTTP policy-condition input for this contract version |
| `executionMode` | current action/metadata hint; asserted | Local-versus-external behavior; it is not identity or policy provenance |
| `idempotencyKey` | HTTP header; asserted | Existing best-effort request deduplication; excluded from the decision hash |
| `integrity` | canonical JSON v1 plus SHA-256; derived | Request and decision-input correlation |

## MCP ingress projection

Both authenticated MCP adapters call the same normalizer and policy provider as HTTP, but
they supply an explicit server-owned `McpActionIngress`:

| Field | Standard Streamable HTTP `/mcp` | Authenticated stdio adapter |
|---|---|---|
| `tenant` / `actor` | external OAuth token plus configured workspace; externally verified | authenticated ActionProxy API-key/OIDC principal plus configured workspace; externally verified |
| `agent` | adapter-created `mcp-client:<client_id>` label; provenance is derived and verification remains `asserted` | adapter-created `mcp:<principal>` label; provenance is derived and verification remains `asserted` |
| `source` | `{type: "mcp", adapterId: <client_id-or-azp>}` from verified OAuth client identity; externally verified | `{type: "mcp", adapterId: "mcp-stdio:<authenticated-client-or-principal>"}`; derived |
| `sourceProtocol` | fixed to `mcp`; derived | fixed to `mcp`; derived |
| `session` | opaque influence-scope id derived from the signed MCP session plus workspace/principal/adapter/protocol/transport; derived | opaque influence-scope id derived from the canonical wrapper UUID plus workspace/principal/adapter/protocol/transport; derived |
| `environment` | server deployment configuration; trusted | server deployment configuration; trusted |
| `idempotencyKey` | HMAC-session-bound, typed JSON-RPC id projection; derived | adapter/principal-bound wrapper request key; derived |
| `tool` / `arguments` | selected governed tool and validated tool arguments; retained as asserted action input | downstream tool name/arguments; retained as asserted action input |

Tool `_meta`, ordinary metadata, `requestedBy`, action hints, and tool arguments
cannot replace these authoritative ingress fields. Standard status/resume reads
also compare the authenticated tenant and OAuth client with stored canonical,
envelope, and authenticated-request evidence.

The raw signed session and raw wrapper UUID are not persisted or returned as
the canonical `sessionId`. Both adapters expose only an opaque
`influence_<sha256>` identifier. This evidence establishes transport scope, not
conversation identity, and it cannot assign source integrity; integrity comes
only from the frozen selected policy rule.

The generic v1 field contract labels `executionMode` as an
asserted hint even when an MCP route constructs the adapted
request server-side. The MCP routes fix it to `local_mock` (standard `/mcp`) or
`external_grant` (stdio) before normalization, so callers cannot choose it, but
the provenance vocabulary is not silently reinterpreted without a new contract
version.

## Policy-context projection

The YAML language is unchanged. For HTTP submissions, all fields it may inspect have explicit provenance:

| Policy field | Classification and derivation |
|---|---|
| `amount` | derived from finite numeric `input.amount` or `input.amountCents`; otherwise explicitly absent |
| `currency` | derived from non-empty `input.currency`; otherwise absent |
| `recipientDomain` | derived as the existing coarse `external` category when recipient arguments are present; otherwise absent |
| `appId` | derived from the normalized tool namespace using the documented mapping; otherwise absent |
| `customerVisible` | derived only for the small, explicit known-tool mapping; otherwise absent |
| `approverGroup` | absent; no authenticated group-to-policy-context resolver supplies it |
| `operationKind` | absent; no trusted tool schema or adapter supplies it |
| `risk` | absent; rule risk remains policy output and caller `riskKind` is ignored |
| `workflowId` | absent; no trusted server workflow context is supplied |

This deliberately causes a conditional rule that depends only on untrusted metadata to miss and fall back to the YAML default. It does not make asserted arguments trustworthy; it only makes their lineage explicit and restricts how policy facts are derived.

## Canonical JSON and hashing

Canonical JSON v1 is repository-defined and versioned; it must not be described as RFC 8785/JCS.

- Object keys are ordered by JavaScript UTF-16 code-unit comparison.
- Arrays retain order.
- Strings retain their exact Unicode code points; no Unicode normalization is performed. Composed and decomposed forms hash differently.
- Object properties whose JavaScript value is `undefined` are omitted. `undefined` array elements are rejected.
- `null` is retained and differs from omission.
- Numbers must be finite and use ECMAScript `JSON.stringify` representation; negative zero becomes `0`.
- BigInt, symbols, functions, non-plain objects, cycles, and non-finite numbers are rejected.
- Hashes are lowercase SHA-256 over the UTF-8 bytes of the canonical string.
- The raw HTTP adapter rejects duplicate JSON object keys, including escaped-equivalent keys, before Zod normalization. It also applies a 1 MiB buffering limit; Fastify remains authoritative for ordinary JSON syntax errors.

`integrity.requestHash` hashes the full request material before adding `integrity`, including request ID and receipt timestamp. `integrity.decisionInputHash` hashes the current policy/execution-relevant projection and excludes rationale, raw metadata/action context, session correlation, idempotency key, request ID, and timestamp.

The vectors in `fixtures/contracts/action-request-v1.json` are the contract authority for this version. Changing their canonical bytes or expected hashes is a public contract decision and requires a new version or explicit maintainer approval.

## Persistence and upgrade behavior

Canonical HTTP and MCP tool-call records persist the request version, request
hash, decision-input hash, and sourced policy-context snapshot. Decision traces
and `action.envelope_created` evidence include those values plus the trusted
identity/source projection. The complete raw canonical request is not
separately duplicated because the existing tool-call record already retains
request payloads. The absence of a separately minimized raw-request projection
is an explicit evidence-minimization limitation.

Verified MCP evidence persists only the opaque influence scope. It does not
persist the wrapper UUID or signed transport-session nonce. Content exposure
rows are a separate minimized store and do not change the request or
decision-input hash algorithms.

The exact-action `ActionEnvelope` is built from the submitted hints and remains
the binding used by approval reviews, receipts, and grants. It is distinct from
the authoritative ingress projection: an ordinary HTTP body may include an
asserted `action.protocol` hint, while its canonical ingress protocol remains
`actionproxy_http`; authenticated MCP adapters construct canonical ingress and
envelope source as `mcp`. Changing approval or grant binding to use a different
request projection would require a new, explicitly versioned contract.
