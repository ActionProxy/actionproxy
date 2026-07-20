# Security model

## Posture

ActionProxy Community has two explicit deployment postures:

- `ACTIONPROXY_DEPLOYMENT_MODE=local` with `ACTIONPROXY_AUTH_MODE=none`: local demo/development only. The server creates an implicit `local-admin` context with all scopes and defaults to `ACTIONPROXY_HOST=127.0.0.1`. Startup is blocked on `0.0.0.0` unless `ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND=true` is set for an intentional localhost-published container/demo run.
- `ACTIONPROXY_DEPLOYMENT_MODE=self_hosted` with `ACTIONPROXY_AUTH_MODE=api_key` or `oidc_jwt`: customer-operated or VPC design-review deployments.
ActionProxy authorizes proposed tool calls, manages the approval lifecycle,
issues external execution grants, and records audit events. Existing customer
runners and MCP tools keep custody of downstream business-tool credentials;
Community does not ship production SaaS connectors.

`ACTIONPROXY_LOCAL_EXECUTION=disabled` keeps that boundary explicit: ActionProxy authorizes external runners and does not execute local tools. `ACTIONPROXY_LOCAL_EXECUTION=mock` exists only for local demo flows with built-in mock tools.

The ChatGPT Secure MCP Tunnel demo preserves this local posture. OpenAI's
`tunnel-client` starts exactly one MCP command—the ActionProxy stdio wrapper—and
the wrapper reaches only the loopback ActionProxy gateway and deterministic
mock MCP child declared in `examples/chatgpt-tunnel/actionproxy.mcp.yaml`. The
launcher accepts `CONTROL_PLANE_API_KEY` only from its process environment and
does not print or write its value; Docker Compose does not inject it into the
ActionProxy container, wrapper, or downstream child. Launcher-owned state under
`.actionproxy/` contains only a marker version, tunnel id, and wrapper-command
hash. The tunnel client may maintain its own OpenAI-managed
profile state outside ActionProxy.

Secure MCP Tunnel is a transport boundary, not an ActionProxy identity upgrade.
The demo still uses the implicit `local-admin` context from
`AUTH_MODE=none`, so it must remain loopback/mock-only. Tunnel entitlement and
workspace association authorize use of the OpenAI tunnel; they do not identify
the ChatGPT user to ActionProxy or authorize production business actions. The
advanced ChatGPT path remains the standard `/mcp` protected resource with
external OAuth 2.1 identity.

The HTTP tool-call boundary, authenticated stdio MCP adapter, and standard
Streamable HTTP `/mcp` adapter now create the provenance-aware
`actionproxy.action-request.v1` before policy evaluation and store its
request/decision hashes and sourced policy context. They derive tenant, actor,
adapter/protocol, environment, and transport idempotency from server,
authentication, and session state; ordinary metadata cannot override those
fields. The JavaScript SDK is a conformant client of the HTTP boundary. The
existing `ActionEnvelope` remains the authorization binding for approval
reviews, receipts, and grants.

The HTTP/core executor boundary also uses `actionproxy.execution-authorization.v1`: an empty, non-serializable process-local token whose private server projection binds current tenant, request/envelope/input, decision/policy, approval/receipt, attempt/grant, executor, expiry, and conservative capabilities. `ToolRegistry` and external grant dispatch reject absent, foreign, expired, replayed, or mismatched authority before invoking a local closure or entering the atomic dispatch transition. Conformance tests cover authenticated stdio MCP forwarding and the standard `/mcp` local mock path.

Governed remediation uses the same boundary. A runner or local mock tool may attach a remediation descriptor to a successful outcome, but submitting that remediation creates a new linked tool call that must pass normal policy, approval, grant, receipt, and audit handling. ActionProxy does not mutate the original execution record or claim it can undo irreversible downstream side effects.

Approval notifications are part of the ActionProxy gateway. Slack, Telegram,
and email are direct approval channels; MCP downstream tools are never used to
send approval notifications. The approver directory resolves who may approve
and who receives notifications. OIDC-backed records bind the stable directory
id used by policy and delivery to an authenticated principal. Slack and
Telegram callbacks map provider identities to that same principal. Email uses
a local outbox by default and may use an operator-owned SMTP service. Messages
are sent one recipient at a time for privacy and per-user delivery audit.

MCP wrapper profiles are executable configuration. Saving a profile and generating its wrapper YAML are safe while server-side discovery is disabled. `ACTIONPROXY_MCP_STDIO_DISCOVERY_ENABLED=true` explicitly permits the server to start profile-defined commands for `tools/list` discovery. Those commands, arguments, working directories, and environment additions run with the server process's operating-system privileges and are not sandboxed. Enable discovery only for trusted profiles and tightly control `admin:integrations` access.

The standard `/mcp` endpoint is a protected OAuth resource, not an
authorization server. It accepts only RS256 JWT access tokens and validates the
configured issuer, exact `/mcp` audience, expiry/not-before, subject,
`client_id`/`azp`, scopes, and a unique compatible JWKS key on every request.
ActionProxy publishes protected-resource metadata and relies on an external
OAuth 2.1 server for authorization-code plus PKCE, consent, client
identification/registration, token issuance, and authorization-server
metadata. API keys, bootstrap keys, the implicit local identity, and wildcard
scopes are rejected at `/mcp`. Enabling the standard resource also requires
global `oidc_jwt` auth and a configured generic API audience so the neighboring
`/v1` routes cannot silently retain a weaker public posture.

The current MCP validator is offline JWT validation; it does not call token
introspection or revocation endpoints. Operators should issue short-lived
access tokens and treat authorization-server/key compromise or delayed
revocation as residual risk.

MCP sessions are signed and bound to tenant, principal, verified OAuth client,
resource, and protocol version. They do not replace bearer authentication.
Origin values are exact-allowlisted when present; request/response sizes and
request time are bounded; duplicate JSON keys are rejected; and status reads
are limited to the originating tenant and adapter. A transport timeout is not
proof of cancellation or non-execution, so ambiguous post-dispatch results are
never automatically retried.

Authenticated stdio and standard Streamable HTTP MCP sessions also establish
opaque `influenceScope` identifiers. The stdio route accepts only a canonical
wrapper-process UUID and derives the stored scope from workspace, principal,
adapter, protocol, and transport; the raw UUID is neither persisted nor
returned. `/mcp` derives its equivalent scope from the signed session. Ordinary
HTTP metadata, MCP arguments/annotations, tool descriptions, and result `_meta`
cannot mint a scope or assign source integrity.

Source integrity is an administrator-reviewed property of a tool/adapter, not
a conclusion about text safety. ActionProxy records
`instructionAuthority: none` in its policy, exposure, and audit evidence for
every result. This is not a wire-payload rewrite: a valid child MCP result,
including child `_meta`, remains opaque and unchanged. Any authority assertion
inside that payload is untrusted content and cannot set integrity or authorize
a later action. `organization_managed`, `verified_publisher`,
`authenticated_external`, `public_untrusted`, and `unknown` are explicit set
members, not a numeric reputation score. A generic web tool is
`public_untrusted`; no hostname or vendor name is automatically trusted.
`verified_publisher` requires a dedicated constrained adapter, and Google-hosted
content is not trusted merely because it is served by Google.

Before classified MCP output is released, ActionProxy writes one minimized,
idempotent exposure record and audit event. A valid MCP `isError: true` result
is included because its content reaches the model. Exposure rows contain no raw
page, URL, query string, prompt, or model output. They do not eliminate the
pre-existing full result persistence in tool-call, receipt, and audit records,
and operators must continue to protect those stores. If exposure evidence
cannot be persisted after an execution outcome is known, the result is
withheld, the known outcome is preserved, and no automatic retry occurs.

For a selected action rule with `influence`, ActionProxy performs one bounded,
workspace-scoped exposure lookup and intersects the observed explicit classes
with base policy. Missing/unverified scope, missing classification, lookup
overflow, or unavailable exposure storage becomes `unknown`, never clean.
Base deny and approval cannot be weakened. Scope/exposure/policy bindings are
revalidated before approval finalization and immediately before local or
external dispatch. Evidence self-validates its binding hash, and a monotonic
exposure revision is compared atomically with the lifecycle transition so a
new source cannot race past the check. Stale bindings fail closed without
touching the executor.

Enabling influence is a rollout boundary. Reads released before opt-in were not
classified or recorded, so operators should start a fresh wrapper process or
signed MCP session and clear prior agent context where possible. A new scope
isolates future ActionProxy enforcement but cannot prove that the model forgot
earlier content.

This is deterministic consequence containment after potentially hostile
content, not prompt-injection prevention. It does not stop a model from being
influenced, inspect content, decode cross-call URLs, quarantine data, or govern
any path that bypasses ActionProxy. A wrapper transport scope can span multiple
conversations; a new scope also does not prove model-side persistent memory was
cleared.

Audit payloads are stored in full. API/UI redaction is a read-time presentation control, not storage redaction: it does not remove or encrypt proposed inputs, original/edited approval payloads, or results already stored in JSONL, SQLite, Postgres, volumes, or backups. Operators must protect those stores as sensitive data.

The design baseline is OWASP ASVS for application controls, OWASP API Security Top 10 for API risks, NIST SSDF for secure development practice, and SLSA-style provenance/SBOM work for supply-chain posture.

## Controls implemented

- Server-derived `AuthContext` for enterprise requests.
- Service-account API keys with hashed-at-rest key storage.
- RS256 OIDC JWT verification from configured JWKS material.
- RBAC scopes on tool calls, approvals, audit, policy, integrations, service accounts, and execution grants.
- Workspace field as a single-tenant/self-hosted authorization boundary.
- Approval routing with managed approver users/groups, default approvers, separation of duties, and optional multi-approval.
- Approval notification routing to direct Slack/Telegram/email channels with delivery records.
- Slack DM delivery to approver directory users and Slack callback signature verification plus Slack user mapping to authorized principals.
- Telegram bot delivery to approver directory users, signed short-lived Telegram connect links, Telegram webhook secret verification, and Telegram user ID mapping to authorized principals.
- Bearer-auth-exempt Telegram webhook delivery with mandatory Telegram secret verification and mapped approver authorization in API-key/OIDC modes.
- Protocol-neutral action envelopes for submitted tool calls.
- Versioned canonical action request, deterministic hash vectors, duplicate-key rejection, and sourced policy context for `POST /v1/tool-calls` and HTTP policy simulation.
- Canonical MCP ingress for authenticated stdio and standard Streamable HTTP,
  including adapter-derived source/protocol/environment/idempotency and
  tenant/adapter-bound status reads.
- OAuth protected-resource metadata and strict per-request RS256 bearer
  validation for `/mcp`; authorization-code/PKCE remains the external
  authorization server's responsibility.
- Signed MCP transport sessions, exact-origin validation, bounded JSON-RPC
  input/output, same-session replay/conflict handling, and conformance tests
  across memory, SQLite, and optional Postgres.
- Verified MCP influence scopes, bounded/idempotent content-exposure storage,
  explicit source-integrity policy intersection, pre-release result evidence,
  binding revalidation, result withholding, and minimized lifecycle audit.
- Trusted approval review hashes bound to approval id, tool call id, envelope hash, and policy version.
- Stored original input/envelope binding validation, edited-input policy evaluation, and active-policy revalidation before approval finalization and execution authorization.
- Signed receipts for policy allow and final human approval decisions.
- Signed one-time external execution grants bound to receipt, tool call, tool name, approved input hash, approved envelope hash, policy version hash, expiry, and nonce.
- Atomic storage transitions for approval finalization and one-time execution-grant consumption; multi-approval edited payloads are rejected rather than merged without consensus.
- External execution outcome reporting that appends receipt outcomes and moves authorized calls to executed or failed.
- Governed remediation plans for supported successful outcomes, submitted as linked normal tool calls rather than privileged undo operations.
- Hash-chained audit events with verification endpoint.
- Redacted API reads for common secret keys and configured policy redaction fields.
- Policy-detector observations store tool names, source metadata, schema hashes, and suggestions, not raw tool-call inputs.
- Atomic workspace/route-scoped idempotency keys for HTTP/core tool-call submission. The reservation and initial tool-call row commit together, so only one same-key/same-request winner continues lifecycle side effects and different payloads conflict.
- Additive `actionproxy.execution-attempt.v1` reservation before local/forwarded execution, with one attempt per workspace/tool call, atomic grant-consume/dispatch, immutable normalized outcomes, and no automatic retry or reservation takeover.
- Additive `actionproxy.execution-authorization.v1` with one-use process-local tokens, a credential-free evidence projection, conservative executor capabilities, mandatory local-registry consumption, current-state external grant-dispatch consumption, and executor non-invocation tests.
- Body size limit, basic rate limiting, strict CORS allowlist, and security headers.
- Local integration secret writes blocked in enterprise auth modes; enterprise secrets must come from environment or secret injection.

## Still not claimed

ActionProxy does not yet claim:

- SOC 2 readiness or certification.
- SCIM lifecycle management.
- SAML support.
- Multi-tenant service operation or public signup.
- Customer-managed encryption keys.
- Formal retention/deletion workflows.
- An OAuth authorization server, login/consent flow, authorization-code
  or PKCE implementation, or client-registration service.
- Live ChatGPT developer-mode interoperability or plugin publication.
- Prompt-injection detection, prevention, content safety, DLP, page scanning,
  hostname reputation, redirect/final-origin attestation, or model-memory reset.
- Governance of host-native tools, direct network or shell
  access, unmediated credentials, or any action path not routed through a
  configured ActionProxy adapter.
- Conversation identity for stdio MCP influence scopes; a wrapper process is a
  transport-wide scope and may span conversations.
- Production SaaS connector credential custody or execution.
- Universal rollback for sent messages, hard deletes, financial side effects, or tools that do not provide prior state and safe remediation semantics.
- Multi-process audit-chain append serialization across multiple server instances.

## Security principle

The product should never ask operators to trust an autonomous agent broadly. It
provides a narrow, logged, policy-controlled execution path where the security
question is: should this normalized payload and policy context run now? Within
the fields represented by the current envelope, receipts and one-time grants
authorize only the hashed action instance. This developer preview is not a
complete production compliance boundary.
