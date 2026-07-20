# ActionProxy Community threat model

This threat model defines the controls and limitations of ActionProxy Community
v0.1.0.

## Local ChatGPT Secure MCP Tunnel demo

| Actor or failure mode | Threat | Current control |
|---|---|---|
| Local launcher or logs | Leaks the OpenAI Platform runtime key | The launcher requires `CONTROL_PLANE_API_KEY` from the environment, redacts subprocess output, never places it in command arguments, and writes only a non-secret versioned marker. |
| Tunnel profile | Bypasses ActionProxy by starting the downstream server directly | The initialized profile contains one stdio command, the ActionProxy wrapper; wrapper discovery must return exactly the three reviewed demo tools before tunnel startup. |
| ChatGPT caller | Treats tunnel/workspace association as end-user identity inside ActionProxy | Explicitly out of scope: the Docker demo remains `AUTH_MODE=none` with implicit local admin and is not a production identity boundary. |
| Destructive tool | Dispatches the simulated delete despite the demo claim | Default policy denies `dangerous.delete_customer` before grant creation or downstream dispatch; smoke/audit tests assert the absence of execution evidence. |
| Browser UI | Captures an API key or starts a local process | The panel keeps only the tunnel id in React memory and generates a copyable terminal command; it has no credential field or launcher backend API. |
| Tunnel disconnect | Leaves the user believing the bridge is active | Foreground `tunnel-client run` exit is terminal and reported clearly; signals are forwarded to the client. ActionProxy deliberately stays up until the operator runs `docker compose down`. |

## Streamable HTTP MCP

The standard `/mcp` endpoint adds an Internet-facing OAuth resource-server
boundary. ActionProxy does not own the authorization-code or PKCE flow: an
external OAuth 2.1 authorization server authenticates the user and issues an
access token for the exact `/mcp` resource.

| Actor or failure mode | Threat | Current control |
|---|---|---|
| MCP client or token thief | Uses an API key, local identity, expired token, wrong issuer/audience, wildcard scope, or ambiguous client identity | `/mcp` accepts only per-request RS256 JWT bearer validation with exact issuer/resource audience, expiry/not-before, `sub`, matching `client_id`/`azp`, least-privilege scopes, and a unique compatible JWKS key. |
| Malicious MCP caller | Forges tenant, actor, adapter, protocol, environment, policy facts, or executor authority in tool arguments/metadata | The adapter constructs canonical provenance from OAuth, server, and signed-session state; tool input remains asserted and cannot override authoritative context. |
| Replayed or changed request | Duplicates a side effect or reuses a JSON-RPC id for another payload | A signed session plus typed JSON-RPC id derives tenant/adapter/resource-scoped idempotency; exact replay returns the existing action and changed payload conflicts without another dispatch. |
| Cross-adapter status request | Reads or resumes another OAuth client's action | Status/resume verifies tenant and OAuth client against stored canonical, envelope, and authenticated-request evidence. |
| Browser or DNS-rebinding origin | Reaches a loopback/network MCP resource from an untrusted site | Supplied `Origin` values must exactly match `ACTIONPROXY_MCP_ALLOWED_ORIGINS`; startup requires HTTPS except explicit loopback development. |
| Timeout, disconnect, or cancellation ambiguity | Treats an uncertain post-dispatch result as retry-safe | The transport response is explicitly not retry-safe and the adapter never retries automatically. The underlying attempt may later settle; an external runner records `timed_out`/`unknown_outcome` when that is what it can establish. A transport timeout does not claim provider cancellation. |
| Authorization-server compromise or misconfiguration | Issues an over-scoped or incorrectly audience-bound token | ActionProxy independently validates token signature, exact audience, issuer, time, client identity, and scopes. User authentication, consent, PKCE, registration, revocation, and authorization-server operations remain external residual risk. |

The implemented endpoint has no OpenAI runtime or connector dependency and
currently dispatches only local mock tools. A live ChatGPT connection through
the operator's public HTTPS and OAuth deployment remains a manual acceptance
test; the automated protocol suite is not evidence of plugin publication or a
complete production deployment.

## Verified MCP content-influence addendum

This addendum applies to the authenticated stdio wrapper and standard `/mcp`
transport only. It limits consequences after classified content reaches a model;
it does not detect or prevent prompt injection.

| Actor or failure mode | Threat | Current control |
|---|---|---|
| MCP caller | Supplies a forged session, source class, trusted hostname, annotation, tool description, or result `_meta` | The stdio route requires a canonical wrapper UUID and derives an opaque scope from authenticated workspace/principal/adapter/transport state; `/mcp` uses its signed session. Only the frozen administrator-selected policy rule assigns integrity. |
| Hostile public result | Injects instructions that cause a later write, memory update, send, or encoded follow-up read | Before releasing classified output, ActionProxy records an exposure. A later action rule may explicitly preserve, require approval, or deny according to every class observed in that verified scope; base policy can never be weakened. |
| Downstream MCP `isError` result | Hides hostile model-visible content behind an error flag | Valid `isError: true` results receive the same result-delivery hash/count validation and pre-release exposure record as successful MCP content. |
| Child transport exception | Smuggles child-controlled text into the model without exposure evidence | The wrapper returns a static sanitized transport error; it does not release child exception text as a valid MCP result. |
| Exposure storage or audit failure after provider success | Releases untracked content or retries a side effect | ActionProxy preserves the known provider outcome, withholds the result, leaves the one-time grant consumed, and never automatically redispatches. |
| Large or corrupt scope history | Forces unbounded policy work or gets treated as clean | Lookup is bounded and indexed; overflow, missing storage/classification, or absent verified scope becomes `unknown` and narrows according to policy. |
| Stale approval/grant | Uses an authorization after exposure or policy changed | The bound exposure snapshot, scope, policy, workspace, input, and source evidence are revalidated before approval finalization and immediately before local/external dispatch. A mismatch fails closed before the executor. |
| Wrapper/host bypass | Agent calls a host-native/provider tool, shell, network, or unmediated credential directly | Not controlled by ActionProxy. Operator examples use exactly one MCP registration (the wrapper), but the real host must disable or restrict every remaining bypass. Doctor reports only `configured_mcp_wrapper` coverage. |
| Cross-conversation memory | Uses content remembered across a new transport scope | Not controlled. A wrapper process/session can span conversations, and starting a new scope does not prove persistent model memory was cleared. |

Integrity classes never grant instruction authority in ActionProxy policy,
exposure, or audit semantics. Valid child MCP result payloads, including
`_meta`, remain opaque and unchanged; a child assertion of authority is still
untrusted content and cannot authorize an action. A generic web adapter is
`public_untrusted`; `verified_publisher` requires a dedicated constrained
adapter. No provider or hostname—including Google—is intrinsically trusted.
Dynamic redirect/final-origin attestation, content scanning, DLP, quarantine,
prompt classifiers, and cross-call URL decoding are outside this release.

## Core gateway

ActionProxy receives proposed AI-agent tool calls, evaluates policy, handles
approvals, authorizes external runners, and records audit events. The release
targets local and self-hosted evaluation. Multi-tenant service operation,
billing, SCIM, SAML, and compliance certification are out of scope.

## Assets

- Tool-call payloads and edited approval payloads.
- Policy files and policy version records.
- Service-account API keys.
- OIDC and Slack identity mappings.
- Pending approvals and decision history.
- External execution grants.
- Audit event chain.
- Integration configuration and generated MCP profiles.

## Trust boundaries

- Agent or SDK caller to ActionProxy HTTP API.
- Human browser/admin UI to ActionProxy HTTP API.
- Slack callback to ActionProxy Slack endpoint.
- MCP/external runner to execution-grant consume endpoint.
- ActionProxy to local storage or Postgres.
- ActionProxy operator to environment/secret injection.
- Self-hosted operator to workspace configuration.

## Threats and controls

| Actor or failure mode | Threat | Current control |
|---|---|---|
| Agent submitter | Spoofs `requestedBy` or submits outside its authority | Authenticated modes derive the actor from the API key or OIDC JWT; `requestedBy` is not authorization evidence. |
| Agent submitter | Replays a submission | `Idempotency-Key` binds retries to a request hash. |
| Human approver | Approves outside their group | Approval routes require approval scopes and configured approver groups. |
| Human approver | Approves their own submitted action | `separationOfDuties` blocks same-principal approval/rejection. |
| Slack callback | Forged button request | Slack request signature and timestamp are verified. |
| Slack user | Valid Slack user approves without ActionProxy authorization | Enterprise modes require Slack user mapping to a principal with approval scopes/groups. |
| MCP/external runner | Executes a different payload than approved | Execution grant is bound to tool call id, tool name, input hash, policy hash, expiry, and nonce. |
| MCP/external runner | Replays a prior authorization | Execution grants are one-time consumable and expire. |
| Concurrent approvers or runners | Races approval finalization or grant consumption to duplicate a side effect | Storage-level conditional transitions select one final approval winner and one grant-consumption winner; service side effects run only for the winning transition. |
| Policy admin | Changes policy without trace | Policy updates produce audit events. |
| Storage admin | Mutates audit history | Audit events are hash chained and verifiable with `/v1/audit/verify`. |
| Audit reader | Sees secrets in API/UI reads | Common secret keys and policy redaction fields are redacted before API responses. |
| Compromised downstream tool | Attempts to bypass ActionProxy | Gateway mode requires external runners to consume grants before forwarding authorized calls. |
| Integration admin | Stores secrets in local config in enterprise mode | Slack bot token/signing secret writes to local config are blocked outside `AUTH_MODE=none`. |
| Integration admin or modified profile | Executes an untrusted MCP stdio command on the server | Server-side MCP stdio discovery is disabled by default and requires `ACTIONPROXY_MCP_STDIO_DISCOVERY_ENABLED=true`; operators must restrict `admin:integrations` and trust reviewed profiles because enabled commands are not sandboxed. |
| Self-hosted operator | Misconfigures a workspace or approval route | Use explicit CORS origins, named approvers, durable storage, and audit verification before exposing the service. |
| Web/API client | Sends oversized or high-rate requests | Fastify body limit and in-memory rate limit apply before route logic. |

## Residual risks

- Local `AUTH_MODE=none` is intentionally unsafe for production.
- JWT verification is based on configured static JWKS material; automatic JWKS refresh is not implemented.
- Rate limiting is process-local, not distributed.
- Audit hash-chain verification detects mutation but does not prevent a storage admin from deleting all records.
- Redaction protects API reads but does not remove sensitive values from stored audit records.
- Multi-tenant isolation, automated backups, retention/deletion workflows, and
  operational monitoring are not supplied as a managed service.
- Full retention, deletion, SIEM forwarding automation, SCIM, SAML, billing,
  and SOC 2 evidence workflows remain outside this release.
