# Architecture

ActionProxy Community is an execution-governance gateway. It receives a
proposed tool call, evaluates deterministic policy, executes it immediately or
pauses it for review, and records evidence for every lifecycle transition.

It is not an agent runtime, connector marketplace, browser, model gateway, or
workflow builder.

## Request lifecycle

```text
agent / SDK / MCP host
          |
          v
authenticated ingress adapter
          |
          v
canonical action request + strict validation
          |
          v
deterministic policy evaluation
      /        |         \
   allow    approval      deny
     |          |           |
     |       reviewer       +--> blocked + audit
     |          |
     +----------+
          |
          v
exact execution authorization
          |
     +----+------------------+
     |                       |
local mock registry    external runner / MCP
     |                       |
     +-----------+-----------+
                 |
                 v
       immutable outcome + audit
```

Routes validate transport input and derive trusted request context. The
`ActionProxyService` owns lifecycle transitions. Policy evaluation is pure.
Storage and execution remain behind interfaces.

## Community composition

The normal server entrypoint registers only:

- health, authentication, tool-call, approval, receipt, grant, audit, policy,
  dashboard, approver, and approval-channel routes;
- the authenticated stdio MCP adapter and standard Streamable HTTP `/mcp`;
- local mock tools when explicitly enabled;
- memory, SQLite, and Postgres stores;
- the local operator console.

The normal web entrypoint is also fixed. It renders the local Community
console, guided lifecycle demo, policy and approval views, approval-channel
configuration, MCP setup, runner queue, and audit evidence. It does not discover
product shape from a runtime capability endpoint.

Import-boundary tests enforce that Community entrypoints cannot reach modules
outside this composition. The public candidate exporter copies only classified
Community paths and verifies the resulting tree.

## Ingress and canonical requests

Supported ingress paths are:

- `POST /v1/tool-calls` for HTTP and SDK callers;
- `POST /v1/mcp/tool-calls` for authenticated stdio wrappers;
- `POST /mcp` for the OAuth-protected Streamable HTTP MCP resource.

Each adapter derives authoritative workspace, principal, protocol, source,
environment, session, and idempotency context from trusted server state.
Caller-provided metadata is treated as an assertion and cannot override these
fields. Duplicate JSON keys and unknown top-level request fields fail
validation.

The versioned `actionproxy.action-request.v1` evidence is computed before
policy evaluation. Approval reviews, receipts, execution attempts, and grants
bind the normalized action envelope and input hashes.

## Authentication and authorization

Local development may use `ACTIONPROXY_AUTH_MODE=none` only on a safe loopback
binding. Self-hosted deployments use API keys or RS256 OIDC JWTs. Route handlers
require explicit scopes from a server-derived `AuthContext`; request bodies
cannot choose their own workspace or authority.

Approver records can bind delivery identities to authenticated principals.
Separation of duties, approver groups, multi-approval requirements, expiry, and
cancellation are enforced by the service and atomic storage transitions.

The standard `/mcp` endpoint is an OAuth 2.1 protected resource, not an
authorization server. An external authorization server owns login, consent,
authorization code with PKCE, client handling, and token issuance. ActionProxy
validates issuer, exact resource audience, time bounds, subject, OAuth client,
scope, and a compatible RS256 key on every request.

## Policy

The YAML policy evaluator is deterministic and side-effect free. Rules match
tool names exactly or by a terminal wildcard such as `salesforce.*`. A decision
is one of:

- `allow`;
- `require_approval`;
- `deny`.

Unknown tools require approval by default. The destructive demo tool is denied
by the bundled policy. Policy decisions include the selected rule and policy
version hashes used by later revalidation.

Content-influence rules may only preserve or narrow the base result. They never
turn approval or denial into automatic execution.

## Approval lifecycle

A pending approval retains the original proposed input and its envelope hash.
If a reviewer edits the input, ActionProxy keeps both the original and edited
payloads, evaluates the edited action again, and binds subsequent evidence to
the accepted input hash.

Atomic compare-and-set transitions ensure one final decision wins a concurrent
approval race. Repeated approval, rejection, cancellation, or expired review
attempts cannot dispatch the action twice.

Slack, Telegram, and email are direct approval-notification channels. The local
email default is a filesystem outbox; an operator-owned SMTP server is optional.
Notification delivery does not replace approval authorization.

## Execution boundary

Local execution is disabled by default. `ACTIONPROXY_LOCAL_EXECUTION=mock`
registers deterministic demo tools only.

Every execution path requires `actionproxy.execution-authorization.v1`, a
non-serializable process-local authority bound to current lifecycle state.
Local tool closures cannot be called through `ToolRegistry` without consuming
that authority.

External runners receive a signed, exact, expiring, single-use grant. Grant
consumption atomically reserves one execution attempt before dispatch. A grant
is bound to workspace, tool call, tool name, input and envelope hashes, policy,
receipt, expiry, and nonce. A replay, mismatch, stale policy, expired grant, or
second consumer fails before dispatch.

Timeouts and disconnects are not proof of cancellation. Ambiguous results are
recorded without automatic retry. A runner reports its immutable outcome back
through the grant endpoint.

## MCP adapters

The stdio wrapper exposes an MCP server to a host while sending every downstream
tool call through ActionProxy. Static and discovery modes share the same
lifecycle. Discovery commands are executable configuration and are disabled on
the server unless explicitly enabled by an operator.

The Secure MCP Tunnel example runs:

```text
ChatGPT -> OpenAI Secure MCP Tunnel -> ActionProxy stdio wrapper
        -> loopback ActionProxy -> deterministic mock MCP child
```

It exposes exactly `docs.search`, `gmail.send_email`, and
`dangerous.delete_customer`. The runtime key belongs only to the tunnel client;
ActionProxy does not store or forward it. This local demo is not an end-user
identity boundary.

The standard `/mcp` resource is the advanced path. Sessions are signed and
bound to tenant, principal, OAuth client, resource, and protocol version.
Origins, body sizes, response sizes, request duration, replay, cancellation,
and cross-session status reads are bounded or rejected.

## Content-influence controls

Authenticated MCP transports create opaque influence scopes from verified
workspace, principal, adapter, protocol, and transport state. Arguments, result
metadata, tool descriptions, and ordinary HTTP metadata cannot mint a scope or
assign integrity.

Before classified model-visible output is released, ActionProxy writes a
minimized content-exposure record and audit event. Raw downstream content is not
placed in that exposure row, although full tool inputs and results still exist
elsewhere in lifecycle storage. If exposure persistence fails after execution,
the known outcome is preserved and the result is withheld without redispatch.

Influence evaluation performs a bounded scope lookup. Missing evidence,
overflow, unavailable storage, or an unverified scope becomes `unknown` and
fails closed according to policy. Scope revision and policy bindings are checked
again before approval finalization and immediately before dispatch.

These controls constrain consequences after potentially hostile content; they
do not claim prompt-injection detection, content safety, DLP, browser isolation,
or model-memory reset.

## Storage and migrations

`Store` and `AuditStore` interfaces isolate lifecycle logic from persistence.
Community implementations are:

- memory plus JSONL audit for ephemeral local development;
- SQLite for durable single-node evaluation;
- Postgres for operator-managed deployments.

Canonical SQL migrations are immutable, ordered artifacts. The migrator records
versions and checksums, applies each migration transactionally, uses a
cross-process SQLite lock or Postgres advisory lock, and rejects checksum
changes. Explicit reconciliation recognizes known pre-release Community schema
states while preserving core lifecycle, approver, audit, receipt, and exposure
records.

Audit events are append-only and hash chained. Verification detects changed or
missing chain entries but does not prevent a storage administrator from deleting
the entire store. Multi-process serialization of audit appends is not claimed.

## Web application

The local web console consumes only Community APIs. Its first-run checklist
walks through allow, approval, reject/approve, deny, and audit evidence before
connection and hardening guidance. Browser storage contains correlation ids and
UI progress only, not full gateway responses or secrets.

The Docker image serves the same built console from `/app`; Vite serves it at
the root during source development.

## Security and operational limitations

- Stored tool inputs, edited inputs, results, and audit payloads may contain raw
  sensitive data. API redaction is a read-time presentation control.
- The audit chain is not externally anchored.
- Local no-auth mode is unsuitable for production.
- MCP child processes run with the wrapper/server operating-system privileges;
  ActionProxy is not a process sandbox.
- Any host-native tool, shell, network path, or credential that bypasses
  ActionProxy remains outside its control.
- Community is a developer preview, not a complete production authorization or
  compliance boundary.

## Source map

- `apps/server/src/app.ts`: Community server composition.
- `apps/server/src/services/action-gate.ts`: lifecycle orchestration.
- `apps/server/src/policy/`: policy loading and evaluation.
- `apps/server/src/storage/`: storage interfaces, migrations, and adapters.
- `apps/server/src/security/`: auth, grants, receipts, audit chain, and content
  influence.
- `apps/server/src/routes/`: transport validation and response mapping.
- `packages/sdk-js/`: JavaScript HTTP SDK and external-runner helper.
- `packages/mcp-wrapper/`: stdio MCP proxy.
- `apps/web/src/`: local Community console.
