# API spec

This document describes the ActionProxy Community v0.1 HTTP surface. The API is
a developer preview and may receive additive changes before a stable release.

## Conventions

- Default base URL: `http://127.0.0.1:8787`.
- JSON request bodies use `Content-Type: application/json`.
- Unknown top-level submission fields fail strict validation with `400`.
- Duplicate JSON object keys are rejected before policy evaluation.
- IDs are opaque strings and must not be parsed for authority.
- Timestamps are ISO 8601 UTC strings.
- Tool input and result values are JSON objects.
- `Idempotency-Key` is recommended for every submission and required by the
  authenticated stdio MCP adapter.

Common errors use an `error` code and may include `message` or validation
`details`:

```json
{
  "error": "invalid_request",
  "message": "The request could not be validated."
}
```

Expected statuses include `400` invalid request, `401` unauthenticated, `403`
forbidden, `404` unknown record/route, `409` lifecycle or idempotency conflict,
and `500` internal failure.

## Authentication

`ACTIONPROXY_AUTH_MODE` selects one of:

- `none`: loopback development only; uses an implicit local administrator;
- `api_key`: `Authorization: Bearer <key>`;
- `oidc_jwt`: an RS256 bearer JWT validated against configured issuer,
  audience, key material, time bounds, subject, and scopes.

Handlers enforce scopes such as `tool_call:submit`, `tool_call:read`,
`approval:read`, `approval:decide`, `audit:read`, `policy:read`, `policy:write`,
`execution_grant:consume`, and `admin:integrations`. Authentication creates the
authoritative workspace/principal context; request bodies cannot select it.

The standard `/mcp` resource has stricter OAuth requirements described below.

## Health and console

### `GET /health`

Returns:

```json
{ "ok": true, "service": "actionproxy-server" }
```

### `GET /app` and `GET /app/*`

Serve the bundled Community console when `ACTIONPROXY_WEB_DIST_PATH` exists.
Docker exposes the console at `/app#/demo`.

## Tool calls

### `POST /v1/tool-calls`

Submits a proposed action. The strict body is:

```json
{
  "toolName": "gmail.send_email",
  "input": {
    "to": "customer@example.com",
    "subject": "Update",
    "body": "Resolved"
  },
  "requestedBy": "support-agent",
  "agentId": "agent-1",
  "reason": "Send the reviewed support update",
  "action": {
    "executionMode": "external_grant",
    "operation": { "kind": "external_send", "name": "send email" },
    "protocol": "actionproxy_http",
    "resources": [{ "type": "email.recipient", "id": "customer@example.com" }],
    "source": { "type": "agent", "id": "agent-1" },
    "context": {}
  },
  "metadata": {}
}
```

Required fields are `toolName`, `input`, `agentId`, and `reason`.
`requestedBy` defaults to the authenticated principal. `action` and `metadata`
are optional assertions; the HTTP adapter derives trusted protocol, actor,
workspace, environment, and idempotency context itself.

`action.executionMode` is `local_mock` or `external_grant`. Operation kinds are
`custom`, `delete`, `external_send`, `financial`, `read`, or `write`.

The response contains the stored `toolCall`, effective `decision`, and `reason`.
Depending on policy it may also contain:

- immediate local mock `result` and signed `receipt`;
- a pending `approval`;
- an authorized external `executionGrant` and `receipt`;
- a blocked record with no execution authority.

No downstream side effect is permitted while the call is pending or blocked.

### `GET /v1/tool-calls`

Lists workspace records. Optional query filters are `decision`, `status`,
`toolName`, `runId`, `sessionId`, and `limit` (`1..1000`). Returns
`{ "toolCalls": [...] }`.

### `GET /v1/tool-calls/:id`

Returns one redacted tool-call record.

### `GET /v1/tool-calls/:id/decision-trace`

Returns the selected exact/wildcard/default rule, sourced canonical policy
context, condition evaluation, policy identity, and any content-influence
intersection evidence.

### `GET /v1/tool-calls/:id/execution-attempts`

Returns immutable attempt reservations and normalized outcomes visible to the
current workspace.

### `GET /v1/tool-calls/:id/remediation-plan`

Returns an available governed remediation descriptor for a completed action,
or a not-found/conflict response when no safe descriptor exists.

### `POST /v1/tool-calls/:id/remediation`

Creates a new linked tool call from the stored descriptor. Optional fields are
`input`, `agentId`, `requestedBy`, `reason`, and `metadata`. The new call passes
through normal policy and never rewrites the original record.

## Approvals

### `GET /v1/approvals/pending`

Lists approvals the authenticated reviewer may inspect.

### `GET /v1/approvals/:id`

Returns the approval and related tool call with read-time redaction.

### `GET /v1/approvals/:id/review`

Returns exact review evidence, including original input/envelope hashes,
policy identity, eligible approvers, content-influence explanation when
applicable, and a `reviewHash` for decision binding.

### `POST /v1/approvals/:id/approve`

Approves the original payload:

```json
{
  "approvedBy": "reviewer@example.com",
  "inputDecision": { "mode": "original" },
  "reviewHash": "..."
}
```

Or approves edited input:

```json
{
  "approvedBy": "reviewer@example.com",
  "editedInput": { "to": "customer@example.com", "body": "Edited" },
  "inputDecision": {
    "mode": "edited",
    "input": { "to": "customer@example.com", "body": "Edited" }
  },
  "reviewHash": "..."
}
```

The service retains both original and edited payloads, re-evaluates policy, and
revalidates lifecycle/policy/influence bindings before authorization. Edited
input is not accepted for a multi-review approval.

### `POST /v1/approvals/:id/reject`

Rejects with reviewer identity and reason. It creates no execution grant.

### `POST /v1/approvals/:id/cancel`

Cancels an outstanding approval when the caller has the required authority.

### `POST /v1/approvals/:id/notifications/resend`

Retries configured notification delivery. It does not change the decision.

Approval finalization is atomic. Concurrent or repeated terminal requests can
produce only one winner and cannot execute twice.

## Authorized actions, grants, and receipts

### `GET /v1/authorized-actions`

Lists exact external actions that have an available execution grant for the
workspace runner queue.

### `POST /v1/execution-grants/:id/consume`

Atomically consumes a signed single-use grant before downstream dispatch. The
request repeats the exact binding information required by the SDK runner. A
replay, expiry, mismatched action/input/envelope/receipt/policy, or stale
authorization fails before an execution attempt is opened.

### `POST /v1/execution-grants/:id/outcome`

Reports one normalized downstream outcome for the consumed attempt. Outcomes
cover success, failure, timeout, cancellation, and unknown/ambiguous results.
Reporting appends evidence and never authorizes another dispatch.

### `GET /v1/receipts/:id`

Returns a signed action receipt with policy/approval binding and immutable
outcome history. This audit-scoped evidence endpoint intentionally includes the
receipt signature; unlike tool-call projections, it never returns an execution
grant nonce or signature. Receipts authorize only the exact hashed action
instance.

## Audit

### `GET /v1/audit`

Lists redacted audit events. Filters include workspace-scoped identifiers,
event type, time range, cursor, and bounded limit.

### `GET /v1/audit/export`

Streams an operator export of audit evidence for the authenticated workspace.

### `GET /v1/audit/verify`

Recomputes the append-only hash chain and returns verification status plus the
first detected break. The chain is not externally anchored.

Stored audit payloads may contain full sensitive inputs/results even when the
API representation is redacted.

## Policy

### `GET /v1/policy`

Returns the current parsed policy file.

### `GET /v1/policy/summary`

Returns deterministic rule counts and current policy identity for the console.

### `GET /v1/policy/presets`

Returns fixed Community demo presets. Presets are authoring suggestions; the
loaded YAML remains authoritative.

### `POST /v1/policy/simulate`

Evaluates a proposed tool call without approval creation or execution. It uses
the same strict canonical HTTP context and returns decision trace evidence.

### `PUT /v1/policy`

Validates and writes the local YAML policy, records an audit event, and updates
policy for later submissions. Existing records are not rewritten.

### Policy detector

- `GET /v1/policy/detector`
- `POST /v1/policy/detector/:id/apply`
- `POST /v1/policy/detector/:id/dismiss`

Detector records contain tool/source/schema metadata and suggestions, not raw
tool inputs. Applying a suggestion creates an ordinary validated YAML rule.

## Approver directory

- `GET /v1/approvers`
- `POST /v1/approvers/users`
- `PUT /v1/approvers/users/:id`
- `DELETE /v1/approvers/users/:id`
- `POST /v1/approvers/groups`
- `PUT /v1/approvers/groups/:id`
- `DELETE /v1/approvers/groups/:id`

Telegram identity linking uses:

- `POST /v1/approvers/users/:id/telegram-connect`
- `POST /v1/approvers/users/:id/telegram-connect/poll`
- `DELETE /v1/approvers/users/:id/telegram-connection`

Directory delivery identifiers do not grant approval authority. Authenticated
principal/group checks remain authoritative.

## Approval channels and MCP profiles

### `GET /v1/integrations`

Returns Community integration status for Slack, Telegram, email, local mock
tools, and MCP wrapper profiles. Secret values are never returned.

Channel configuration/test routes are:

- `PUT /v1/integrations/slack`
- `POST /v1/integrations/slack/test`
- `PUT /v1/integrations/telegram`
- `POST /v1/integrations/telegram/test`
- `PUT /v1/integrations/email`
- `POST /v1/integrations/email/test`

The email transport is local outbox or operator-owned SMTP. Callback routes are
`POST /v1/slack/interactions` and `POST /v1/telegram/webhook`; each validates
the provider signature/secret and maps the provider identity to an authorized
principal.

Local mock-tool configuration uses `PUT /v1/integrations/tools/:id`.

MCP wrapper profiles use:

- `PUT /v1/integrations/mcp-wrapper/profiles/:id`
- `GET /v1/integrations/mcp-wrapper/profiles/:id/yaml`
- `POST /v1/integrations/mcp-wrapper/profiles/:id/sync-tools`

Profile IDs are restricted to `A-Z`, `a-z`, digits, `.`, `_`, and `-`. A profile
contains one downstream command plus ActionProxy connection/polling settings.
Server-side discovery is disabled unless explicitly enabled because profile
commands run with the server process's operating-system privileges.

## Auth administration and dashboard

- `GET /v1/me` returns the current server-derived identity and scopes.
- `POST /v1/service-accounts` creates a scoped service account.
- `POST /v1/service-accounts/:id/keys` creates a key whose plaintext is returned
  only once; stored key material is hashed.
- `GET /v1/dashboard/overview` returns the Community console summary.

## Authenticated stdio MCP adapter

### `POST /v1/mcp/tool-calls`

Uses the same strict body as `POST /v1/tool-calls`. It additionally requires a
header-safe `Idempotency-Key` and canonical UUID in
`X-ActionProxy-MCP-Session-Id`. The adapter derives its identity, protocol,
execution mode, idempotency, and opaque influence scope. Body metadata cannot
mint these values.

### `GET /v1/mcp/tool-calls/:id`

Requires the same session header and rejects reads from another authenticated
principal, OAuth/API client, adapter, or influence scope.

## Standard Streamable HTTP MCP

The advanced `/mcp` path is experimental and production-shaped, not
production-complete.

### Protected-resource metadata

- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-protected-resource/mcp`

The metadata names the exact configured resource and external authorization
server. ActionProxy is not the authorization server.

### `POST /mcp`

Accepts Streamable HTTP MCP JSON-RPC for initialization, tool listing, tool
calls, status/resume behavior, and cancellation. Requests require an RS256 OAuth
access token with exact `/mcp` audience/resource binding, least-privilege scopes,
subject, and unambiguous `client_id`/`azp` identity. API keys, implicit local
identity, wildcard scopes, and wrong-audience tokens are rejected.

Sessions are signed and bound to workspace, principal, OAuth client, resource,
and MCP protocol version. Exact same-session replay returns the prior result;
changed replay conflicts. Request/response sizes, origin, and duration are
bounded. A transport timeout does not prove provider cancellation and is never
automatically retried.

### `GET /mcp` and `DELETE /mcp`

Support the Streamable HTTP session transport behavior and authenticated
session termination where applicable.

See `CHATGPT_MCP.md` for deployment responsibilities and honest limitations.

## Compatibility boundary

The compatibility target is the existing pre-release core tool-call, approval,
receipt, audit, approver, and content-exposure data recognized by Community
migrations. Interfaces outside this documented v0.1 surface have no public
compatibility guarantee. An unknown Community route returns `404`.
