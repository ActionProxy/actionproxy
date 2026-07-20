# ActionProxy MCP Wrapper

Wrap downstream MCP servers with ActionProxy approval, one-time execution grants, and audit.

The wrapper is distributed as source in this repository. ActionProxy v0.1.0
does not publish npm packages, so build the workspace package before using the
local binary:

```bash
corepack pnpm install
corepack pnpm --filter @actionproxy/mcp-wrapper build
./packages/mcp-wrapper/dist/index.js wrap --config actionproxy.mcp.yaml
```

The wrapper is a local stdio MCP server. A host connects to `actionproxy-mcp`, the wrapper reads tools from configured downstream MCP servers, and each `tools/call` is first submitted to ActionProxy. ActionProxy authorizes the call; the downstream MCP server still owns the real tool implementation and credentials.

## CLI

```bash
./packages/mcp-wrapper/dist/index.js wrap --config actionproxy.mcp.yaml
```

Inspect the configured tool plane without starting a downstream process or
contacting ActionProxy:

```bash
./packages/mcp-wrapper/dist/index.js doctor --config actionproxy.mcp.yaml
./packages/mcp-wrapper/dist/index.js doctor --config actionproxy.mcp.yaml --json
```

Opt in to bounded downstream discovery when you are ready to run the configured
commands. Discovery performs MCP `initialize` and one `tools/list`, then closes
each process. It never calls a tool and still does not contact ActionProxy:

```bash
./packages/mcp-wrapper/dist/index.js doctor --config actionproxy.mcp.yaml --discover
```

`--discover` is protocol-read-only, not process-safe: it executes each
configured child command with its configured OS privileges. Child startup is
not sandboxed, and a malicious process can act during initialization without a
`tools/call`. Run discovery only for reviewed configurations in an isolated
environment appropriate to those commands.

Doctor output uses `actionproxy.tool-plane-report.v1` with
`coverage: configured_mcp_wrapper`. Its explicit `unverified` list distinguishes
configuration inspection from endpoint, host-registration, policy, approval,
execution, and audit verification.

The report does not verify agent-host configuration, host-native or provider-
hosted tools, direct network or shell access, unmediated credentials,
conversation identity, ActionProxy server policy, or prompt-injection
resistance. Registering only this wrapper in the MCP host is an operator
responsibility; doctor cannot inspect or disable alternate host capabilities.

## Config

```yaml
actionproxy:
  baseUrl: http://localhost:8787
  bearerTokenEnv: ACTIONPROXY_MCP_BEARER_TOKEN
  requestedBy: mcp-host@example.com
  agentId: actionproxy-mcp-wrapper
  approvalPollIntervalMs: 1000
  approvalTimeoutMs: 120000
  requestTimeoutMs: 30000

servers:
  demo:
    command: node
    args: ["./examples/mcp-demo/server.mjs"]
    envPassthrough: [DOWNSTREAM_CREDENTIAL_REFERENCE]
    requestTimeoutMs: 30000

policies:
  gmail.send_email:
    approval: required
```

`policies` is documented intent for the wrapper config. Policy enforcement still happens in the ActionProxy server YAML policy.

`bearerTokenEnv` is an environment-variable name, never a token value. For an
authenticated deployment, create a wrapper service account with only
`tool_call:submit`, `tool_call:read`, and `execution_grant:consume`, then start
the wrapper with that variable set. Inline `token`, `bearerToken`, and `apiKey`
config values are rejected.

The wrapper passes only a small operating-system environment allowlist and
explicit `servers.<name>.env` entries to a downstream process. Existing parent
variables must be named individually under `envPassthrough`; only their names,
not values, enter YAML, and startup fails when a named variable is absent. The
ActionProxy bearer variable is always removed and cannot be passed through,
even with different casing. Raw child stderr is drained rather than copied into
ordinary wrapper logs.

## Behavior

- `tools/list` returns the downstream tools.
- `tools/call` submits the tool name and arguments to the trusted
  `POST /v1/mcp/tool-calls` adapter boundary.
- Allowed calls receive an execution grant, the wrapper consumes it, then forwards to the downstream MCP server.
- Approval-required calls wait until ActionProxy approval completes, consume the final execution grant, then forward downstream.
- Blocked or rejected calls return an MCP error result and do not call downstream.

Every submission carries a stable, random wrapper-session UUID in
`X-ActionProxy-MCP-Session-Id`. Valid downstream results that will be returned
to the model are reported before release with bounded
`actionproxy.result-delivery.v1` evidence: a model-visible flag, canonical JSON
SHA-256 hash, and canonical byte count. This also applies to valid MCP
`isError: true` results. If outcome reporting fails, the result is withheld.
Transport exceptions have no trusted model-visible result and return only a
static wrapper message; child-provided exception text is not copied into the
host response.

The server derives an opaque influence scope from the UUID plus authenticated
workspace, principal, adapter, protocol, and transport state. The raw UUID is
not persisted or returned. Administrator-reviewed `resultSource` policy labels
classify model-visible output before release; later `influence` rules can only
preserve, require approval, or deny relative to base policy. Integrity is
adapter provenance, not content safety or instruction authority. A generic web
tool is `public_untrusted`, and no hostname or vendor is automatically trusted.
`instructionAuthority: none` is ActionProxy policy/exposure/audit evidence, not
a mutation of the child result. The valid child payload, including `_meta`, is
opaque and unchanged; child assertions cannot grant authority or authorize a
later action.
One wrapper process may span conversations, and restarting it does not prove
the model cleared persistent memory.

When enabling influence on an existing installation, start a fresh wrapper
process and clear prior agent context where the host permits it. Reads released
before opt-in were not classified or recorded, so the new scope can isolate
future enforcement but cannot retroactively account for earlier content.

The wrapper sets `metadata.actionproxyExecution = "external"` so ActionProxy authorizes the call but does not require a gateway-side tool implementation for arbitrary downstream MCP tools.
If ActionProxy does not return a valid grant, or if grant consumption fails, the wrapper fails closed and does not call the downstream tool.

Each stdio process creates a random transport-session nonce. A typed JSON-RPC
request id and that nonce deterministically produce the `Idempotency-Key`: a
repeated numeric id is stable, numeric `1` differs from string `"1"`, and a
same-id changed payload reaches ActionProxy's conflict check. `tools/call`
notifications without an id are ignored and cannot create a side effect.

HTTP responses, stdio frames, newline buffers, discovered tool counts/schemas,
and tool results have conservative size limits. ActionProxy and downstream MCP
requests have timeouts. A downstream timeout after one-time grant consumption
is reported as `timed_out`; a disconnect, unconfirmed cancellation, malformed
output, or other transport ambiguity is `unknown_outcome`. Neither state is
retried automatically. Stdio idempotency is scoped to the running wrapper
session; process restart is not presented as safe recovery for an unknown
outcome.

## Scope

This package implements a bounded stdio JSON-RPC wrapper. The authenticated
ActionProxy server remains authoritative for tenant, actor, source protocol,
policy, approvals, execution attempts, and executor authorization. The wrapper
does not add a connector marketplace, identity provider, approval authority,
or retry/recovery engine.

It is also not a prompt-injection detector, content scanner, model gateway, or
proof that the host cannot bypass the wrapper.
