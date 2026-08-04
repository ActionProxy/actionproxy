# Use ActionProxy With MCP Or External Runners

ActionProxy can sit beside an MCP server, internal API runner, queue worker, LangGraph node, or another gateway. It should not replace those systems or take their credentials by default.

Recommended split:

- The agent or MCP host proposes a tool call to ActionProxy.
- ActionProxy normalizes the action envelope, evaluates policy, queues approval when needed, signs a receipt, and issues a one-time execution grant.
- The external runner consumes the grant with the exact approved tool name, tool-call id, input, and policy hash.
- The runner executes the real downstream call with its own credentials.
- The runner reports `succeeded` or `failed` back to ActionProxy.

## SDK Helper

```ts
import { ActionProxyClient, runExternalAction } from '@actionproxy/sdk-js';

const client = new ActionProxyClient({
  baseUrl: 'http://127.0.0.1:8787',
});

await runExternalAction({
  client,
  toolName: 'jira.create_issue',
  input: { projectKey: 'SUP', summary: 'Follow up with customer' },
  requestedBy: 'agent@example.com',
  agentId: 'support-agent',
  reason: 'Create a tracked support follow-up.',
  metadata: { source: 'internal-runner' },
  execute: async (approvedInput) => {
    return fakeJiraCreateIssue(approvedInput);
  },
});
```

`runExternalAction` submits with `metadata.actionproxyExecution = "external"` and `action.executionMode = "external_grant"`, waits for authorization, consumes the grant, calls `execute`, and reports the downstream outcome. If grant consumption is rejected because of replay, expiry, policy mismatch, or input hash mismatch, `execute` is not called.

## MCP Pattern

For MCP, keep your existing downstream MCP server as the owner of real tool credentials. Put ActionProxy's MCP wrapper in front of it:

```bash
/absolute/path/to/actionproxy/actionproxy integrate --mode mcp --json
```

That command creates a new, non-overwriting, credential-free starter with a
three-tool downstream fixture. Its exact `@actionproxy/mcp-wrapper@0.1.0`
dependency points to a local tarball that the generated preparer builds from
the reviewed ActionProxy checkout; it neither assumes nor probes npm registry
availability. The generated policy is a sample and is not loaded by
`./actionproxy local`. Doctor proves exact mock-tool discovery only; complete
the host-driven policy, approval, execution, and audit checks before replacing
the fixture.

The versioned MCP-wrapper configuration data model is
[`schemas/actionproxy.mcp-wrapper.v1.schema.json`](../schemas/actionproxy.mcp-wrapper.v1.schema.json).
It is draft 2020-12 generated output. Runtime parsing remains authoritative for
environment-variable credential isolation and other checks JSON Schema cannot
express.

Terminal 1 — start ActionProxy without local tool execution:

```bash
corepack pnpm dev:proxy
```

Terminal 2 — build and run the wrapper:

```bash
corepack pnpm --filter @actionproxy/mcp-wrapper build
./packages/mcp-wrapper/dist/index.js wrap --config examples/mcp-demo/actionproxy.mcp.yaml
```

The wrapper maps MCP `tools/call` requests into ActionProxy proposals, waits for approval, consumes the grant, forwards only the approved call to the downstream server, then reports the outcome.

### Local ChatGPT tunnel example

For a Docker-first ChatGPT demonstration, the Secure MCP Tunnel launcher gives
OpenAI `tunnel-client` exactly one stdio MCP command: this wrapper. The wrapper
then mediates the three deterministic demo tools through the local gateway:

```bash
./actionproxy chatgpt
```

The concierge guides tunnel access, tunnel-ID entry, and `tunnel-client`
installation/recheck; `--tunnel-id` remains available for automation. A missing
client offers an explicit `I` choice, and the same reviewed local operation is
available as `./actionproxy tunnel-client install|status|remove [--json]`.
Installation is limited to the checksum-pinned official OpenAI `v0.0.10` asset
at `.actionproxy/bin/tunnel-client`, without `sudo`, a `PATH` change, or a
Gatekeeper change. The upstream binary is ad-hoc signed rather than Developer
ID-signed/notarized; it is optional, downloaded after checkout, and outside the
repository SBOM. Receipt-bound removal refuses active, modified, and manually
placed clients, while `stop` and `reset` retain it. This bootstrap convenience
does not change the MCP governance or credential-custody boundary.

The launcher requests the runtime key with hidden terminal input and gives
`tunnel-client` a private temporary-file reference. The compatibility command
`corepack pnpm demo:chatgpt:tunnel -- --tunnel-id tunnel_...` delegates to the
same implementation.

The tunnel profile never points directly at the downstream MCP server. See
`examples/chatgpt-tunnel/README.md`. This is a local mock demonstration; use the
standard OAuth-protected `/mcp` endpoint for the advanced self-hosted ChatGPT
path.

Validate the config without starting children, or explicitly opt in to
initialization plus one bounded `tools/list` per configured server:

```bash
./packages/mcp-wrapper/dist/index.js doctor --config examples/mcp-demo/actionproxy.mcp.yaml
./packages/mcp-wrapper/dist/index.js doctor --config examples/mcp-demo/actionproxy.mcp.yaml --discover --json
```

The `actionproxy.tool-plane-report.v1` report covers only the configured wrapper.
Discovery never sends `tools/call`. It does not inspect the real host
registration or verify host-native/provider tools, direct network or shell
access, unmediated credentials, conversation identity, ActionProxy server
policy, or prompt-injection resistance. The supplied Codex, Claude, and generic
host examples each register exactly one MCP entry—the wrapper—but operators
must enforce that topology in the actual host.

The wrapper supplies a stable random UUID per process; ActionProxy derives an
opaque influence scope bound to authenticated workspace/principal/adapter state.
For classified model-visible results, the runner reports
`actionproxy.result-delivery.v1` hash/count metadata and ActionProxy records a
minimized exposure before release. Valid `isError: true` MCP results are
included. If evidence persistence fails after a known downstream outcome, the
result is withheld and the action is not retried.

Later tool rules may use `influence` to require approval or deny based on an
explicit set of source classes observed in that scope. Source integrity is
assigned to a reviewed tool/adapter; it is not inferred from result `_meta`, a
hostname, provider popularity, or content inspection. In ActionProxy policy,
exposure, and audit semantics, returned content has no instruction authority.
The child MCP result, including `_meta`, remains opaque and unchanged; a child
assertion cannot grant authority, set integrity, or widen a later action. See
`docs/POLICY_SPEC.md`.

## What To Verify

- Payload hash binding rejects edited inputs after approval.
- One-time grant consumption rejects replay.
- Failed downstream calls report `status: failed` and do not look successful in audit.
- `GET /v1/tool-calls/:id/decision-trace` explains the matched rule and fallback path.
- `POST /v1/policy/simulate` can test a policy change without creating tool calls, approvals, receipts, grants, audit events, or downstream execution.
- `GET /v1/tool-calls?sessionId=...&runId=...` and
  `GET /v1/audit?toolCallId=...` provide exact forensic correlation.
- An approval caused by influence identifies bounded source tool-call ids and
  integrity classes without repeating hostile content.
- A stale exposure or policy binding fails before local dispatch or grant
  consumption; the downstream executor is not called.
