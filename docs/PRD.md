# Product requirements — ActionProxy v0

## Problem

Developers can now build AI agents that call tools, but most internal business actions are too risky to execute without review. Teams need a simple way to approve, block, and audit agent actions.

## Target users

- AI engineer
- Internal tools engineer
- Automation consultant
- Solutions engineer
- Startup CTO
- Developer building with tool-calling agents

## v0 value proposition

> Add approval gates, audit logs, and governed remediation paths around sensitive AI-agent tool calls.

The differentiated control surface is exact-action authorization: ActionProxy normalizes each proposed tool call into a protocol-neutral envelope, renders approval review from that envelope, signs receipts for the approved envelope/input hashes, binds external execution to one-time grants, and lets supported outcomes propose linked remediation actions. For configured MCP paths, ActionProxy can also bind model-visible results to a verified transport influence scope and deterministically narrow later actions according to administrator-assigned source-integrity classes.

## v0 user story

As an AI engineer, I want to wrap my agent's tool calls with a policy-controlled approval layer, so I can safely test workflows that include sensitive actions.

## v0 open-source scope

Included:

- local HTTP server
- protocol-neutral action envelope
- YAML policy
- allow / require approval / deny decisions
- mock tools for local demos
- pending approvals
- approve / reject endpoints
- trusted review hashes
- signed receipts
- one-time external execution grants
- governed remediation plans for supported outcomes
- MCP wrapper and SDK/HTTP adapter paths
- versioned MCP wrapper configuration/discovery report
- verified MCP influence scopes, minimized content-exposure evidence, and
  source-aware action narrowing
- OAuth-protected Streamable HTTP MCP endpoint for ChatGPT developer mode
- audit log
- local admin UI
- curl demo

Excluded:

- real SaaS connectors
- hosted service
- no-code builder
- billing
- prompt-injection detection, content scanning, or a model gateway
- dynamic hostname/vendor reputation
- control over host-native tools, direct network/shell access, or credentials
  that bypass configured ActionProxy adapters

## Success criteria

A developer can understand, install, run, and demo the product locally in under 15 minutes.

The demo should make the value obvious:

- `docs.search` is authorized immediately, and executes through the local mock registry only when demo mode is enabled.
- `gmail.send_email` requires approval.
- `dangerous.delete_customer` is blocked.
- ChatGPT developer-mode calls through the standard `/mcp` endpoint use the same
  approval, grant, execution, and audit lifecycle and cannot approve or reject
  themselves.
- External adapters receive `authorized` plus a one-time grant, then report `executed` or `failed`.
- A classified MCP result is recorded as a minimized exposure before it is
  released to the model; if that evidence cannot be persisted, the known
  downstream outcome remains recorded and the result is withheld without
  automatic redispatch.
- An influence-guarded action in a verified scope is intersected with all
  observed source classes. The guard can preserve, require approval, or deny,
  but never turn a base approval or denial into automatic execution.
- Supported successful outcomes can expose a remediation plan; submitting it creates a new governed tool call instead of rewriting the original history.
- Audit log records all of it.

## Product boundary

ActionProxy remains an execution-governance gateway. Product work should deepen
policy, approval, exact-action authorization, controlled execution, and audit
evidence without turning the Community project into an agent framework,
connector marketplace, generic workflow builder, or hosted SaaS control plane.
