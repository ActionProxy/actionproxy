# ActionProxy Community capabilities

ActionProxy Community is a self-hosted execution-governance gateway. It accepts
a proposed tool call through a supported adapter, evaluates deterministic
policy, allows, denies, or queues the call for approval, grants exact execution
authority, and records the outcome.

## Included in v0.1

| Area | Included |
|---|---|
| Gateway | HTTP tool-call lifecycle, policy decisions, approvals, receipts, execution grants, and audit |
| Operator experience | Local web console, guided mock demo, policy simulation, approval review, runner queue, and audit verification |
| Adapters | JavaScript SDK, external-runner helper, stdio MCP wrapper, and experimental OAuth-protected `/mcp` |
| ChatGPT demo | Secure MCP Tunnel launcher with three deterministic mock tools |
| Storage | Memory, SQLite, and Postgres |
| Approval delivery | Web console, Slack, Telegram, email outbox, and SMTP |
| Self-hosted security | API-key and OIDC JWT modes, scoped routes, approval groups, response redaction, and hash-chained audit |
| Content consequences | Source-aware influence scopes and fail-closed policy narrowing for calls routed through supported MCP paths |

The SDK and MCP wrapper are workspace components built from a source checkout.
They are not published registry packages in v0.1.

## Deliberately not included

- A hosted ActionProxy service or control plane
- Native production SaaS connectors or provider credential custody
- An agent runtime, chatbot, browser, or workflow builder
- Billing, pricing, organization provisioning, SCIM, or SAML
- A connector marketplace
- Prompt-injection detection or proof that model memory is clean
- Interception of host-native tools, networking, shell access, or credentials
  outside configured ActionProxy adapters
- A complete production compliance or authorization boundary

Real tool effects should remain in an existing MCP server, internal API, or
external runner. That executor consumes ActionProxy's exact one-time grant and
reports the outcome back for audit.

## Developer-preview limitations

- Stored action and audit payloads can contain raw sensitive data.
- Local unauthenticated mode is safe only on loopback.
- Audit chains are not anchored to an independent transparency service.
- Operators own availability, backups, retention, key management, identity
  configuration, and prevention of bypass paths.
- Standard `/mcp` is experimental and requires an external OAuth 2.1
  authorization server for public deployment.

See [Security model](SECURITY_MODEL.md), [Threat model](THREAT_MODEL.md), and
[External runners and MCP](EXTERNAL_RUNNERS_MCP.md).
