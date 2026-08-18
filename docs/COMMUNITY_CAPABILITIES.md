# ActionProxy Community capabilities

ActionProxy Community is a self-hosted execution-governance gateway. It accepts
a proposed tool call through a supported adapter, evaluates deterministic
policy, allows, denies, or queues the call for approval, grants exact execution
authority, and records the outcome.

## Included in v0.1

| Area                 | Included                                                                                                                                                                                                  |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Gateway              | HTTP tool-call lifecycle, policy decisions, original or single-reviewer edited approvals, receipts, execution grants, and audit                                                                            |
| Operator experience  | Local web console, guided mock demo, policy simulation, approval review, runner queue, and audit verification                                                                                             |
| Adapters             | JavaScript SDK, external-runner helper, stdio MCP wrapper, and experimental OAuth-protected `/mcp`                                                                                                        |
| Real-tool reference  | Opt-in Google Workspace downstream-MCP example for a real Gmail search and an approval-gated draft; the third-party MCP process owns OAuth and no native Google connector ships                         |
| ChatGPT demo         | Secure MCP Tunnel launcher with three deterministic mock tools, plus an explicit checksum-pinned checkout-local installer/status/remover for the reviewed official OpenAI `tunnel-client` `v0.0.10` asset |
| Storage              | Memory, SQLite, and Postgres                                                                                                                                                                              |
| Approval delivery    | Web console, Slack, Telegram, email outbox, and SMTP                                                                                                                                                      |
| Self-hosted security | API-key and OIDC JWT modes, scoped routes, approval groups, response redaction, and hash-chained audit                                                                                                    |
| Content consequences | Source-aware influence scopes and fail-closed policy narrowing for calls routed through supported MCP paths                                                                                               |

The SDK and MCP wrapper are independently packable as
`@actionproxy/sdk-js@0.1.1` and `@actionproxy/mcp-wrapper@0.1.1`. Registry
availability is a separately verified release fact; until both exact npm
records resolve with the reviewed repository metadata, integrity values, and
provenance, consumers use the reviewed local tarballs described in [the
adoption guide](ADOPTING.md).

The optional `tunnel-client` binary is downloaded only after explicit install
intent and is not part of the ActionProxy repository or its SBOM. Its checked-in
SHA-256 is the ActionProxy review anchor. The upstream binary is ad-hoc signed,
not Developer ID-signed or notarized, and ActionProxy neither removes
quarantine attributes, invokes Gatekeeper-override commands, nor claims Apple
verification. Status writes no ActionProxy state and downloads nothing, though
it may execute a selected client's help/version probes; removal is limited to
an unchanged receipt-owned local install, and `stop`/`reset` retain it.

## Deliberately not included

- A hosted ActionProxy service or control plane
- Native production SaaS connectors or ActionProxy provider credential custody
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

The included [Google Workspace MCP reference](../examples/google-workspace-mcp-demo/README.md)
is a concrete example of that boundary. Its external `workspace-mcp` process
is not vendored, sandboxed, or covered by ActionProxy's SBOM. It may read real
mailbox data and create a real draft, so operators must use a test account,
review the downstream dependency, and complete the documented live acceptance
before making a provider-support claim.

## Developer-preview limitations

- Stored action and audit payloads can contain raw sensitive data.
- Local unauthenticated mode is safe only on loopback.
- Audit chains are not anchored to an independent transparency service.
- One-time grants prevent replay of the same authorization; semantic
  deduplication across separately proposed and approved provider operations
  remains the operator-owned executor's responsibility.
- Operators own availability, backups, retention, key management, identity
  configuration, and prevention of bypass paths.
- Standard `/mcp` is experimental and requires an external OAuth 2.1
  authorization server for public deployment.

See [OSS test status](OSS_TEST_STATUS.md) for the current automated, live, and
remaining release evidence. See also [Security model](SECURITY_MODEL.md),
[Threat model](THREAT_MODEL.md), and
[External runners and MCP](EXTERNAL_RUNNERS_MCP.md).
