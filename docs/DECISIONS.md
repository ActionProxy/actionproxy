# Architecture decisions

## ADR 001 — Start with approval-gated tool calls, not full workflow automation

Decision: v0.1.0 focuses only on tool-call approval.

Reason: This is the smallest valuable unit. A broad workflow builder would be harder to explain and slower to launch.

## ADR 002 — Start with HTTP and YAML

Decision: v0.1.0 exposes HTTP endpoints and reads YAML policy.

Reason: Developers can understand, test, and integrate this quickly.

## ADR 003 — Use mock tools first

Decision: v0.1.0 uses mock business tools and does not ship native Gmail,
Salesforce, Jira, or other SaaS execution connectors. Optional approval
notifications may call operator-configured Slack, Telegram, or SMTP transports.
An opt-in Google Workspace reference may launch an operator-owned downstream
MCP server; this does not move OAuth custody or provider execution into the
ActionProxy server.

Reason: The product value is the approval lifecycle, not connector breadth.

## ADR 004 — Store audit as append-only events

Decision: v0.1.0 appends hash-chained audit events through a shared audit-store
interface. Memory lifecycle mode uses a JSONL audit file; SQLite and Postgres
persist the same audit contract in their selected durable store.

Reason: The append-only contract and hash-chain verification must remain
consistent while storage can match local, Docker, or self-hosted deployment
needs.

## ADR 005 — Keep storage behind an interface

Decision: v0.1.0 keeps storage behind shared interfaces and supports memory,
SQLite, Postgres, and append-only JSONL audit implementations.

Reason: Local simplicity and durable self-hosted operation should not fight each
other.

## ADR 006 — Make ActionProxy proxy-first, not a connector runtime

Decision: ActionProxy should authorize, approve, grant, and audit tool calls while external runners or downstream MCP servers execute the actual business tools.

Reason: Most organizations already have tool integrations, MCP servers, internal APIs, or connector platforms. Rebuilding those inside ActionProxy would duplicate credentials and broaden the trust boundary. The built-in tool registry remains available only for local mock demos via `ACTIONPROXY_LOCAL_EXECUTION=mock`.

## ADR 007 — Keep approval channels in the control plane

Decision: ActionProxy sends approval notifications directly through the web UI,
Slack, Telegram, and email channels. MCP profiles are downstream business-tool
sources only.

Reason: Approval delivery is security-sensitive control-plane behavior. Routing approval notifications through downstream business tools would require ActionProxy to discover, trust, and choose business-tool connectors for its own authorization path, which weakens the separation between approval control and data-plane execution.

## ADR 008 — Authorize canonical action envelopes, not adapter payloads

Decision: Every proposed tool call is normalized into an `actionproxy.action.v1` envelope before review, receipt signing, grant issuance, or audit. Adapters only map their native protocol payloads into this envelope.

Reason: The security question is whether this exact payload should run now. A protocol-neutral envelope lets ActionProxy render trusted review screens, sign receipts over the approved envelope/input hashes, and bind one-time grants to the receipt without trusting agent-written descriptions or adapter-specific payload formats.

## ADR 009 — Use a deterministic first-run concierge

Decision: the fresh-download experience is a Node-built-ins-only terminal
concierge that orchestrates the local Docker deployment and an optional OpenAI
Secure MCP Tunnel. It is not an onboarding chatbot, policy engine, approval
authority, general package manager, or browser process-control API. Its only
software-installation exception is an explicit, checksum-pinned download of the
reviewed official OpenAI `tunnel-client` `v0.0.10` asset into this checkout's
`.actionproxy/bin`; it never uses `sudo`, changes `PATH`, or alters Gatekeeper
state. The Docker first-run path defaults to SQLite so audit evidence survives
`stop` and restart.

Reason: prerequisite and transport failures need reproducible checks and exact
remediation. Keeping machine actions in the terminal preserves the browser as
a read/approve console, keeps runtime credentials out of web state, and avoids
adding a local remote-code-execution surface to the gateway. Explicit consent,
a checked-in digest, an ownership receipt, and digest-bound removal keep the one
installer exception narrow and auditable without turning ActionProxy into a
general software manager.
