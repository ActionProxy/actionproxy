# ActionProxy

**Open-source approval gates for AI agent tool calls.**

ActionProxy sits between an AI agent and the tools it wants to use. Calls routed
through an ActionProxy adapter are evaluated against deterministic policy,
allowed, denied, or paused for human approval, and recorded as lifecycle
evidence.

Use it when an agent can send email, update a CRM, change a ticket, issue a
refund, call an internal API, or invoke an MCP tool—but should not receive broad
authority to do so unattended.

![ActionProxy local demo lab](docs/assets/actionproxy-demo-lab.png)

```text
agent proposes a tool call
        ↓
ActionProxy evaluates policy
        ↓
allow · deny · require approval
        ↓
approved calls receive exact, one-time authority
        ↓
runner executes the tool
        ↓
ActionProxy records the outcome and audit evidence
```

## Five-minute demo

### Source quickstart

Prerequisites: Node.js 24 and Corepack. Node 22 is also supported in CI.

```bash
nvm use
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm dev
```

`pnpm dev` starts the Community gateway and Vite console together. Open
`http://127.0.0.1:5173/#/demo`, choose **Run full demo**, and follow the
allow, approval, denial, and audit steps. The tools are deterministic mocks; no
SaaS credentials are needed.

If you do not use `nvm`, install a current Node 24 release with your preferred
version manager. The checked-in `.node-version` also works with tools such as
`asdf` and `mise`.

Advanced development commands:

```bash
corepack pnpm dev:server  # gateway only, with local mock execution
corepack pnpm dev:web     # Vite console only
corepack pnpm dev:proxy   # gateway for an external runner; no local execution
```

### Docker alternative

Build and run the same Community source on loopback:

```bash
docker compose up --build
```

Open `http://127.0.0.1:8787/app#/demo`. To use another host port:

```bash
ACTIONPROXY_DOCKER_PORT=18787 docker compose up --build
```

Stop the foreground process with `Ctrl+C`, then run `docker compose down` when
you also want to remove the container. The named data volume remains unless
you explicitly add `--volumes`.

### Connect ChatGPT

The beginner ChatGPT path keeps ActionProxy on loopback and exposes only its
stdio MCP wrapper through OpenAI Secure MCP Tunnel:

```text
ChatGPT → OpenAI Secure MCP Tunnel → ActionProxy MCP wrapper
        → local ActionProxy gateway → deterministic mock tools
```

After creating a tunnel for an entitled ChatGPT workspace, keep its runtime key
in the shell and run:

```bash
export CONTROL_PLANE_API_KEY='<runtime-key-from-openai-platform>'
corepack pnpm demo:chatgpt:tunnel -- --tunnel-id tunnel_...
```

The launcher verifies Docker and the wrapper, exposes exactly `docs.search`,
`gmail.send_email`, and `dangerous.delete_customer`, and never asks the browser
for the runtime key. See the complete
[Secure MCP Tunnel example](examples/chatgpt-tunnel/README.md).

For an advanced public HTTPS resource-server integration, see
[OAuth-protected Streamable HTTP MCP](docs/CHATGPT_MCP.md). That adapter is
experimental and requires an external OAuth 2.1 authorization server.

## What ships

- Local HTTP approval gateway and web console
- YAML policy with allow, deny, and approval decisions
- Deterministic mock tools for a zero-credential demo
- Approval review with original and edited payload evidence
- Append-only, hash-chained audit events and verification
- Exact, expiring, single-use grants for external runners
- Memory, SQLite, and Postgres storage adapters
- JavaScript SDK and external-runner helper
- Stdio MCP wrapper and bounded tool-discovery doctor
- Experimental OAuth-protected Streamable HTTP `/mcp`
- Source-aware content-influence consequence controls
- Slack, Telegram, email-outbox, and SMTP approval notifications
- API-key and OIDC JWT authentication modes for self-hosted deployments

See [Community capabilities](docs/COMMUNITY_CAPABILITIES.md) for the precise
boundary and current limitations.

## What ActionProxy is not

ActionProxy is not an LLM gateway, chatbot, browser, agent framework, workflow
builder, connector marketplace, or hosted control plane. It cannot intercept
tools, networking, shell access, credentials, or model memory that bypass its
configured adapters.

Source labels and content-influence policy contain consequences after content
is read; they do not detect prompt injection, make retrieved text trustworthy,
or turn data into instructions.

## Curl lifecycle

With the server running:

```bash
examples/local-curl-demo/create-doc-search.sh
examples/local-curl-demo/create-email-approval.sh
examples/local-curl-demo/list-pending.sh
examples/local-curl-demo/approve-first-pending.sh
examples/local-curl-demo/create-denied-action.sh
curl -s http://127.0.0.1:8787/v1/audit | jq
curl -s http://127.0.0.1:8787/v1/audit/verify | jq
```

The expected behavior is:

- `docs.search` executes immediately;
- `gmail.send_email` has no effect before approval and one mock effect after;
- `dangerous.delete_customer` is denied without downstream execution;
- the audit API records proposal, decision, approval, authority, execution, and
  denial evidence.

## SDK and external runners

The JavaScript SDK is a workspace component in `packages/sdk-js/`. It contains
the HTTP client, polling helper, gated-tool helper, and external-runner
authority flow. Packages are not published to npm for v0.1; use them from this
checkout.

Start ActionProxy without local tool execution before testing an external
runner:

```bash
corepack pnpm dev:proxy
node examples/external-runner/run-external-action.mjs
```

See [External runners and MCP](docs/EXTERNAL_RUNNERS_MCP.md).

## MCP wrapper

The stdio wrapper in `packages/mcp-wrapper/` lets an MCP host expose downstream
tools only through ActionProxy policy and approval.

```bash
corepack pnpm dev:proxy
```

In a second terminal:

```bash
corepack pnpm demo:mcp
```

Use `corepack pnpm demo:mcp:manual` to approve through the web console, or
`corepack pnpm demo:mcp:hosts` to print local Codex, Claude Code, and generic
stdio host configurations. Discovery starts reviewed child commands and is not
a sandbox.

## Storage

The default memory mode resets tool-call and approval state on restart. Use
SQLite for a durable local instance or Postgres for a self-hosted server:

```bash
ACTIONPROXY_STORAGE=sqlite corepack pnpm dev:server
```

```bash
docker compose --profile postgres up -d postgres
ACTIONPROXY_STORAGE=postgres \
DATABASE_URL=postgres://actionproxy:actionproxy@127.0.0.1:54329/actionproxy \
corepack pnpm dev:server
```

SQLite requires the `sqlite3` command-line tool; the Docker image includes it.
See [Storage](docs/STORAGE.md).

## Approval channels

The local console is always available for approval review. Optional Slack,
Telegram, email-outbox, and SMTP notifications call the same approval service;
a delivery failure never removes the pending approval. See
[Approval channels](docs/APPROVAL_CHANNELS.md).

## Security posture

Implemented controls include hashed API keys, RS256 OIDC verification,
route-level scopes, server-derived actors, approval groups, separation of
duties, exact execution grants, response redaction, CORS/body/rate controls,
and hash-chained audit verification.

Important developer-preview limitations:

- Stored tool-call, receipt, and audit payloads can contain sensitive raw data.
  Response redaction does not encrypt, truncate, or delete the stored payload.
- The local unauthenticated mode is for loopback demonstrations only.
- Audit chains are locally verifiable but are not anchored to an independent
  transparency service.
- ActionProxy is not by itself a complete production authorization or
  compliance boundary.
- Operators must ensure agents cannot bypass ActionProxy through other tools,
  credentials, networking, or shell access.

Read [Security](SECURITY.md), the [security model](docs/SECURITY_MODEL.md), and
the [threat model](docs/THREAT_MODEL.md) before using real data or tools.

## Development and validation

```bash
corepack pnpm test
corepack pnpm lint
corepack pnpm build
corepack pnpm test:e2e:community
corepack pnpm docker:smoke:community
```

The release process also validates Node 22/24, Postgres without skips, the
generated Community tree, dependency advisories, runtime licenses, a CycloneDX
SBOM, secret scanning, workflow references, and Docker restart behavior.

If setup fails, start with [Troubleshooting](docs/TROUBLESHOOTING.md).

## Repository map

```text
apps/server/              Community gateway
apps/web/                 Local operator console
packages/sdk-js/          JavaScript SDK workspace component
packages/mcp-wrapper/     Stdio MCP wrapper workspace component
examples/                 Runnable local examples
docs/                     API, policy, security, storage, and operating docs
```

## Contributing

ActionProxy is licensed under Apache-2.0. Read [CONTRIBUTING.md](CONTRIBUTING.md),
the [Code of Conduct](CODE_OF_CONDUCT.md), and [Support](SUPPORT.md). Good starter
work is listed in [First issues](docs/FIRST_ISSUES.md).

The public repository is generated from a private source monorepo. Accepted
public contributions are ported back with the original contributor attribution
preserved.
