# ActionProxy

**Open-source approval gates for AI agent tool calls.**

```bash
./actionproxy
```

That is the fresh-download first run. It guides you through a local lifecycle
proof or an experimental ChatGPT connection; details and prerequisites follow
below.

ActionProxy sits between an AI agent and the tools it wants to use. Calls routed
through an ActionProxy adapter are evaluated against deterministic policy,
allowed, denied, or paused for human approval, and recorded as lifecycle
evidence.

Use it when an agent can send email, update a CRM, change a ticket, issue a
refund, call an internal API, or invoke an MCP tool—but should not receive broad
authority to do so unattended.

![ActionProxy local Quickstart](docs/assets/actionproxy-quickstart.png)

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

## First run

From a fresh source download, start with one command:

```bash
./actionproxy
```

The guided path is supported on macOS and requires Node.js 22–24 and
Docker Desktop. Node.js 24 is recommended. It checks prerequisites before
changing anything, builds the Community container, lets Docker assign a free
loopback port, verifies the exact mock-tool inventory, and opens **Quickstart**.
No host-side `pnpm install`, account, SaaS credential, or real business system
is needed for the local proof. A cold Docker build can still download its base
image and install dependencies inside the image.

Cold-build time varies with network and host performance. Warm reruns reuse the
local Docker cache and the retained SQLite volume.

Choose one of two journeys, or invoke it directly:

```bash
./actionproxy local
./actionproxy chatgpt
```

The local journey proves all three policy outcomes:

- `docs.search` is allowed and executes immediately;
- `gmail.send_email` pauses with zero effects until a human decides; and
- `dangerous.delete_customer` is denied without downstream dispatch.

All three tools are deterministic mocks. The container stores lifecycle and
audit evidence in a checkout-specific SQLite volume, so `stop` and a later
restart retain it:

```bash
./actionproxy status
./actionproxy stop
```

`Start a new proof` clears only browser guidance. To delete the concierge-owned
container state and audit volume, run `./actionproxy reset` and type the exact
confirmation phrase it displays. The concierge never targets unrelated Docker
projects or volumes.

### Connect ChatGPT

The ChatGPT journey keeps the gateway on loopback and exposes only its stdio
MCP wrapper through OpenAI Secure MCP Tunnel:

```text
ChatGPT → OpenAI Secure MCP Tunnel → ActionProxy MCP wrapper
        → local ActionProxy gateway → deterministic mock tools
```

This journey is experimental in v0.1. Its local lifecycle, launcher, secret
handling, and simulated tunnel states have automated coverage, but the mandatory
clean-Mac live ChatGPT acceptance has not yet been recorded. Treat the steps as
guided evaluation, not as a claim of release-proven live ChatGPT support.

ChatGPT developer-mode access, Platform Tunnels **Read** + **Use**, and tunnel
association with the target ChatGPT workspace are separate prerequisites. The
concierge checks the local pieces and guides the workspace steps; it cannot
grant access or change administrator settings.

Run `./actionproxy chatgpt` even if you have not prepared the tunnel yet. In
the same terminal, the concierge:

- checks Mac, Node, Docker Desktop, and Compose first;
- explains the separate Platform and ChatGPT access boundaries;
- can open the official tunnel, developer-mode, and access-request guidance;
- accepts and validates the tunnel ID when you have it;
- detects `tunnel-client`; when it is absent, offers an explicit `I` choice to
  install ActionProxy's reviewed, pinned copy of the official OpenAI `v0.0.10`
  asset locally, while retaining the exact manual release/checksum procedure;
  and
- builds and verifies the local gateway before asking for the runtime key with
  hidden input.

You can pause safely at every external-access step and rerun the same command.
Once the gateway is ready, the browser Quickstart opens alongside the remaining
tunnel setup and shows the matching live state. Passing
`--tunnel-id tunnel_0123456789abcdef0123456789abcdef` remains available for
automation or experienced users.

ActionProxy downloads `tunnel-client` only after you choose `I` in the
interactive missing-client flow or explicitly run the install command. It
installs the ActionProxy-reviewed, pinned official OpenAI `v0.0.10` asset at
`.actionproxy/bin/tunnel-client`; the checked-in SHA-256 is the trust anchor.
The upstream binary is ad-hoc signed, not Developer ID-signed or notarized, so
ActionProxy does not claim that Apple has verified it. The installer never runs
`sudo`, changes `PATH`, removes quarantine metadata, or bypasses Gatekeeper.
This describes the optional host-side tunnel helper; a cold Docker build can
separately download images and image-local dependencies.

Inspect or manage only this checkout-local installation with:

```bash
./actionproxy tunnel-client status
./actionproxy tunnel-client install
./actionproxy tunnel-client remove
```

Each command also accepts `--json`. A verified local install is reusable
offline. `remove` deletes only an unchanged client bound to ActionProxy's own
install receipt; it refuses a live launcher, a modified file, and manually
placed clients. `stop` and `reset` retain the client. The downloaded optional
binary is not part of the repository release or its SBOM.

The runtime key is supplied to `tunnel-client` through a private, temporary
file and is removed when the tunnel ends; never put the key in a command
argument, browser, profile, or checked-in configuration.

For noninteractive automation, point
`ACTIONPROXY_CONTROL_PLANE_KEY_FILE` at an absolute, caller-owned regular file
with mode `0600`. The concierge reads it only after the non-secret checks and
build, copies the value into an OS-temporary `0700` session, and leaves the
caller file untouched. Legacy `CONTROL_PLANE_API_KEY` input is accepted only
when invoking `./actionproxy` directly; the root shim immediately moves it to
an unlinked private file descriptor before starting Node. Environment secrets
still have an unavoidable pre-start process-listing window, so do not put the
raw variable in front of `corepack pnpm`, `node scripts/first-run.mjs`, or the
compatibility adapter. Use the file input whenever strict process-list secrecy
matters.

The external OpenAI links in this first-run guidance were last reviewed on
**2026-08-03**; use the linked canonical pages rather than relying on a copied
menu path.

The existing automation-compatible command remains available and delegates to
the same implementation:

```bash
corepack pnpm demo:chatgpt:tunnel -- --tunnel-id tunnel_0123456789abcdef0123456789abcdef
```

See the complete [Secure MCP Tunnel manual fallback and troubleshooting
guide](examples/chatgpt-tunnel/README.md). For an advanced public HTTPS
resource-server integration, see [OAuth-protected Streamable HTTP
MCP](docs/CHATGPT_MCP.md); that adapter is experimental and requires an
external OAuth 2.1 authorization server.

## Adopt in another project

If a developer or AI coding agent is adding ActionProxy to an existing
application, start with the [third-party adoption guide](docs/ADOPTING.md), not
the contribution workflow. Generate a credential-free starter from the
consumer project's directory with one deterministic command:

```bash
/absolute/path/to/actionproxy/actionproxy integrate --mode sdk --json
# or: --mode mcp
# or: --mode http
```

The default directory is `actionproxy-<mode>-integration`. Use
`--output NAME` for another single-directory name. Generation creates a new
directory only, refuses to overwrite any existing entry, targets a loopback
gateway, and includes a machine-readable descriptor plus a mode-specific proof
checklist. SDK and MCP starters build a versioned local package tarball from the
reviewed checkout; they do not assume or probe npm registry availability. The
HTTP starter has no runtime dependency. The generated descriptor records the
package and source-binding contract. A private `actionproxy-source.json` stores
the reviewed checkout's local path so the starter can find it after `cd`; its
contents and absolute path are omitted from command output. `--json` reports
generated filenames, hashes, and next commands without credentials or absolute
paths. The starter's `.gitignore` excludes that binding, local package
tarballs, and installed dependencies.

Each starter rechecks `./actionproxy status --json` immediately before it runs,
requires a healthy loopback-only gateway, and uses the live Docker-assigned
port. Its generated policy is clearly marked as a sample; `./actionproxy local`
continues to enforce the bundled deterministic demo policy unless an operator
starts the server separately with an explicit policy path.

The guide provides a single decision tree for the three supported integration
boundaries:

- put the stdio wrapper in front of an existing MCP server;
- use `runExternalAction` when a JavaScript or TypeScript runner owns the
  downstream function; or
- implement the documented HTTP grant lifecycle from another runtime.

The SDK and MCP-wrapper package sources are independently versioned at
`0.1.0`. Their manifests and isolated packed-consumer tests are release-ready,
but this document does not claim that either package exists in npm until the
exact registry records are independently verified. The guide includes the
truthful local-tarball fallback, machine-readable OpenAPI and JSON Schema
contracts, a mock-first completion contract, and a prompt developers can give
directly to a coding agent. Do not let an agent invent package availability,
bypass grant consumption, or replace an unknown downstream outcome with an
automatic retry.

### Develop from source

Use the Node/Corepack workflow when changing ActionProxy itself:

In the public checkout, coding agents and automated contributors should first
read the repository-wide [AGENTS.md](AGENTS.md).

If you already use `nvm`, run `nvm use` first. Otherwise select Node 22–24 with
your existing Node installation or version manager; Node 24 is recommended.

```bash
node --version
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm dev
```

Open `http://127.0.0.1:5173/#/demo`. The checked-in `.node-version` also works
with tools such as `asdf` and `mise`.

These development commands are alternatives; run each process you need in its
own terminal:

```bash
corepack pnpm dev:server  # gateway only, with local mock execution
corepack pnpm dev:web     # Vite console only
corepack pnpm dev:proxy   # external-runner mode; no local execution
```

For a manual Docker run, use `docker compose up --build` and open
`http://127.0.0.1:8787/app#/demo`. Set `ACTIONPROXY_DOCKER_PORT=18787` when an
explicit alternate host port is useful. The Compose default uses SQLite and
publishes only to `127.0.0.1`.

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
boundary, and [OSS test status](docs/OSS_TEST_STATUS.md) for what is automated,
what still needs live validation, and what remains before release.

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
authority flow. Its independently packable candidate is
`@actionproxy/sdk-js@0.1.0`. This README does not infer registry availability
from the manifest; verify the exact npm record after an owner-authorized
release, or use the pinned local-tarball workflow in
[the adoption guide](docs/ADOPTING.md#javascript-consumer-path).

Start ActionProxy without local tool execution before testing an external
runner:

Terminal 1 — gateway:

```bash
corepack pnpm dev:proxy
```

Terminal 2 — external runner:

```bash
node examples/external-runner/run-external-action.mjs
```

See [External runners and MCP](docs/EXTERNAL_RUNNERS_MCP.md).

## MCP wrapper

The stdio wrapper in `packages/mcp-wrapper/` lets an MCP host expose downstream
tools only through ActionProxy policy and approval. Its independently packable
candidate is `@actionproxy/mcp-wrapper@0.1.0`; the same registry-verification
rule and local-tarball fallback apply.

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

### Real Google Workspace reference

Community also includes an opt-in, downstream
[Google Workspace MCP reference](examples/google-workspace-mcp-demo/README.md).
It demonstrates a real Gmail search followed by a draft that remains paused
until an ActionProxy approval is granted:

```text
local scripted host → ActionProxy MCP wrapper → operator-owned workspace-mcp
                    → Google Workspace
```

This is not the bundled `gmail.send_email` mock and it is not an
ActionProxy-native Google connector. The third-party MCP process owns Google
OAuth and runs with the local user's ordinary process and network authority;
ActionProxy does not vendor it or take custody of its OAuth tokens. Use a
dedicated test account, review the external dependency before invocation, and
keep the example's `.env.local` and `.actionproxy/` state untracked. The
documented first proof can search Gmail and create a draft after review; it
does not send email. The reference pins the third-party
[`workspace-mcp` 1.22.0 README](https://github.com/taylorwilsdon/google_workspace_mcp/blob/v1.22.0/README.md),
[`v1.22.0` license](https://github.com/taylorwilsdon/google_workspace_mcp/blob/v1.22.0/LICENSE),
and [official PyPI 1.22.0 record](https://pypi.org/project/workspace-mcp/1.22.0/).
Its Python transitive dependencies remain outside ActionProxy's pnpm lock and
SBOM. No live Google-account acceptance has been recorded for this release
candidate, so this is not a claim of verified native or live connector support.

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
corepack pnpm openapi:check
node scripts/generate-config-schemas.mjs --check
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

The public repository is generated from a reviewed Community boundary.
Accepted public contributions retain the original contributor attribution.
