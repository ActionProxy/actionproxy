<!-- actionproxy-public-agent-instructions:v1 -->

# ActionProxy Community Repository Instructions

These instructions apply to the whole public repository. Follow explicit user
instructions first, then the rules in this file.

## Product boundary

ActionProxy Community is an execution-governance gateway for AI agent tool
calls. It receives a proposed call, evaluates deterministic policy, allows,
denies, or pauses it for approval, executes only with valid authority, and
records lifecycle evidence.

Keep the product narrow. It is not an agent runtime, chatbot, browser, generic
workflow builder, connector marketplace, hosted control plane, or production
SaaS connector bundle.

## Read before editing

Start with [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md). Read
the documents relevant to the change:

- [Architecture](docs/ARCHITECTURE.md) for module ownership and request flow.
- [API specification](docs/API_SPEC.md) for HTTP contracts.
- [Policy specification](docs/POLICY_SPEC.md) for rules and decisions.
- [Security model](docs/SECURITY_MODEL.md) for trust boundaries.
- [Architecture decisions](docs/DECISIONS.md) for established tradeoffs.

## Adopting from another repository

When the user wants to add ActionProxy to an existing application, read
[the third-party adoption guide](docs/ADOPTING.md) before changing either
repository. Do not treat adoption as an ActionProxy contribution.

Choose exactly one execution boundary: the MCP wrapper for an existing MCP
server, `runExternalAction` for a JavaScript or TypeScript runner, or the
documented HTTP grant lifecycle for another runtime. Begin with a simulated
effect and prove zero dispatch before approval, exactly one after approval,
zero after denial, and a valid audit chain. The coordinated package candidates
are exactly `@actionproxy/sdk-js@0.1.1` and
`@actionproxy/mcp-wrapper@0.1.1`. Use them from npm only after both exact
records resolve with reviewed repository metadata, integrity values, and
provenance; otherwise use the guide's explicit local-tarball workflow. Never
invent a registry dependency, dist-tag, or cross-repository import.

## Repository map

- `apps/server/src/app.ts` composes the Community Fastify application.
- `apps/server/src/services/action-gate.ts` owns the governed lifecycle.
- `apps/server/src/policy/` contains pure policy loading and evaluation.
- `apps/server/src/storage/` contains storage interfaces and adapters.
- `apps/server/src/routes/` validates transport input and maps service errors.
- `apps/server/src/tools/` contains deterministic local mock tools.
- `apps/web/src/` contains the local operator console.
- `packages/sdk-js/` contains the JavaScript client and runner helpers.
- `packages/mcp-wrapper/` contains the stdio MCP proxy.
- `examples/google-workspace-mcp-demo/` is the opt-in real-provider reference;
  its third-party MCP process, not ActionProxy, owns Google OAuth.
- `examples/` contains local demonstrations; `docs/` is the contract source of
  truth.

Tests are colocated with implementation files wherever practical.

## Dependency-free orientation

Before installing packages, an agent can inspect the supported command surface
and machine state without mutating it:

```bash
./actionproxy --help
./actionproxy doctor --json
./actionproxy tunnel-client status --json
```

When explicitly asked to exercise the local mock lifecycle, use the
noninteractive browser-free path and inspect its live status:

```bash
./actionproxy local --no-open
./actionproxy status --json
./actionproxy stop
```

Do not solicit, read, paste, log, or persist a human's OpenAI runtime key. The
interactive ChatGPT journey owns hidden credential input and administrator
access steps; a coding agent may prepare code and diagnostics but must leave
those human-only actions to the user.

Do not run the Google Workspace MCP reference, open its `.env.local`, start its
OAuth flow, inspect its credential directory, auto-approve its draft, or print
mailbox results unless the user explicitly authorizes that live-provider test.
Use only a dedicated test mailbox. Never include OAuth values, mailbox content,
account addresses, or message bodies in agent output, diagnostics, fixtures, or
release evidence. The reference launches third-party code through `uvx`; review
and independently verify its exact checked-in wheel URL and SHA-256 pin before
treating a live run as release evidence.

`doctor` and `tunnel-client status` perform no ActionProxy state mutation or
download, although ChatGPT checks may execute a selected client's help/version
probes. Do not invoke
`./actionproxy tunnel-client install` or `remove` unless the user explicitly
authorized that filesystem/network action. Installation is limited to
ActionProxy's reviewed, SHA-256-pinned official OpenAI `v0.0.10` asset at
`.actionproxy/bin/tunnel-client`; it does not use `sudo`, change `PATH`, remove
quarantine attributes, or invoke Gatekeeper-override commands. The upstream
binary is ad-hoc signed, not Developer
ID-signed or notarized, and is outside the repository SBOM. Removal applies only
to an unchanged install-receipt-owned client and refuses active, modified, or
manually placed files. `stop` and `reset` retain it.

## Architecture invariants

- Keep routes thin. Put lifecycle behavior in `ActionProxyService`.
- Keep policy evaluation pure and independent of HTTP, storage, and execution.
- Keep local execution behind `ToolRegistry`; external execution must consume
  the existing exact grant and execution-attempt lifecycle.
- Audit events are append-only. Never rewrite earlier evidence.
- Preserve both original and edited approval inputs and their hashes.
- Unknown tools require approval by default. The destructive demo fixture must
  remain denied before downstream dispatch.
- Do not create an alternate policy, approval, authorization, or audit path.
- Keep storage behind interfaces and preserve migration compatibility.

## Validation by change area

Install source-development dependencies with:

```bash
corepack pnpm install --frozen-lockfile
```

Run the smallest relevant checks first:

| Change area                               | Focused validation                                                                                                |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Server, policy, approvals, audit, storage | `corepack pnpm --filter @actionproxy/server test` and `corepack pnpm --filter @actionproxy/server lint`           |
| Web console                               | `corepack pnpm --filter @actionproxy/web test` and `corepack pnpm --filter @actionproxy/web lint`                 |
| JavaScript SDK                            | `corepack pnpm --filter @actionproxy/sdk-js test` and `corepack pnpm --filter @actionproxy/sdk-js lint`           |
| MCP wrapper                               | `corepack pnpm --filter @actionproxy/mcp-wrapper test` and `corepack pnpm --filter @actionproxy/mcp-wrapper lint` |
| First-run concierge                       | `corepack pnpm test:first-run`                                                                                    |
| Community browser lifecycle               | `corepack pnpm test:e2e:community`                                                                                |

The browser suite requires the configured Playwright browser. For broad or
cross-package changes, run:

```bash
corepack pnpm test
corepack pnpm lint
corepack pnpm build
```

For API contract changes, also run the relevant scripts under
`examples/local-curl-demo/` or state why that validation was not run.

## Safety and contribution discipline

- Inspect the working tree before editing and preserve unrelated changes.
- Never add credentials, tokens, customer payloads, or production data.
- Never commit `.actionproxy` state, a downloaded `tunnel-client`, or its local
  install receipt.
- Do not add real SaaS calls, analytics, hosted dependencies, or new vendors
  unless the requested Community feature explicitly requires them.
- Do not weaken authentication, approval freshness, single-dispatch,
  loopback-only demo, secret-handling, or audit-integrity controls.
- Do not publish packages, push commits, create releases, or change repository
  visibility unless the user explicitly requests that action.
- Update public documentation and compatibility notes when API, policy,
  approval, execution, audit, migration, or storage behavior changes.

## Public manifest and handoff

`PUBLIC_MANIFEST.json` is generated integrity metadata. Never edit it by hand.
Run focused validation before refreshing it.

When preparing a Git contribution and the user has authorized staging, run:

```bash
corepack pnpm manifest:refresh
git add --all
corepack pnpm verify:tracked-checkout
corepack pnpm verify:oss-boundary
```

For a machine-readable final boundary report in a Git checkout, run:

```bash
node scripts/verify-public-export.mjs . --checkout --strict --json
```

For a clean source archive without `.git`, use:

```bash
node scripts/verify-public-export.mjs . --strict --json
```

Manifest and Git attestation commands are not applicable to an edited archive.
Do not initialize a repository or stage files merely to make those checks pass;
report that limitation instead.

At handoff, summarize changed files, commands and results, compatibility or
security effects, and anything that remains unvalidated.
