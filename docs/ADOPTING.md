# Adopt ActionProxy From Another Project

This guide is for a developer or AI coding agent adding ActionProxy Community
to an existing application. It is not the contribution guide for changing
ActionProxy itself.

ActionProxy is an Apache-2.0 developer preview. Its two integration packages
are published to npm with verified provenance. ActionProxy does not publish a
registry container image: keep the gateway's reviewed source checkout separate
from the application that is adopting it, and do the first integration with
mocks before connecting a real business tool.

See [OSS test status](OSS_TEST_STATUS.md) for the current automated evidence and
the manual or live paths that remain externally unvalidated.

Verify both coordinated registry records and install only the exact package
needed by the consumer:

```bash
npm view @actionproxy/sdk-js@0.1.1 version dist.integrity repository.url dist.attestations
npm view @actionproxy/mcp-wrapper@0.1.1 version dist.integrity repository.url dist.attestations

npm install --save-exact @actionproxy/sdk-js@0.1.1
# or
npm install --save-exact @actionproxy/mcp-wrapper@0.1.1
```

Both lookups must resolve `0.1.1`, the reviewed repository metadata, an
integrity value, and provenance attestations. A failed or mismatched lookup is
not permission to guess a package name or dist-tag. Use the reviewed local
tarball flow below when an exact source-bound or offline dependency is needed.

## Generate a safe starter

Run the generator from the separate consumer repository. The absolute path is
to the reviewed ActionProxy checkout:

```bash
cd /absolute/path/to/your-consumer-project
/absolute/path/to/actionproxy/actionproxy integrate --mode sdk --json
```

Choose exactly one mode:

- `sdk` creates a JavaScript external-runner example whose exact
  `@actionproxy/sdk-js@0.1.1` dependency points to a generated local-tarball
  path;
- `mcp` creates a wrapper configuration and deterministic three-tool stdio MCP
  server whose exact `@actionproxy/mcp-wrapper@0.1.1` dependency uses the same
  local-tarball flow; or
- `http` creates a dependency-free Node client for the HTTP submission proof.

The default output names are `actionproxy-sdk-integration`,
`actionproxy-mcp-integration`, and `actionproxy-http-integration`. To choose a
different name, pass one safe directory component:

```bash
/absolute/path/to/actionproxy/actionproxy integrate \
  --mode mcp \
  --output actionproxy-proof \
  --json
```

Generation is deliberately conservative:

- it writes only beneath a real current working directory;
- it creates one new directory and never overwrites an existing entry;
- generated code accepts only a loopback HTTP ActionProxy URL;
- examples use deterministic mocks and contain no credential or auto-approval;
- SDK and MCP dependencies use exact `0.1.1` package identities through
  `file:vendor/...tgz`, with a preparer using the generated source binding;
- `actionproxy.policy.sample.yaml` is explicitly sample-only and is not loaded
  by First Run; and
- every file is accompanied by a SHA-256 digest in the JSON result.

`--json` still generates the directory; it changes stdout to the stable
`actionproxy.integration-starter.v1` result. The allowlisted result contains
the mode, package version/source, relative output name, relative file names and
hashes, an optional loopback `gatewayBaseUrl` hint, next commands, safeguards,
and a mode-specific proof checklist. It contains no file contents, credential,
arbitrary environment value, or absolute path. Each directory also contains
`actionproxy-integration.json`, which adds source-binding metadata,
sample-policy status, and the schema-artifact map so a coding agent can inspect
the contract without scraping terminal text.

The separately generated `actionproxy-source.json` is mode `0600` and contains
the local filesystem path to the reviewed ActionProxy checkout. The starter
uses it to locate `./actionproxy` and the package sources after changing into
the generated directory. The `--json` result lists that file's relative name
and SHA-256 with the other generated files, but never returns its contents or
absolute source path. The generated `.gitignore` excludes the binding,
`vendor/*.tgz`, and `node_modules/`; keep those local-only entries out of a
shared consumer repository.

For `sdk` and `mcp`, the generated `prepare-local-package.mjs` command reads the
source binding, verifies
the expected ActionProxy source/package identity, builds the exact package
from that reviewed checkout, and writes it under the starter's
`vendor/` directory before `npm install` consumes the file dependency. This
starter deliberately selects the local source tarball even though the exact
package is available from npm; it does not probe the registry or switch the
dependency source.

If the requested output already exists, the command fails instead of merging
or replacing it. If a later write fails, inspect the newly created directory
and explicitly rename or remove only that directory before retrying.

The generated configuration defaults to `http://127.0.0.1:8787`, but run
commands go through `run-with-live-gateway.mjs`. Immediately before every proof,
doctor, or wrapper process, that helper resolves the reviewed checkout through
the source binding and calls `./actionproxy status --json`. It requires the
recorded project to be running with a healthy loopback-only gateway, reads the
live Docker-assigned port, and passes the resulting `ACTIONPROXY_BASE_URL` only
to that child. If no gateway is running, use the generated start command:

```bash
node run-with-live-gateway.mjs --start
```

It starts the local no-browser journey through that same binding. An optional
`gatewayBaseUrl` in the generation report is a generation-time hint, not
cached proof of health. The SDK and HTTP scripts reject non-loopback URLs, and
the MCP wrapper's environment override remains loopback for this starter.

The generated proof scope is deliberately different for each mode:

- `http` automatically checks gateway health, one allowed read execution, a
  pending email with zero execution attempts, a denied destructive call with
  zero attempts, and local audit-chain validity. It does not approve the email.
- `sdk` checks health, waits for a human decision on one mock email, then checks
  that the simulated callback and execution attempt each occurred exactly once
  and that the audit chain verifies. It does not separately submit allow and
  deny fixtures.
- `mcp` runs bounded discovery and requires exactly the three deterministic mock
  tools. Doctor does not prove policy, approval, execution, or audit; those
  checks require calls from an MCP host.

The generated policy file documents the intended fixtures for adaptation. It
is not silently activated: `./actionproxy local` continues to enforce its
bundled deterministic demo policy. For a later real integration, start the
server with an explicitly selected, operator-owned policy as described below.

## Choose one integration boundary

| Existing application boundary                                  | Use                                                       | Start here                                                      |
| -------------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------------------------- |
| An MCP server already owns the tool and its credentials        | Put the ActionProxy stdio wrapper in front of that server | [External runners and MCP](EXTERNAL_RUNNERS_MCP.md#mcp-pattern) |
| A JavaScript or TypeScript runner owns the downstream function | Use `ActionProxyClient` and `runExternalAction`           | [JavaScript consumer path](#javascript-consumer-path)           |
| Another language or process owns execution                     | Implement the documented HTTP grant lifecycle             | [HTTP consumer path](#http-consumer-path)                       |

Do not put a second policy or approval check in the consumer. ActionProxy is
authoritative for allow, deny, approval, exact one-time authority, and audit;
the existing runner remains authoritative for its tool credentials and the
actual downstream call.

For a concrete opt-in provider example, see the
[Google Workspace downstream MCP reference](../examples/google-workspace-mcp-demo/README.md).
It keeps OAuth in a third-party MCP process and demonstrates a real Gmail read
plus an approval-gated draft. It is an exploratory reference, not a native
ActionProxy connector or a substitute for the mock-first proof above.

For every external SDK, MCP, or HTTP integration, preserve these invariants:

1. A proposal, policy decision, or approval record is not dispatch authority.
2. `pending_approval`, `blocked`, `rejected`, and `cancelled` produce zero
   downstream calls.
3. Only `authorized` can proceed, and the runner must consume the exact bound
   grant before one downstream call.
4. Grant replay, changed input, expiry, stale policy, or binding mismatch fails
   before dispatch.
5. Report the downstream outcome once. Treat `unknown_outcome` as possibly
   executed, reconcile it, and never retry automatically.
6. Remove direct tool registrations, credentials, network paths, or shell
   capabilities that let the agent reach the same effect around ActionProxy.

## Prove the boundary before adapting it

From the ActionProxy source checkout, a coding agent can perform read-only
orientation without installing packages:

```bash
./actionproxy --help
./actionproxy doctor --json
```

When the user has explicitly asked it to start the local mock proof, the agent
can use the browser-free path:

```bash
./actionproxy local --no-open
./actionproxy status --json
```

The status report supplies the Docker-assigned loopback port. The expected
proof is always the same:

- `docs.search` is allowed and executes;
- `gmail.send_email` has zero execution before approval and exactly one after;
- `dangerous.delete_customer` is denied with no downstream dispatch; and
- `GET /v1/audit/verify` returns a valid local hash chain.

Stop only the concierge-owned runtime with `./actionproxy stop`. Its SQLite
audit volume remains available for a later restart.

An AI coding agent must not solicit, read, paste, log, or persist a human's
OpenAI runtime key. The interactive `./actionproxy chatgpt` journey owns that
hidden input and all administrator access steps.

If tunnel testing is in scope, an agent can inspect the local prerequisite
without ActionProxy state mutation or download. These checks may execute the
selected client's help/version probes:

```bash
./actionproxy tunnel-client status --json
./actionproxy doctor --chatgpt --json
```

It may run `./actionproxy tunnel-client install --json` only after the user has
explicitly authorized that checkout-local download. The command is
deterministic and machine-readable: it selects the reviewed pinned asset,
verifies it, and writes only beneath `.actionproxy/bin`. An agent must not
substitute a newer release, arbitrary URL, package-manager install, `sudo`, or
Gatekeeper workaround. `./actionproxy tunnel-client remove --json` removes
only an unchanged receipt-owned install; `stop` and `reset` intentionally do
not uninstall it.

## JavaScript consumer path

Verify the two coordinated records before installing the exact SDK:

```bash
npm view @actionproxy/sdk-js@0.1.1 version dist.integrity repository.url dist.attestations
npm view @actionproxy/mcp-wrapper@0.1.1 version dist.integrity repository.url dist.attestations
npm install --save-exact @actionproxy/sdk-js@0.1.1
```

Both lookups must resolve the exact versions, reviewed repository metadata,
integrity values, and provenance attestations. A failed or mismatched lookup is
a release-availability failure, not permission to guess a tag or package name.

For the source-bound or offline fallback, build a local tarball from the
reviewed ActionProxy checkout:

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm --filter @actionproxy/sdk-js build
corepack pnpm --filter @actionproxy/sdk-js pack --out actionproxy-sdk-js-0.1.1.tgz
```

Then, from the separate consumer repository, install the tarball by its
absolute path:

```bash
corepack pnpm add /absolute/path/to/actionproxy/actionproxy-sdk-js-0.1.1.tgz
```

Do not import through `../actionproxy/packages/...` or add monorepo-relative
paths to the consumer. The tarball makes the evaluated source boundary
explicit while preserving the published package shape.

Start the gateway in external-runner mode from the ActionProxy checkout. Use a
separate web-console terminal if a human will review approvals:

Terminal 1 — gateway:

```bash
corepack pnpm dev:proxy
```

Terminal 2 — web console:

```bash
corepack pnpm dev:web
```

For a real integration, load an operator-owned policy file with
`ACTIONPROXY_POLICY_PATH=/absolute/path/to/policy.yaml`. Start with a rule that
requires approval and exact external grant consumption:

```yaml
version: 1

default:
  approval: required
  risk: unknown
  reason: "Unknown tools require approval by default."

tools:
  customer.send_update:
    approval: required
    risk: external_communication
    reason: "A human must review customer-visible messages."
    externalExecution:
      grantTtlSeconds: 300
      requireGrantConsumption: true
```

Use `runExternalAction` for a downstream effect. It submits the proposal,
waits for the authoritative decision, consumes the exact one-time grant, calls
the provided function only after authorization, and reports the outcome:

```ts
import { ActionProxyClient, runExternalAction } from "@actionproxy/sdk-js";

const client = new ActionProxyClient({ baseUrl: "http://127.0.0.1:8787" });

const governed = await runExternalAction({
  client,
  toolName: "customer.send_update",
  input: {
    to: "customer@example.com",
    subject: "Refund update",
    body: "Your request is ready.",
  },
  requestedBy: "local-developer",
  agentId: "consumer-app",
  idempotencyKey: "consumer-demo:customer-update:1",
  reason: "Send the reviewed customer update.",
  execute: async (approvedInput) => {
    // Keep this callback local and simulated until the complete proof passes.
    return { simulated: true, deliveredTo: approvedInput.to };
  },
});

console.log(governed.toolCall.status, governed.result);
```

For the first run, leave the callback simulated. Confirm it has not been
called while the approval is pending, approve through
`http://127.0.0.1:5173/#/approvals`, and confirm it runs exactly once with the
approved input. A blocked or rejected proposal never invokes the callback.

If the callback throws after the grant is consumed, `runExternalAction`
records `unknown_outcome` and requires reconciliation. Do not automatically
retry it: the downstream system may have accepted the effect before the error
became visible.

## MCP consumer path

If an existing MCP server owns the real tool, wrap that server instead of
moving its credentials into ActionProxy. The wrapper exposes the downstream
tool list, submits every `tools/call` proposal to ActionProxy, consumes the
approved grant, and only then forwards the call.

Use the complete [MCP wrapper guide](../packages/mcp-wrapper/README.md) and the
[coding-host examples](../examples/mcp-hosts/README.md). The generated Codex,
Claude Code, and generic stdio configurations register only the wrapper. Do
not also register the downstream MCP server directly, because that creates an
ungoverned bypass.

Verify both coordinated records before installing the exact wrapper:

```bash
npm view @actionproxy/sdk-js@0.1.1 version dist.integrity repository.url dist.attestations
npm view @actionproxy/mcp-wrapper@0.1.1 version dist.integrity repository.url dist.attestations
npm install --save-exact @actionproxy/mcp-wrapper@0.1.1
```

The source-bound or offline fallback is symmetrical with the SDK:

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm --filter @actionproxy/mcp-wrapper build
corepack pnpm --filter @actionproxy/mcp-wrapper pack \
  --out actionproxy-mcp-wrapper-0.1.1.tgz
```

## HTTP consumer path

For another language or process, follow [the HTTP API contract](API_SPEC.md)
and the executable [local curl lifecycle](../examples/local-curl-demo/README.md).
The versioned HTTP/SDK fixtures live in
`../fixtures/contracts/http-sdk-conformance-v1.json`.

The runner must submit an external action, wait for `authorized`, consume the
returned grant with the exact tool call, input, and policy binding, execute at
most once, and report the outcome. Do not recreate grant authority locally or
treat an approval record by itself as permission to dispatch.

The generated OpenAPI 3.1 contract is
[`openapi/actionproxy.openapi.json`](../openapi/actionproxy.openapi.json).
Treat server validation as authoritative when a limitation is explicitly
called out, and pin both the package/API version and ActionProxy source revision
used by the consumer.

## Machine-readable contract map

Prefer these artifacts over inferring behavior from examples or prose:

| Contract                          | Artifact                                                                                                | Drift check                                        |
| --------------------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Community HTTP API                | [`openapi/actionproxy.openapi.json`](../openapi/actionproxy.openapi.json)                               | `corepack pnpm openapi:check`                      |
| Policy YAML data model            | [`schemas/actionproxy.policy.v1.schema.json`](../schemas/actionproxy.policy.v1.schema.json)             | `node scripts/generate-config-schemas.mjs --check` |
| MCP-wrapper YAML data model       | [`schemas/actionproxy.mcp-wrapper.v1.schema.json`](../schemas/actionproxy.mcp-wrapper.v1.schema.json)   | `node scripts/generate-config-schemas.mjs --check` |
| Conventional YAML editor mappings | [`schemas/editor-associations.json`](../schemas/editor-associations.json)                               | `node scripts/generate-config-schemas.mjs --check` |
| HTTP/SDK lifecycle cases          | [`fixtures/contracts/http-sdk-conformance-v1.json`](../fixtures/contracts/http-sdk-conformance-v1.json) | SDK and server contract tests                      |
| MCP protocol cases                | [`fixtures/contracts/mcp-conformance-v1.json`](../fixtures/contracts/mcp-conformance-v1.json)           | MCP-wrapper contract tests                         |
| Generated starter contract        | `actionproxy-integration.json` in each generated directory                                              | file hashes in `integrate --json` output           |

The OpenAPI artifact declares OpenAPI 3.1 and JSON Schema draft 2020-12. Its
generator compares the explicit Community operation inventory to the Fastify
routes and excludes static web assets and routes outside the Community boundary.
The two configuration schemas also use draft 2020-12 and carry versioned
canonical IDs. Do not hand-edit generated JSON. Change its generator or runtime
parser, regenerate, and run the checks:

```bash
corepack pnpm openapi:generate
corepack pnpm openapi:check
node scripts/generate-config-schemas.mjs
node scripts/generate-config-schemas.mjs --check
node --test scripts/generate-openapi.test.mjs \
  scripts/generate-config-schemas.test.mjs
```

JSON Schema cannot express every security check. Runtime parsing remains
authoritative for credential-environment isolation, case-insensitive secret
names, and cross-field behavior documented by the MCP wrapper. The policy
schema likewise preserves the v1 parser's compatibility boundaries instead of
pretending unknown legacy fields are rejected everywhere.

## Isolated packed-consumer conformance

The package conformance test does not import either workspace through a
monorepo-relative path. It builds both `0.1.1` tarballs, installs them offline
into a fresh temporary consumer, verifies the exact package contents and type
declarations, imports only their public exports, exercises SDK success and
`unknown_outcome`, and invokes the installed `actionproxy-mcp` binary's static
doctor report:

```bash
corepack pnpm --filter @actionproxy/mcp-wrapper exec vitest run \
  src/package-artifacts.test.ts
```

Run this on every supported Node line before publishing. A passing workspace
test alone is not package-consumer evidence: it can accidentally rely on source
files, hoisted dependencies, or monorepo resolution that are absent from the
tarball.

## Completion contract

Before replacing a simulated callback with a real tool, require evidence for
all of these statements. The mode-specific generated checklist is a safe first
proof, not a claim that it automatically covers every item:

- the integration uses exactly one boundary: SDK runner, MCP wrapper, or HTTP;
- the tool cannot be reached through an ungoverned alternate path;
- allow executes once, pending approval executes zero times, approval executes
  once, and deny executes zero times;
- edited approval input, when enabled, is the input that executes;
- duplicate grant consumption and changed-input replay fail closed;
- ambiguous downstream outcomes are not retried automatically;
- `GET /v1/audit/verify` passes and the expected decision, approval, grant,
  attempt, and outcome events are present; and
- no credentials, customer payloads, or runtime keys entered source control,
  prompts, logs, browser storage, or ActionProxy policy.

## Prompt for a coding agent

Replace the bracketed values and give this task to a coding agent working in
the consumer repository:

```text
Integrate ActionProxy Community from [absolute ActionProxy checkout] into this
project to govern [tool/function]. Read that checkout's AGENTS.md and
docs/ADOPTING.md first. Choose exactly one supported boundary: MCP wrapper for
an existing MCP server, runExternalAction for a JavaScript/TypeScript runner,
or the documented HTTP grant lifecycle otherwise. From this consumer project,
run [absolute ActionProxy checkout]/actionproxy integrate --mode [mcp|sdk|http]
--json and inspect actionproxy-integration.json plus the versioned OpenAPI/JSON
Schema artifact for that boundary. Start with the generated simulated effect
and deterministic proof. Do not request or handle an OpenAI runtime key,
auto-approve, create a parallel policy path, expose a direct downstream bypass,
dispatch from an approval record without consuming exact one-time authority,
or retry an unknown outcome. Prove zero dispatch before approval, exactly one
after approval, zero after denial, and a valid audit chain. Report the chosen
boundary, generated file hashes, files changed, commands and results, and every
production control that remains unresolved.
```
