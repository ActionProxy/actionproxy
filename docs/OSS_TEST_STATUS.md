# ActionProxy Community test status

Last reviewed: **2026-08-17**

This page records what the Community/OSS boundary tests automatically, what has
been exercised only with local fixtures or mocks, and what still needs manual or
external validation. It is an evidence map, not a claim that ActionProxy is a
complete production authorization or compliance boundary.

## Current release status

Community v0.1.1 is **not published yet**. The exact PR2 source checkpoint and
generated Community tree passed the complete local release matrix described
below. The remaining release gates are the owner-controlled public PR workflow,
CodeQL on the exact public head, synchronization-ledger closure, and separately
authorized tag, GitHub Release, and npm publication steps.

Until those steps finish, the public release remains a source-only developer
preview and the two `@actionproxy` packages remain unavailable from npm.
A live ChatGPT Secure MCP Tunnel run, a live Google Workspace downstream-MCP
run, and an uninvolved-user
walkthrough remain post-release validation—not core source-release blockers—so
long as those paths stay explicitly experimental/unvalidated and no live
interoperability, provider-effect, or usability-completion claim is made. npm
publication is a later, separate owner-authorized phase.

An older passing candidate does not validate source or generated artifacts that
changed afterward. Required test skips, stale evidence, or a result from a
different manifest cannot be counted as a release pass.

## OSS integration boundary

Community is proxy-first. It governs a call through HTTP, the JavaScript SDK and
external-runner helper, stdio MCP, or the experimental Streamable HTTP `/mcp`
adapter. The real executor and its credentials remain in an operator-owned MCP
server, internal API, or external runner.

The Community approval channels are the web console, Slack approval messages,
Telegram, the local email outbox, and operator-owned SMTP. The Docs, Gmail,
Jira, and Salesforce setup cards are deterministic local mocks, not production
provider connectors. Separately, Community includes an opt-in Google Workspace
downstream-MCP reference. That example launches an operator-owned third-party
MCP process for real Gmail access; it does not turn the Gmail setup card into a
real connector and does not give ActionProxy custody of Google OAuth tokens.

Native Google Workspace, Slack connected-app/OAuth execution, HubSpot, Zendesk,
Stripe, Teams, and managed Mailgun/Resend delivery are outside the Community
boundary. OSS release testing must prove those modules remain excluded and
unreachable; their provider behavior is not an OSS release gate.

## Exact PR2 candidate validation

The committed PR2 source regenerated a 350-entry Community manifest (351
physical tracked files including `PUBLIC_MANIFEST.json`). The exact generated
tree passed these local gates on 2026-08-17:

| Area | Result | What it covered |
| --- | ---: | --- |
| Community Dashboard edited approval | 27 passed | The focused Community component suite, including editing the reviewed JSON, rendering the edited email proposal, and sending one `inputDecision.mode: "edited"` approval with the review hash |
| JavaScript SDK approval API | 31 passed | The focused client suite, including exact serialization of both `inputDecision.mode: "edited"` and legacy `editedInput` approval payloads |
| Telegram terminal presentation | 39 passed, 1 skipped; 1 Playwright E2E passed | Telegram service/routes plus Memory and SQLite presentation persistence; Postgres persistence was skipped because this focused run had no test database URL. The maintained browser/Fastify/fake-Bot-API E2E verified one terminal card update and exactly-once execution |
| Generated Community export | Passed | Strict export verification and public secret scanning passed for 350 manifest-declared files and 351 physical files including `PUBLIC_MANIFEST.json` |
| Focused type checks | Passed | Community web and JavaScript SDK TypeScript checks |
| Complete Node matrix | Passed on Node 22.15.0 and 24.11.0 | Frozen dependency closure, full root tests, all workspace type checks, builds, package-consumer checks, contracts, schemas, supply-chain checks, and host/preflight suites |
| Community browser lifecycle | 33 passed, 3 intentional skips | Desktop, tablet, 390px, and 320px projects; the desktop macOS visual baseline passed and the same visual-only assertion was intentionally skipped on the three non-desktop projects |
| Real Postgres 16 | 58 passed, 0 skipped | All five required migration, atomicity, forensic-query, content-influence-upgrade, and MCP-backend files against Postgres 16.14 |
| Community Docker | Passed | The exact Community image completed both Memory and SQLite restart/persistence smoke paths |
| OSS boundary and secrets | Passed on Node 22.15.0 and 24.11.0 | Full source-import closure, exact manifest checkout, frozen Community mapping, and public secret scan |

The older focused coverage below passed on Node `24.11.0` on 2026-08-03, with
the Google reference checks refreshed on 2026-08-04. These historical counts
remain useful but are not represented as a rerun against the current tree.

| Area | Result | What it covered |
| --- | ---: | --- |
| Community integration routes and channels | 31 passed | Community-only route shape, Slack delivery/callback/signature behavior, Telegram delivery/webhook behavior, email outbox, and the server import boundary |
| JavaScript SDK | 33 passed | HTTP contracts, approval waiting, exact grant consumption, external execution outcomes, replay/mutation rejection, and no automatic retry of ambiguous outcomes |
| MCP wrapper and package consumer | 63 passed | Configuration/schema parity, doctor, real child-process framing, governed allow/approval/deny, cancellation/timeouts, package inventory, and isolated tarball installation |
| Offline contract validation | 7 passed | OpenAPI 3.1 validation, JSON Schema draft 2020-12 compilation, broken/local/remote reference handling, and exact validator pins |
| Release version consistency | 3 passed | Root, package, contract, First Run, MCP sample, manifest, and intended-tag version agreement |
| First Run and tunnel launcher | 65 passed, 3 skipped | Local and ChatGPT orchestration, credential canaries, pinned installer/removal, interruption and recovery behavior; the skipped cases require a real macOS controlling terminal |
| Supply chain | Passed | Zero dependency advisories, 63 allowlisted production-license records, and a validated CycloneDX 1.7 SBOM with the same 63-component runtime closure |
| Landing release candidate | 13/13 configuration; 24/24 applicable release cases | Four-viewport release/noindex checks for all 14 routes, contract artifacts, metadata, navigation, responsive layout, keyboard/reduced-motion behavior, and serious/critical Axe findings |
| Google reference export boundary | 27/27 on Node 22.15.0 and 27/27 on Node 24.11.0 | Exactly eight explicitly classified reference files exported; `.env.local`, `.actionproxy`, native provider code, and secrets absent; pinned-artifact, environment-isolation, lifecycle, timeout, signal-cleanup, and audit safety checks passed; no live provider call made |
| Public candidate boundary/determinism | 26/26 | Historical explicit-export, byte-identity, three-pass-determinism, strict-mutation, manifest/checkout, workflow, and coding-agent checks; current export size is reported separately above rather than attributed to this older run |

## Automated release coverage

The public workflow and local release tooling are designed to cover:

- frozen install, unit/integration tests, type checks, and builds on Node 22 and
  Node 24;
- policy allow, deny, require-approval, rejection, cancellation, expiry,
  both edited-input approval forms for single-reviewer Community actions,
  original-only and multi-reviewer edit rejection, absence of an approval
  revision route, idempotency, race, grant, replay, timeout, `unknown_outcome`,
  hostile-output, and audit-chain behavior;
- memory and SQLite behavior plus a real Postgres 16 zero-skip conformance job;
- the JavaScript SDK, external-runner authority flow, isolated package
  consumers, stdio MCP wrapper, packaged MCP smoke, and experimental `/mcp`
  protocol/OAuth contracts;
- Community browser lifecycle, responsive/accessibility checks, and the local
  web approval experience;
- Docker memory and SQLite restart/persistence smoke tests;
- deterministic Community export, exact manifest/checkout attestation, private
  module exclusion, secret scanning, immutable workflow references, dependency
  audit, runtime-license inventory, and CycloneDX SBOM validation; and
- public-only CodeQL after repository visibility permits code-scanning upload.

The canonical workflow is [`.github/workflows/security.yml`](../.github/workflows/security.yml).
The main local commands are:

```bash
corepack pnpm test
corepack pnpm lint
corepack pnpm build
corepack pnpm test:e2e:community
corepack pnpm test:postgres:no-skip
corepack pnpm docker:smoke:community
corepack pnpm test:consumer-conformance
corepack pnpm smoke:mcp-package
```

## Integration evidence and limitations

| Surface | Automated evidence | Live or external evidence still missing |
| --- | --- | --- |
| HTTP gateway | Service, route, browser, Docker, storage, approval, grant, execution-attempt, and audit tests | Repeat the complete lifecycle from the final clean archive and correlate only current-run IDs and dispatch counts |
| JavaScript SDK / external runner | Unit and conformance tests plus isolated offline tarball installation | Run the generated SDK starter against the final candidate under Node 22 and 24; downstream provider effects remain operator-owned |
| stdio MCP wrapper | Real deterministic child processes, discovery, exact-once forwarding, cancellation, timeout, hostile output, and packaged smoke | Run the generated MCP starter and full manual approval lifecycle from the final candidate; an arbitrary third-party MCP smoke is useful but not a baseline blocker |
| Google Workspace downstream MCP reference | Exact top-level wheel URL and SHA-256 pin, checked-in policy/config review, 27/27 isolated safety tests on each supported Node major, demo-script syntax/build checks, and the MCP wrapper's deterministic child-process and exact-grant coverage | Post-release experimental validation: from the final clean archive, independently verify the pinned artifact and record its source/license review, then use a dedicated test account to prove a real read, zero draft effects before approval, exactly one draft after approval, rejection/cancellation with zero effects, send denial with no dispatch, audit validity, and sanitized cleanup |
| Experimental `/mcp` | Metadata, OAuth challenge/binding, session, list/call, allow/approval/deny, replay, timeout, and hostile-output tests | No live external authorization-server/ChatGPT interoperability claim; keep the adapter experimental until that is tested |
| ChatGPT Secure MCP Tunnel | Fake-launcher tests, secret-leak canaries, pinned installer tests, official-binary install/status/remove acceptance, and deterministic three-tool local smoke | Post-release experimental validation: one entitled ChatGPT workspace must complete the current-session allow/approve/deny, disconnect, recovery, persistence, and audit proof before any live interoperability claim |
| Web console | Component and Community Playwright coverage for approval review, zero pre-approval effects, execution, rejection, denial, audit, recovery, responsive layout, and accessibility | Repeat the exact README path from the final clean archive; an uninvolved-developer repeat is post-release usability validation before any usability-completion claim |
| Slack approvals | Mocked Slack API delivery plus signed approve/reject callback and approver-authorization tests | No complete real-workspace delivery and button callback acceptance is recorded for the final candidate |
| Telegram approvals | Mocked Bot API delivery, webhook-secret, setup-link, identity mapping, approval callbacks, stale/replayed callback handling, configured Web UI origin/port propagation, and terminal card synchronization across Web/API and Telegram decisions; automated cases cover removal of callback buttons, multiple deliveries/resends, partial quorum, finalization during send, and bounded edit failure without changing the authoritative decision. A maintained Playwright E2E drives the real Community Web UI and Fastify lifecycle while capturing an isolated fake Bot API send/edit pair and exactly-once execution. | Run a complete public-HTTPS webhook approve/reject loop on the final candidate and verify the real Bot API terminal edit, retained status link, stale-button response, and deleted/inaccessible-message behavior; existing live evidence covers only historical bot setup/test-send |
| Email outbox | File delivery, payload redaction, review-link resolution, integration routes, and Docker-visible outbox smoke | No additional provider work is required for the local outbox itself |
| SMTP | Configuration/readiness and shared email-message behavior | Add an automated local fake-SMTP protocol test and perform a real delivery/open test before calling SMTP live-validated |

Slack, Telegram, and SMTP may remain optional developer-preview channels only
if their documentation states that the operator must validate the provider path.
Run one sandbox end-to-end acceptance per channel before describing it as
release-quality or production-ready.

Telegram terminal-card edits are best-effort presentation maintenance, not an
authorization step. Automated failure and timeout isolation does not establish
that a live Telegram message was edited; deployments must retain the web console
as the canonical review/status surface and audit presentation-update failures.

## Formal release blockers

These are release blockers for the exact final Community tree:

1. Preserve the exact attributable PR2 source checkpoint and regenerate an
   identical Community tree after these evidence-only documentation updates.
2. Run the public PR workflow and CodeQL against the exact reviewed PR2 head;
   do not substitute local evidence from another tree.
3. Close the private synchronization ledger with the exact squash topology,
   merged-main checks, and restored-protection evidence before any release tag.
4. From a fresh generated Mac tree with no `.git`, `node_modules`, or
   `.actionproxy`, prove exact approval, rejection, edited approval, denial,
   SQLite persistence, HTTP, SDK, MCP, and audit integrity.
5. Run the public workflow on the exact release commit, including full-history
   secret scanning and public-only CodeQL before the release tag, and confirm
   the intended repository protections and release settings.
6. Preserve the locally verified package tarballs, public manifest, OpenAPI and
   schema artifacts, license report, SBOM, and their digests as one immutable
   evidence set; these local package artifacts test the shipped source and do
   not imply npm availability. Download the evidence again and recheck every
   hash before release.
7. Verify every advertised OpenAPI and JSON Schema URL returns the exact
   attested bytes with the intended content type, CORS, cache behavior, and
   locally resolvable references.
8. Obtain owner/legal signoff for the final project/source-release and trademark
   names before publishing `v0.1.1`. Package-name clearance belongs to the later
   npm phase.

After PR2 merges, explicitly pass the public workflow/CodeQL on exact `main`,
then create the tag, verify the logged-out commit and tagged archives, publish
the GitHub Release, and only then deploy the indexable landing artifact. npm
package links are not part of this critical path.

## Post-release validation for experimental paths

These items do not block the source-only developer preview. They must remain
reported under `postReleaseValidation`, not `manualGates`, and the related
paths/claims remain experimental or unvalidated until they pass:

1. Complete the real entitled ChatGPT Secure MCP Tunnel acceptance, including
   zero effects before review, exactly one approved effect, destructive denial
   without dispatch, tunnel loss/recovery, and retained audit evidence.
2. Complete the Google Workspace downstream-MCP acceptance from the exact
   public archive with a dedicated test account. Record only versions,
   timestamps, booleans, and sanitized identifiers; never retain OAuth values,
   mailbox content, message bodies, or account addresses in evidence.
3. Have an uninvolved Mac developer complete the documented first-run path
   without maintainer coaching before making usability-completion claims.

## Planned or claim-dependent hardening

The following work improves confidence but should not turn Community into a
connector marketplace or hosted control plane. It is not a baseline source-only
release blocker unless the corresponding public claim or release scope changes:

- make the first post-release product milestone a guided **Connect your first
  real tool** handoff: continue from a verified mock proof into exactly one
  downstream MCP, SDK runner, or HTTP boundary; keep provider credentials in
  the user-owned executor; start with discovery or a read-only call; require an
  explicit simulated-to-real transition; and verify one-use execution plus
  audit evidence without auto-approval or an ungoverned bypass claim;
- keep npm publication as a separate owner-authorized phase; for the coordinated
  v0.1.1 npm launch, registry provenance and clean consumer installation are
  release gates;
- add fake-SMTP protocol coverage and a secret-backed Telegram terminal-card
  edit acceptance without making PR CI depend on third-party availability;
- maintain optional secret-backed Slack, Telegram, SMTP, external OAuth, and
  arbitrary downstream MCP acceptance jobs without making PR CI depend on
  third-party availability;
- add per-package SBOMs, artifact attestations, and scheduled post-release
  checks for public links, contract digests, and clean package installation;
- document API/package/schema compatibility rules and publish a dereferenced
  OpenAPI artifact for generators that cannot resolve sibling schemas; and
- add a sanitized support bundle and cleanup preview without collecting
  credentials, raw payloads, tunnel/workspace identifiers, or broad process
  environment data.

See [Community capabilities](COMMUNITY_CAPABILITIES.md),
[Adopting ActionProxy](ADOPTING.md), [Approval channels](APPROVAL_CHANNELS.md),
[External runners and MCP](EXTERNAL_RUNNERS_MCP.md), and
[Security model](SECURITY_MODEL.md) for the corresponding product boundaries.
