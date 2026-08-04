# Contributing to ActionProxy

Thank you for helping improve ActionProxy Community.

Coding agents and automated contributors must read the repository-wide
[AGENTS.md](AGENTS.md) before editing. It defines the Community boundary,
architecture invariants, focused validation commands, and manifest rules.

## Development setup

Use Node.js 24 for development; CI also tests Node.js 22.

```bash
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm dev
```

The terminal prints the local Quickstart URL. Use the deterministic mock tools
so tests and examples never contact business systems.

## Before opening a pull request

```bash
corepack pnpm lint
corepack pnpm test
corepack pnpm build
corepack pnpm test:e2e:community
corepack pnpm manifest:refresh
git add --all
corepack pnpm verify:tracked-checkout
corepack pnpm verify:oss-boundary
```

Commit the refreshed `PUBLIC_MANIFEST.json` with the files it describes. CI
checks the tracked checkout against that manifest; ignored build and test output
does not affect the attestation.

For the same final boundary result as stable JSON, run:

```bash
node scripts/verify-public-export.mjs . --checkout --strict --json
```

In a clean downloaded archive without `.git`, omit `--checkout`. Manifest and
Git attestation commands are not applicable after editing an archive.

Keep changes inside the approval-gateway boundary. Hosted services, production
SaaS connectors, billing, identity expansion, agent runtimes, and workflow
builders are not part of ActionProxy Community.

Never commit credentials, tokens, customer payloads, or production data. Report
security issues through the process in [SECURITY.md](SECURITY.md), not a public
issue.

## Public contribution flow

By submitting a contribution, you agree that it is licensed under the
repository's Apache License 2.0.

The maintainers incorporate accepted public changes into the maintained source
tree while retaining the original contributor's authorship and attribution.
Public pull requests must include tests for changed behavior and update the
relevant Community docs.
