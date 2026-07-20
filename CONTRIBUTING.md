# Contributing to ActionProxy

Thank you for helping improve ActionProxy Community.

## Development setup

Use Node.js 24 for development; CI also tests Node.js 22.

```bash
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm dev
```

The terminal prints the local Demo Lab URL. Use the deterministic mock tools so
tests and examples never contact business systems.

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

Keep changes inside the approval-gateway boundary. Hosted services, production
SaaS connectors, billing, identity expansion, agent runtimes, and workflow
builders are not part of ActionProxy Community.

Never commit credentials, tokens, customer payloads, or production data. Report
security issues through the process in [SECURITY.md](SECURITY.md), not a public
issue.

## Public contribution flow

The maintainers port accepted public changes into the source monorepo and retain
the original contributor's authorship and attribution. Public pull requests must
include tests for changed behavior and update the relevant Community docs.
