# Changelog

All notable public changes to ActionProxy are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.1

### Added

- Prepared `@actionproxy/sdk-js` and `@actionproxy/mcp-wrapper` for their first
  public npm release with exact-install guidance, focused registry metadata,
  protected publication gates, and anonymous consumer verification.

### Changed

- Closed the generated Community source import graph and added verification
  that rejects unresolved relative imports.

### Security

- Replaced SDK and MCP-wrapper trailing-slash regular expressions with
  linear-time normalization and added long-input regressions.
- Fully redacted public secret-scan diagnostics and made approval return
  navigation reconstruct typed Quickstart URLs instead of replaying an
  untrusted query string.
- Enforced one effective approver authorization identity per workspace across
  Memory, LocalDev, SQLite, and Postgres storage, including collisions between
  an authenticated principal and another approver's legacy ID fallback.
- Pinned the transitive `nanoid` 3.x dependency to `3.3.18`, the patched floor
  for the zero-size custom-generator denial-of-service advisory.

### Distribution

- Exact registry availability is authoritative only after both `0.1.1` records,
  their integrity, and their provenance verify independently. The reviewed
  source-tarball path remains the fallback when either registry record is absent.

## 0.1.0

### Added

- Approval-gated tool-call lifecycle with allow, deny, and human-approval decisions.
- YAML policy, immutable approval input evidence, signed receipts, one-time execution grants, and append-only audit history.
- Local Community console, JavaScript workspace SDK, stdio MCP wrapper, mock tools, and curl demos.
- Memory, SQLite, and Postgres storage implementations.
- One-command `./actionproxy` First Run for macOS with a deterministic local
  allow/approval/deny proof, Docker-assigned loopback port, retained SQLite
  evidence, safe `stop`, and confirmation-gated `reset`.
- Experimental Secure MCP Tunnel journey for a local three-tool ChatGPT
  demonstration, with live ChatGPT acceptance still pending, plus an
  experimental OAuth-protected Streamable HTTP `/mcp` resource.
- Explicit, checksum-pinned installation, read-only status, offline reuse, and
  receipt-scoped removal of the reviewed official OpenAI `tunnel-client`
  `v0.0.10` asset without `sudo`, `PATH`, or Gatekeeper changes.
- Source-integrity classification, verified MCP influence scopes, minimized
  content-exposure evidence, and fail-closed consequence narrowing.
- Immutable migration artifacts with checksum/locking/restart protection and a
  deterministic Community export manifest with Git checkout attestation.
- Guided allow/approve-or-reject/deny/audit onboarding in the Community console.
- `./actionproxy integrate --mode sdk|mcp|http --json` for non-overwriting,
  credential-free starter integrations with machine-readable hashes and proof
  checklists.
- Versioned JavaScript SDK and MCP-wrapper source-package candidates, an
  OpenAPI 3.1 contract, policy and MCP-wrapper JSON Schemas, and an isolated
  packed-consumer conformance suite.
- An opt-in downstream Google Workspace MCP example pinned to third-party
  `workspace-mcp` 1.22.0. Google OAuth remains in that downstream process; an
  ActionProxy-native Google connector is excluded, Python transitive
  dependencies remain outside the ActionProxy lock/SBOM, and no live Google
  acceptance is claimed.

### Distribution

- `@actionproxy/sdk-js@0.1.0` and `@actionproxy/mcp-wrapper@0.1.0` are packable
  source-package candidates. The packages are not currently published to npm.

### Security

- Local unauthenticated mode is restricted to deliberate development use.
- API-key and OIDC JWT modes are available for self-hosted evaluation.
- Tool-call, approval, remediation, and execution-outcome projections withhold
  internal execution-grant nonces and grant/receipt signatures without hiding
  ordinary provider payload fields with the same names.
- This release is a developer preview and is not presented as a complete production authorization or compliance boundary.
