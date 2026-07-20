# Changelog

All notable public changes to ActionProxy are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0

### Added

- Approval-gated tool-call lifecycle with allow, deny, and human-approval decisions.
- YAML policy, immutable approval input evidence, signed receipts, one-time execution grants, and append-only audit history.
- Local Community console, JavaScript workspace SDK, stdio MCP wrapper, mock tools, and curl demos.
- Memory, SQLite, and Postgres storage implementations.
- Secure MCP Tunnel example for a local three-tool ChatGPT demonstration and
  an experimental OAuth-protected Streamable HTTP `/mcp` resource.
- Source-integrity classification, verified MCP influence scopes, minimized
  content-exposure evidence, and fail-closed consequence narrowing.
- Immutable migration artifacts with checksum/locking/restart protection and a
  deterministic Community export manifest with Git checkout attestation.
- Guided allow/approve-or-reject/deny/audit onboarding in the Community console.

### Security

- Local unauthenticated mode is restricted to deliberate development use.
- API-key and OIDC JWT modes are available for self-hosted evaluation.
- This release is a developer preview and is not presented as a complete production authorization or compliance boundary.
