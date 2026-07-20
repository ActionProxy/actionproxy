# Security policy

## Supported versions

ActionProxy is pre-1.0. Security fixes are made on `main` until release branches exist.

## Reporting a vulnerability

Do not open public issues for vulnerabilities.

Use GitHub's **Report a vulnerability** action on the repository Security page.
It creates a private security advisory visible only to you and the repository's
security managers. If that action is unavailable, open a public issue
containing only `Private security reporting unavailable`; do not include any
vulnerability details. Maintainers will restore the private channel before
requesting the report.

Include:

- affected version or commit,
- reproduction steps,
- impact assessment,
- whether secrets, payloads, audit events, or approvals are exposed or modifiable.

## Security posture

`ACTIONPROXY_AUTH_MODE=none` is local-demo only and must not be exposed to untrusted networks.
Startup is blocked when `ACTIONPROXY_AUTH_MODE=none` and `ACTIONPROXY_HOST=0.0.0.0` unless `ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND=true` is set. Use that opt-in only for intentional localhost-published demo containers, such as Docker `-p 127.0.0.1:8787:8787`.

Any self-hosted deployment reachable beyond loopback should use:

- `ACTIONPROXY_AUTH_MODE=api_key` for service accounts and agent submitters,
- `ACTIONPROXY_AUTH_MODE=oidc_jwt` for human users behind an enterprise IdP,
- durable storage,
- configured `ACTIONPROXY_EXECUTION_GRANT_SECRET`,
- secret injection through environment or the deployment platform, not local UI writes.

Current controls are intended for developer-preview evaluation. This repository
does not claim managed multi-tenant operation, SOC 2 certification, SCIM, SAML,
or regulated high-assurance readiness.

## Audit data custody

ActionProxy stores audit payloads in full, including proposed inputs, original and edited approval payloads, and execution results. API/UI redaction happens only when data is read. It is not storage redaction and does not remove, encrypt, truncate, or retroactively sanitize values in JSONL, SQLite, Postgres, Docker volumes, or backups. Protect the storage path and backups as sensitive business data and avoid submitting secrets that are not required for approval evidence.

Server-side MCP stdio discovery is disabled by default. `ACTIONPROXY_MCP_STDIO_DISCOVERY_ENABLED=true` allows the server to execute profile-defined commands, arguments, working directories, and environment additions for `tools/list` discovery. Enable it only for profiles and administrators you trust; this feature does not sandbox those commands. Saving profiles and generating wrapper YAML do not require the opt-in.
