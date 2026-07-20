# Storage

ActionProxy supports three storage modes:

- `memory`
- `sqlite`
- `postgres`

The core service uses the same storage interface in every mode, so API behavior should remain compatible across local demos, durable local installs, and Postgres deployments.

## Concurrency contract

Approval decision/rejection and one-time execution-grant consumption use explicit storage-level atomic primitives instead of service-level read/check/write updates.

The tested contract is intentionally narrow:

- memory and SQLite pass same-process `Promise.all` races, including two SQLite store instances pointed at one database file;
- Postgres atomic approval and grant updates are exercised in CI through two independent store/pool instances;
- audit hash-chain appends are serialized within one running `ChainedAuditStore`/server process.

ActionProxy does not currently claim a multi-process audit-chain writer guarantee for multiple server processes appending to the same backend. Use a single audit writer/server process for the community release unless an external deployment layer provides stronger serialization.

## Memory

```bash
ACTIONPROXY_STORAGE=memory
ACTIONPROXY_APPROVER_DIRECTORY_PATH=.actionproxy/approver-directory.local.json
```

This is the default. Tool-call and approval state is in memory. Audit events continue to append to `.actionproxy/audit.jsonl`.

The approver directory is the exception: ActionProxy persists approver users and groups to `ACTIONPROXY_APPROVER_DIRECTORY_PATH` even in memory mode. The default path is `.actionproxy/approver-directory.local.json`. The file is written with atomic replacement and restrictive local file permissions where the filesystem supports them, so local approver identities, Slack IDs, Telegram IDs, and notification routing do not disappear on every dev-server restart.

Use this for quick local demos and tests where tool-call and pending-approval restart persistence is not required.

## SQLite

```bash
ACTIONPROXY_STORAGE=sqlite
ACTIONPROXY_SQLITE_PATH=.actionproxy/actionproxy.sqlite
```

SQLite stores:

- tool calls
- approvals
- audit events
- approver users and groups, including authenticated-principal mappings
- execution results
- policy versions
- workspace record
- service accounts and hashed API keys
- execution grants
- execution attempts and signed receipts
- idempotency records
- observed policy-detector tools
- content-influence scopes and minimized exposure evidence

The current implementation uses the local `sqlite3` command-line tool instead of a native Node module. Install `sqlite3` before using SQLite mode. Every CLI invocation has a bounded busy timeout so a short-lived writer does not immediately surface as `database is locked`.

The Community runtime Docker image installs `sqlite3` and packages the complete
canonical `apps/server/src/storage/migrations/` directory. The Docker smoke
creates SQLite state on a named volume, restarts the container against that same
volume, and verifies approval, audit, MCP, and content-exposure persistence.
The default Docker/Compose demo remains memory mode.

On startup, ActionProxy verifies the ordered migration ledger and applies only pending migrations. SQLite serializes startup migration work with a database-adjacent process lock plus `BEGIN IMMEDIATE`. A dead lock owner is reclaimed; a live owner is allowed a bounded wait. Normal restart startup reads the ledger in one SQLite process instead of repeating table-by-table schema inspection.

SQLite is the recommended durable mode for local, self-hosted, and small-team installs.

## Postgres

```bash
ACTIONPROXY_STORAGE=postgres
DATABASE_URL=postgres://actionproxy:actionproxy@127.0.0.1:54329/actionproxy
```

Start the local Postgres service:

```bash
docker compose --profile postgres up -d postgres
```

Then start ActionProxy:

```bash
ACTIONPROXY_STORAGE=postgres DATABASE_URL=postgres://actionproxy:actionproxy@127.0.0.1:54329/actionproxy corepack pnpm dev
```

Postgres uses the same initial schema as SQLite and stores:

- tool calls
- approvals
- audit events
- approver users and groups, including authenticated-principal mappings
- execution results
- policy versions
- workspace record
- service accounts and hashed API keys
- execution grants
- execution attempts and signed receipts
- idempotency records
- observed policy-detector tools
- content-influence scopes and minimized exposure evidence

Postgres mode requires the server package dependency `pg`.

## Migrations

The v0.1 migration sequence is:

```text
1  0001_initial
2  0002_legacy_schema_reconciliation
3  0003_approver_principal_identity
```

Each entry is an immutable SQL artifact under
`apps/server/src/storage/migrations/`. Its checksum covers the exact file bytes.
The reconciliation file declares only recognized missing Community columns; the
migrator applies those declarations with backend-appropriate metadata checks.
Migration SQL is never generated or rewritten during public export.

Applied entries are stored in `actionproxy_schema_migrations` with their immutable ID, numeric position, SHA-256 checksum, and application timestamp. Startup fails closed if the database contains an unknown entry, a gap or reordering, or a checksum that no longer matches the released migration source. Do not edit a released migration or its compatibility manifest; add the next ordered migration instead.

SQLite applies each pending step transactionally while holding its migration lock. Postgres uses one checked-out connection, a transaction-scoped advisory lock keyed by the current database and schema, and one transaction for ledger verification plus all pending steps. `PostgresStore.connect` reuses that migrated pool rather than creating a second startup pool.

Databases created before the ledger are adopted only when their exact known
Community schema/checksum state is recognized. ActionProxy creates absent core
tables and indexes, adds only declared missing Community columns, and records
the ordered ledger. Existing tool calls, pending approvals, receipts, audit
events, approver identities, and content-influence records are not rewritten.
Unrelated tables are ignored. Restarting verifies the ledger and does not replay
reconciliation.

Back up the database before upgrading a real installation. If checksum or ordering verification fails, restore the matching application build or database backup; do not manually rewrite the ledger to force startup.

## Compatibility

Existing API responses are unchanged:

- `POST /v1/tool-calls`
- `GET /v1/tool-calls`
- `GET /v1/tool-calls/:id`
- `GET /v1/approvals/pending`
- approval and rejection endpoints
- `GET /v1/audit`

Durable modes preserve pending approvals, approver directory records, and audit events across process restarts. Memory mode does not preserve pending approvals after restart, but it does preserve approver directory records through `ACTIONPROXY_APPROVER_DIRECTORY_PATH`.

Policy-detector observations use the same storage mode as tool calls and approvals. Detector rows store tool names, source metadata, schema hashes, coverage, status, and suggestions; they do not store raw tool-call inputs.

Audit events written by the server include `eventHash` and `previousEventHash`. Existing pre-enterprise audit rows without those fields remain readable, but hash-chain verification only passes for events written through the chained audit writer.

Audit payloads are stored in full in JSONL, SQLite, and Postgres. Redaction applied by API/UI read routes is not storage redaction and does not alter existing rows, files, volumes, or backups.
