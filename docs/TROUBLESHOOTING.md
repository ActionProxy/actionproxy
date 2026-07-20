# Troubleshooting

## Corepack or pnpm reports an unsupported Node release

ActionProxy supports Node 22 and 24 and recommends Node 24. The repository pins
that version in `.nvmrc` and `.node-version`.

```bash
nvm install 24
nvm use
node --version
corepack enable
corepack pnpm --version
```

If Corepack fails with `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING`, the active
shell is usually still running an unsupported Node release with a pnpm 11
shim. Confirm that
`node --version` prints `v24.x` (or `v22.x`) before retrying. Open a new shell
after `nvm use` if the old Corepack executable remains cached by the shell.

The expected pnpm release is the exact version in the root `packageManager`
field. If an older Corepack cache is damaged, remove it using the documented
procedure for your Node/version-manager installation and rerun `corepack
enable`; do not copy a global pnpm installation into the repository.

## Port 8787 or 5173 is occupied

`corepack pnpm dev` starts the API on `127.0.0.1:8787` and Vite on
`127.0.0.1:5173`. Stop the process using the occupied port, or set an explicit
server port before starting the server-only command. The combined supervisor
stops both children when either cannot start.

For Docker, choose another host port without changing the container port:

```bash
ACTIONPROXY_DOCKER_PORT=18787 docker compose up --build
```

## The browser route returns the wrong page

Use `http://127.0.0.1:5173/#/demo` with Vite. Use
`http://127.0.0.1:8787/app#/demo` when the server is serving the bundled Docker
console.

## SQLite cannot start

Source development requires the `sqlite3` command-line tool when
`ACTIONPROXY_STORAGE=sqlite`. The Community Docker image already includes it.
Confirm the configured data directory is writable and that another migration
process has not exceeded the bounded startup-lock timeout.

## An MCP tool is missing

Run the wrapper doctor first:

```bash
corepack pnpm --filter @actionproxy/mcp-wrapper build
./packages/mcp-wrapper/dist/index.js doctor \
  --config examples/mcp-demo/actionproxy.mcp.yaml --discover --json
```

Discovery starts the configured child command and is not a sandbox. Use it only
for reviewed local profiles.

## An approval notification was not delivered

The pending approval should still be visible in the web console. Inspect the
audit log for the channel delivery error, correct the deployment-managed
configuration, and use the channel test action before retrying a real flow.
