# Troubleshooting

## Corepack or pnpm reports an unsupported Node release

ActionProxy supports Node 22–24 and recommends Node 24. Select a supported
release with your existing Node installation or version manager, then verify
the active shell before invoking Corepack:

```bash
node --version
corepack enable
corepack pnpm --version
```

The repository includes `.nvmrc` and `.node-version`. If you already use
`nvm`, `nvm install 24` followed by `nvm use` selects the recommended release;
tools such as `asdf` and `mise` can use `.node-version` instead. ActionProxy
does not require or install a particular version manager.

If Corepack fails with `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING`, the active
shell is usually still running an unsupported Node release with a pnpm 11
shim. Confirm that
`node --version` prints a supported release before retrying. After changing
Node versions, open a new shell if the old Corepack executable remains cached.

The expected pnpm release is the exact version in the root `packageManager`
field. If an older Corepack cache is damaged, remove it using the documented
procedure for your Node/version-manager installation and rerun `corepack
enable`; do not copy a global pnpm installation into the repository.

## Port 8787 or 5173 is occupied

The beginner command uses a Docker-assigned loopback port, so an occupied 8787
does not require manual intervention:

```bash
./actionproxy local --port auto
```

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

## `tunnel-client` is missing or incompatible

The ChatGPT journey offers `I` only when an interactive user explicitly chooses
the ActionProxy-reviewed convenience install. You can inspect or invoke the
same scoped operation directly:

```bash
./actionproxy tunnel-client status
./actionproxy tunnel-client install
./actionproxy tunnel-client remove
```

Each command accepts `--json`. Install selects the official OpenAI `v0.0.10`
asset for this Mac, verifies it against ActionProxy's checked-in SHA-256, and
places it at `.actionproxy/bin/tunnel-client` without `sudo`, a `PATH` change,
or a Gatekeeper/quarantine change. The upstream binary is ad-hoc signed, not
Developer ID-signed or notarized; the digest is ActionProxy's review anchor, not
an Apple-verification claim. The optional downloaded binary is outside the
repository SBOM.

If the network is unavailable, a previously receipt-verified compatible local
install is reused. Otherwise follow the manual official-release and checksum
procedure in the [Secure MCP Tunnel example](../examples/chatgpt-tunnel/README.md),
then rerun the journey. A manually placed file remains user-owned.

Removal is intentionally conservative: it refuses while a First Run launcher is
active and removes only the unchanged checkout-local client bound to
ActionProxy's install receipt. It refuses modified or manually placed files and
never touches `TUNNEL_CLIENT_BIN` or a client on `PATH`. `stop` and `reset`
retain the client. The following diagnostics write no ActionProxy state and
never download software or start Docker; ChatGPT diagnostics may execute the
selected client's help/version probes:

```bash
./actionproxy doctor --chatgpt
./actionproxy doctor --chatgpt --json
```

## The Secure MCP Tunnel is not visible in ChatGPT

Treat Platform tunnel access and ChatGPT workspace access as separate checks.
The external instructions below were reviewed on **2026-08-03**:

1. Confirm that the target ChatGPT workspace allows developer mode using
   OpenAI's canonical [developer-mode guidance](https://help.openai.com/en/articles/12584461-developer-mode-apps-and-full-mcp-connectors-in-chatgpt-beta).
2. Confirm that the Platform organization owner or RBAC administrator granted
   you Tunnels **Read** + **Use**. Creating or editing the tunnel additionally
   requires **Manage**.
3. In [Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels),
   confirm that the tunnel is associated with the target ChatGPT workspace. A
   Platform organization association alone does not make it appear in a
   different ChatGPT workspace.
4. Keep the launcher running, then open
   [ChatGPT app settings](https://chatgpt.com/plugins) in that workspace and
   create the developer-mode app described by OpenAI's current UI.

If discovery or tool calls fail after the tunnel appears, rerun:

```bash
./actionproxy doctor --chatgpt
```

Then confirm the launcher terminal is still connected. See the complete
[Secure MCP Tunnel example](../examples/chatgpt-tunnel/README.md) and OpenAI's
[Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

## An approval notification was not delivered

The pending approval should still be visible in the web console. Inspect the
audit log for the channel delivery error, correct the deployment-managed
configuration, and use the channel test action before retrying a real flow.
