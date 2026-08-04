# Connect ChatGPT to local ActionProxy

This guided, mock-only journey lets ChatGPT call three local tools through
ActionProxy. It sends no email, changes no customer, connects no SaaS account,
and does not turn local demo authentication into a production identity
boundary.

```text
ChatGPT → OpenAI Secure MCP Tunnel → ActionProxy MCP wrapper
        → local ActionProxy gateway → deterministic mock tools
```

## Fast path

From a fresh checkout on a Mac, you only need these prerequisites before the
first command:

- Node.js 22, 23, or 24 (Node 24 recommended);
- Docker Desktop with Docker Compose v2.

Then run:

```bash
./actionproxy chatgpt
```

The concierge checks the machine first, then keeps you in one guided flow while
you confirm OpenAI access and locate or create the workspace-associated tunnel.
If `tunnel-client` is missing, it offers an explicit `I` choice to install the
ActionProxy-reviewed, pinned copy of the official OpenAI `v0.0.10` asset in
this checkout, while retaining a manual installation path. It opens only
canonical help pages, validates each answer, and rechecks without making you
restart the command. Every external step has a safe pause option.

After those checks, it starts one dedicated loopback-only Docker project on an
automatically assigned port, verifies SQLite and exactly three mock tools, and
opens the browser Quickstart before requesting the OpenAI runtime key with
hidden terminal input. It passes the key to `tunnel-client` through a
mode-`0600` temporary file, removes it on exit or interruption, and never
passes it to Docker or the browser.

Experienced users and noninteractive automation may still supply
`--tunnel-id tunnel_REPLACE_WITH_32_LOWERCASE_HEX` explicitly.

Do not paste the runtime key into a command argument, ChatGPT, ActionProxy's web
console, or a tunnel profile. For noninteractive automation, create a
caller-owned mode-`0600` file outside the checkout and set
`ACTIONPROXY_CONTROL_PLANE_KEY_FILE` to its absolute path. The concierge reads
it after the build, copies it into a private OS-temporary session, and leaves
the caller file untouched. Legacy `CONTROL_PLANE_API_KEY` remains supported
only when `./actionproxy` is invoked directly; the root shim moves it into an
unlinked private file descriptor before Node starts. No program can erase the
raw environment's brief pre-start process-listing window. Do not put the raw
variable in front of `corepack pnpm` or a direct Node entry point; use the file
input for the strict no-process-list exposure path.

The compatibility command delegates to the same implementation:

```bash
corepack pnpm demo:chatgpt:tunnel -- --tunnel-id tunnel_REPLACE_WITH_32_LOWERCASE_HEX
```

## Access boundaries

OpenAI Platform tunnel access and ChatGPT workspace access are separate:

- The Platform identity needs Tunnels **Read + Use**.
- The tunnel must be associated with the target ChatGPT workspace.
- The ChatGPT workspace must allow developer-mode apps.
- Creating or editing tunnels additionally requires **Manage**; the ActionProxy
  runtime does not need that permission.

Use the semantic links printed by the concierge rather than relying on a menu
name that may change. The canonical registry is
[`openai-links.json`](./openai-links.json), reviewed **2026-08-03**. It links to
OpenAI's Secure MCP Tunnel guide, Platform tunnel settings, ChatGPT app
settings, developer-mode guidance, runtime API keys, and tunnel-client release
and configuration pages.

### Install, inspect, or remove the checkout-local client

Choosing `I` in the missing-client flow is the only implicit-journey action
that downloads `tunnel-client` to the host. A cold Docker build can separately
download images and install image-local dependencies. The same helper operation
is available explicitly, along with status that writes no ActionProxy state or
downloads, and scoped removal:

```bash
./actionproxy tunnel-client install
./actionproxy tunnel-client status
./actionproxy tunnel-client remove
```

Each command accepts `--json`. Installation downloads the platform-specific
asset from the official OpenAI `tunnel-client` `v0.0.10` release, verifies it
against the SHA-256 pinned in ActionProxy's reviewed distribution manifest, and
atomically places the executable at `.actionproxy/bin/tunnel-client`. A private
receipt binds the installed file to that digest. A verified existing install is
reused without network access, so later runs can work offline.

The checked-in SHA-256 is the trust anchor for this convenience path. The
upstream `v0.0.10` binary is ad-hoc signed, not Developer ID-signed or notarized;
ActionProxy therefore does not claim that Apple has verified it. Installation
does not use `sudo`, modify global or shell `PATH`, remove quarantine metadata,
or invoke Gatekeeper-override commands. If macOS blocks the binary, the
concierge stops instead of overriding that decision. The optional downloaded
binary is not bundled in the ActionProxy repository and is outside the
repository SBOM.

`remove` refuses to act while a First Run launcher is active. It removes only an
unchanged checkout-local file that matches ActionProxy's install receipt, and
refuses a modified binary or a client placed manually at the same path. Receipt
validation remains sufficient for removal after a later reviewed-distribution
update. Neither `./actionproxy stop` nor `./actionproxy reset` removes the client
or tunnel profiles. Checkout-local is an installation boundary, not a process
sandbox; the native client runs with the current macOS user's ordinary
filesystem and network authority.

For the manual fallback, download the matching
`tunnel-client-v0.0.10-darwin-arm64.zip` or
`tunnel-client-v0.0.10-darwin-amd64.zip` plus `SHA256SUMS.txt` from the same
official release. Before extracting it, run:

```bash
shasum -a 256 tunnel-client-v0.0.10-darwin-<ARCH>.zip
```

Compare all 64 hexadecimal characters with that asset's line in
`SHA256SUMS.txt`. Do not use `sudo`, remove its quarantine attribute, or bypass
Gatekeeper. Put the verified executable at `.actionproxy/bin/tunnel-client` or
set `TUNNEL_CLIENT_BIN` to its path. A manually placed file remains user-owned;
the scoped ActionProxy removal command will refuse to delete it.

## Prove all three policy paths

Keep the launcher terminal open. Once it prints **Secure tunnel ready**, open
the printed ChatGPT app-settings link, add or refresh the developer-mode app,
select the workspace-associated tunnel, and start a new conversation.

Run the prompts revealed by Quickstart, in order:

```text
Use ActionProxy to search the demo docs for the refund policy.
```

```text
Use ActionProxy to send a demo email to customer@example.com with subject
"Refund update" and body "Your request is ready." Wait while I approve it in
ActionProxy.
```

Review the exact proposal locally. Nothing has executed while it is pending.
Approving it continues the original ChatGPT call and produces exactly one mock
execution.

```text
Use ActionProxy to delete customer cus_123 as a policy test.
```

The default policy denies that call before downstream dispatch. ChatGPT may
show its own confirmation; that confirmation is separate from ActionProxy's
policy and approval decision.

Discovery must expose exactly:

- `docs.search` — allowed and executed immediately;
- `gmail.send_email` — held for human approval; and
- `dangerous.delete_customer` — denied before dispatch.

## Diagnose and recover

These checks never install software or start Docker:

```bash
./actionproxy doctor
./actionproxy doctor --chatgpt
./actionproxy doctor --chatgpt --json
```

Inspect the currently recorded Docker and live tunnel state with:

```bash
./actionproxy status
```

If ChatGPT does not call a tool after 30 seconds:

1. Confirm the app is enabled in the conversation.
2. Start a new conversation after adding or refreshing the app.
3. Ask ChatGPT explicitly to invoke the named ActionProxy tool.
4. Run `./actionproxy local` to isolate gateway behavior from ChatGPT access.

The console and audit persist when the tunnel exits. Press `Ctrl+C` to stop
only the tunnel, then use:

```bash
./actionproxy stop
```

That removes only the concierge-owned container and network and retains the
SQLite audit volume. To delete that volume, run `./actionproxy reset` and type
the exact interactive confirmation `DELETE LOCAL AUDIT`. Reset does not remove
unrelated Docker resources, tunnel profiles, or the checkout-local
`tunnel-client`; use `./actionproxy tunnel-client remove` for an
installer-receipt-owned client.

For the advanced public OAuth resource-server path, see
[`docs/CHATGPT_MCP.md`](../../docs/CHATGPT_MCP.md). It is not required for this
first-run demonstration.
