# Google Workspace MCP Demo

This opt-in developer-preview reference puts ActionProxy in front of a real
Google Workspace MCP server. It is included in Community to demonstrate the
downstream MCP boundary; it is not part of the zero-credential First Run.

The first governed write action is creating a Gmail draft. The demo does not send live email.

```text
Scripted MCP host
  -> ActionProxy MCP wrapper
  -> ActionProxy policy / approval / grant / audit
  -> workspace-mcp
  -> Gmail draft
```

This folder is intentionally separate from production server code. ActionProxy
does not store the Google credentials or implement a native Google connector
for this reference. The operator-owned third-party MCP process receives the
OAuth settings and keeps its own local OAuth state.

Use a dedicated test mailbox. The downstream MCP server can access data allowed
by the scopes you grant, but the proof withholds provider result content and
account addresses from terminal output. The MCP wrapper reports downstream
results back to ActionProxy as execution outcomes, and those results may be
stored raw even though they are not printed. Do not use mailbox content, OAuth
values, account addresses, or message bodies in screenshots, issue reports, or
release evidence.

## Prerequisites

- macOS
- Node dependencies installed with `corepack pnpm install`
- `uv` / `uvx` installed with Homebrew:

```bash
brew install uv
```

The downstream MCP server is third-party
[`workspace-mcp` 1.22.0](https://pypi.org/project/workspace-mcp/1.22.0/).
Review its pinned
[`v1.22.0` README](https://github.com/taylorwilsdon/google_workspace_mcp/blob/v1.22.0/README.md)
and
[`v1.22.0` MIT license](https://github.com/taylorwilsdon/google_workspace_mcp/blob/v1.22.0/LICENSE)
before granting access. The example launches it locally through `uvx` from an
exact `workspace-mcp` 1.22.0 PyPI wheel URL with a checked-in SHA-256 fragment.
ActionProxy does not vendor or sandbox it, and its Python dependency closure is
separate from ActionProxy's Node lock and SBOM. Every run asks before allowing
`uvx` network/download activity, including when its cache is warm, unless that
launch uses `--allow-download`. The runner keeps the uv cache and any uv-managed
Python under `.actionproxy/google-workspace-mcp/`. Independently verify the
checked-in wheel pin, upstream source, and MIT license before granting access.

Reviewed on 2026-08-04 against the official PyPI `1.22.0` metadata:

- Python: `>=3.10`
- wheel: `workspace_mcp-1.22.0-py3-none-any.whl`
- wheel SHA-256:
  `c17daecb5b3050f7e89019a1f364cf20e950ecadca9a705c1627387ebc987b21`
- source archive SHA-256:
  `56f9bb6b629bd816a53a535f6a0afd73a3e8218eb45abb98a1f470db8a9e1210`

The wrapper installs from the exact wheel URL with its SHA-256 fragment, so the
top-level artifact is byte-pinned. Its Python dependencies are still resolved
from the ranges declared by that wheel; they are not part of ActionProxy's pnpm
lock or SBOM. Re-run third-party review and acceptance before changing the pin.

No live Google-account acceptance has been recorded for this release candidate.
The automated suite exercises the isolated runner and ActionProxy governance
boundary without invoking Google OAuth or a provider API. Do not describe this
example as verified live Google support until the documented manual acceptance
has completed against the exact public candidate.

## Google Cloud Setup

Use a test Gmail or Google Workspace account.

1. Open Google Cloud Console and create or choose a project.
2. Enable the Gmail API for that project.
3. Configure the OAuth consent screen.
4. If the app is in testing mode, add your Gmail account as a test user.
5. Create an OAuth Client ID.
6. Choose **Desktop app** as the application type.
7. Copy the client ID and client secret.

The demo uses Gmail draft permissions through `workspace-mcp` and creates a draft only after ActionProxy approval.

## Configure Local Secrets

Create the local file with private permissions:

```bash
umask 077
cp examples/google-workspace-mcp-demo/.env.example examples/google-workspace-mcp-demo/.env.local
chmod 600 examples/google-workspace-mcp-demo/.env.local
```

Fill in:

```bash
GOOGLE_OAUTH_CLIENT_ID=...
GOOGLE_OAUTH_CLIENT_SECRET=...
USER_GOOGLE_EMAIL=your-test-account@gmail.com
```

This file is mandatory and authoritative. The runner removes all supported
Google-demo and input variables inherited from the shell before reading it, so
an ambient Google account or OAuth value cannot silently override this file.
The scoped gateway and web commands also strip Google Workspace, Gmail, OAuth,
and downstream MCP variables from their child environments. The runner passes
the reviewed OAuth values only to the downstream wrapper process; they are not
supplied to the ActionProxy gateway or Vite process.

Optional:

```bash
GMAIL_DRAFT_TO=your-test-account@gmail.com
GMAIL_DRAFT_SUBJECT=ActionProxy local Gmail MCP draft test
GMAIL_DRAFT_BODY=This draft was created only after ActionProxy approval.
GMAIL_SEARCH_QUERY=subject:"ActionProxy local Gmail MCP draft test" newer_than:1d
```

`GMAIL_DRAFT_TO` must resolve to the same address as `USER_GOOGLE_EMAIL`.
The runner intentionally refuses to submit an initial proposal for any other
recipient. Use
synthetic subject/body text: ActionProxy retains proposed inputs in its local
audit store even though the terminal does not print them.

OAuth tokens, the pinned third-party cache, attachments, logs, temporary files,
the downstream process home, and the scoped development gateway data are
confined to:

```text
.actionproxy/google-workspace-mcp/
```

The runner enforces mode `0700` on its state directories and `0600` on
`.env.local` and its non-secret dependency marker. New child files inherit a
`0077` umask. `.actionproxy/` and `.env.local` are ignored by git, but ignoring a
file is not an access control: keep the checkout accessible only to the intended
local user.

## Run

Terminal 1:

```bash
corepack pnpm dev:proxy:gmail-mcp
```

Terminal 2:

```bash
corepack pnpm dev:web:gmail-mcp
```

Terminal 3:

```bash
corepack pnpm demo:gmail-mcp
```

Pressing Ctrl+C in Terminal 3 stops the wrapper and its downstream MCP process
with a bounded cleanup, including during OAuth or approval waiting. The gateway,
web console, and scoped local evidence remain until you stop or remove them.

Every run asks before launching the pinned third-party package because `uvx`
may still contact package indexes or resolve transitive dependencies with a
warm cache. The downstream startup timeout is three minutes so a clean Mac has time to
resolve and prepare the pinned Python package. If startup times out, confirm the
network can reach PyPI, then rerun; the same removable private cache is reused,
but the next launch still requires explicit network/download consent.

On a new account, the first read-only search opens the Google OAuth flow and
returns an authentication-needed result. Complete the browser callback and
press Enter; the runner retries that same search exactly once without printing
the provider URL or account. After the script calls `draft_gmail_message`, open:

```text
http://127.0.0.1:5173/#/approvals
```

Choose **Approve exact proposal** without editing its JSON. Before approval, the
runner verifies that ActionProxy has recorded zero execution attempts. It then
consumes the one-time execution grant and requires one successful attempt. When
you choose the exact-proposal action without editing, that self-addressed input
is forwarded. The same run automatically proves a rejected draft, a cancelled
draft, a denied live-send proposal, and the local audit hash chain.

For repeatable development against an isolated test account only, you can
explicitly auto-approve the pending ActionProxy approval:

```bash
corepack pnpm demo:gmail-mcp -- --allow-download --auto-approve
```

Do not use `--auto-approve` for the first acceptance run or with a mailbox that
contains real user or production data.

## Expected Behavior

- `search_gmail_messages` executes without approval.
- On first authentication, its initial provider attempt may report that OAuth
  is needed. After the browser callback, the runner makes one bounded retry and
  proves the successful current call separately.
- `draft_gmail_message` creates a pending ActionProxy approval.
- Zero downstream execution attempts exist before approval.
- The submitted proposal is self-addressed. Acceptance requires choosing
  **Approve exact proposal** without editing; this runner does not yet
  independently hash-check an input edited in the approval UI.
- Under that acceptance procedure, ActionProxy forwards the proposal to
  `workspace-mcp` exactly once.
- One Gmail draft appears in the test account; no message is sent.
- A second proposal is rejected and a third is cancelled, both without a
  downstream attempt.
- The `gmail:drafts` downstream permission normally withholds
  `send_gmail_message` entirely. The runner therefore submits a real
  `send_gmail_message` proposal directly to ActionProxy and requires
  `decision=deny`, `status=blocked`, a `policy.deny` audit event, and zero
  execution attempts. If a reviewed upstream version unexpectedly exposes the
  send tool at this permission level, the wrapper path must prove the same
  denial and no-dispatch evidence.
- Audit includes the expected policy, approval, grant, attempt, outcome, reject,
  cancellation, and denial evidence, and its local hash chain verifies.

ActionProxy's audit proves what reached and passed its configured boundary. It
does not independently prove the resulting state in Gmail. Before approving,
confirm that no matching draft exists. After completion, confirm exactly one
matching draft and no sent message. Those provider checks remain manual release
evidence.

The scoped development command uses memory governance storage by default, which
clears when that gateway process stops, but its JSONL audit and downstream
execution outcomes may still be written beneath
`.actionproxy/google-workspace-mcp/actionproxy-data/`. If you deliberately use
SQLite, Postgres, or another persistent configuration, use a test-only scoped
store and clean it separately according to that backend; stopping the process
does not erase persistent evidence.

## Cleanup

After the test, delete the test draft, revoke the test app from the Google
account, stop the local processes, and move only these paths to Trash if you do
not want to retain OAuth material or the local third-party cache:

```text
.actionproxy/google-workspace-mcp/
examples/google-workspace-mcp-demo/.env.local
```

Do not copy either path into an archive or public bug report. A release-evidence
record should contain only reviewed versions, timestamps, boolean checks, and
non-identifying correlation values.

## Troubleshooting

If ActionProxy is not reachable, start it with:

```bash
corepack pnpm dev:proxy:gmail-mcp
```

If `uvx` is missing:

```bash
brew install uv
```

If Google OAuth does not open or complete:

- confirm the Gmail API is enabled,
- confirm the OAuth client is a Desktop app,
- confirm your email is added as a test user when the consent app is in testing mode,
- delete `.actionproxy/google-workspace-mcp/credentials` and retry if cached credentials are stale.

The pinned downstream uses `127.0.0.1:8000` for its local OAuth callback. The
runner checks that port before starting. If it is occupied, inspect the owner
with `lsof -nP -iTCP:8000 -sTCP:LISTEN`, stop that specific process, and rerun.

If `draft_gmail_message` is not listed, confirm `actionproxy.mcp.yaml` uses:

```text
stdioFraming: newline
--from https://files.pythonhosted.org/.../workspace_mcp-1.22.0-py3-none-any.whl#sha256=<checked-in-sha256>
workspace-mcp
--permissions gmail:drafts --tool-tier extended
```

`draft_gmail_message` is in the extended Gmail tool tier for `workspace-mcp`.
