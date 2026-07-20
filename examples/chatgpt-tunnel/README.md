# Connect ChatGPT to the local ActionProxy demo

This beginner path keeps ActionProxy on loopback and uses OpenAI Secure MCP
Tunnel to reach the existing ActionProxy stdio wrapper:

```text
ChatGPT -> OpenAI Secure MCP Tunnel -> ActionProxy MCP wrapper
        -> local ActionProxy gateway -> deterministic mock MCP tools
```

It is a local, mock-only demonstration. It does not send email, delete customer
data, connect a SaaS account, or turn local demo authentication into a
production identity boundary.

## Prerequisites

- Docker with Compose;
- Node.js 22 or 24 and Corepack;
- ChatGPT developer mode;
- an OpenAI Platform tunnel associated with the target ChatGPT workspace;
- Tunnels `Read` and `Use` permission; and
- the current `tunnel-client` on `PATH`.

Create or select the tunnel in
[OpenAI Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels).
Keep its runtime API key in the shell only:

```bash
export CONTROL_PLANE_API_KEY='<runtime-key-from-openai-platform>'
```

From the repository root, run:

```bash
corepack pnpm demo:chatgpt:tunnel -- --tunnel-id tunnel_REPLACE_ME
```

The launcher verifies its prerequisites, starts the bundled Community Docker
service, checks that the wrapper exposes exactly the three demo tools,
initializes and validates the tunnel profile, and keeps the tunnel running in
the foreground. It stores only non-secret profile metadata under the ignored
`.actionproxy/` directory. Use `--profile another-name` when the default profile
already belongs to another tunnel.

Open the printed local Demo Lab URL. In ChatGPT, enable developer mode, open
**Settings -> Plugins**, create a developer-mode app, choose **Tunnel** as the
connection, and select the same tunnel. Keep the launcher terminal open.

Try these prompts:

```text
Use ActionProxy to search the demo docs for the refund policy.
```

```text
Use ActionProxy to send a demo email to customer@example.com with subject
"Refund update" and body "Your request is ready." Wait while I approve it in
ActionProxy.
```

Approve the pending email in Demo Lab. The original ChatGPT tool call then
continues and returns a mock result.

```text
Use ActionProxy to delete customer cus_123 as a policy test.
```

The default policy denies the deletion before the downstream demo process is
called. ChatGPT's own confirmation UI, when shown, is separate from ActionProxy
approval.

Press `Ctrl+C` to stop the tunnel. ActionProxy remains available locally until
you run:

```bash
docker compose down
```

For a public, production-shaped resource-server integration, use the standard
[OAuth-protected `/mcp` walkthrough](../../docs/CHATGPT_MCP.md). The
[`../chatgpt-app/`](../chatgpt-app/) directory contains its local automated
protocol fixture.

Official references:

- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [Connect from ChatGPT](https://developers.openai.com/apps-sdk/deploy/connect-chatgpt)
