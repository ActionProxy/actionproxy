# Standard `/mcp` protocol fixture

The simplest ChatGPT demonstration is the
[Secure MCP Tunnel example](../chatgpt-tunnel/README.md). This directory holds
the separate automated fixture for ActionProxy's experimental, OAuth-protected
Streamable HTTP `/mcp` resource.

```text
MCP client → public HTTPS /mcp → ActionProxy policy and approval
           → Community mock tools → audit evidence
```

It is a protocol and lifecycle test, not a live ChatGPT test. It neither
contacts ChatGPT nor supplies the external OAuth 2.1 authorization server that
a public deployment requires.

## Run the local smoke test

Use Node.js 22 or 24. From the repository root:

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm demo:chatgpt
```

The fixture creates ephemeral local signing material and OAuth-shaped access
tokens, starts the Community server on loopback, and proves:

- protected-resource metadata and bearer authentication;
- MCP version negotiation and signed sessions;
- the exact configured tool list;
- immediate execution for `docs.search`;
- zero email effects before approval and exactly one afterward;
- status reads do not redispatch an action;
- denial of `dangerous.delete_customer`; and
- correlated lifecycle audit evidence.

The fixture uses deterministic mock tools. It does not send email, delete
customer data, or connect a SaaS provider.

## Deployment helpers

[`actionproxy.env.example`](actionproxy.env.example) documents the resource
server's environment contract. [`check-endpoint.mjs`](check-endpoint.mjs)
validates protected-resource metadata and the unauthenticated OAuth challenge
without accepting or printing an access token:

```bash
node examples/chatgpt-app/check-endpoint.mjs https://your-host.example/mcp
```

For the external authorization-server responsibilities, PKCE and audience
requirements, private approver bootstrap, ChatGPT developer-mode setup, and
security boundaries, follow [OAuth-protected MCP for ChatGPT](../../docs/CHATGPT_MCP.md).

A real external authorization-server and ChatGPT workspace run has not yet been
claimed. That live validation is not a v0.1 blocker while this path remains
explicitly experimental; the real Secure MCP Tunnel run is the required
ChatGPT release gate.
