# OAuth-protected MCP for ChatGPT and other clients

ActionProxy exposes an experimental Streamable HTTP MCP resource at `/mcp` for
advanced self-hosted deployments. This is separate from the beginner
[Secure MCP Tunnel demo](../examples/chatgpt-tunnel/README.md).

```text
ChatGPT or another MCP client
  → public HTTPS /mcp
  → ActionProxy policy, approval, execution, and audit
  → mock tool or authorized external executor
```

The current Community endpoint is a data-only MCP app. It exposes tools and
structured results without an embedded ChatGPT widget. The bundled tools are
deterministic mocks; they do not send email, delete customer data, or connect
to SaaS providers.

## Responsibility boundary

ActionProxy is the OAuth 2.1 protected resource server. It publishes
protected-resource metadata, returns bearer challenges, and validates access
tokens. A separate authorization server owns authentication, consent,
authorization-code exchange, PKCE S256, client identification or registration,
token issuance, and key rotation.

The authorization server must:

1. Publish OAuth or OpenID Connect discovery metadata.
2. Support authorization code plus PKCE with `S256`.
3. Identify or register ChatGPT through CIMD, DCR, or a predefined client.
4. Preserve ChatGPT's exact `resource` value through authorization and token
   exchange.
5. Issue `RS256` JWT access tokens whose `aud` is the exact public `/mcp` URL.
6. Include a non-empty subject, client identity, expiry, and the
   `tool_call:read tool_call:submit` scopes.

ActionProxy does not implement login, authorization, token, consent, CIMD, or
DCR endpoints. It does not require an OpenAI API key for this connection.

## Prove the protocol locally first

The fixture in [`examples/chatgpt-app/`](../examples/chatgpt-app/) creates
ephemeral signing material and OAuth-shaped tokens, starts ActionProxy on
loopback, and tests the protocol without contacting ChatGPT:

```bash
corepack pnpm demo:chatgpt
```

It covers metadata, authentication, negotiation, sessions, tool listing,
allow/approval/deny, zero preapproval effects, replay resistance, and audit
correlation.

## Configure the resource server

Use a public HTTPS resource URL and exactly one trusted JWKS source:

```bash
ACTIONPROXY_MCP_STREAMABLE_HTTP_ENABLED=true \
ACTIONPROXY_MCP_RESOURCE_URL=https://actionproxy.example/mcp \
ACTIONPROXY_MCP_AUTHORIZATION_SERVER=https://auth.example \
ACTIONPROXY_MCP_ALLOWED_ORIGINS=https://chatgpt.com \
ACTIONPROXY_MCP_SESSION_SECRET='<at-least-32-random-bytes>' \
ACTIONPROXY_AUTH_MODE=oidc_jwt \
ACTIONPROXY_OIDC_ISSUER=https://auth.example \
ACTIONPROXY_OIDC_AUDIENCE=https://actionproxy.example/api \
ACTIONPROXY_OIDC_JWKS_PATH=/run/secrets/actionproxy-jwks.json \
ACTIONPROXY_LOCAL_EXECUTION=mock \
corepack pnpm dev:server
```

The generic API audience and exact MCP resource audience are distinct checks.
Do not put session secrets, access tokens, or private signing keys in browser
state, source control, MCP tool results, or a public JWKS file.

Keep ActionProxy bound to loopback behind an operator-controlled HTTPS reverse
proxy or secure development ingress. Expose only `/mcp` and the protected
resource metadata paths publicly. Keep `/v1`, `/app`, data files, and bootstrap
interfaces private.

The environment template is
[`examples/chatgpt-app/actionproxy.env.example`](../examples/chatgpt-app/actionproxy.env.example).
Copy it to the ignored root `.env.local` and replace every example or
`replace-with-...` value. Generate separate random session, grant, and
bootstrap secrets; never reuse one secret for multiple purposes.

## Bind an approver privately

Before inviting ChatGPT, create an enabled approver whose `principalId` is the
same authenticated subject that will review approvals. Run this from the
ActionProxy host against loopback with the temporary bootstrap credential:

```bash
export ACTIONPROXY_BOOTSTRAP_TOKEN='replace-with-temporary-bootstrap-secret'
export ACTIONPROXY_OPERATOR_PRINCIPAL_ID='replace-with-operator-oidc-sub'

curl -fsS http://127.0.0.1:8787/v1/approvers/users \
  -H "authorization: Bearer $ACTIONPROXY_BOOTSTRAP_TOKEN" \
  -H 'content-type: application/json' \
  --data "{\"displayName\":\"ChatGPT demo reviewer\",\"principalId\":\"$ACTIONPROXY_OPERATOR_PRINCIPAL_ID\",\"defaultApprover\":true,\"enabled\":true}" | jq
```

Then remove `ACTIONPROXY_BOOTSTRAP_ADMIN_API_KEY` and restart. Use a short-lived
ordinary operator token with only `approval:read`, `approval:approve`, and
`audit:read`. The Community console does not implement a browser OIDC login
flow, so approve through the private API or another configured approval
channel.

## Check discovery

The dependency-free preflight checks protected-resource metadata and confirms
that an unauthenticated MCP request receives the OAuth discovery challenge. It
does not accept or print access tokens:

```bash
node examples/chatgpt-app/check-endpoint.mjs https://your-host.example/mcp
```

## Connect from ChatGPT

OpenAI's current developer-mode setup is:

1. In ChatGPT, open **Settings → Security and login** and enable
   **Developer mode**. A workspace administrator may need to allow it.
2. Open **Settings → Plugins** or `https://chatgpt.com/plugins`.
3. Select the plus button and create a developer-mode app.
4. Name it `ActionProxy Community Demo` and use the exact public MCP URL,
   such as `https://your-host.example/mcp`.
5. Complete the external OAuth flow.
6. Verify that ChatGPT lists only the intended ActionProxy tools.

In a new conversation, add the app and try:

```text
Use ActionProxy to search the demo docs for the refund policy.
```

```text
Use ActionProxy to submit a demo email to customer@example.com with subject
"Refund update" and body "Your request is ready."
```

ChatGPT may show its own app confirmation first. That consent is separate from
ActionProxy approval. The tool result should identify the pending ActionProxy
approval and its tool-call correlation ID. Review the pending action with the
private operator interface, then ask ChatGPT to check that tool call's status.

Finally exercise the denied path:

```text
Use ActionProxy to run the delete-customer demo for cus_123 as a policy test.
```

The default policy denies it before mock execution.

## Implemented behavior

- Protected-resource discovery and bearer challenges
- Exact resource and audience binding
- Authenticated `initialize`, `tools/list`, and `tools/call`
- Signed Streamable HTTP sessions and tool security metadata
- Policy allow, deny, and approval results
- Replay-resistant execution authority and audit correlation
- Bounded requests, timeouts, and hostile-output withholding

## Security and claim boundaries

- Only calls routed through this MCP resource are governed. ActionProxy cannot
  intercept other apps, tools, networking, shell access, credentials, or model
  memory.
- A signed MCP session is transport scope, not verified ChatGPT conversation
  identity.
- ChatGPT confirmation does not replace ActionProxy policy or human approval.
- Source-aware policy narrows consequences after classified content is read; it
  does not detect or prevent prompt injection.
- The external authorization server and HTTPS deployment remain operator
  responsibilities.

Automated tests cover protocol conformance, but a real external authorization
server and ChatGPT workspace run has not yet been claimed. Describe this path
as experimental protocol compatibility until that test passes. Live OAuth
validation is not a v0.1 blocker while the claim remains experimental; the
real Secure MCP Tunnel run is the required ChatGPT release gate.

Official references:

- [OpenAI Apps SDK authentication](https://developers.openai.com/apps-sdk/build/auth)
- [Connect from ChatGPT](https://developers.openai.com/apps-sdk/deploy/connect-chatgpt)
- [MCP authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
