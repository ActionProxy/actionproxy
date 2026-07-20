# Good first issues

These starter tasks are deliberately small and belong to the Community
approval gateway. Before starting one, check the current GitHub issues and open
or claim the corresponding issue so work is not duplicated.

## Suggested labels

- `good first issue`
- `help wanted`
- `docs`
- `demo`
- `mcp`
- `policy`
- `tests`
- `needs-triage`

## Add a LangGraph proxy example

Labels: `good first issue`, `docs`, `help wanted`

Show a LangGraph node submitting a proposed tool call to ActionProxy before invoking an existing tool.

Acceptance criteria:

- Add one read-only action and one approval-gated action to `examples/framework-integrations/README.md`.
- Keep the downstream tool implementation and credentials outside ActionProxy.
- Explain that ActionProxy is an approval gateway, not the graph runtime.

## Add a policy recipe for outbound email

Labels: `good first issue`, `policy`, `docs`

Document a policy with read-only search allowed, outbound email requiring approval, and destructive deletion denied.

Acceptance criteria:

- Include expected decisions for `docs.search`, `gmail.send_email`, and `dangerous.delete_customer`.
- Link the recipe to the local curl demo.
- Add a focused evaluator test if the recipe introduces a new policy shape.

## Improve curl-demo preflight errors

Labels: `good first issue`, `demo`

Make every script in `examples/local-curl-demo/` fail clearly when the server is unavailable or `jq` is missing.

Acceptance criteria:

- Preserve the `ACTIONPROXY_BASE_URL` override.
- Add no dependency beyond POSIX shell, `curl`, and `jq`.
- Keep the successful demo output concise.

## Add MCP wrapper troubleshooting examples

Labels: `good first issue`, `mcp`, `docs`

Add copyable diagnostics for a missing child command, invalid wrapper YAML, a server URL mistake, and an approval timeout.

Acceptance criteria:

- Use the repository-built `packages/mcp-wrapper/dist/index.js` binary.
- Reference the static doctor command and packaged MCP smoke test.
- Explain that discovery starts the configured child and is not a sandbox.

## Add a policy-detector fixture for a mock tool

Labels: `good first issue`, `tests`, `policy`

Add one mock-style tool observation and verify that the detector produces a stable suggested YAML rule.

Acceptance criteria:

- Add a focused server test with deterministic expected output.
- Do not add a SaaS connector or credentials.
- Document why the suggested decision is safe for the mock action.

## Help wanted: short local demo recording

Labels: `help wanted`, `demo`

Create a small recording showing a mock email proposal pause for approval, execute after approval, and appear in the audit trail.

Acceptance criteria:

- Use only repository demo data.
- Show the proposal, review, final execution, and audit evidence.
- Keep the optimized asset small enough for a GitHub README.
