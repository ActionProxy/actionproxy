# ActionProxy examples

All examples run from a source checkout. They use deterministic mocks unless a
README explicitly says otherwise.

| Example | Purpose |
|---|---|
| `local-curl-demo/` | HTTP allow, approval, denial, and audit lifecycle |
| `demo-agent/` | Small deterministic agent proposing tool calls |
| `external-runner/` | Consume a one-time grant before an external effect |
| `framework-integrations/` | Framework-neutral external-runner patterns |
| `mcp-demo/` | Three-tool downstream MCP wrapper lifecycle |
| `mcp-hosts/` | Local stdio configuration for MCP hosts |
| `google-workspace-mcp-demo/` | Opt-in real Gmail search and approval-gated draft through a third-party downstream MCP server |
| `chatgpt-tunnel/` | ChatGPT Secure MCP Tunnel to the local Docker demo |
| `chatgpt-app/` | Automated protocol smoke for experimental standard `/mcp` |
| `customer-support/` | Narrative approval-gateway walkthrough |

Start with the root [guided first run](../README.md#first-run). The Google
Workspace reference is the only example here that intentionally reaches a real
business tool. Its credentials remain with the operator-owned downstream MCP
process; every other example uses deterministic mocks unless its README says
otherwise.
