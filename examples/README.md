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
| `chatgpt-tunnel/` | ChatGPT Secure MCP Tunnel to the local Docker demo |
| `chatgpt-app/` | Automated protocol smoke for experimental standard `/mcp` |
| `customer-support/` | Narrative approval-gateway walkthrough |

Start with the root [five-minute demo](../README.md#five-minute-demo). Real
business-tool credentials should stay with an existing MCP server, internal
API, or external runner rather than these examples.
