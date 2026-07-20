# Customer support workflow example

This example uses the built-in deterministic mock tools to demonstrate the
complete allow, approval, execution, denial, and audit lifecycle without SaaS
credentials.

## Workflow

1. Support agent asks an AI agent to handle a ticket.
2. Agent calls `docs.search` to find policy context.
3. Agent proposes `gmail.send_email` to reply to the customer.
4. ActionProxy requires approval for the email.
5. A human approves or rejects.
6. ActionProxy executes the approved mock email tool.
7. Audit log records all steps.

## Why this is a good public demo

It is easy for developers and business buyers to understand:

- AI can help with real work.
- Human approval stays in control.
- Risky actions are not silently executed.
- The audit trail is visible.

## Production integration mapping

The same governed action names can be mapped to tools owned by an external MCP
server, connector runner, or internal API:

- Zendesk or Intercom ticket read
- Help-center/docs search
- Gmail or Outlook send
- Salesforce/HubSpot account update
- Jira escalation creation
- Slack approval
