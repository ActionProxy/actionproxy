# Slack approval-channel setup

ActionProxy can send pending-approval cards through an operator-owned Slack bot.
Slack is a review and notification surface only: the pending record remains in
ActionProxy, every decision still goes through `ActionProxyService`, and the
browser/API review flow continues to work without Slack.

Community does not use Slack as a downstream business-tool executor. An agent
that needs to perform a Slack action should do so through its existing MCP
server or external runner after ActionProxy approval and grant consumption.

## Create the Slack app

In a Slack app owned by the operator:

1. Enable bot users.
2. Add the minimum bot scope needed to send approval DMs, normally
   `chat:write`.
3. Install the app to the target workspace.
4. Enable Interactivity & Shortcuts.
5. Set the request URL to the publicly reachable ActionProxy callback:
   `https://actionproxy.example/v1/slack/interactions`.
6. Copy the bot token and signing secret into the deployment secret manager.

Use HTTPS for any callback reachable outside the local machine.

## Configure ActionProxy

Environment configuration:

```bash
SLACK_BOT_TOKEN=xoxb-...
SLACK_SIGNING_SECRET=...
SLACK_APPROVAL_CHANNEL_ID=
```

`SLACK_APPROVAL_CHANNEL_ID` is an optional default channel. For per-reviewer
direct messages, add Slack user IDs to ActionProxy approver records instead.

You can also save non-secret settings from **Integrations → Approval channels**
in the local console. In authenticated deployments, secret writes through the
local integration API are blocked; inject secrets through the runtime.

## Map Slack users to approvers

Create or update each ActionProxy approver with a stable Slack user ID and an
authenticated principal binding. Slack display names and email addresses are
not sufficient authorization identifiers.

A reviewer may approve only when all of these checks pass:

- Slack signed the callback with the configured signing secret;
- the timestamp is within the replay window;
- the Slack user maps to an enabled ActionProxy approver;
- that approver maps to the authenticated principal/groups allowed by policy;
- the approval is still pending and the review binding is current.

The Slack channel or user that receives a notification does not become an
authorized reviewer merely by receiving it.

## Policy routing

Add `slack.default` to an approval-required rule:

```yaml
tools:
  gmail.send_email:
    approval: required
    risk: external_communication
    reason: "External email requires review."
    notify:
      channels:
        - slack.default
```

If `notify.channels` is omitted, ActionProxy tries enabled channels marked as
defaults. Delivery failure is audited and never approves, denies, or executes
the call.

## Test

1. Start ActionProxy with Slack secrets injected.
2. Open `http://127.0.0.1:5173/#/integrations` for source development, or the
   bundled Docker console at `http://127.0.0.1:8787/app#/integrations`.
3. Confirm the Slack channel is configured.
4. Use the test action to send a non-decision setup message.
5. Submit an approval-required demo email.
6. Confirm the card reaches only the intended approver.
7. Approve or reject from Slack.
8. Verify the decision and delivery events in `/v1/audit`.

The local test must use mock tools. Do not use a production business tool merely
to prove approval delivery.

## Failure behavior

- Invalid or stale Slack signatures return an authorization error.
- Unknown Slack users cannot decide an approval.
- A disabled or unmapped approver cannot decide an approval.
- Replayed button callbacks cannot execute twice.
- An expired, cancelled, rejected, already-approved, or stale review returns a
  lifecycle conflict.
- Slack delivery errors leave the approval pending for another configured
  channel or the browser console.

## Security notes

- Treat bot tokens and signing secrets as deployment secrets.
- Never place them in Git, screenshots, browser storage, approval payloads, or
  MCP profile files.
- Restrict the Slack app to the smallest workspace and scope set needed.
- Rotate a token after suspected exposure and verify the audit chain.
- Slack is not the source of policy truth; ActionProxy policy and approver
  authorization remain authoritative.
