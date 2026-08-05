# Approval channels

The ActionProxy web console is the canonical fallback for reviewing pending
approvals. Optional notification channels deliver the same pending approval to
an identified reviewer; they do not create a separate authorization path.

## Available Community channels

- **Slack:** signed interactive messages and direct delivery to mapped users.
- **Telegram:** webhook-validated messages and stable numeric user mapping.
- **Email outbox:** local JSON messages for development and integration tests.
- **SMTP:** self-hosted email delivery using deployment-managed credentials.

Configure channels from the Integrations page or deployment environment. Do
not commit bot tokens, signing secrets, SMTP passwords, or API keys.

See [OSS test status](OSS_TEST_STATUS.md) for the distinction between automated
channel tests, historical or local evidence, and live provider validation that
operators still need to perform.

## Lifecycle rules

- ActionProxy creates the pending approval before attempting delivery.
- Delivery failure is audited and never removes the pending approval.
- Slack and Telegram buttons call the same approval service as the web console.
- Email and Telegram can include a web-console review URL resolved from the
  deployment's public base URL.
- Actor identity and approval scopes are derived by the server. Client-supplied
  display names do not grant authority.
- Separation-of-duties and multi-approval rules apply consistently across
  every channel.

For a local demo, leave channels disabled and approve in the web console. For
self-hosting, read [Security model](SECURITY_MODEL.md) before enabling public
webhooks or email links.
