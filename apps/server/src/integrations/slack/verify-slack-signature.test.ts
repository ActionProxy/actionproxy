import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifySlackSignature } from './verify-slack-signature';

describe('verifySlackSignature', () => {
  it('accepts valid Slack signatures', () => {
    const signingSecret = 'test_secret';
    const timestamp = '1710000000';
    const body = 'payload=%7B%22type%22%3A%22block_actions%22%7D';
    const signature = sign(signingSecret, timestamp, body);

    expect(
      verifySlackSignature({
        body,
        nowSeconds: 1710000000,
        signature,
        signingSecret,
        timestamp,
      }),
    ).toBe(true);
  });

  it('rejects stale timestamps and mismatched signatures', () => {
    const signingSecret = 'test_secret';
    const timestamp = '1710000000';
    const body = 'payload=%7B%7D';
    const signature = sign(signingSecret, timestamp, body);

    expect(
      verifySlackSignature({
        body,
        nowSeconds: 1710000601,
        signature,
        signingSecret,
        timestamp,
      }),
    ).toBe(false);
    expect(
      verifySlackSignature({
        body: `${body}tampered=true`,
        nowSeconds: 1710000000,
        signature,
        signingSecret,
        timestamp,
      }),
    ).toBe(false);
  });
});

function sign(secret: string, timestamp: string, body: string): string {
  return `v0=${createHmac('sha256', secret).update(`v0:${timestamp}:${body}`).digest('hex')}`;
}
