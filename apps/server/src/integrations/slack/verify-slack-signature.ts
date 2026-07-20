import { createHmac, timingSafeEqual } from 'node:crypto';

const FIVE_MINUTES_IN_SECONDS = 60 * 5;

export function verifySlackSignature(input: {
  body: string;
  nowSeconds?: number;
  signature: string | undefined;
  signingSecret: string;
  timestamp: string | undefined;
}): boolean {
  if (!input.signature || !input.timestamp) return false;

  const timestampSeconds = Number(input.timestamp);
  if (!Number.isFinite(timestampSeconds)) return false;

  const nowSeconds = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - timestampSeconds) > FIVE_MINUTES_IN_SECONDS) return false;

  const baseString = `v0:${input.timestamp}:${input.body}`;
  const expected = `v0=${createHmac('sha256', input.signingSecret).update(baseString).digest('hex')}`;

  return safeEqual(expected, input.signature);
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  if (leftBuffer.length !== rightBuffer.length) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
}
