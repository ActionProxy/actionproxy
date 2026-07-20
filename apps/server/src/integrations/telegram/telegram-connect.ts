import { hmacSha256Hex, safeEqual } from '../../security/crypto';

const TELEGRAM_CONNECT_VERSION = 'ag1';
const TELEGRAM_CONNECT_SIGNATURE_LENGTH = 20;
const TELEGRAM_START_PARAMETER_MAX_LENGTH = 64;

export interface TelegramConnectTokenPayload {
  expiresAt: string;
  userId: string;
}

export function createTelegramConnectToken(input: {
  expiresAt: Date;
  secret: string;
  userId: string;
}): string {
  const expires = Math.floor(input.expiresAt.getTime() / 1000).toString(36);
  const user = Buffer.from(input.userId, 'utf8').toString('base64url');
  const signingInput = `${TELEGRAM_CONNECT_VERSION}_${expires}_${user}`;
  const signature = hmacSha256Hex(input.secret, signingInput).slice(0, TELEGRAM_CONNECT_SIGNATURE_LENGTH);
  const token = `${signingInput}_${signature}`;
  if (token.length > TELEGRAM_START_PARAMETER_MAX_LENGTH) {
    throw new Error('ActionProxy user ID is too long for a Telegram connect link.');
  }
  return token;
}

export function parseTelegramConnectToken(
  token: string | undefined,
  secret: string,
  now = new Date(),
): TelegramConnectTokenPayload | undefined {
  const parts = (token ?? '').split('_');
  if (parts.length < 4 || parts[0] !== TELEGRAM_CONNECT_VERSION) return undefined;

  const signature = parts.at(-1);
  const expires = parts[1];
  const user = parts.slice(2, -1).join('_');
  if (!signature || !expires || !user) return undefined;

  const signingInput = `${TELEGRAM_CONNECT_VERSION}_${expires}_${user}`;
  const expectedSignature = hmacSha256Hex(secret, signingInput).slice(0, TELEGRAM_CONNECT_SIGNATURE_LENGTH);
  if (!safeEqual(signature, expectedSignature)) return undefined;

  const expiresAtMs = Number.parseInt(expires, 36) * 1000;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs < now.getTime()) return undefined;

  try {
    return {
      expiresAt: new Date(expiresAtMs).toISOString(),
      userId: Buffer.from(user, 'base64url').toString('utf8'),
    };
  } catch {
    return undefined;
  }
}

export function telegramStartTokenFromText(text: string | undefined): string | undefined {
  const match = /^\/start(?:@[A-Za-z0-9_]+)?(?:\s+([A-Za-z0-9_-]{1,64}))?\s*$/.exec(text ?? '');
  return match?.[1];
}

export function isTelegramStartCommand(text: string | undefined): boolean {
  return /^\/start(?:@[A-Za-z0-9_]+)?(?:\s+[A-Za-z0-9_-]{1,64})?\s*$/.test(text ?? '');
}
