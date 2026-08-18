import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { canonicalJsonStringify, hashCanonicalJson } from '../contracts/action-request';

export const MCP_SESSION_VERSION = 'actionproxy.mcp-session.v2' as const;

export type McpJsonRpcId = number | string;

export interface McpSessionBinding {
  adapterId: string;
  catalogRevision: string;
  expiresAt: number;
  issuedAt: number;
  principalId: string;
  protocolVersion: string;
  resource: string;
  sessionId: string;
  tenantId: string;
  version: typeof MCP_SESSION_VERSION;
}

export interface McpSessionExpectedBinding {
  adapterId: string;
  catalogRevision: string;
  principalId: string;
  protocolVersion?: string;
  resource: string;
  tenantId: string;
}

export type McpSessionErrorCode =
  | 'mcp_session_binding_mismatch'
  | 'mcp_session_expired'
  | 'mcp_session_invalid';

export class McpSessionError extends Error {
  constructor(
    public readonly code: McpSessionErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'McpSessionError';
  }
}

export interface McpSessionAuthorityOptions {
  now?: () => number;
  randomId?: () => string;
}

/**
 * Issues signed, self-contained MCP transport sessions. The OAuth bearer is
 * still validated on every request; this token only binds protocol state to
 * the already-authenticated tenant, principal, adapter, and resource.
 */
export class McpSessionAuthority {
  private readonly now: () => number;
  private readonly randomId: () => string;

  constructor(
    private readonly secret: string,
    private readonly ttlMs: number,
    options: McpSessionAuthorityOptions = {},
  ) {
    if (Buffer.byteLength(secret, 'utf8') < 32) {
      throw new Error('MCP session secret must contain at least 32 UTF-8 bytes.');
    }
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error('MCP session TTL must be a positive number.');
    }
    this.now = options.now ?? Date.now;
    this.randomId = options.randomId ?? (() => randomBytes(18).toString('base64url'));
  }

  issue(input: Omit<McpSessionExpectedBinding, 'protocolVersion'> & { protocolVersion: string }): {
    session: McpSessionBinding;
    token: string;
  } {
    const issuedAt = this.now();
    const session: McpSessionBinding = {
      adapterId: requiredString(input.adapterId, 'adapterId'),
      catalogRevision: requiredString(input.catalogRevision, 'catalogRevision'),
      expiresAt: issuedAt + this.ttlMs,
      issuedAt,
      principalId: requiredString(input.principalId, 'principalId'),
      protocolVersion: requiredString(input.protocolVersion, 'protocolVersion'),
      resource: requiredString(input.resource, 'resource'),
      sessionId: requiredString(this.randomId(), 'sessionId'),
      tenantId: requiredString(input.tenantId, 'tenantId'),
      version: MCP_SESSION_VERSION,
    };
    const payload = Buffer.from(canonicalJsonStringify(session), 'utf8').toString('base64url');
    return { session, token: `${payload}.${this.sign(payload)}` };
  }

  verify(token: string, expected: McpSessionExpectedBinding): McpSessionBinding {
    const [payload, signature, extra] = token.split('.');
    if (!payload || !signature || extra !== undefined || !safeSignatureEqual(signature, this.sign(payload))) {
      throw new McpSessionError('mcp_session_invalid', 'MCP session is invalid.');
    }

    const session = parseSession(payload);
    if (session.expiresAt <= this.now()) {
      throw new McpSessionError('mcp_session_expired', 'MCP session has expired.');
    }
    if (
      session.adapterId !== expected.adapterId ||
      session.catalogRevision !== expected.catalogRevision ||
      session.principalId !== expected.principalId ||
      session.resource !== expected.resource ||
      session.tenantId !== expected.tenantId ||
      (expected.protocolVersion !== undefined && session.protocolVersion !== expected.protocolVersion)
    ) {
      throw new McpSessionError('mcp_session_binding_mismatch', 'MCP session does not match the authenticated transport.');
    }
    return session;
  }

  idempotencyKey(session: McpSessionBinding, requestId: McpJsonRpcId): string {
    if (typeof requestId === 'number' && (!Number.isSafeInteger(requestId) || !Number.isFinite(requestId))) {
      throw new McpSessionError('mcp_session_invalid', 'MCP JSON-RPC request id must be a safe integer or string.');
    }
    return `mcp_${hashCanonicalJson({
      adapterId: session.adapterId,
      requestId: { type: typeof requestId, value: requestId },
      resource: session.resource,
      sessionId: session.sessionId,
      tenantId: session.tenantId,
      version: 'actionproxy.mcp-idempotency.v1',
    })}`;
  }

  private sign(payload: string): string {
    return createHmac('sha256', this.secret).update(payload, 'utf8').digest('base64url');
  }
}

function parseSession(payload: string): McpSessionBinding {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as unknown;
  } catch {
    throw new McpSessionError('mcp_session_invalid', 'MCP session is invalid.');
  }
  if (!isRecord(parsed)) throw new McpSessionError('mcp_session_invalid', 'MCP session is invalid.');

  const session = parsed as Partial<McpSessionBinding>;
  if (
    session.version !== MCP_SESSION_VERSION ||
    typeof session.adapterId !== 'string' ||
    typeof session.catalogRevision !== 'string' ||
    typeof session.principalId !== 'string' ||
    typeof session.protocolVersion !== 'string' ||
    typeof session.resource !== 'string' ||
    typeof session.sessionId !== 'string' ||
    typeof session.tenantId !== 'string' ||
    typeof session.issuedAt !== 'number' ||
    !Number.isSafeInteger(session.issuedAt) ||
    typeof session.expiresAt !== 'number' ||
    !Number.isSafeInteger(session.expiresAt) ||
    session.expiresAt <= session.issuedAt
  ) {
    throw new McpSessionError('mcp_session_invalid', 'MCP session is invalid.');
  }
  return session as McpSessionBinding;
}

function requiredString(value: string, name: string): string {
  const normalized = value.trim();
  if (!normalized || Buffer.byteLength(normalized, 'utf8') > 1024) {
    throw new Error(`MCP session ${name} must be a non-empty bounded string.`);
  }
  return normalized;
}

function safeSignatureEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
