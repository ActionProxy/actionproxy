import { describe, expect, it } from 'vitest';
import { MCP_SESSION_VERSION, McpSessionAuthority, McpSessionError } from './mcp-session';

const secret = 'mcp-test-session-secret-with-at-least-32-bytes';

describe('MCP signed session authority', () => {
  it('issues and verifies a session bound to resource, tenant, principal, adapter, and protocol', () => {
    const authority = new McpSessionAuthority(secret, 60_000, {
      now: () => 1_000,
      randomId: () => 'session_01',
    });
    const issued = authority.issue(binding());

    expect(issued.session).toEqual({
      ...binding(),
      expiresAt: 61_000,
      issuedAt: 1_000,
      sessionId: 'session_01',
      version: MCP_SESSION_VERSION,
    });
    expect(authority.verify(issued.token, binding())).toEqual(issued.session);
    expect(issued.token).not.toContain(secret);
  });

  it('rejects token tampering, expiry, and every authenticated binding mismatch', () => {
    let now = 1_000;
    const authority = new McpSessionAuthority(secret, 1_000, {
      now: () => now,
      randomId: () => 'session_02',
    });
    const issued = authority.issue(binding());
    const [payload, signature] = issued.token.split('.');

    expectMcpSessionError(() => authority.verify(`${payload}x.${signature}`, binding()), 'mcp_session_invalid');
    for (const mismatch of [
      { adapterId: 'other-client' },
      { principalId: 'other-user' },
      { protocolVersion: '2024-11-05' },
      { resource: 'https://other.example/mcp' },
      { tenantId: 'other-tenant' },
    ]) {
      expectMcpSessionError(
        () => authority.verify(issued.token, { ...binding(), ...mismatch }),
        'mcp_session_binding_mismatch',
      );
    }

    now = 2_000;
    expectMcpSessionError(() => authority.verify(issued.token, binding()), 'mcp_session_expired');
  });

  it('derives stable, typed request idempotency keys without using the bearer or signed token', () => {
    const authority = new McpSessionAuthority(secret, 60_000, {
      now: () => 1_000,
      randomId: () => 'session_03',
    });
    const first = authority.issue(binding()).session;
    const second = { ...first, sessionId: 'session_04' };

    expect(authority.idempotencyKey(first, '1')).toBe(authority.idempotencyKey(first, '1'));
    expect(authority.idempotencyKey(first, '1')).not.toBe(authority.idempotencyKey(first, 1));
    expect(authority.idempotencyKey(first, '1')).not.toBe(authority.idempotencyKey(second, '1'));
    expect(authority.idempotencyKey(first, '1')).toMatch(/^mcp_[a-f0-9]{64}$/u);
    expect(() => authority.idempotencyKey(first, Number.MAX_VALUE)).toThrow('safe integer');
  });

  it('rejects weak secrets and invalid TTLs', () => {
    expect(() => new McpSessionAuthority('short', 60_000)).toThrow('at least 32');
    expect(() => new McpSessionAuthority(secret, 0)).toThrow('positive');
  });
});

function binding() {
  return {
    adapterId: 'chatgpt-client',
    principalId: 'user_01',
    protocolVersion: '2025-06-18',
    resource: 'https://proxy.example/mcp',
    tenantId: 'tenant_01',
  };
}

function expectMcpSessionError(run: () => unknown, code: McpSessionError['code']): void {
  try {
    run();
    throw new Error('Expected MCP session error.');
  } catch (error) {
    expect(error).toBeInstanceOf(McpSessionError);
    expect((error as McpSessionError).code).toBe(code);
  }
}
