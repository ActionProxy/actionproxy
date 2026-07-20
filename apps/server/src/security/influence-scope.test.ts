import { describe, expect, it } from 'vitest';
import { deriveInfluenceScopeId, parseMcpWrapperSessionId } from './influence-scope';

describe('verified influence scopes', () => {
  it('accepts only canonical wrapper UUIDs', () => {
    expect(parseMcpWrapperSessionId('550e8400-e29b-41d4-a716-446655440000')).toBe(
      '550e8400-e29b-41d4-a716-446655440000',
    );
    expect(parseMcpWrapperSessionId('550E8400-E29B-41D4-A716-446655440000')).toBeUndefined();
    expect(parseMcpWrapperSessionId('not-a-session')).toBeUndefined();
    expect(parseMcpWrapperSessionId(undefined)).toBeUndefined();
  });

  it('binds the opaque scope to every authenticated transport dimension', () => {
    const base = {
      adapterId: 'mcp-stdio:client-1',
      principalId: 'principal-1',
      protocol: 'mcp' as const,
      transport: 'stdio' as const,
      transportSessionId: '550e8400-e29b-41d4-a716-446655440000',
      workspaceId: 'workspace-1',
    };
    const scope = deriveInfluenceScopeId(base);
    expect(scope).toMatch(/^influence_[a-f0-9]{64}$/u);
    expect(scope).not.toContain(base.transportSessionId);
    expect(deriveInfluenceScopeId(base)).toBe(scope);
    expect(deriveInfluenceScopeId({ ...base, principalId: 'principal-2' })).not.toBe(scope);
    expect(deriveInfluenceScopeId({ ...base, workspaceId: 'workspace-2' })).not.toBe(scope);
    expect(deriveInfluenceScopeId({ ...base, adapterId: 'mcp-stdio:client-2' })).not.toBe(scope);
    expect(deriveInfluenceScopeId({
      ...base,
      transport: 'streamable_http',
      transportSessionId: 'signed-mcp-session-1',
    })).not.toBe(scope);
    expect(deriveInfluenceScopeId({
      ...base,
      transportSessionId: '550e8400-e29b-41d4-b716-446655440000',
    })).not.toBe(scope);
  });
});
