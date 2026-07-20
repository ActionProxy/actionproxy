import { hashCanonicalJson } from '../contracts/action-request';

export const INFLUENCE_SCOPE_VERSION = 'actionproxy.influence-scope.v1' as const;

export interface InfluenceScopeBinding {
  adapterId: string;
  principalId: string;
  protocol: 'mcp';
  transport: 'stdio' | 'streamable_http';
  transportSessionId: string;
  workspaceId: string;
}

/**
 * Validates the process UUID emitted by the ActionProxy stdio wrapper. The
 * value is used only while deriving an opaque scope and must never be stored.
 */
export function parseMcpWrapperSessionId(value: string | undefined): string | undefined {
  if (!value || Buffer.byteLength(value, 'utf8') !== 36) return undefined;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)) {
    return undefined;
  }
  return value;
}

/**
 * Produces a non-reversible identifier bound to the authenticated transport.
 * Only this derived identifier is suitable for canonical evidence or storage.
 */
export function deriveInfluenceScopeId(binding: InfluenceScopeBinding): string {
  const normalized = {
    adapterId: bounded(binding.adapterId, 'adapterId'),
    principalId: bounded(binding.principalId, 'principalId'),
    protocol: binding.protocol,
    transport: binding.transport,
    transportSessionId: bounded(binding.transportSessionId, 'transportSessionId'),
    version: INFLUENCE_SCOPE_VERSION,
    workspaceId: bounded(binding.workspaceId, 'workspaceId'),
  };
  return `influence_${hashCanonicalJson(normalized)}`;
}

function bounded(value: string, field: string): string {
  if (!value || value.trim() !== value || Buffer.byteLength(value, 'utf8') > 1024) {
    throw new Error(`Influence scope ${field} must be a non-empty bounded string.`);
  }
  return value;
}
