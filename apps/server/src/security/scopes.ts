import type { AuthContext } from '../models';
import { ForbiddenError, UnauthorizedError } from '../errors';

export const ALL_SCOPES = [
  'tool_call:submit',
  'tool_call:read',
  'approval:read',
  'approval:approve',
  'approval:reject',
  'audit:read',
  'policy:read',
  'policy:write',
  'admin:approvers',
  'admin:integrations',
  'admin:service_accounts',
  'execution_grant:consume',
] as const;

export type ActionProxyScope = (typeof ALL_SCOPES)[number];

export function hasScope(auth: AuthContext | undefined, scope: string): boolean {
  if (!auth) return false;
  return auth.scopes.includes('*') || auth.scopes.includes(scope);
}

export function requireAuth(auth: AuthContext | undefined): AuthContext {
  if (!auth) throw new UnauthorizedError('Authentication is required.');
  return auth;
}

export function requireScope(auth: AuthContext | undefined, scope: string): AuthContext {
  const context = requireAuth(auth);
  if (!hasScope(context, scope)) {
    throw new ForbiddenError(`Missing required scope: ${scope}`);
  }
  return context;
}

export function hasAnyGroup(auth: AuthContext, groups: string[]): boolean {
  if (groups.length === 0) return true;
  const principalGroups = new Set(auth.groups);
  return groups.some((group) => principalGroups.has(group));
}

export function principalMatchesActor(auth: AuthContext, actor: string | undefined): boolean {
  if (!actor) return false;
  return auth.principalId === actor || auth.email === actor || auth.displayName === actor;
}
