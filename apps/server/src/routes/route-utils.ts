import type { FastifyReply, FastifyRequest } from 'fastify';
import { ConflictError, ForbiddenError, NotFoundError, UnauthorizedError } from '../errors';
import type { AuthContext } from '../models';

export function authContext(request: FastifyRequest): AuthContext {
  if (!request.authContext) return localRouteContext();
  return request.authContext;
}

export function mapKnownError(reply: FastifyReply, error: unknown) {
  if (error instanceof NotFoundError) return reply.status(404).send({ error: 'not_found', message: error.message });
  if (error instanceof ConflictError) return reply.status(409).send({ error: 'conflict', message: error.message });
  if (error instanceof UnauthorizedError) return reply.status(401).send({ error: 'unauthorized', message: error.message });
  if (error instanceof ForbiddenError) return reply.status(403).send({ error: 'forbidden', message: error.message });
  throw error;
}

export function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function localRouteContext(): AuthContext {
  return {
    authProvider: 'none',
    displayName: 'local-admin',
    groups: ['actionproxy-admins', 'actionproxy-approvers'],
    principalId: 'local-admin',
    principalType: 'local',
    scopes: ['*'],
    workspaceId: 'default',
  };
}
