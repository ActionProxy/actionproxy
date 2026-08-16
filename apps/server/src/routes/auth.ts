import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { AuthService } from '../security/auth-service';
import { requireScope } from '../security/scopes';
import type { AuditStore } from '../storage/audit-store';
import { authContext, mapKnownError } from './route-utils';

const createServiceAccountSchema = z.object({
  description: z.string().optional(),
  groups: z.array(z.string().min(1)).optional(),
  name: z.string().min(1),
  scopes: z.array(z.string().min(1)).optional(),
});

const createApiKeySchema = z.object({
  scopes: z.array(z.string().min(1)).optional(),
});

export async function registerAuthRoutes(
  app: FastifyInstance,
  authService: AuthService,
  auditStore: AuditStore,
): Promise<void> {
  app.get('/v1/me', async (request) => {
    const auth = authContext(request);
    return { auth, availableScopes: authService.availableScopes() };
  });

  app.post('/v1/service-accounts', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:service_accounts');
    const parsed = createServiceAccountSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const serviceAccount = await authService.createServiceAccount(parsed.data, auth);
      await auditStore.append({
        actor: auth.email ?? auth.principalId,
        auth,
        data: {
          groups: serviceAccount.groups,
          name: serviceAccount.name,
          scopes: serviceAccount.scopes,
          serviceAccountId: serviceAccount.id,
        },
        id: `audit_${randomUUID()}`,
        timestamp: new Date().toISOString(),
        type: 'service_account.created',
        workspaceId: auth.workspaceId,
      });
      return { serviceAccount };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });

  app.post('/v1/service-accounts/:id/keys', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:service_accounts');
    const params = z.object({ id: z.string().min(1) }).parse(request.params);
    const parsed = createApiKeySchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    try {
      const result = await authService.createApiKey(params.id, parsed.data, auth);
      await auditStore.append({
        actor: auth.email ?? auth.principalId,
        auth,
        data: {
          apiKeyId: result.apiKey.id,
          keyPrefix: result.apiKey.keyPrefix,
          scopes: result.apiKey.scopes,
          serviceAccountId: result.apiKey.serviceAccountId,
        },
        id: `audit_${randomUUID()}`,
        timestamp: new Date().toISOString(),
        type: 'api_key.created',
        workspaceId: auth.workspaceId,
      });
      return { apiKey: sanitizeApiKey(result.apiKey), token: result.token };
    } catch (error) {
      return mapKnownError(reply, error);
    }
  });
}

function sanitizeApiKey<T extends { keyHash?: string }>(apiKey: T): Omit<T, 'keyHash'> {
  const { keyHash: _keyHash, ...safe } = apiKey;
  return safe;
}
