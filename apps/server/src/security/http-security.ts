import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { AppConfig, AuthConfig } from '../config';
import { ForbiddenError, McpInsufficientScopeError, RateLimitError, UnauthorizedError } from '../errors';
import type { AuthContext } from '../models';
import type { AuthService } from './auth-service';

declare module 'fastify' {
  interface FastifyRequest {
    authContext?: AuthContext;
  }
}

interface RateBucket {
  count: number;
  resetAt: number;
}

const publicRoutes = new Set([
  'GET /health',
  'POST /v1/slack/interactions',
  'POST /v1/telegram/webhook',
  'GET /.well-known/oauth-protected-resource',
  'GET /.well-known/oauth-protected-resource/mcp',
]);

export function registerSecurityHooks(
  app: FastifyInstance,
  config: AppConfig & { auth: AuthConfig },
  authService: AuthService,
): void {
  const buckets = new Map<string, RateBucket>();

  app.addHook('onRequest', async (request, reply) => {
    applySecurityHeaders(reply);
    applyCors(request, reply, config.auth.allowedCorsOrigins);

    if (request.method === 'OPTIONS') {
      return reply.status(204).send();
    }

    enforceRateLimit(buckets, request, config.auth.rateLimit);

    if (isMcpEndpoint(request)) {
      if (!config.mcp?.streamableHttp?.enabled) return;
      try {
        request.authContext = await authService.authenticateMcpAuthorizationHeader(
          headerValue(request.headers.authorization),
          config.mcp.streamableHttp.resourceUrl!,
        );
      } catch (error) {
        if (error instanceof UnauthorizedError) {
          return reply
            .header('www-authenticate', mcpBearerChallenge(config))
            .status(401)
            .send({ error: 'unauthorized', message: error.message });
        }
        throw error;
      }
      return;
    }

    if (isPublicRequest(request)) return;

    request.authContext = await authService.authenticateAuthorizationHeader(headerValue(request.headers.authorization));
  });

  app.setErrorHandler((error, request, reply) => {
    if (error instanceof UnauthorizedError) {
      if (isMcpEndpoint(request) && config.mcp?.streamableHttp?.enabled) {
        reply.header('www-authenticate', mcpBearerChallenge(config));
      }
      return reply.status(401).send({ error: 'unauthorized', message: error.message });
    }
    if (error instanceof McpInsufficientScopeError) {
      if (isMcpEndpoint(request) && config.mcp?.streamableHttp?.enabled) {
        reply.header(
          'www-authenticate',
          `${mcpBearerChallenge(config)}, error="insufficient_scope", scope="${error.requiredScope}"`,
        );
      }
      return reply.status(403).send({ error: 'insufficient_scope', message: error.message, scope: error.requiredScope });
    }
    if (error instanceof ForbiddenError) {
      return reply.status(403).send({ error: 'forbidden', message: error.message });
    }
    if (error instanceof RateLimitError) {
      return reply.status(429).send({ error: 'rate_limited', message: error.message });
    }
    return reply.send(error);
  });
}

function isPublicRequest(request: FastifyRequest): boolean {
  const pathname = request.url.split('?')[0] ?? '';
  if (publicRoutes.has(`${request.method} ${pathname}`)) return true;
  return request.method === 'GET' && !pathname.startsWith('/v1/');
}

function isMcpEndpoint(request: FastifyRequest): boolean {
  return (request.url.split('?')[0] ?? '') === '/mcp';
}

function mcpBearerChallenge(config: AppConfig): string {
  const resourceUrl = config.mcp?.streamableHttp?.resourceUrl;
  const metadataUrl = resourceUrl
    ? new URL('/.well-known/oauth-protected-resource/mcp', resourceUrl).toString()
    : '/.well-known/oauth-protected-resource/mcp';
  return `Bearer resource_metadata="${metadataUrl}"`;
}

function applySecurityHeaders(reply: { header: (name: string, value: string) => unknown }): void {
  reply.header('x-content-type-options', 'nosniff');
  reply.header('referrer-policy', 'no-referrer');
  reply.header('x-frame-options', 'DENY');
  reply.header('content-security-policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
}

function applyCors(
  request: FastifyRequest,
  reply: { header: (name: string, value: string) => unknown },
  allowedOrigins: string[],
): void {
  const origin = headerValue(request.headers.origin);
  if (!origin || !allowedOrigins.includes(origin)) return;

  reply.header('access-control-allow-origin', origin);
  reply.header('vary', 'origin');
  reply.header('access-control-allow-methods', 'GET,POST,PUT,OPTIONS');
  reply.header(
    'access-control-allow-headers',
    'authorization,content-type,idempotency-key,mcp-protocol-version,mcp-session-id,last-event-id',
  );
  reply.header('access-control-expose-headers', 'mcp-session-id,mcp-protocol-version,www-authenticate');
}

function enforceRateLimit(
  buckets: Map<string, RateBucket>,
  request: FastifyRequest,
  rateLimit: AuthConfig['rateLimit'],
): void {
  const now = Date.now();
  const key = `${request.ip}:${request.method}:${request.url.split('?')[0]}`;
  const bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + rateLimit.windowMs });
    return;
  }

  bucket.count += 1;
  if (bucket.count > rateLimit.max) {
    throw new RateLimitError('Rate limit exceeded.');
  }
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
