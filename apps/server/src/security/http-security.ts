import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { AppConfig, AuthConfig } from '../config';
import { ForbiddenError, McpInsufficientScopeError, RateLimitError, UnauthorizedError } from '../errors';
import type { AuthContext, JsonObject } from '../models';
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

const AUTH_PROVIDERS = new Set<AuthContext['authProvider']>([
  'api_key',
  'none',
  'oidc_jwt',
  'slack',
  'telegram',
  'tunnel_single_user',
]);
const PRINCIPAL_TYPES = new Set<AuthContext['principalType']>([
  'local',
  'service_account',
  'slack',
  'telegram',
  'user',
]);

export type McpAuthenticatedPrincipal = AuthContext & { clientId: string };

/**
 * Server-owned authentication seam for the standard MCP endpoint.
 *
 * A resolver may use a trusted transport identity or another verified server
 * dependency. Request headers are deliberately not interpreted here as
 * identity assertions. `oauthPresentation: 'none'` is intended for an
 * authenticated transport such as a single-user Secure MCP Tunnel.
 */
export interface McpRequestAuthentication {
  oauthPresentation: 'none' | 'protected-resource';
  resolvePrincipal: (request: FastifyRequest) => McpAuthenticatedPrincipal | Promise<McpAuthenticatedPrincipal>;
}

export interface HttpErrorProjection {
  body: JsonObject;
  statusCode: number;
}

/** Edition-owned, static projection for errors absent from Community core. */
export type HttpErrorProjector = (error: unknown) => HttpErrorProjection | undefined;

export interface SecurityHookOptions {
  projectHttpError?: HttpErrorProjector;
  mcpRequestAuthentication?: McpRequestAuthentication;
}

const publicRoutes = new Set([
  'GET /health',
  'POST /v1/slack/interactions',
  'POST /v1/telegram/webhook',
  'GET /v1/integrations/google-workspace/oauth/callback',
  'GET /v1/integrations/slack/oauth/callback',
  'GET /.well-known/oauth-protected-resource',
  'GET /.well-known/oauth-protected-resource/mcp',
]);

export function registerSecurityHooks(
  app: FastifyInstance,
  config: AppConfig & { auth: AuthConfig },
  authService: AuthService,
  options: SecurityHookOptions = {},
): void {
  const buckets = new Map<string, RateBucket>();
  const mcpRequestAuthentication = options.mcpRequestAuthentication;
  const projectHttpError = options.projectHttpError;

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
        request.authContext = assertMcpAuthenticatedPrincipal(
          mcpRequestAuthentication
            ? await mcpRequestAuthentication.resolvePrincipal(request)
            : await authService.authenticateMcpAuthorizationHeader(
                headerValue(request.headers.authorization),
                config.mcp.streamableHttp.resourceUrl!,
              ),
        );
      } catch (error) {
        if (error instanceof UnauthorizedError) {
          if (presentsMcpOAuth(mcpRequestAuthentication)) {
            reply.header('www-authenticate', mcpBearerChallenge(config));
          }
          return reply.status(401).send({ error: 'unauthorized', message: error.message });
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
      if (isMcpEndpoint(request) && config.mcp?.streamableHttp?.enabled && presentsMcpOAuth(mcpRequestAuthentication)) {
        reply.header('www-authenticate', mcpBearerChallenge(config));
      }
      return reply.status(401).send({ error: 'unauthorized', message: error.message });
    }
    if (error instanceof McpInsufficientScopeError) {
      if (isMcpEndpoint(request) && config.mcp?.streamableHttp?.enabled && presentsMcpOAuth(mcpRequestAuthentication)) {
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
    const projected = projectHttpError?.(error);
    if (projected) return reply.status(projected.statusCode).send(projected.body);
    return reply.send(error);
  });
}

export function assertMcpAuthenticatedPrincipal(value: unknown): McpAuthenticatedPrincipal {
  const principal = value as Partial<AuthContext> | null | undefined;
  if (
    !principal ||
    !boundedIdentity(principal.clientId, 256) ||
    !boundedIdentity(principal.principalId, 512) ||
    !boundedIdentity(principal.workspaceId, 256) ||
    !boundedIdentity(principal.displayName, 512) ||
    !AUTH_PROVIDERS.has(principal.authProvider as AuthContext['authProvider']) ||
    !PRINCIPAL_TYPES.has(principal.principalType as AuthContext['principalType']) ||
    (principal.email !== undefined && !boundedIdentity(principal.email, 1024)) ||
    !Array.isArray(principal.groups) ||
    principal.groups.length > 128 ||
    principal.groups.some((group) => !boundedIdentity(group, 256)) ||
    new Set(principal.groups).size !== principal.groups.length ||
    !Array.isArray(principal.scopes) ||
    principal.scopes.length < 1 ||
    principal.scopes.length > 128 ||
    principal.scopes.some((scope) => !boundedIdentity(scope, 256)) ||
    new Set(principal.scopes).size !== principal.scopes.length
  ) {
    throw new UnauthorizedError('MCP authentication did not resolve a valid bounded principal.');
  }
  return value as McpAuthenticatedPrincipal;
}

export function presentsMcpOAuth(authentication: McpRequestAuthentication | undefined): boolean {
  return authentication?.oauthPresentation !== 'none';
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

function boundedIdentity(value: unknown, maxLength: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maxLength &&
    value === value.trim() &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  );
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
