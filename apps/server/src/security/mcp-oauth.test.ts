import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  createSign,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { AuthConfig } from '../config';
import type { Store } from '../storage/store';
import { AuthService, type JwksFetch } from './auth-service';

const ISSUER = 'https://issuer.example.com';
const RESOURCE = 'https://actionproxy.example/mcp';
const now = () => Math.floor(Date.now() / 1000);
const firstKey = signingKey('first-key');
const secondKey = signingKey('second-key');

describe('strict MCP OAuth bearer validation', () => {
  it('derives actor, adapter, scopes, and workspace only from verified server/token state', async () => {
    const service = authService({ jwksJson: jwks(firstKey) });
    const token = signToken(firstKey, {
      aud: RESOURCE,
      client_id: 'chatgpt-client-123',
      email: 'alice@example.com',
      exp: now() + 300,
      groups: ['support-managers'],
      iss: ISSUER,
      name: 'Alice',
      scope: 'tool_call:read tool_call:submit',
      sub: 'user_alice',
      tenant: 'forged-tenant',
      workspace_id: 'forged-workspace',
    });

    await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE)).resolves.toEqual({
      authProvider: 'oidc_jwt',
      clientId: 'chatgpt-client-123',
      displayName: 'Alice',
      email: 'alice@example.com',
      groups: ['support-managers'],
      principalId: 'user_alice',
      principalType: 'user',
      scopes: ['tool_call:read', 'tool_call:submit'],
      workspaceId: 'server-workspace',
    });
  });

  it('accepts azp as the client identity fallback and an audience array', async () => {
    const service = authService({ jwksJson: jwks(firstKey) });
    const token = validToken(firstKey, { aud: ['another-resource', RESOURCE], azp: 'chatgpt-client', client_id: undefined });

    await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE)).resolves.toMatchObject({
      clientId: 'chatgpt-client',
    });
  });

  it('rejects API keys, bootstrap keys, and implicit local auth without changing generic API behavior', async () => {
    const service = authService({ bootstrapAdminApiKey: 'bootstrap-secret', jwksJson: jwks(firstKey), mode: 'none' });

    await expect(service.authenticateMcpAuthorizationHeader(undefined, RESOURCE)).rejects.toThrow(/OAuth bearer/u);
    await expect(service.authenticateMcpAuthorizationHeader('Bearer apx_prefix_secret', RESOURCE)).rejects.toThrow(/OAuth bearer/u);
    await expect(service.authenticateMcpAuthorizationHeader('Bearer bootstrap-secret', RESOURCE)).rejects.toThrow(/OAuth bearer/u);
    await expect(service.authenticateAuthorizationHeader('Bearer not-a-jwt')).resolves.toMatchObject({
      authProvider: 'none',
      workspaceId: 'server-workspace',
    });
  });

  it.each([
    ['missing kid', firstKey, {}, { kid: undefined }, /key id is required/u],
    ['wrong algorithm', firstKey, {}, { alg: 'PS256' }, /algorithm is not trusted/u],
    ['wrong issuer', firstKey, { iss: 'https://attacker.example' }, {}, /issuer is not trusted/u],
    ['missing issuer', firstKey, { iss: undefined }, {}, /issuer is not trusted/u],
    ['wrong audience', firstKey, { aud: 'https://another.example/mcp' }, {}, /audience is not trusted/u],
    ['missing audience', firstKey, { aud: undefined }, {}, /audience is not trusted/u],
    ['malformed audience', firstKey, { aud: [RESOURCE, 7] }, {}, /audience is not trusted/u],
    ['missing expiry', firstKey, { exp: undefined }, {}, /expiry is missing or invalid/u],
    ['string expiry', firstKey, { exp: String(now() + 300) }, {}, /expiry is missing or invalid/u],
    ['expired token', firstKey, { exp: now() - 1 }, {}, /expiry is missing or invalid/u],
    ['future not-before', firstKey, { nbf: now() + 60 }, {}, /not active/u],
    ['malformed not-before', firstKey, { nbf: 'soon' }, {}, /not active/u],
    ['missing subject', firstKey, { sub: undefined }, {}, /subject is missing/u],
    ['missing client identity', firstKey, { client_id: undefined }, {}, /client identity is missing/u],
    ['malformed client identity', firstKey, { client_id: 17 }, {}, /client identity is invalid/u],
    ['conflicting client identity', firstKey, { azp: 'other-client' }, {}, /client identity is inconsistent/u],
    ['wildcard scope', firstKey, { scope: 'tool_call:read *' }, {}, /wildcard scope/u],
    ['malformed scope', firstKey, { scope: { submit: true } }, {}, /scope claim is invalid/u],
  ])('fails closed for %s', async (_name, key, payload, header, message) => {
    const service = authService({ jwksJson: jwks(firstKey) });
    const token = validToken(key as SigningKey, payload as Record<string, unknown>, header as Record<string, unknown>);

    await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE)).rejects.toThrow(message as RegExp);
  });

  it('requires exactly one compatible RSA signing key for the mandatory kid', async () => {
    const token = validToken(firstKey);
    const duplicate = JSON.stringify({ keys: [firstKey.jwk, firstKey.jwk] });
    const incompatible = JSON.stringify({ keys: [{ ...firstKey.jwk, use: 'enc' }] });

    await expect(authService({ jwksJson: duplicate }).authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE))
      .rejects.toThrow(/ambiguous/u);
    await expect(authService({ jwksJson: incompatible }).authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE))
      .rejects.toThrow(/not compatible/u);
  });

  it('rejects unknown key ids and invalid signatures without exposing either token', async () => {
    const service = authService({ jwksJson: jwks(firstKey) });
    const unknownKid = validToken(secondKey);
    const invalidSignature = validToken(secondKey, {}, { kid: firstKey.kid });

    await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${unknownKid}`, RESOURCE)).rejects.toThrow(
      /key id is not trusted/u,
    );
    await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${invalidSignature}`, RESOURCE)).rejects.toThrow(
      /signature is invalid/u,
    );
  });

  it('supports a locally mounted JWKS path and observes safe key rotation', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-jwks-'));
    const jwksPath = path.join(directory, 'jwks.json');
    try {
      fs.writeFileSync(jwksPath, jwks(firstKey));
      const service = authService({ jwksPath });
      await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${validToken(firstKey)}`, RESOURCE)).resolves.toBeDefined();

      fs.writeFileSync(jwksPath, jwks(secondKey));
      await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${validToken(secondKey)}`, RESOURCE)).resolves.toBeDefined();
    } finally {
      fs.rmSync(directory, { force: true, recursive: true });
    }
  });

  it('caches a remote JWKS and refreshes it once when a rotated kid is unknown', async () => {
    const fetchJwks = vi
      .fn<JwksFetch>()
      .mockResolvedValueOnce(jwksResponse(jwks(firstKey)))
      .mockResolvedValueOnce(jwksResponse(jwks(secondKey)));
    const service = authService({ jwksUri: 'https://issuer.example.com/jwks' }, fetchJwks);

    await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${validToken(firstKey)}`, RESOURCE)).resolves.toBeDefined();
    await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${validToken(firstKey)}`, RESOURCE)).resolves.toBeDefined();
    await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${validToken(secondKey)}`, RESOURCE)).resolves.toBeDefined();
    expect(fetchJwks).toHaveBeenCalledTimes(2);
    expect(fetchJwks).toHaveBeenNthCalledWith(
      1,
      'https://issuer.example.com/jwks',
      expect.objectContaining({ redirect: 'error', signal: expect.any(AbortSignal) }),
    );
  });

  it('fails closed for unavailable, malformed, oversized, and unsafe remote JWKS sources', async () => {
    const unavailable = vi.fn<JwksFetch>().mockRejectedValue(new Error('provider included secret-provider-detail'));
    const malformed = vi.fn<JwksFetch>().mockResolvedValue(jwksResponse('{not-json'));
    const oversized = vi.fn<JwksFetch>().mockResolvedValue(jwksResponse('{}', String(256 * 1024 + 1)));
    const unsafe = vi.fn<JwksFetch>();
    const token = validToken(firstKey);

    await expect(authService({ jwksUri: 'https://issuer.example.com/jwks' }, unavailable)
      .authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE)).rejects.toThrow('MCP JWKS is unavailable.');
    await expect(authService({ jwksUri: 'https://issuer.example.com/jwks' }, malformed)
      .authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE)).rejects.toThrow('MCP JWKS is invalid.');
    await expect(authService({ jwksUri: 'https://issuer.example.com/jwks' }, oversized)
      .authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE)).rejects.toThrow(/too large/u);
    await expect(authService({ jwksUri: 'http://metadata.internal/jwks' }, unsafe)
      .authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE)).rejects.toThrow(/must use HTTPS/u);
    expect(unsafe).not.toHaveBeenCalled();
  });

  it('bounds streamed JWKS bodies even when content-length is absent', async () => {
    const oversizedBody = vi.fn<JwksFetch>().mockResolvedValue(jwksResponse('x'.repeat(256 * 1024 + 1)));
    const service = authService({ jwksUri: 'https://issuer.example.com/jwks' }, oversizedBody);

    await expect(service.authenticateMcpAuthorizationHeader(`Bearer ${validToken(firstKey)}`, RESOURCE)).rejects.toThrow(
      /too large/u,
    );
  });

  it('aborts a stalled remote JWKS fetch at the bounded timeout', async () => {
    vi.useFakeTimers();
    try {
      const stalled = vi.fn<JwksFetch>((_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new Error('aborted provider request')), { once: true });
        }));
      const service = authService({ jwksUri: 'https://issuer.example.com/jwks' }, stalled);
      const authentication = service.authenticateMcpAuthorizationHeader(`Bearer ${validToken(firstKey)}`, RESOURCE);
      const rejection = expect(authentication).rejects.toThrow('MCP JWKS is unavailable.');

      await vi.advanceTimersByTimeAsync(3_000);
      await rejection;
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not leak bearer tokens, claims, provider details, or configured URLs in failures', async () => {
    const fetchJwks = vi.fn<JwksFetch>().mockRejectedValue(new Error('provider-secret-detail'));
    const service = authService({ jwksUri: 'https://issuer.example.com/private-jwks?account=secret-account' }, fetchJwks);
    const token = validToken(firstKey, { confidential_claim: 'claim-secret-value' });

    let failure: unknown;
    try {
      await service.authenticateMcpAuthorizationHeader(`Bearer ${token}`, RESOURCE);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    const message = (failure as Error).message;
    expect(message).toBe('MCP JWKS is unavailable.');
    expect(message).not.toContain(token);
    expect(message).not.toContain('claim-secret-value');
    expect(message).not.toContain('provider-secret-detail');
    expect(message).not.toContain('secret-account');
  });

  it('accepts valid numeric time bounds for generic OIDC JWTs', async () => {
    const service = authService({ audience: RESOURCE, jwksJson: jwks(firstKey), mode: 'oidc_jwt' });
    const token = signToken(firstKey, {
      aud: RESOURCE,
      exp: now() + 300,
      iss: ISSUER,
      nbf: now() - 1,
      scope: 'tool_call:read',
      sub: 'api-user-with-numeric-time-bounds',
    });

    await expect(service.authenticateAuthorizationHeader(`Bearer ${token}`)).resolves.toMatchObject({
      principalId: 'api-user-with-numeric-time-bounds',
      scopes: ['tool_call:read'],
    });
  });

  it('uses the bounded remote JWKS cache and rotation path for generic OIDC API authentication', async () => {
    const fetchJwks = vi
      .fn<JwksFetch>()
      .mockResolvedValueOnce(jwksResponse(jwks(firstKey)))
      .mockResolvedValueOnce(jwksResponse(jwks(secondKey)));
    const service = authService(
      { audience: RESOURCE, jwksUri: 'https://issuer.example.com/jwks', mode: 'oidc_jwt' },
      fetchJwks,
    );

    await expect(service.authenticateAuthorizationHeader(`Bearer ${validToken(firstKey)}`)).resolves.toMatchObject({
      principalId: 'user-123',
    });
    await expect(service.authenticateAuthorizationHeader(`Bearer ${validToken(firstKey)}`)).resolves.toBeDefined();
    await expect(service.authenticateAuthorizationHeader(`Bearer ${validToken(secondKey)}`)).resolves.toMatchObject({
      principalId: 'user-123',
    });
    expect(fetchJwks).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['missing expiry', { exp: undefined }, /expiry is missing or invalid/u],
    ['string expiry', { exp: String(now() + 300) }, /expiry is missing or invalid/u],
    ['expired token', { exp: now() - 1 }, /expiry is missing or invalid/u],
    ['string not-before', { exp: now() + 300, nbf: 'soon' }, /not active yet/u],
    ['future not-before', { exp: now() + 300, nbf: now() + 60 }, /not active yet/u],
  ])('rejects %s for generic OIDC JWTs before trusting scopes', async (_name, claims, message) => {
    const service = authService({ audience: RESOURCE, jwksJson: jwks(firstKey), mode: 'oidc_jwt' });
    const token = signToken(firstKey, {
      aud: RESOURCE,
      iss: ISSUER,
      scope: 'tool_call:submit',
      sub: 'api-user-with-invalid-time-bounds',
      ...claims,
    });

    await expect(service.authenticateAuthorizationHeader(`Bearer ${token}`)).rejects.toThrow(message);
  });
});

interface SigningKey {
  jwk: Record<string, unknown>;
  kid: string;
  privateKey: KeyObject;
}

function signingKey(kid: string): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    jwk: { ...publicKey.export({ format: 'jwk' }), alg: 'RS256', kid, use: 'sig' },
    kid,
    privateKey,
  };
}

function validToken(
  key: SigningKey,
  overrides: Record<string, unknown> = {},
  headerOverrides: Record<string, unknown> = {},
): string {
  return signToken(
    key,
    {
      aud: RESOURCE,
      client_id: 'chatgpt-client',
      exp: now() + 300,
      iss: ISSUER,
      scope: 'tool_call:read tool_call:submit',
      sub: 'user-123',
      ...overrides,
    },
    headerOverrides,
  );
}

function signToken(
  key: SigningKey,
  payload: Record<string, unknown>,
  headerOverrides: Record<string, unknown> = {},
): string {
  const header = { alg: 'RS256', kid: key.kid, typ: 'at+jwt', ...headerOverrides };
  const encodedHeader = base64UrlJson(header);
  const encodedPayload = base64UrlJson(payload);
  const signedValue = `${encodedHeader}.${encodedPayload}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signedValue);
  signer.end();
  return `${signedValue}.${signer.sign(key.privateKey).toString('base64url')}`;
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function jwks(key: SigningKey): string {
  return JSON.stringify({ keys: [key.jwk] });
}

function jwksResponse(body: string, contentLength?: string): Awaited<ReturnType<JwksFetch>> {
  const response = new Response(body, {
    headers: contentLength === undefined ? undefined : { 'content-length': contentLength },
    status: 200,
  });
  return response as unknown as Awaited<ReturnType<JwksFetch>>;
}

function authService(
  oidc: Partial<AuthConfig['oidc']> & { bootstrapAdminApiKey?: string; mode?: AuthConfig['mode'] },
  fetchJwks?: JwksFetch,
): AuthService {
  const { bootstrapAdminApiKey, mode, ...oidcConfig } = oidc;
  const config: AuthConfig = {
    allowedCorsOrigins: [],
    bootstrapAdminApiKey,
    mode: mode ?? 'api_key',
    oidc: {
      emailClaim: 'email',
      groupsClaim: 'groups',
      issuer: ISSUER,
      nameClaim: 'name',
      scopesClaim: 'scope',
      ...oidcConfig,
    },
    rateLimit: { max: 100, windowMs: 60_000 },
    slackUserMap: {},
    workspaceId: 'server-workspace',
  };
  return new AuthService(config, {} as Store, fetchJwks);
}
