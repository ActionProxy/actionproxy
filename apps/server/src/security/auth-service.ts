import fs from 'node:fs';
import { createPublicKey, createVerify, randomUUID } from 'node:crypto';
import type { AuthConfig, SlackUserMapping } from '../config';
import { ForbiddenError, UnauthorizedError } from '../errors';
import type { ApiKeyRecord, AuthContext, JsonObject, ServiceAccountRecord } from '../models';
import type { Store } from '../storage/store';
import { ALL_SCOPES, type ActionProxyScope } from './scopes';
import { randomToken, safeEqual, sha256Hex } from './crypto';

export interface CreateServiceAccountInput {
  description?: string;
  groups?: string[];
  name: string;
  scopes?: string[];
}

export interface CreateApiKeyInput {
  scopes?: string[];
}

export interface CreatedApiKey {
  apiKey: ApiKeyRecord;
  token: string;
}

interface JwtHeader {
  alg?: string;
  kid?: string;
  typ?: string;
}

interface Jwks {
  keys?: JsonObject[];
}

interface JwksFetchResponse {
  body: {
    getReader(): {
      cancel(): Promise<unknown>;
      read(): Promise<{ done: boolean; value?: Uint8Array }>;
    };
  } | null;
  headers: {
    get(name: string): string | null;
  };
  ok: boolean;
}

export type JwksFetch = (
  url: string,
  init: { redirect: 'error'; signal: AbortSignal },
) => Promise<JwksFetchResponse>;

interface LoadedMcpJwks {
  fromCache: boolean;
  jwks: Jwks;
  remote: boolean;
}

const MCP_JWKS_CACHE_MS = 5 * 60 * 1000;
const MCP_JWKS_FETCH_TIMEOUT_MS = 3_000;
const MCP_JWKS_MAX_BYTES = 256 * 1024;
const MCP_JWKS_UNKNOWN_KID_REFRESH_COOLDOWN_MS = 30_000;

const defaultJwksFetch: JwksFetch = async (url, init) =>
  (await globalThis.fetch(url, init)) as unknown as JwksFetchResponse;

export class AuthService {
  private remoteJwksCache?: { fetchedAt: number; jwks: Jwks; uri: string };
  private remoteJwksFetch?: { promise: Promise<Jwks>; uri: string };
  private remoteUnknownKidRefreshedAt = 0;

  constructor(
    private readonly config: AuthConfig,
    private readonly store: Store,
    private readonly fetchJwks: JwksFetch = defaultJwksFetch,
  ) {}

  async ensureWorkspace(): Promise<void> {
    const existing = await this.store.getWorkspace(this.config.workspaceId);
    if (existing) return;

    await this.store.createWorkspace({
      createdAt: new Date().toISOString(),
      id: this.config.workspaceId,
      name: this.config.workspaceId,
    });
  }

  workspaceId(): string {
    return this.config.workspaceId;
  }

  localContext(actor = 'local-admin'): AuthContext {
    return {
      authProvider: 'none',
      displayName: actor,
      email: actor.includes('@') ? actor : undefined,
      groups: ['actionproxy-admins', 'actionproxy-approvers'],
      principalId: actor,
      principalType: 'local',
      scopes: ['*'],
      workspaceId: this.config.workspaceId,
    };
  }

  async authenticateAuthorizationHeader(value: string | undefined): Promise<AuthContext> {
    if (this.config.mode === 'none') return this.localContext();

    const token = bearerToken(value);
    if (!token) throw new UnauthorizedError('Bearer authentication is required.');

    if (this.config.bootstrapAdminApiKey && safeEqual(token, this.config.bootstrapAdminApiKey)) {
      return {
        authProvider: 'api_key',
        displayName: 'Bootstrap Admin',
        groups: ['actionproxy-admins', 'actionproxy-approvers'],
        principalId: 'bootstrap-admin',
        principalType: 'service_account',
        scopes: ['*'],
        workspaceId: this.config.workspaceId,
      };
    }

    if (token.startsWith('apx_')) return this.authenticateApiKey(token);
    if (this.config.mode === 'oidc_jwt') return this.authenticateOidcJwt(token);

    throw new UnauthorizedError('API key authentication is required.');
  }

  /**
   * Strict OAuth access-token validation for the MCP protected-resource boundary.
   * This intentionally does not accept ActionProxy API keys, bootstrap keys, or
   * the implicit local context accepted by the generic API authentication path.
   */
  async authenticateMcpAuthorizationHeader(
    value: string | undefined,
    expectedAudience: string,
  ): Promise<AuthContext> {
    const token = bearerToken(value);
    if (!token || token.startsWith('apx_') || this.isBootstrapToken(token)) {
      throw new UnauthorizedError('MCP OAuth bearer authentication is required.');
    }

    const issuer = stringClaim(this.config.oidc.issuer);
    if (!issuer) throw new UnauthorizedError('MCP OAuth issuer is not configured.');
    if (!expectedAudience.trim()) throw new UnauthorizedError('MCP OAuth audience is not configured.');

    const { header, payload, signature, signedValue } = parseMcpJwt(token);
    if (header.alg !== 'RS256') throw new UnauthorizedError('MCP access token algorithm is not trusted.');
    const kid = stringClaim(header.kid);
    if (!kid) throw new UnauthorizedError('MCP access token key id is required.');

    let loaded = await this.loadMcpJwks();
    let jwk = resolveUniqueMcpSigningKey(loaded.jwks, kid);
    if (!jwk && loaded.remote && loaded.fromCache && this.canRefreshUnknownKid()) {
      loaded = await this.loadRemoteMcpJwks(true);
      jwk = resolveUniqueMcpSigningKey(loaded.jwks, kid);
    }
    if (!jwk) throw new UnauthorizedError('MCP access token key id is not trusted.');
    if (!verifyMcpJwtSignature(signedValue, signature, jwk)) {
      throw new UnauthorizedError('MCP access token signature is invalid.');
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.iss !== issuer) throw new UnauthorizedError('MCP access token issuer is not trusted.');
    if (!strictAudienceMatches(payload.aud, expectedAudience)) {
      throw new UnauthorizedError('MCP access token audience is not trusted.');
    }
    if (!isNumericDate(payload.exp) || payload.exp <= now) {
      throw new UnauthorizedError('MCP access token expiry is missing or invalid.');
    }
    if (payload.nbf !== undefined && (!isNumericDate(payload.nbf) || payload.nbf > now)) {
      throw new UnauthorizedError('MCP access token is not active.');
    }

    const principalId = stringClaim(payload.sub);
    if (!principalId) throw new UnauthorizedError('MCP access token subject is missing.');
    const clientId = mcpClientId(payload);
    const scopes = strictScopesClaim(payload[this.config.oidc.scopesClaim]);
    if (scopes.includes('*')) throw new UnauthorizedError('MCP access token wildcard scope is not allowed.');

    const email = stringClaim(payload[this.config.oidc.emailClaim]);
    return {
      authProvider: 'oidc_jwt',
      clientId,
      displayName: stringClaim(payload[this.config.oidc.nameClaim]) ?? email ?? principalId,
      email,
      groups: stringArrayClaim(payload[this.config.oidc.groupsClaim]),
      principalId,
      principalType: 'user',
      scopes,
      workspaceId: this.config.workspaceId,
    };
  }

  async slackContext(mapping: SlackUserMapping | undefined, slackUserId: string): Promise<AuthContext> {
    if (this.config.mode === 'none') {
      return this.localContext(`slack:${slackUserId}`);
    }

    if (!mapping) {
      throw new ForbiddenError(`Slack user is not mapped to an ActionProxy principal: ${slackUserId}`);
    }

    return {
      authProvider: 'slack',
      displayName: mapping.displayName ?? mapping.email ?? mapping.principalId,
      email: mapping.email,
      groups: mapping.groups ?? [],
      principalId: mapping.principalId,
      principalType: 'slack',
      scopes: mapping.scopes ?? ['approval:read', 'approval:approve', 'approval:reject'],
      workspaceId: this.config.workspaceId,
    };
  }

  slackUserMapping(slackUserId: string): SlackUserMapping | undefined {
    return this.config.slackUserMap[slackUserId];
  }

  async telegramContext(telegramUserId: string): Promise<AuthContext> {
    if (this.config.mode === 'none') {
      return this.localContext(`telegram:${telegramUserId}`);
    }

    throw new ForbiddenError(`Telegram user is not mapped to an ActionProxy principal: ${telegramUserId}`);
  }

  async createServiceAccount(input: CreateServiceAccountInput, actor: AuthContext): Promise<ServiceAccountRecord> {
    const now = new Date().toISOString();
    const record: ServiceAccountRecord = {
      createdAt: now,
      description: input.description,
      groups: uniqueStrings(input.groups ?? []),
      id: `svc_${randomUUID()}`,
      name: input.name,
      scopes: uniqueStrings(input.scopes ?? ['tool_call:submit', 'tool_call:read']),
      updatedAt: now,
      workspaceId: actor.workspaceId,
    };
    return this.store.createServiceAccount(record);
  }

  async createApiKey(serviceAccountId: string, input: CreateApiKeyInput, actor: AuthContext): Promise<CreatedApiKey> {
    const serviceAccount = await this.store.getServiceAccount(serviceAccountId);
    if (!serviceAccount || serviceAccount.workspaceId !== actor.workspaceId) {
      throw new ForbiddenError('Service account is not available in this workspace.');
    }
    if (serviceAccount.revokedAt) throw new ForbiddenError('Service account is revoked.');

    const keyPrefix = randomUUID().replaceAll('-', '').slice(0, 12);
    const token = `apx_${keyPrefix}_${randomToken(32)}`;
    const now = new Date().toISOString();
    const scopes = restrictScopes(input.scopes ?? serviceAccount.scopes, serviceAccount.scopes);
    const record: ApiKeyRecord = {
      createdAt: now,
      id: `key_${randomUUID()}`,
      keyHash: hashApiKey(token),
      keyPrefix,
      scopes,
      serviceAccountId,
      workspaceId: actor.workspaceId,
    };
    await this.store.createApiKey(record);
    return { apiKey: record, token };
  }

  private async authenticateApiKey(token: string): Promise<AuthContext> {
    const keyPrefix = parseApiKeyPrefix(token);
    if (!keyPrefix) throw new UnauthorizedError('Invalid API key format.');

    const apiKey = await this.store.getApiKeyByPrefix(keyPrefix);
    if (!apiKey || apiKey.revokedAt || !safeEqual(apiKey.keyHash, hashApiKey(token))) {
      throw new UnauthorizedError('Invalid API key.');
    }

    const serviceAccount = await this.store.getServiceAccount(apiKey.serviceAccountId);
    if (!serviceAccount || serviceAccount.revokedAt) throw new UnauthorizedError('Service account is unavailable.');

    await this.store.updateApiKey({ ...apiKey, lastUsedAt: new Date().toISOString() });

    return {
      authProvider: 'api_key',
      displayName: serviceAccount.name,
      groups: serviceAccount.groups,
      principalId: serviceAccount.id,
      principalType: 'service_account',
      scopes: restrictScopes(apiKey.scopes.length > 0 ? apiKey.scopes : serviceAccount.scopes, serviceAccount.scopes),
      workspaceId: apiKey.workspaceId,
    };
  }

  private authenticateOidcJwt(token: string): AuthContext {
    const { header, payload, signedValue, signature } = parseJwt(token);
    if (header.alg !== 'RS256') throw new UnauthorizedError('Only RS256 OIDC JWTs are supported.');
    if (!verifyJwtSignature(header, signedValue, signature, this.loadJwks())) {
      throw new UnauthorizedError('Invalid JWT signature.');
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number' && payload.exp <= now) throw new UnauthorizedError('JWT is expired.');
    if (typeof payload.nbf === 'number' && payload.nbf > now) throw new UnauthorizedError('JWT is not active yet.');
    if (this.config.oidc.issuer && payload.iss !== this.config.oidc.issuer) {
      throw new UnauthorizedError('JWT issuer is not trusted.');
    }
    if (this.config.oidc.audience && !audienceMatches(payload.aud, this.config.oidc.audience)) {
      throw new UnauthorizedError('JWT audience is not trusted.');
    }

    const principalId = stringClaim(payload.sub) ?? stringClaim(payload.email);
    if (!principalId) throw new UnauthorizedError('JWT has no subject.');

    const email = stringClaim(payload[this.config.oidc.emailClaim]);
    const displayName = stringClaim(payload[this.config.oidc.nameClaim]) ?? email ?? principalId;
    return {
      authProvider: 'oidc_jwt',
      displayName,
      email,
      groups: stringArrayClaim(payload[this.config.oidc.groupsClaim]),
      principalId,
      principalType: 'user',
      scopes: scopesClaim(payload[this.config.oidc.scopesClaim]),
      workspaceId: this.config.workspaceId,
    };
  }

  private loadJwks(): Jwks {
    const raw = this.config.oidc.jwksJson ?? (this.config.oidc.jwksPath ? fs.readFileSync(this.config.oidc.jwksPath, 'utf8') : undefined);
    if (!raw) throw new UnauthorizedError('OIDC JWKS is not configured.');
    try {
      return JSON.parse(raw) as Jwks;
    } catch {
      throw new UnauthorizedError('OIDC JWKS is invalid JSON.');
    }
  }

  private isBootstrapToken(token: string): boolean {
    return Boolean(this.config.bootstrapAdminApiKey && safeEqual(token, this.config.bootstrapAdminApiKey));
  }

  private async loadMcpJwks(): Promise<LoadedMcpJwks> {
    if (this.config.oidc.jwksJson) {
      return { fromCache: false, jwks: parseMcpJwks(this.config.oidc.jwksJson), remote: false };
    }
    if (this.config.oidc.jwksPath) {
      let raw: string;
      try {
        raw = fs.readFileSync(this.config.oidc.jwksPath, 'utf8');
      } catch {
        throw new UnauthorizedError('MCP JWKS is unavailable.');
      }
      return { fromCache: false, jwks: parseMcpJwks(raw), remote: false };
    }
    if (this.config.oidc.jwksUri) return this.loadRemoteMcpJwks(false);
    throw new UnauthorizedError('MCP JWKS is not configured.');
  }

  private async loadRemoteMcpJwks(forceRefresh: boolean): Promise<LoadedMcpJwks> {
    const uri = safeRemoteJwksUri(this.config.oidc.jwksUri);
    const now = Date.now();
    if (
      !forceRefresh &&
      this.remoteJwksCache?.uri === uri &&
      now - this.remoteJwksCache.fetchedAt < MCP_JWKS_CACHE_MS
    ) {
      return { fromCache: true, jwks: this.remoteJwksCache.jwks, remote: true };
    }

    let pending = this.remoteJwksFetch?.uri === uri ? this.remoteJwksFetch.promise : undefined;
    if (!pending) {
      pending = this.fetchRemoteMcpJwks(uri);
      this.remoteJwksFetch = { promise: pending, uri };
    }

    try {
      const jwks = await pending;
      this.remoteJwksCache = { fetchedAt: Date.now(), jwks, uri };
      return { fromCache: false, jwks, remote: true };
    } finally {
      if (this.remoteJwksFetch?.promise === pending) this.remoteJwksFetch = undefined;
    }
  }

  private async fetchRemoteMcpJwks(uri: string): Promise<Jwks> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), MCP_JWKS_FETCH_TIMEOUT_MS);
    try {
      const response = await this.fetchJwks(uri, { redirect: 'error', signal: controller.signal });
      if (!response.ok) throw new UnauthorizedError('MCP JWKS is unavailable.');
      const declaredLength = response.headers.get('content-length');
      if (declaredLength !== null) {
        const bytes = Number(declaredLength);
        if (!Number.isFinite(bytes) || bytes < 0 || bytes > MCP_JWKS_MAX_BYTES) {
          throw new UnauthorizedError('MCP JWKS response is too large.');
        }
      }
      return parseMcpJwks(await readBoundedResponse(response));
    } catch (error) {
      if (error instanceof UnauthorizedError) throw error;
      throw new UnauthorizedError('MCP JWKS is unavailable.');
    } finally {
      clearTimeout(timeout);
    }
  }

  private canRefreshUnknownKid(): boolean {
    const now = Date.now();
    if (now - this.remoteUnknownKidRefreshedAt < MCP_JWKS_UNKNOWN_KID_REFRESH_COOLDOWN_MS) return false;
    this.remoteUnknownKidRefreshedAt = now;
    return true;
  }
}

export function hashApiKey(token: string): string {
  return sha256Hex(token);
}

function bearerToken(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const [scheme, token] = value.split(/\s+/, 2);
  return scheme?.toLowerCase() === 'bearer' && token ? token : undefined;
}

function parseApiKeyPrefix(token: string): string | undefined {
  const [, prefix] = token.match(/^apx_([^_]+)_/) ?? [];
  return prefix;
}

function parseJwt(token: string): { header: JwtHeader; payload: JsonObject; signedValue: string; signature: Buffer } {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
  if (!encodedHeader || !encodedPayload || !encodedSignature) throw new UnauthorizedError('Invalid JWT format.');

  const header = parseBase64Json<JwtHeader>(encodedHeader);
  const payload = parseBase64Json<JsonObject>(encodedPayload);
  return {
    header,
    payload,
    signature: Buffer.from(encodedSignature, 'base64url'),
    signedValue: `${encodedHeader}.${encodedPayload}`,
  };
}

function parseBase64Json<T>(value: string): T {
  try {
    return JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as T;
  } catch {
    throw new UnauthorizedError('JWT contains invalid JSON.');
  }
}

function verifyJwtSignature(header: JwtHeader, signedValue: string, signature: Buffer, jwks: Jwks): boolean {
  const keys = jwks.keys ?? [];
  const jwk = keys.find((candidate) => (header.kid ? candidate.kid === header.kid : true));
  if (!jwk) throw new UnauthorizedError('JWT key id is not trusted.');

  try {
    const verifier = createVerify('RSA-SHA256');
    verifier.update(signedValue);
    verifier.end();
    return verifier.verify(createPublicKey({ format: 'jwk', key: jwk }), signature);
  } catch {
    return false;
  }
}

function parseMcpJwt(token: string): {
  header: JwtHeader;
  payload: JsonObject;
  signature: Buffer;
  signedValue: string;
} {
  const segments = token.split('.');
  if (segments.length !== 3) throw new UnauthorizedError('MCP access token format is invalid.');
  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw new UnauthorizedError('MCP access token format is invalid.');
  }
  if (![encodedHeader, encodedPayload, encodedSignature].every(isUnpaddedBase64Url)) {
    throw new UnauthorizedError('MCP access token encoding is invalid.');
  }

  const header = parseMcpJsonSegment<JwtHeader>(encodedHeader);
  const payload = parseMcpJsonSegment<JsonObject>(encodedPayload);
  if (!isPlainObject(header) || !isPlainObject(payload)) {
    throw new UnauthorizedError('MCP access token claims are invalid.');
  }

  const signature = Buffer.from(encodedSignature, 'base64url');
  if (signature.length === 0) throw new UnauthorizedError('MCP access token signature is invalid.');
  return {
    header,
    payload,
    signature,
    signedValue: `${encodedHeader}.${encodedPayload}`,
  };
}

function parseMcpJsonSegment<T>(value: string): T {
  try {
    return JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as T;
  } catch {
    throw new UnauthorizedError('MCP access token contains invalid JSON.');
  }
}

function isUnpaddedBase64Url(value: string): boolean {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  try {
    return Buffer.from(value, 'base64url').toString('base64url') === value;
  } catch {
    return false;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseMcpJwks(raw: string): Jwks {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new UnauthorizedError('MCP JWKS is invalid.');
  }
  if (!isPlainObject(parsed) || !Array.isArray(parsed.keys) || parsed.keys.length === 0) {
    throw new UnauthorizedError('MCP JWKS is invalid.');
  }
  if (!parsed.keys.every(isPlainObject)) throw new UnauthorizedError('MCP JWKS is invalid.');
  return { keys: parsed.keys as JsonObject[] };
}

function resolveUniqueMcpSigningKey(jwks: Jwks, kid: string): JsonObject | undefined {
  const matching = (jwks.keys ?? []).filter((candidate) => candidate.kid === kid);
  if (matching.length > 1) throw new UnauthorizedError('MCP JWKS key id is ambiguous.');
  const [jwk] = matching;
  if (!jwk) return undefined;
  if (!isCompatibleRsaSigningJwk(jwk)) throw new UnauthorizedError('MCP JWKS signing key is not compatible.');
  return jwk;
}

function isCompatibleRsaSigningJwk(jwk: JsonObject): boolean {
  if (jwk.kty !== 'RSA') return false;
  if (jwk.alg !== undefined && jwk.alg !== 'RS256') return false;
  if (jwk.use !== undefined && jwk.use !== 'sig') return false;
  if (
    jwk.key_ops !== undefined &&
    (!Array.isArray(jwk.key_ops) || !jwk.key_ops.every((operation) => typeof operation === 'string') || !jwk.key_ops.includes('verify'))
  ) {
    return false;
  }
  return stringClaim(jwk.n) !== undefined && stringClaim(jwk.e) !== undefined;
}

function verifyMcpJwtSignature(signedValue: string, signature: Buffer, jwk: JsonObject): boolean {
  try {
    const verifier = createVerify('RSA-SHA256');
    verifier.update(signedValue);
    verifier.end();
    return verifier.verify(createPublicKey({ format: 'jwk', key: jwk }), signature);
  } catch {
    return false;
  }
}

function strictAudienceMatches(value: unknown, expected: string): boolean {
  if (typeof value === 'string') return value === expected;
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((audience): audience is string => typeof audience === 'string') &&
    value.includes(expected)
  );
}

function isNumericDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function mcpClientId(payload: JsonObject): string {
  const clientClaimPresent = Object.prototype.hasOwnProperty.call(payload, 'client_id');
  const authorizedPartyPresent = Object.prototype.hasOwnProperty.call(payload, 'azp');
  const clientId = stringClaim(payload.client_id);
  const authorizedParty = stringClaim(payload.azp);
  if ((clientClaimPresent && !clientId) || (authorizedPartyPresent && !authorizedParty)) {
    throw new UnauthorizedError('MCP access token client identity is invalid.');
  }
  if (clientId && authorizedParty && clientId !== authorizedParty) {
    throw new UnauthorizedError('MCP access token client identity is inconsistent.');
  }
  const resolved = clientId ?? authorizedParty;
  if (!resolved) throw new UnauthorizedError('MCP access token client identity is missing.');
  return resolved;
}

function strictScopesClaim(value: unknown): string[] {
  if (value === undefined) return [];
  if (typeof value === 'string') return uniqueStrings(value.split(/\s+/u));
  if (Array.isArray(value) && value.every((scope): scope is string => typeof scope === 'string')) {
    return uniqueStrings(value);
  }
  throw new UnauthorizedError('MCP access token scope claim is invalid.');
}

function safeRemoteJwksUri(value: string | undefined): string {
  if (!value) throw new UnauthorizedError('MCP JWKS URI is not configured.');
  let uri: URL;
  try {
    uri = new URL(value);
  } catch {
    throw new UnauthorizedError('MCP JWKS URI is invalid.');
  }
  const loopback = uri.hostname === '127.0.0.1' || uri.hostname === '::1' || uri.hostname === 'localhost';
  if (uri.protocol !== 'https:' && !(uri.protocol === 'http:' && loopback)) {
    throw new UnauthorizedError('MCP JWKS URI must use HTTPS.');
  }
  if (uri.username || uri.password || uri.hash) throw new UnauthorizedError('MCP JWKS URI is invalid.');
  return uri.toString();
}

async function readBoundedResponse(response: JwksFetchResponse): Promise<string> {
  if (!response.body) throw new UnauthorizedError('MCP JWKS response is empty.');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > MCP_JWKS_MAX_BYTES) {
        await reader.cancel();
        throw new UnauthorizedError('MCP JWKS response is too large.');
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof UnauthorizedError) throw error;
    throw new UnauthorizedError('MCP JWKS is unavailable.');
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString('utf8');
}

function audienceMatches(value: unknown, expected: string): boolean {
  if (typeof value === 'string') return value === expected;
  return Array.isArray(value) && value.includes(expected);
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function stringArrayClaim(value: unknown): string[] {
  if (Array.isArray(value)) return uniqueStrings(value.filter((item): item is string => typeof item === 'string'));
  if (typeof value === 'string') return uniqueStrings(value.split(/[,\s]+/).filter(Boolean));
  return [];
}

function scopesClaim(value: unknown): ActionProxyScope[] | string[] {
  return stringArrayClaim(value);
}

function restrictScopes(requested: string[], allowed: string[]): string[] {
  const requestedUnique = uniqueStrings(requested);
  if (allowed.includes('*')) return requestedUnique;
  const allowedSet = new Set(allowed);
  return requestedUnique.filter((scope) => allowedSet.has(scope));
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

export function allScopes(): string[] {
  return [...ALL_SCOPES];
}
