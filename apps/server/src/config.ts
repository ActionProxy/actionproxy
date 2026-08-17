import fs from 'node:fs';
import path from 'node:path';
import { normalizeEmailPublicBaseUrl } from './integrations/email/public-base-url';

export type StorageMode = 'memory' | 'sqlite' | 'postgres';
export type AuthMode = 'api_key' | 'none' | 'oidc_jwt';
export type DeploymentMode = 'local' | 'self_hosted';
export type LocalExecutionMode = 'disabled' | 'mock';
export type EmailTransportMode = 'outbox' | 'smtp';

export interface TelemetryConfig {
  enabled: boolean;
  otlpEndpoint?: string;
  otlpHeaders: Record<string, string>;
  serviceName: string;
}

export interface QuickstartConfig {
  enabled: boolean;
  loopbackPublicationAttested?: boolean;
  originToken?: string;
  sessionId?: string;
  updateToken?: string;
}

export interface SlackUserMapping {
  displayName?: string;
  email?: string;
  groups?: string[];
  principalId: string;
  scopes?: string[];
}

export interface AppConfig {
  allowUnsafeLocalBind?: boolean;
  host: string;
  port: number;
  policyPath: string;
  dataDir: string;
  approverDirectoryPath?: string;
  logLevel: string;
  webDistPath?: string;
  deployment?: {
    mode: DeploymentMode;
  };
  auth?: {
    allowedCorsOrigins: string[];
    bootstrapAdminApiKey?: string;
    mode: AuthMode;
    oidc: {
      audience?: string;
      emailClaim: string;
      groupsClaim: string;
      issuer?: string;
      jwksJson?: string;
      jwksPath?: string;
      jwksUri?: string;
      nameClaim: string;
      scopesClaim: string;
    };
    rateLimit: {
      max: number;
      windowMs: number;
    };
    slackUserMap: Record<string, SlackUserMapping>;
    workspaceId: string;
  };
  executionGrants?: {
    secret: string;
    ttlSeconds: number;
  };
  telemetry?: TelemetryConfig;
  localExecution?: {
    mode: LocalExecutionMode;
  };
  quickstart?: QuickstartConfig;
  mcp?: {
    stdioDiscoveryEnabled: boolean;
    streamableHttp?: {
      allowedOrigins: string[];
      authorizationServer?: string;
      enabled: boolean;
      maxResponseBytes: number;
      requestTimeoutMs: number;
      resourceUrl?: string;
      sessionSecret?: string;
      sessionTtlMs: number;
    };
  };
  email?: {
    approvalRecipient?: string;
    from?: string;
    publicBaseUrl?: string;
    smtp?: {
      host?: string;
      password?: string;
      port?: number;
      secure?: boolean;
      username?: string;
    };
    transport?: EmailTransportMode;
  };
  storage?: {
    databaseUrl?: string;
    mode: StorageMode;
    sqlitePath: string;
  };
  slack?: {
    approvalChannelId?: string;
    botToken?: string;
    signingSecret?: string;
  };
  telegram?: {
    approvalChatId?: string;
    botToken?: string;
    publicBaseUrl?: string;
    webhookSecret?: string;
  };
}

export type AuthConfig = NonNullable<AppConfig['auth']>;
export type ExecutionGrantsConfig = NonNullable<AppConfig['executionGrants']>;
export type ResolvedAppConfig = AppConfig & {
  auth: AuthConfig;
  executionGrants: ExecutionGrantsConfig;
  mcp: NonNullable<AppConfig['mcp']> & {
    streamableHttp: NonNullable<
      NonNullable<AppConfig['mcp']>['streamableHttp']
    >;
  };
  telemetry: TelemetryConfig;
  quickstart: QuickstartConfig;
};

export function loadConfig(): AppConfig {
  const cwd = process.cwd();
  const repositoryRoot = findCommunityRepositoryRoot(cwd);
  const configRoot = repositoryRoot ?? cwd;
  if (!localEnvFilesDisabled()) loadLocalEnvFiles(configRoot, cwd);
  const dataDir = resolveDataDir(configRoot);
  const storageMode = parseStorageMode(productEnv('STORAGE'));
  const authMode = parseAuthMode(productEnv('AUTH_MODE'));
  const deploymentMode = parseDeploymentMode(
    productEnv('DEPLOYMENT_MODE'),
    authMode,
  );
  const publicBaseUrl = normalizeEmailPublicBaseUrl(
    productEnv('PUBLIC_BASE_URL'),
    {
      label: 'ACTIONPROXY_PUBLIC_BASE_URL',
      requireHttps: false,
    },
  );
  const emailPublicBaseUrl = normalizeEmailPublicBaseUrl(
    productEnv('EMAIL_PUBLIC_BASE_URL')?.trim() ||
      publicBaseUrl,
    {
      label: 'ACTIONPROXY_EMAIL_PUBLIC_BASE_URL or ACTIONPROXY_PUBLIC_BASE_URL',
      requireHttps: false,
    },
  );
  return {
    allowUnsafeLocalBind:
      parseBoolean(productEnv('ALLOW_UNSAFE_LOCAL_BIND')) ?? false,
    host: productEnv('HOST') ?? '127.0.0.1',
    port: Number(productEnv('PORT') ?? '8787'),
    policyPath: path.resolve(
      configRoot,
      productEnv('POLICY_PATH') ??
        (repositoryRoot
          ? 'apps/server/src/policies/default.policy.yaml'
          : 'src/policies/default.policy.yaml'),
    ),
    dataDir,
    approverDirectoryPath: path.resolve(
      configRoot,
      productEnv('APPROVER_DIRECTORY_PATH') ??
        path.join(dataDir, 'approver-directory.local.json'),
    ),
    logLevel: productEnv('LOG_LEVEL') ?? 'info',
    webDistPath: productEnv('WEB_DIST_PATH')
      ? path.resolve(configRoot, productEnv('WEB_DIST_PATH')!)
      : path.resolve(configRoot, 'apps/web/dist'),
    deployment: {
      mode: deploymentMode,
    },
    localExecution: {
      mode: parseLocalExecutionMode(productEnv('LOCAL_EXECUTION')),
    },
    quickstart: {
      enabled: parseBoolean(productEnv('QUICKSTART_MODE')) ?? false,
      loopbackPublicationAttested:
        parseBoolean(productEnv('QUICKSTART_LOOPBACK_PUBLISHED')) ?? false,
      originToken: productEnv('QUICKSTART_ORIGIN_TOKEN'),
      sessionId: productEnv('QUICKSTART_SESSION_ID'),
      updateToken: productEnv('QUICKSTART_UPDATE_TOKEN'),
    },
    mcp: {
      stdioDiscoveryEnabled:
        parseBoolean(productEnv('MCP_STDIO_DISCOVERY_ENABLED')) ?? false,
      streamableHttp: {
        allowedOrigins: splitCsv(productEnv('MCP_ALLOWED_ORIGINS')),
        authorizationServer: productEnv('MCP_AUTHORIZATION_SERVER'),
        enabled:
          parseBoolean(productEnv('MCP_STREAMABLE_HTTP_ENABLED')) ?? false,
        maxResponseBytes: numberEnv(
          productEnv('MCP_MAX_RESPONSE_BYTES'),
          256 * 1024,
        ),
        requestTimeoutMs: numberEnv(
          productEnv('MCP_REQUEST_TIMEOUT_MS'),
          30_000,
        ),
        resourceUrl: productEnv('MCP_RESOURCE_URL'),
        sessionSecret: productEnv('MCP_SESSION_SECRET'),
        sessionTtlMs: numberEnv(
          productEnv('MCP_SESSION_TTL_MS'),
          30 * 60 * 1000,
        ),
      },
    },
    auth: {
      allowedCorsOrigins: splitCsv(productEnv('CORS_ORIGINS')),
      bootstrapAdminApiKey: productEnv('BOOTSTRAP_ADMIN_API_KEY'),
      mode: authMode,
      oidc: {
        audience: productEnv('OIDC_AUDIENCE'),
        emailClaim: productEnv('OIDC_EMAIL_CLAIM') ?? 'email',
        groupsClaim: productEnv('OIDC_GROUPS_CLAIM') ?? 'groups',
        issuer: productEnv('OIDC_ISSUER'),
        jwksJson: productEnv('OIDC_JWKS_JSON'),
        jwksPath: productEnv('OIDC_JWKS_PATH')
          ? path.resolve(configRoot, productEnv('OIDC_JWKS_PATH')!)
          : undefined,
        jwksUri: productEnv('OIDC_JWKS_URI'),
        nameClaim: productEnv('OIDC_NAME_CLAIM') ?? 'name',
        scopesClaim: productEnv('OIDC_SCOPES_CLAIM') ?? 'scope',
      },
      rateLimit: {
        max: numberEnv(productEnv('RATE_LIMIT_MAX'), 600),
        windowMs: numberEnv(productEnv('RATE_LIMIT_WINDOW_MS'), 60_000),
      },
      slackUserMap: parseJsonEnv<Record<string, SlackUserMapping>>(
        productEnv('SLACK_USER_MAP_JSON'),
        {},
      ),
      workspaceId: productEnv('WORKSPACE_ID') ?? 'default',
    },
    executionGrants: {
      secret:
        productEnv('EXECUTION_GRANT_SECRET') ??
        'local-dev-execution-grant-secret',
      ttlSeconds: numberEnv(productEnv('EXECUTION_GRANT_TTL_SECONDS'), 300),
    },
    telemetry: {
      enabled: parseBoolean(productEnv('OTEL_ENABLED')) ?? false,
      otlpEndpoint:
        productEnv('OTEL_EXPORTER_OTLP_ENDPOINT')?.trim() || undefined,
      otlpHeaders: parseOtlpHeaders(productEnv('OTEL_EXPORTER_OTLP_HEADERS')),
      serviceName: productEnv('OTEL_SERVICE_NAME')?.trim() || 'actionproxy',
    },
    email: {
      approvalRecipient: productEnv('EMAIL_APPROVAL_RECIPIENT'),
      from: productEnv('EMAIL_FROM'),
      publicBaseUrl: emailPublicBaseUrl,
      smtp: {
        host: productEnv('EMAIL_SMTP_HOST'),
        password: productEnv('EMAIL_SMTP_PASSWORD'),
        port: numberEnv(productEnv('EMAIL_SMTP_PORT'), 0),
        secure: parseBoolean(productEnv('EMAIL_SMTP_SECURE')),
        username: productEnv('EMAIL_SMTP_USERNAME'),
      },
      transport: parseEmailTransport(productEnv('EMAIL_TRANSPORT')),
    },
    storage: {
      databaseUrl: process.env.DATABASE_URL,
      mode: storageMode,
      sqlitePath: path.resolve(
        configRoot,
        productEnv('SQLITE_PATH') ??
          path.join(
            dataDir,
            sqliteFilenameForDataDir(configRoot, dataDir),
          ),
      ),
    },
    slack: {
      approvalChannelId: process.env.SLACK_APPROVAL_CHANNEL_ID,
      botToken: process.env.SLACK_BOT_TOKEN,
      signingSecret: process.env.SLACK_SIGNING_SECRET,
    },
    telegram: {
      approvalChatId: process.env.TELEGRAM_APPROVAL_CHAT_ID,
      botToken: process.env.TELEGRAM_BOT_TOKEN,
      publicBaseUrl: normalizeEmailPublicBaseUrl(
        process.env.TELEGRAM_PUBLIC_BASE_URL?.trim() || publicBaseUrl,
        {
          label:
            'TELEGRAM_PUBLIC_BASE_URL or ACTIONPROXY_PUBLIC_BASE_URL',
          requireHttps: false,
        },
      ),
      webhookSecret: process.env.TELEGRAM_WEBHOOK_SECRET,
    },
  };
}

export function withConfigDefaults(config: AppConfig): ResolvedAppConfig {
  return {
    ...config,
    allowUnsafeLocalBind: config.allowUnsafeLocalBind ?? false,
    auth: config.auth ?? defaultAuthConfig(),
    deployment: config.deployment ?? {
      mode: (config.auth?.mode ?? 'none') === 'none' ? 'local' : 'self_hosted',
    },
    executionGrants: config.executionGrants ?? defaultExecutionGrantConfig(),
    mcp: {
      stdioDiscoveryEnabled: config.mcp?.stdioDiscoveryEnabled ?? false,
      streamableHttp:
        config.mcp?.streamableHttp ?? defaultMcpStreamableHttpConfig(config),
    },
    telemetry: config.telemetry ?? defaultTelemetryConfig(),
    quickstart: config.quickstart ?? { enabled: false },
  };
}

export interface StartupConfigValidationOptions {
  /** A composed edition supplies an MCP principal resolver and validates its own trust boundary. */
  injectedMcpAuthentication?: boolean;
}

export function assertSafeStartupConfig(
  config: AppConfig,
  options: StartupConfigValidationOptions = {},
): void {
  assertSafeMcpStreamableHttpConfig(config, options);
  assertSafeQuickstartConfig(config);
  if (
    !isUnauthenticatedWildcardBind(config) ||
    config.allowUnsafeLocalBind === true
  )
    return;

  throw new Error(unsafeLocalBindBlockedMessage(config.host));
}

function assertSafeQuickstartConfig(config: AppConfig): void {
  if (config.quickstart?.enabled !== true) return;

  const authMode = config.auth?.mode ?? 'none';
  const deploymentMode =
    config.deployment?.mode ?? (authMode === 'none' ? 'local' : 'self_hosted');
  const localExecutionMode = config.localExecution?.mode ?? 'disabled';

  if (deploymentMode !== 'local') {
    throw new Error(
      'ActionProxy Quickstart mode requires ACTIONPROXY_DEPLOYMENT_MODE=local.',
    );
  }
  if (authMode !== 'none') {
    throw new Error(
      'ActionProxy Quickstart mode requires ACTIONPROXY_AUTH_MODE=none.',
    );
  }
  if (localExecutionMode !== 'mock') {
    throw new Error(
      'ActionProxy Quickstart mode requires ACTIONPROXY_LOCAL_EXECUTION=mock.',
    );
  }
  if (!isQuickstartLocalBind(config)) {
    throw new Error(
      'ActionProxy Quickstart mode requires a loopback server bind, or the explicit launcher-attested Docker demo bind ACTIONPROXY_HOST=0.0.0.0 with ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND=true and ACTIONPROXY_QUICKSTART_LOOPBACK_PUBLISHED=true.',
    );
  }

  const sessionId = config.quickstart.sessionId;
  if (!sessionId || !isQuickstartSessionId(sessionId)) {
    throw new Error(
      'ActionProxy Quickstart mode requires ACTIONPROXY_QUICKSTART_SESSION_ID to be a canonical lowercase UUID v4.',
    );
  }

  const updateToken = config.quickstart.updateToken;
  if (
    !updateToken ||
    updateToken !== updateToken.trim() ||
    updateToken.length < 32 ||
    updateToken.length > 256 ||
    /[\s\u0000-\u001f\u007f]/u.test(updateToken)
  ) {
    throw new Error(
      'ActionProxy Quickstart mode requires a private 32-256 character ACTIONPROXY_QUICKSTART_UPDATE_TOKEN without whitespace or control characters.',
    );
  }

  const originToken = config.quickstart.originToken;
  if (
    !originToken ||
    originToken !== originToken.trim() ||
    originToken.length < 32 ||
    originToken.length > 256 ||
    /[\s\u0000-\u001f\u007f]/u.test(originToken)
  ) {
    throw new Error(
      'ActionProxy Quickstart mode requires a private 32-256 character ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN without whitespace or control characters.',
    );
  }
  if (originToken === updateToken) {
    throw new Error(
      'ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN must be distinct from ACTIONPROXY_QUICKSTART_UPDATE_TOKEN.',
    );
  }
}

function assertSafeMcpStreamableHttpConfig(
  config: AppConfig,
  options: StartupConfigValidationOptions,
): void {
  const mcp = config.mcp?.streamableHttp;
  if (!mcp?.enabled) return;

  const resource = absoluteOAuthUrl(
    mcp.resourceUrl,
    'ACTIONPROXY_MCP_RESOURCE_URL',
  );
  if (resource.search || resource.hash) {
    throw new Error(
      'ACTIONPROXY_MCP_RESOURCE_URL must not contain a query string or fragment.',
    );
  }
  if (resource.pathname !== '/mcp') {
    throw new Error(
      'ACTIONPROXY_MCP_RESOURCE_URL must identify the exact standard /mcp endpoint without a trailing slash.',
    );
  }
  if (!options.injectedMcpAuthentication) {
    const authorizationServerValue =
      mcp.authorizationServer ?? config.auth?.oidc.issuer;
    const authorizationServer = absoluteOAuthUrl(
      authorizationServerValue,
      'ACTIONPROXY_MCP_AUTHORIZATION_SERVER',
    );
    if (authorizationServer.search || authorizationServer.hash) {
      throw new Error(
        'ACTIONPROXY_MCP_AUTHORIZATION_SERVER must not contain a query string or fragment.',
      );
    }
    if (config.auth?.mode !== 'oidc_jwt') {
      throw new Error(
        'MCP Streamable HTTP requires ACTIONPROXY_AUTH_MODE=oidc_jwt so ordinary ActionProxy API routes do not use local or API-key-only authentication.',
      );
    }
    if (!config.auth.oidc.audience) {
      throw new Error(
        'MCP Streamable HTTP requires ACTIONPROXY_OIDC_AUDIENCE for audience validation on ordinary ActionProxy API routes.',
      );
    }
    if (
      !config.auth?.oidc.issuer ||
      config.auth.oidc.issuer !== authorizationServerValue
    ) {
      throw new Error(
        'MCP Streamable HTTP requires ACTIONPROXY_OIDC_ISSUER to match its authorization server.',
      );
    }
    if (
      !config.auth.oidc.jwksJson &&
      !config.auth.oidc.jwksPath &&
      !config.auth.oidc.jwksUri
    ) {
      throw new Error(
        'MCP Streamable HTTP requires OIDC JWKS JSON, path, or URI for bearer validation.',
      );
    }
  }
  if (!mcp.sessionSecret || Buffer.byteLength(mcp.sessionSecret, 'utf8') < 32) {
    throw new Error(
      'ACTIONPROXY_MCP_SESSION_SECRET must contain at least 32 UTF-8 bytes.',
    );
  }
  if (!Number.isFinite(mcp.sessionTtlMs) || mcp.sessionTtlMs <= 0) {
    throw new Error(
      'ACTIONPROXY_MCP_SESSION_TTL_MS must be a positive number.',
    );
  }
  if (!Number.isFinite(mcp.requestTimeoutMs) || mcp.requestTimeoutMs <= 0) {
    throw new Error(
      'ACTIONPROXY_MCP_REQUEST_TIMEOUT_MS must be a positive number.',
    );
  }
  if (!Number.isFinite(mcp.maxResponseBytes) || mcp.maxResponseBytes < 1024) {
    throw new Error(
      'ACTIONPROXY_MCP_MAX_RESPONSE_BYTES must be at least 1024 bytes.',
    );
  }
}

function absoluteOAuthUrl(
  value: string | undefined,
  environmentName: string,
): URL {
  if (!value)
    throw new Error(
      `${environmentName} is required when MCP Streamable HTTP is enabled.`,
    );
  if (value !== value.trim())
    throw new Error(
      `${environmentName} must not contain surrounding whitespace.`,
    );
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${environmentName} must be an absolute URL.`);
  }
  const loopback =
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '::1' ||
    parsed.hostname === 'localhost';
  if (
    parsed.protocol !== 'https:' &&
    !(parsed.protocol === 'http:' && loopback)
  ) {
    throw new Error(
      `${environmentName} must use HTTPS except for explicit loopback development.`,
    );
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${environmentName} must not contain URL credentials.`);
  }
  return parsed;
}

export function unsafeLocalBindWarning(config: AppConfig): string | undefined {
  if (
    !isUnauthenticatedWildcardBind(config) ||
    config.allowUnsafeLocalBind !== true
  )
    return undefined;

  return `Unsafe local bind opt-in active: ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND=true with ACTIONPROXY_AUTH_MODE=none and ACTIONPROXY_HOST=${config.host} exposes the local-admin demo gateway on all container/server interfaces. Only use this with a localhost-only host binding such as Docker '-p 127.0.0.1:8787:8787'.`;
}

function productEnv(name: string): string | undefined {
  return process.env[`ACTIONPROXY_${name}`];
}

function resolveDataDir(cwd: string): string {
  const explicit = productEnv('DATA_DIR');
  if (explicit) return path.resolve(cwd, explicit);

  return path.resolve(cwd, '.actionproxy');
}

function sqliteFilenameForDataDir(_cwd: string, _dataDir: string): string {
  return 'actionproxy.sqlite';
}

function parseStorageMode(value: string | undefined): StorageMode {
  if (value === 'sqlite' || value === 'postgres' || value === 'memory')
    return value;
  return 'memory';
}

function parseAuthMode(value: string | undefined): AuthMode {
  if (value === 'api_key' || value === 'oidc_jwt' || value === 'none')
    return value;
  return 'none';
}

function isUnauthenticatedWildcardBind(config: AppConfig): boolean {
  return (
    (config.auth?.mode ?? 'none') === 'none' && isWildcardBindHost(config.host)
  );
}

function isWildcardBindHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return (
    normalized === '0.0.0.0' || normalized === '::' || normalized === '[::]'
  );
}

function isQuickstartLocalBind(config: AppConfig): boolean {
  const normalized = config.host.trim().toLowerCase();
  const loopback =
    normalized === '127.0.0.1' ||
    normalized === '::1' ||
    normalized === '[::1]' ||
    normalized === 'localhost';
  return (
    loopback ||
    (normalized === '0.0.0.0' &&
      config.allowUnsafeLocalBind === true &&
      config.quickstart?.loopbackPublicationAttested === true)
  );
}

function isQuickstartSessionId(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
    value,
  );
}

function unsafeLocalBindBlockedMessage(host: string): string {
  return `Unsafe ActionProxy startup blocked: ACTIONPROXY_AUTH_MODE=none with ACTIONPROXY_HOST=${host} would expose the implicit local-admin demo gateway on all network interfaces. Use ACTIONPROXY_HOST=127.0.0.1 for local demos, set ACTIONPROXY_AUTH_MODE=api_key or oidc_jwt for networked use, or set ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND=true only for an intentionally localhost-published Docker/demo run.`;
}

function parseDeploymentMode(
  value: string | undefined,
  authMode: AuthMode,
): DeploymentMode {
  if (value === 'local' || value === 'self_hosted')
    return value;
  return authMode === 'none' ? 'local' : 'self_hosted';
}

function parseLocalExecutionMode(
  value: string | undefined,
): LocalExecutionMode {
  if (value === 'mock' || value === 'disabled') return value;
  return 'disabled';
}

function parseEmailTransport(
  value: string | undefined,
): EmailTransportMode | undefined {
  if (value === 'smtp' || value === 'outbox')
    return value;
  return undefined;
}

function defaultAuthConfig(): AuthConfig {
  return {
    allowedCorsOrigins: [],
    mode: 'none',
    oidc: {
      emailClaim: 'email',
      groupsClaim: 'groups',
      nameClaim: 'name',
      scopesClaim: 'scope',
    },
    rateLimit: {
      max: 600,
      windowMs: 60_000,
    },
    slackUserMap: {},
    workspaceId: 'default',
  };
}

function defaultExecutionGrantConfig(): ExecutionGrantsConfig {
  return {
    secret: 'local-dev-execution-grant-secret',
    ttlSeconds: 300,
  };
}

function defaultMcpStreamableHttpConfig(
  config: AppConfig,
): NonNullable<NonNullable<AppConfig['mcp']>['streamableHttp']> {
  return {
    allowedOrigins: [],
    authorizationServer: config.auth?.oidc.issuer,
    enabled: false,
    maxResponseBytes: 256 * 1024,
    requestTimeoutMs: 30_000,
    sessionTtlMs: 30 * 60 * 1000,
  };
}

function defaultTelemetryConfig(): TelemetryConfig {
  return {
    enabled: false,
    otlpHeaders: {},
    serviceName: 'actionproxy',
  };
}

function splitCsv(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function numberEnv(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBoolean(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  return undefined;
}

function parseJsonEnv<T>(value: string | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function parseOtlpHeaders(value: string | undefined): Record<string, string> {
  if (!value?.trim()) return {};
  const parsed = parseJsonEnv<unknown>(value, undefined);
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    return Object.fromEntries(
      Object.entries(parsed as Record<string, unknown>)
        .filter(
          (entry): entry is [string, string] =>
            typeof entry[1] === 'string' && entry[0].trim().length > 0,
        )
        .map(([key, headerValue]) => [key.trim(), headerValue.trim()]),
    );
  }
  return Object.fromEntries(
    value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry): [string, string] => {
        const separator = entry.indexOf('=');
        return separator >= 0
          ? [
              entry.slice(0, separator).trim(),
              entry.slice(separator + 1).trim(),
            ]
          : [entry, ''];
      })
      .filter(([key]) => key.length > 0),
  );
}

function findCommunityRepositoryRoot(cwd: string): string | undefined {
  let candidate = path.resolve(cwd);
  for (;;) {
    if (
      fs.existsSync(path.join(candidate, 'pnpm-workspace.yaml')) &&
      fs.existsSync(path.join(candidate, 'apps', 'server', 'package.json'))
    ) {
      return candidate;
    }
    const parent = path.dirname(candidate);
    if (parent === candidate) return undefined;
    candidate = parent;
  }
}

function loadLocalEnvFiles(configRoot: string, cwd: string): void {
  const roots = [configRoot, ...(cwd === configRoot ? [] : [cwd])];
  for (const filename of ['.env.local', '.env']) {
    for (const root of roots) loadLocalEnvFile(path.join(root, filename));
  }
}

function localEnvFilesDisabled(): boolean {
  return /^(?:1|true|yes|on)$/iu.test(
    process.env.ACTIONPROXY_DISABLE_LOCAL_ENV_FILES?.trim() ?? '',
  );
}

function loadLocalEnvFile(envPath: string): void {
  if (!fs.existsSync(envPath)) return;
  const body = fs.readFileSync(envPath, 'utf8');
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) continue;

    const [, key, rawValue] = match;
    if (!key || process.env[key] !== undefined) continue;
    process.env[key] = parseDotEnvValue(rawValue ?? '');
  }
}

function parseDotEnvValue(rawValue: string): string {
  const value = rawValue.trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    const unquoted = value.slice(1, -1);
    return value.startsWith('"')
      ? unquoted
          .replace(/\\n/g, '\n')
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, '\\')
      : unquoted;
  }
  const commentIndex = value.indexOf(' #');
  return commentIndex >= 0 ? value.slice(0, commentIndex).trim() : value;
}
