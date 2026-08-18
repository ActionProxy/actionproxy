import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { assertSafeStartupConfig, loadConfig, unsafeLocalBindWarning, withConfigDefaults } from './config';

const originalCwd = process.cwd();
const originalEnv = { ...process.env };

describe('ActionProxy config', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-config-test-')));
    process.chdir(tempDir);
    resetEnvForTest();
  });

  afterEach(() => {
    process.chdir(originalCwd);
    restoreEnv();
  });

  it('reads new ACTIONPROXY environment variables', () => {
    process.env.ACTIONPROXY_HOST = '0.0.0.0';
    process.env.ACTIONPROXY_PORT = '9876';
    process.env.ACTIONPROXY_DATA_DIR = '.custom-actionproxy';
    process.env.ACTIONPROXY_STORAGE = 'sqlite';
    process.env.ACTIONPROXY_SQLITE_PATH = '.custom-actionproxy/custom.sqlite';
    process.env.ACTIONPROXY_QUICKSTART_MODE = 'true';
    process.env.ACTIONPROXY_QUICKSTART_LOOPBACK_PUBLISHED = 'true';
    process.env.ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN = 'o'.repeat(32);
    process.env.ACTIONPROXY_QUICKSTART_SESSION_ID = '550e8400-e29b-41d4-a716-446655440000';
    process.env.ACTIONPROXY_QUICKSTART_UPDATE_TOKEN = 'q'.repeat(32);

    const config = loadConfig();

    expect(config.host).toBe('0.0.0.0');
    expect(config.port).toBe(9876);
    expect(config.dataDir).toBe(path.join(tempDir, '.custom-actionproxy'));
    expect(config.storage?.mode).toBe('sqlite');
    expect(config.storage?.sqlitePath).toBe(path.join(tempDir, '.custom-actionproxy/custom.sqlite'));
    expect(config.quickstart).toEqual({
      enabled: true,
      loopbackPublicationAttested: true,
      originToken: 'o'.repeat(32),
      sessionId: '550e8400-e29b-41d4-a716-446655440000',
      updateToken: 'q'.repeat(32),
    });
  });

  it('loads root environment files and resolves their paths from the repository root', () => {
    const serverCwd = path.join(tempDir, 'apps', 'server');
    fs.mkdirSync(serverCwd, { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
    fs.writeFileSync(path.join(serverCwd, 'package.json'), '{"name":"@actionproxy/server"}\n');
    fs.writeFileSync(
      path.join(tempDir, '.env'),
      [
        'ACTIONPROXY_PORT=9010',
        'ACTIONPROXY_POLICY_PATH=apps/server/src/policies/default.policy.yaml',
        'ACTIONPROXY_DATA_DIR=.actionproxy-root',
        'ACTIONPROXY_APPROVER_DIRECTORY_PATH=.actionproxy-root/approvers.json',
        'ACTIONPROXY_WEB_DIST_PATH=apps/web/dist',
        'ACTIONPROXY_SQLITE_PATH=.actionproxy-root/actionproxy.sqlite',
      ].join('\n'),
    );
    fs.writeFileSync(path.join(tempDir, '.env.local'), 'ACTIONPROXY_PORT=9011\n');
    process.chdir(serverCwd);

    const config = loadConfig();

    expect(config.port).toBe(9011);
    expect(config.policyPath).toBe(path.join(tempDir, 'apps/server/src/policies/default.policy.yaml'));
    expect(config.dataDir).toBe(path.join(tempDir, '.actionproxy-root'));
    expect(config.approverDirectoryPath).toBe(path.join(tempDir, '.actionproxy-root/approvers.json'));
    expect(config.webDistPath).toBe(path.join(tempDir, 'apps/web/dist'));
    expect(config.storage?.sqlitePath).toBe(path.join(tempDir, '.actionproxy-root/actionproxy.sqlite'));
  });

  it('can disable repository env files before any values are ingested', () => {
    const serverCwd = path.join(tempDir, 'apps', 'server');
    fs.mkdirSync(serverCwd, { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
    fs.writeFileSync(path.join(serverCwd, 'package.json'), '{"name":"@actionproxy/server"}\n');
    fs.writeFileSync(
      path.join(tempDir, '.env.local'),
      [
        'ACTIONPROXY_PORT=9011',
        'ACTIONPROXY_STORAGE=postgres',
        'ACTIONPROXY_OTEL_ENABLED=true',
        'ACTIONPROXY_EMAIL_TRANSPORT=smtp',
        'ACTIONPROXY_EMAIL_SMTP_PASSWORD=env-file-canary',
        'GOOGLE_OAUTH_CLIENT_SECRET=env-file-canary',
        'DATABASE_URL=postgres://env-file-canary',
        'SLACK_BOT_TOKEN=env-file-canary',
        'TELEGRAM_BOT_TOKEN=env-file-canary',
      ].join('\n'),
    );
    process.env.ACTIONPROXY_DISABLE_LOCAL_ENV_FILES = 'true';
    process.env.ACTIONPROXY_EMAIL_TRANSPORT = 'outbox';
    process.chdir(serverCwd);

    const config = loadConfig();

    expect(config.port).toBe(8787);
    expect(config.storage?.mode).toBe('memory');
    expect(config.telemetry?.enabled).toBe(false);
    expect(config.email?.transport).toBe('outbox');
    for (const name of [
      'ACTIONPROXY_EMAIL_SMTP_PASSWORD',
      'GOOGLE_OAUTH_CLIENT_SECRET',
      'DATABASE_URL',
      'SLACK_BOT_TOKEN',
      'TELEGRAM_BOT_TOKEN',
    ]) {
      expect(process.env[name]).toBeUndefined();
    }
  });

  it('resolves the default policy from the repository root under filtered package execution', () => {
    const serverCwd = path.join(tempDir, 'apps', 'server');
    fs.mkdirSync(serverCwd, { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
    fs.writeFileSync(path.join(serverCwd, 'package.json'), '{"name":"@actionproxy/server"}\n');
    process.chdir(serverCwd);

    expect(loadConfig().policyPath).toBe(
      path.join(tempDir, 'apps/server/src/policies/default.policy.yaml'),
    );
  });

  it('keeps explicit process environment above root environment files', () => {
    const serverCwd = path.join(tempDir, 'apps', 'server');
    fs.mkdirSync(serverCwd, { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n');
    fs.writeFileSync(path.join(serverCwd, 'package.json'), '{"name":"@actionproxy/server"}\n');
    fs.writeFileSync(path.join(tempDir, '.env.local'), 'ACTIONPROXY_PORT=9011\n');
    process.env.ACTIONPROXY_PORT = '9012';
    process.chdir(serverCwd);

    expect(loadConfig().port).toBe(9012);
  });

  it('defaults omitted auth and deployment config to the local posture', () => {
    const resolved = withConfigDefaults({
      dataDir: tempDir,
      host: '127.0.0.1',
      logLevel: 'silent',
      policyPath: path.join(tempDir, 'policy.yaml'),
      port: 0,
    });

    expect(resolved.auth.mode).toBe('none');
    expect(resolved.deployment?.mode).toBe('local');
  });

  it('defaults new installs to .actionproxy storage', () => {
    const config = loadConfig();

    expect(config.dataDir).toBe(path.join(tempDir, '.actionproxy'));
    expect(config.storage?.sqlitePath).toBe(path.join(tempDir, '.actionproxy/actionproxy.sqlite'));
  });

  it('uses the global product URL for email and lets the compatibility override take precedence', () => {
    process.env.ACTIONPROXY_PUBLIC_BASE_URL = 'https://console.example.com/actionproxy///';
    process.env.ACTIONPROXY_EMAIL_PUBLIC_BASE_URL = '';

    expect(loadConfig().email?.publicBaseUrl).toBe(
      'https://console.example.com/actionproxy',
    );

    process.env.ACTIONPROXY_EMAIL_PUBLIC_BASE_URL =
      'https://approvals.example.com/review/';

    expect(loadConfig().email?.publicBaseUrl).toBe(
      'https://approvals.example.com/review',
    );
  });

  it('uses the configured product origin for Telegram links and lets its override take precedence', () => {
    process.env.ACTIONPROXY_PUBLIC_BASE_URL =
      'http://127.0.0.1:9417/actionproxy///';

    expect(loadConfig().telegram?.publicBaseUrl).toBe(
      'http://127.0.0.1:9417/actionproxy',
    );

    process.env.TELEGRAM_PUBLIC_BASE_URL =
      'https://telegram-console.example/review/';

    expect(loadConfig().telegram?.publicBaseUrl).toBe(
      'https://telegram-console.example/review',
    );
  });

  it('rejects invalid email review URLs', () => {
    process.env.ACTIONPROXY_PUBLIC_BASE_URL = 'https://console.example.com?workspace=demo';
    expect(() => loadConfig()).toThrow('must not contain a query string or fragment');
  });

  it('keeps unauthenticated local demo defaults on loopback', () => {
    const config = withConfigDefaults(loadConfig());

    expect(config.host).toBe('127.0.0.1');
    expect(config.auth.mode).toBe('none');
    expect(config.allowUnsafeLocalBind).toBe(false);
    expect(config.mcp.stdioDiscoveryEnabled).toBe(false);
    expect(() => assertSafeStartupConfig(config)).not.toThrow();
    expect(unsafeLocalBindWarning(config)).toBeUndefined();
  });

  it('enables server-side MCP stdio discovery only through an explicit opt-in', () => {
    expect(withConfigDefaults(loadConfig()).mcp.stdioDiscoveryEnabled).toBe(false);

    process.env.ACTIONPROXY_MCP_STDIO_DISCOVERY_ENABLED = 'true';

    expect(withConfigDefaults(loadConfig()).mcp.stdioDiscoveryEnabled).toBe(true);
  });

  it('keeps Streamable HTTP MCP disabled by default and reads its explicit resource-server settings', () => {
    expect(withConfigDefaults(loadConfig()).mcp.streamableHttp.enabled).toBe(false);

    process.env.ACTIONPROXY_MCP_STREAMABLE_HTTP_ENABLED = 'true';
    process.env.ACTIONPROXY_MCP_RESOURCE_URL = 'https://proxy.example/mcp';
    process.env.ACTIONPROXY_MCP_AUTHORIZATION_SERVER = 'https://issuer.example';
    process.env.ACTIONPROXY_MCP_ALLOWED_ORIGINS = 'https://chatgpt.com,https://inspector.example';
    process.env.ACTIONPROXY_MCP_SESSION_SECRET = 'test-mcp-session-secret-with-at-least-32-bytes';
    process.env.ACTIONPROXY_MCP_SESSION_TTL_MS = '900000';
    process.env.ACTIONPROXY_MCP_REQUEST_TIMEOUT_MS = '15000';
    process.env.ACTIONPROXY_MCP_MAX_RESPONSE_BYTES = '131072';
    process.env.ACTIONPROXY_AUTH_MODE = 'oidc_jwt';
    process.env.ACTIONPROXY_OIDC_ISSUER = 'https://issuer.example';
    process.env.ACTIONPROXY_OIDC_AUDIENCE = 'https://proxy.example/api';
    process.env.ACTIONPROXY_OIDC_JWKS_URI = 'https://issuer.example/.well-known/jwks.json';

    const config = withConfigDefaults(loadConfig());
    expect(config.mcp.streamableHttp).toMatchObject({
      allowedOrigins: ['https://chatgpt.com', 'https://inspector.example'],
      authorizationServer: 'https://issuer.example',
      enabled: true,
      maxResponseBytes: 131072,
      requestTimeoutMs: 15000,
      resourceUrl: 'https://proxy.example/mcp',
      sessionTtlMs: 900000,
    });
    expect(config.auth.oidc.jwksUri).toBe('https://issuer.example/.well-known/jwks.json');
    expect(() => assertSafeStartupConfig(config)).not.toThrow();

    expect(() => assertSafeStartupConfig({
      ...config,
      auth: {
        ...config.auth,
        oidc: { ...config.auth.oidc, issuer: 'https://issuer.example/' },
      },
      mcp: {
        ...config.mcp,
        streamableHttp: {
          ...config.mcp.streamableHttp,
          authorizationServer: 'https://issuer.example/',
        },
      },
    })).not.toThrow();
  });

  it('fails closed when Streamable HTTP MCP lacks OAuth, audience, HTTPS, JWKS, or session state', () => {
    const base = withConfigDefaults(loadConfig());
    const enabled = {
      ...base,
      mcp: {
        ...base.mcp,
        streamableHttp: {
          ...base.mcp.streamableHttp,
          enabled: true,
        },
      },
    };
    expect(() => assertSafeStartupConfig(enabled)).toThrow('ACTIONPROXY_MCP_RESOURCE_URL is required');

    const resourceOnly = {
      ...enabled,
      mcp: {
        ...enabled.mcp,
        streamableHttp: {
          ...enabled.mcp.streamableHttp,
          resourceUrl: 'http://public.example/mcp',
        },
      },
    };
    expect(() => assertSafeStartupConfig(resourceOnly)).toThrow('must use HTTPS');

    const issuerMissing = {
      ...resourceOnly,
      auth: {
        ...resourceOnly.auth,
        mode: 'oidc_jwt' as const,
        oidc: { ...resourceOnly.auth.oidc, audience: 'https://proxy.example/api' },
      },
      mcp: {
        ...resourceOnly.mcp,
        streamableHttp: {
          ...resourceOnly.mcp.streamableHttp,
          authorizationServer: 'https://issuer.example',
          resourceUrl: 'https://proxy.example/mcp',
        },
      },
    };
    expect(() => assertSafeStartupConfig(issuerMissing)).toThrow('ACTIONPROXY_OIDC_ISSUER');

    const jwksMissing = {
      ...issuerMissing,
      auth: {
        ...issuerMissing.auth,
        oidc: { ...issuerMissing.auth.oidc, issuer: 'https://issuer.example' },
      },
    };
    expect(() => assertSafeStartupConfig(jwksMissing)).toThrow('requires OIDC JWKS');

    const secretMissing = {
      ...jwksMissing,
      auth: {
        ...jwksMissing.auth,
        oidc: { ...jwksMissing.auth.oidc, jwksJson: '{"keys":[]}' },
      },
    };
    expect(() => assertSafeStartupConfig(secretMissing)).toThrow('MCP_SESSION_SECRET');

    expect(() => assertSafeStartupConfig({
      ...secretMissing,
      auth: { ...secretMissing.auth, mode: 'none' },
    })).toThrow('ACTIONPROXY_AUTH_MODE=oidc_jwt');

    expect(() => assertSafeStartupConfig({
      ...secretMissing,
      auth: {
        ...secretMissing.auth,
        oidc: { ...secretMissing.auth.oidc, audience: undefined },
      },
    })).toThrow('ACTIONPROXY_OIDC_AUDIENCE');

    expect(() => assertSafeStartupConfig({
      ...secretMissing,
      mcp: {
        ...secretMissing.mcp,
        streamableHttp: {
          ...secretMissing.mcp.streamableHttp,
          resourceUrl: 'https://proxy.example/mcp/',
          sessionSecret: 'test-mcp-session-secret-with-at-least-32-bytes',
        },
      },
    })).toThrow('exact standard /mcp endpoint without a trailing slash');

    expect(() => assertSafeStartupConfig({
      ...secretMissing,
      auth: {
        ...secretMissing.auth,
        oidc: { ...secretMissing.auth.oidc, issuer: 'https://issuer.example?tenant=forged' },
      },
      mcp: {
        ...secretMissing.mcp,
        streamableHttp: {
          ...secretMissing.mcp.streamableHttp,
          authorizationServer: 'https://issuer.example?tenant=forged',
          sessionSecret: 'test-mcp-session-secret-with-at-least-32-bytes',
        },
      },
    })).toThrow('must not contain a query string or fragment');
  });

  it('keeps resource and signed-session bounds when an edition injects MCP authentication', () => {
    const base = withConfigDefaults(loadConfig());
    const injected = {
      ...base,
      auth: { ...base.auth, mode: 'none' as const },
      mcp: {
        ...base.mcp,
        streamableHttp: {
          ...base.mcp.streamableHttp,
          enabled: true,
          resourceUrl: 'http://127.0.0.1:8787/mcp',
          sessionSecret: ['single-user-tunnel-session', 'secret-32-bytes'].join('-'),
        },
      },
    };

    expect(() =>
      assertSafeStartupConfig(injected, { injectedMcpAuthentication: true }),
    ).not.toThrow();
    expect(() => assertSafeStartupConfig(injected)).toThrow(
      'ACTIONPROXY_MCP_AUTHORIZATION_SERVER is required',
    );
    expect(() =>
      assertSafeStartupConfig(
        {
          ...injected,
          mcp: {
            ...injected.mcp,
            streamableHttp: {
              ...injected.mcp.streamableHttp,
              resourceUrl: 'http://127.0.0.1:8787/mcp/',
            },
          },
        },
        { injectedMcpAuthentication: true },
      ),
    ).toThrow('exact standard /mcp endpoint without a trailing slash');
    expect(() =>
      assertSafeStartupConfig(
        {
          ...injected,
          mcp: {
            ...injected.mcp,
            streamableHttp: {
              ...injected.mcp.streamableHttp,
              sessionSecret: 'too-short',
            },
          },
        },
        { injectedMcpAuthentication: true },
      ),
    ).toThrow('MCP_SESSION_SECRET');
  });

  it('blocks unauthenticated startup on 0.0.0.0 by default', () => {
    process.env.ACTIONPROXY_HOST = '0.0.0.0';
    process.env.ACTIONPROXY_AUTH_MODE = 'none';

    const config = withConfigDefaults(loadConfig());

    expect(() => assertSafeStartupConfig(config)).toThrow(
      /Unsafe ActionProxy startup blocked: ACTIONPROXY_AUTH_MODE=none with ACTIONPROXY_HOST=0\.0\.0\.0/,
    );
  });

  it('allows unauthenticated 0.0.0.0 only with explicit unsafe opt-in and warning', () => {
    process.env.ACTIONPROXY_HOST = '0.0.0.0';
    process.env.ACTIONPROXY_AUTH_MODE = 'none';
    process.env.ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND = 'true';

    const config = withConfigDefaults(loadConfig());

    expect(config.allowUnsafeLocalBind).toBe(true);
    expect(() => assertSafeStartupConfig(config)).not.toThrow();
    expect(unsafeLocalBindWarning(config)).toContain('ACTIONPROXY_ALLOW_UNSAFE_LOCAL_BIND');
    expect(unsafeLocalBindWarning(config)).toContain("-p 127.0.0.1:8787:8787");
  });

  it('allows authenticated wildcard binds without unsafe local opt-in', () => {
    process.env.ACTIONPROXY_HOST = '0.0.0.0';
    process.env.ACTIONPROXY_AUTH_MODE = 'api_key';

    const config = withConfigDefaults(loadConfig());

    expect(config.auth.mode).toBe('api_key');
    expect(config.allowUnsafeLocalBind).toBe(false);
    expect(() => assertSafeStartupConfig(config)).not.toThrow();
    expect(unsafeLocalBindWarning(config)).toBeUndefined();
  });

  it('keeps Quickstart routes disabled unless explicitly enabled', () => {
    const config = withConfigDefaults(loadConfig());

    expect(config.quickstart).toEqual({
      enabled: false,
      loopbackPublicationAttested: false,
      originToken: undefined,
      sessionId: undefined,
      updateToken: undefined,
    });
    expect(() => assertSafeStartupConfig(config)).not.toThrow();
  });

  it('accepts Quickstart only in the local unauthenticated mock posture', () => {
    const base = withConfigDefaults(loadConfig());
    const quickstart = {
      ...base,
      localExecution: { mode: 'mock' as const },
      quickstart: {
        enabled: true,
        originToken: 'o'.repeat(32),
        sessionId: '550e8400-e29b-41d4-a716-446655440000',
        updateToken: 'q'.repeat(32),
      },
    };

    expect(() => assertSafeStartupConfig(quickstart)).not.toThrow();
    expect(() =>
      assertSafeStartupConfig({
        ...quickstart,
        allowUnsafeLocalBind: true,
        host: '0.0.0.0',
        quickstart: {
          ...quickstart.quickstart,
          loopbackPublicationAttested: true,
        },
      }),
    ).not.toThrow();
    expect(() =>
      assertSafeStartupConfig({
        ...quickstart,
        allowUnsafeLocalBind: true,
        host: '0.0.0.0',
      }),
    ).toThrow('ACTIONPROXY_QUICKSTART_LOOPBACK_PUBLISHED=true');

    expect(() =>
      assertSafeStartupConfig({
        ...quickstart,
        deployment: { mode: 'self_hosted' },
      }),
    ).toThrow('ACTIONPROXY_DEPLOYMENT_MODE=local');
    expect(() =>
      assertSafeStartupConfig({
        ...quickstart,
        auth: { ...quickstart.auth, mode: 'api_key' },
      }),
    ).toThrow('ACTIONPROXY_AUTH_MODE=none');
    expect(() =>
      assertSafeStartupConfig({
        ...quickstart,
        localExecution: { mode: 'disabled' },
      }),
    ).toThrow('ACTIONPROXY_LOCAL_EXECUTION=mock');
    expect(() =>
      assertSafeStartupConfig({ ...quickstart, host: '192.0.2.10' }),
    ).toThrow('loopback server bind');
    expect(() =>
      assertSafeStartupConfig({
        ...quickstart,
        allowUnsafeLocalBind: true,
        host: '::',
      }),
    ).toThrow('loopback server bind');
  });

  it('requires bounded Quickstart session credentials', () => {
    const base = withConfigDefaults(loadConfig());
    const quickstart = {
      ...base,
      localExecution: { mode: 'mock' as const },
      quickstart: {
        enabled: true,
        originToken: 'short',
        sessionId: 'short',
        updateToken: 'short',
      },
    };

    expect(() => assertSafeStartupConfig(quickstart)).toThrow(
      'ACTIONPROXY_QUICKSTART_SESSION_ID',
    );
    expect(() =>
      assertSafeStartupConfig({
        ...quickstart,
        quickstart: {
          ...quickstart.quickstart,
          sessionId: '550e8400-e29b-41d4-a716-446655440000',
        },
      }),
    ).toThrow('ACTIONPROXY_QUICKSTART_UPDATE_TOKEN');
    expect(() =>
      assertSafeStartupConfig({
        ...quickstart,
        quickstart: {
          ...quickstart.quickstart,
          originToken: 'short',
          sessionId: '550e8400-e29b-41d4-a716-446655440000',
          updateToken: 'q'.repeat(32),
        },
      }),
    ).toThrow('ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN');
    expect(() =>
      assertSafeStartupConfig({
        ...quickstart,
        quickstart: {
          ...quickstart.quickstart,
          originToken: 'q'.repeat(32),
          sessionId: '550e8400-e29b-41d4-a716-446655440000',
          updateToken: 'q'.repeat(32),
        },
      }),
    ).toThrow('must be distinct');
  });
});

function resetEnvForTest() {
  for (const key of Object.keys(process.env)) {
    delete process.env[key];
  }
  for (const [key, value] of Object.entries(originalEnv)) {
    if (key.startsWith('ACTIONPROXY_')) continue;
    if (key === 'DATABASE_URL') continue;
    process.env[key] = value;
  }
}

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    delete process.env[key];
  }
  for (const [key, value] of Object.entries(originalEnv)) {
    process.env[key] = value;
  }
}
