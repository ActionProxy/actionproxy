import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { buildApp } from './app';
import type { AppConfig } from './config';

let app: FastifyInstance | undefined;

const policyPath = path.resolve('src/policies/default.policy.yaml');

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('app startup safety', () => {
  it('refuses unauthenticated wildcard binds by default', async () => {
    await expect(buildApp(startupConfig())).rejects.toThrow(
      /Unsafe ActionProxy startup blocked: ACTIONPROXY_AUTH_MODE=none with ACTIONPROXY_HOST=0\.0\.0\.0/,
    );
  });

  it('starts unauthenticated wildcard binds only with explicit unsafe opt-in', async () => {
    app = await buildApp(startupConfig({ allowUnsafeLocalBind: true }));

    const response = await app.inject({ method: 'GET', url: '/health' });
    expect(response.statusCode).toBe(200);
  });

});

function startupConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  return {
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-startup-test-')),
    host: '0.0.0.0',
    localExecution: { mode: 'mock' },
    logLevel: 'silent',
    policyPath,
    port: 0,
    ...overrides,
  };
}
