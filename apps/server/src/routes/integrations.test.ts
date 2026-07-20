import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../config';
import { IntegrationConfigService } from '../integrations/integration-config';
import type { SlackFetch } from '../integrations/slack/slack-service';
import type { TelegramFetch } from '../integrations/telegram/telegram-service';
import { JsonlAuditStore } from '../storage/jsonl-audit-store';
import { registerIntegrationRoutes } from './integrations';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('Community integration routes', () => {
  it('returns the fixed Community approval-channel, MCP, and local-tool shape', async () => {
    app = await makeApp();

    const response = await app.inject({ method: 'GET', url: '/v1/integrations' });
    const body = response.json();

    expect(response.statusCode).toBe(200);
    expect(body.approvalChannels.items.map((item: { provider: string }) => item.provider)).toEqual([
      'web',
      'slack',
      'telegram',
      'email',
    ]);
    expect(body.downstreamToolSources).toHaveProperty('mcpWrapper');
    expect(body.localDemoTools).toHaveLength(4);
    expect(body).not.toHaveProperty('connectedApps');
    expect(body).not.toHaveProperty('businessActions');
  });

  it('saves Slack configuration, masks secrets, and sends a test message', async () => {
    const fetchMock = vi.fn<SlackFetch>(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true, channel: 'C123', ts: '1710000000.000100' }),
    }));
    const auditStore = new JsonlAuditStore(tempDir());
    app = await makeApp({ auditStore, slackFetch: fetchMock });

    const updated = await app.inject({
      method: 'PUT',
      payload: {
        approvalChannelId: 'C123',
        botToken: 'xoxb-secret',
        enabled: true,
        publicBaseUrl: 'https://actionproxy.example',
        signingSecret: 'signing-secret',
      },
      url: '/v1/integrations/slack',
    });
    const tested = await app.inject({ method: 'POST', url: '/v1/integrations/slack/test' });
    const status = await app.inject({ method: 'GET', url: '/v1/integrations' });
    const events = await auditStore.list(20);

    expect(updated.statusCode).toBe(200);
    expect(updated.json().slack).toMatchObject({
      configured: { approvalChannelId: true, botToken: true, signingSecret: true },
      status: 'ready',
    });
    expect(tested.json()).toMatchObject({
      delivery: { channelId: 'C123', provider: 'slack' },
      ok: true,
    });
    expect(status.body).not.toContain('xoxb-secret');
    expect(status.body).not.toContain('signing-secret');
    expect(events.map((event) => event.type)).toEqual(
      expect.arrayContaining(['integration.slack.updated', 'integration.slack.test_sent']),
    );
  });

  it('saves Telegram configuration, masks secrets, and sends a test message', async () => {
    const fetchMock = vi.fn<TelegramFetch>(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true, result: { chat: { id: 12345 }, message_id: 42 } }),
    }));
    app = await makeApp({ telegramFetch: fetchMock });

    const updated = await app.inject({
      method: 'PUT',
      payload: {
        approvalChatId: '12345',
        botToken: '123456:secret',
        enabled: true,
        publicBaseUrl: 'https://actionproxy.example',
        webhookSecret: 'telegram-secret',
      },
      url: '/v1/integrations/telegram',
    });
    const tested = await app.inject({ method: 'POST', payload: {}, url: '/v1/integrations/telegram/test' });
    const status = await app.inject({ method: 'GET', url: '/v1/integrations' });

    expect(updated.statusCode).toBe(200);
    expect(updated.json().telegram).toMatchObject({ status: 'ready' });
    expect(tested.json()).toMatchObject({
      delivery: { destination: '12345', messageId: '42', provider: 'telegram' },
      ok: true,
    });
    expect(status.body).not.toContain('123456:secret');
    expect(status.body).not.toContain('telegram-secret');
  });

  it('writes email test messages to the local outbox', async () => {
    app = await makeApp();

    const updated = await app.inject({
      method: 'PUT',
      payload: {
        approvalRecipient: 'approvals@example.com',
        enabled: true,
        from: 'actionproxy@example.com',
        publicBaseUrl: 'https://actionproxy.example',
        transport: 'outbox',
      },
      url: '/v1/integrations/email',
    });
    const tested = await app.inject({ method: 'POST', url: '/v1/integrations/email/test' });

    expect(updated.statusCode).toBe(200);
    expect(updated.json().email).toMatchObject({ status: 'ready' });
    expect(tested.json()).toMatchObject({
      delivery: { destination: 'approvals@example.com', provider: 'email' },
      ok: true,
    });
  });

  it('saves an MCP wrapper profile and serves generated YAML', async () => {
    app = await makeApp();

    const saved = await app.inject({
      method: 'PUT',
      payload: {
        actionproxy: { baseUrl: 'http://127.0.0.1:8787' },
        policies: { 'docs.search': { approval: 'never' } },
        server: { args: ['./examples/mcp-demo/server.mjs'], command: 'node', name: 'demo' },
      },
      url: '/v1/integrations/mcp-wrapper/profiles/demo',
    });
    const yaml = await app.inject({
      method: 'GET',
      url: '/v1/integrations/mcp-wrapper/profiles/demo/yaml',
    });

    expect(saved.statusCode).toBe(200);
    expect(saved.json().profile).toMatchObject({ id: 'demo', server: { command: 'node', name: 'demo' } });
    expect(yaml.statusCode).toBe(200);
    expect(yaml.json().yaml).toContain('baseUrl: http://127.0.0.1:8787');
  });

  it('rejects removed email configuration and leaves private integration routes unregistered', async () => {
    app = await makeApp();

    const removedEmail = await app.inject({
      method: 'PUT',
      payload: { enabled: true, managed: { provider: 'removed' } },
      url: '/v1/integrations/email',
    });
    const privateRoutes = await Promise.all([
      app.inject({ method: 'GET', url: '/v1/integrations/connected-apps' }),
      app.inject({ method: 'POST', url: '/v1/integrations/business-actions/custom.write/dry-run' }),
    ]);

    expect(removedEmail.statusCode).toBe(400);
    expect(privateRoutes.map((response) => response.statusCode)).toEqual([404, 404]);
  });
});

async function makeApp({
  auditStore = new JsonlAuditStore(tempDir()),
  configOverrides,
  slackFetch,
  telegramFetch,
}: {
  auditStore?: JsonlAuditStore;
  configOverrides?: Partial<AppConfig>;
  slackFetch?: SlackFetch;
  telegramFetch?: TelegramFetch;
} = {}): Promise<FastifyInstance> {
  const server = Fastify({ logger: false });
  const service = new IntegrationConfigService(config({ ...configOverrides, dataDir: tempDir() }));
  await registerIntegrationRoutes(server, service, auditStore, { slackFetch, telegramFetch });
  return server;
}

function config(overrides: Partial<AppConfig> = {}): AppConfig {
  return {
    dataDir: tempDir(),
    host: '127.0.0.1',
    logLevel: 'silent',
    policyPath: path.resolve('src/policies/default.policy.yaml'),
    port: 0,
    ...overrides,
  };
}

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-integrations-route-test-'));
}
