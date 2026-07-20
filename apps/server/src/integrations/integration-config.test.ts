import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { AppConfig } from '../config';
import {
  IntegrationConfigService,
  type LocalIntegrationConfig,
  type McpWrapperProfile,
} from './integration-config';

describe('IntegrationConfigService', () => {
  it('reads and writes local Slack configuration without returning secrets', () => {
    const service = createService();
    const status = service.updateSlack({
      approvalChannelId: 'C123',
      botToken: 'xoxb-local-secret',
      enabled: true,
      publicBaseUrl: 'https://example.test/',
      signingSecret: 'local-signing-secret',
    });

    expect(status).toMatchObject({
      callbackUrl: 'https://example.test/v1/slack/interactions',
      configured: {
        approvalChannelId: true,
        botToken: true,
        signingSecret: true,
      },
      status: 'ready',
    });
    expect(JSON.stringify(service.getStatus())).not.toContain(
      'xoxb-local-secret',
    );
    expect(JSON.stringify(service.getStatus())).not.toContain(
      'local-signing-secret',
    );
  });

  it('lets environment Slack values override local values and honors disable', () => {
    const service = createService(
      {
        slack: {
          approvalChannelId: 'C_ENV',
          botToken: 'xoxb-env',
          signingSecret: 'env-secret',
        },
      },
      {
        slack: {
          approvalChannelId: 'C_LOCAL',
          botToken: 'xoxb-local',
          enabled: true,
          signingSecret: 'local-secret',
        },
      },
    );

    expect(service.getEffectiveSlackConfig()).toMatchObject({
      approvalChannelId: 'C_ENV',
      botToken: 'xoxb-env',
      signingSecret: 'env-secret',
    });
    expect(service.getStatus().slack.sources).toMatchObject({
      approvalChannelId: 'env',
      botToken: 'env',
      signingSecret: 'env',
    });

    service.updateSlack({ enabled: false });
    expect(service.getEffectiveSlackConfig()).toBeUndefined();
    expect(service.getStatus().slack.status).toBe('disabled');
  });

  it('reads and writes Telegram configuration without returning secrets', () => {
    const service = createService();
    const status = service.updateTelegram({
      approvalChatId: '12345',
      botToken: '123456:secret',
      enabled: true,
      publicBaseUrl: 'https://example.test/',
      webhookSecret: 'webhook-secret',
    });

    expect(status).toMatchObject({
      callbackUrl: 'https://example.test/v1/telegram/webhook',
      configured: {
        approvalChatId: true,
        botToken: true,
        webhookSecret: true,
      },
      status: 'ready',
    });
    expect(JSON.stringify(service.getStatus())).not.toContain('123456:secret');
    expect(JSON.stringify(service.getStatus())).not.toContain('webhook-secret');
  });

  it('configures local outbox email and reports its loopback review URL', () => {
    const service = createService({ port: 4321 });
    const status = service.updateEmail({
      approvalRecipient: 'approvals@example.com',
      enabled: true,
      from: 'actionproxy@example.com',
      transport: 'outbox',
    });

    expect(status).toMatchObject({
      fields: {
        publicBaseUrl: 'http://127.0.0.1:4321',
        transport: 'outbox',
      },
      sources: { publicBaseUrl: 'default' },
      status: 'ready',
    });
    expect(service.getEffectiveEmailConfig()).toMatchObject({
      from: 'actionproxy@example.com',
      publicBaseUrl: 'http://127.0.0.1:4321',
      transport: 'outbox',
    });
  });

  it('keeps SMTP partial until self-hosted review and sender settings are complete', () => {
    const service = createService({
      deployment: { mode: 'self_hosted' },
      email: {
        from: 'actionproxy@example.com',
        smtp: { host: 'smtp.example.com', port: 465, secure: true },
        transport: 'smtp',
      },
    });

    expect(
      service.updateEmail({
        approvalRecipient: 'approvals@example.com',
        enabled: true,
      }),
    ).toMatchObject({
      configured: { publicBaseUrl: false },
      sources: { publicBaseUrl: 'missing' },
      status: 'partial',
    });
    expect(service.getEffectiveEmailConfig()).toBeUndefined();

    expect(
      service.updateEmail({ publicBaseUrl: 'https://gateway.example.com' }),
    ).toMatchObject({ status: 'ready' });
  });

  it('does not reveal SMTP passwords and locks operator-configured review URLs', () => {
    const service = createService({
      email: {
        from: 'actionproxy@example.com',
        publicBaseUrl: 'https://gateway.example.com/base/',
        smtp: {
          host: 'smtp.example.com',
          password: 'environment-smtp-secret',
          port: 465,
        },
        transport: 'smtp',
      },
    });

    const status = service.updateEmail({ enabled: true });
    expect(status.sources.publicBaseUrl).toBe('env');
    expect(status.fields.publicBaseUrl).toBe(
      'https://gateway.example.com/base',
    );
    expect(JSON.stringify(status)).not.toContain('environment-smtp-secret');
    expect(() =>
      service.updateEmail({ publicBaseUrl: 'https://other.example.com' }),
    ).toThrow('controlled by deployment configuration');
  });

  it('does not save channel secrets through authenticated deployments', () => {
    const service = createService({
      auth: {
        allowedCorsOrigins: [],
        mode: 'api_key',
        oidc: {
          emailClaim: 'email',
          groupsClaim: 'groups',
          nameClaim: 'name',
          scopesClaim: 'scope',
        },
        rateLimit: { max: 100, windowMs: 60_000 },
        slackUserMap: {},
        workspaceId: 'default',
      },
    });

    expect(() => service.updateSlack({ botToken: 'secret' })).toThrow(
      'Authenticated deployments',
    );
    expect(() => service.updateTelegram({ webhookSecret: 'secret' })).toThrow(
      'Authenticated deployments',
    );
    expect(() =>
      service.updateEmail({ smtp: { password: 'secret' } }),
    ).toThrow('Authenticated deployments');
  });

  it('saves MCP profiles, generates YAML, and records policy coverage', () => {
    const service = createService();
    const profile: McpWrapperProfile = {
      actionproxy: { baseUrl: 'http://127.0.0.1:8787' },
      id: 'demo',
      policies: { 'gmail.send_email': { approval: 'required' } },
      server: {
        args: ['./examples/mcp-demo/server.mjs'],
        command: 'node',
        name: 'demo',
      },
    };

    const saved = service.saveMcpProfile(profile);
    const tools = service.saveMcpDiscoveredTools(
      'demo',
      [
        {
          description: 'Send email',
          inputSchema: { type: 'object' },
          name: 'gmail.send_email',
          serverName: 'demo',
        },
      ],
      {
        default: { approval: 'required', risk: 'unknown' },
        tools: {
          'gmail.send_email': {
            approval: 'required',
            risk: 'external',
          },
        },
        version: 1,
      },
    );

    expect(fs.existsSync(saved.yamlPath)).toBe(true);
    expect(service.getMcpProfileYaml('demo')).toContain('command: node');
    expect(tools).toMatchObject([
      {
        name: 'gmail.send_email',
        policyCoverage: {
          decision: 'require_approval',
          matchedRule: 'gmail.send_email',
          risk: 'external',
        },
        schemaHash: expect.any(String),
      },
    ]);
  });

  it('saves local mock-tool setup and returns one fixed Community status shape', () => {
    const service = createService();
    const updated = service.updateToolIntegration('gmail', {
      enabled: true,
      values: {
        defaultRecipientDomain: 'example.com',
        senderEmail: 'support@example.com',
      },
    });
    const status = service.getStatus();

    expect(updated).toMatchObject({
      enabled: true,
      id: 'gmail',
      status: 'ready',
      tools: ['gmail.send_email'],
    });
    expect(status.localDemoTools).toHaveLength(4);
    expect(status.approvalChannels.items.map((item) => item.provider)).toEqual([
      'web',
      'slack',
      'telegram',
      'email',
    ]);
    expect(service.getCommunityStatus()).toEqual(status);
  });

  it('ignores corrupt or unrelated local configuration fields', () => {
    const dataDir = fs.mkdtempSync(
      path.join(os.tmpdir(), 'actionproxy-integrations-config-test-'),
    );
    const configPath = path.join(dataDir, 'integrations.local.json');
    fs.writeFileSync(configPath, '{broken', 'utf8');
    const service = new IntegrationConfigService(baseConfig({ dataDir }));
    expect(service.getStatus().localDemoTools).toHaveLength(4);

    fs.writeFileSync(
      configPath,
      `${JSON.stringify({ obsoleteSection: { enabled: true } })}\n`,
      'utf8',
    );
    service.updateToolIntegration('docs', { enabled: true });
    expect(JSON.parse(fs.readFileSync(configPath, 'utf8'))).toEqual({
      tools: { docs: { enabled: true } },
    });
  });
});

function createService(
  overrides: Partial<AppConfig> = {},
  local?: LocalIntegrationConfig,
): IntegrationConfigService {
  const config = baseConfig(overrides);
  if (local) {
    fs.writeFileSync(
      path.join(config.dataDir, 'integrations.local.json'),
      `${JSON.stringify(local, null, 2)}\n`,
      'utf8',
    );
  }
  return new IntegrationConfigService(config);
}

function baseConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  const dataDir =
    overrides.dataDir ??
    fs.mkdtempSync(
      path.join(os.tmpdir(), 'actionproxy-integrations-config-test-'),
    );
  fs.mkdirSync(dataDir, { recursive: true });
  return {
    dataDir,
    host: '127.0.0.1',
    logLevel: 'silent',
    policyPath: path.resolve('src/policies/default.policy.yaml'),
    port: 0,
    ...overrides,
  };
}
