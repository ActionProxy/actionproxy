import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  IntegrationConfigService,
  type IntegrationStatusResponse,
  type LocalEmailIntegrationConfig,
  type LocalSlackIntegrationConfig,
  type LocalTelegramIntegrationConfig,
  type LocalToolIntegrationConfig,
  type McpWrapperProfile,
  type McpWrapperProfileSummary,
  toolIntegrationIds,
  type ToolIntegrationId,
} from '../integrations/integration-config';
import { EmailService } from '../integrations/email/email-service';
import { discoverMcpTools } from '../integrations/mcp-discovery';
import { SlackService, type SlackFetch } from '../integrations/slack/slack-service';
import { TelegramService, type TelegramFetch, type TelegramTestRecipient } from '../integrations/telegram/telegram-service';
import type { AuditEvent, AuthContext, JsonObject } from '../models';
import type { PolicyManager } from '../policy/policy-manager';
import { requireScope } from '../security/scopes';
import type { ApproverDirectoryService } from '../services/approver-directory';
import type { PolicyDetectorService } from '../services/policy-detector';
import type { AuditStore } from '../storage/audit-store';
import { authContext } from './route-utils';

export interface IntegrationRouteOptions {
  approverDirectory?: ApproverDirectoryService;
  mcpDiscovery?: typeof discoverMcpTools;
  policyDetector?: PolicyDetectorService;
  policyManager?: PolicyManager;
  slackFetch?: SlackFetch;
  telegramFetch?: TelegramFetch;
}

const profileIdSchema = z.string().min(1).max(80).regex(/^[A-Za-z0-9._-]+$/);
const toolIntegrationIdSchema = z.enum(toolIntegrationIds);

const slackUpdateSchema = z.object({
  approvalChannelId: z.string().optional(),
  botToken: z.string().optional(),
  enabled: z.boolean().optional(),
  publicBaseUrl: z.string().optional(),
  signingSecret: z.string().optional(),
}).strict();

const telegramUpdateSchema = z.object({
  approvalChatId: z.string().optional(),
  botToken: z.string().optional(),
  enabled: z.boolean().optional(),
  publicBaseUrl: z.string().optional(),
  webhookSecret: z.string().optional(),
}).strict();

const telegramTestSchema = z.object({
  userId: z.string().min(1).max(120).optional(),
}).strict();

const emailUpdateSchema = z.object({
  approvalRecipient: z.string().optional(),
  enabled: z.boolean().optional(),
  from: z.string().optional(),
  publicBaseUrl: z.string().optional(),
  smtp: z
    .object({
      host: z.string().optional(),
      password: z.string().optional(),
      port: z.number().int().positive().optional(),
      secure: z.boolean().optional(),
      username: z.string().optional(),
    }).strict()
    .optional(),
  transport: z.enum(['outbox', 'smtp']).optional(),
}).strict();

const toolIntegrationUpdateSchema = z.object({
  displayName: z.string().optional(),
  enabled: z.boolean().optional(),
  values: z.record(z.string()).optional(),
}).strict();

const mcpProfileSchema = z.object({
  actionproxy: z.object({
    agentId: z.string().optional(),
    approvalPollIntervalMs: z.number().int().positive().optional(),
    approvalTimeoutMs: z.number().int().positive().optional(),
    baseUrl: z.string().min(1),
    bearerTokenEnv: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/u).optional(),
    requestedBy: z.string().optional(),
    requestTimeoutMs: z.number().int().positive().optional(),
  }).strict(),
  id: z.string().optional(),
  name: z.string().optional(),
  policies: z.record(z.object({ approval: z.enum(['deny', 'never', 'required']) })).optional(),
  server: z.object({
    args: z.array(z.string()).optional(),
    command: z.string().min(1),
    cwd: z.string().optional(),
    env: z.record(z.string()).optional(),
    name: z.string().min(1),
    requestTimeoutMs: z.number().int().positive().optional(),
  }).strict(),
}).strict();

export async function registerIntegrationRoutes(
  app: FastifyInstance,
  integrationConfig: IntegrationConfigService,
  auditStore: AuditStore,
  options: IntegrationRouteOptions = {},
): Promise<void> {
  app.get('/v1/integrations', async (request) => {
    requireScope(authContext(request), 'admin:integrations');
    return integrationConfig.getCommunityStatus(options.policyManager?.getPolicy());
  });

  app.put('/v1/integrations/slack', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:integrations');
    const parsed = slackUpdateSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    let slack;
    try {
      slack = integrationConfig.updateSlack(parsed.data);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return reply.status(400).send({ error: 'invalid_integration_config', message });
    }
    await appendIntegrationAudit(auditStore, 'integration.slack.updated', {
      configured: slack.configured,
      enabled: slack.enabled,
      fields: slack.fields,
      sources: slack.sources,
      status: slack.status,
    }, auth);
    return { slack };
  });

  app.put('/v1/integrations/telegram', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:integrations');
    const parsed = telegramUpdateSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    let telegram;
    try {
      telegram = integrationConfig.updateTelegram(parsed.data);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return reply.status(400).send({ error: 'invalid_integration_config', message });
    }
    await appendIntegrationAudit(auditStore, 'integration.telegram.updated', {
      configured: telegram.configured,
      enabled: telegram.enabled,
      fields: telegram.fields,
      sources: telegram.sources,
      status: telegram.status,
    }, auth);
    return { telegram };
  });

  app.put('/v1/integrations/email', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:integrations');
    const parsed = emailUpdateSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    let email;
    try {
      email = integrationConfig.updateEmail(parsed.data);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return reply.status(400).send({ error: 'invalid_integration_config', message });
    }
    await appendIntegrationAudit(auditStore, 'integration.email.updated', {
      configured: email.configured,
      enabled: email.enabled,
      fields: {
        ...email.fields,
        smtpUsername: email.fields.smtpUsername ? '[configured]' : undefined,
      },
      sources: email.sources,
      status: email.status,
    }, auth);
    return { email };
  });

  app.put('/v1/integrations/tools/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:integrations');
    const params = z.object({ id: toolIntegrationIdSchema }).safeParse(request.params);
    if (!params.success) {
      return reply.status(400).send({ error: 'invalid_request', details: params.error.flatten() });
    }

    const parsed = toolIntegrationUpdateSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    const integration = integrationConfig.updateToolIntegration(params.data.id, parsed.data);
    await appendIntegrationAudit(auditStore, 'integration.tool.updated', {
      enabled: integration.enabled,
      id: integration.id,
      mode: integration.mode,
      status: integration.status,
      tools: integration.tools,
    }, auth);
    return { integration };
  });

  app.post('/v1/integrations/slack/test', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:integrations');
    const effectiveSlackConfig = integrationConfig.getEffectiveSlackConfig();
    if (!effectiveSlackConfig) {
      const status = integrationConfig.getStatus().slack;
      const body = {
        error: 'slack_not_ready',
        message: 'Slack bot token is required. Add an approval channel to send a test message.',
        slack: status,
      };
      await appendIntegrationAudit(auditStore, 'integration.slack.test_failed', {
        error: body.message,
        status: status.status,
      }, auth);
      return reply.status(409).send(body);
    }

    try {
      const delivery = await new SlackService(() => integrationConfig.getEffectiveSlackConfig(), {
        fetch: options.slackFetch,
      }).sendTestMessage();
      await appendIntegrationAudit(auditStore, 'integration.slack.test_sent', {
        ...delivery,
      }, auth);
      return { delivery, ok: true };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await appendIntegrationAudit(auditStore, 'integration.slack.test_failed', { error: message }, auth);
      return reply.status(502).send({ error: 'slack_test_failed', message, ok: false });
    }
  });

  app.post('/v1/integrations/telegram/test', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:integrations');
    const parsed = telegramTestSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    const effectiveTelegramConfig = integrationConfig.getEffectiveTelegramConfig();
    if (!effectiveTelegramConfig) {
      const status = integrationConfig.getStatus().telegram;
      const body = {
        error: 'telegram_not_ready',
        message: 'Telegram bot token is required before sending a test message.',
        telegram: status,
      };
      await appendIntegrationAudit(auditStore, 'integration.telegram.test_failed', {
        error: body.message,
        status: status.status,
      }, auth);
      return reply.status(409).send(body);
    }

    try {
      const testRecipient = parsed.data.userId
        ? await telegramTestRecipientForUser(options.approverDirectory, auth.workspaceId, parsed.data.userId)
        : undefined;
      const delivery = await new TelegramService(() => integrationConfig.getEffectiveTelegramConfig(), {
        fetch: options.telegramFetch,
      }).sendTestMessage(testRecipient);
      await appendIntegrationAudit(auditStore, 'integration.telegram.test_sent', {
        ...delivery,
        testRecipientUserId: testRecipient?.userId,
      }, auth);
      return { delivery, ok: true };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await appendIntegrationAudit(auditStore, 'integration.telegram.test_failed', { error: message }, auth);
      const status = message.includes('not found') ? 404 : message.includes('has not connected Telegram') ? 409 : 502;
      return reply.status(status).send({ error: 'telegram_test_failed', message, ok: false });
    }
  });

  app.post('/v1/integrations/email/test', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:integrations');
    const effectiveEmailConfig = integrationConfig.getEffectiveEmailConfig();
    if (!effectiveEmailConfig) {
      const status = integrationConfig.getStatus(options.policyManager?.getPolicy()).email;
      const body = {
        email: status,
        error: 'email_not_ready',
        message: !status.configured.publicBaseUrl
          ? 'Email delivery is not ready because the approval review URL is missing or invalid. Configure ACTIONPROXY_PUBLIC_BASE_URL (or the email-specific compatibility override) with an absolute HTTP/HTTPS URL.'
          : 'Email delivery is not ready. Configure the selected transport and sender settings.',
      };
      await appendIntegrationAudit(auditStore, 'integration.email.test_failed', {
        error: body.message,
        status: status.status,
      }, auth);
      return reply.status(409).send(body);
    }

    try {
      const delivery = await new EmailService(() => integrationConfig.getEffectiveEmailConfig()).sendTestMessage();
      await appendIntegrationAudit(auditStore, 'integration.email.test_sent', {
        ...delivery,
      }, auth);
      return { delivery, ok: true };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await appendIntegrationAudit(auditStore, 'integration.email.test_failed', { error: message }, auth);
      return reply.status(502).send({ error: 'email_test_failed', message, ok: false });
    }
  });

  app.put('/v1/integrations/mcp-wrapper/profiles/:id', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:integrations');
    const params = z.object({ id: profileIdSchema }).safeParse(request.params);
    if (!params.success) {
      return reply.status(400).send({ error: 'invalid_request', details: params.error.flatten() });
    }

    const parsed = mcpProfileSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }

    const profile: McpWrapperProfile = { ...parsed.data, id: params.data.id };
    const saved = integrationConfig.saveMcpProfile(profile);
    const yaml = integrationConfig.generateMcpYaml(profile);
    await appendIntegrationAudit(auditStore, 'integration.mcp_profile.saved', {
      profileId: saved.id,
      profileName: saved.name ?? null,
      serverName: saved.server.name,
      yamlPath: saved.yamlPath,
    }, auth);
    return { profile: saved, yaml };
  });

  app.get('/v1/integrations/mcp-wrapper/profiles/:id/yaml', async (request, reply) => {
    requireScope(authContext(request), 'admin:integrations');
    const params = z.object({ id: profileIdSchema }).safeParse(request.params);
    if (!params.success) {
      return reply.status(400).send({ error: 'invalid_request', details: params.error.flatten() });
    }

    const yaml = integrationConfig.getMcpProfileYaml(params.data.id);
    if (!yaml) {
      return reply.status(404).send({ error: 'not_found', message: `MCP wrapper profile not found: ${params.data.id}` });
    }

    return { profileId: params.data.id, yaml };
  });

  app.post('/v1/integrations/mcp-wrapper/profiles/:id/sync-tools', async (request, reply) => {
    const auth = requireScope(authContext(request), 'admin:integrations');
    const params = z.object({ id: profileIdSchema }).safeParse(request.params);
    if (!params.success) {
      return reply.status(400).send({ error: 'invalid_request', details: params.error.flatten() });
    }

    const profile = integrationConfig.getMcpProfile(params.data.id);
    if (!profile) {
      return reply.status(404).send({ error: 'not_found', message: `MCP wrapper profile not found: ${params.data.id}` });
    }
    if (!integrationConfig.isMcpStdioDiscoveryEnabled()) {
      return reply.status(409).send({
        error: 'mcp_stdio_discovery_disabled',
        message:
          'Server-side MCP stdio discovery is disabled. Set ACTIONPROXY_MCP_STDIO_DISCOVERY_ENABLED=true only when this server may execute commands from trusted MCP profiles.',
      });
    }

    try {
      const discovered = await (options.mcpDiscovery ?? discoverMcpTools)(profile);
      const tools = integrationConfig.saveMcpDiscoveredTools(
        profile.id,
        discovered,
        options.policyManager?.getPolicy(),
      );
      if (options.policyDetector && options.policyManager) {
        for (const tool of tools) {
          await options.policyDetector.observeTool({
            auth,
            mcpProfileId: profile.id,
            mcpServerName: tool.serverName,
            policy: options.policyManager.getPolicy(),
            schemaHash: tool.schemaHash,
            source: 'mcp_discovery',
            toolName: tool.name,
            workspaceId: auth.workspaceId,
          });
        }
      }
      await appendIntegrationAudit(auditStore, 'integration.mcp_profile.tools_synced', {
        profileId: profile.id,
        serverName: profile.server.name,
        toolCount: tools.length,
        tools: tools.map((tool) => tool.name),
      }, auth);
      return { profileId: profile.id, tools };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return reply.status(502).send({ error: 'mcp_discovery_failed', message });
    }
  });
}

async function telegramTestRecipientForUser(
  approverDirectory: ApproverDirectoryService | undefined,
  workspaceId: string,
  userId: string,
): Promise<TelegramTestRecipient> {
  if (!approverDirectory) throw new Error('Approver directory is not configured.');

  const user = await approverDirectory.getUser(workspaceId, userId);
  if (!user || !user.enabled) throw new Error(`Approver user not found: ${userId}`);
  if (!user.telegramChatId) {
    throw new Error(`Approver ${user.displayName} has not connected Telegram yet.`);
  }

  return {
    chatId: user.telegramChatId,
    displayName: user.displayName,
    telegramUserId: user.telegramUserId,
    userId: user.id,
  };
}

function appendIntegrationAudit(
  auditStore: AuditStore,
  type: Extract<
    AuditEvent['type'],
    | 'integration.mcp_profile.saved'
    | 'integration.mcp_profile.tools_synced'
    | 'integration.email.test_failed'
    | 'integration.email.test_sent'
    | 'integration.email.updated'
    | 'integration.slack.test_failed'
    | 'integration.slack.test_sent'
    | 'integration.slack.updated'
    | 'integration.telegram.test_failed'
    | 'integration.telegram.test_sent'
    | 'integration.telegram.updated'
    | 'integration.tool.updated'
  >,
  data: JsonObject,
  auth: AuthContext,
): Promise<void> {
  return auditStore.append({
    actor: auth.email ?? auth.principalId,
    auth,
    data,
    id: `audit_${randomUUID()}`,
    timestamp: new Date().toISOString(),
    type,
    workspaceId: auth.workspaceId,
  });
}

export type {
  IntegrationStatusResponse,
  LocalEmailIntegrationConfig,
  LocalSlackIntegrationConfig,
  LocalTelegramIntegrationConfig,
  LocalToolIntegrationConfig,
  McpWrapperProfileSummary,
  ToolIntegrationId,
};
