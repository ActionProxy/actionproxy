import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import type { AppConfig } from '../config';
import { evaluatePolicy } from '../policy/evaluate-policy';
import type { PolicyFile } from '../policy/policy-types';
import {
  localEmailPublicBaseUrl,
  normalizeEmailPublicBaseUrl,
} from './email/public-base-url';

export type ConfigSource = 'default' | 'env' | 'local' | 'missing';
export type IntegrationStatus = 'disabled' | 'partial' | 'ready';
export type ToolIntegrationId = 'docs' | 'gmail' | 'jira' | 'salesforce';
export type EmailTransport = 'outbox' | 'smtp';

export interface LocalSlackIntegrationConfig {
  approvalChannelId?: string;
  botToken?: string;
  enabled?: boolean;
  publicBaseUrl?: string;
  signingSecret?: string;
}

export interface LocalTelegramIntegrationConfig {
  approvalChatId?: string;
  botToken?: string;
  enabled?: boolean;
  publicBaseUrl?: string;
  webhookSecret?: string;
}

export interface LocalEmailIntegrationConfig {
  approvalRecipient?: string;
  enabled?: boolean;
  from?: string;
  publicBaseUrl?: string;
  smtp?: {
    host?: string;
    password?: string;
    port?: number;
    secure?: boolean;
    username?: string;
  };
  transport?: EmailTransport;
}

export interface LocalToolIntegrationConfig {
  displayName?: string;
  enabled?: boolean;
  values?: Record<string, string>;
}

export interface ToolIntegrationField {
  key: string;
  label: string;
  placeholder?: string;
  value?: string;
}

export interface ToolIntegrationStatus {
  description: string;
  displayName: string;
  enabled: boolean;
  fields: ToolIntegrationField[];
  id: ToolIntegrationId;
  mode: 'mock';
  name: string;
  status: IntegrationStatus;
  tools: string[];
}

export interface McpWrapperProfile {
  actionproxy: {
    agentId?: string;
    approvalPollIntervalMs?: number;
    approvalTimeoutMs?: number;
    baseUrl: string;
    bearerTokenEnv?: string;
    requestedBy?: string;
    requestTimeoutMs?: number;
  };
  id: string;
  name?: string;
  policies?: Record<string, { approval: 'deny' | 'never' | 'required' }>;
  server: {
    args?: string[];
    command: string;
    cwd?: string;
    env?: Record<string, string>;
    name: string;
    requestTimeoutMs?: number;
  };
}

export interface McpDiscoveredTool {
  description?: string;
  discoveredAt: string;
  inputSchema?: Record<string, unknown>;
  name: string;
  policyCoverage?: {
    approval: string;
    decision: string;
    matchedRule: string;
    reason: string;
    risk: string;
  };
  profileId: string;
  schemaHash: string;
  serverName: string;
}

export interface LocalIntegrationConfig {
  email?: LocalEmailIntegrationConfig;
  mcpWrapper?: {
    discoveredTools?: Record<string, McpDiscoveredTool>;
    profiles?: Record<string, McpWrapperProfile>;
  };
  slack?: LocalSlackIntegrationConfig;
  telegram?: LocalTelegramIntegrationConfig;
  tools?: Partial<Record<ToolIntegrationId, LocalToolIntegrationConfig>>;
}

export interface EffectiveSlackConfig {
  approvalChannelId?: string;
  botToken: string;
  publicBaseUrl?: string;
  signingSecret?: string;
}

export interface EffectiveTelegramConfig {
  approvalChatId?: string;
  botToken: string;
  publicBaseUrl?: string;
  webhookSecret?: string;
}

export interface EffectiveEmailConfig {
  approvalRecipient?: string;
  from: string;
  outboxDir: string;
  publicBaseUrl: string;
  smtp?: {
    host: string;
    password?: string;
    port: number;
    secure?: boolean;
    username?: string;
  };
  transport: EmailTransport;
}

export interface SlackIntegrationStatus {
  callbackPath: string;
  callbackUrl?: string;
  configured: {
    approvalChannelId: boolean;
    botToken: boolean;
    signingSecret: boolean;
  };
  enabled: boolean;
  fields: {
    approvalChannelId?: string;
    publicBaseUrl?: string;
  };
  sources: {
    approvalChannelId: ConfigSource;
    botToken: ConfigSource;
    signingSecret: ConfigSource;
  };
  status: IntegrationStatus;
}

export interface TelegramIntegrationStatus {
  callbackPath: string;
  callbackUrl?: string;
  configured: {
    approvalChatId: boolean;
    botToken: boolean;
    webhookSecret: boolean;
  };
  enabled: boolean;
  fields: {
    approvalChatId?: string;
    publicBaseUrl?: string;
  };
  sources: {
    approvalChatId: ConfigSource;
    botToken: ConfigSource;
    publicBaseUrl: ConfigSource;
    webhookSecret: ConfigSource;
  };
  status: IntegrationStatus;
}

export interface EmailIntegrationStatus {
  configured: {
    approvalRecipient: boolean;
    from: boolean;
    publicBaseUrl: boolean;
    smtpHost: boolean;
    smtpPassword: boolean;
    smtpPort: boolean;
  };
  enabled: boolean;
  fields: {
    approvalRecipient?: string;
    from?: string;
    publicBaseUrl?: string;
    smtpHost?: string;
    smtpPort?: number;
    smtpSecure?: boolean;
    smtpUsername?: string;
    transport: EmailTransport;
  };
  outboxDir: string;
  sources: {
    approvalRecipient: ConfigSource;
    from: ConfigSource;
    publicBaseUrl: ConfigSource;
    smtpHost: ConfigSource;
    smtpPassword: ConfigSource;
    smtpPort: ConfigSource;
  };
  status: IntegrationStatus;
}

export interface ApprovalChannelStatus {
  default: boolean;
  description: string;
  displayName: string;
  enabled: boolean;
  id: string;
  provider: 'email' | 'slack' | 'telegram' | 'web';
  status: IntegrationStatus | 'ready';
}

export interface McpWrapperProfileSummary extends McpWrapperProfile {
  discoveredTools: McpDiscoveredTool[];
  yamlPath: string;
}

export interface IntegrationStatusResponse {
  approvalChannels: {
    email: EmailIntegrationStatus;
    items: ApprovalChannelStatus[];
    slack: SlackIntegrationStatus;
    telegram: TelegramIntegrationStatus;
    web: ApprovalChannelStatus;
  };
  downstreamToolSources: {
    mcpWrapper: {
      profiles: McpWrapperProfileSummary[];
    };
  };
  email: EmailIntegrationStatus;
  localDemoTools: ToolIntegrationStatus[];
  mcpWrapper: {
    profiles: McpWrapperProfileSummary[];
  };
  slack: SlackIntegrationStatus;
  telegram: TelegramIntegrationStatus;
  tools: ToolIntegrationStatus[];
}

export type CommunityIntegrationStatusResponse = IntegrationStatusResponse;

const slackCallbackPath = '/v1/slack/interactions';
const telegramCallbackPath = '/v1/telegram/webhook';

export const toolIntegrationIds = [
  'docs',
  'jira',
  'gmail',
  'salesforce',
] as const satisfies readonly ToolIntegrationId[];

const toolIntegrationCatalog: Record<
  ToolIntegrationId,
  Omit<ToolIntegrationStatus, 'displayName' | 'enabled' | 'fields' | 'status'>
> = {
  docs: {
    description:
      'Local mock adapter for the docs.search demo tool. Production tools should usually come through MCP or an external runner.',
    id: 'docs',
    mode: 'mock',
    name: 'Docs',
    tools: ['docs.search'],
  },
  gmail: {
    description:
      'Local mock adapter for the gmail.send_email demo tool. ActionProxy does not store production Gmail credentials.',
    id: 'gmail',
    mode: 'mock',
    name: 'Gmail',
    tools: ['gmail.send_email'],
  },
  jira: {
    description:
      'Local mock adapter for the jira.create_issue demo tool. Use an existing MCP server or external runner for real Jira calls.',
    id: 'jira',
    mode: 'mock',
    name: 'Jira',
    tools: ['jira.create_issue'],
  },
  salesforce: {
    description:
      'Local mock adapter for Salesforce demo tools. Use an existing MCP server or external runner for real CRM calls.',
    id: 'salesforce',
    mode: 'mock',
    name: 'Salesforce',
    tools: ['salesforce.update_opportunity', 'salesforce.*'],
  },
};

const toolIntegrationFields: Record<
  ToolIntegrationId,
  Omit<ToolIntegrationField, 'value'>[]
> = {
  docs: [
    {
      key: 'collectionName',
      label: 'Collection name',
      placeholder: 'Support knowledge base',
    },
    { key: 'owner', label: 'Owner', placeholder: 'support@example.com' },
  ],
  gmail: [
    {
      key: 'senderEmail',
      label: 'Sender email',
      placeholder: 'support@example.com',
    },
    {
      key: 'defaultRecipientDomain',
      label: 'Recipient domain',
      placeholder: 'example.com',
    },
  ],
  jira: [
    {
      key: 'siteUrl',
      label: 'Site URL',
      placeholder: 'https://example.atlassian.net',
    },
    { key: 'projectKey', label: 'Project key', placeholder: 'SUP' },
  ],
  salesforce: [
    {
      key: 'instanceUrl',
      label: 'Instance URL',
      placeholder: 'https://example.my.salesforce.com',
    },
    {
      key: 'defaultStage',
      label: 'Default stage',
      placeholder: 'Qualification',
    },
  ],
};

export class IntegrationConfigService {
  private readonly configPath: string;
  private readonly mcpDir: string;

  constructor(
    private readonly appConfig: AppConfig,
    options: { configPath?: string; mcpDir?: string } = {},
  ) {
    this.configPath =
      options.configPath ??
      path.join(appConfig.dataDir, 'integrations.local.json');
    this.mcpDir = options.mcpDir ?? path.join(appConfig.dataDir, 'mcp');
  }

  isMcpStdioDiscoveryEnabled(): boolean {
    return this.appConfig.mcp?.stdioDiscoveryEnabled === true;
  }

  getStatus(policy?: PolicyFile): IntegrationStatusResponse {
    const config = this.readConfig();
    const slack = this.getSlackStatus(config.slack);
    const telegram = this.getTelegramStatus(config.telegram);
    const email = this.getEmailStatus(config.email);
    const profiles = Object.values(config.mcpWrapper?.profiles ?? {})
      .map((profile) => ({
        ...profile,
        discoveredTools: this.getMcpDiscoveredTools(
          profile.id,
          config,
          policy,
        ),
        yamlPath: this.profileYamlPath(profile.id),
      }))
      .sort((left, right) => left.id.localeCompare(right.id));
    const tools = this.getToolIntegrationStatuses(config.tools);
    const web: ApprovalChannelStatus = {
      default: false,
      description:
        'Canonical ActionProxy approval page. Delivery is not external.',
      displayName: 'Web UI',
      enabled: true,
      id: 'web.default',
      provider: 'web',
      status: 'ready',
    };
    return {
      approvalChannels: {
        email,
        items: [
          web,
          approvalChannelFromSlack(slack),
          approvalChannelFromTelegram(telegram),
          approvalChannelFromEmail(email),
        ],
        slack,
        telegram,
        web,
      },
      downstreamToolSources: { mcpWrapper: { profiles } },
      email,
      localDemoTools: tools,
      mcpWrapper: { profiles },
      slack,
      telegram,
      tools,
    };
  }

  getCommunityStatus(policy?: PolicyFile): IntegrationStatusResponse {
    return this.getStatus(policy);
  }

  getEffectiveSlackConfig(): EffectiveSlackConfig | undefined {
    const local = this.readConfig().slack;
    if (local?.enabled === false) return undefined;
    const botToken = this.appConfig.slack?.botToken || local?.botToken;
    if (!botToken) return undefined;
    return {
      approvalChannelId:
        this.appConfig.slack?.approvalChannelId || local?.approvalChannelId,
      botToken,
      publicBaseUrl: local?.publicBaseUrl,
      signingSecret:
        this.appConfig.slack?.signingSecret || local?.signingSecret,
    };
  }

  getSlackSigningSecret(): string | undefined {
    const local = this.readConfig().slack;
    if (local?.enabled === false) return undefined;
    return this.appConfig.slack?.signingSecret || local?.signingSecret;
  }

  getEffectiveTelegramConfig(): EffectiveTelegramConfig | undefined {
    const local = this.readConfig().telegram;
    if (local?.enabled === false) return undefined;
    const botToken = this.appConfig.telegram?.botToken || local?.botToken;
    if (!botToken) return undefined;
    return {
      approvalChatId:
        this.appConfig.telegram?.approvalChatId || local?.approvalChatId,
      botToken,
      publicBaseUrl:
        this.appConfig.telegram?.publicBaseUrl || local?.publicBaseUrl,
      webhookSecret:
        this.appConfig.telegram?.webhookSecret || local?.webhookSecret,
    };
  }

  getTelegramWebhookSecret(): string | undefined {
    const local = this.readConfig().telegram;
    if (local?.enabled === false) return undefined;
    return this.appConfig.telegram?.webhookSecret || local?.webhookSecret;
  }

  getEffectiveEmailConfig(): EffectiveEmailConfig | undefined {
    const local = this.readConfig().email;
    const status = this.getEmailStatus(local);
    if (!status.enabled || status.status !== 'ready') return undefined;
    return {
      approvalRecipient: status.fields.approvalRecipient,
      from: status.fields.from!,
      outboxDir: status.outboxDir,
      publicBaseUrl: status.fields.publicBaseUrl!,
      smtp:
        status.fields.transport === 'smtp'
          ? {
              host: status.fields.smtpHost!,
              password:
                this.appConfig.email?.smtp?.password || local?.smtp?.password,
              port: status.fields.smtpPort!,
              secure: status.fields.smtpSecure,
              username:
                this.appConfig.email?.smtp?.username || local?.smtp?.username,
            }
          : undefined,
      transport: status.fields.transport,
    };
  }

  updateSlack(input: LocalSlackIntegrationConfig): SlackIntegrationStatus {
    if (
      this.appConfig.auth?.mode &&
      this.appConfig.auth.mode !== 'none' &&
      (input.botToken !== undefined || input.signingSecret !== undefined)
    ) {
      throw new Error(
        'Authenticated deployments do not allow saving Slack secrets to local integration config.',
      );
    }
    const config = this.readConfig();
    config.slack = normalizeSlackIntegrationConfig({
      ...config.slack,
      ...input,
      approvalChannelId:
        input.approvalChannelId ?? config.slack?.approvalChannelId,
      botToken: input.botToken ?? config.slack?.botToken,
      publicBaseUrl: input.publicBaseUrl ?? config.slack?.publicBaseUrl,
      signingSecret: input.signingSecret ?? config.slack?.signingSecret,
    });
    this.writeConfig(config);
    return this.getSlackStatus(config.slack);
  }

  updateTelegram(
    input: LocalTelegramIntegrationConfig,
  ): TelegramIntegrationStatus {
    if (
      this.appConfig.auth?.mode &&
      this.appConfig.auth.mode !== 'none' &&
      (input.botToken !== undefined || input.webhookSecret !== undefined)
    ) {
      throw new Error(
        'Authenticated deployments do not allow saving Telegram secrets to local integration config.',
      );
    }
    const config = this.readConfig();
    config.telegram = normalizeTelegramIntegrationConfig({
      ...config.telegram,
      ...input,
      approvalChatId:
        input.approvalChatId ?? config.telegram?.approvalChatId,
      botToken: input.botToken ?? config.telegram?.botToken,
      publicBaseUrl: input.publicBaseUrl ?? config.telegram?.publicBaseUrl,
      webhookSecret: input.webhookSecret ?? config.telegram?.webhookSecret,
    });
    this.writeConfig(config);
    return this.getTelegramStatus(config.telegram);
  }

  updateEmail(input: LocalEmailIntegrationConfig): EmailIntegrationStatus {
    if (
      this.appConfig.auth?.mode &&
      this.appConfig.auth.mode !== 'none' &&
      input.smtp?.password !== undefined
    ) {
      throw new Error(
        'Authenticated deployments do not allow saving SMTP secrets to local integration config.',
      );
    }
    const requestedPublicBaseUrl = normalizeEmailPublicBaseUrl(
      input.publicBaseUrl,
    );
    const environmentPublicBaseUrl = normalizeEmailPublicBaseUrl(
      this.appConfig.email?.publicBaseUrl,
    );
    if (
      requestedPublicBaseUrl &&
      environmentPublicBaseUrl &&
      requestedPublicBaseUrl !== environmentPublicBaseUrl
    ) {
      throw new Error(
        'Email approval review URL is controlled by deployment configuration and cannot be overridden.',
      );
    }

    const config = this.readConfig();
    config.email = normalizeEmailIntegrationConfig({
      ...config.email,
      ...input,
      approvalRecipient:
        input.approvalRecipient ?? config.email?.approvalRecipient,
      from: input.from ?? config.email?.from,
      publicBaseUrl: environmentPublicBaseUrl
        ? safeEmailPublicBaseUrl(config.email?.publicBaseUrl)
        : input.publicBaseUrl ?? config.email?.publicBaseUrl,
      smtp: {
        ...config.email?.smtp,
        ...input.smtp,
        password: input.smtp?.password ?? config.email?.smtp?.password,
      },
      transport: input.transport ?? config.email?.transport,
    });
    this.writeConfig(config);
    return this.getEmailStatus(config.email);
  }

  updateToolIntegration(
    id: ToolIntegrationId,
    input: LocalToolIntegrationConfig,
  ): ToolIntegrationStatus {
    const config = this.readConfig();
    config.tools = config.tools ?? {};
    config.tools[id] = normalizeToolIntegrationConfig({
      ...config.tools[id],
      ...input,
      displayName: input.displayName ?? config.tools[id]?.displayName,
      values: { ...config.tools[id]?.values, ...input.values },
    });
    this.writeConfig(config);
    return this.getToolIntegrationStatus(id, config.tools[id]);
  }

  saveMcpProfile(profile: McpWrapperProfile): McpWrapperProfileSummary {
    const config = this.readConfig();
    config.mcpWrapper = config.mcpWrapper ?? {};
    config.mcpWrapper.profiles = config.mcpWrapper.profiles ?? {};
    config.mcpWrapper.profiles[profile.id] = profile;
    this.writeConfig(config);
    this.writeMcpProfileYaml(profile);
    return {
      ...profile,
      discoveredTools: this.getMcpDiscoveredTools(profile.id, config),
      yamlPath: this.profileYamlPath(profile.id),
    };
  }

  saveMcpDiscoveredTools(
    profileId: string,
    tools: Array<{
      description?: string;
      inputSchema?: Record<string, unknown>;
      name: string;
      serverName: string;
    }>,
    policy?: PolicyFile,
  ): McpDiscoveredTool[] {
    const config = this.readConfig();
    const profile = config.mcpWrapper?.profiles?.[profileId];
    if (!profile)
      throw new Error(`MCP wrapper profile not found: ${profileId}`);
    config.mcpWrapper = config.mcpWrapper ?? {};
    config.mcpWrapper.discoveredTools = {
      ...(config.mcpWrapper.discoveredTools ?? {}),
    };
    for (const tool of tools) {
      config.mcpWrapper.discoveredTools[`${profileId}:${tool.name}`] = {
        description: blankToUndefined(tool.description),
        discoveredAt: new Date().toISOString(),
        inputSchema: tool.inputSchema,
        name: tool.name,
        policyCoverage: policy ? policyCoverage(policy, tool.name) : undefined,
        profileId,
        schemaHash: schemaHash(tool.inputSchema ?? {}),
        serverName: tool.serverName,
      };
    }
    this.writeConfig(config);
    return this.getMcpDiscoveredTools(profileId, config, policy);
  }

  getMcpProfile(profileId: string): McpWrapperProfile | undefined {
    return this.readConfig().mcpWrapper?.profiles?.[profileId];
  }

  generateMcpYaml(profile: McpWrapperProfile): string {
    return YAML.stringify(
      stripUndefined({
        actionproxy: profile.actionproxy,
        policies: profile.policies,
        servers: {
          [profile.server.name]: {
            args: profile.server.args,
            command: profile.server.command,
            cwd: profile.server.cwd,
            env: profile.server.env,
          },
        },
      }),
    );
  }

  getMcpProfileYaml(profileId: string): string | undefined {
    const profile = this.getMcpProfile(profileId);
    return profile ? this.generateMcpYaml(profile) : undefined;
  }

  private getSlackStatus(
    local: LocalSlackIntegrationConfig | undefined,
  ): SlackIntegrationStatus {
    const disabled = local?.enabled === false;
    const botToken = this.appConfig.slack?.botToken || local?.botToken;
    const approvalChannelId =
      this.appConfig.slack?.approvalChannelId || local?.approvalChannelId;
    const signingSecret =
      this.appConfig.slack?.signingSecret || local?.signingSecret;
    const enabled =
      !disabled &&
      Boolean(local?.enabled || botToken || approvalChannelId || signingSecret);
    const ready = enabled && Boolean(botToken && signingSecret);
    return {
      callbackPath: slackCallbackPath,
      callbackUrl: local?.publicBaseUrl
        ? `${trimTrailingSlash(local.publicBaseUrl)}${slackCallbackPath}`
        : undefined,
      configured: {
        approvalChannelId: Boolean(approvalChannelId),
        botToken: Boolean(botToken),
        signingSecret: Boolean(signingSecret),
      },
      enabled,
      fields: { approvalChannelId, publicBaseUrl: local?.publicBaseUrl },
      sources: {
        approvalChannelId: fieldSource(
          this.appConfig.slack?.approvalChannelId,
          local?.approvalChannelId,
        ),
        botToken: fieldSource(this.appConfig.slack?.botToken, local?.botToken),
        signingSecret: fieldSource(
          this.appConfig.slack?.signingSecret,
          local?.signingSecret,
        ),
      },
      status: !enabled ? 'disabled' : ready ? 'ready' : 'partial',
    };
  }

  private getTelegramStatus(
    local: LocalTelegramIntegrationConfig | undefined,
  ): TelegramIntegrationStatus {
    const disabled = local?.enabled === false;
    const approvalChatId =
      this.appConfig.telegram?.approvalChatId || local?.approvalChatId;
    const botToken = this.appConfig.telegram?.botToken || local?.botToken;
    const publicBaseUrl =
      this.appConfig.telegram?.publicBaseUrl || local?.publicBaseUrl;
    const webhookSecret =
      this.appConfig.telegram?.webhookSecret || local?.webhookSecret;
    const enabled =
      !disabled &&
      Boolean(
        local?.enabled ||
          approvalChatId ||
          botToken ||
          publicBaseUrl ||
          webhookSecret,
      );
    const ready = enabled && Boolean(botToken && webhookSecret);
    return {
      callbackPath: telegramCallbackPath,
      callbackUrl: publicBaseUrl
        ? `${trimTrailingSlash(publicBaseUrl)}${telegramCallbackPath}`
        : undefined,
      configured: {
        approvalChatId: Boolean(approvalChatId),
        botToken: Boolean(botToken),
        webhookSecret: Boolean(webhookSecret),
      },
      enabled,
      fields: { approvalChatId, publicBaseUrl },
      sources: {
        approvalChatId: fieldSource(
          this.appConfig.telegram?.approvalChatId,
          local?.approvalChatId,
        ),
        botToken: fieldSource(
          this.appConfig.telegram?.botToken,
          local?.botToken,
        ),
        publicBaseUrl: fieldSource(
          this.appConfig.telegram?.publicBaseUrl,
          local?.publicBaseUrl,
        ),
        webhookSecret: fieldSource(
          this.appConfig.telegram?.webhookSecret,
          local?.webhookSecret,
        ),
      },
      status: !enabled ? 'disabled' : ready ? 'ready' : 'partial',
    };
  }

  private getEmailStatus(
    local: LocalEmailIntegrationConfig | undefined,
  ): EmailIntegrationStatus {
    const disabled = local?.enabled === false;
    const transport =
      this.appConfig.email?.transport ?? local?.transport ?? 'outbox';
    const approvalRecipient =
      this.appConfig.email?.approvalRecipient || local?.approvalRecipient;
    const from = this.appConfig.email?.from || local?.from;
    const environmentPublicBaseUrl = safeEmailPublicBaseUrl(
      this.appConfig.email?.publicBaseUrl,
    );
    const localPublicBaseUrl = safeEmailPublicBaseUrl(local?.publicBaseUrl);
    const defaultPublicBaseUrl = isLocalDeployment(this.appConfig)
      ? localEmailPublicBaseUrl(this.appConfig.port)
      : undefined;
    const publicBaseUrl =
      environmentPublicBaseUrl || localPublicBaseUrl || defaultPublicBaseUrl;
    const publicBaseUrlSource: ConfigSource = environmentPublicBaseUrl
      ? 'env'
      : localPublicBaseUrl
        ? 'local'
        : defaultPublicBaseUrl
          ? 'default'
          : 'missing';
    const smtpHost = this.appConfig.email?.smtp?.host || local?.smtp?.host;
    const smtpPort = this.appConfig.email?.smtp?.port || local?.smtp?.port;
    const smtpSecure =
      this.appConfig.email?.smtp?.secure ?? local?.smtp?.secure;
    const smtpUsername =
      this.appConfig.email?.smtp?.username || local?.smtp?.username;
    const smtpPassword =
      this.appConfig.email?.smtp?.password || local?.smtp?.password;
    const enabled =
      !disabled &&
      Boolean(local?.enabled || approvalRecipient || from || smtpHost);
    const ready =
      enabled &&
      Boolean(publicBaseUrl) &&
      (transport === 'smtp'
        ? Boolean(from && smtpHost && smtpPort)
        : Boolean(from));
    return {
      configured: {
        approvalRecipient: Boolean(approvalRecipient),
        from: Boolean(from),
        publicBaseUrl: Boolean(publicBaseUrl),
        smtpHost: Boolean(smtpHost),
        smtpPassword: Boolean(smtpPassword),
        smtpPort: Boolean(smtpPort),
      },
      enabled,
      fields: {
        approvalRecipient,
        from,
        publicBaseUrl,
        smtpHost,
        smtpPort,
        smtpSecure,
        smtpUsername,
        transport,
      },
      outboxDir: path.join(this.appConfig.dataDir, 'outbox', 'email'),
      sources: {
        approvalRecipient: fieldSource(
          this.appConfig.email?.approvalRecipient,
          local?.approvalRecipient,
        ),
        from: fieldSource(this.appConfig.email?.from, local?.from),
        publicBaseUrl: publicBaseUrlSource,
        smtpHost: fieldSource(
          this.appConfig.email?.smtp?.host,
          local?.smtp?.host,
        ),
        smtpPassword: fieldSource(
          this.appConfig.email?.smtp?.password,
          local?.smtp?.password,
        ),
        smtpPort: fieldSource(
          this.appConfig.email?.smtp?.port?.toString(),
          local?.smtp?.port?.toString(),
        ),
      },
      status: !enabled ? 'disabled' : ready ? 'ready' : 'partial',
    };
  }

  private getMcpDiscoveredTools(
    profileId: string,
    config: LocalIntegrationConfig,
    policy?: PolicyFile,
  ): McpDiscoveredTool[] {
    return Object.values(config.mcpWrapper?.discoveredTools ?? {})
      .filter((tool) => tool.profileId === profileId)
      .map((tool) => ({
        ...tool,
        policyCoverage: policy
          ? policyCoverage(policy, tool.name)
          : tool.policyCoverage,
      }))
      .sort((left, right) => left.name.localeCompare(right.name));
  }

  private getToolIntegrationStatuses(
    local:
      | Partial<Record<ToolIntegrationId, LocalToolIntegrationConfig>>
      | undefined,
  ): ToolIntegrationStatus[] {
    return toolIntegrationIds.map((id) =>
      this.getToolIntegrationStatus(id, local?.[id]),
    );
  }

  private getToolIntegrationStatus(
    id: ToolIntegrationId,
    local: LocalToolIntegrationConfig | undefined,
  ): ToolIntegrationStatus {
    const catalog = toolIntegrationCatalog[id];
    const values = local?.values ?? {};
    const fields = toolIntegrationFields[id].map((field) => ({
      ...field,
      value: values[field.key],
    }));
    const enabled = local?.enabled === true;
    const hasValues = fields.some((field) => Boolean(field.value));
    return {
      ...catalog,
      displayName: local?.displayName || catalog.name,
      enabled,
      fields,
      status: enabled ? 'ready' : hasValues ? 'partial' : 'disabled',
    };
  }

  private readConfig(): LocalIntegrationConfig {
    if (!fs.existsSync(this.configPath)) return {};
    try {
      const parsed = JSON.parse(fs.readFileSync(this.configPath, 'utf8'));
      return isRecord(parsed)
        ? normalizeLocalIntegrationConfig(parsed)
        : {};
    } catch {
      return {};
    }
  }

  private writeConfig(config: LocalIntegrationConfig): void {
    fs.mkdirSync(path.dirname(this.configPath), { recursive: true });
    fs.writeFileSync(
      this.configPath,
      `${JSON.stringify(normalizeLocalIntegrationConfig(config), null, 2)}\n`,
      'utf8',
    );
  }

  private writeMcpProfileYaml(profile: McpWrapperProfile): void {
    fs.mkdirSync(this.profileDir(profile.id), { recursive: true });
    fs.writeFileSync(
      this.profileYamlPath(profile.id),
      this.generateMcpYaml(profile),
      'utf8',
    );
  }

  private profileDir(profileId: string): string {
    return path.join(this.mcpDir, profileId);
  }

  private profileYamlPath(profileId: string): string {
    return path.join(this.profileDir(profileId), 'actionproxy.mcp.yaml');
  }
}

function normalizeLocalIntegrationConfig(
  input: Record<string, unknown> | LocalIntegrationConfig,
): LocalIntegrationConfig {
  const email = isRecord(input.email)
    ? normalizeEmailIntegrationConfig(input.email as LocalEmailIntegrationConfig)
    : undefined;
  const slack = isRecord(input.slack)
    ? normalizeSlackIntegrationConfig(input.slack as LocalSlackIntegrationConfig)
    : undefined;
  const telegram = isRecord(input.telegram)
    ? normalizeTelegramIntegrationConfig(
        input.telegram as LocalTelegramIntegrationConfig,
      )
    : undefined;
  const rawToolConfig = isRecord(input.tools) ? input.tools : undefined;
  const tools = rawToolConfig
    ? Object.fromEntries(
        toolIntegrationIds.flatMap((id) => {
          const value = rawToolConfig[id];
          return isRecord(value)
            ? [[id, normalizeToolIntegrationConfig(value)]]
            : [];
        }),
      )
    : undefined;
  const rawMcp = isRecord(input.mcpWrapper) ? input.mcpWrapper : undefined;
  const rawProfiles = isRecord(rawMcp?.profiles) ? rawMcp.profiles : undefined;
  const rawTools = isRecord(rawMcp?.discoveredTools)
    ? rawMcp.discoveredTools
    : undefined;
  const profiles = rawProfiles
    ? Object.fromEntries(
        Object.entries(rawProfiles).flatMap(([profileId, value]) =>
          isRecord(value)
            ? [
                [
                  profileId,
                  normalizeMcpWrapperProfile(
                    profileId,
                    value as unknown as McpWrapperProfile,
                  ),
                ],
              ]
            : [],
        ),
      )
    : undefined;
  const discoveredTools = rawTools
    ? Object.fromEntries(
        Object.entries(rawTools).filter(([, value]) => isRecord(value)),
      ) as Record<string, McpDiscoveredTool>
    : undefined;
  return {
    ...(email ? { email } : {}),
    ...(rawMcp ? { mcpWrapper: { discoveredTools, profiles } } : {}),
    ...(slack ? { slack } : {}),
    ...(telegram ? { telegram } : {}),
    ...(tools && Object.keys(tools).length ? { tools } : {}),
  };
}

function normalizeMcpWrapperProfile(
  profileId: string,
  profile: McpWrapperProfile,
): McpWrapperProfile {
  return { ...profile, id: profile.id ?? profileId };
}

function normalizeSlackIntegrationConfig(
  input: LocalSlackIntegrationConfig,
): LocalSlackIntegrationConfig {
  return {
    approvalChannelId: blankToUndefined(input.approvalChannelId),
    botToken: blankToUndefined(input.botToken),
    enabled: input.enabled,
    publicBaseUrl: blankToUndefined(input.publicBaseUrl),
    signingSecret: blankToUndefined(input.signingSecret),
  };
}

function normalizeTelegramIntegrationConfig(
  input: LocalTelegramIntegrationConfig,
): LocalTelegramIntegrationConfig {
  return {
    approvalChatId: blankToUndefined(input.approvalChatId),
    botToken: blankToUndefined(input.botToken),
    enabled: input.enabled,
    publicBaseUrl: blankToUndefined(input.publicBaseUrl),
    webhookSecret: blankToUndefined(input.webhookSecret),
  };
}

function normalizeEmailIntegrationConfig(
  input: LocalEmailIntegrationConfig,
): LocalEmailIntegrationConfig {
  return {
    approvalRecipient: blankToUndefined(input.approvalRecipient),
    enabled: input.enabled,
    from: blankToUndefined(input.from),
    publicBaseUrl: normalizeEmailPublicBaseUrl(input.publicBaseUrl),
    smtp: input.smtp
      ? {
          host: blankToUndefined(input.smtp.host),
          password: blankToUndefined(input.smtp.password),
          port: input.smtp.port,
          secure: input.smtp.secure,
          username: blankToUndefined(input.smtp.username),
        }
      : undefined,
    transport: input.transport === 'smtp' ? 'smtp' : 'outbox',
  };
}

function normalizeToolIntegrationConfig(
  input: LocalToolIntegrationConfig,
): LocalToolIntegrationConfig {
  const values = Object.fromEntries(
    Object.entries(input.values ?? {})
      .map(([key, value]) => [key, value.trim()] as const)
      .filter(([, value]) => Boolean(value)),
  );
  return {
    displayName: blankToUndefined(input.displayName),
    enabled: input.enabled,
    values: Object.keys(values).length ? values : undefined,
  };
}

function fieldSource(
  environmentValue: string | undefined,
  localValue: string | undefined,
): ConfigSource {
  if (environmentValue) return 'env';
  if (localValue) return 'local';
  return 'missing';
}

function isLocalDeployment(config: AppConfig): boolean {
  const mode =
    config.deployment?.mode ??
    ((config.auth?.mode ?? 'none') === 'none' ? 'local' : 'self_hosted');
  return mode === 'local';
}

function safeEmailPublicBaseUrl(value: string | undefined): string | undefined {
  try {
    return normalizeEmailPublicBaseUrl(value);
  } catch {
    return undefined;
  }
}

function approvalChannelFromSlack(
  slack: SlackIntegrationStatus,
): ApprovalChannelStatus {
  return {
    default: true,
    description: 'Slack approval cards with signed interactive callbacks.',
    displayName: 'Slack approvals',
    enabled: slack.enabled,
    id: 'slack.default',
    provider: 'slack',
    status: slack.status,
  };
}

function approvalChannelFromTelegram(
  telegram: TelegramIntegrationStatus,
): ApprovalChannelStatus {
  return {
    default: true,
    description: 'Telegram bot approval cards with inline callback buttons.',
    displayName: 'Telegram approvals',
    enabled: telegram.enabled,
    id: 'telegram.default',
    provider: 'telegram',
    status: telegram.status,
  };
}

function approvalChannelFromEmail(
  email: EmailIntegrationStatus,
): ApprovalChannelStatus {
  return {
    default: true,
    description: 'Email notifications with a link to the approval page.',
    displayName: 'Email approvals',
    enabled: email.enabled,
    id: 'email.default',
    provider: 'email',
    status: email.status,
  };
}

function policyCoverage(
  policy: PolicyFile,
  toolName: string,
): NonNullable<McpDiscoveredTool['policyCoverage']> {
  const evaluation = evaluatePolicy(policy, toolName);
  return {
    approval: evaluation.approval,
    decision: evaluation.decision,
    matchedRule: evaluation.matchedRule,
    reason: evaluation.reason,
    risk: evaluation.risk,
  };
}

function schemaHash(inputSchema: Record<string, unknown>): string {
  return createHash('sha256')
    .update(JSON.stringify(inputSchema))
    .digest('hex')
    .slice(0, 16);
}

function blankToUndefined(value: string | undefined): string | undefined {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/u, '');
}

function stripUndefined(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripUndefined);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, entry]) => entry !== undefined)
      .map(([key, entry]) => [key, stripUndefined(entry)]),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
