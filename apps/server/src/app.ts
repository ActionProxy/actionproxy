import Fastify from 'fastify';
import { assertSafeStartupConfig, unsafeLocalBindWarning, withConfigDefaults, type AppConfig } from './config';
import { loadPolicy } from './policy/load-policy';
import { PolicyManager } from './policy/policy-manager';
import type { DeterministicPolicyProvider } from './policy/policy-provider';
import { LocalDevStore } from './storage/local-dev-store';
import { JsonlAuditStore } from './storage/jsonl-audit-store';
import { SqliteStore } from './storage/sqlite-store';
import { PostgresStore } from './storage/postgres-store';
import type { PolicyVersionStore } from './storage/migrate';
import type { Store } from './storage/store';
import type { AuditStore } from './storage/audit-store';
import { ToolRegistry } from './services/tool-registry';
import { registerMockTools } from './tools/mock-tools';
import { ActionProxyService } from './services/action-gate';
import { registerHealthRoutes } from './routes/health';
import { registerToolCallRoutes } from './routes/tool-calls';
import { registerApprovalRoutes } from './routes/approvals';
import { registerAuditRoutes } from './routes/audit';
import { registerAuthorizedActionRoutes } from './routes/authorized-actions';
import { registerPolicyRoutes } from './routes/policy';
import { registerPolicyDetectorRoutes } from './routes/policy-detector';
import { registerSlackRoutes } from './routes/slack';
import { registerTelegramRoutes } from './routes/telegram';
import { registerIntegrationRoutes } from './routes/integrations';
import { registerAuthRoutes } from './routes/auth';
import { registerExecutionGrantRoutes } from './routes/execution-grants';
import { registerReceiptRoutes } from './routes/receipts';
import { registerApproverRoutes } from './routes/approvers';
import { registerDashboardRoutes } from './routes/dashboard';
import { registerWebAppRoutes } from './routes/web';
import { registerMcpRoutes } from './routes/mcp';
import { registerQuickstartStatusRoutes } from './routes/quickstart-status';
import { IntegrationConfigService } from './integrations/integration-config';
import { ApprovalNotificationFanout } from './integrations/approval-notifications';
import { EmailService } from './integrations/email/email-service';
import { SlackService } from './integrations/slack/slack-service';
import { TelegramService } from './integrations/telegram/telegram-service';
import { ApproverDirectoryService } from './services/approver-directory';
import { PolicyDetectorService } from './services/policy-detector';
import { AuthService } from './security/auth-service';
import { ChainedAuditStore } from './security/audit-chain';
import { hashJson } from './security/crypto';
import { ExecutionGrantService } from './security/execution-grants';
import { registerSecurityHooks } from './security/http-security';
import { redactionOptionsFromPolicy } from './security/redaction';
import { createTelemetryRecorder } from './telemetry/telemetry';
import { createExecutionAuthorizationAuthority } from './contracts/execution-authorization';
import type { ActionProxyAppContext } from './app-context';
import { QuickstartStatusService } from './services/quickstart-status';

export interface BuildAppOverrides {
  /** Test/conformance seam; production uses the built-in deterministic YAML provider. */
  policyProvider?: DeterministicPolicyProvider;
  /** Test/conformance seam for bounded executor and failure-injection coverage. */
  registerTools?: (tools: ToolRegistry) => void;
}

export interface AppExtension<Modules> {
  createIntegrationConfig?: (config: ReturnType<typeof withConfigDefaults>) => IntegrationConfigService;
  createModules: (context: ActionProxyAppContext) => Modules | Promise<Modules>;
  registerIntegrationRoutes?: (context: ActionProxyAppContext, modules: Modules) => void | Promise<void>;
  registerRoutes?: (context: ActionProxyAppContext, modules: Modules) => void | Promise<void>;
}

export function buildApp(config: AppConfig, overrides: BuildAppOverrides = {}) {
  return buildComposedApp(config, overrides);
}

export function buildExtendedApp<Modules>(
  config: AppConfig,
  extension: AppExtension<Modules>,
  overrides: BuildAppOverrides = {},
) {
  return buildComposedApp(config, overrides, extension);
}

async function buildComposedApp<Modules>(
  config: AppConfig,
  overrides: BuildAppOverrides,
  extension?: AppExtension<Modules>,
) {
  const resolvedConfig = withConfigDefaults(config);
  assertSafeStartupConfig(resolvedConfig);
  const app = Fastify({ bodyLimit: 1024 * 1024, logger: { level: resolvedConfig.logLevel } });
  const startupWarning = unsafeLocalBindWarning(resolvedConfig);
  if (startupWarning) {
    app.log.warn(startupWarning);
  }

  const policy = loadPolicy(resolvedConfig.policyPath);
  const policyManager = new PolicyManager(resolvedConfig.policyPath, policy);
  const stores = await createStores(resolvedConfig);
  const store = stores.store;
  const auditStore = new ChainedAuditStore(stores.auditStore);
  const telemetry = createTelemetryRecorder(resolvedConfig.telemetry);
  const authService = new AuthService(resolvedConfig.auth, store);
  await authService.ensureWorkspace();
  if (hasCloseHook(store)) {
    app.addHook('onClose', async () => {
      await store.close();
    });
  }
  await recordPolicyVersion(store, policy);
  const localExecutionMode = resolvedConfig.localExecution?.mode ?? 'disabled';
  const executionAuthorizations = createExecutionAuthorizationAuthority();
  const tools = new ToolRegistry(executionAuthorizations);
  if (localExecutionMode === 'mock') {
    registerMockTools(tools);
  }
  overrides.registerTools?.(tools);
  const integrationConfig = extension?.createIntegrationConfig?.(resolvedConfig)
    ?? new IntegrationConfigService(resolvedConfig);
  const approverDirectory = new ApproverDirectoryService(store);
  const policyDetector = new PolicyDetectorService(store, auditStore);
  const slackService = new SlackService(() => integrationConfig.getEffectiveSlackConfig());
  const telegramService = new TelegramService(() => integrationConfig.getEffectiveTelegramConfig());
  const emailService = new EmailService(() => integrationConfig.getEffectiveEmailConfig());
  const approvalChannels = [slackService, telegramService, emailService];
  const approvalNotifier = new ApprovalNotificationFanout(approvalChannels);
  let actionProxy: ActionProxyService;
  const executionGrants = new ExecutionGrantService(
    resolvedConfig.executionGrants,
    store,
    auditStore,
    telemetry,
    () => hashJson(policyManager.getPolicy()),
    executionAuthorizations,
    async (toolCall, input) => {
      await actionProxy.assertExternalDispatchCurrent(toolCall, input);
      return undefined;
    },
  );
  const redaction = redactionOptionsFromPolicy(policy);

  actionProxy = new ActionProxyService({
    approvalNotifier,
    auditStore,
    executionGrants,
    executionAuthorizations,
    policy,
    policyVersionHash: policyHash(policy),
    policyVersionId: `policy_${policyHash(policy).slice(0, 16)}`,
    policyDetector,
    policyProvider: overrides.policyProvider,
    receiptSigningSecret: resolvedConfig.executionGrants.secret,
    store,
    telemetry,
    localExecutionMode,
    approverDirectory,
    tools,
    workspaceId: resolvedConfig.auth.workspaceId,
  });
  const context: ActionProxyAppContext = {
    actionProxy,
    app,
    approverDirectory,
    auditStore,
    authService,
    config: resolvedConfig,
    executionGrants,
    integrationConfig,
    policyDetector,
    policyManager,
    rawAuditStore: stores.auditStore,
    redaction,
    store,
    telemetry,
  };
  const extensionModules = extension
    ? await extension.createModules(context)
    : undefined;
  registerSecurityHooks(app, resolvedConfig, authService);
  await registerHealthRoutes(app);
  if (resolvedConfig.quickstart.enabled) {
    const quickstartStatus = new QuickstartStatusService({
      sessionId: resolvedConfig.quickstart.sessionId!,
      updateToken: resolvedConfig.quickstart.updateToken!,
    });
    await registerQuickstartStatusRoutes(app, quickstartStatus);
  }
  await registerAuthRoutes(app, authService, auditStore);
  await registerToolCallRoutes(app, actionProxy, redaction, {
    environment: resolvedConfig.deployment?.mode ?? 'local',
    quickstart: resolvedConfig.quickstart.enabled
      ? {
          originToken: resolvedConfig.quickstart.originToken!,
          sessionId: resolvedConfig.quickstart.sessionId!,
        }
      : undefined,
  });
  await registerApprovalRoutes(app, actionProxy, redaction);
  await registerAuditRoutes(app, auditStore, redaction, telemetry);
  await registerAuthorizedActionRoutes(app, store);
  await registerPolicyRoutes(app, policyManager, auditStore, {
    approverDirectory,
    environment: resolvedConfig.deployment?.mode ?? 'local',
    policyDetector,
  });
  await registerPolicyDetectorRoutes(app, policyDetector, policyManager, { approverDirectory });
  if (extension?.registerIntegrationRoutes && extensionModules !== undefined) {
    await extension.registerIntegrationRoutes(context, extensionModules);
  } else {
    await registerIntegrationRoutes(app, integrationConfig, auditStore, {
      approverDirectory,
      policyDetector,
      policyManager,
    });
  }
  await registerDashboardRoutes(app, {
    auditStore,
    config: resolvedConfig,
    integrationConfig,
    policyManager,
    redaction,
    store,
  });
  await registerExecutionGrantRoutes(app, executionGrants);
  await registerReceiptRoutes(app, store);
  await registerMcpRoutes(app, {
    actionProxy,
    config: resolvedConfig,
    redaction,
    store,
  });
  await registerApproverRoutes(app, approverDirectory, auditStore, {
    telegram: {
      configProvider: () => integrationConfig.getEffectiveTelegramConfig(),
    },
  });
  await registerSlackRoutes(app, actionProxy, {
    approverDirectory,
    authService,
    signingSecretProvider: () => integrationConfig.getSlackSigningSecret(),
  });
  await registerTelegramRoutes(app, actionProxy, {
    approverDirectory,
    authService,
    configProvider: () => integrationConfig.getEffectiveTelegramConfig(),
  });
  if (extension?.registerRoutes && extensionModules !== undefined) {
    await extension.registerRoutes(context, extensionModules);
  }
  await registerWebAppRoutes(app, resolvedConfig.webDistPath);

  return app;
}

async function createStores(config: AppConfig): Promise<{ auditStore: AuditStore; store: Store }> {
  if (config.storage?.mode === 'sqlite') {
    const sqliteStore = new SqliteStore(config.storage.sqlitePath);
    return { auditStore: sqliteStore, store: sqliteStore };
  }

  if (config.storage?.mode === 'postgres') {
    if (!config.storage.databaseUrl) {
      throw new Error('ACTIONPROXY_STORAGE=postgres requires DATABASE_URL.');
    }
    const postgresStore = await PostgresStore.connect(config.storage.databaseUrl);
    return { auditStore: postgresStore, store: postgresStore };
  }

  return {
    auditStore: new JsonlAuditStore(config.dataDir),
    store: new LocalDevStore(config.approverDirectoryPath ?? `${config.dataDir}/approver-directory.local.json`),
  };
}

async function recordPolicyVersion(store: Store, policy: unknown): Promise<void> {
  if (!hasPolicyVersionStore(store)) return;

  const hash = policyHash(policy).slice(0, 16);
  await store.recordPolicyVersion({
    createdAt: new Date().toISOString(),
    id: `policy_${hash}`,
    policy: policy as Parameters<PolicyVersionStore['recordPolicyVersion']>[0]['policy'],
    version: String((policy as { version?: unknown }).version ?? 'unknown'),
  });
}

function policyHash(policy: unknown): string {
  return hashJson(policy);
}

function hasPolicyVersionStore(store: Store): store is Store & PolicyVersionStore {
  return 'recordPolicyVersion' in store && typeof store.recordPolicyVersion === 'function';
}

function hasCloseHook(store: Store): store is Store & { close: () => Promise<void> } {
  return 'close' in store && typeof store.close === 'function';
}
