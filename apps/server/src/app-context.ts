import type { FastifyInstance } from 'fastify';
import type { ResolvedAppConfig } from './config';
import type { IntegrationConfigService } from './integrations/integration-config';
import type { PolicyManager } from './policy/policy-manager';
import type { ChainedAuditStore } from './security/audit-chain';
import type { AuthService } from './security/auth-service';
import type { ExecutionGrantService } from './security/execution-grants';
import type { RedactionOptions } from './security/redaction';
import type { ActionProxyService } from './services/action-gate';
import type { ApproverDirectoryService } from './services/approver-directory';
import type { PolicyDetectorService } from './services/policy-detector';
import type { AuditStore } from './storage/audit-store';
import type { Store } from './storage/store';
import type { TelemetryRecorder } from './telemetry/telemetry';

export interface ActionProxyAppContext {
  actionProxy: ActionProxyService;
  app: FastifyInstance;
  approverDirectory: ApproverDirectoryService;
  auditStore: ChainedAuditStore;
  authService: AuthService;
  config: ResolvedAppConfig;
  executionGrants: ExecutionGrantService;
  integrationConfig: IntegrationConfigService;
  policyDetector: PolicyDetectorService;
  policyManager: PolicyManager;
  redaction: RedactionOptions;
  rawAuditStore: AuditStore;
  store: Store;
  telemetry: TelemetryRecorder;
}
