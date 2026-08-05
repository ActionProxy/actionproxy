export type JsonObject = Record<string, unknown>;

export type PolicyDecision = "allow" | "require_approval" | "deny";
export type ToolCallStatus =
  | "submitted"
  | "authorized"
  | "executed"
  | "pending_approval"
  | "blocked"
  | "rejected"
  | "failed";
export type ApprovalStatus =
  | "pending"
  | "approved"
  | "cancelled"
  | "expired"
  | "rejected";
export type ApprovalMode = "never" | "required" | "deny";
export type ContentIntegrity =
  | "organization_managed"
  | "verified_publisher"
  | "authenticated_external"
  | "public_untrusted"
  | "unknown";
export type ContentInfluenceSource = ContentIntegrity | "none";

export interface PolicyResultSource {
  integrity: ContentIntegrity;
  sourceId?: string;
}

export interface PolicyInfluenceGuard {
  allowFrom: ContentInfluenceSource[];
  otherwise: "required" | "deny";
}

export interface ContentInfluenceEvidence {
  baseDecision: PolicyDecision;
  bindingHash: string;
  effectiveDecision: PolicyDecision;
  evaluatedAt: string;
  exposureRevision: number;
  exposureSnapshotHash: string;
  influenceScope: { id?: string; verified: boolean };
  observedSources: ContentInfluenceSource[];
  policy: { versionHash: string; versionId?: string };
  selectedRule: PolicyInfluenceGuard;
  sourceCount: number;
  sourceCountIsLowerBound: boolean;
  sourceReferences: Array<{
    integrity: ContentIntegrity;
    sourceId?: string;
    sourceToolCallId: string;
  }>;
  version: "actionproxy.content-influence.v1";
}

export interface ToolCallRecord {
  id: string;
  toolName: string;
  input: JsonObject;
  requestedBy: string;
  agentId: string;
  reason: string;
  metadata: JsonObject;
  status: ToolCallStatus;
  decision?: PolicyDecision;
  contentInfluence?: ContentInfluenceEvidence;
  influenceScopeId?: string;
  inputHash?: string;
  actionEnvelopeHash?: string;
  policyReason?: string;
  policyVersionHash?: string;
  policyVersionId?: string;
  risk?: string;
  result?: unknown;
  resultWithheld?: boolean;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ApprovalRecord {
  id: string;
  toolCallId: string;
  status: ApprovalStatus;
  requestedBy: string;
  approvedBy?: string;
  rejectedBy?: string;
  rejectionReason?: string;
  note?: string;
  originalInput: JsonObject;
  originalEnvelopeHash?: string;
  originalInputHash?: string;
  editedInput?: JsonObject;
  approvedEnvelopeHash?: string;
  approvedInputHash?: string;
  reviewHash?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ApprovalReview {
  actionEnvelope?: {
    actor: { displayName?: string; email?: string; id: string; type: string };
    agent: { id: string; name?: string };
    context: { reason: string; risk?: string; sideEffects?: string };
    envelopeHash: string;
    executionMode: "external_grant" | "local_mock";
    input: JsonObject;
    inputHash: string;
    operation: { kind?: string; name: string };
    protocol: string;
    source: { id?: string; name?: string; type: string };
    toolName: string;
    version: "actionproxy.action.v1";
  };
  approval: ApprovalRecord;
  contentInfluence?: ContentInfluenceEvidence;
  freshness: {
    expiresAt: string;
    renderedAt: string;
    state: "fresh" | "stale" | "warning";
    warnings: Array<{
      code: string;
      message: string;
      severity: "stale" | "warning";
    }>;
  };
  policy: {
    decision?: PolicyDecision;
    reason?: string;
    risk?: string;
    versionHash?: string;
    versionId?: string;
  };
  proposerRationaleTrust?: "untrusted";
  reviewHash: string;
  toolCall: ToolCallRecord;
}

export interface AuditEvent {
  id: string;
  type: string;
  toolCallId?: string;
  approvalId?: string;
  actor?: string;
  eventHash?: string;
  previousEventHash?: string;
  timestamp: string;
  data: JsonObject;
}

export type AuthorizedActionStatus =
  | "completed"
  | "consumed"
  | "expired"
  | "failed"
  | "waiting";

export interface AuthorizedActionSummary {
  approval?: Pick<
    ApprovalRecord,
    | "approvedBy"
    | "createdAt"
    | "id"
    | "rejectedBy"
    | "status"
    | "toolCallId"
    | "updatedAt"
  >;
  grant: {
    consumedAt?: string;
    createdAt: string;
    expiresAt: string;
    id: string;
    inputHash: string;
    toolCallId: string;
    toolName: string;
  };
  status: AuthorizedActionStatus;
  toolCall: Pick<
    ToolCallRecord,
    | "agentId"
    | "createdAt"
    | "decision"
    | "error"
    | "id"
    | "requestedBy"
    | "risk"
    | "status"
    | "toolName"
    | "updatedAt"
  >;
}

export interface PolicySummaryRule {
  approval: ApprovalMode;
  decision: PolicyDecision;
  influence?: PolicyInfluenceGuard;
  matchType: "default" | "exact" | "wildcard";
  pattern: string;
  reason: string;
  resultSource?: "none" | PolicyResultSource;
  risk: string;
}

export interface PolicySummary {
  defaultRule: PolicySummaryRule;
  rules: PolicySummaryRule[];
  version: number;
}

export interface PolicyRule {
  approval: ApprovalMode;
  approvers?: {
    groups?: string[];
    users?: string[];
    requiredApprovals?: number;
    separationOfDuties?: boolean;
  };
  conditions?: Record<string, unknown>;
  externalExecution?: {
    grantTtlSeconds?: number;
    requireGrantConsumption?: boolean;
  };
  influence?: PolicyInfluenceGuard;
  notify?: { channels?: string[] };
  reason?: string;
  redaction?: { fields?: string[]; replacement?: string };
  resultSource?: "none" | PolicyResultSource;
  risk?: string;
}

export interface PolicyFile {
  default: PolicyRule;
  tools: Record<string, PolicyRule>;
  version: number;
}

export type ObservedToolSource = "local_demo" | "mcp_discovery" | "runtime";
export type ObservedToolStatus = "dismissed" | "resolved" | "unresolved";
export type ObservedToolMatchType = "default" | "exact" | "wildcard";

export interface ObservedToolRecord {
  id: string;
  workspaceId: string;
  toolName: string;
  sources: ObservedToolSource[];
  sourceIds: {
    agentIds?: string[];
    mcpProfileIds?: string[];
    mcpServerNames?: string[];
  };
  firstSeenAt: string;
  lastSeenAt: string;
  callCount: number;
  schemaChange?: {
    currentSchemaHash: string;
    previousSchemaHash: string;
    reviewState: "needs_review" | "reviewed";
  };
  schemaHash?: string;
  coverage: {
    approval: ApprovalMode;
    decision: PolicyDecision;
    matchedRule: string;
    matchType: ObservedToolMatchType;
    reason: string;
    risk: string;
    status: "covered" | "uncovered";
  };
  status: ObservedToolStatus;
  suggestion: {
    approval: ApprovalMode;
    confidence: "high" | "low" | "medium";
    pattern: string;
    patternType: "exact" | "wildcard";
    reason: string;
    resultSource?: PolicyRule["resultSource"];
    risk: string;
  };
  createdAt: string;
  updatedAt: string;
}

export interface PolicyDetectorResponse {
  tools: ObservedToolRecord[];
  unresolvedCount: number;
}

export interface PolicyDecisionTrace {
  actionEnvelopeHash?: string;
  approverResolution: {
    configuredGroups: string[];
    configuredUsers: string[];
    defaultApproversUsed: boolean;
    notificationChannels: string[];
    requiredApprovals: number;
    resolvedRecipientCount?: number;
    separationOfDuties: boolean;
    status: "not_required" | "not_resolved" | "resolved" | "resolved_empty";
  };
  contentInfluence?: ContentInfluenceEvidence;
  decision: PolicyDecision;
  fallbackPath: Array<"default" | "exact" | "wildcard">;
  inputHash?: string;
  matchType: "default" | "exact" | "wildcard";
  matchedRule: string;
  policyReason: string;
  policyRisk: string;
  policyVersionHash?: string;
  ruleEvaluations: Array<{
    conditions: Array<{
      actual?: unknown;
      expected: unknown;
      key: string;
      matched: boolean;
    }>;
    conditionsMatched: boolean;
    exists: boolean;
    matchType: "default" | "exact" | "wildcard";
    pattern: string;
    selected: boolean;
  }>;
  toolName: string;
}

export interface PolicySimulationResponse {
  sideEffects: false;
  trace: PolicyDecisionTrace;
}

export interface HealthResponse {
  ok: boolean;
  service: string;
}

export type QuickstartJourney = "local" | "chatgpt";
export type QuickstartSetupStage =
  | "gateway_starting"
  | "gateway_ready"
  | "tunnel_checking"
  | "tunnel_ready"
  | "tunnel_stopped"
  | "failed";
export type QuickstartCheckState =
  | "pending"
  | "running"
  | "pass"
  | "action_required"
  | "fail";

export interface QuickstartSetupDetails {
  composeVersion: string;
  dockerVersion: string;
  nodeVersion: string;
  port: number;
  projectName: string;
  runtimeKeyExcludedFromDocker?: boolean;
}

export interface QuickstartStatus {
  approvalTimeoutMs: number;
  checks: Array<{
    id: string;
    remediationCode?: string;
    state: QuickstartCheckState;
  }>;
  journey: QuickstartJourney;
  schemaVersion: string;
  sessionId: string;
  setupDetails?: QuickstartSetupDetails;
  setupStage: QuickstartSetupStage;
  startedAt: string;
  tunnelUiUrl?: string;
  updatedAt: string;
}

export interface AuditVerification {
  checked: number;
  errors: Array<{
    eventId: string;
    index: number;
    reason: string;
  }>;
  firstEventHash?: string;
  lastEventHash?: string;
  valid: boolean;
}

export type IntegrationStatus = "disabled" | "partial" | "ready";
export type ToolIntegrationId = "docs" | "gmail" | "jira" | "salesforce";

export interface ApprovalChannelStatus {
  default: boolean;
  description: string;
  displayName: string;
  enabled: boolean;
  id: string;
  provider: "email" | "slack" | "telegram" | "web";
  status: IntegrationStatus | "ready";
}

export interface McpDiscoveredTool {
  description?: string;
  discoveredAt: string;
  inputSchema?: JsonObject;
  name: string;
  policyCoverage?: {
    approval: ApprovalMode;
    decision: PolicyDecision;
    matchedRule: string;
    reason: string;
    risk: string;
  };
  profileId: string;
  schemaHash: string;
  serverName: string;
}

export interface McpWrapperProfileSummary {
  actionproxy: {
    agentId?: string;
    approvalPollIntervalMs?: number;
    approvalTimeoutMs?: number;
    baseUrl: string;
    bearerTokenEnv?: string;
    requestedBy?: string;
    requestTimeoutMs?: number;
  };
  discoveredTools: McpDiscoveredTool[];
  id: string;
  name?: string;
  policies?: Record<string, { approval: ApprovalMode }>;
  server: {
    args?: string[];
    command: string;
    cwd?: string;
    env?: Record<string, string>;
    name: string;
  };
  yamlPath: string;
}

export interface ToolIntegrationStatus {
  description: string;
  displayName: string;
  enabled: boolean;
  fields: Array<{
    key: string;
    label: string;
    placeholder?: string;
    value?: string;
  }>;
  id: ToolIntegrationId;
  mode: "mock";
  name: string;
  status: IntegrationStatus;
  tools: string[];
}

export interface IntegrationStatusResponse {
  approvalChannels?: { items: ApprovalChannelStatus[] };
  downstreamToolSources?: {
    mcpWrapper: { profiles: McpWrapperProfileSummary[] };
  };
  localDemoTools?: ToolIntegrationStatus[];
  mcpWrapper: { profiles: McpWrapperProfileSummary[] };
  tools: ToolIntegrationStatus[];
}

export interface ApproverUserRecord {
  id: string;
  workspaceId: string;
  displayName: string;
  email?: string;
  groups: string[];
  defaultApprover: boolean;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ApproverGroupRecord {
  id: string;
  workspaceId: string;
  displayName: string;
  description?: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ApproverDirectoryResponse {
  groups: ApproverGroupRecord[];
  users: ApproverUserRecord[];
}

export interface DashboardData {
  auditEvents: AuditEvent[];
  approvers: ApproverDirectoryResponse | null;
  authorizedActions: AuthorizedActionSummary[];
  health: HealthResponse | null;
  integrations: IntegrationStatusResponse | null;
  pendingApprovals: ApprovalRecord[];
  policy: PolicySummary | null;
  policyDetector: PolicyDetectorResponse | null;
  policyFile: PolicyFile | null;
  toolCalls: ToolCallRecord[];
}
