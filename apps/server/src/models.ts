export type JsonObject = Record<string, unknown>;

export type PolicyDecision = 'allow' | 'require_approval' | 'deny';
export type ToolCallStatus =
  | 'submitted'
  | 'authorized'
  | 'executed'
  | 'pending_approval'
  | 'blocked'
  | 'rejected'
  | 'failed';
export type ApprovalStatus = 'pending' | 'approved' | 'cancelled' | 'expired' | 'rejected';
export type PrincipalType = 'local' | 'service_account' | 'slack' | 'telegram' | 'user';
export type ObservedToolSource = 'local_demo' | 'mcp_discovery' | 'runtime';
export type ObservedToolStatus = 'dismissed' | 'resolved' | 'unresolved';
export type ObservedToolMatchType = 'default' | 'exact' | 'wildcard';
export type ActionProtocol =
  | 'actionproxy_http'
  | 'cli'
  | 'custom'
  | 'langgraph'
  | 'mcp'
  | 'n8n'
  | 'openai_tools'
  | 'webhook';
export type ActionExecutionMode = 'external_grant' | 'local_mock';
export type ActionOperationKind = 'custom' | 'delete' | 'external_send' | 'financial' | 'read' | 'write';
export type ReceiptDecisionKind = 'human_approval' | 'policy_allow';
export type ReceiptOutcomeStatus = 'failed' | 'succeeded';
export type RemediationKind = 'compensating_action' | 'exact_revert' | 'not_reversible' | 'soft_revert';
export type RemediationStatus = 'available' | 'unavailable';
export interface AuthContext {
  principalId: string;
  principalType: PrincipalType;
  displayName: string;
  email?: string;
  groups: string[];
  scopes: string[];
  authProvider: 'api_key' | 'none' | 'oidc_jwt' | 'slack' | 'telegram';
  /** OAuth client identity verified from a signed access token. Never caller metadata. */
  clientId?: string;
  workspaceId: string;
}

export interface SubmitToolCallRequest {
  toolName: string;
  input: JsonObject;
  requestedBy: string;
  agentId: string;
  reason: string;
  action?: SubmitActionEnvelopeHints;
  metadata?: JsonObject;
}

export interface SubmitActionEnvelopeHints {
  context?: Partial<ActionEnvelope['context']>;
  executionMode?: ActionExecutionMode;
  operation?: Partial<ActionEnvelope['operation']>;
  protocol?: ActionProtocol;
  resources?: ActionResourceHint[];
  source?: Partial<ActionEnvelope['source']>;
}

export interface ActionActor {
  authProvider?: AuthContext['authProvider'];
  displayName?: string;
  email?: string;
  id: string;
  type: PrincipalType | 'unknown';
}

export interface ActionAgent {
  id: string;
  name?: string;
}

export interface ActionResourceHint {
  id?: string;
  metadata?: JsonObject;
  name?: string;
  type: string;
  url?: string;
}

export interface ActionEnvelope {
  actor: ActionActor;
  agent: ActionAgent;
  context: {
    dataClassification?: string;
    metadata?: JsonObject;
    reason: string;
    reversibility?: string;
    risk?: string;
    sideEffects?: string;
  };
  envelopeHash: string;
  executionMode: ActionExecutionMode;
  input: JsonObject;
  inputHash: string;
  operation: {
    kind?: ActionOperationKind;
    name: string;
  };
  protocol: ActionProtocol;
  resources?: ActionResourceHint[];
  source: {
    id?: string;
    metadata?: JsonObject;
    name?: string;
    type: string;
  };
  toolName: string;
  version: 'actionproxy.action.v1';
}

export interface ToolCallRecord {
  id: string;
  workspaceId?: string;
  toolName: string;
  input: JsonObject;
  inputHash?: string;
  actionEnvelope?: ActionEnvelope;
  actionEnvelopeHash?: string;
  canonicalActionRequestHash?: string;
  canonicalActionRequestVersion?: 'actionproxy.action-request.v1';
  canonicalDecisionInputHash?: string;
  canonicalPolicyContext?: import('./contracts/action-request').CanonicalPolicyContext;
  contentInfluence?: import('./contracts/content-influence').ContentInfluenceEvidenceV1;
  influenceScopeId?: string;
  requestedBy: string;
  requestedByAuth?: AuthContext;
  agentId: string;
  reason: string;
  metadata: JsonObject;
  status: ToolCallStatus;
  decision?: PolicyDecision;
  authorizationDecision?: PolicyDecision;
  authorizationReason?: string;
  decisionTrace?: JsonObject;
  policyReason?: string;
  policyVersionId?: string;
  policyVersionHash?: string;
  resultDelivery?: ResultDeliveryMetadataV1;
  resultSource?: import('./policy/policy-types').PolicyRule['resultSource'];
  resultWithheld?: boolean;
  risk?: string;
  result?: unknown;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export interface RemediationDescriptor {
  action?: SubmitActionEnvelopeHints;
  evidence?: JsonObject;
  input?: JsonObject;
  kind: RemediationKind;
  metadata?: JsonObject;
  reason: string;
  status: RemediationStatus;
  toolName?: string;
}

export interface RemediationPlan {
  originalToolCall: ToolCallRecord;
  receipt?: ActionReceiptRecord;
  relatedToolCalls: ToolCallRecord[];
  remediation: RemediationDescriptor;
}

export interface ApprovalDecisionRecord {
  actor: string;
  auth?: AuthContext;
  authorizationHash?: string;
  authorizationNonce?: string;
  authorizationVersion?: 'actionproxy.approval-authorization.v1';
  approvedEnvelopeHash?: string;
  approvedInputHash?: string;
  decisionId?: string;
  decidedAt: string;
  editedInput?: JsonObject;
  inputDecision?: 'edited' | 'original';
  note?: string;
  reviewHash?: string;
}

export interface ApprovalRecord {
  id: string;
  workspaceId?: string;
  toolCallId: string;
  status: ApprovalStatus;
  requestedBy: string;
  requestedByAuth?: AuthContext;
  authorization?: import('./contracts/approval-authorization').ApprovalAuthorizationV1;
  authorizationConsumedAt?: string;
  authorizationConsumedReason?: 'approved' | 'cancelled' | 'expired' | 'rejected';
  approvedBy?: string;
  cancelledAt?: string;
  cancelledBy?: string;
  cancellationReason?: string;
  expiredAt?: string;
  finalizedAt?: string;
  rejectedBy?: string;
  note?: string;
  rejectionReason?: string;
  originalInput: JsonObject;
  originalEnvelopeHash?: string;
  originalInputHash?: string;
  editedInput?: JsonObject;
  approvedEnvelopeHash?: string;
  approvedInputHash?: string;
  reviewHash?: string;
  approverUsers?: string[];
  approverGroups?: string[];
  requiredApprovals?: number;
  separationOfDuties?: boolean;
  decisions?: ApprovalDecisionRecord[];
  createdAt: string;
  updatedAt: string;
}

export type ApprovalNotificationProvider = 'email' | 'slack' | 'telegram';
export type ApprovalDeliveryStatus = 'failed' | 'sent';

export interface ApprovalDeliveryRecord {
  id: string;
  workspaceId?: string;
  approvalId: string;
  toolCallId: string;
  channelId: string;
  provider: ApprovalNotificationProvider;
  status: ApprovalDeliveryStatus;
  messageId?: string;
  destination?: string;
  error?: string;
  recipientEmail?: string;
  recipientSlackUserId?: string;
  recipientTelegramChatId?: string;
  recipientTelegramUserId?: string;
  recipientUserId?: string;
  data: JsonObject;
  createdAt: string;
  updatedAt: string;
}

export interface ApproverUserRecord {
  id: string;
  workspaceId: string;
  displayName: string;
  email?: string;
  principalId?: string;
  slackUserId?: string;
  telegramChatId?: string;
  telegramUsername?: string;
  telegramUserId?: string;
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

export interface ServiceAccountRecord {
  id: string;
  workspaceId: string;
  name: string;
  description?: string;
  groups: string[];
  scopes: string[];
  createdAt: string;
  updatedAt: string;
  revokedAt?: string;
}

export interface ApiKeyRecord {
  id: string;
  workspaceId: string;
  serviceAccountId: string;
  keyPrefix: string;
  keyHash: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt?: string;
  revokedAt?: string;
}

export interface WorkspaceRecord {
  id: string;
  name: string;
  createdAt: string;
}

export interface WorkspaceUserRecord {
  id: string;
  workspaceId: string;
  principalId: string;
  displayName: string;
  email?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ExecutionGrantRecord {
  id: string;
  workspaceId: string;
  toolCallId: string;
  toolName: string;
  inputHash: string;
  approvedEnvelopeHash?: string;
  approvedInputHash?: string;
  policyVersionHash?: string;
  receiptHash?: string;
  receiptId?: string;
  actor: string;
  auth?: AuthContext;
  expiresAt: string;
  nonce: string;
  signature: string;
  consumedAt?: string;
  createdAt: string;
}

export interface ActionReceiptOutcome {
  auth?: AuthContext;
  error?: string;
  recordedAt: string;
  recordedBy: string;
  remediation?: RemediationDescriptor;
  result?: JsonObject;
  resultDelivery?: ResultDeliveryMetadataV1;
  status: ReceiptOutcomeStatus;
}

export interface ResultDeliveryMetadataV1 {
  byteCount: number;
  canonicalResultHash: string;
  modelVisible: boolean;
  version: 'actionproxy.result-delivery.v1';
}

export interface ActionReceiptRecord {
  approvalId?: string;
  approvedEnvelopeHash: string;
  approvedInputHash: string;
  createdAt: string;
  decisionActor: string;
  decisionAuth?: AuthContext;
  decisionKind: ReceiptDecisionKind;
  executionMode: ActionExecutionMode;
  expiresAt?: string;
  id: string;
  issuedAt: string;
  keyId: string;
  operation: ActionEnvelope['operation'];
  originalEnvelopeHash: string;
  originalInputHash: string;
  outcome?: ActionReceiptOutcome;
  policyDecision?: PolicyDecision;
  policyReason?: string;
  policyRisk?: string;
  policyVersionHash?: string;
  policyVersionId?: string;
  protocol: ActionProtocol;
  receiptHash: string;
  reviewHash?: string;
  signature: string;
  signatureAlg: 'HMAC-SHA256';
  source: ActionEnvelope['source'];
  toolCallId: string;
  toolName: string;
  version: 'actionproxy.receipt.v1';
  workspaceId: string;
}

export interface IdempotencyRecord {
  key: string;
  workspaceId: string;
  route: string;
  requestHash: string;
  toolCallId: string;
  createdAt: string;
}

export interface ObservedToolCoverage {
  approval: PolicyRuleApproval;
  decision: PolicyDecision;
  matchType: ObservedToolMatchType;
  matchedRule: string;
  reason: string;
  risk: string;
  status: 'covered' | 'uncovered';
}

export interface ObservedToolSuggestion {
  approval: PolicyRuleApproval;
  confidence: 'high' | 'low' | 'medium';
  pattern: string;
  patternType: 'exact' | 'wildcard';
  reason: string;
  resultSource?: import('./policy/policy-types').PolicyRule['resultSource'];
  risk: string;
}

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
    reviewState: 'needs_review' | 'reviewed';
  };
  schemaHash?: string;
  coverage: ObservedToolCoverage;
  status: ObservedToolStatus;
  suggestion: ObservedToolSuggestion;
  createdAt: string;
  updatedAt: string;
}

export type PolicyRuleApproval = 'deny' | 'never' | 'required';

export interface AuditEvent {
  id: string;
  type:
    | 'action.envelope_created'
    | 'tool_call.submitted'
    | 'tool_call.authorized'
    | 'policy.allow'
    | 'policy.require_approval'
    | 'policy.deny'
    | 'policy.updated'
    | 'approval.created'
    | 'approval.review_rendered'
    | 'approval.approval_recorded'
    | 'approval.approved'
    | 'approval.cancelled'
    | 'approval.expired'
    | 'approval.rejected'
    | 'execution_grant.created'
    | 'execution_grant.consumed'
    | 'execution_grant.rejected'
    | 'execution.attempt_reserved'
    | 'execution.attempt_dispatched'
    | 'execution.attempt_completed'
    | 'receipt.created'
    | 'receipt.outcome_recorded'
    | 'content.exposure_recorded'
    | 'content.influence_evaluated'
    | 'content.influence_approval_required'
    | 'content.influence_denied'
    | 'content.influence_binding_stale'
    | 'content.result_withheld'
    | 'remediation.plan_rendered'
    | 'remediation.submitted'
    | 'approval_notification.sent'
    | 'approval_notification.failed'
    | 'approver_directory.updated'
    | 'service_account.created'
    | 'api_key.created'
    | 'audit.verify'
    | 'tool_call.executed'
    | 'tool_call.failed'
    | 'slack.approval_notification.sent'
    | 'slack.approval_notification.failed'
    | 'email.approval_notification.sent'
    | 'email.approval_notification.failed'
    | 'telegram.approval_notification.sent'
    | 'telegram.approval_notification.failed'
    | 'slack.interaction.approved'
    | 'slack.interaction.rejected'
    | 'slack.interaction.failed'
    | 'telegram.interaction.approved'
    | 'telegram.interaction.rejected'
    | 'telegram.interaction.failed'
    | 'integration.slack.updated'
    | 'integration.slack.test_sent'
    | 'integration.slack.test_failed'
    | 'integration.telegram.updated'
    | 'integration.telegram.test_sent'
    | 'integration.telegram.test_failed'
    | 'integration.email.updated'
    | 'integration.email.test_sent'
    | 'integration.email.test_failed'
    | 'integration.tool.updated'
    | 'integration.mcp_profile.saved'
    | 'integration.mcp_profile.tools_synced'
    | 'policy_detector.dismissed'
    | 'policy_detector.schema_changed'
    | 'policy_detector.tool_observed';
  workspaceId?: string;
  toolCallId?: string;
  approvalId?: string;
  actor?: string;
  auth?: AuthContext;
  inputHash?: string;
  policyVersionId?: string;
  policyVersionHash?: string;
  previousEventHash?: string;
  eventHash?: string;
  timestamp: string;
  data: JsonObject;
}
