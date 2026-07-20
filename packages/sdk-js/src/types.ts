import type {
  ApprovalAuthorizationEvidenceV1,
  CanonicalActionRequestVersionV1,
  CanonicalPolicyContextV1,
  PolicyDecisionTraceV1,
} from './contracts';

export type JsonValue = string | number | boolean | null | JsonObject | JsonValue[];
export type JsonObject = Record<string, unknown>;

export type PolicyDecision = 'allow' | 'require_approval' | 'deny';
export type ToolCallStatus = 'submitted' | 'authorized' | 'executed' | 'pending_approval' | 'blocked' | 'rejected' | 'failed';
export type ApprovalStatus = 'pending' | 'approved' | 'cancelled' | 'expired' | 'rejected';
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
export type RemediationKind = 'compensating_action' | 'exact_revert' | 'not_reversible' | 'soft_revert';
export type RemediationStatus = 'available' | 'unavailable';
export type ContentIntegrity =
  | 'organization_managed'
  | 'verified_publisher'
  | 'authenticated_external'
  | 'public_untrusted'
  | 'unknown';
export type ContentInfluenceSource = ContentIntegrity | 'none';

export interface PolicyResultSource {
  integrity: ContentIntegrity;
  sourceId?: string;
}

export interface PolicyInfluenceGuard {
  allowFrom: ContentInfluenceSource[];
  otherwise: 'required' | 'deny';
}

export interface ResultDeliveryMetadataV1 {
  byteCount: number;
  canonicalResultHash: string;
  modelVisible: boolean;
  version: 'actionproxy.result-delivery.v1';
}

export interface ContentInfluenceEvidenceV1 {
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
  version: 'actionproxy.content-influence.v1';
}

export interface SubmitToolCallInput<TInput extends JsonObject = JsonObject> {
  toolName: string;
  input: TInput;
  requestedBy: string;
  agentId: string;
  reason: string;
  action?: SubmitActionEnvelopeHints;
  metadata?: JsonObject;
}

export interface SubmitToolCallOptions {
  /** Caller-supplied replay identity. The server remains authoritative for its tenant scope. */
  idempotencyKey?: string;
}

export interface SubmitActionEnvelopeHints {
  context?: JsonObject;
  executionMode?: ActionExecutionMode;
  operation?: {
    kind?: ActionOperationKind;
    name?: string;
  };
  protocol?: ActionProtocol;
  resources?: Array<{ id?: string; metadata?: JsonObject; name?: string; type: string; url?: string }>;
  source?: {
    id?: string;
    metadata?: JsonObject;
    name?: string;
    type?: string;
  };
}

export interface ActionEnvelope<TInput extends JsonObject = JsonObject> {
  actor: { authProvider?: string; displayName?: string; email?: string; id: string; type: string };
  agent: { id: string; name?: string };
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
  input: TInput;
  inputHash: string;
  operation: { kind?: ActionOperationKind; name: string };
  protocol: ActionProtocol;
  resources?: Array<{ id?: string; metadata?: JsonObject; name?: string; type: string; url?: string }>;
  source: { id?: string; metadata?: JsonObject; name?: string; type: string };
  toolName: string;
  version: 'actionproxy.action.v1';
}

export interface ToolCallRecord<TInput extends JsonObject = JsonObject> {
  id: string;
  workspaceId?: string;
  toolName: string;
  input: TInput;
  actionEnvelope?: ActionEnvelope<TInput>;
  actionEnvelopeHash?: string;
  canonicalActionRequestHash?: string;
  canonicalActionRequestVersion?: CanonicalActionRequestVersionV1;
  canonicalDecisionInputHash?: string;
  canonicalPolicyContext?: CanonicalPolicyContextV1;
  inputHash?: string;
  requestedBy: string;
  agentId: string;
  reason: string;
  metadata: JsonObject;
  status: ToolCallStatus;
  decision?: PolicyDecision;
  authorizationDecision?: PolicyDecision;
  authorizationReason?: string;
  contentInfluence?: ContentInfluenceEvidenceV1;
  decisionTrace?: PolicyDecisionTraceV1;
  influenceScopeId?: string;
  policyReason?: string;
  policyVersionHash?: string;
  policyVersionId?: string;
  resultDelivery?: ResultDeliveryMetadataV1;
  resultSource?: 'none' | PolicyResultSource;
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

export interface RemediationPlan<TInput extends JsonObject = JsonObject> {
  originalToolCall: ToolCallRecord<TInput>;
  receipt?: ActionReceiptRecord;
  relatedToolCalls: ToolCallRecord[];
  remediation: RemediationDescriptor;
}

export interface ApprovalRecord<TInput extends JsonObject = JsonObject> {
  id: string;
  workspaceId?: string;
  toolCallId: string;
  status: ApprovalStatus;
  requestedBy: string;
  authorization?: ApprovalAuthorizationEvidenceV1;
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
  originalInput: TInput;
  originalEnvelopeHash?: string;
  originalInputHash?: string;
  editedInput?: TInput;
  approvedEnvelopeHash?: string;
  approvedInputHash?: string;
  reviewHash?: string;
  approverUsers?: string[];
  approverGroups?: string[];
  requiredApprovals?: number;
  separationOfDuties?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface AuditAuthContext {
  authProvider: 'api_key' | 'none' | 'oidc_jwt' | 'slack' | 'telegram';
  clientId?: string;
  displayName: string;
  email?: string;
  groups: string[];
  principalId: string;
  principalType: 'local' | 'service_account' | 'slack' | 'telegram' | 'user';
  scopes: string[];
  workspaceId: string;
}

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
    | 'execution.attempt_reserved'
    | 'execution.attempt_dispatched'
    | 'execution.attempt_completed'
    | 'execution_grant.created'
    | 'execution_grant.consumed'
    | 'execution_grant.rejected'
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
  auth?: AuditAuthContext;
  inputHash?: string;
  policyVersionId?: string;
  policyVersionHash?: string;
  previousEventHash?: string;
  eventHash?: string;
  timestamp: string;
  data: JsonObject;
}

export interface SubmitToolCallResponse<TInput extends JsonObject = JsonObject> {
  id: string;
  status: ToolCallStatus;
  decision?: PolicyDecision;
  reason?: string;
  risk?: string;
  result?: unknown;
  error?: string;
  approval?: {
    id: string;
    status: ApprovalStatus;
  };
  toolCall: ToolCallRecord<TInput>;
}

export interface ExecutionGrant {
  approvedEnvelopeHash?: string;
  approvedInputHash?: string;
  consumedAt?: string;
  expiresAt: string;
  id: string;
  inputHash: string;
  policyVersionHash?: string;
  receiptHash?: string;
  receiptId?: string;
  toolCallId: string;
  toolName: string;
}

export interface ConsumeExecutionGrantInput<TInput extends JsonObject = JsonObject> {
  input: TInput;
  policyVersionHash?: string;
  toolCallId: string;
  toolName: string;
}

export interface ConsumeExecutionGrantResponse {
  grant: ExecutionGrant;
  ok: true;
}

export interface ActionReceiptRecord {
  approvalId?: string;
  approvedEnvelopeHash: string;
  approvedInputHash: string;
  createdAt: string;
  decisionActor: string;
  decisionKind: 'human_approval' | 'policy_allow';
  executionMode: ActionExecutionMode;
  expiresAt?: string;
  id: string;
  issuedAt: string;
  keyId: string;
  operation: { kind?: ActionOperationKind; name: string };
  originalEnvelopeHash: string;
  originalInputHash: string;
  outcome?: {
    error?: string;
    recordedAt: string;
    recordedBy: string;
    remediation?: RemediationDescriptor;
    result?: JsonObject;
    resultDelivery?: ResultDeliveryMetadataV1;
    status: 'failed' | 'succeeded';
  };
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
  source: { id?: string; metadata?: JsonObject; name?: string; type: string };
  toolCallId: string;
  toolName: string;
  version: 'actionproxy.receipt.v1';
  workspaceId: string;
}

export interface ReportExecutionGrantOutcomeInput {
  error?: string;
  remediation?: RemediationDescriptor;
  result?: JsonObject;
  resultDelivery?: ResultDeliveryMetadataV1;
  status: 'cancelled' | 'failed' | 'succeeded' | 'timed_out' | 'unknown_outcome';
}

export interface ReportExecutionGrantOutcomeResponse<TInput extends JsonObject = JsonObject> {
  grant: ExecutionGrant;
  ok: true;
  receipt?: ActionReceiptRecord;
  toolCall: ToolCallRecord<TInput>;
}

export interface SubmitRemediationInput<TInput extends JsonObject = JsonObject> {
  agentId?: string;
  input?: TInput;
  metadata?: JsonObject;
  reason?: string;
  requestedBy?: string;
}

export interface SubmitRemediationResponse<TInput extends JsonObject = JsonObject> extends SubmitToolCallResponse<TInput> {
  plan: RemediationPlan;
}

export interface ListToolCallsOptions {
  decision?: PolicyDecision;
  limit?: number;
  runId?: string;
  sessionId?: string;
  status?: ToolCallStatus;
  toolName?: string;
}

export interface ListAuditEventsOptions {
  from?: string;
  limit?: number;
  to?: string;
  toolCallId?: string;
}

export interface ExportAuditEventsOptions {
  from?: string;
  to?: string;
  toolCallId?: string;
}

export interface AuditExportResponse {
  count: number;
  events: AuditEvent[];
  exportedAt: string;
  filters: {
    from?: string;
    to?: string;
    toolCallId?: string;
  };
}

export interface ApproveApprovalInput<TInput extends JsonObject = JsonObject> {
  approvalNonce?: string;
  approvedBy: string;
  note?: string;
  inputDecision?: { mode: 'edited'; input: TInput } | { mode: 'original' };
  editedInput?: TInput | null;
  reviewHash?: string;
}

export interface RejectApprovalInput {
  approvalNonce?: string;
  rejectedBy: string;
  reason?: string;
}

export interface CancelApprovalInput {
  approvalNonce?: string;
  cancelledBy: string;
  reason?: string;
}

export interface ActionProxyFetchResponse {
  ok: boolean;
  status: number;
  text(): Promise<string>;
}

export type ActionProxyFetch = (
  url: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  },
) => Promise<ActionProxyFetchResponse>;

export interface ActionProxyClientOptions {
  baseUrl: string;
  apiKey?: string;
  fetch?: ActionProxyFetch;
}

export interface WaitForToolCallOptions {
  intervalMs?: number;
  timeoutMs?: number;
  until?: ToolCallStatus[];
}

export interface RunExternalActionClient {
  consumeExecutionGrant<TInput extends JsonObject = JsonObject>(
    grantId: string,
    input: ConsumeExecutionGrantInput<TInput>,
  ): Promise<ConsumeExecutionGrantResponse>;
  reportExecutionGrantOutcome<TInput extends JsonObject = JsonObject>(
    grantId: string,
    input: ReportExecutionGrantOutcomeInput,
  ): Promise<ReportExecutionGrantOutcomeResponse<TInput>>;
  submitToolCall<TInput extends JsonObject = JsonObject>(
    input: SubmitToolCallInput<TInput>,
    options?: SubmitToolCallOptions,
  ): Promise<SubmitToolCallResponse<TInput>>;
  waitForToolCall<TInput extends JsonObject = JsonObject>(
    id: string,
    options?: WaitForToolCallOptions,
  ): Promise<ToolCallRecord<TInput>>;
}

export interface RunExternalActionInput<TInput extends JsonObject = JsonObject, TResult extends JsonObject = JsonObject> {
  action?: SubmitActionEnvelopeHints;
  agentId: string;
  client: RunExternalActionClient;
  execute: (
    input: TInput,
    context: {
      consumed: ConsumeExecutionGrantResponse;
      toolCall: ToolCallRecord<TInput>;
    },
  ) => Promise<TResult> | TResult;
  input: TInput;
  idempotencyKey?: string;
  metadata?: JsonObject;
  reason: string;
  requestedBy: string;
  toolName: string;
  wait?: WaitForToolCallOptions;
}

export interface RunExternalActionResult<TInput extends JsonObject = JsonObject, TResult extends JsonObject = JsonObject> {
  consumed: ConsumeExecutionGrantResponse;
  outcome: ReportExecutionGrantOutcomeResponse<TInput>;
  result: TResult;
  submitted: SubmitToolCallResponse<TInput>;
  toolCall: ToolCallRecord<TInput>;
}

export interface GatedToolConfig<TInput extends JsonObject = JsonObject> {
  client: {
    submitToolCall(
      input: SubmitToolCallInput<TInput>,
      options?: SubmitToolCallOptions,
    ): Promise<SubmitToolCallResponse<TInput>>;
    waitForToolCall(id: string, options?: WaitForToolCallOptions): Promise<ToolCallRecord<TInput>>;
  };
  toolName: string;
  requestedBy: string;
  agentId: string;
  reason?: string | ((input: TInput) => string);
  idempotencyKey?: string | ((input: TInput) => string | undefined);
  metadata?: JsonObject | ((input: TInput) => JsonObject | undefined);
  waitForFinalStatus?: boolean;
  wait?: WaitForToolCallOptions;
  execute?: (input: TInput) => unknown | Promise<unknown>;
}

export interface GatedToolCallOptions {
  idempotencyKey?: string;
  reason?: string;
  metadata?: JsonObject;
  waitForFinalStatus?: boolean;
  wait?: WaitForToolCallOptions;
}

export type GatedTool<TInput extends JsonObject = JsonObject> = (
  input: TInput,
  options?: GatedToolCallOptions,
) => Promise<SubmitToolCallResponse<TInput>>;
