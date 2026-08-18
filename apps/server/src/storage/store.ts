import type {
  ApiKeyRecord,
  ActionReceiptRecord,
  ApproverGroupRecord,
  ApproverUserRecord,
  ApprovalDeliveryRecord,
  ApprovalDecisionRecord,
  ApprovalRecord,
  ExecutionGrantRecord,
  IdempotencyRecord,
  ObservedToolRecord,
  PolicyDecision,
  ServiceAccountRecord,
  ToolCallRecord,
  ToolCallStatus,
  WorkspaceRecord,
  WorkspaceUserRecord,
} from '../models';
import type { ApprovalAuthorizationV1 } from '../contracts/approval-authorization';
import type {
  ExecutionAttemptOutcomeV1,
  ExecutionAttemptRecordV1,
  ExecutionAttemptState,
} from '../contracts/execution-attempt';
import type { ContentIntegrity } from '../policy/policy-types';

export interface ContentExposureRecord {
  influenceScopeId: string;
  integrity: ContentIntegrity;
  observedAt: string;
  policyVersionHash: string;
  sourceId?: string;
  sourceToolCallId: string;
  workspaceId: string;
}

export interface ListContentExposuresInput {
  influenceScopeId: string;
  limit: number;
  workspaceId: string;
}

export interface ListContentExposuresResult {
  overflow: boolean;
  records: ContentExposureRecord[];
  revision: number;
}

export interface ContentExposureRevisionGuard {
  influenceScopeId: string;
  revision: number;
}

export interface AtomicIdempotentToolCallInput {
  idempotency: IdempotencyRecord;
  toolCall: ToolCallRecord;
}

export type AtomicIdempotentToolCallResult = {
  idempotency: IdempotencyRecord;
  outcome: 'conflict' | 'created' | 'replay';
  toolCall: ToolCallRecord;
};

export type AtomicExecutionAttemptReservationResult = {
  attempt?: ExecutionAttemptRecordV1;
  outcome: 'binding_mismatch' | 'existing' | 'not_found' | 'reserved';
};

export interface AtomicExecutionAttemptTransitionInput {
  attemptId: string;
  expectedState: 'dispatched' | 'reserved';
  nextState: ExecutionAttemptState;
  outcome?: ExecutionAttemptOutcomeV1;
  reservationOwner: string;
  transitionedAt: string;
  workspaceId: string;
  contentExposureRevision?: ContentExposureRevisionGuard;
}

export type AtomicExecutionAttemptTransitionResult = {
  attempt?: ExecutionAttemptRecordV1;
  outcome:
    | 'already_terminal'
    | 'content_influence_mismatch'
    | 'not_found'
    | 'owner_mismatch'
    | 'replay'
    | 'state_mismatch'
    | 'transitioned';
};

export interface AtomicExecutionAttemptGrantBindingInput {
  attemptId: string;
  grantId: string;
  reservationOwner: string;
  updatedAt: string;
  workspaceId: string;
}

export type AtomicExecutionAttemptGrantBindingResult = {
  attempt?: ExecutionAttemptRecordV1;
  outcome: 'already_bound' | 'bound' | 'not_found' | 'owner_mismatch' | 'state_mismatch';
};

export interface AtomicGrantDispatchInput {
  attemptId: string;
  dispatchedAt: string;
  grantId: string;
  reservationOwner: string;
  toolCallId: string;
  workspaceId: string;
  contentExposureRevision?: ContentExposureRevisionGuard;
}

export type AtomicGrantDispatchResult = {
  attempt?: ExecutionAttemptRecordV1;
  grant?: ExecutionGrantRecord;
  outcome:
    | 'attempt_not_found'
    | 'attempt_state_mismatch'
    | 'binding_mismatch'
    | 'content_influence_mismatch'
    | 'dispatched'
    | 'grant_already_consumed'
    | 'grant_not_found';
};

export interface AtomicActionReceiptOutcomeInput {
  outcome: NonNullable<ActionReceiptRecord['outcome']>;
  receiptId: string;
}

export type AtomicActionReceiptOutcomeResult = {
  outcome: 'existing' | 'not_found' | 'recorded';
  receipt?: ActionReceiptRecord;
};

export interface AtomicApprovedExternalAuthorizationPublicationInput {
  approvalId: string;
  attempt: ExecutionAttemptRecordV1;
  grant: ExecutionGrantRecord;
  receipt: ActionReceiptRecord;
  toolCall: ToolCallRecord;
}

export interface AtomicApprovedExternalAuthorizationPublicationResult {
  approval?: ApprovalRecord;
  attempt?: ExecutionAttemptRecordV1;
  grant?: ExecutionGrantRecord;
  outcome: 'binding_mismatch' | 'conflict' | 'created' | 'not_found' | 'replay' | 'state_mismatch';
  receipt?: ActionReceiptRecord;
  toolCall?: ToolCallRecord;
}

export interface AtomicKnownExternalExecutionOutcomeAdoptionInput {
  attemptId: string;
  receipt: ActionReceiptRecord;
  toolCall: ToolCallRecord;
  workspaceId: string;
}

export interface AtomicKnownExternalExecutionOutcomeAdoptionResult {
  attempt?: ExecutionAttemptRecordV1;
  grant?: ExecutionGrantRecord;
  outcome: 'adopted' | 'binding_mismatch' | 'conflict' | 'not_found' | 'reconciliation_required' | 'replay' | 'state_mismatch';
  receipt?: ActionReceiptRecord;
  toolCall?: ToolCallRecord;
}

export interface AtomicKnownExternalExecutionOutcomeRecordingInput {
  attemptId: string;
  attemptOutcome: ExecutionAttemptOutcomeV1;
  receiptOutcome: NonNullable<ActionReceiptRecord['outcome']>;
  reservationOwner: string;
  toolCall: ToolCallRecord;
  workspaceId: string;
}

export interface AtomicKnownExternalExecutionOutcomeRecordingResult {
  attempt?: ExecutionAttemptRecordV1;
  grant?: ExecutionGrantRecord;
  outcome:
    | 'binding_mismatch'
    | 'conflict'
    | 'not_found'
    | 'owner_mismatch'
    | 'reconciliation_required'
    | 'recorded'
    | 'replay'
    | 'state_mismatch';
  receipt?: ActionReceiptRecord;
  toolCall?: ToolCallRecord;
}

export interface ApprovalAuthorizationGuard {
  activePolicyVersionHash: string;
  authorization: ApprovalAuthorizationV1;
  originalInput: ApprovalRecord['originalInput'];
}

export interface AtomicApprovalDecisionInput {
  approvalId: string;
  authorization: ApprovalAuthorizationGuard;
  approvedEnvelopeHash: string;
  approvedInputHash: string;
  decision: ApprovalDecisionRecord;
  editedInput?: ApprovalDecisionRecord['editedInput'];
  note?: string;
  reviewHash: string;
  updatedAt: string;
  contentExposureRevision?: ContentExposureRevisionGuard;
}

export type AtomicApprovalDecisionResult = {
  approval?: ApprovalRecord;
  outcome:
    | 'already_final'
    | 'authorization_mismatch'
    | 'content_influence_mismatch'
    | 'duplicate'
    | 'expired'
    | 'finalized'
    | 'not_found'
    | 'recorded'
    | 'replayed';
};

export interface AtomicApprovalRejectionInput {
  approvalId: string;
  authorization?: ApprovalAuthorizationGuard;
  reason?: string;
  rejectedBy: string;
  updatedAt: string;
}

export type AtomicApprovalRejectionResult = {
  approval?: ApprovalRecord;
  outcome: 'already_final' | 'authorization_mismatch' | 'expired' | 'not_found' | 'rejected' | 'replayed';
};

export interface AtomicApprovalCancellationInput {
  approvalId: string;
  authorization?: ApprovalAuthorizationGuard;
  cancelledBy: string;
  reason?: string;
  updatedAt: string;
}

export type AtomicApprovalCancellationResult = {
  approval?: ApprovalRecord;
  outcome: 'already_final' | 'authorization_mismatch' | 'cancelled' | 'expired' | 'not_found' | 'replayed';
};

export interface AtomicApprovalExpiryInput {
  approvalId: string;
  authorization: ApprovalAuthorizationV1;
  expiredAt: string;
}

export type AtomicApprovalExpiryResult = {
  approval?: ApprovalRecord;
  outcome: 'already_final' | 'authorization_mismatch' | 'expired' | 'not_found';
};

export interface ListToolCallsFilters {
  decision?: PolicyDecision;
  limit?: number;
  runId?: string;
  sessionId?: string;
  status?: ToolCallStatus;
  toolName?: string;
  workspaceId?: string;
}

export interface ListExecutionGrantsFilters {
  limit?: number;
  workspaceId?: string;
}

export interface Store {
  createToolCall(record: ToolCallRecord): Promise<ToolCallRecord>;
  createToolCallIdempotentlyAtomically(input: AtomicIdempotentToolCallInput): Promise<AtomicIdempotentToolCallResult>;
  updateToolCall(record: ToolCallRecord): Promise<ToolCallRecord>;
  getToolCall(id: string): Promise<ToolCallRecord | undefined>;
  listToolCalls(filters?: ListToolCallsFilters): Promise<ToolCallRecord[]>;

  recordContentExposure(record: ContentExposureRecord): Promise<'conflict' | 'created' | 'replay'>;
  listContentExposures(input: ListContentExposuresInput): Promise<ListContentExposuresResult>;

  createApproval(record: ApprovalRecord): Promise<ApprovalRecord>;
  updateApproval(record: ApprovalRecord): Promise<ApprovalRecord>;
  getApproval(id: string): Promise<ApprovalRecord | undefined>;
  getApprovalByToolCallId(toolCallId: string): Promise<ApprovalRecord | undefined>;
  listPendingApprovals(): Promise<ApprovalRecord[]>;
  recordApprovalDecisionAtomically(input: AtomicApprovalDecisionInput): Promise<AtomicApprovalDecisionResult>;
  rejectApprovalAtomically(input: AtomicApprovalRejectionInput): Promise<AtomicApprovalRejectionResult>;
  cancelApprovalAtomically(input: AtomicApprovalCancellationInput): Promise<AtomicApprovalCancellationResult>;
  expireApprovalAtomically(input: AtomicApprovalExpiryInput): Promise<AtomicApprovalExpiryResult>;

  createApprovalDelivery(record: ApprovalDeliveryRecord): Promise<ApprovalDeliveryRecord>;
  updateApprovalDelivery(record: ApprovalDeliveryRecord): Promise<ApprovalDeliveryRecord>;
  listApprovalDeliveries(approvalId: string): Promise<ApprovalDeliveryRecord[]>;

  upsertApproverUser(record: ApproverUserRecord): Promise<ApproverUserRecord>;
  getApproverUser(workspaceId: string, id: string): Promise<ApproverUserRecord | undefined>;
  listApproverUsers(workspaceId: string): Promise<ApproverUserRecord[]>;
  deleteApproverUser(workspaceId: string, id: string): Promise<boolean>;

  upsertApproverGroup(record: ApproverGroupRecord): Promise<ApproverGroupRecord>;
  getApproverGroup(workspaceId: string, id: string): Promise<ApproverGroupRecord | undefined>;
  listApproverGroups(workspaceId: string): Promise<ApproverGroupRecord[]>;
  deleteApproverGroup(workspaceId: string, id: string): Promise<boolean>;

  createWorkspace(record: WorkspaceRecord): Promise<WorkspaceRecord>;
  getWorkspace(id: string): Promise<WorkspaceRecord | undefined>;

  upsertWorkspaceUser(record: WorkspaceUserRecord): Promise<WorkspaceUserRecord>;
  getWorkspaceUser(workspaceId: string, id: string): Promise<WorkspaceUserRecord | undefined>;
  getWorkspaceUserByPrincipal(workspaceId: string, principalId: string): Promise<WorkspaceUserRecord | undefined>;
  listWorkspaceUsers(workspaceId: string): Promise<WorkspaceUserRecord[]>;

  createServiceAccount(record: ServiceAccountRecord): Promise<ServiceAccountRecord>;
  getServiceAccount(id: string): Promise<ServiceAccountRecord | undefined>;
  listServiceAccounts(workspaceId: string): Promise<ServiceAccountRecord[]>;

  createApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord>;
  getApiKeyByPrefix(keyPrefix: string): Promise<ApiKeyRecord | undefined>;
  updateApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord>;

  createExecutionGrant(record: ExecutionGrantRecord): Promise<ExecutionGrantRecord>;
  getExecutionGrant(id: string): Promise<ExecutionGrantRecord | undefined>;
  listExecutionGrants(filters?: ListExecutionGrantsFilters): Promise<ExecutionGrantRecord[]>;
  updateExecutionGrant(record: ExecutionGrantRecord): Promise<ExecutionGrantRecord>;
  consumeExecutionGrantAtomically(id: string, consumedAt: string): Promise<ExecutionGrantRecord | undefined>;

  reserveExecutionAttemptAtomically(
    record: ExecutionAttemptRecordV1,
    approvalAuthorization?: ApprovalAuthorizationV1,
  ): Promise<AtomicExecutionAttemptReservationResult>;
  getExecutionAttempt(id: string): Promise<ExecutionAttemptRecordV1 | undefined>;
  getExecutionAttemptByToolCallId(
    workspaceId: string,
    toolCallId: string,
  ): Promise<ExecutionAttemptRecordV1 | undefined>;
  listExecutionAttempts(
    workspaceId: string,
    filters?: { state?: ExecutionAttemptState; toolCallId?: string },
  ): Promise<ExecutionAttemptRecordV1[]>;
  transitionExecutionAttemptAtomically(
    input: AtomicExecutionAttemptTransitionInput,
  ): Promise<AtomicExecutionAttemptTransitionResult>;
  bindExecutionAttemptGrantAtomically(
    input: AtomicExecutionAttemptGrantBindingInput,
  ): Promise<AtomicExecutionAttemptGrantBindingResult>;
  consumeExecutionGrantAndDispatchAttemptAtomically(input: AtomicGrantDispatchInput): Promise<AtomicGrantDispatchResult>;
  publishApprovedExternalAuthorizationAtomically(
    input: AtomicApprovedExternalAuthorizationPublicationInput,
  ): Promise<AtomicApprovedExternalAuthorizationPublicationResult>;
  adoptKnownExternalExecutionOutcomeAtomically(
    input: AtomicKnownExternalExecutionOutcomeAdoptionInput,
  ): Promise<AtomicKnownExternalExecutionOutcomeAdoptionResult>;
  recordKnownExternalExecutionOutcomeAtomically(
    input: AtomicKnownExternalExecutionOutcomeRecordingInput,
  ): Promise<AtomicKnownExternalExecutionOutcomeRecordingResult>;

  createActionReceipt(record: ActionReceiptRecord): Promise<ActionReceiptRecord>;
  getActionReceipt(id: string): Promise<ActionReceiptRecord | undefined>;
  getActionReceiptByToolCallId(toolCallId: string): Promise<ActionReceiptRecord | undefined>;
  recordActionReceiptOutcomeAtomically(
    input: AtomicActionReceiptOutcomeInput,
  ): Promise<AtomicActionReceiptOutcomeResult>;
  updateActionReceipt(record: ActionReceiptRecord): Promise<ActionReceiptRecord>;

  createIdempotencyRecord(record: IdempotencyRecord): Promise<IdempotencyRecord>;
  getIdempotencyRecord(workspaceId: string, route: string, key: string): Promise<IdempotencyRecord | undefined>;

  upsertObservedTool(record: ObservedToolRecord): Promise<ObservedToolRecord>;
  getObservedTool(id: string): Promise<ObservedToolRecord | undefined>;
  getObservedToolByName(workspaceId: string, toolName: string): Promise<ObservedToolRecord | undefined>;
  listObservedTools(workspaceId: string): Promise<ObservedToolRecord[]>;

}
