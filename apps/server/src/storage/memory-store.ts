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
  ServiceAccountRecord,
  ToolCallRecord,
  WorkspaceRecord,
  WorkspaceUserRecord,
} from '../models';
import type {
  AtomicActionReceiptOutcomeInput,
  AtomicActionReceiptOutcomeResult,
  AtomicApprovedExternalAuthorizationPublicationInput,
  AtomicApprovedExternalAuthorizationPublicationResult,
  AtomicKnownExternalExecutionOutcomeAdoptionInput,
  AtomicKnownExternalExecutionOutcomeAdoptionResult,
  AtomicKnownExternalExecutionOutcomeRecordingInput,
  AtomicKnownExternalExecutionOutcomeRecordingResult,
  AtomicExecutionAttemptGrantBindingInput,
  AtomicExecutionAttemptGrantBindingResult,
  AtomicExecutionAttemptReservationResult,
  AtomicExecutionAttemptTransitionInput,
  AtomicExecutionAttemptTransitionResult,
  AtomicGrantDispatchInput,
  AtomicGrantDispatchResult,
  AtomicIdempotentToolCallInput,
  AtomicIdempotentToolCallResult,
  AtomicApprovalCancellationInput,
  AtomicApprovalCancellationResult,
  AtomicApprovalDecisionInput,
  AtomicApprovalDecisionResult,
  AtomicApprovalExpiryInput,
  AtomicApprovalExpiryResult,
  AtomicApprovalRejectionInput,
  AtomicApprovalRejectionResult,
  ApprovalAuthorizationGuard,
  ContentExposureRecord,
  ListContentExposuresInput,
  ListContentExposuresResult,
  ListToolCallsFilters,
  Store,
} from './store';
import type {
  ExecutionAttemptRecordV1,
  ExecutionAttemptState,
} from '../contracts/execution-attempt';
import {
  approvalAuthorizationExpired,
  approvalAuthorizationMismatch,
  isValidApprovalAuthorization,
  type ApprovalAuthorizationV1,
} from '../contracts/approval-authorization';
import { validContentInfluenceBindingHash } from '../contracts/content-influence';
import { hashJson } from '../security/crypto';
import { assertApproverPrincipalAvailable } from './approver-principal-constraint';
import {
  approvedExternalAuthorizationMatchesCurrent,
  assertApprovedExternalAuthorizationPublicationCandidate,
  sameApprovedExternalAuthorizationPublication,
} from './approved-external-authorization-atomicity';
import {
  assertKnownExternalExecutionOutcomeAdoptionCandidate,
  externalOutcomeAdoptionState,
  knownExternalOutcomeMatchesCurrent,
  outcomeProjectionCanBeAdopted,
  sameKnownExternalOutcomeProjection,
} from './external-outcome-adoption-atomicity';
import {
  assertKnownExternalExecutionOutcomeRecordingCandidate,
  knownExternalOutcomeRecordingBindingsMatch,
  knownExternalOutcomeRecordingConflictDisposition,
  knownExternalOutcomeRecordingMatchesCurrent,
  sameRecordedKnownExternalOutcomeProjection,
} from './external-outcome-recording-atomicity';

export class MemoryStore implements Store {
  private toolCalls = new Map<string, ToolCallRecord>();
  private contentExposureScopes = new Map<string, ContentExposureScope>();
  private approvals = new Map<string, ApprovalRecord>();
  private approvalDeliveries = new Map<string, ApprovalDeliveryRecord>();
  private approverUsers = new Map<string, ApproverUserRecord>();
  private approverGroups = new Map<string, ApproverGroupRecord>();
  private workspaces = new Map<string, WorkspaceRecord>();
  private workspaceUsers = new Map<string, WorkspaceUserRecord>();
  private serviceAccounts = new Map<string, ServiceAccountRecord>();
  private apiKeys = new Map<string, ApiKeyRecord>();
  private executionGrants = new Map<string, ExecutionGrantRecord>();
  private executionAttempts = new Map<string, ExecutionAttemptRecordV1>();
  private executionAttemptByToolCall = new Map<string, string>();
  private actionReceipts = new Map<string, ActionReceiptRecord>();
  private idempotency = new Map<string, IdempotencyRecord>();
  private observedTools = new Map<string, ObservedToolRecord>();

  async createToolCall(record: ToolCallRecord): Promise<ToolCallRecord> {
    this.toolCalls.set(record.id, record);
    return record;
  }

  async createToolCallIdempotentlyAtomically(
    input: AtomicIdempotentToolCallInput,
  ): Promise<AtomicIdempotentToolCallResult> {
    assertIdempotencyCandidate(input);
    const key = idempotencyKey(input.idempotency.workspaceId, input.idempotency.route, input.idempotency.key);
    const current = this.idempotency.get(key);
    if (current) {
      const toolCall = this.toolCalls.get(current.toolCallId);
      if (!toolCall) throw new Error(`Idempotency record references missing tool call: ${current.toolCallId}`);
      return {
        idempotency: current,
        outcome: current.requestHash === input.idempotency.requestHash ? 'replay' : 'conflict',
        toolCall,
      };
    }

    if (this.toolCalls.has(input.toolCall.id)) {
      throw new Error(`Tool call already exists without this idempotency reservation: ${input.toolCall.id}`);
    }
    this.toolCalls.set(input.toolCall.id, input.toolCall);
    this.idempotency.set(key, input.idempotency);
    return { idempotency: input.idempotency, outcome: 'created', toolCall: input.toolCall };
  }

  async updateToolCall(record: ToolCallRecord): Promise<ToolCallRecord> {
    this.toolCalls.set(record.id, record);
    return record;
  }

  async getToolCall(id: string): Promise<ToolCallRecord | undefined> {
    return this.toolCalls.get(id);
  }

  async listToolCalls(filters: ListToolCallsFilters = {}): Promise<ToolCallRecord[]> {
    const limit = filters.limit ?? 100;
    return [...this.toolCalls.values()]
      .filter((toolCall) => !filters.workspaceId || toolCall.workspaceId === filters.workspaceId)
      .filter((toolCall) => !filters.sessionId || toolCallForensicSessionValue(toolCall, 'sessionId') === filters.sessionId)
      .filter((toolCall) => !filters.runId || toolCallForensicSessionValue(toolCall, 'runId') === filters.runId)
      .filter((toolCall) => !filters.status || toolCall.status === filters.status)
      .filter((toolCall) => !filters.decision || toolCall.decision === filters.decision)
      .filter((toolCall) => !filters.toolName || toolCall.toolName === filters.toolName)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .slice(0, limit);
  }

  async recordContentExposure(record: ContentExposureRecord): Promise<'conflict' | 'created' | 'replay'> {
    const scopeKey = contentExposureScopeKey(record.workspaceId, record.influenceScopeId);
    const scope = this.contentExposureScopes.get(scopeKey) ?? { orderedPrefix: [], records: new Map(), revision: 0 };
    const current = scope.records.get(record.sourceToolCallId);
    if (current) return sameContentExposureEvidence(current, record) ? 'replay' : 'conflict';
    const stored = storedContentExposure(record);
    scope.records.set(record.sourceToolCallId, stored);
    insertIntoBoundedExposurePrefix(scope.orderedPrefix, stored);
    scope.revision += 1;
    this.contentExposureScopes.set(scopeKey, scope);
    return 'created';
  }

  async listContentExposures(input: ListContentExposuresInput): Promise<ListContentExposuresResult> {
    const limit = contentExposureLimit(input.limit);
    const scope = this.contentExposureScopes.get(contentExposureScopeKey(input.workspaceId, input.influenceScopeId));
    const candidates = scope?.orderedPrefix.slice(0, limit + 1) ?? [];
    return {
      overflow: (scope?.revision ?? 0) > limit,
      records: candidates.slice(0, limit).map(storedContentExposure),
      revision: scope?.revision ?? 0,
    };
  }

  async createApproval(record: ApprovalRecord): Promise<ApprovalRecord> {
    this.approvals.set(record.id, record);
    return record;
  }

  async updateApproval(record: ApprovalRecord): Promise<ApprovalRecord> {
    this.approvals.set(record.id, record);
    return record;
  }

  async getApproval(id: string): Promise<ApprovalRecord | undefined> {
    return this.approvals.get(id);
  }

  async getApprovalByToolCallId(toolCallId: string): Promise<ApprovalRecord | undefined> {
    return [...this.approvals.values()].find((approval) => approval.toolCallId === toolCallId);
  }

  async listPendingApprovals(): Promise<ApprovalRecord[]> {
    return [...this.approvals.values()].filter((approval) => approval.status === 'pending');
  }

  async recordApprovalDecisionAtomically(input: AtomicApprovalDecisionInput): Promise<AtomicApprovalDecisionResult> {
    const current = this.approvals.get(input.approvalId);
    if (!current) return { outcome: 'not_found' };
    if (
      current.authorizationConsumedAt &&
      sameAuthorization(current.authorization, input.authorization.authorization)
    ) {
      return { approval: current, outcome: 'replayed' };
    }
    if (current.status !== 'pending') return { approval: current, outcome: 'already_final' };
    if (
      !contentExposureRevisionMatches(
        this.contentExposureScopes,
        current.workspaceId ?? 'default',
        input.contentExposureRevision,
      )
    ) {
      return { approval: current, outcome: 'content_influence_mismatch' };
    }
    const authorizationFailure = this.approvalAuthorizationFailure(current, input.authorization);
    if (authorizationFailure) return { approval: current, outcome: authorizationFailure };
    if (approvalAuthorizationExpired(current.authorization!)) {
      const expired = expireApproval(current, current.authorization!.expiresAt);
      this.approvals.set(expired.id, expired);
      return { approval: expired, outcome: 'expired' };
    }
    if (!decisionMatchesAuthorization(input, current.authorization!)) {
      return { approval: current, outcome: 'authorization_mismatch' };
    }
    if (
      !priorDecisionsMatchAuthorization(
        current.decisions,
        current.authorization!,
        input.approvedInputHash,
        input.approvedEnvelopeHash,
      )
    ) {
      return { approval: current, outcome: 'authorization_mismatch' };
    }
    if (hasApprovalDecision(current.decisions, input.decision)) {
      return { approval: current, outcome: 'duplicate' };
    }

    const decisions = [...(current.decisions ?? []), input.decision];
    const finalized = decisions.length >= Math.max(1, current.requiredApprovals ?? 1);
    const approval: ApprovalRecord = {
      ...current,
      approvedBy: finalized ? input.decision.actor : current.approvedBy,
      approvedEnvelopeHash: finalized ? input.approvedEnvelopeHash : current.approvedEnvelopeHash,
      approvedInputHash: finalized ? input.approvedInputHash : current.approvedInputHash,
      decisions,
      editedInput: input.editedInput ?? current.editedInput,
      note: input.note,
      reviewHash: input.reviewHash,
      status: finalized ? 'approved' : 'pending',
      updatedAt: input.updatedAt,
      authorizationConsumedAt: finalized ? input.updatedAt : current.authorizationConsumedAt,
      authorizationConsumedReason: finalized ? 'approved' : current.authorizationConsumedReason,
      finalizedAt: finalized ? input.updatedAt : current.finalizedAt,
    };
    this.approvals.set(approval.id, approval);
    return { approval, outcome: finalized ? 'finalized' : 'recorded' };
  }

  async rejectApprovalAtomically(input: AtomicApprovalRejectionInput): Promise<AtomicApprovalRejectionResult> {
    const current = this.approvals.get(input.approvalId);
    if (!current) return { outcome: 'not_found' };
    if (
      input.authorization &&
      current.authorizationConsumedAt &&
      sameAuthorization(current.authorization, input.authorization.authorization)
    ) {
      return { approval: current, outcome: 'replayed' };
    }
    if (current.status !== 'pending') return { approval: current, outcome: 'already_final' };
    if (current.authorization) {
      if (!input.authorization) return { approval: current, outcome: 'authorization_mismatch' };
      const authorizationFailure = this.approvalAuthorizationFailure(current, input.authorization);
      if (authorizationFailure) return { approval: current, outcome: authorizationFailure };
      if (approvalAuthorizationExpired(current.authorization)) {
        const expired = expireApproval(current, current.authorization.expiresAt);
        this.approvals.set(expired.id, expired);
        return { approval: expired, outcome: 'expired' };
      }
    }
    const approval: ApprovalRecord = {
      ...current,
      authorizationConsumedAt: current.authorization ? input.updatedAt : undefined,
      authorizationConsumedReason: current.authorization ? 'rejected' : undefined,
      finalizedAt: input.updatedAt,
      rejectedBy: input.rejectedBy,
      rejectionReason: input.reason,
      status: 'rejected',
      updatedAt: input.updatedAt,
    };
    this.approvals.set(approval.id, approval);
    return { approval, outcome: 'rejected' };
  }

  async cancelApprovalAtomically(input: AtomicApprovalCancellationInput): Promise<AtomicApprovalCancellationResult> {
    const current = this.approvals.get(input.approvalId);
    if (!current) return { outcome: 'not_found' };
    if (
      input.authorization &&
      current.authorizationConsumedAt &&
      sameAuthorization(current.authorization, input.authorization.authorization)
    ) {
      return { approval: current, outcome: 'replayed' };
    }
    if (current.status !== 'pending') return { approval: current, outcome: 'already_final' };
    if (current.authorization) {
      if (!input.authorization) return { approval: current, outcome: 'authorization_mismatch' };
      const authorizationFailure = this.approvalAuthorizationFailure(current, input.authorization);
      if (authorizationFailure) return { approval: current, outcome: authorizationFailure };
      if (approvalAuthorizationExpired(current.authorization)) {
        const expired = expireApproval(current, current.authorization.expiresAt);
        this.approvals.set(expired.id, expired);
        return { approval: expired, outcome: 'expired' };
      }
    }
    const approval: ApprovalRecord = {
      ...current,
      authorizationConsumedAt: current.authorization ? input.updatedAt : undefined,
      authorizationConsumedReason: current.authorization ? 'cancelled' : undefined,
      cancelledAt: input.updatedAt,
      cancelledBy: input.cancelledBy,
      cancellationReason: input.reason,
      finalizedAt: input.updatedAt,
      status: 'cancelled',
      updatedAt: input.updatedAt,
    };
    this.approvals.set(approval.id, approval);
    return { approval, outcome: 'cancelled' };
  }

  async expireApprovalAtomically(input: AtomicApprovalExpiryInput): Promise<AtomicApprovalExpiryResult> {
    const current = this.approvals.get(input.approvalId);
    if (!current) return { outcome: 'not_found' };
    if (current.status !== 'pending') return { approval: current, outcome: 'already_final' };
    if (!sameAuthorization(current.authorization, input.authorization)) {
      return { approval: current, outcome: 'authorization_mismatch' };
    }
    if (!approvalAuthorizationExpired(current.authorization!)) {
      return { approval: current, outcome: 'authorization_mismatch' };
    }
    const approval = expireApproval(current, input.expiredAt);
    this.approvals.set(approval.id, approval);
    return { approval, outcome: 'expired' };
  }

  private approvalAuthorizationFailure(
    approval: ApprovalRecord,
    guard: ApprovalAuthorizationGuard,
  ): 'authorization_mismatch' | 'replayed' | undefined {
    if (approval.authorizationConsumedAt) return 'replayed';
    if (!sameAuthorization(approval.authorization, guard.authorization)) return 'authorization_mismatch';
    const toolCall = this.toolCalls.get(approval.toolCallId);
    if (!toolCall) return 'authorization_mismatch';
    if (guard.activePolicyVersionHash !== toolCall.policyVersionHash) return 'authorization_mismatch';
    if (guard.activePolicyVersionHash !== guard.authorization.binding.policy.legacyVersionHash) {
      return 'authorization_mismatch';
    }
    if (hashJson(guard.originalInput) !== guard.authorization.binding.action.originalInputHash) {
      return 'authorization_mismatch';
    }
    if (hashJson(guard.originalInput) !== hashJson(approval.originalInput)) return 'authorization_mismatch';
    if (approvalAuthorizationMismatch(guard.authorization, approval, toolCall)) return 'authorization_mismatch';
    if (!priorDecisionsMatchAuthorization(approval.decisions, guard.authorization)) {
      return 'authorization_mismatch';
    }
    return undefined;
  }

  async createApprovalDelivery(record: ApprovalDeliveryRecord): Promise<ApprovalDeliveryRecord> {
    this.approvalDeliveries.set(record.id, record);
    return record;
  }

  async updateApprovalDelivery(record: ApprovalDeliveryRecord): Promise<ApprovalDeliveryRecord> {
    this.approvalDeliveries.set(record.id, record);
    return record;
  }

  async listApprovalDeliveries(approvalId: string): Promise<ApprovalDeliveryRecord[]> {
    return [...this.approvalDeliveries.values()]
      .filter((delivery) => delivery.approvalId === approvalId)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  async upsertApproverUser(record: ApproverUserRecord): Promise<ApproverUserRecord> {
    assertApproverPrincipalAvailable(this.approverUsers.values(), record);
    this.approverUsers.set(workspaceKey(record.workspaceId, record.id), record);
    return record;
  }

  async getApproverUser(workspaceId: string, id: string): Promise<ApproverUserRecord | undefined> {
    return this.approverUsers.get(workspaceKey(workspaceId, id));
  }

  async listApproverUsers(workspaceId: string): Promise<ApproverUserRecord[]> {
    return [...this.approverUsers.values()]
      .filter((user) => user.workspaceId === workspaceId)
      .sort((left, right) => left.displayName.localeCompare(right.displayName));
  }

  async deleteApproverUser(workspaceId: string, id: string): Promise<boolean> {
    return this.approverUsers.delete(workspaceKey(workspaceId, id));
  }

  async upsertApproverGroup(record: ApproverGroupRecord): Promise<ApproverGroupRecord> {
    this.approverGroups.set(workspaceKey(record.workspaceId, record.id), record);
    return record;
  }

  async getApproverGroup(workspaceId: string, id: string): Promise<ApproverGroupRecord | undefined> {
    return this.approverGroups.get(workspaceKey(workspaceId, id));
  }

  async listApproverGroups(workspaceId: string): Promise<ApproverGroupRecord[]> {
    return [...this.approverGroups.values()]
      .filter((group) => group.workspaceId === workspaceId)
      .sort((left, right) => left.displayName.localeCompare(right.displayName));
  }

  async deleteApproverGroup(workspaceId: string, id: string): Promise<boolean> {
    return this.approverGroups.delete(workspaceKey(workspaceId, id));
  }

  async createWorkspace(record: WorkspaceRecord): Promise<WorkspaceRecord> {
    this.workspaces.set(record.id, record);
    return record;
  }

  async getWorkspace(id: string): Promise<WorkspaceRecord | undefined> {
    return this.workspaces.get(id);
  }

  async upsertWorkspaceUser(record: WorkspaceUserRecord): Promise<WorkspaceUserRecord> {
    this.workspaceUsers.set(workspaceKey(record.workspaceId, record.id), record);
    return record;
  }

  async getWorkspaceUser(workspaceId: string, id: string): Promise<WorkspaceUserRecord | undefined> {
    return this.workspaceUsers.get(workspaceKey(workspaceId, id));
  }

  async getWorkspaceUserByPrincipal(workspaceId: string, principalId: string): Promise<WorkspaceUserRecord | undefined> {
    return [...this.workspaceUsers.values()].find(
      (user) => user.workspaceId === workspaceId && user.principalId === principalId,
    );
  }

  async listWorkspaceUsers(workspaceId: string): Promise<WorkspaceUserRecord[]> {
    return [...this.workspaceUsers.values()]
      .filter((user) => user.workspaceId === workspaceId)
      .sort((left, right) => left.displayName.localeCompare(right.displayName));
  }

  async createServiceAccount(record: ServiceAccountRecord): Promise<ServiceAccountRecord> {
    this.serviceAccounts.set(record.id, record);
    return record;
  }

  async getServiceAccount(id: string): Promise<ServiceAccountRecord | undefined> {
    return this.serviceAccounts.get(id);
  }

  async listServiceAccounts(workspaceId: string): Promise<ServiceAccountRecord[]> {
    return [...this.serviceAccounts.values()]
      .filter((account) => account.workspaceId === workspaceId)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  async createApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord> {
    this.apiKeys.set(record.keyPrefix, record);
    return record;
  }

  async getApiKeyByPrefix(keyPrefix: string): Promise<ApiKeyRecord | undefined> {
    return this.apiKeys.get(keyPrefix);
  }

  async updateApiKey(record: ApiKeyRecord): Promise<ApiKeyRecord> {
    this.apiKeys.set(record.keyPrefix, record);
    return record;
  }

  async createExecutionGrant(record: ExecutionGrantRecord): Promise<ExecutionGrantRecord> {
    this.executionGrants.set(record.id, record);
    return record;
  }

  async getExecutionGrant(id: string): Promise<ExecutionGrantRecord | undefined> {
    return this.executionGrants.get(id);
  }

  async listExecutionGrants(filters: { limit?: number; workspaceId?: string } = {}): Promise<ExecutionGrantRecord[]> {
    return [...this.executionGrants.values()]
      .filter((grant) => !filters.workspaceId || grant.workspaceId === filters.workspaceId)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .slice(0, filters.limit ?? 100);
  }

  async updateExecutionGrant(record: ExecutionGrantRecord): Promise<ExecutionGrantRecord> {
    this.executionGrants.set(record.id, record);
    return record;
  }

  async consumeExecutionGrantAtomically(id: string, consumedAt: string): Promise<ExecutionGrantRecord | undefined> {
    const current = this.executionGrants.get(id);
    if (!current || current.consumedAt) return undefined;
    const consumed = { ...current, consumedAt };
    this.executionGrants.set(id, consumed);
    return consumed;
  }

  async reserveExecutionAttemptAtomically(
    record: ExecutionAttemptRecordV1,
    approvalAuthorization?: ApprovalAuthorizationV1,
  ): Promise<AtomicExecutionAttemptReservationResult> {
    const toolCall = this.toolCalls.get(record.toolCallId);
    if (!toolCall || (toolCall.workspaceId ?? 'default') !== record.workspaceId) return { outcome: 'not_found' };
    if (!executionAttemptBindingMatches(record, toolCall, this.approvals, this.actionReceipts, approvalAuthorization)) {
      return { outcome: 'binding_mismatch' };
    }
    const toolCallKey = executionAttemptToolCallKey(record.workspaceId, record.toolCallId);
    const existingId = this.executionAttemptByToolCall.get(toolCallKey);
    if (existingId) return { attempt: this.executionAttempts.get(existingId), outcome: 'existing' };
    if (this.executionAttempts.has(record.id)) {
      return { attempt: this.executionAttempts.get(record.id), outcome: 'binding_mismatch' };
    }
    this.executionAttempts.set(record.id, record);
    this.executionAttemptByToolCall.set(toolCallKey, record.id);
    return { attempt: record, outcome: 'reserved' };
  }

  async getExecutionAttempt(id: string): Promise<ExecutionAttemptRecordV1 | undefined> {
    return this.executionAttempts.get(id);
  }

  async getExecutionAttemptByToolCallId(
    workspaceId: string,
    toolCallId: string,
  ): Promise<ExecutionAttemptRecordV1 | undefined> {
    const id = this.executionAttemptByToolCall.get(executionAttemptToolCallKey(workspaceId, toolCallId));
    return id ? this.executionAttempts.get(id) : undefined;
  }

  async listExecutionAttempts(
    workspaceId: string,
    filters: { state?: ExecutionAttemptState; toolCallId?: string } = {},
  ): Promise<ExecutionAttemptRecordV1[]> {
    return [...this.executionAttempts.values()]
      .filter((attempt) => attempt.workspaceId === workspaceId)
      .filter((attempt) => !filters.state || attempt.state === filters.state)
      .filter((attempt) => !filters.toolCallId || attempt.toolCallId === filters.toolCallId)
      .sort((left, right) => right.reservedAt.localeCompare(left.reservedAt));
  }

  async transitionExecutionAttemptAtomically(
    input: AtomicExecutionAttemptTransitionInput,
  ): Promise<AtomicExecutionAttemptTransitionResult> {
    const current = this.executionAttempts.get(input.attemptId);
    if (!current || current.workspaceId !== input.workspaceId) return { outcome: 'not_found' };
    if (current.reservationOwner !== input.reservationOwner) return { attempt: current, outcome: 'owner_mismatch' };
    if (executionAttemptTransitionIsReplay(current, input)) return { attempt: current, outcome: 'replay' };
    if (executionAttemptIsTerminal(current.state)) return { attempt: current, outcome: 'already_terminal' };
    if (!contentExposureRevisionMatches(this.contentExposureScopes, input.workspaceId, input.contentExposureRevision)) {
      return { attempt: current, outcome: 'content_influence_mismatch' };
    }
    if (current.state !== input.expectedState || !executionAttemptTransitionIsValid(input)) {
      return { attempt: current, outcome: 'state_mismatch' };
    }
    const updated = transitionedExecutionAttempt(current, input);
    this.executionAttempts.set(updated.id, updated);
    return { attempt: updated, outcome: 'transitioned' };
  }

  async bindExecutionAttemptGrantAtomically(
    input: AtomicExecutionAttemptGrantBindingInput,
  ): Promise<AtomicExecutionAttemptGrantBindingResult> {
    const current = this.executionAttempts.get(input.attemptId);
    if (!current || current.workspaceId !== input.workspaceId) return { outcome: 'not_found' };
    if (current.reservationOwner !== input.reservationOwner) return { attempt: current, outcome: 'owner_mismatch' };
    if (current.state !== 'reserved') return { attempt: current, outcome: 'state_mismatch' };
    if (current.grantId) return { attempt: current, outcome: 'already_bound' };
    const updated = { ...current, grantId: input.grantId, updatedAt: input.updatedAt };
    this.executionAttempts.set(updated.id, updated);
    return { attempt: updated, outcome: 'bound' };
  }

  async consumeExecutionGrantAndDispatchAttemptAtomically(
    input: AtomicGrantDispatchInput,
  ): Promise<AtomicGrantDispatchResult> {
    const attempt = this.executionAttempts.get(input.attemptId);
    if (!attempt || attempt.workspaceId !== input.workspaceId) return { outcome: 'attempt_not_found' };
    const grant = this.executionGrants.get(input.grantId);
    if (!grant || grant.workspaceId !== input.workspaceId) return { attempt, outcome: 'grant_not_found' };
    if (grant.consumedAt) return { attempt, grant, outcome: 'grant_already_consumed' };
    if (attempt.state !== 'reserved') return { attempt, grant, outcome: 'attempt_state_mismatch' };
    if (
      attempt.reservationOwner !== input.reservationOwner ||
      attempt.grantId !== input.grantId ||
      attempt.toolCallId !== input.toolCallId ||
      grant.toolCallId !== input.toolCallId
    ) {
      return { attempt, grant, outcome: 'binding_mismatch' };
    }
    if (!contentExposureRevisionMatches(this.contentExposureScopes, input.workspaceId, input.contentExposureRevision)) {
      return { attempt, grant, outcome: 'content_influence_mismatch' };
    }
    const consumedGrant = { ...grant, consumedAt: input.dispatchedAt };
    const dispatchedAttempt: ExecutionAttemptRecordV1 = {
      ...attempt,
      dispatchedAt: input.dispatchedAt,
      state: 'dispatched',
      updatedAt: input.dispatchedAt,
    };
    this.executionGrants.set(consumedGrant.id, consumedGrant);
    this.executionAttempts.set(dispatchedAttempt.id, dispatchedAttempt);
    return { attempt: dispatchedAttempt, grant: consumedGrant, outcome: 'dispatched' };
  }

  async publishApprovedExternalAuthorizationAtomically(
    input: AtomicApprovedExternalAuthorizationPublicationInput,
  ): Promise<AtomicApprovedExternalAuthorizationPublicationResult> {
    assertApprovedExternalAuthorizationPublicationCandidate(input);
    const workspaceId = input.toolCall.workspaceId ?? 'default';
    const approval = this.approvals.get(input.approvalId);
    const toolCall = this.toolCalls.get(input.toolCall.id);
    if (!approval || !toolCall || (toolCall.workspaceId ?? 'default') !== workspaceId) {
      return { approval, outcome: 'not_found', toolCall };
    }
    const attemptId = this.executionAttemptByToolCall.get(executionAttemptToolCallKey(workspaceId, toolCall.id));
    const attempt = attemptId ? this.executionAttempts.get(attemptId) : undefined;
    const receipt = [...this.actionReceipts.values()].find(
      (candidate) => candidate.workspaceId === workspaceId && candidate.toolCallId === toolCall.id,
    );
    const grant = [...this.executionGrants.values()].find(
      (candidate) => candidate.workspaceId === workspaceId && candidate.toolCallId === toolCall.id,
    );
    const publicationExists = attempt !== undefined || receipt !== undefined || grant !== undefined || toolCall.status === 'authorized';
    if (publicationExists) {
      return sameApprovedExternalAuthorizationPublication(input, { attempt, grant, receipt, toolCall })
        ? { approval, attempt, grant, outcome: 'replay', receipt, toolCall }
        : { approval, attempt, grant, outcome: 'conflict', receipt, toolCall };
    }
    if (approval.status !== 'approved' || toolCall.status !== 'pending_approval') {
      return { approval, outcome: 'state_mismatch', toolCall };
    }
    if (!approvedExternalAuthorizationMatchesCurrent(input, approval, toolCall)) {
      return { approval, outcome: 'binding_mismatch', toolCall };
    }
    if (
      this.executionAttempts.has(input.attempt.id)
      || this.executionGrants.has(input.grant.id)
      || this.actionReceipts.has(input.receipt.id)
    ) {
      return { approval, outcome: 'conflict', toolCall };
    }
    this.actionReceipts.set(input.receipt.id, input.receipt);
    this.executionGrants.set(input.grant.id, input.grant);
    this.executionAttempts.set(input.attempt.id, input.attempt);
    this.executionAttemptByToolCall.set(executionAttemptToolCallKey(workspaceId, toolCall.id), input.attempt.id);
    this.toolCalls.set(input.toolCall.id, input.toolCall);
    return {
      approval,
      attempt: input.attempt,
      grant: input.grant,
      outcome: 'created',
      receipt: input.receipt,
      toolCall: input.toolCall,
    };
  }

  async adoptKnownExternalExecutionOutcomeAtomically(
    input: AtomicKnownExternalExecutionOutcomeAdoptionInput,
  ): Promise<AtomicKnownExternalExecutionOutcomeAdoptionResult> {
    assertKnownExternalExecutionOutcomeAdoptionCandidate(input);
    const attempt = this.executionAttempts.get(input.attemptId);
    const toolCall = this.toolCalls.get(input.toolCall.id);
    const receipt = this.actionReceipts.get(input.receipt.id);
    const grant = attempt?.grantId ? this.executionGrants.get(attempt.grantId) : undefined;
    if (!attempt || !toolCall || !receipt || !grant) return { attempt, grant, outcome: 'not_found', receipt, toolCall };
    const state = externalOutcomeAdoptionState(attempt);
    if (state === 'reconciliation_required') return { attempt, grant, outcome: state, receipt, toolCall };
    if (state === 'state_mismatch') return { attempt, grant, outcome: state, receipt, toolCall };
    if (sameKnownExternalOutcomeProjection(input, receipt, toolCall)) {
      return { attempt, grant, outcome: 'replay', receipt, toolCall };
    }
    if (!knownExternalOutcomeMatchesCurrent(input, { attempt, grant, receipt, toolCall })) {
      return { attempt, grant, outcome: 'binding_mismatch', receipt, toolCall };
    }
    if (!outcomeProjectionCanBeAdopted(input, receipt, toolCall)) {
      return { attempt, grant, outcome: 'conflict', receipt, toolCall };
    }
    const adoptedReceipt = receipt.outcome ? receipt : input.receipt;
    const adoptedToolCall = toolCall.status === 'authorized' ? input.toolCall : toolCall;
    this.actionReceipts.set(adoptedReceipt.id, adoptedReceipt);
    this.toolCalls.set(adoptedToolCall.id, adoptedToolCall);
    return { attempt, grant, outcome: 'adopted', receipt: adoptedReceipt, toolCall: adoptedToolCall };
  }

  async recordKnownExternalExecutionOutcomeAtomically(
    input: AtomicKnownExternalExecutionOutcomeRecordingInput,
  ): Promise<AtomicKnownExternalExecutionOutcomeRecordingResult> {
    assertKnownExternalExecutionOutcomeRecordingCandidate(input);
    const attempt = this.executionAttempts.get(input.attemptId);
    if (!attempt || attempt.workspaceId !== input.workspaceId) return { outcome: 'not_found' };
    const toolCall = this.toolCalls.get(attempt.toolCallId);
    const receipt = attempt.binding.receiptId
      ? this.actionReceipts.get(attempt.binding.receiptId)
      : undefined;
    const grant = attempt.grantId ? this.executionGrants.get(attempt.grantId) : undefined;
    if (!toolCall || !receipt || !grant) return { attempt, grant, outcome: 'not_found', receipt, toolCall };
    if (attempt.reservationOwner !== input.reservationOwner) {
      return { attempt, grant, outcome: 'owner_mismatch', receipt, toolCall };
    }
    const current = { attempt, grant, receipt, toolCall };
    if (!knownExternalOutcomeRecordingBindingsMatch(input, current)) {
      return { attempt, grant, outcome: 'binding_mismatch', receipt, toolCall };
    }
    if (sameRecordedKnownExternalOutcomeProjection(input, attempt, receipt, toolCall)) {
      return { attempt, grant, outcome: 'replay', receipt, toolCall };
    }
    if (!knownExternalOutcomeRecordingMatchesCurrent(input, current)) {
      return {
        attempt,
        grant,
        outcome: knownExternalOutcomeRecordingConflictDisposition(attempt),
        receipt,
        toolCall,
      };
    }
    if (attempt.state !== 'dispatched') {
      return {
        attempt,
        grant,
        outcome: knownExternalOutcomeRecordingConflictDisposition(attempt),
        receipt,
        toolCall,
      };
    }
    const completedAttempt: ExecutionAttemptRecordV1 = {
      ...attempt,
      completedAt: input.attemptOutcome.recordedAt,
      outcome: input.attemptOutcome,
      state: input.attemptOutcome.status,
      updatedAt: input.attemptOutcome.recordedAt,
    };
    const completedReceipt = { ...receipt, outcome: input.receiptOutcome };
    this.executionAttempts.set(completedAttempt.id, completedAttempt);
    this.actionReceipts.set(completedReceipt.id, completedReceipt);
    this.toolCalls.set(input.toolCall.id, input.toolCall);
    return {
      attempt: completedAttempt,
      grant,
      outcome: 'recorded',
      receipt: completedReceipt,
      toolCall: input.toolCall,
    };
  }

  async createActionReceipt(record: ActionReceiptRecord): Promise<ActionReceiptRecord> {
    this.actionReceipts.set(record.id, record);
    return record;
  }

  async getActionReceipt(id: string): Promise<ActionReceiptRecord | undefined> {
    return this.actionReceipts.get(id);
  }

  async getActionReceiptByToolCallId(toolCallId: string): Promise<ActionReceiptRecord | undefined> {
    return [...this.actionReceipts.values()].find((receipt) => receipt.toolCallId === toolCallId);
  }

  async updateActionReceipt(record: ActionReceiptRecord): Promise<ActionReceiptRecord> {
    this.actionReceipts.set(record.id, record);
    return record;
  }

  async recordActionReceiptOutcomeAtomically(
    input: AtomicActionReceiptOutcomeInput,
  ): Promise<AtomicActionReceiptOutcomeResult> {
    const current = this.actionReceipts.get(input.receiptId);
    if (!current) return { outcome: 'not_found' };
    if (current.outcome) return { outcome: 'existing', receipt: current };
    const receipt = { ...current, outcome: input.outcome };
    this.actionReceipts.set(receipt.id, receipt);
    return { outcome: 'recorded', receipt };
  }

  async createIdempotencyRecord(record: IdempotencyRecord): Promise<IdempotencyRecord> {
    this.idempotency.set(idempotencyKey(record.workspaceId, record.route, record.key), record);
    return record;
  }

  async getIdempotencyRecord(workspaceId: string, route: string, key: string): Promise<IdempotencyRecord | undefined> {
    return this.idempotency.get(idempotencyKey(workspaceId, route, key));
  }

  async upsertObservedTool(record: ObservedToolRecord): Promise<ObservedToolRecord> {
    this.observedTools.set(record.id, record);
    return record;
  }

  async getObservedTool(id: string): Promise<ObservedToolRecord | undefined> {
    return this.observedTools.get(id);
  }

  async getObservedToolByName(workspaceId: string, toolName: string): Promise<ObservedToolRecord | undefined> {
    return [...this.observedTools.values()].find(
      (record) => record.workspaceId === workspaceId && record.toolName === toolName,
    );
  }

  async listObservedTools(workspaceId: string): Promise<ObservedToolRecord[]> {
    return [...this.observedTools.values()]
      .filter((record) => record.workspaceId === workspaceId)
      .sort((left, right) => right.lastSeenAt.localeCompare(left.lastSeenAt));
  }

}

function idempotencyKey(workspaceId: string, route: string, key: string): string {
  return JSON.stringify([workspaceId, route, key]);
}

function assertIdempotencyCandidate(input: AtomicIdempotentToolCallInput): void {
  if (
    input.idempotency.toolCallId !== input.toolCall.id ||
    input.idempotency.workspaceId !== (input.toolCall.workspaceId ?? 'default')
  ) {
    throw new Error('Idempotency reservation does not match the candidate tool call.');
  }
}

function executionAttemptToolCallKey(workspaceId: string, toolCallId: string): string {
  return JSON.stringify([workspaceId, toolCallId]);
}

function executionAttemptBindingMatches(
  record: ExecutionAttemptRecordV1,
  toolCall: ToolCallRecord,
  approvals: Map<string, ApprovalRecord>,
  receipts: Map<string, ActionReceiptRecord>,
  approvalAuthorization?: ApprovalAuthorizationV1,
): boolean {
  if (
    record.version !== 'actionproxy.execution-attempt.v1' ||
    record.attemptNumber !== 1 ||
    record.state !== 'reserved' ||
    record.outcome !== undefined ||
    record.dispatchedAt !== undefined ||
    record.completedAt !== undefined ||
    record.grantId !== undefined ||
    !record.id ||
    !record.reservationOwner ||
    record.providerIdempotency !== 'none' ||
    record.retryPolicy !== 'never_automatic' ||
    (record.executionMode === 'local_mock' && record.executorId !== 'actionproxy.local-tool-registry') ||
    (record.executionMode === 'external_grant' && record.executorId !== 'actionproxy.external-runner')
  ) {
    return false;
  }
  const decision = isJsonObject(toolCall.decisionTrace?.decisionV1) ? toolCall.decisionTrace.decisionV1 : undefined;
  if (
    record.binding.canonicalActionRequestHash !== (toolCall.canonicalActionRequestHash ?? null) ||
    record.binding.canonicalActionRequestVersion !== (toolCall.canonicalActionRequestVersion ?? null) ||
    record.binding.canonicalDecisionInputHash !== (toolCall.canonicalDecisionInputHash ?? null) ||
    record.binding.decisionId !== (typeof decision?.decisionId === 'string' ? decision.decisionId : null) ||
    record.binding.decisionVersion !== (typeof decision?.version === 'string' ? decision.version : null) ||
    record.binding.policyVersionHash !== (toolCall.policyVersionHash ?? null) ||
    !executionAttemptGovernanceBindingMatches(record, toolCall)
  ) {
    return false;
  }

  const approval = record.binding.approvalId
    ? approvals.get(record.binding.approvalId)
    : [...approvals.values()].find((candidate) => candidate.toolCallId === record.toolCallId && candidate.status === 'approved');
  if (record.binding.approvalId !== null) {
    if (
      !approval ||
      approval.status !== 'approved' ||
      approval.authorizationConsumedReason !== 'approved' ||
      !approval.authorizationConsumedAt ||
      !approval.authorization ||
      !approvalAuthorization ||
      !isValidApprovalAuthorization(approval.authorization) ||
      !isValidApprovalAuthorization(approvalAuthorization) ||
      approvalAuthorizationExpired(approval.authorization) ||
      approvalAuthorizationExpired(approvalAuthorization) ||
      approval.authorization.authorizationHash !== approvalAuthorization.authorizationHash ||
      approval.toolCallId !== record.toolCallId ||
      (approval.workspaceId ?? 'default') !== record.workspaceId ||
      approval.approvedInputHash !== record.inputHash ||
      approval.approvedEnvelopeHash !== record.binding.actionEnvelopeHash ||
      record.binding.approvalAuthorizationHash !== (approval.authorization?.authorizationHash ?? null) ||
      record.binding.approvalAuthorizationNonce !== (approval.authorization?.nonce ?? null)
    ) {
      return false;
    }
  } else if (
    record.binding.approvalAuthorizationHash !== null ||
    record.binding.approvalAuthorizationNonce !== null
  ) {
    return false;
  }

  if (record.binding.receiptId !== null) {
    const receipt = receipts.get(record.binding.receiptId);
    if (
      !receipt ||
      receipt.toolCallId !== record.toolCallId ||
      receipt.workspaceId !== record.workspaceId ||
      receipt.receiptHash !== record.binding.receiptHash ||
      receipt.approvedEnvelopeHash !== record.binding.actionEnvelopeHash ||
      receipt.approvedInputHash !== record.inputHash ||
      (receipt.approvalId ?? null) !== record.binding.approvalId
    ) {
      return false;
    }
  } else if (record.binding.receiptHash !== null) {
    return false;
  } else if (
    record.binding.actionEnvelopeHash !== (toolCall.actionEnvelopeHash ?? null) ||
    record.inputHash !== toolCall.inputHash
  ) {
    return false;
  }
  return true;
}

function executionAttemptGovernanceBindingMatches(
  record: ExecutionAttemptRecordV1,
  toolCall: ToolCallRecord,
): boolean {
  const contentInfluenceBindingHash = validContentInfluenceBindingHash(toolCall.contentInfluence) ??
    (toolCall.contentInfluence ? 'invalid' : null);
  return (
    record.binding.contentInfluenceBindingHash === contentInfluenceBindingHash &&
    record.binding.influenceScopeId === (toolCall.influenceScopeId ?? null) &&
    record.binding.resultSourceHash === hashJson(toolCall.resultSource ?? null)
  );
}

function executionAttemptTransitionIsValid(input: AtomicExecutionAttemptTransitionInput): boolean {
  if (input.expectedState === 'reserved') {
    if (input.nextState === 'dispatched') return input.outcome === undefined;
    return input.nextState === 'failed_before_dispatch' && input.outcome?.status === input.nextState;
  }
  return (
    input.nextState !== 'reserved' &&
    input.nextState !== 'dispatched' &&
    input.nextState !== 'failed_before_dispatch' &&
    input.outcome?.status === input.nextState
  );
}

function executionAttemptTransitionIsReplay(
  current: ExecutionAttemptRecordV1,
  input: AtomicExecutionAttemptTransitionInput,
): boolean {
  if (current.state !== input.nextState) return false;
  if (current.state === 'dispatched') {
    return input.outcome === undefined && current.dispatchedAt === input.transitionedAt;
  }
  if (!executionAttemptIsTerminal(current.state)) return false;
  return (
    current.completedAt === input.transitionedAt &&
    current.outcome !== undefined &&
    input.outcome !== undefined &&
    hashJson(current.outcome) === hashJson(input.outcome)
  );
}

function transitionedExecutionAttempt(
  current: ExecutionAttemptRecordV1,
  input: AtomicExecutionAttemptTransitionInput,
): ExecutionAttemptRecordV1 {
  if (input.nextState === 'dispatched') {
    return { ...current, dispatchedAt: input.transitionedAt, state: 'dispatched', updatedAt: input.transitionedAt };
  }
  return {
    ...current,
    completedAt: input.transitionedAt,
    outcome: input.outcome,
    state: input.nextState,
    updatedAt: input.transitionedAt,
  };
}

function executionAttemptIsTerminal(state: ExecutionAttemptState): boolean {
  return state !== 'reserved' && state !== 'dispatched';
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toolCallForensicSessionValue(
  toolCall: ToolCallRecord,
  field: 'runId' | 'sessionId',
): string | undefined {
  const canonicalEvidence = isJsonObject(toolCall.decisionTrace?.canonicalRequestEvidence)
    ? toolCall.decisionTrace.canonicalRequestEvidence
    : undefined;
  const session = isJsonObject(canonicalEvidence?.session) ? canonicalEvidence.session : undefined;
  const canonicalValue = isJsonObject(session?.value) ? session.value[field] : undefined;
  if (canonicalValue !== undefined) return typeof canonicalValue === 'string' ? canonicalValue : undefined;
  const legacyValue = toolCall.metadata[field];
  return typeof legacyValue === 'string' ? legacyValue : undefined;
}

function hasApprovalDecision(
  decisions: ApprovalDecisionRecord[] | undefined,
  candidate: ApprovalDecisionRecord,
): boolean {
  return (decisions ?? []).some(
    (decision) =>
      decision.actor === candidate.actor ||
      (candidate.auth?.principalId !== undefined && decision.auth?.principalId === candidate.auth.principalId),
  );
}

function decisionMatchesAuthorization(
  input: AtomicApprovalDecisionInput,
  authorization: ApprovalAuthorizationV1,
): boolean {
  const decision = input.decision;
  if (
    authorization.binding.requirements.requiredApprovals > 1 &&
    (input.editedInput !== undefined || decision.editedInput !== undefined || decision.inputDecision !== 'original')
  ) {
    return false;
  }
  return (
    decision.authorizationVersion === authorization.version &&
    decision.authorizationHash === authorization.authorizationHash &&
    decision.authorizationNonce === authorization.nonce &&
    (decision.decisionId ?? null) === authorization.binding.decision.decisionId &&
    decision.reviewHash === authorization.binding.action.reviewHash &&
    input.reviewHash === authorization.binding.action.reviewHash &&
    decision.approvedInputHash === input.approvedInputHash &&
    decision.approvedEnvelopeHash === input.approvedEnvelopeHash
  );
}

function expireApproval(approval: ApprovalRecord, expiredAt: string): ApprovalRecord {
  return {
    ...approval,
    authorizationConsumedAt: expiredAt,
    authorizationConsumedReason: 'expired',
    expiredAt,
    finalizedAt: expiredAt,
    status: 'expired',
    updatedAt: expiredAt,
  };
}

function priorDecisionsMatchAuthorization(
  decisions: ApprovalDecisionRecord[] | undefined,
  authorization: ApprovalAuthorizationV1,
  approvedInputHash?: string,
  approvedEnvelopeHash?: string,
): boolean {
  return (decisions ?? []).every(
    (decision) =>
      decision.authorizationVersion === authorization.version &&
      decision.authorizationHash === authorization.authorizationHash &&
      decision.authorizationNonce === authorization.nonce &&
      (decision.decisionId ?? null) === authorization.binding.decision.decisionId &&
      decision.reviewHash === authorization.binding.action.reviewHash &&
      (approvedInputHash === undefined || decision.approvedInputHash === approvedInputHash) &&
      (approvedEnvelopeHash === undefined || decision.approvedEnvelopeHash === approvedEnvelopeHash),
  );
}

function sameAuthorization(
  stored: ApprovalAuthorizationV1 | undefined,
  supplied: ApprovalAuthorizationV1,
): stored is ApprovalAuthorizationV1 {
  return (
    stored !== undefined &&
    authorizationIdentityIsUsable(stored) &&
    authorizationIdentityIsUsable(supplied) &&
    stored.authorizationHash === supplied.authorizationHash &&
    stored.nonce === supplied.nonce &&
    JSON.stringify(stored) === JSON.stringify(supplied)
  );
}

function authorizationIdentityIsUsable(authorization: ApprovalAuthorizationV1): boolean {
  try {
    return (
      isValidApprovalAuthorization(authorization) &&
      typeof authorization.binding.action.originalEnvelopeHash === 'string' &&
      typeof authorization.binding.action.originalInputHash === 'string' &&
      typeof authorization.binding.action.reviewHash === 'string' &&
      typeof authorization.binding.approval.approvalId === 'string' &&
      typeof authorization.binding.approval.tenantId === 'string' &&
      typeof authorization.binding.approval.toolCallId === 'string' &&
      typeof authorization.binding.policy.legacyVersionHash === 'string' &&
      Array.isArray(authorization.binding.requirements.eligibleGroups) &&
      Number.isInteger(authorization.binding.requirements.requiredApprovals)
    );
  } catch {
    return false;
  }
}

function workspaceKey(workspaceId: string, id: string): string {
  return `${workspaceId}:${id}`;
}

function contentExposureScopeKey(workspaceId: string, influenceScopeId: string): string {
  return JSON.stringify([workspaceId, influenceScopeId]);
}

function contentExposureRevisionMatches(
  scopes: Map<string, ContentExposureScope>,
  workspaceId: string,
  expected: AtomicExecutionAttemptTransitionInput['contentExposureRevision'],
): boolean {
  if (!expected) return true;
  return (scopes.get(contentExposureScopeKey(workspaceId, expected.influenceScopeId))?.revision ?? 0) === expected.revision;
}

const MAX_MEMORY_EXPOSURE_PREFIX = 1001;

interface ContentExposureScope {
  orderedPrefix: ContentExposureRecord[];
  records: Map<string, ContentExposureRecord>;
  revision: number;
}

function insertIntoBoundedExposurePrefix(
  prefix: ContentExposureRecord[],
  record: ContentExposureRecord,
): void {
  let low = 0;
  let high = prefix.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (compareContentExposure(prefix[middle]!, record) <= 0) low = middle + 1;
    else high = middle;
  }
  if (low >= MAX_MEMORY_EXPOSURE_PREFIX) return;
  prefix.splice(low, 0, record);
  if (prefix.length > MAX_MEMORY_EXPOSURE_PREFIX) prefix.pop();
}

function compareContentExposure(left: ContentExposureRecord, right: ContentExposureRecord): number {
  return left.observedAt.localeCompare(right.observedAt) ||
    left.sourceToolCallId.localeCompare(right.sourceToolCallId);
}

function sameContentExposureEvidence(left: ContentExposureRecord, right: ContentExposureRecord): boolean {
  return left.integrity === right.integrity &&
    (left.sourceId ?? null) === (right.sourceId ?? null) &&
    left.policyVersionHash === right.policyVersionHash;
}

function storedContentExposure(record: ContentExposureRecord): ContentExposureRecord {
  return {
    influenceScopeId: record.influenceScopeId,
    integrity: record.integrity,
    observedAt: record.observedAt,
    policyVersionHash: record.policyVersionHash,
    ...(record.sourceId === undefined ? {} : { sourceId: record.sourceId }),
    sourceToolCallId: record.sourceToolCallId,
    workspaceId: record.workspaceId,
  };
}

function contentExposureLimit(limit: number): number {
  return Number.isFinite(limit) ? Math.min(1000, Math.max(1, Math.trunc(limit))) : 100;
}
