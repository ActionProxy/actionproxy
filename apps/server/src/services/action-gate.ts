import { randomUUID } from 'node:crypto';
import type {
  ActionEnvelope,
  ActionReceiptRecord,
  ApprovalDecisionRecord,
  ApprovalDeliveryRecord,
  ApprovalRecord,
  AuditEvent,
  AuthContext,
  JsonObject,
  RemediationDescriptor,
  RemediationPlan,
  SubmitToolCallRequest,
  ToolCallRecord,
} from '../models';
import type { LocalExecutionMode } from '../config';
import type { ContentIntegrity, PolicyEvaluation, PolicyFile, PolicyRule } from '../policy/policy-types';
import { evaluateContentInfluence, resultSourceForPolicyRule } from '../policy/content-influence';
import type { PolicyEvaluationContext } from '../policy/evaluate-policy';
import {
  createYamlPolicyProvider,
  evaluatePolicyProvider,
  type DeterministicPolicyProvider,
  type PolicyProviderEvaluation,
} from '../policy/policy-provider';
import {
  policyContextFromCanonicalActionRequest,
  policyContextFromSubmit,
  policyContextFromToolCall,
  tracePolicyForToolCall,
  type PolicyDecisionTrace,
} from '../policy/policy-trace';
import {
  canonicalActionRequestEvidence,
  normalizeActionRequest,
  type CanonicalActionRequest,
  type CanonicalActionIngress,
} from '../contracts/action-request';
import {
  buildContentInfluenceEvidence,
  MAX_INFLUENCE_EXPOSURES,
  sameContentInfluenceBinding,
  validContentInfluenceBindingHash,
  validatedContentExposureRevisionGuard,
  type ContentInfluenceEvidenceV1,
} from '../contracts/content-influence';
import { validatedActionProxyDecisionForToolCall } from '../contracts/decision';
import {
  approvalAuthorizationExpired,
  approvalAuthorizationMismatch,
  buildApprovalAuthorization,
  DEFAULT_APPROVAL_AUTHORIZATION_TTL_MS,
  isValidApprovalAuthorization,
} from '../contracts/approval-authorization';
import {
  buildExecutionAttempt,
  executionAttemptOutcome,
  type ExecutionAttemptOutcomeV1,
  type ExecutionAttemptRecordV1,
  type ExecutionAttemptTerminalState,
} from '../contracts/execution-attempt';
import {
  buildExecutionAuthorizationBinding,
  ExecutionAuthorizationError,
  type ExecutionAuthorization,
  type ExecutionAuthorizationAuthority,
  type ExecutionAuthorizationBindingV1,
  type ExecutionAuthorizationProjectionV1,
} from '../contracts/execution-authorization';
import type { ApprovalAuthorizationGuard, ContentExposureRevisionGuard, Store } from '../storage/store';
import type { AuditStore } from '../storage/audit-store';
import type { ToolRegistry } from './tool-registry';
import { ConflictError, ForbiddenError, NotFoundError } from '../errors';
import type { ListToolCallsFilters } from '../storage/store';
import { hashJson } from '../security/crypto';
import { actionEnvelopeForInput, normalizeActionEnvelope, reviewHashFor } from '../security/action-envelope';
import { ACTION_RECEIPT_KEY_ID, signReceipt } from '../security/action-receipts';
import { redactToolCallResult } from '../security/redaction';
import { hasAnyGroup, principalMatchesActor } from '../security/scopes';
import type { ApprovalNotifier, ApprovalNotificationResult } from '../integrations/approval-notifications';
import type { ApprovalNotificationRecipient, ApproverDirectoryService } from './approver-directory';
import type { PolicyDetectorService } from './policy-detector';
import type { TelemetryAttributes, TelemetryRecorder } from '../telemetry/telemetry';
import {
  isRemediationForToolCall,
  metadataWithRemediationLink,
  remediationFromToolResult,
  unavailableRemediation,
} from './remediation';

export interface ExecutionGrantIssuer {
  createGrant(input: {
    actor: string;
    auth?: AuthContext;
    receipt?: ActionReceiptRecord;
    toolCall: ToolCallRecord;
    ttlSeconds?: number;
  }): Promise<unknown>;
}

export interface ActionProxyServiceDeps {
  policy: PolicyFile;
  store: Store;
  auditStore: AuditStore;
  tools: ToolRegistry;
  approverDirectory?: ApproverDirectoryService;
  approvalNotifier?: ApprovalNotifier;
  approvalAuthorizationTtlMs?: number;
  executionGrants?: ExecutionGrantIssuer;
  executionAuthorizations: ExecutionAuthorizationAuthority;
  localExecutionMode?: LocalExecutionMode;
  policyVersionHash?: string;
  policyVersionId?: string;
  policyDetector?: PolicyDetectorService;
  policyProvider?: DeterministicPolicyProvider;
  receiptSigningSecret?: string;
  telemetry?: TelemetryRecorder;
  workspaceId?: string;
}

export interface ApprovalReview {
  actionEnvelope: ActionEnvelope;
  approval: ApprovalRecord;
  contentInfluence?: ContentInfluenceEvidenceV1;
  freshness: ApprovalReviewFreshness;
  policy: {
    decision?: ToolCallRecord['decision'];
    reason?: string;
    risk?: string;
    versionHash?: string;
    versionId?: string;
  };
  proposerRationaleTrust: 'untrusted';
  reviewHash: string;
  toolCall: ToolCallRecord;
}

export interface ApprovalReviewFreshness {
  expiresAt: string;
  renderedAt: string;
  state: 'fresh' | 'stale' | 'warning';
  warnings: Array<{
    code:
      | 'authorization_expired'
      | 'envelope_hash_mismatch'
      | 'original_input_hash_mismatch'
      | 'policy_changed'
      | 'review_hash_mismatch';
    message: string;
    severity: 'stale' | 'warning';
  }>;
}

const approvalReviewTtlMs = 5 * 60 * 1000;

interface EvaluatedInfluenceState {
  evidence: ContentInfluenceEvidenceV1;
}

export class ActionProxyService {
  constructor(private readonly deps: ActionProxyServiceDeps) {}

  async submitToolCall(
    request: SubmitToolCallRequest,
    options: { auth?: AuthContext; idempotencyKey?: string; ingress?: CanonicalActionIngress } = {},
  ): Promise<{ toolCall: ToolCallRecord; approval?: ApprovalRecord }> {
    const now = this.now().toISOString();
    const actor = actorForSubmit(request, options.auth);
    const workspaceId = options.auth?.workspaceId ?? this.deps.workspaceId ?? 'default';
    const toolCallId = `toolcall_${randomUUID()}`;
    const canonicalActionRequest = options.ingress
      ? normalizeActionRequest({
          auth: options.auth,
          idempotencyKey: options.idempotencyKey,
          ingress: options.ingress,
          receivedAt: now,
          request,
          requestId: toolCallId,
          workspaceId,
        })
      : undefined;
    const policyVersionHash = this.currentPolicyVersionHash();
    const policyVersionId = this.currentPolicyVersionId(policyVersionHash);
    const baseProviderEvaluation = this.evaluatePolicyProvider(
      request.toolName,
      canonicalActionRequest
        ? policyContextFromCanonicalActionRequest(canonicalActionRequest)
        : policyContextFromSubmit(request),
      { policyVersionHash, policyVersionId },
    );
    const baseEvaluation = baseProviderEvaluation.trace.evaluation;
    const influenceScopeId = verifiedInfluenceScopeId(canonicalActionRequest);
    const contentInfluence = await this.evaluateInfluence({
      baseEvaluation,
      evaluatedAt: now,
      influenceScopeId,
      policyVersionHash,
      policyVersionId,
      workspaceId,
    });
    const evaluation = effectivePolicyEvaluation(baseEvaluation, contentInfluence?.evidence);
    const providerEvaluation = providerEvaluationWithEffectiveDecision(baseProviderEvaluation, evaluation);
    const actionEnvelope = normalizeActionEnvelope({ actor, auth: options.auth, request });
    const requestHash = hashJson({ input: request, route: 'POST /v1/tool-calls' });

    let toolCall: ToolCallRecord = {
      id: toolCallId,
      workspaceId,
      toolName: request.toolName,
      input: request.input,
      inputHash: actionEnvelope.inputHash,
      actionEnvelope,
      actionEnvelopeHash: actionEnvelope.envelopeHash,
      canonicalActionRequestHash: canonicalActionRequest?.integrity.requestHash,
      canonicalActionRequestVersion: canonicalActionRequest?.version,
      canonicalDecisionInputHash: canonicalActionRequest?.integrity.decisionInputHash,
      canonicalPolicyContext: canonicalActionRequest?.context.policy,
      contentInfluence: contentInfluence?.evidence,
      influenceScopeId,
      requestedBy: actor,
      requestedByAuth: options.auth,
      agentId: request.agentId,
      reason: request.reason,
      metadata: request.metadata ?? {},
      status: 'submitted',
      decision: evaluation.decision,
      authorizationDecision: evaluation.decision,
      authorizationReason: evaluation.reason,
      policyReason: evaluation.reason,
      policyVersionHash,
      policyVersionId,
      resultSource: frozenResultSource(evaluation.rule, this.deps.policy),
      risk: evaluation.risk,
      createdAt: now,
      updatedAt: now,
    };
    toolCall = {
      ...toolCall,
      decisionTrace: {
        ...(await this.decisionTraceForToolCall(toolCall, providerEvaluation)),
        ...(canonicalActionRequest
          ? { canonicalRequestEvidence: canonicalActionRequestEvidence(canonicalActionRequest) }
          : {}),
        ...(contentInfluence ? { contentInfluence: contentInfluence.evidence as unknown as JsonObject } : {}),
      },
    };
    if (requiresContentExposureBeforeRelease(toolCall)) {
      // Classified MCP output starts withheld before any downstream dispatch. This makes
      // every projection fail closed even if the first persistence operation after a
      // known provider outcome fails; release is the explicit state transition that
      // follows durable exposure and audit evidence.
      toolCall = { ...toolCall, resultWithheld: true };
    }
    if (options.idempotencyKey) {
      const reservation = await this.deps.store.createToolCallIdempotentlyAtomically({
        idempotency: {
          createdAt: now,
          key: options.idempotencyKey,
          requestHash,
          route: 'POST /v1/tool-calls',
          toolCallId: toolCall.id,
          workspaceId,
        },
        toolCall,
      });
      if (reservation.outcome === 'conflict') {
        throw new ConflictError('Idempotency key was already used for a different request.');
      }
      if (reservation.outcome === 'replay') {
        const replayedToolCall = await this.getToolCall(reservation.toolCall.id, options.auth);
        const approval = await this.deps.store.getApprovalByToolCallId(replayedToolCall.id);
        return approval ? { approval, toolCall: replayedToolCall } : { toolCall: replayedToolCall };
      }
      toolCall = reservation.toolCall;
    } else {
      await this.deps.store.createToolCall(toolCall);
    }
    await this.deps.policyDetector?.observeTool({
      agentId: request.agentId,
      auth: options.auth,
      input: request.input,
      policy: this.deps.policy,
      source: runtimeObservationSource(request),
      toolName: request.toolName,
      workspaceId,
    });
    await this.audit('tool_call.submitted', {
      toolCallId: toolCall.id,
      actor,
      auth: options.auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId,
      data: {
        agentId: request.agentId,
        decisionV1: toolCall.decisionTrace?.decisionV1,
        input: request.input,
        reason: request.reason,
        toolName: request.toolName,
      },
    });
    await this.audit('action.envelope_created', {
      toolCallId: toolCall.id,
      actor,
      auth: options.auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId,
      data: {
        actionEnvelope,
        actionEnvelopeHash: actionEnvelope.envelopeHash,
        canonicalActionRequestHash: canonicalActionRequest?.integrity.requestHash,
        canonicalActionRequestVersion: canonicalActionRequest?.version,
        canonicalDecisionInputHash: canonicalActionRequest?.integrity.decisionInputHash,
        canonicalPolicyContext: canonicalActionRequest?.context.policy,
        canonicalRequestEvidence: canonicalActionRequest
          ? canonicalActionRequestEvidence(canonicalActionRequest)
          : undefined,
        executionMode: actionEnvelope.executionMode,
        protocol: actionEnvelope.protocol,
        source: actionEnvelope.source,
      },
    });
    if (contentInfluence) {
      await this.audit('content.influence_evaluated', {
        toolCallId: toolCall.id,
        actor,
        auth: options.auth,
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        workspaceId,
        data: contentInfluence.evidence as unknown as JsonObject,
      });
    }
    this.telemetry('tool_call.submit', telemetryForToolCall(toolCall, { status: toolCall.status }));
    this.telemetry('policy.evaluate', telemetryForToolCall(toolCall, {
      decision: evaluation.decision,
      matched_rule: evaluation.matchedRule,
      'policy.decision': evaluation.decision,
    }));

    if (
      contentInfluence?.evidence.baseDecision !== 'deny' &&
      contentInfluence?.evidence.effectiveDecision === 'deny'
    ) {
      await this.audit('content.influence_denied', {
        toolCallId: toolCall.id,
        actor,
        auth: options.auth,
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        workspaceId,
        data: minimizedInfluenceAudit(contentInfluence.evidence),
      });
    }

    if (evaluation.decision === 'deny') {
      toolCall = { ...toolCall, status: 'blocked', updatedAt: new Date().toISOString() };
      await this.deps.store.updateToolCall(toolCall);
      await this.audit('policy.deny', {
        toolCallId: toolCall.id,
        actor,
        auth: options.auth,
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        workspaceId,
        data: { reason: evaluation.reason, risk: evaluation.risk, matchedRule: evaluation.matchedRule },
      });
      this.telemetry('policy.deny', telemetryForToolCall(toolCall, {
        decision: evaluation.decision,
        matched_rule: evaluation.matchedRule,
        status: toolCall.status,
      }));
      return { toolCall };
    }

    if (evaluation.decision === 'require_approval') {
      const influenceIntroducedApproval = contentInfluence?.evidence.baseDecision === 'allow';
      const resolvedRecipients = await this.resolveApprovalRecipients(evaluation.rule, workspaceId);
      const approvalId = `approval_${randomUUID()}`;
      const reviewHash = reviewHashFor({
        actionEnvelopeHash: actionEnvelope.envelopeHash,
        approvalId,
        policyVersionHash: toolCall.policyVersionHash,
        toolCallId: toolCall.id,
      });
      const approverUsers = approvalApproverUsersFor(evaluation.rule, resolvedRecipients);
      const approverGroups = evaluation.rule.approvers?.groups ?? [];
      const requiredApprovals = evaluation.rule.approvers?.requiredApprovals ?? 1;
      const separationOfDuties = evaluation.rule.approvers?.separationOfDuties ?? false;
      const expiresAt = new Date(
        Date.parse(now) + Math.max(1, this.deps.approvalAuthorizationTtlMs ?? DEFAULT_APPROVAL_AUTHORIZATION_TTL_MS),
      ).toISOString();
      const authorization = buildApprovalAuthorization({
        approvalId,
        approverGroups,
        approverUsers,
        expiresAt,
        issuedAt: now,
        originalEnvelopeHash: actionEnvelope.envelopeHash,
        originalInputHash: actionEnvelope.inputHash,
        requestedBy: actor,
        requestedByPrincipalId: options.auth?.principalId,
        requiredApprovals,
        reviewHash,
        separationOfDuties,
        toolCall,
      });
      const approval: ApprovalRecord = {
        id: approvalId,
        workspaceId,
        toolCallId: toolCall.id,
        status: 'pending',
        requestedBy: actor,
        requestedByAuth: options.auth,
        authorization,
        originalInput: request.input,
        originalEnvelopeHash: actionEnvelope.envelopeHash,
        originalInputHash: actionEnvelope.inputHash,
        reviewHash,
        approverUsers,
        approverGroups,
        requiredApprovals,
        separationOfDuties,
        decisions: [],
        createdAt: now,
        updatedAt: now,
      };

      toolCall = { ...toolCall, status: 'pending_approval', updatedAt: new Date().toISOString() };
      await this.deps.store.updateToolCall(toolCall);
      await this.deps.store.createApproval(approval);
      await this.audit('policy.require_approval', {
        toolCallId: toolCall.id,
        actor,
        auth: options.auth,
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        workspaceId,
        data: { reason: evaluation.reason, risk: evaluation.risk, matchedRule: evaluation.matchedRule },
      });
      if (influenceIntroducedApproval) {
        await this.audit('content.influence_approval_required', {
          toolCallId: toolCall.id,
          approvalId: approval.id,
          actor,
          auth: options.auth,
          inputHash: toolCall.inputHash,
          policyVersionHash: toolCall.policyVersionHash,
          policyVersionId: toolCall.policyVersionId,
          workspaceId,
          data: minimizedInfluenceAudit(contentInfluence!.evidence),
        });
      }
      await this.audit('approval.created', {
        toolCallId: toolCall.id,
        approvalId: approval.id,
        actor,
        auth: options.auth,
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        workspaceId,
        data: {
          approverGroups: approval.approverGroups ?? [],
          approverUsers: approval.approverUsers ?? [],
          approvalAuthorizationHash: authorization.authorizationHash,
          approvalAuthorizationVersion: authorization.version,
          expiresAt: authorization.expiresAt,
          notificationChannels: evaluation.rule.notify?.channels ?? null,
          originalInput: request.input,
          originalInputHash: actionEnvelope.inputHash,
          originalEnvelopeHash: actionEnvelope.envelopeHash,
          reviewHash,
          contentInfluence: contentInfluence?.evidence ?? null,
          requiredApprovals: approval.requiredApprovals ?? 1,
          separationOfDuties: approval.separationOfDuties ?? false,
        },
      });
      this.telemetry('approval.created', telemetryForToolCall(toolCall, {
        'approval.id': approval.id,
        'approval.status': approval.status,
        decision: evaluation.decision,
        matched_rule: evaluation.matchedRule,
        status: toolCall.status,
      }));
      await this.notifyApprovalRequired(toolCall, approval, actor, options.auth, evaluation.rule, resolvedRecipients);
      return { toolCall, approval };
    }

    await this.audit('policy.allow', {
      toolCallId: toolCall.id,
      actor,
      auth: options.auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId,
      data: { reason: evaluation.reason, risk: evaluation.risk, matchedRule: evaluation.matchedRule },
    });
    this.telemetry('policy.allow', telemetryForToolCall(toolCall, {
      decision: evaluation.decision,
      matched_rule: evaluation.matchedRule,
    }));

    const receipt = await this.createActionReceipt({
      actor,
      auth: options.auth,
      decisionKind: 'policy_allow',
      input: request.input,
      toolCall,
    });
    toolCall = actionEnvelope.executionMode === 'external_grant'
      ? await this.authorizeExternalExecution(
          toolCall,
          request.input,
          actor,
          options.auth,
          evaluation.rule.externalExecution?.grantTtlSeconds,
          receipt,
        )
      : await this.executeToolCall(toolCall, request.input, actor, options.auth, receipt);
    return { toolCall };
  }

  async getToolCall(id: string, auth?: AuthContext): Promise<ToolCallRecord> {
    const toolCall = await this.deps.store.getToolCall(id);
    if (!toolCall) throw new NotFoundError(`Tool call not found: ${id}`);
    assertWorkspace(toolCall.workspaceId, auth);
    return toolCall;
  }

  async getDecisionTrace(id: string, auth?: AuthContext): Promise<PolicyDecisionTrace> {
    const toolCall = await this.getToolCall(id, auth);
    if (isPolicyDecisionTrace(toolCall.decisionTrace)) return toolCall.decisionTrace;
    const policyVersionHash = this.currentPolicyVersionHash();
    return tracePolicyForToolCall({
      approverDirectory: this.deps.approverDirectory,
      policy: this.deps.policy,
      policyVersionHash,
      policyVersionId: this.currentPolicyVersionId(policyVersionHash),
      toolCall,
    });
  }

  async listToolCalls(filters: ListToolCallsFilters = {}, auth?: AuthContext): Promise<ToolCallRecord[]> {
    return this.deps.store.listToolCalls({
      ...filters,
      workspaceId: auth?.workspaceId ?? filters.workspaceId,
    });
  }

  async listExecutionAttemptsForToolCall(
    toolCallId: string,
    auth?: AuthContext,
  ): Promise<ExecutionAttemptRecordV1[]> {
    const toolCall = await this.getToolCall(toolCallId, auth);
    return this.deps.store.listExecutionAttempts(toolCall.workspaceId ?? auth?.workspaceId ?? this.deps.workspaceId ?? 'default', {
      toolCallId,
    });
  }

  async listPendingApprovals(auth?: AuthContext): Promise<ApprovalRecord[]> {
    const approvals = (await this.deps.store.listPendingApprovals()).filter(
      (approval) => !auth || (approval.workspaceId ?? 'default') === auth.workspaceId,
    );
    const current = await Promise.all(
      approvals.map(async (approval) => {
        const toolCall = await this.deps.store.getToolCall(approval.toolCallId);
        return toolCall ? this.expireApprovalIfNeeded(approval, toolCall, auth) : approval;
      }),
    );
    return current.filter((approval) => approval.status === 'pending');
  }

  async getApproval(id: string, auth?: AuthContext): Promise<ApprovalRecord> {
    const approval = await this.deps.store.getApproval(id);
    if (!approval) throw new NotFoundError(`Approval not found: ${id}`);
    assertWorkspace(approval.workspaceId, auth);
    const toolCall = await this.deps.store.getToolCall(approval.toolCallId);
    return toolCall ? this.expireApprovalIfNeeded(approval, toolCall, auth) : approval;
  }

  async getApprovalForPrincipal(id: string, auth: AuthContext): Promise<ApprovalRecord> {
    const approval = await this.getApproval(id, auth);
    const isRequester = approval.requestedByAuth?.principalId === auth.principalId;
    const isNamedApprover = approval.approverUsers?.includes(auth.principalId) === true;
    const approverGroups = approval.approverGroups ?? [];
    const isGroupApprover = approval.approverUsers === undefined
      && approverGroups.length > 0
      && hasAnyGroup(auth, approverGroups);
    if (!isRequester && !isNamedApprover && !isGroupApprover) {
      throw new NotFoundError(`Approval not found: ${id}`);
    }
    return approval;
  }

  async listApprovalDeliveries(approvalId: string, auth?: AuthContext): Promise<ApprovalDeliveryRecord[]> {
    const approval = await this.deps.store.getApproval(approvalId);
    if (!approval) throw new NotFoundError(`Approval not found: ${approvalId}`);
    assertWorkspace(approval.workspaceId, auth);
    return this.deps.store.listApprovalDeliveries(approvalId);
  }

  async getApprovalReview(approvalId: string, auth?: AuthContext): Promise<ApprovalReview> {
    const approval = await this.getApproval(approvalId, auth);
    const toolCall = await this.getToolCall(approval.toolCallId, auth);
    const actionEnvelope = this.actionEnvelopeForToolCall(toolCall);
    const reviewHash = reviewHashFor({
      actionEnvelopeHash: actionEnvelope.envelopeHash,
      approvalId: approval.id,
      policyVersionHash: toolCall.policyVersionHash,
      toolCallId: toolCall.id,
    });
    await this.audit('approval.review_rendered', {
      toolCallId: toolCall.id,
      approvalId: approval.id,
      actor: actorForDecision(undefined, auth),
      auth,
      inputHash: actionEnvelope.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: {
        actionEnvelopeHash: actionEnvelope.envelopeHash,
        reviewHash,
      },
    });
    return {
      actionEnvelope,
      approval,
      contentInfluence: toolCall.contentInfluence,
      freshness: this.approvalReviewFreshness({ actionEnvelope, approval, reviewHash, toolCall }),
      policy: {
        decision: toolCall.decision,
        reason: toolCall.policyReason,
        risk: toolCall.risk,
        versionHash: toolCall.policyVersionHash,
        versionId: toolCall.policyVersionId,
      },
      proposerRationaleTrust: 'untrusted',
      reviewHash,
      toolCall,
    };
  }

  async resendApprovalNotifications(approvalId: string, auth?: AuthContext): Promise<ApprovalDeliveryRecord[]> {
    const approval = await this.getApproval(approvalId, auth);
    if (approval.status !== 'pending') throw new ConflictError(`Approval is already ${approval.status}`);
    const toolCall = await this.getToolCall(approval.toolCallId, auth);
    const evaluation = this.evaluatePolicy(toolCall.toolName, policyContextFromToolCall(toolCall));
    return this.notifyApprovalRequired(toolCall, approval, actorForDecision(undefined, auth), auth, evaluation.rule);
  }

  async recordAuditEvent(
    type: AuditEvent['type'],
    payload: {
      toolCallId?: string;
      approvalId?: string;
      actor?: string;
      auth?: AuthContext;
      data: JsonObject;
      workspaceId?: string;
    },
  ): Promise<void> {
    await this.audit(type, payload);
  }

  private evaluatePolicy(toolName: string, context: PolicyEvaluationContext = {}) {
    return this.evaluatePolicyProvider(toolName, context).trace.evaluation;
  }

  private evaluatePolicyProvider(
    toolName: string,
    context: PolicyEvaluationContext = {},
    identity: { policyVersionHash?: string; policyVersionId?: string } = {},
  ): PolicyProviderEvaluation {
    const policyVersionHash = identity.policyVersionHash ?? this.currentPolicyVersionHash();
    const policyVersionId = identity.policyVersionId ?? this.currentPolicyVersionId(policyVersionHash);
    return evaluatePolicyProvider(
      this.deps.policyProvider ?? createYamlPolicyProvider(this.deps.policy, { policyVersionHash, policyVersionId }),
      { context, toolName },
    );
  }

  private async evaluateInfluence(input: {
    baseEvaluation: PolicyEvaluation;
    evaluatedAt: string;
    influenceScopeId?: string;
    policyVersionHash: string;
    policyVersionId?: string;
    workspaceId: string;
  }): Promise<EvaluatedInfluenceState | undefined> {
    const selectedRule = input.baseEvaluation.rule.influence;
    if (!selectedRule) return undefined;

    let exposureLookup;
    if (input.influenceScopeId) {
      try {
        exposureLookup = await this.deps.store.listContentExposures({
          influenceScopeId: input.influenceScopeId,
          limit: MAX_INFLUENCE_EXPOSURES,
          workspaceId: input.workspaceId,
        });
      } catch {
        // Unavailable evidence is never interpreted as a clean scope.
        exposureLookup = { overflow: true, records: [], revision: -1 };
      }
    }
    const observedIntegrities = exposureLookup?.overflow
      ? ['unknown' as const]
      : exposureLookup?.records.map((record) => record.integrity);
    const evaluation = evaluateContentInfluence(input.baseEvaluation, {
      observedIntegrities,
      scopeVerified: Boolean(input.influenceScopeId),
    });
    return {
      evidence: buildContentInfluenceEvidence({
        evaluatedAt: input.evaluatedAt,
        evaluation,
        exposureLookup,
        influenceScopeId: input.influenceScopeId,
        policyVersionHash: input.policyVersionHash,
        policyVersionId: input.policyVersionId,
        selectedRule,
      }),
    };
  }

  private async revalidatedInfluence(
    toolCall: ToolCallRecord,
    baseEvaluation: PolicyEvaluation,
  ): Promise<EvaluatedInfluenceState | undefined> {
    const selectedRule = baseEvaluation.rule.influence;
    const stored = toolCall.contentInfluence;
    if (!selectedRule || !stored || !validContentInfluenceBindingHash(stored)) return undefined;
    const influenceScopeId = verifiedStoredInfluenceScopeId(toolCall);
    const observedIntegrities = stored.observedSources.filter((source): source is ContentIntegrity => source !== 'none');
    const evaluation = evaluateContentInfluence(baseEvaluation, {
      observedIntegrities,
      scopeVerified: Boolean(influenceScopeId),
    });
    if (
      stored.influenceScope.id !== influenceScopeId ||
      stored.influenceScope.verified !== Boolean(influenceScopeId) ||
      stored.policy.versionHash !== this.currentPolicyVersionHash() ||
      (stored.policy.versionId ?? null) !== (this.currentPolicyVersionId() ?? null) ||
      hashJson(stored.selectedRule) !== hashJson(selectedRule) ||
      stored.baseDecision !== evaluation.baseDecision ||
      stored.effectiveDecision !== evaluation.effectiveDecision ||
      hashJson(stored.observedSources) !== hashJson(evaluation.observedSources)
    ) {
      return undefined;
    }
    return { evidence: stored };
  }

  private async recordContentExposureBeforeRelease(
    toolCall: ToolCallRecord,
    actor: string,
    auth?: AuthContext,
  ): Promise<boolean> {
    const source = toolCall.resultSource;
    const influenceScopeId = verifiedStoredInfluenceScopeId(toolCall);
    if (!source || source === 'none') return true;

    try {
      if (!influenceScopeId) {
        throw new Error('Verified influence-scope evidence is unavailable for this classified MCP result.');
      }
      const outcome = await this.deps.store.recordContentExposure({
        influenceScopeId,
        integrity: source.integrity,
        observedAt: this.now().toISOString(),
        policyVersionHash: toolCall.policyVersionHash ?? this.currentPolicyVersionHash(),
        sourceId: source.sourceId,
        sourceToolCallId: toolCall.id,
        workspaceId: toolCall.workspaceId ?? auth?.workspaceId ?? this.deps.workspaceId ?? 'default',
      });
      if (outcome === 'conflict') {
        throw new Error('Existing content-exposure evidence conflicts with the frozen result source.');
      }
      await this.audit('content.exposure_recorded', {
        toolCallId: toolCall.id,
        actor,
        auth,
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        workspaceId: toolCall.workspaceId,
        data: {
          influenceScopeId,
          instructionAuthority: 'none',
          integrity: source.integrity,
          recordOutcome: outcome,
          sourceId: source.sourceId ?? null,
          sourceToolCallId: toolCall.id,
        },
      });
      return true;
    } catch {
      try {
        await this.audit('content.result_withheld', {
          toolCallId: toolCall.id,
          actor: 'actionproxy:content-influence',
          auth,
          inputHash: toolCall.inputHash,
          policyVersionHash: toolCall.policyVersionHash,
          policyVersionId: toolCall.policyVersionId,
          workspaceId: toolCall.workspaceId,
          data: {
            influenceScopeId,
            integrity: source.integrity,
            reason: 'content_exposure_persistence_failed',
            sourceId: source.sourceId ?? null,
          },
        });
      } catch {
        // The known provider outcome remains authoritative; release still fails closed.
      }
      return false;
    }
  }

  private async contentInfluenceBindingFailure(
    toolCall: ToolCallRecord,
    current: EvaluatedInfluenceState | undefined,
    influenceExpected = false,
  ): Promise<string | undefined> {
    const stored = toolCall.contentInfluence;
    if (!stored && !current && !influenceExpected) return undefined;
    if (stored && current && sameContentInfluenceBinding(stored, current.evidence)) return undefined;

    try {
      await this.audit('content.influence_binding_stale', {
        toolCallId: toolCall.id,
        actor: 'actionproxy:content-influence',
        auth: toolCall.requestedByAuth,
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        workspaceId: toolCall.workspaceId,
        data: {
          currentBindingHash: current?.evidence.bindingHash ?? null,
          storedBindingHash: stored?.bindingHash ?? null,
        },
      });
    } catch {
      // A stale authorization remains denied even if secondary audit export fails.
    }
    return 'Content-influence evidence changed after authorization. Resubmit the action for a new decision.';
  }

  /** Used by the external-grant boundary immediately before durable dispatch. */
  async assertExternalDispatchCurrent(toolCall: ToolCallRecord, input: JsonObject): Promise<void> {
    const failure = await this.finalPolicyRevalidationFailure(toolCall, input);
    if (failure) throw new ForbiddenError(failure);
  }

  async getRemediationPlan(toolCallId: string, auth?: AuthContext): Promise<RemediationPlan> {
    const toolCall = await this.getToolCall(toolCallId, auth);
    const receipt = await this.deps.store.getActionReceiptByToolCallId(toolCall.id);
    if (receipt) assertWorkspace(receipt.workspaceId, auth);
    const relatedToolCalls = (await this.listToolCalls({ limit: 1000 }, auth)).filter((candidate) =>
      isRemediationForToolCall(candidate, toolCall.id),
    );

    const remediation =
      toolCall.status !== 'executed'
        ? unavailableRemediation(`Only executed tool calls can be remediated. Current status: ${toolCall.status}.`)
        : receipt === undefined
          ? unavailableRemediation('No signed receipt is available for this tool call.')
          : receipt.outcome === undefined
            ? unavailableRemediation('No execution outcome is available for this receipt.')
            : receipt.outcome.status !== 'succeeded'
              ? unavailableRemediation('Only successful execution outcomes can provide remediation.')
              : (receipt.outcome.remediation ??
                unavailableRemediation('The execution outcome did not include remediation instructions.'));

    await this.audit('remediation.plan_rendered', {
      toolCallId: toolCall.id,
      actor: actorForDecision(undefined, auth),
      auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: {
        kind: remediation.kind,
        reason: remediation.reason,
        receiptHash: receipt?.receiptHash ?? null,
        receiptId: receipt?.id ?? null,
        relatedToolCallIds: relatedToolCalls.map((related) => related.id),
        status: remediation.status,
        toolName: remediation.toolName ?? null,
      },
    });

    return {
      originalToolCall: toolCall,
      receipt,
      relatedToolCalls,
      remediation,
    };
  }

  async submitRemediation(
    toolCallId: string,
    input: {
      agentId?: string;
      input?: JsonObject;
      metadata?: JsonObject;
      reason?: string;
      requestedBy?: string;
    } = {},
    options: { auth?: AuthContext; idempotencyKey?: string } = {},
  ): Promise<{ approval?: ApprovalRecord; plan: RemediationPlan; toolCall: ToolCallRecord }> {
    const plan = await this.getRemediationPlan(toolCallId, options.auth);
    const remediation = plan.remediation;
    if (remediation.status !== 'available' || !remediation.toolName || remediation.input === undefined) {
      throw new ConflictError('Remediation is not available for this tool call.');
    }

    const baseMetadata = {
      ...(remediation.metadata ?? {}),
      ...(input.metadata ?? {}),
    };
    const submitResult = await this.submitToolCall(
      {
        action: remediation.action,
        agentId: input.agentId ?? `${plan.originalToolCall.agentId}:remediation`,
        input: input.input ?? remediation.input,
        metadata: metadataWithRemediationLink({
          baseMetadata,
          kind: remediation.kind,
          originalReceiptHash: plan.receipt?.receiptHash,
          originalReceiptId: plan.receipt?.id,
          originalToolCallId: plan.originalToolCall.id,
        }),
        reason: input.reason ?? `Remediate ${plan.originalToolCall.toolName}: ${remediation.reason}`,
        requestedBy: input.requestedBy ?? actorForDecision(undefined, options.auth),
        toolName: remediation.toolName,
      },
      {
        auth: options.auth,
        idempotencyKey: options.idempotencyKey ? `remediation:${toolCallId}:${options.idempotencyKey}` : undefined,
      },
    );

    await this.audit('remediation.submitted', {
      toolCallId: submitResult.toolCall.id,
      actor: actorForDecision(input.requestedBy, options.auth),
      auth: options.auth,
      inputHash: submitResult.toolCall.inputHash,
      policyVersionHash: submitResult.toolCall.policyVersionHash,
      policyVersionId: submitResult.toolCall.policyVersionId,
      workspaceId: submitResult.toolCall.workspaceId,
      data: {
        kind: remediation.kind,
        originalReceiptHash: plan.receipt?.receiptHash ?? null,
        originalReceiptId: plan.receipt?.id ?? null,
        originalToolCallId: plan.originalToolCall.id,
        remediationToolCallId: submitResult.toolCall.id,
        status: submitResult.toolCall.status,
        toolName: remediation.toolName,
      },
    });

    return {
      ...submitResult,
      plan,
    };
  }

  async approveApproval(
    approvalId: string,
    input: {
      approvalNonce?: string;
      approvedBy?: string;
      inputDecision?: { mode: 'edited'; input: JsonObject } | { mode: 'original' };
      note?: string;
      editedInput?: JsonObject | null;
      reviewHash?: string;
    },
    auth?: AuthContext,
  ): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
    const initial = await this.loadApprovalState(approvalId, auth);
    const initialApproval = await this.expireApprovalIfNeeded(initial.approval, initial.toolCall, auth);
    if (initialApproval.status !== 'pending') {
      throw new ConflictError(`Approval is already ${initialApproval.status}`);
    }
    this.assertCanDecideApproval(initialApproval, auth);
    this.assertClientApprovalNonce(initialApproval, input.approvalNonce);

    // Reload immediately before policy evaluation and the storage CAS. No execution decision
    // relies on the earlier route-facing snapshot.
    const authoritative = await this.loadApprovalState(approvalId, auth);
    const approval = await this.expireApprovalIfNeeded(authoritative.approval, authoritative.toolCall, auth);
    const toolCall = authoritative.toolCall;
    if (approval.status !== 'pending') throw new ConflictError(`Approval is already ${approval.status}`);
    if (toolCall.status !== 'pending_approval') throw new ConflictError(`Tool call is not pending approval: ${toolCall.status}`);
    this.assertCanDecideApproval(approval, auth);
    this.assertClientApprovalNonce(approval, input.approvalNonce);

    const now = this.now().toISOString();
    const actor = actorForDecision(input.approvedBy, auth);
    const actionEnvelope = this.actionEnvelopeForToolCall(toolCall);
    const expectedReviewHash = reviewHashFor({
      actionEnvelopeHash: actionEnvelope.envelopeHash,
      approvalId: approval.id,
      policyVersionHash: toolCall.policyVersionHash,
      toolCallId: toolCall.id,
    });
    if (input.reviewHash !== undefined && input.reviewHash !== expectedReviewHash) {
      throw new ConflictError('Approval review hash is stale or does not match this approval.');
    }
    const inputDecision = approvalInputDecision(input);
    const requiredApprovals = Math.max(1, approval.requiredApprovals ?? 1);
    if (inputDecision.mode === 'edited' && requiredApprovals > 1) {
      throw new ConflictError('Edited input is not supported when requiredApprovals is greater than 1.');
    }
    const approvedInput = inputDecision.mode === 'edited' ? inputDecision.input : approval.originalInput;
    const approvedEnvelope = actionEnvelopeForInput(actionEnvelope, approvedInput);
    this.assertApprovalBindingIsCurrent(approval, actionEnvelope, expectedReviewHash);
    await this.assertApprovalPolicyIsCurrent(toolCall, approvedInput, approvedEnvelope);
    const authorization = this.approvalAuthorizationGuard(approval, toolCall);
    const decision: ApprovalDecisionRecord = {
      actor,
      auth,
      authorizationHash: authorization.authorization.authorizationHash,
      authorizationNonce: authorization.authorization.nonce,
      authorizationVersion: authorization.authorization.version,
      approvedEnvelopeHash: approvedEnvelope.envelopeHash,
      approvedInputHash: approvedEnvelope.inputHash,
      decisionId: authorization.authorization.binding.decision.decisionId ?? undefined,
      decidedAt: now,
      editedInput: inputDecision.mode === 'edited' ? inputDecision.input : undefined,
      inputDecision: inputDecision.mode,
      note: input.note,
      reviewHash: expectedReviewHash,
    };
    const transition = await this.deps.store.recordApprovalDecisionAtomically({
      approvalId: approval.id,
      authorization,
      approvedEnvelopeHash: approvedEnvelope.envelopeHash,
      approvedInputHash: approvedEnvelope.inputHash,
      decision,
      editedInput: inputDecision.mode === 'edited' ? inputDecision.input : undefined,
      note: input.note,
      reviewHash: expectedReviewHash,
      updatedAt: now,
      contentExposureRevision: contentExposureRevisionGuard(toolCall),
    });
    if (transition.outcome === 'not_found') throw new NotFoundError(`Approval not found: ${approvalId}`);
    if (transition.outcome === 'duplicate') {
      throw new ConflictError('This principal has already approved this request.');
    }
    if (transition.outcome === 'authorization_mismatch') {
      throw new ConflictError('Approval authorization binding changed. Resubmit the action.');
    }
    if (transition.outcome === 'content_influence_mismatch') {
      await this.auditInfluenceDispatchMismatchBestEffort(toolCall, auth);
      throw new ConflictError('Content-influence evidence changed at approval finalization. Resubmit the action.');
    }
    if (transition.outcome === 'expired') {
      await this.recordExpiredApproval(transition.approval, toolCall, auth);
      throw new ConflictError('Approval authorization has expired. Resubmit the action.');
    }
    if (transition.outcome === 'replayed') {
      throw new ConflictError('Approval authorization nonce has already been consumed.');
    }
    if (transition.outcome === 'already_final') {
      throw new ConflictError(`Approval is already ${transition.approval?.status ?? 'finalized'}`);
    }
    const updatedApproval = transition.approval!;
    const nextDecisions = updatedApproval.decisions ?? [];
    const isFinalApproval = transition.outcome === 'finalized';
    await this.audit(isFinalApproval ? 'approval.approved' : 'approval.approval_recorded', {
      toolCallId: toolCall.id,
      approvalId: approval.id,
      actor,
      auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: {
        approvalsRecorded: nextDecisions.length,
        requiredApprovals,
        note: input.note ?? null,
        originalInput: approval.originalInput,
        editedInput: inputDecision.mode === 'edited' ? inputDecision.input : null,
        inputDecision: inputDecision.mode,
        originalInputHash: approval.originalInputHash ?? actionEnvelope.inputHash,
        originalEnvelopeHash: approval.originalEnvelopeHash ?? actionEnvelope.envelopeHash,
        approvedInputHash: approvedEnvelope.inputHash,
        approvedEnvelopeHash: approvedEnvelope.envelopeHash,
        approvalAuthorizationHash: authorization.authorization.authorizationHash,
        approvalAuthorizationVersion: authorization.authorization.version,
        reviewHash: expectedReviewHash,
      },
    });
    this.telemetry(isFinalApproval ? 'approval.approved' : 'approval.approval_recorded', telemetryForToolCall(toolCall, {
      'approval.id': approval.id,
      'approval.status': updatedApproval.status,
    }));

    if (!isFinalApproval) {
      return { approval: updatedApproval, toolCall };
    }

    const receipt = await this.createActionReceipt({
      actor,
      approval: updatedApproval,
      auth,
      decisionKind: 'human_approval',
      input: approvedInput,
      reviewHash: expectedReviewHash,
      toolCall,
    });
    const executedToolCall = approvedEnvelope.executionMode === 'external_grant'
      ? await this.authorizeExternalExecution(toolCall, approvedInput, actor, auth, undefined, receipt, updatedApproval)
      : await this.executeToolCall(toolCall, approvedInput, actor, auth, receipt, updatedApproval);

    return { approval: updatedApproval, toolCall: executedToolCall };
  }

  async rejectApproval(
    approvalId: string,
    input: { approvalNonce?: string; rejectedBy?: string; reason?: string },
    auth?: AuthContext,
  ): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
    const initial = await this.loadApprovalState(approvalId, auth);
    const initialApproval = await this.expireApprovalIfNeeded(initial.approval, initial.toolCall, auth);
    if (initialApproval.status !== 'pending') {
      throw new ConflictError(`Approval is already ${initialApproval.status}`);
    }
    this.assertCanDecideApproval(initialApproval, auth);
    this.assertClientApprovalNonce(initialApproval, input.approvalNonce);

    const authoritative = await this.loadApprovalState(approvalId, auth);
    const approval = await this.expireApprovalIfNeeded(authoritative.approval, authoritative.toolCall, auth);
    const toolCall = authoritative.toolCall;
    if (approval.status !== 'pending') throw new ConflictError(`Approval is already ${approval.status}`);
    const now = this.now().toISOString();
    const actor = actorForDecision(input.rejectedBy, auth);
    this.assertCanDecideApproval(approval, auth);
    this.assertClientApprovalNonce(approval, input.approvalNonce);

    const transition = await this.deps.store.rejectApprovalAtomically({
      approvalId: approval.id,
      authorization: this.safeTerminalAuthorizationGuard(approval, toolCall),
      reason: input.reason,
      rejectedBy: actor,
      updatedAt: now,
    });
    if (transition.outcome === 'not_found') throw new NotFoundError(`Approval not found: ${approvalId}`);
    if (transition.outcome === 'authorization_mismatch') {
      throw new ConflictError('Approval authorization binding changed. Cancel or resubmit the action.');
    }
    if (transition.outcome === 'expired') {
      await this.recordExpiredApproval(transition.approval, toolCall, auth);
      throw new ConflictError('Approval authorization has expired.');
    }
    if (transition.outcome === 'replayed') {
      throw new ConflictError('Approval authorization nonce has already been consumed.');
    }
    if (transition.outcome === 'already_final') {
      throw new ConflictError(`Approval is already ${transition.approval?.status ?? 'finalized'}`);
    }
    const updatedApproval = transition.approval!;

    const updatedToolCall: ToolCallRecord = {
      ...toolCall,
      status: 'rejected',
      updatedAt: now,
    };

    await this.deps.store.updateToolCall(updatedToolCall);
    await this.audit('approval.rejected', {
      toolCallId: toolCall.id,
      approvalId: approval.id,
      actor,
      auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: { reason: input.reason ?? null },
    });
    this.telemetry('approval.rejected', telemetryForToolCall(updatedToolCall, {
      'approval.id': approval.id,
      'approval.status': updatedApproval.status,
      status: updatedToolCall.status,
    }));

    return { approval: updatedApproval, toolCall: updatedToolCall };
  }

  async cancelApproval(
    approvalId: string,
    input: { approvalNonce?: string; cancelledBy?: string; reason?: string },
    auth?: AuthContext,
  ): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
    const initial = await this.loadApprovalState(approvalId, auth);
    const initialApproval = await this.expireApprovalIfNeeded(initial.approval, initial.toolCall, auth);
    if (initialApproval.status !== 'pending') {
      throw new ConflictError(`Approval is already ${initialApproval.status}`);
    }
    this.assertCanDecideApproval(initialApproval, auth);
    this.assertClientApprovalNonce(initialApproval, input.approvalNonce);

    const authoritative = await this.loadApprovalState(approvalId, auth);
    const approval = await this.expireApprovalIfNeeded(authoritative.approval, authoritative.toolCall, auth);
    const toolCall = authoritative.toolCall;
    if (approval.status !== 'pending') throw new ConflictError(`Approval is already ${approval.status}`);
    this.assertCanDecideApproval(approval, auth);
    this.assertClientApprovalNonce(approval, input.approvalNonce);

    const now = this.now().toISOString();
    const actor = actorForDecision(input.cancelledBy, auth);
    const transition = await this.deps.store.cancelApprovalAtomically({
      approvalId: approval.id,
      authorization: this.safeTerminalAuthorizationGuard(approval, toolCall),
      cancelledBy: actor,
      reason: input.reason,
      updatedAt: now,
    });
    if (transition.outcome === 'not_found') throw new NotFoundError(`Approval not found: ${approvalId}`);
    if (transition.outcome === 'authorization_mismatch') {
      throw new ConflictError('Approval authorization binding changed. Resubmit the action.');
    }
    if (transition.outcome === 'expired') {
      await this.recordExpiredApproval(transition.approval, toolCall, auth);
      throw new ConflictError('Approval authorization has expired.');
    }
    if (transition.outcome === 'replayed') {
      throw new ConflictError('Approval authorization nonce has already been consumed.');
    }
    if (transition.outcome === 'already_final') {
      throw new ConflictError(`Approval is already ${transition.approval?.status ?? 'finalized'}`);
    }
    const updatedApproval = transition.approval!;
    const updatedToolCall = await this.terminalizeToolCall(toolCall, now);

    await this.audit('approval.cancelled', {
      toolCallId: toolCall.id,
      approvalId: approval.id,
      actor,
      auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: {
        approvalAuthorizationHash: approval.authorization?.authorizationHash ?? null,
        reason: input.reason ?? null,
      },
    });
    this.telemetry('approval.cancelled', telemetryForToolCall(updatedToolCall, {
      'approval.id': approval.id,
      'approval.status': updatedApproval.status,
      status: updatedToolCall.status,
    }));
    return { approval: updatedApproval, toolCall: updatedToolCall };
  }

  private async loadApprovalState(
    approvalId: string,
    auth?: AuthContext,
  ): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
    const approval = await this.deps.store.getApproval(approvalId);
    if (!approval) throw new NotFoundError(`Approval not found: ${approvalId}`);
    assertWorkspace(approval.workspaceId, auth);
    const toolCall = await this.deps.store.getToolCall(approval.toolCallId);
    if (!toolCall) throw new NotFoundError(`Tool call not found: ${approval.toolCallId}`);
    assertWorkspace(toolCall.workspaceId, auth);
    return { approval, toolCall };
  }

  private approvalAuthorizationGuard(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
  ): ApprovalAuthorizationGuard {
    const authorization = approval.authorization;
    if (!authorization || !isValidApprovalAuthorization(authorization)) {
      throw new ConflictError(
        'Approval lacks actionproxy.approval-authorization.v1 state. Resubmit the action.',
      );
    }
    const mismatch = approvalAuthorizationMismatch(authorization, approval, toolCall);
    if (mismatch) {
      throw new ConflictError(`Approval authorization binding is invalid (${mismatch}). Resubmit the action.`);
    }
    const activePolicyVersionHash = this.currentPolicyVersionHash();
    if (authorization.binding.policy.legacyVersionHash !== activePolicyVersionHash) {
      throw new ConflictError('The active policy changed after approval creation. Resubmit the action.');
    }
    return {
      activePolicyVersionHash,
      authorization,
      originalInput: approval.originalInput,
    };
  }

  private safeTerminalAuthorizationGuard(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
  ): ApprovalAuthorizationGuard | undefined {
    const authorization = approval.authorization;
    if (!authorization || !isValidApprovalAuthorization(authorization)) return undefined;
    if (approvalAuthorizationMismatch(authorization, approval, toolCall)) return undefined;
    return {
      activePolicyVersionHash: authorization.binding.policy.legacyVersionHash,
      authorization,
      originalInput: approval.originalInput,
    };
  }

  private assertClientApprovalNonce(approval: ApprovalRecord, suppliedNonce?: string): void {
    if (suppliedNonce === undefined) return;
    if (!approval.authorization || suppliedNonce !== approval.authorization.nonce) {
      throw new ConflictError('Approval authorization nonce is stale or does not match this approval.');
    }
  }

  private async expireApprovalIfNeeded(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
    auth?: AuthContext,
  ): Promise<ApprovalRecord> {
    if (
      approval.status !== 'pending' ||
      !approval.authorization ||
      !isValidApprovalAuthorization(approval.authorization) ||
      !approvalAuthorizationExpired(approval.authorization, this.now())
    ) {
      return approval;
    }

    const transition = await this.deps.store.expireApprovalAtomically({
      approvalId: approval.id,
      authorization: approval.authorization,
      expiredAt: this.now().toISOString(),
    });
    if (transition.outcome === 'expired' && transition.approval) {
      await this.recordExpiredApproval(transition.approval, toolCall, auth);
      return transition.approval;
    }
    return transition.approval ?? approval;
  }

  private async recordExpiredApproval(
    approval: ApprovalRecord | undefined,
    toolCall: ToolCallRecord,
    auth?: AuthContext,
  ): Promise<void> {
    if (!approval) return;
    const updatedToolCall = await this.terminalizeToolCall(toolCall, approval.expiredAt ?? approval.updatedAt);
    await this.audit('approval.expired', {
      toolCallId: toolCall.id,
      approvalId: approval.id,
      actor: 'actionproxy:approval-expiry',
      auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: {
        approvalAuthorizationHash: approval.authorization?.authorizationHash ?? null,
        expiredAt: approval.expiredAt ?? approval.updatedAt,
      },
    });
    this.telemetry('approval.expired', telemetryForToolCall(updatedToolCall, {
      'approval.id': approval.id,
      'approval.status': approval.status,
      status: updatedToolCall.status,
    }));
  }

  private async terminalizeToolCall(toolCall: ToolCallRecord, updatedAt: string): Promise<ToolCallRecord> {
    if (toolCall.status !== 'pending_approval') return toolCall;
    const updated: ToolCallRecord = { ...toolCall, status: 'rejected', updatedAt };
    await this.deps.store.updateToolCall(updated);
    return updated;
  }

  private now(): Date {
    return new Date();
  }

  private assertCanDecideApproval(approval: ApprovalRecord, auth?: AuthContext): void {
    if (!auth || auth.authProvider === 'none') return;

    assertWorkspace(approval.workspaceId, auth);

    if (approval.approverUsers !== undefined && !approval.approverUsers.includes(auth.principalId)) {
      throw new ForbiddenError('Principal is not an allowed approver for this approval.');
    }

    if (approval.approverUsers === undefined && !hasAnyGroup(auth, approval.approverGroups ?? [])) {
      throw new ForbiddenError('Principal is not in an allowed approver group for this approval.');
    }

    if (approval.separationOfDuties && principalMatchesActor(auth, approval.requestedBy)) {
      throw new ForbiddenError('The submitter cannot approve or reject this request.');
    }

    if (approval.separationOfDuties && approval.requestedByAuth?.principalId === auth.principalId) {
      throw new ForbiddenError('The submitter cannot approve or reject this request.');
    }
  }

  private async executeToolCall(
    toolCall: ToolCallRecord,
    input: JsonObject,
    actor: string,
    auth?: AuthContext,
    receipt?: ActionReceiptRecord,
    approval?: ApprovalRecord,
  ): Promise<ToolCallRecord> {
    const revalidationFailure = await this.finalPolicyRevalidationFailure(toolCall, input);
    if (revalidationFailure) {
      return this.failToolCall(toolCall, input, actor, revalidationFailure, auth, receipt);
    }

    const actionEnvelope = actionEnvelopeForInput(this.actionEnvelopeForToolCall(toolCall), input);
    const baseToolCall: ToolCallRecord = {
      ...toolCall,
      actionEnvelope,
      actionEnvelopeHash: actionEnvelope.envelopeHash,
      input,
      inputHash: actionEnvelope.inputHash,
    };
    const attempt = await this.reserveExecutionAttempt(baseToolCall, 'local_mock', actor, auth, receipt, approval);

    if ((this.deps.localExecutionMode ?? 'mock') === 'disabled') {
      const message =
        'Local tool execution is disabled. Use metadata.actionproxyExecution = "external" for proxy execution, or set ACTIONPROXY_LOCAL_EXECUTION=mock for local demo tools.';
      await this.completeExecutionAttempt(attempt, 'failed_before_dispatch', actor, auth, {
        errorClass: 'execution_preflight',
        errorCode: 'local_execution_disabled',
        errorMessage: message,
      });
      return this.failToolCall(
        baseToolCall,
        input,
        actor,
        message,
        auth,
        receipt,
      );
    }

    if (!this.deps.tools.has(toolCall.toolName)) {
      const message = `No tool registered for ${toolCall.toolName}`;
      await this.completeExecutionAttempt(attempt, 'failed_before_dispatch', actor, auth, {
        errorClass: 'execution_preflight',
        errorCode: 'tool_not_registered',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }

    const authorizationRevalidationFailure = await this.finalPolicyRevalidationFailure(baseToolCall, input);
    if (authorizationRevalidationFailure) {
      await this.completeExecutionAttempt(attempt, 'failed_before_dispatch', actor, auth, {
        errorClass: 'execution_authorization',
        errorCode: 'execution_authorization_policy_revalidation_failed',
        errorMessage: authorizationRevalidationFailure,
      });
      return this.failToolCall(baseToolCall, input, actor, authorizationRevalidationFailure, auth, receipt);
    }

    let executionAuthorization: ExecutionAuthorization;
    let executionAuthorizationProjection: ExecutionAuthorizationProjectionV1;
    try {
      const authorizationBinding = buildExecutionAuthorizationBinding({
        approval,
        attempt,
        toolCall: baseToolCall,
      });
      executionAuthorization = this.deps.executionAuthorizations.issue({
        binding: authorizationBinding,
        capabilities: this.deps.tools.describe().capabilities,
      });
      executionAuthorizationProjection = this.deps.executionAuthorizations.inspect(executionAuthorization);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.completeExecutionAttempt(attempt, 'failed_before_dispatch', actor, auth, {
        errorClass: error instanceof Error ? error.name : 'execution_authorization_error',
        errorCode:
          error instanceof ExecutionAuthorizationError
            ? error.code
            : 'execution_authorization_issue_failed',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }

    let authorizationBinding: ExecutionAuthorizationBindingV1;
    try {
      authorizationBinding = await this.currentLocalExecutionAuthorizationBinding(
        attempt,
        baseToolCall,
        approval,
        'reserved',
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.completeExecutionAttempt(attempt, 'failed_before_dispatch', actor, auth, {
        errorClass: error instanceof Error ? error.name : 'execution_authorization_error',
        errorCode: 'execution_authorization_binding_mismatch',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }

    let dispatched: ExecutionAttemptRecordV1;
    try {
      dispatched = await this.transitionExecutionAttempt(
        attempt,
        'reserved',
        'dispatched',
        undefined,
        contentExposureRevisionGuard(baseToolCall),
      );
    } catch (error) {
      if (!(error instanceof ConflictError) || !error.message.includes('content_influence_mismatch')) {
        throw error;
      }
      const message = error instanceof Error ? error.message : String(error);
      await this.auditInfluenceDispatchMismatchBestEffort(baseToolCall, auth);
      await this.completeExecutionAttempt(attempt, 'failed_before_dispatch', actor, auth, {
        errorClass: error instanceof Error ? error.name : 'execution_authorization_error',
        errorCode: 'content_influence_binding_stale',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }
    try {
      authorizationBinding = await this.currentLocalExecutionAuthorizationBinding(
        dispatched,
        baseToolCall,
        approval,
        'dispatched',
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.completeExecutionAttempt(dispatched, 'unknown_outcome', actor, auth, {
        errorClass: error instanceof Error ? error.name : 'execution_authorization_error',
        errorCode: 'execution_authorization_binding_mismatch',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }
    let execution: Promise<unknown>;
    try {
      execution = this.deps.tools.execute({
        authorization: executionAuthorization,
        authorizationBinding,
        input,
        toolName: toolCall.toolName,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.completeExecutionAttempt(dispatched, 'unknown_outcome', actor, auth, {
        errorClass: error instanceof Error ? error.name : 'unknown_execution_error',
        errorCode:
          error instanceof ExecutionAuthorizationError
            ? error.code
            : 'executor_threw_after_dispatch',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }
    // Attach a handler immediately while durable dispatched evidence is written. The original
    // promise is still awaited below; this only prevents a fast rejection from becoming an
    // unhandled rejection during the evidence write.
    void execution.catch(() => undefined);
    await this.auditExecutionAttempt(
      'execution.attempt_dispatched',
      dispatched,
      actor,
      auth,
      executionAuthorizationProjection,
    );

    let result: unknown;
    try {
      result = await execution;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.completeExecutionAttempt(dispatched, 'unknown_outcome', actor, auth, {
        errorClass: error instanceof Error ? error.name : 'unknown_execution_error',
        errorCode: 'executor_threw_after_dispatch',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }

    const normalizedResult = isJsonObject(result) ? result : { value: result };
    await this.completeExecutionAttempt(dispatched, 'succeeded', actor, auth, { result: normalizedResult });

    const remediation = remediationFromToolResult(result);
    const exposureRequired = requiresContentExposureBeforeRelease(baseToolCall);
    let updated: ToolCallRecord = {
      ...baseToolCall,
      status: 'executed',
      result,
      ...(exposureRequired ? { resultWithheld: true } : {}),
      updatedAt: new Date().toISOString(),
    };
    await this.deps.store.updateToolCall(updated);
    if (receipt) {
      await this.recordReceiptOutcome(receipt, {
        actor,
        auth,
        remediation,
        result: normalizedResult,
        status: 'succeeded',
        toolCall: updated,
      });
    }
    if (exposureRequired) {
      const exposureRecorded = await this.recordContentExposureBeforeRelease(updated, actor, auth);
      if (exposureRecorded) {
        const releasable = { ...updated, resultWithheld: false, updatedAt: new Date().toISOString() };
        try {
          await this.deps.store.updateToolCall(releasable);
          updated = releasable;
        } catch {
          await this.auditResultWithheldBestEffort(updated, auth, 'result_release_state_persistence_failed');
        }
      }
    }
    await this.audit('tool_call.executed', {
      toolCallId: toolCall.id,
      actor,
      auth,
      inputHash: updated.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: {
        toolName: toolCall.toolName,
        input,
        result: result as JsonObject,
        resultWithheld: updated.resultWithheld ?? false,
      },
    });
    this.telemetry('tool_call.executed', telemetryForToolCall(updated, { status: updated.status }));
    return updated;
  }

  private async auditResultWithheldBestEffort(
    toolCall: ToolCallRecord,
    auth: AuthContext | undefined,
    reason: string,
  ): Promise<void> {
    try {
      await this.audit('content.result_withheld', {
        toolCallId: toolCall.id,
        actor: 'actionproxy:content-influence',
        auth,
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        workspaceId: toolCall.workspaceId,
        data: {
          influenceScopeId: toolCall.influenceScopeId ?? null,
          reason,
          sourceToolCallId: toolCall.id,
        },
      });
    } catch {
      // A known result remains withheld even when secondary audit export fails.
    }
  }

  private async reserveExecutionAttempt(
    toolCall: ToolCallRecord,
    executionMode: ExecutionAttemptRecordV1['executionMode'],
    actor: string,
    auth?: AuthContext,
    receipt?: ActionReceiptRecord,
    approval?: ApprovalRecord,
  ): Promise<ExecutionAttemptRecordV1> {
    const attempt = buildExecutionAttempt({
      approval,
      executionMode,
      inputHash: toolCall.inputHash ?? hashJson(toolCall.input),
      now: new Date().toISOString(),
      receipt,
      toolCall,
    });
    const reservation = await this.deps.store.reserveExecutionAttemptAtomically(attempt, approval?.authorization);
    if (reservation.outcome !== 'reserved' || !reservation.attempt) {
      throw new ConflictError(`Execution attempt could not be reserved: ${reservation.outcome}`);
    }
    await this.auditExecutionAttempt('execution.attempt_reserved', reservation.attempt, actor, auth);
    return reservation.attempt;
  }

  private async currentLocalExecutionAuthorizationBinding(
    authorizedAttempt: ExecutionAttemptRecordV1,
    authorizedToolCall: ToolCallRecord,
    approval?: ApprovalRecord,
    expectedState: 'dispatched' | 'reserved' = 'dispatched',
  ): Promise<ExecutionAuthorizationBindingV1> {
    const [storedAttempt, storedToolCall, storedApproval] = await Promise.all([
      this.deps.store.getExecutionAttempt(authorizedAttempt.id),
      this.deps.store.getToolCall(authorizedToolCall.id),
      approval ? this.deps.store.getApproval(approval.id) : Promise.resolve(undefined),
    ]);
    if (!storedAttempt || storedAttempt.state !== expectedState) {
      throw new ExecutionAuthorizationError(
        'execution_authorization_binding_mismatch',
        `Execution authorization requires the current ${expectedState} attempt.`,
      );
    }
    if (!storedToolCall) {
      throw new ExecutionAuthorizationError(
        'execution_authorization_binding_mismatch',
        'Execution authorization requires the current tool call.',
      );
    }
    if (approval && !storedApproval) {
      throw new ExecutionAuthorizationError(
        'execution_authorization_binding_mismatch',
        'Execution authorization requires the current approval.',
      );
    }
    if (
      !approval &&
      (storedToolCall.inputHash !== authorizedToolCall.inputHash ||
        storedToolCall.actionEnvelopeHash !== authorizedToolCall.actionEnvelopeHash)
    ) {
      throw new ExecutionAuthorizationError(
        'execution_authorization_binding_mismatch',
        'The stored action changed after execution authorization.',
      );
    }

    const currentToolCall: ToolCallRecord = {
      ...storedToolCall,
      actionEnvelope: authorizedToolCall.actionEnvelope,
      actionEnvelopeHash: authorizedToolCall.actionEnvelopeHash,
      input: authorizedToolCall.input,
      inputHash: authorizedToolCall.inputHash,
    };
    const revalidationFailure = await this.finalPolicyRevalidationFailure(currentToolCall, currentToolCall.input);
    if (revalidationFailure) {
      throw new ExecutionAuthorizationError(
        'execution_authorization_binding_mismatch',
        revalidationFailure,
      );
    }
    return buildExecutionAuthorizationBinding({
      approval: storedApproval,
      attempt: storedAttempt,
      toolCall: currentToolCall,
    });
  }

  private async transitionExecutionAttempt(
    attempt: ExecutionAttemptRecordV1,
    expectedState: 'dispatched' | 'reserved',
    nextState: ExecutionAttemptRecordV1['state'],
    outcome?: ExecutionAttemptOutcomeV1,
    contentExposureRevision?: ContentExposureRevisionGuard,
  ): Promise<ExecutionAttemptRecordV1> {
    const transition = await this.deps.store.transitionExecutionAttemptAtomically({
      attemptId: attempt.id,
      expectedState,
      nextState,
      outcome,
      reservationOwner: attempt.reservationOwner,
      transitionedAt: outcome?.recordedAt ?? new Date().toISOString(),
      workspaceId: attempt.workspaceId,
      contentExposureRevision,
    });
    if (transition.outcome !== 'transitioned' || !transition.attempt) {
      throw new ConflictError(`Execution attempt transition was rejected: ${transition.outcome}`);
    }
    return transition.attempt;
  }

  private async auditInfluenceDispatchMismatchBestEffort(
    toolCall: ToolCallRecord,
    auth?: AuthContext,
  ): Promise<void> {
    try {
      await this.audit('content.influence_binding_stale', {
        actor: 'actionproxy:content-influence',
        auth,
        data: {
          expectedExposureRevision: toolCall.contentInfluence?.exposureRevision ?? null,
          influenceScopeId: toolCall.contentInfluence?.influenceScope.id ?? null,
          reason: 'atomic_dispatch_revision_mismatch',
          storedBindingHash: toolCall.contentInfluence?.bindingHash ?? null,
        },
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        toolCallId: toolCall.id,
        workspaceId: toolCall.workspaceId,
      });
    } catch {
      // The atomic mismatch remains fail-closed even if secondary audit export fails.
    }
  }

  private async completeExecutionAttempt(
    attempt: ExecutionAttemptRecordV1,
    status: ExecutionAttemptTerminalState,
    actor: string,
    auth: AuthContext | undefined,
    input: {
      errorClass?: string;
      errorCode?: string;
      errorMessage?: string;
      result?: JsonObject;
    } = {},
  ): Promise<ExecutionAttemptRecordV1> {
    const outcome = executionAttemptOutcome(status, {
      ...input,
      recordedAt: new Date().toISOString(),
    });
    const completed = await this.transitionExecutionAttempt(
      attempt,
      attempt.state === 'reserved' ? 'reserved' : 'dispatched',
      status,
      outcome,
    );
    await this.auditExecutionAttempt('execution.attempt_completed', completed, actor, auth);
    return completed;
  }

  private async auditExecutionAttempt(
    type: 'execution.attempt_completed' | 'execution.attempt_dispatched' | 'execution.attempt_reserved',
    attempt: ExecutionAttemptRecordV1,
    actor: string,
    auth?: AuthContext,
    executionAuthorization?: ExecutionAuthorizationProjectionV1,
  ): Promise<void> {
    await this.audit(type, {
      actor,
      approvalId: attempt.binding.approvalId ?? undefined,
      auth,
      data: {
        attemptId: attempt.id,
        attemptNumber: attempt.attemptNumber,
        binding: attempt.binding,
        completedAt: attempt.completedAt ?? null,
        dispatchedAt: attempt.dispatchedAt ?? null,
        executionMode: attempt.executionMode,
        ...(executionAuthorization
          ? {
              executionAuthorization: {
                authorizationId: executionAuthorization.authorizationId,
                capabilities: executionAuthorization.capabilities,
                executorId: executionAuthorization.binding.executor.id,
                expiresAt: executionAuthorization.expiresAt,
                version: executionAuthorization.version,
              },
            }
          : {}),
        executorId: attempt.executorId,
        grantId: attempt.grantId ?? null,
        outcome: attempt.outcome ?? null,
        providerIdempotency: attempt.providerIdempotency,
        reservedAt: attempt.reservedAt,
        retryPolicy: attempt.retryPolicy,
        state: attempt.state,
      },
      inputHash: attempt.inputHash,
      policyVersionHash: attempt.binding.policyVersionHash ?? undefined,
      toolCallId: attempt.toolCallId,
      workspaceId: attempt.workspaceId,
    });
  }

  private async failToolCall(
    toolCall: ToolCallRecord,
    input: JsonObject,
    actor: string,
    message: string,
    auth?: AuthContext,
    receipt?: ActionReceiptRecord,
  ): Promise<ToolCallRecord> {
    const actionEnvelope = actionEnvelopeForInput(this.actionEnvelopeForToolCall(toolCall), input);
    const updated: ToolCallRecord = {
      ...toolCall,
      input,
      inputHash: actionEnvelope.inputHash,
      actionEnvelope,
      actionEnvelopeHash: actionEnvelope.envelopeHash,
      status: 'failed',
      error: message,
      updatedAt: new Date().toISOString(),
    };
    await this.deps.store.updateToolCall(updated);
    if (receipt) {
      await this.recordReceiptOutcome(receipt, {
        actor,
        auth,
        error: message,
        status: 'failed',
        toolCall: updated,
      });
    }
    await this.audit('tool_call.failed', {
      toolCallId: toolCall.id,
      actor,
      auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: { toolName: toolCall.toolName, input, error: message },
    });
    this.telemetry('tool_call.failed', telemetryForToolCall(updated, {
      'error.present': true,
      status: updated.status,
    }));
    return updated;
  }

  private async authorizeExternalExecution(
    toolCall: ToolCallRecord,
    input: JsonObject,
    actor: string,
    auth?: AuthContext,
    ttlSeconds?: number,
    receipt?: ActionReceiptRecord,
    approval?: ApprovalRecord,
  ): Promise<ToolCallRecord> {
    const revalidationFailure = await this.finalPolicyRevalidationFailure(toolCall, input);
    if (revalidationFailure) {
      return this.failToolCall(toolCall, input, actor, revalidationFailure, auth, receipt);
    }

    const actionEnvelope = actionEnvelopeForInput(this.actionEnvelopeForToolCall(toolCall), input);
    const baseToolCall: ToolCallRecord = {
      ...toolCall,
      input,
      inputHash: actionEnvelope.inputHash,
      actionEnvelope,
      actionEnvelopeHash: actionEnvelope.envelopeHash,
    };
    let attempt = await this.reserveExecutionAttempt(baseToolCall, 'external_grant', actor, auth, receipt, approval);
    let grant: unknown;
    try {
      grant = await this.deps.executionGrants?.createGrant({ actor, auth, receipt, toolCall: baseToolCall, ttlSeconds });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.completeExecutionAttempt(attempt, 'failed_before_dispatch', actor, auth, {
        errorClass: error instanceof Error ? error.name : 'execution_grant_error',
        errorCode: 'execution_grant_creation_failed',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }
    const grantId = isJsonObject(grant) && typeof grant.id === 'string' ? grant.id : undefined;
    if (!grantId) {
      const message = 'External execution authorization failed because no execution grant was issued.';
      await this.completeExecutionAttempt(attempt, 'failed_before_dispatch', actor, auth, {
        errorClass: 'execution_preflight',
        errorCode: 'execution_grant_missing',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }
    const binding = await this.deps.store.bindExecutionAttemptGrantAtomically({
      attemptId: attempt.id,
      grantId,
      reservationOwner: attempt.reservationOwner,
      updatedAt: new Date().toISOString(),
      workspaceId: attempt.workspaceId,
    });
    if (
      (binding.outcome !== 'bound' && binding.outcome !== 'already_bound') ||
      !binding.attempt ||
      binding.attempt.grantId !== grantId
    ) {
      const message = `Execution attempt could not be bound to its grant: ${binding.outcome}`;
      await this.completeExecutionAttempt(attempt, 'failed_before_dispatch', actor, auth, {
        errorClass: 'execution_preflight',
        errorCode: 'execution_grant_binding_failed',
        errorMessage: message,
      });
      return this.failToolCall(baseToolCall, input, actor, message, auth, receipt);
    }
    attempt = binding.attempt;
    const result = redactToolCallResult({
      ok: true,
      externalExecution: true,
      note: 'Execution authorized for an external tool runner.',
      ...(receipt === undefined ? {} : { receipt }),
      ...(grant === undefined ? {} : { grant }),
    } as JsonObject);
    const updated: ToolCallRecord = {
      ...baseToolCall,
      input,
      status: 'authorized',
      result,
      updatedAt: new Date().toISOString(),
    };
    await this.deps.store.updateToolCall(updated);
    await this.audit('tool_call.authorized', {
      toolCallId: toolCall.id,
      actor,
      auth,
      inputHash: updated.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: {
        actionEnvelopeHash: actionEnvelope.envelopeHash,
        executionAttemptId: attempt.id,
        grantId: grantId ?? null,
        input,
        receiptId: receipt?.id ?? null,
        receiptHash: receipt?.receiptHash ?? null,
        result,
        toolName: toolCall.toolName,
      },
    });
    this.telemetry('tool_call.authorized', telemetryForToolCall(updated, {
      'grant.id': grantId,
      'receipt.hash': receipt?.receiptHash,
      'receipt.id': receipt?.id,
      status: updated.status,
    }));
    return updated;
  }

  private async createActionReceipt(input: {
    actor: string;
    approval?: ApprovalRecord;
    auth?: AuthContext;
    decisionKind: 'human_approval' | 'policy_allow';
    input: JsonObject;
    reviewHash?: string;
    toolCall: ToolCallRecord;
  }): Promise<ActionReceiptRecord> {
    const now = new Date().toISOString();
    const originalEnvelope = this.actionEnvelopeForToolCall(input.toolCall);
    const approvedEnvelope = actionEnvelopeForInput(originalEnvelope, input.input);
    const unsigned = {
      approvalId: input.approval?.id,
      approvedEnvelopeHash: approvedEnvelope.envelopeHash,
      approvedInputHash: approvedEnvelope.inputHash,
      createdAt: now,
      decisionActor: input.actor,
      decisionAuth: input.auth,
      decisionKind: input.decisionKind,
      executionMode: approvedEnvelope.executionMode,
      id: `receipt_${randomUUID()}`,
      issuedAt: now,
      keyId: ACTION_RECEIPT_KEY_ID,
      operation: approvedEnvelope.operation,
      originalEnvelopeHash: input.approval?.originalEnvelopeHash ?? originalEnvelope.envelopeHash,
      originalInputHash: input.approval?.originalInputHash ?? originalEnvelope.inputHash,
      policyDecision: input.toolCall.decision,
      policyReason: input.toolCall.policyReason,
      policyRisk: input.toolCall.risk,
      policyVersionHash: input.toolCall.policyVersionHash,
      policyVersionId: input.toolCall.policyVersionId,
      protocol: approvedEnvelope.protocol,
      reviewHash: input.reviewHash,
      signatureAlg: 'HMAC-SHA256' as const,
      source: approvedEnvelope.source,
      toolCallId: input.toolCall.id,
      toolName: input.toolCall.toolName,
      version: 'actionproxy.receipt.v1' as const,
      workspaceId: input.toolCall.workspaceId ?? input.auth?.workspaceId ?? this.deps.workspaceId ?? 'default',
    };
    const receipt = signReceipt(this.deps.receiptSigningSecret ?? 'local-dev-execution-grant-secret', unsigned);
    await this.deps.store.createActionReceipt(receipt);
    await this.audit('receipt.created', {
      toolCallId: input.toolCall.id,
      approvalId: input.approval?.id,
      actor: input.actor,
      auth: input.auth,
      inputHash: approvedEnvelope.inputHash,
      policyVersionHash: input.toolCall.policyVersionHash,
      policyVersionId: input.toolCall.policyVersionId,
      workspaceId: receipt.workspaceId,
      data: {
        approvedEnvelopeHash: receipt.approvedEnvelopeHash,
        approvedInputHash: receipt.approvedInputHash,
        decisionKind: receipt.decisionKind,
        originalEnvelopeHash: receipt.originalEnvelopeHash,
        originalInputHash: receipt.originalInputHash,
        receiptHash: receipt.receiptHash,
        receiptId: receipt.id,
        reviewHash: receipt.reviewHash ?? null,
      },
    });
    this.telemetry('receipt.created', telemetryForToolCall(input.toolCall, {
      'receipt.hash': receipt.receiptHash,
      'receipt.id': receipt.id,
    }));
    return receipt;
  }

  private async recordReceiptOutcome(
    receipt: ActionReceiptRecord,
    input: {
      actor: string;
      auth?: AuthContext;
      error?: string;
      remediation?: RemediationDescriptor;
      result?: JsonObject;
      status: 'failed' | 'succeeded';
      toolCall: ToolCallRecord;
    },
  ): Promise<ActionReceiptRecord> {
    const updated: ActionReceiptRecord = {
      ...receipt,
      outcome: {
        auth: input.auth,
        error: input.error,
        recordedAt: new Date().toISOString(),
        recordedBy: input.actor,
        remediation: input.remediation,
        result: input.result,
        status: input.status,
      },
    };
    await this.deps.store.updateActionReceipt(updated);
    await this.audit('receipt.outcome_recorded', {
      toolCallId: receipt.toolCallId,
      approvalId: receipt.approvalId,
      actor: input.actor,
      auth: input.auth,
      inputHash: input.toolCall.inputHash,
      policyVersionHash: receipt.policyVersionHash,
      policyVersionId: receipt.policyVersionId,
      workspaceId: receipt.workspaceId,
      data: {
        error: input.error ?? null,
        receiptHash: receipt.receiptHash,
        receiptId: receipt.id,
        remediation: input.remediation ?? null,
        result: input.result ?? null,
        status: input.status,
      },
    });
    this.telemetry('receipt.outcome_recorded', telemetryForToolCall(input.toolCall, {
      'error.present': Boolean(input.error),
      'execution.status': input.status,
      'receipt.hash': receipt.receiptHash,
      'receipt.id': receipt.id,
    }));
    return updated;
  }

  private actionEnvelopeForToolCall(toolCall: ToolCallRecord): ActionEnvelope {
    if (toolCall.actionEnvelope) return toolCall.actionEnvelope;
    return normalizeActionEnvelope({
      actor: toolCall.requestedBy,
      auth: toolCall.requestedByAuth,
      request: {
        agentId: toolCall.agentId,
        input: toolCall.input,
        metadata: toolCall.metadata,
        reason: toolCall.reason,
        requestedBy: toolCall.requestedBy,
        toolName: toolCall.toolName,
      },
    });
  }

  private assertApprovalBindingIsCurrent(
    approval: ApprovalRecord,
    actionEnvelope: ActionEnvelope,
    expectedReviewHash: string,
  ): void {
    if (approval.originalInputHash && approval.originalInputHash !== hashJson(approval.originalInput)) {
      throw new ConflictError('Approval original input no longer matches its stored hash. Resubmit the action.');
    }
    if (approval.originalEnvelopeHash && approval.originalEnvelopeHash !== actionEnvelope.envelopeHash) {
      throw new ConflictError('Approval action envelope no longer matches the submitted action. Resubmit the action.');
    }
    if (approval.reviewHash && approval.reviewHash !== expectedReviewHash) {
      throw new ConflictError('Approval review binding is stale. Resubmit the action.');
    }
  }

  private async assertApprovalPolicyIsCurrent(
    toolCall: ToolCallRecord,
    approvedInput: JsonObject,
    approvedEnvelope: ActionEnvelope,
  ): Promise<void> {
    const currentPolicyVersionHash = this.currentPolicyVersionHash();
    if (toolCall.policyVersionHash && toolCall.policyVersionHash !== currentPolicyVersionHash) {
      throw new ConflictError('The active policy changed after submission. Resubmit the action for a new decision.');
    }

    const originalBaseEvaluation = this.evaluatePolicy(toolCall.toolName, policyContextFromToolCall(toolCall));
    if (hashJson(toolCall.resultSource ?? null) !== hashJson(frozenResultSource(originalBaseEvaluation.rule, this.deps.policy) ?? null)) {
      throw new ConflictError('The frozen result-source classification changed before approval. Resubmit the action.');
    }
    const originalInfluence = await this.revalidatedInfluence(toolCall, originalBaseEvaluation);
    const bindingFailure = await this.contentInfluenceBindingFailure(
      toolCall,
      originalInfluence,
      Boolean(originalBaseEvaluation.rule.influence),
    );
    if (bindingFailure) throw new ConflictError(bindingFailure);
    const originalEvaluation = effectivePolicyEvaluation(originalBaseEvaluation, originalInfluence?.evidence);

    const approvedBaseEvaluation = this.evaluatePolicy(
      toolCall.toolName,
      policyContextFromToolCall({
        ...toolCall,
        actionEnvelope: approvedEnvelope,
        actionEnvelopeHash: approvedEnvelope.envelopeHash,
        input: approvedInput,
        inputHash: approvedEnvelope.inputHash,
      }),
    );
    if (hashJson(toolCall.resultSource ?? null) !== hashJson(frozenResultSource(approvedBaseEvaluation.rule, this.deps.policy) ?? null)) {
      throw new ConflictError('The approved input selects a different result-source classification. Resubmit the action.');
    }
    const approvedInfluence = await this.revalidatedInfluence(toolCall, approvedBaseEvaluation);
    const approvedBindingFailure = await this.contentInfluenceBindingFailure(
      toolCall,
      approvedInfluence,
      Boolean(approvedBaseEvaluation.rule.influence),
    );
    if (approvedBindingFailure) throw new ConflictError(approvedBindingFailure);
    const approvedEvaluation = effectivePolicyEvaluation(approvedBaseEvaluation, approvedInfluence?.evidence);
    if (originalEvaluation.decision !== 'require_approval') {
      throw new ConflictError('The submitted action no longer follows an approval-required policy path. Resubmit it.');
    }
    if (approvedEvaluation.decision === 'deny') {
      throw new ConflictError('The approved input is denied by final policy revalidation. Resubmit a permitted action.');
    }
    if (
      approvedEvaluation.decision === 'require_approval' &&
      approvedEvaluation.matchedRule !== originalEvaluation.matchedRule
    ) {
      throw new ConflictError('The approved input requires a different approval policy route. Resubmit the action.');
    }
  }

  private async finalPolicyRevalidationFailure(
    toolCall: ToolCallRecord,
    input: JsonObject,
  ): Promise<string | undefined> {
    const decision = validatedActionProxyDecisionForToolCall(toolCall);
    if (toolCall.decisionTrace?.decisionV1 !== undefined && !decision) {
      return 'Final policy revalidation failed because the stored decision-v1 projection is invalid or inconsistent.';
    }
    const currentPolicyVersionHash = this.currentPolicyVersionHash();
    if (toolCall.policyVersionHash && toolCall.policyVersionHash !== currentPolicyVersionHash) {
      return 'Final policy revalidation failed because the active policy changed after authorization.';
    }

    const actionEnvelope = actionEnvelopeForInput(this.actionEnvelopeForToolCall(toolCall), input);
    const providerEvaluation = this.evaluatePolicyProvider(
      toolCall.toolName,
      policyContextFromToolCall({
        ...toolCall,
        actionEnvelope,
        actionEnvelopeHash: actionEnvelope.envelopeHash,
        input,
        inputHash: actionEnvelope.inputHash,
      }),
    );
    const descriptor = providerEvaluation.descriptor;
    if (providerEvaluation.status !== 'ok') {
      return 'Final policy revalidation failed because the policy provider identity changed or became unavailable.';
    }
    if (
      decision &&
      (descriptor.evaluatorVersion !== decision.evaluatorVersion ||
        descriptor.policyDigest !== decision.policy.digest ||
        descriptor.policySchemaVersion !== decision.policy.schemaVersion ||
        descriptor.policyVersion !== decision.policy.version ||
        descriptor.providerId !== decision.policy.provider.id ||
        descriptor.providerVersion !== decision.policy.provider.version)
    ) {
      return 'Final policy revalidation failed because the policy provider identity changed or became unavailable.';
    }
    const baseEvaluation = providerEvaluation.trace.evaluation;
    const verifiedScopeId = verifiedStoredInfluenceScopeId(toolCall);
    if (authoritativeMcpToolCall(toolCall) && !verifiedScopeId) {
      return 'Final policy revalidation failed because authoritative MCP scope or source evidence changed.';
    }
    const currentResultSource = frozenResultSource(baseEvaluation.rule, this.deps.policy);
    if (hashJson(toolCall.resultSource ?? null) !== hashJson(currentResultSource ?? null)) {
      return 'Final policy revalidation failed because the frozen result-source classification changed.';
    }
    const influence = await this.revalidatedInfluence(toolCall, baseEvaluation);
    const influenceFailure = await this.contentInfluenceBindingFailure(
      toolCall,
      influence,
      Boolean(baseEvaluation.rule.influence),
    );
    if (influenceFailure) return influenceFailure;
    const evaluation = effectivePolicyEvaluation(baseEvaluation, influence?.evidence);
    if (evaluation.decision === 'deny') {
      return `Final policy revalidation denied execution: ${evaluation.reason}`;
    }
    if (toolCall.decision === 'allow' && evaluation.decision !== 'allow') {
      return `Final policy revalidation now requires approval: ${evaluation.reason}`;
    }
    if (toolCall.decision !== 'allow' && toolCall.decision !== 'require_approval') {
      return 'Final policy revalidation failed because the stored decision does not authorize execution.';
    }
    return undefined;
  }

  private approvalReviewFreshness(input: {
    actionEnvelope: ActionEnvelope;
    approval: ApprovalRecord;
    reviewHash: string;
    toolCall: ToolCallRecord;
  }): ApprovalReviewFreshness {
    const renderedAt = this.now();
    const warnings: ApprovalReviewFreshness['warnings'] = [];

    const currentPolicyVersionHash = this.currentPolicyVersionHash();
    if (input.toolCall.policyVersionHash && input.toolCall.policyVersionHash !== currentPolicyVersionHash) {
      warnings.push({
        code: 'policy_changed',
        message: 'The active policy has changed since this action was submitted.',
        severity: 'warning',
      });
    }

    if (input.approval.authorization && approvalAuthorizationExpired(input.approval.authorization, renderedAt)) {
      warnings.push({
        code: 'authorization_expired',
        message: 'The approval authorization has expired and cannot authorize execution.',
        severity: 'stale',
      });
    }

    if (input.approval.originalInputHash && input.approval.originalInputHash !== hashJson(input.approval.originalInput)) {
      warnings.push({
        code: 'original_input_hash_mismatch',
        message: 'The approval original-input hash no longer matches the stored original input.',
        severity: 'stale',
      });
    }

    if (input.approval.originalEnvelopeHash && input.approval.originalEnvelopeHash !== input.actionEnvelope.envelopeHash) {
      warnings.push({
        code: 'envelope_hash_mismatch',
        message: 'The approval envelope hash no longer matches the current action envelope.',
        severity: 'stale',
      });
    }

    if (input.approval.reviewHash && input.approval.reviewHash !== input.reviewHash) {
      warnings.push({
        code: 'review_hash_mismatch',
        message: 'The approval review hash no longer matches the current trusted review.',
        severity: 'stale',
      });
    }

    return {
      expiresAt: new Date(renderedAt.getTime() + approvalReviewTtlMs).toISOString(),
      renderedAt: renderedAt.toISOString(),
      state: warnings.some((warning) => warning.severity === 'stale') ? 'stale' : warnings.length ? 'warning' : 'fresh',
      warnings,
    };
  }

  private async notifyApprovalRequired(
    toolCall: ToolCallRecord,
    approval: ApprovalRecord,
    actor: string,
    auth?: AuthContext,
    rule?: PolicyRule,
    resolvedRecipients?: ApprovalNotificationRecipient[],
  ): Promise<ApprovalDeliveryRecord[]> {
    if (!this.deps.approvalNotifier) return [];

    try {
      const recipients =
        resolvedRecipients ??
        (await this.resolveApprovalRecipients(
          rule ?? this.evaluatePolicy(toolCall.toolName, policyContextFromToolCall(toolCall)).rule,
          approval.workspaceId ?? toolCall.workspaceId ?? auth?.workspaceId ?? this.deps.workspaceId ?? 'default',
        ));
      if (recipients !== undefined && recipients.length === 0) {
        return [
          await this.recordApprovalDelivery(
            toolCall,
            approval,
            {
              channelId: 'approval-recipient-resolution',
              error: 'No enabled approval recipients resolved for this approval.',
              provider: 'email',
              status: 'failed',
            },
            actor,
            auth,
          ),
        ];
      }
      const deliveries = await this.deps.approvalNotifier.notifyApprovalRequired({
        approval,
        channels: rule?.notify?.channels,
        ...(recipients === undefined ? {} : { recipients }),
        toolCall,
      });
      const records: ApprovalDeliveryRecord[] = [];
      for (const delivery of deliveries) {
        records.push(await this.recordApprovalDelivery(toolCall, approval, delivery, actor, auth));
      }
      return records;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return [
        await this.recordApprovalDelivery(
          toolCall,
          approval,
          {
            channelId: 'approval-notification',
            error: message,
            provider: 'slack',
            status: 'failed',
          },
          actor,
          auth,
        ),
      ];
    }
  }

  private async recordApprovalDelivery(
    toolCall: ToolCallRecord,
    approval: ApprovalRecord,
    delivery: ApprovalNotificationResult,
    actor: string,
    auth?: AuthContext,
  ): Promise<ApprovalDeliveryRecord> {
    const now = new Date().toISOString();
    const record: ApprovalDeliveryRecord = {
      approvalId: approval.id,
      channelId: delivery.channelId,
      createdAt: now,
      data: {
        ...(delivery.data ?? {}),
        messageTs: delivery.messageTs ?? null,
      },
      destination: delivery.destination,
      error: delivery.error,
      id: `delivery_${randomUUID()}`,
      messageId: delivery.messageId ?? delivery.messageTs,
      provider: delivery.provider,
      recipientEmail: delivery.recipientEmail,
      recipientSlackUserId: delivery.recipientSlackUserId,
      recipientTelegramChatId: delivery.recipientTelegramChatId,
      recipientTelegramUserId: delivery.recipientTelegramUserId,
      recipientUserId: delivery.recipientUserId,
      status: delivery.status,
      toolCallId: toolCall.id,
      updatedAt: now,
      workspaceId: toolCall.workspaceId,
    };
    await this.deps.store.createApprovalDelivery(record);

    await this.audit(delivery.status === 'sent' ? 'approval_notification.sent' : 'approval_notification.failed', {
      toolCallId: toolCall.id,
      approvalId: approval.id,
      actor,
      auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId: toolCall.workspaceId,
      data: deliveryAuditData(record),
    });

    const legacyType = legacyNotificationAuditType(delivery);
    if (legacyType) {
      await this.audit(legacyType, {
        toolCallId: toolCall.id,
        approvalId: approval.id,
        actor,
        auth,
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        workspaceId: toolCall.workspaceId,
        data: deliveryAuditData(record),
      });
    }

    return record;
  }

  private async resolveApprovalRecipients(
    rule: PolicyRule,
    workspaceId: string,
  ): Promise<ApprovalNotificationRecipient[] | undefined> {
    return this.deps.approverDirectory?.resolveRecipients(rule, workspaceId);
  }

  private async audit(
    type: AuditEvent['type'],
    payload: {
      toolCallId?: string;
      approvalId?: string;
      actor?: string;
      auth?: AuthContext;
      data: JsonObject;
      inputHash?: string;
      policyVersionHash?: string;
      policyVersionId?: string;
      workspaceId?: string;
    },
  ): Promise<void> {
    await this.deps.auditStore.append({
      id: `audit_${randomUUID()}`,
      type,
      workspaceId: payload.workspaceId ?? payload.auth?.workspaceId ?? this.deps.workspaceId,
      toolCallId: payload.toolCallId,
      approvalId: payload.approvalId,
      actor: payload.actor,
      auth: payload.auth,
      inputHash: payload.inputHash,
      policyVersionHash: payload.policyVersionHash,
      policyVersionId: payload.policyVersionId,
      timestamp: new Date().toISOString(),
      data: payload.data,
    });
  }

  private currentPolicyVersionHash(): string {
    return hashJson(this.deps.policy);
  }

  private currentPolicyVersionId(policyVersionHash = this.currentPolicyVersionHash()): string {
    return `policy_${policyVersionHash.slice(0, 16)}`;
  }

  private async decisionTraceForToolCall(
    toolCall: ToolCallRecord,
    providerEvaluation?: PolicyProviderEvaluation,
  ): Promise<JsonObject> {
    const trace = await tracePolicyForToolCall({
      approverDirectory: this.deps.approverDirectory,
      policy: this.deps.policy,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      providerEvaluation,
      toolCall,
    });
    return trace as unknown as JsonObject;
  }

  private telemetry(name: string, attributes: TelemetryAttributes): void {
    void this.deps.telemetry?.recordLifecycle(name, attributes).catch(() => undefined);
  }
}

function verifiedInfluenceScopeId(request: CanonicalActionRequest | undefined): string | undefined {
  if (
    !request ||
    request.source.value?.type !== 'mcp' ||
    !request.session.present ||
    request.session.provenance.source !== 'actionproxy.verified-mcp-influence-scope' ||
    !['derived', 'externally_verified', 'trusted'].includes(request.session.provenance.trust)
  ) {
    return undefined;
  }
  const value = request.session.value?.sessionId;
  return typeof value === 'string' && /^influence_[a-f0-9]{64}$/u.test(value) ? value : undefined;
}

function verifiedStoredInfluenceScopeId(toolCall: ToolCallRecord): string | undefined {
  const influenceScopeId = toolCall.influenceScopeId;
  const canonical = toolCall.decisionTrace?.canonicalRequestEvidence;
  if (
    typeof influenceScopeId !== 'string' ||
    !/^influence_[a-f0-9]{64}$/u.test(influenceScopeId) ||
    !isJsonObject(canonical) ||
    !isJsonObject(canonical.source) ||
    !isJsonObject(canonical.source.value) ||
    canonical.source.value.type !== 'mcp' ||
    typeof canonical.source.value.adapterId !== 'string' ||
    !isJsonObject(canonical.sourceProtocol) ||
    canonical.sourceProtocol.value !== 'mcp' ||
    !isJsonObject(canonical.tenant) ||
    !isJsonObject(canonical.tenant.value) ||
    canonical.tenant.value.id !== (toolCall.workspaceId ?? 'default') ||
    !isJsonObject(canonical.session) ||
    canonical.session.present !== true ||
    !isJsonObject(canonical.session.provenance) ||
    canonical.session.provenance.source !== 'actionproxy.verified-mcp-influence-scope' ||
    !['derived', 'externally_verified', 'trusted'].includes(String(canonical.session.provenance.trust)) ||
    !isJsonObject(canonical.session.value) ||
    canonical.session.value.sessionId !== influenceScopeId ||
    toolCall.actionEnvelope?.protocol !== 'mcp' ||
    toolCall.actionEnvelope.source.type !== 'mcp' ||
    toolCall.actionEnvelope.source.id !== canonical.source.value.adapterId
  ) {
    return undefined;
  }
  return influenceScopeId;
}

function contentExposureRevisionGuard(toolCall: ToolCallRecord): ContentExposureRevisionGuard | undefined {
  return validatedContentExposureRevisionGuard(
    toolCall.contentInfluence,
    verifiedStoredInfluenceScopeId(toolCall),
  );
}

function requiresContentExposureBeforeRelease(toolCall: ToolCallRecord): boolean {
  if (!toolCall.resultSource || toolCall.resultSource === 'none') return false;
  return Boolean(verifiedStoredInfluenceScopeId(toolCall) || authoritativeMcpToolCall(toolCall));
}

function authoritativeMcpToolCall(toolCall: ToolCallRecord): boolean {
  const evidence = toolCall.decisionTrace?.canonicalRequestEvidence;
  if (!isJsonObject(evidence) || !isJsonObject(evidence.source)) return false;
  const source = evidence.source;
  return isJsonObject(source.value) && source.value.type === 'mcp';
}

function frozenResultSource(
  rule: PolicyRule,
  policy: PolicyFile,
): PolicyRule['resultSource'] {
  if (rule.resultSource === 'none') return 'none';
  if (rule.resultSource) return { ...rule.resultSource };
  const influenceEnabled = Boolean(policy.default.influence) || Object.values(policy.tools).some((candidate) => candidate.influence);
  return influenceEnabled ? resultSourceForPolicyRule(rule) : undefined;
}

function effectivePolicyEvaluation(
  base: PolicyEvaluation,
  influence: ContentInfluenceEvidenceV1 | undefined,
): PolicyEvaluation {
  if (!influence) return base;
  const approval = influence.effectiveDecision === 'allow'
    ? 'never'
    : influence.effectiveDecision === 'require_approval'
      ? 'required'
      : 'deny';
  const restriction = influence.effectiveDecision !== influence.baseDecision;
  return {
    ...base,
    approval,
    decision: influence.effectiveDecision,
    reason: restriction
      ? `${base.reason} Content observed in this verified influence scope requires a stricter decision.`
      : base.reason,
    rule: { ...base.rule, approval },
  };
}

function providerEvaluationWithEffectiveDecision(
  provider: PolicyProviderEvaluation,
  evaluation: PolicyEvaluation,
): PolicyProviderEvaluation {
  if (provider.trace.evaluation.decision === evaluation.decision) return provider;
  return {
    ...provider,
    trace: {
      ...provider.trace,
      decision: evaluation.decision,
      evaluation,
    },
  };
}

function minimizedInfluenceAudit(evidence: ContentInfluenceEvidenceV1): JsonObject {
  return {
    baseDecision: evidence.baseDecision,
    bindingHash: evidence.bindingHash,
    effectiveDecision: evidence.effectiveDecision,
    exposureSnapshotHash: evidence.exposureSnapshotHash,
    influenceScopeId: evidence.influenceScope.id ?? null,
    observedSources: [...evidence.observedSources],
    sourceReferences: evidence.sourceReferences.map((reference) => ({
      integrity: reference.integrity,
      ...(reference.sourceId ? { sourceId: reference.sourceId } : {}),
      sourceToolCallId: reference.sourceToolCallId,
    })),
  };
}

function isPolicyDecisionTrace(value: unknown): value is PolicyDecisionTrace {
  return (
    isJsonObject(value) &&
    typeof value.toolName === 'string' &&
    typeof value.decision === 'string' &&
    typeof value.matchedRule === 'string' &&
    typeof value.policyReason === 'string' &&
    typeof value.policyRisk === 'string' &&
    Array.isArray(value.ruleEvaluations) &&
    isJsonObject(value.approverResolution)
  );
}

function telemetryForToolCall(toolCall: ToolCallRecord, attributes: TelemetryAttributes = {}): TelemetryAttributes {
  return {
    'input.hash': toolCall.inputHash,
    'policy.version.hash': toolCall.policyVersionHash,
    'policy.version.id': toolCall.policyVersionId,
    status: toolCall.status,
    'tool.name': toolCall.toolName,
    'tool_call.id': toolCall.id,
    'workspace.id': toolCall.workspaceId,
    ...attributes,
  };
}

function deliveryAuditData(record: ApprovalDeliveryRecord): JsonObject {
  return {
    channelId: record.channelId,
    data: record.data,
    destination: record.destination ?? null,
    deliveryId: record.id,
    error: record.error ?? null,
    messageId: record.messageId ?? null,
    provider: record.provider,
    recipientEmail: record.recipientEmail ?? null,
    recipientSlackUserId: record.recipientSlackUserId ?? null,
    recipientTelegramChatId: record.recipientTelegramChatId ?? null,
    recipientTelegramUserId: record.recipientTelegramUserId ?? null,
    recipientUserId: record.recipientUserId ?? null,
    status: record.status,
  };
}

function approvalApproverUsersFor(
  rule: PolicyRule,
  resolvedRecipients: ApprovalNotificationRecipient[] | undefined,
): string[] | undefined {
  if (resolvedRecipients === undefined) return rule.approvers?.users;

  const resolvedUserIds = resolvedRecipients.map((recipient) => recipient.principalId);
  const explicitUsers = rule.approvers?.users ?? [];
  const explicitGroups = rule.approvers?.groups ?? [];
  const usesDefaultApprovers = explicitUsers.length === 0 && explicitGroups.length === 0;

  if (resolvedUserIds.length > 0 || explicitUsers.length > 0 || usesDefaultApprovers) {
    return resolvedUserIds;
  }

  return undefined;
}

function legacyNotificationAuditType(delivery: ApprovalNotificationResult): AuditEvent['type'] | undefined {
  if (delivery.provider === 'slack') {
    return delivery.status === 'sent' ? 'slack.approval_notification.sent' : 'slack.approval_notification.failed';
  }

  if (delivery.provider === 'email') {
    return delivery.status === 'sent' ? 'email.approval_notification.sent' : 'email.approval_notification.failed';
  }

  if (delivery.provider === 'telegram') {
    return delivery.status === 'sent'
      ? 'telegram.approval_notification.sent'
      : 'telegram.approval_notification.failed';
  }

  return undefined;
}

function approvalInputDecision(input: {
  editedInput?: JsonObject | null;
  inputDecision?: { mode: 'edited'; input: JsonObject } | { mode: 'original' };
}): { mode: 'edited'; input: JsonObject } | { mode: 'original' } {
  if (input.inputDecision) return input.inputDecision;
  if (input.editedInput !== undefined && input.editedInput !== null) {
    return { input: input.editedInput, mode: 'edited' };
  }
  return { mode: 'original' };
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function actorForSubmit(request: SubmitToolCallRequest, auth: AuthContext | undefined): string {
  if (!auth || auth.authProvider === 'none') return request.requestedBy;
  return auth.email ?? auth.principalId;
}

function runtimeObservationSource(request: SubmitToolCallRequest): 'local_demo' | 'runtime' {
  return request.metadata?.source === 'dashboard-demo' || request.agentId === 'demo-agent' ? 'local_demo' : 'runtime';
}

function actorForDecision(bodyActor: string | undefined, auth: AuthContext | undefined): string {
  if (!auth || auth.authProvider === 'none') return bodyActor ?? 'local-admin';
  return auth.email ?? auth.principalId;
}

function assertWorkspace(workspaceId: string | undefined, auth: AuthContext | undefined): void {
  if (!auth || auth.authProvider === 'none') return;
  if ((workspaceId ?? 'default') !== auth.workspaceId) {
    throw new ForbiddenError('Requested object is not in this workspace.');
  }
}
