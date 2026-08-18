import { randomUUID } from 'node:crypto';
import type {
  ActionEnvelope,
  ActionReceiptRecord,
  ApprovalDecisionSource,
  ApprovalDecisionRecord,
  ApprovalDeliveryRecord,
  ApprovalRecord,
  AuditEvent,
  AuthContext,
  ExecutionGrantRecord,
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
import {
  ApprovalPresentationSynchronizedConflictError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
} from '../errors';
import type { ListToolCallsFilters } from '../storage/store';
import { hashJson } from '../security/crypto';
import { actionEnvelopeForInput, normalizeActionEnvelope, reviewHashFor } from '../security/action-envelope';
import { ACTION_RECEIPT_KEY_ID, signReceipt } from '../security/action-receipts';
import { redactToolCallResult } from '../security/redaction';
import { hasAnyGroup, principalMatchesActor } from '../security/scopes';
import type {
  ApprovalNotifier,
  ApprovalNotificationResult,
  ApprovalPresentationResult,
  ApprovalResolutionContext,
} from '../integrations/approval-notifications';
import type { ApprovalNotificationRecipient, ApproverDirectoryService } from './approver-directory';
import type { PolicyDetectorService } from './policy-detector';
import type { TelemetryAttributes, TelemetryRecorder } from '../telemetry/telemetry';
import {
  isRemediationForToolCall,
  metadataWithRemediationLink,
  remediationFromToolResult,
  unavailableRemediation,
} from './remediation';
import {
  actionEnvelopeWithPreparedAction,
  ActionContractUnavailableError,
  PreparedActionEditConflict,
  type PreparedActionEditDisposition,
  type PreparedActionLifecycle,
  type PreparedActionReviewProjection,
  type PreparedActionSubmission,
} from '../contracts/prepared-action-lifecycle';

export interface ExecutionGrantIssuer {
  createGrant(input: {
    actor: string;
    auth?: AuthContext;
    receipt?: ActionReceiptRecord;
    toolCall: ToolCallRecord;
    ttlSeconds?: number;
  }): Promise<unknown>;
  prepareGrant?(input: {
    actor: string;
    auth?: AuthContext;
    deterministicSeed: string;
    issuedAt: string;
    receipt: ActionReceiptRecord;
    toolCall: ToolCallRecord;
    ttlSeconds?: number;
  }): ExecutionGrantRecord;
  recordPreparedGrantCreated?(
    grant: ExecutionGrantRecord,
    input: { actor: string; auditId?: string; auth?: AuthContext; emitTelemetry?: boolean },
  ): Promise<void>;
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
  preparedAction?: PreparedActionReviewProjection;
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

interface PendingApprovalCandidate {
  approval: ApprovalRecord;
  resolvedRecipients?: ApprovalNotificationRecipient[];
  toolCall: ToolCallRecord;
}

export interface ApprovalDecisionOptions {
  source?: ApprovalDecisionSource;
}

export interface ApprovalPresentationReference {
  channelId: string;
  destination: string;
  messageId: string;
  provider: ApprovalDeliveryRecord['provider'];
}

interface ApprovalPresentationSyncWork {
  approval: ApprovalRecord;
  deliveriesOverride?: ApprovalDeliveryRecord[];
  includeStoredDeliveries: boolean;
  resolution?: ApprovalResolutionContext;
  syncPresentation: NonNullable<ApprovalNotifier['syncApprovalPresentation']>;
  toolCall: ToolCallRecord;
}

interface ApprovalPresentationSyncState {
  acceptingTrailing: boolean;
  trailing?: ApprovalPresentationSyncWork;
  promise: Promise<void>;
}

export class ActionProxyService {
  private readonly approvalPresentationSyncs = new Map<string, ApprovalPresentationSyncState>();
  private preparedActionLifecycle?: PreparedActionLifecycle;

  constructor(private readonly deps: ActionProxyServiceDeps) {}

  /** Installed once by the private platform composition before routes open. */
  installPreparedActionLifecycle(lifecycle: PreparedActionLifecycle): void {
    if (this.preparedActionLifecycle && this.preparedActionLifecycle !== lifecycle) {
      throw new Error('Prepared-action lifecycle is already installed.');
    }
    this.preparedActionLifecycle = lifecycle;
  }

  async submitToolCall(
    request: SubmitToolCallRequest,
    options: {
      actionContractId?: string;
      auth?: AuthContext;
      connectionId?: string;
      forceApproval?: boolean;
      idempotencyKey?: string;
      ingress?: CanonicalActionIngress;
      supersedesIntentId?: string;
      /** Trusted internal identity for pre-bound internal child actions. Never read from request bodies. */
      toolCallId?: string;
      /** Trusted original linkage for an atomic prepared-action approval revision. */
      revision?: {
        createdAt: string;
        createdBy: string;
        fromApprovalId: string;
        fromIntentId: string;
        fromToolCallId: string;
        supersededAt: string;
      };
    } = {},
  ): Promise<{
    approval?: ApprovalRecord;
    revision?: {
      outcome: 'created' | 'replay';
      supersededApproval: ApprovalRecord;
      supersededToolCall: ToolCallRecord;
    };
    toolCall: ToolCallRecord;
  }> {
    const now = this.now().toISOString();
    const workspaceId = options.auth?.workspaceId ?? this.deps.workspaceId ?? 'default';
    const requestHash = hashJson({
      actionContractId: options.actionContractId ?? null,
      connectionId: options.connectionId ?? null,
      forceApproval: options.forceApproval ?? false,
      proposalRequest: request,
      route: 'POST /v1/tool-calls',
      supersedesIntentId: options.supersedesIntentId ?? null,
      toolCallId: options.toolCallId ?? null,
      revision: options.revision
        ? {
            fromApprovalId: options.revision.fromApprovalId,
            fromIntentId: options.revision.fromIntentId,
            fromToolCallId: options.revision.fromToolCallId,
          }
        : null,
    });
    if (options.idempotencyKey) {
      const existingIdempotency = await this.deps.store.getIdempotencyRecord(
        workspaceId,
        'POST /v1/tool-calls',
        options.idempotencyKey,
      );
      if (existingIdempotency) {
        if (existingIdempotency.requestHash !== requestHash) {
          throw new ConflictError('Idempotency key was already used for a different request.');
        }
        const replayedToolCall = await this.getToolCall(existingIdempotency.toolCallId, options.auth);
        if (
          this.preparedActionLifecycle?.isPreparedAction(request.toolName) &&
          !replayedToolCall.actionEnvelope?.preparedAction
        ) {
          throw new ConflictError(
            'Idempotency record points to an unprepared action where a prepared intent is required. Reject and resubmit with a new key.',
          );
        }
        const approval = await this.deps.store.getApprovalByToolCallId(replayedToolCall.id);
        if (
          !approval &&
          replayedToolCall.actionEnvelope?.preparedAction &&
          replayedToolCall.decision === 'require_approval'
        ) {
          throw new ConflictError('Prepared-action approval publication is incomplete; reject and resubmit with a new key.');
        }
        if (options.revision && approval) {
          const supersededApproval = await this.deps.store.getApproval(options.revision.fromApprovalId);
          const supersededToolCall = await this.deps.store.getToolCall(options.revision.fromToolCallId);
          if (
            !supersededApproval ||
            !supersededToolCall ||
            supersededApproval.status !== 'superseded' ||
            supersededApproval.supersededByApprovalId !== approval.id ||
            supersededToolCall.status !== 'rejected'
          ) {
            throw new ConflictError('Prepared-action revision replay does not match the authoritative supersession chain.');
          }
          return {
            approval,
            revision: { outcome: 'replay', supersededApproval, supersededToolCall },
            toolCall: replayedToolCall,
          };
        }
        if (replayedToolCall.actionEnvelope?.preparedAction) {
          await this.recordPreparedSubmissionPublishedBestEffort({
            actor: actorForSubmit(request, options.auth),
            approval,
            auth: options.auth,
            toolCall: replayedToolCall,
          });
        }
        return approval ? { approval, toolCall: replayedToolCall } : { toolCall: replayedToolCall };
      }
    }
    const toolCallId = options.toolCallId ?? `toolcall_${randomUUID()}`;
    let prepared = this.preparedActionLifecycle
      ? await this.preparedActionLifecycle.prepareSubmission(request, {
          actionContractId: options.actionContractId,
          auth: options.auth,
          connectionId: options.connectionId,
          idempotencyKey: options.idempotencyKey,
          now,
          supersedesIntentId: options.supersedesIntentId,
          toolCallId,
          workspaceId,
        })
      : undefined;
    if (
      this.preparedActionLifecycle?.isPreparedAction(request.toolName) &&
      !prepared
    ) {
      throw new ActionContractUnavailableError(
        `No enabled prepared-action contract is registered for ${request.toolName}.`,
      );
    }
    const effectiveRequest: SubmitToolCallRequest = prepared
      ? {
          ...request,
          action: {
            context: {
              dataClassification: request.action?.context?.dataClassification,
              metadata: request.action?.context?.metadata,
              reason: request.action?.context?.reason,
              risk: prepared.governance.risk,
              sideEffects: `prepared_${prepared.governance.operationKind}`,
            },
            executionMode: prepared.governance.executionMode,
            operation: {
              kind: prepared.governance.operationKind,
              name: request.toolName,
            },
            protocol: request.action?.protocol,
            resources: prepared.resources,
            source: request.action?.source,
          },
          input: prepared.effectiveInput,
          metadata: metadataWithPreparedGovernance(request.metadata, prepared),
        }
      : request;
    const actor = actorForSubmit(effectiveRequest, options.auth);
    const canonicalActionRequest = options.ingress
      ? normalizeActionRequest({
          auth: options.auth,
          idempotencyKey: options.idempotencyKey,
          ingress: options.ingress,
          receivedAt: now,
          request: effectiveRequest,
          requestId: toolCallId,
          trustedResources: prepared
            ? {
                source: `action-contract:${prepared.binding.contractId}@${prepared.binding.contractVersion}`,
                value: prepared.resources,
              }
            : undefined,
          trustedCredentialReference: prepared
            ? {
                source: `prepared-intent:${prepared.binding.intentId}`,
                value: prepared.connectionId,
              }
            : undefined,
          trustedExecutionMode: prepared
            ? {
                source: `action-contract:${prepared.binding.contractId}@${prepared.binding.contractVersion}`,
                value: prepared.governance.executionMode,
              }
            : undefined,
          trustedOperation: prepared
            ? {
                source: `action-contract:${prepared.binding.contractId}@${prepared.binding.contractVersion}`,
                value: {
                  kind: prepared.governance.operationKind,
                  name: effectiveRequest.toolName,
                },
              }
            : undefined,
          trustedPolicy: prepared
            ? {
                customerVisible: prepared.governance.customerVisible,
                operationKind: prepared.governance.operationKind,
                risk: prepared.governance.risk,
                source: `action-contract:${prepared.binding.contractId}@${prepared.binding.contractVersion}`,
              }
            : undefined,
          workspaceId,
        })
      : undefined;
    const policyVersionHash = this.currentPolicyVersionHash();
    const policyVersionId = this.currentPolicyVersionId(policyVersionHash);
    const baseProviderEvaluation = this.evaluatePolicyProvider(
      effectiveRequest.toolName,
      canonicalActionRequest
        ? policyContextFromCanonicalActionRequest(canonicalActionRequest)
        : policyContextFromSubmit(effectiveRequest),
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
    const policyEvaluation = effectivePolicyEvaluation(baseEvaluation, contentInfluence?.evidence);
    const evaluation: PolicyEvaluation = (options.forceApproval || prepared) && policyEvaluation.decision === 'allow'
      ? {
          ...policyEvaluation,
          decision: 'require_approval',
          reason: `${policyEvaluation.reason} This server-owned action contract requires human approval.`,
        }
      : policyEvaluation;
    const providerEvaluation = providerEvaluationWithEffectiveDecision(baseProviderEvaluation, evaluation);
    const normalizedEnvelope = normalizeActionEnvelope({ actor, auth: options.auth, request: effectiveRequest });
    const actionEnvelope = prepared
      ? actionEnvelopeWithPreparedAction(normalizedEnvelope, prepared, hashJson)
      : normalizedEnvelope;
    let toolCall: ToolCallRecord = {
      id: toolCallId,
      workspaceId,
      toolName: effectiveRequest.toolName,
      input: effectiveRequest.input,
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
      agentId: effectiveRequest.agentId,
      reason: effectiveRequest.reason,
      metadata: effectiveRequest.metadata ?? {},
      status: prepared && evaluation.decision === 'deny' ? 'blocked' : 'submitted',
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
    const preparedApprovalCandidate = prepared && evaluation.decision === 'require_approval'
      ? await this.buildPendingApprovalCandidate({
          actionEnvelope,
          actor,
          auth: options.auth,
          input: effectiveRequest.input,
          now,
          prepared: true,
          rule: evaluation.rule,
          toolCall,
          workspaceId,
        })
      : undefined;
    if (preparedApprovalCandidate) toolCall = preparedApprovalCandidate.toolCall;
    const idempotency = options.idempotencyKey
      ? {
          createdAt: now,
          key: options.idempotencyKey,
          requestHash,
          route: 'POST /v1/tool-calls',
          toolCallId: toolCall.id,
          workspaceId,
        }
      : undefined;
    let persistedPreparedApproval: ApprovalRecord | undefined;
    if (prepared && this.preparedActionLifecycle) {
      if (options.revision) {
        const revisionResult = await this.preparedActionLifecycle.persistRevision({
          approval: requiredPreparedApproval(preparedApprovalCandidate).approval,
          createdAt: options.revision.createdAt,
          createdBy: options.revision.createdBy,
          fromApprovalId: options.revision.fromApprovalId,
          fromIntentId: options.revision.fromIntentId,
          fromToolCallId: options.revision.fromToolCallId,
          idempotency,
          prepared,
          supersededAt: options.revision.supersededAt,
          toolCall,
        });
        if (revisionResult.outcome === 'conflict') {
          throw new ConflictError('Another revision already superseded this approval.');
        }
        return {
          approval: revisionResult.replacementApproval,
          revision: {
            outcome: revisionResult.outcome,
            supersededApproval: revisionResult.supersededApproval,
            supersededToolCall: revisionResult.supersededToolCall,
          },
          toolCall: revisionResult.replacementToolCall,
        };
      }
      const reservation = await this.preparedActionLifecycle.persistSubmission({
        approval: preparedApprovalCandidate?.approval,
        idempotency,
        prepared,
        toolCall,
      });
      if (reservation.outcome === 'conflict') {
        throw new ConflictError('Prepared-action idempotency or persistence binding conflicts with existing state.');
      }
      if (reservation.outcome === 'replay') {
        const replayedToolCall = await this.getToolCall(reservation.toolCall.id, options.auth);
        const approval = reservation.approval ?? await this.deps.store.getApprovalByToolCallId(replayedToolCall.id);
        if (!approval && replayedToolCall.decision === 'require_approval') {
          throw new ConflictError('Prepared-action approval publication is incomplete; reject and resubmit with a new key.');
        }
        await this.recordPreparedSubmissionPublishedBestEffort({
          actor,
          approval,
          auth: options.auth,
          toolCall: replayedToolCall,
        });
        return approval ? { approval, toolCall: replayedToolCall } : { toolCall: replayedToolCall };
      }
      prepared = reservation.prepared;
      toolCall = reservation.toolCall;
      persistedPreparedApproval = reservation.approval;
    } else if (idempotency) {
      const reservation = await this.deps.store.createToolCallIdempotentlyAtomically({
        idempotency,
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
    const observation = {
      agentId: effectiveRequest.agentId,
      auth: options.auth,
      input: effectiveRequest.input,
      policy: this.deps.policy,
      source: runtimeObservationSource(effectiveRequest),
      toolName: effectiveRequest.toolName,
      workspaceId,
    };
    if (prepared) {
      await this.recordPreparedSubmissionPublishedBestEffort({
        actor,
        approval: persistedPreparedApproval,
        auth: options.auth,
        toolCall,
      });
      try {
        await this.deps.policyDetector?.observeTool(observation);
      } catch {
        // The compound prepared-action publication is authoritative. Detector
        // telemetry cannot roll it back or strand a reviewable approval.
      }
    } else {
      await this.deps.policyDetector?.observeTool(observation);
      await this.audit('tool_call.submitted', {
      toolCallId: toolCall.id,
      actor,
      auth: options.auth,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      workspaceId,
      data: {
        agentId: effectiveRequest.agentId,
        decisionV1: toolCall.decisionTrace?.decisionV1,
        input: effectiveRequest.input,
        reason: effectiveRequest.reason,
        toolName: effectiveRequest.toolName,
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
      if (toolCall.status !== 'blocked') {
        toolCall = { ...toolCall, status: 'blocked', updatedAt: new Date().toISOString() };
        await this.deps.store.updateToolCall(toolCall);
      }
      if (!prepared) {
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
      }
      this.telemetry('policy.deny', telemetryForToolCall(toolCall, {
        decision: evaluation.decision,
        matched_rule: evaluation.matchedRule,
        status: toolCall.status,
      }));
      return { toolCall };
    }

    if (evaluation.decision === 'require_approval') {
      const influenceIntroducedApproval = contentInfluence?.evidence.baseDecision === 'allow';
      const candidate = prepared
        ? requiredPreparedApproval(preparedApprovalCandidate)
        : await this.buildPendingApprovalCandidate({
            actionEnvelope,
            actor,
            auth: options.auth,
            input: effectiveRequest.input,
            now,
            prepared: false,
            rule: evaluation.rule,
            toolCall,
            workspaceId,
          });
      let approval = prepared ? persistedPreparedApproval ?? candidate.approval : candidate.approval;
      const resolvedRecipients = candidate.resolvedRecipients;
      if (prepared) {
        if (toolCall.status !== 'pending_approval' || approval.toolCallId !== toolCall.id) {
          throw new ConflictError('Prepared approval publication does not match the authoritative tool call.');
        }
      } else {
        toolCall = candidate.toolCall;
        await this.deps.store.updateToolCall(toolCall);
        await this.deps.store.createApproval(approval);
      }
      const authorization = approval.authorization;
      if (!authorization || !approval.reviewHash) {
        throw new ConflictError('Approval authorization is missing from the authoritative pending approval.');
      }
      const reviewHash = approval.reviewHash;
      if (!prepared) {
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
            originalInput: effectiveRequest.input,
            originalInputHash: actionEnvelope.inputHash,
            originalEnvelopeHash: actionEnvelope.envelopeHash,
            reviewHash,
            contentInfluence: contentInfluence?.evidence ?? null,
            requiredApprovals: approval.requiredApprovals ?? 1,
            separationOfDuties: approval.separationOfDuties ?? false,
          },
        });
      }
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
      input: effectiveRequest.input,
      toolCall,
    });
    toolCall = actionEnvelope.executionMode === 'external_grant'
      ? await this.authorizeExternalExecution(
          toolCall,
          effectiveRequest.input,
          actor,
          options.auth,
          evaluation.rule.externalExecution?.grantTtlSeconds,
          receipt,
        )
      : await this.executeToolCall(toolCall, effectiveRequest.input, actor, options.auth, receipt);
    return { toolCall };
  }

  private async buildPendingApprovalCandidate(input: {
    actionEnvelope: ActionEnvelope;
    actor: string;
    auth?: AuthContext;
    input: JsonObject;
    now: string;
    prepared: boolean;
    rule: PolicyRule;
    toolCall: ToolCallRecord;
    workspaceId: string;
  }): Promise<PendingApprovalCandidate> {
    const resolvedRecipients = await this.resolveApprovalRecipients(input.rule, input.workspaceId);
    const approverUsers = approvalApproverUsersFor(input.rule, resolvedRecipients);
    const approverGroups = input.rule.approvers?.groups ?? [];
    const requiredApprovals = input.rule.approvers?.requiredApprovals ?? 1;
    const separationOfDuties = input.rule.approvers?.separationOfDuties ?? false;
    const pendingToolCall: ToolCallRecord = {
      ...input.toolCall,
      status: 'pending_approval',
      updatedAt: input.now,
    };
    const approvalId = input.prepared && this.preparedActionLifecycle
      ? this.preparedActionLifecycle.preparedApprovalId(pendingToolCall)
      : `approval_${randomUUID()}`;
    const reviewHash = reviewHashFor({
      actionEnvelopeHash: input.actionEnvelope.envelopeHash,
      approvalId,
      policyVersionHash: pendingToolCall.policyVersionHash,
      toolCallId: pendingToolCall.id,
    });
    const expiresAt = new Date(
      Date.parse(input.now) + Math.max(
        1,
        this.deps.approvalAuthorizationTtlMs ?? DEFAULT_APPROVAL_AUTHORIZATION_TTL_MS,
      ),
    ).toISOString();
    const authorization = buildApprovalAuthorization({
      approvalId,
      approverGroups,
      approverUsers,
      expiresAt,
      issuedAt: input.now,
      originalEnvelopeHash: input.actionEnvelope.envelopeHash,
      originalInputHash: input.actionEnvelope.inputHash,
      requestedBy: input.actor,
      requestedByPrincipalId: input.auth?.principalId,
      requiredApprovals,
      reviewHash,
      separationOfDuties,
      toolCall: pendingToolCall,
    });
    return {
      approval: {
        approverGroups,
        approverUsers,
        authorization,
        createdAt: input.now,
        decisions: [],
        id: approvalId,
        originalEnvelopeHash: input.actionEnvelope.envelopeHash,
        originalInput: input.input,
        originalInputHash: input.actionEnvelope.inputHash,
        requestedBy: input.actor,
        requestedByAuth: input.auth,
        requiredApprovals,
        reviewHash,
        separationOfDuties,
        status: 'pending',
        toolCallId: pendingToolCall.id,
        updatedAt: input.now,
        workspaceId: input.workspaceId,
      },
      resolvedRecipients,
      toolCall: pendingToolCall,
    };
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
    const preparedAction = await this.preparedActionLifecycle?.reviewProjection(toolCall);
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
      preparedAction,
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
    if (toolCall.actionEnvelope?.preparedAction) {
      if (!this.preparedActionLifecycle) {
        throw new ActionContractUnavailableError(
          'The prepared-action lifecycle is unavailable for this authorized action.',
        );
      }
      await this.preparedActionLifecycle.assertDispatchCurrent(toolCall, input);
    }
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
    options: ApprovalDecisionOptions = {},
  ): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
    const initial = await this.loadApprovalState(approvalId, auth);
    this.assertCanDecideApproval(initial.approval, auth);
    const inputDecision = approvalInputDecision(input);
    const initialPreparedEditDisposition = await this.resolvePreparedInlineEditDisposition(
      initial.toolCall,
      inputDecision.mode === 'edited',
    );
    if (initial.approval.status !== 'pending') {
      if (initialPreparedEditDisposition) {
        throw new PreparedActionEditConflict(initialPreparedEditDisposition);
      }
      const recovered = await this.recoverApprovedPreparedExternalAuthorization(
        initial.approval,
        initial.toolCall,
        auth,
      );
      if (recovered) return recovered;
      throw new ConflictError(`Approval is already ${initial.approval.status}`);
    }

    // Reload immediately before policy evaluation and the storage CAS. No execution decision
    // relies on the earlier route-facing snapshot.
    const authoritative = await this.loadApprovalState(approvalId, auth);
    this.assertCanDecideApproval(authoritative.approval, auth);
    const authoritativePreparedEditDisposition = await this.resolvePreparedInlineEditDisposition(
      authoritative.toolCall,
      inputDecision.mode === 'edited',
    );
    const preparedEditDisposition = authoritativePreparedEditDisposition ?? initialPreparedEditDisposition;
    if (preparedEditDisposition) {
      throw new PreparedActionEditConflict(preparedEditDisposition);
    }
    const approval = await this.expireApprovalIfNeeded(authoritative.approval, authoritative.toolCall, auth);
    const toolCall = authoritative.toolCall;
    if (approval.status !== 'pending') {
      throw authoritative.approval.status === 'pending' && approval.status === 'expired'
        ? new ApprovalPresentationSynchronizedConflictError('Approval is already expired')
        : new ConflictError(`Approval is already ${approval.status}`);
    }
    if (toolCall.status !== 'pending_approval') throw new ConflictError(`Tool call is not pending approval: ${toolCall.status}`);
    this.assertCanDecideApproval(approval, auth);
    this.assertClientApprovalNonce(approval, input.approvalNonce);

    const now = this.now().toISOString();
    const actor = actorForDecision(input.approvedBy, auth);
    const source = approvalDecisionSource(options.source, auth);
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
    const requiredApprovals = Math.max(1, approval.requiredApprovals ?? 1);
    if (inputDecision.mode === 'edited' && toolCall.metadata.approvalInputMode === 'original_only') {
      throw new ConflictError(
        'This approval only permits the original input. Reject it and submit a new proposal to make changes.',
      );
    }
    if (inputDecision.mode === 'edited' && requiredApprovals > 1) {
      throw new ConflictError('Edited input is not supported when requiredApprovals is greater than 1.');
    }
    const approvedInput = inputDecision.mode === 'edited' ? inputDecision.input : approval.originalInput;
    const approvedEnvelope = actionEnvelopeForInput(actionEnvelope, approvedInput);
    if (actionEnvelope.preparedAction) {
      if (!this.preparedActionLifecycle) {
        throw new ActionContractUnavailableError(
          'The prepared-action registry is unavailable for this approval.',
        );
      }
      await this.preparedActionLifecycle.assertApprovalCurrent(toolCall, approvedInput);
    }
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
      source,
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
      throw new ApprovalPresentationSynchronizedConflictError(
        'Approval authorization has expired. Resubmit the action.',
      );
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
    const recordDecisionEvidence = async () => {
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
          source,
        },
      });
      this.telemetry(isFinalApproval ? 'approval.approved' : 'approval.approval_recorded', telemetryForToolCall(toolCall, {
        'approval.id': approval.id,
        'approval.status': updatedApproval.status,
      }));
    };

    if (!isFinalApproval) {
      await recordDecisionEvidence();
      return { approval: updatedApproval, toolCall };
    }

    const resolution: ApprovalResolutionContext = {
      actor,
      auth,
      decidedAt: updatedApproval.finalizedAt ?? now,
      source,
    };
    try {
      await recordDecisionEvidence();
      if (toolCall.actionEnvelope?.preparedAction && approvedEnvelope.executionMode === 'external_grant') {
        const published = await this.publishApprovedPreparedExternalAuthorization(updatedApproval, toolCall, auth);
        return { approval: updatedApproval, toolCall: published };
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
    } finally {
      await this.syncApprovalPresentationBestEffort(updatedApproval, toolCall, resolution);
    }
  }

  private async resolvePreparedInlineEditDisposition(
    toolCall: ToolCallRecord,
    edited: boolean,
  ): Promise<PreparedActionEditDisposition | undefined> {
    if (!edited || !toolCall.actionEnvelope?.preparedAction) return undefined;
    if (!this.preparedActionLifecycle) {
      throw new ActionContractUnavailableError(
        'The prepared-action registry is unavailable for this approval.',
      );
    }
    const revision = await this.preparedActionLifecycle.revisionContext(toolCall);
    return revision.editMode;
  }

  private async recoverApprovedPreparedExternalAuthorization(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
    auth?: AuthContext,
  ): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord } | undefined> {
    if (
      approval.status !== 'approved' ||
      !toolCall.actionEnvelope?.preparedAction ||
      this.actionEnvelopeForToolCall(toolCall).executionMode !== 'external_grant' ||
      !['authorized', 'pending_approval'].includes(toolCall.status)
    ) {
      return undefined;
    }
    let recoveredToolCall = toolCall;
    try {
      recoveredToolCall = await this.publishApprovedPreparedExternalAuthorization(approval, toolCall, auth);
      return { approval, toolCall: recoveredToolCall };
    } finally {
      await this.syncApprovalPresentationBestEffort(approval, recoveredToolCall);
    }
  }

  private async publishApprovedPreparedExternalAuthorization(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
    requestAuth?: AuthContext,
  ): Promise<ToolCallRecord> {
    const grantIssuer = this.deps.executionGrants;
    if (!grantIssuer?.prepareGrant || !grantIssuer.recordPreparedGrantCreated) {
      throw new ActionContractUnavailableError(
        'Prepared-action authorization publication is unavailable in this server composition.',
      );
    }
    const approvedInput = approval.editedInput ?? approval.originalInput;
    if (
      approval.approvedInputHash !== hashJson(approvedInput) ||
      approval.approvedEnvelopeHash === undefined
    ) {
      throw new ConflictError('Approved prepared action does not match its finalized input binding.');
    }
    await this.preparedActionLifecycle?.assertApprovalCurrent(toolCall, approvedInput);
    const revalidationFailure = await this.finalPolicyRevalidationFailure(toolCall, approvedInput);
    if (revalidationFailure) {
      return this.failToolCall(toolCall, approvedInput, approval.approvedBy ?? 'actionproxy:approval', revalidationFailure, requestAuth);
    }

    const finalDecision = [...(approval.decisions ?? [])]
      .sort((left, right) => left.decidedAt.localeCompare(right.decidedAt))
      .at(-1);
    const actor = approval.approvedBy ?? finalDecision?.actor ?? 'actionproxy:approval';
    const decisionAuth = finalDecision?.auth;
    const issuedAt = approval.finalizedAt ?? approval.authorizationConsumedAt ?? approval.updatedAt;
    const seed = hashJson({
      approvalAuthorizationHash: approval.authorization?.authorizationHash ?? null,
      approvalId: approval.id,
      approvedEnvelopeHash: approval.approvedEnvelopeHash,
      approvedInputHash: approval.approvedInputHash,
      finalizedAt: issuedAt,
      toolCallId: toolCall.id,
    });
    const approvedEnvelope = actionEnvelopeForInput(this.actionEnvelopeForToolCall(toolCall), approvedInput);
    if (approvedEnvelope.envelopeHash !== approval.approvedEnvelopeHash) {
      throw new ConflictError('Approved prepared action envelope no longer matches the finalized approval.');
    }
    const baseToolCall: ToolCallRecord = {
      ...toolCall,
      actionEnvelope: approvedEnvelope,
      actionEnvelopeHash: approvedEnvelope.envelopeHash,
      input: approvedInput,
      inputHash: approvedEnvelope.inputHash,
    };
    const receipt = this.prepareActionReceipt({
      actor,
      approval,
      auth: decisionAuth,
      decisionKind: 'human_approval',
      input: approvedInput,
      reviewHash: approval.reviewHash,
      toolCall: baseToolCall,
    }, { deterministicSeed: seed, issuedAt });
    const grant = grantIssuer.prepareGrant({
      actor,
      auth: decisionAuth,
      deterministicSeed: seed,
      issuedAt,
      receipt,
      toolCall: baseToolCall,
    });
    const attemptSeed = hashJson({ grantId: grant.id, kind: 'prepared-external-attempt', seed });
    const attempt: ExecutionAttemptRecordV1 = {
      ...buildExecutionAttempt({
        approval,
        executionMode: 'external_grant',
        id: `attempt_${attemptSeed.slice(0, 32)}`,
        inputHash: baseToolCall.inputHash!,
        now: issuedAt,
        receipt,
        reservationOwner: `reservation_${attemptSeed.slice(32)}`,
        toolCall: baseToolCall,
      }),
      grantId: grant.id,
    };
    const result = redactToolCallResult({
      externalExecution: true,
      grant,
      note: 'Execution authorized for the server-owned prepared-action executor.',
      ok: true,
      receipt,
    } as JsonObject);
    const authorizedToolCall: ToolCallRecord = {
      ...baseToolCall,
      result,
      status: 'authorized',
      updatedAt: issuedAt,
    };
    const publication = await this.deps.store.publishApprovedExternalAuthorizationAtomically({
      approvalId: approval.id,
      attempt,
      grant,
      receipt,
      toolCall: authorizedToolCall,
    });
    if (
      (publication.outcome !== 'created' && publication.outcome !== 'replay') ||
      !publication.toolCall ||
      !publication.grant ||
      !publication.receipt ||
      !publication.attempt
    ) {
      throw new ConflictError(`Prepared-action authorization publication was rejected: ${publication.outcome}.`);
    }
    await this.recordApprovedExternalAuthorizationPublishedBestEffort({
      actor,
      approval,
      attempt: publication.attempt,
      auth: decisionAuth,
      emitTelemetry: publication.outcome === 'created',
      grant: publication.grant,
      receipt: publication.receipt,
      toolCall: publication.toolCall,
    });
    return publication.toolCall;
  }

  private async recordApprovedExternalAuthorizationPublishedBestEffort(input: {
    actor: string;
    approval: ApprovalRecord;
    attempt: ExecutionAttemptRecordV1;
    auth?: AuthContext;
    emitTelemetry: boolean;
    grant: ExecutionGrantRecord;
    receipt: ActionReceiptRecord;
    toolCall: ToolCallRecord;
  }): Promise<void> {
    const eventId = (type: string) => `audit_prepared_authorization_${hashJson({
      approvalId: input.approval.id,
      type,
      workspaceId: input.toolCall.workspaceId ?? 'default',
    })}`;
    const bestEffort = async (operation: () => Promise<void>): Promise<void> => {
      try {
        await operation();
      } catch {
        // Each event is attempted independently. Deterministic ids let an
        // approval replay fill missing events without duplicating existing ones.
      }
    };
    await bestEffort(() => this.recordActionReceiptCreated(input.receipt, input, {
      auditId: eventId('receipt.created'),
      emitTelemetry: input.emitTelemetry,
    }));
    await bestEffort(() => this.auditExecutionAttempt(
      'execution.attempt_reserved',
      input.attempt,
      input.actor,
      input.auth,
      undefined,
      eventId('execution.attempt_reserved'),
    ));
    await bestEffort(() => this.deps.executionGrants!.recordPreparedGrantCreated!(input.grant, {
        auditId: eventId('execution_grant.created'),
        actor: input.actor,
        auth: input.auth,
        emitTelemetry: input.emitTelemetry,
      }));
    await bestEffort(() => this.audit('tool_call.authorized', {
        actor: input.actor,
        approvalId: input.approval.id,
        auth: input.auth,
        data: {
          actionEnvelopeHash: input.toolCall.actionEnvelopeHash,
          executionAttemptId: input.attempt.id,
          grantId: input.grant.id,
          input: input.toolCall.input,
          receiptHash: input.receipt.receiptHash,
          receiptId: input.receipt.id,
          result: input.toolCall.result ?? null,
          toolName: input.toolCall.toolName,
        },
        id: eventId('tool_call.authorized'),
        inputHash: input.toolCall.inputHash,
        policyVersionHash: input.toolCall.policyVersionHash,
        policyVersionId: input.toolCall.policyVersionId,
        toolCallId: input.toolCall.id,
        workspaceId: input.toolCall.workspaceId,
      }));
    if (input.emitTelemetry) {
      this.telemetry('tool_call.authorized', telemetryForToolCall(input.toolCall, {
        'grant.id': input.grant.id,
        'receipt.hash': input.receipt.receiptHash,
        'receipt.id': input.receipt.id,
        status: input.toolCall.status,
      }));
    }
  }

  private async recordPreparedRevisionPublishedBestEffort(input: {
    actor: string;
    approval: ApprovalRecord;
    auth?: AuthContext;
    supersededApproval: ApprovalRecord;
    supersededToolCall: ToolCallRecord;
    toolCall: ToolCallRecord;
  }): Promise<void> {
    const binding = input.toolCall.actionEnvelope?.preparedAction;
    const base = {
      actor: input.actor,
      auth: input.auth,
      inputHash: input.toolCall.inputHash,
      policyVersionHash: input.toolCall.policyVersionHash,
      policyVersionId: input.toolCall.policyVersionId,
      timestamp: input.approval.createdAt,
      toolCallId: input.toolCall.id,
      workspaceId: input.toolCall.workspaceId,
    };
    const eventId = (type: string) => `audit_revision_${hashJson({
      approvalId: input.approval.id,
      type,
      workspaceId: input.toolCall.workspaceId ?? 'default',
    })}`;
    try {
      await this.audit('prepared_action.created', {
        ...base,
        data: {
          adapterId: binding?.adapterId ?? null,
          adapterVersion: binding?.adapterVersion ?? null,
          contractId: binding?.contractId ?? null,
          contractVersion: binding?.contractVersion ?? null,
          intentHash: binding?.intentHash ?? null,
          intentId: binding?.intentId ?? null,
          operationHash: binding?.operationHash ?? null,
          revision: true,
          serializerVersion: binding?.serializerVersion ?? null,
        },
        id: eventId('prepared_action.created'),
      });
      await this.audit('tool_call.submitted', {
        ...base,
        data: {
          agentId: input.toolCall.agentId,
          decisionV1: input.toolCall.decisionTrace?.decisionV1,
          input: input.toolCall.input,
          preparedIntentHash: binding?.intentHash ?? null,
          reason: input.toolCall.reason,
          revision: true,
          toolName: input.toolCall.toolName,
        },
        id: eventId('tool_call.submitted'),
      });
      await this.audit('action.envelope_created', {
        ...base,
        data: {
          actionEnvelope: input.toolCall.actionEnvelope ?? null,
          actionEnvelopeHash: input.toolCall.actionEnvelopeHash ?? null,
          canonicalActionRequestHash: input.toolCall.canonicalActionRequestHash ?? null,
          canonicalActionRequestVersion: input.toolCall.canonicalActionRequestVersion ?? null,
          canonicalDecisionInputHash: input.toolCall.canonicalDecisionInputHash ?? null,
          canonicalPolicyContext: input.toolCall.canonicalPolicyContext ?? null,
          revision: true,
        },
        id: eventId('action.envelope_created'),
      });
      await this.audit('policy.require_approval', {
        ...base,
        data: {
          reason: input.toolCall.policyReason,
          revision: true,
          risk: input.toolCall.risk,
        },
        id: eventId('policy.require_approval'),
      });
      await this.audit('approval.created', {
        ...base,
        approvalId: input.approval.id,
        data: {
          approvalAuthorizationHash: input.approval.authorization?.authorizationHash ?? null,
          approvalAuthorizationVersion: input.approval.authorization?.version ?? null,
          approverGroups: input.approval.approverGroups ?? [],
          approverUsers: input.approval.approverUsers ?? [],
          expiresAt: input.approval.authorization?.expiresAt ?? null,
          originalEnvelopeHash: input.approval.originalEnvelopeHash ?? null,
          originalInput: input.approval.originalInput,
          originalInputHash: input.approval.originalInputHash ?? null,
          requiredApprovals: input.approval.requiredApprovals ?? 1,
          reviewHash: input.approval.reviewHash ?? null,
          revision: true,
          separationOfDuties: input.approval.separationOfDuties ?? false,
        },
        id: eventId('approval.created'),
      });
      await this.audit('approval.superseded', {
        actor: input.actor,
        approvalId: input.supersededApproval.id,
        auth: input.auth,
        data: {
          replacementApprovalId: input.approval.id,
          replacementToolCallId: input.toolCall.id,
        },
        id: eventId('approval.superseded'),
        inputHash: input.supersededToolCall.inputHash,
        policyVersionHash: input.supersededToolCall.policyVersionHash,
        policyVersionId: input.supersededToolCall.policyVersionId,
        timestamp: input.approval.createdAt,
        toolCallId: input.supersededToolCall.id,
        workspaceId: input.supersededToolCall.workspaceId,
      });
      await this.audit('approval.revised', {
        ...base,
        approvalId: input.approval.id,
        data: {
          supersededApprovalId: input.supersededApproval.id,
          supersededToolCallId: input.supersededToolCall.id,
        },
        id: eventId('approval.revised'),
      });
    } catch {
      // The composite revision transaction is authoritative. Deterministic
      // event ids let an exact idempotent replay fill any missing audit rows.
    }
  }

  private async recordPreparedSubmissionPublishedBestEffort(input: {
    actor: string;
    approval?: ApprovalRecord;
    auth?: AuthContext;
    toolCall: ToolCallRecord;
  }): Promise<void> {
    const binding = input.toolCall.actionEnvelope?.preparedAction;
    if (!binding) return;
    const timestamp = input.approval?.createdAt ?? input.toolCall.createdAt;
    const base = {
      actor: input.actor,
      auth: input.auth,
      inputHash: input.toolCall.inputHash,
      policyVersionHash: input.toolCall.policyVersionHash,
      policyVersionId: input.toolCall.policyVersionId,
      timestamp,
      toolCallId: input.toolCall.id,
      workspaceId: input.toolCall.workspaceId,
    };
    const record = async (
      type: AuditEvent['type'],
      data: JsonObject,
      approvalId?: string,
    ): Promise<void> => {
      try {
        await this.audit(type, {
          ...base,
          approvalId,
          data,
          id: `audit_prepared_submission_${hashJson({
            approvalId: approvalId ?? null,
            toolCallId: input.toolCall.id,
            type,
            workspaceId: input.toolCall.workspaceId ?? 'default',
          })}`,
        });
      } catch {
        // Each append is independently replayable. One unavailable secondary
        // audit sink must not prevent later events or strand the durable action.
      }
    };
    await record('prepared_action.created', {
      adapterId: binding.adapterId,
      adapterVersion: binding.adapterVersion,
      contractId: binding.contractId,
      contractVersion: binding.contractVersion,
      intentHash: binding.intentHash,
      intentId: binding.intentId,
      operationHash: binding.operationHash,
      serializerVersion: binding.serializerVersion,
    });
    await record('tool_call.submitted', {
      agentId: input.toolCall.agentId,
      decisionV1: input.toolCall.decisionTrace?.decisionV1,
      input: input.toolCall.input,
      preparedIntentHash: binding.intentHash,
      reason: input.toolCall.reason,
      toolName: input.toolCall.toolName,
    });
    await record('action.envelope_created', {
      actionEnvelope: input.toolCall.actionEnvelope,
      actionEnvelopeHash: input.toolCall.actionEnvelopeHash,
      canonicalActionRequestHash: input.toolCall.canonicalActionRequestHash,
      canonicalActionRequestVersion: input.toolCall.canonicalActionRequestVersion,
      canonicalDecisionInputHash: input.toolCall.canonicalDecisionInputHash,
      canonicalPolicyContext: input.toolCall.canonicalPolicyContext,
      executionMode: input.toolCall.actionEnvelope?.executionMode,
      protocol: input.toolCall.actionEnvelope?.protocol,
      source: input.toolCall.actionEnvelope?.source,
    });
    if (input.toolCall.contentInfluence) {
      await record(
        'content.influence_evaluated',
        input.toolCall.contentInfluence as unknown as JsonObject,
      );
    }
    const policyType: AuditEvent['type'] = input.toolCall.decision === 'deny'
      ? 'policy.deny'
      : input.toolCall.decision === 'allow'
        ? 'policy.allow'
        : 'policy.require_approval';
    await record(policyType, {
      reason: input.toolCall.policyReason,
      risk: input.toolCall.risk,
    });
    if (
      input.toolCall.contentInfluence?.baseDecision !== input.toolCall.contentInfluence?.effectiveDecision &&
      input.toolCall.contentInfluence?.effectiveDecision === 'deny'
    ) {
      await record('content.influence_denied', minimizedInfluenceAudit(input.toolCall.contentInfluence));
    }
    if (
      input.approval &&
      input.toolCall.contentInfluence?.baseDecision === 'allow' &&
      input.toolCall.contentInfluence?.effectiveDecision === 'require_approval'
    ) {
      await record(
        'content.influence_approval_required',
        minimizedInfluenceAudit(input.toolCall.contentInfluence),
        input.approval.id,
      );
    }
    if (input.approval) {
      await record('approval.created', {
        approvalAuthorizationHash: input.approval.authorization?.authorizationHash ?? null,
        approvalAuthorizationVersion: input.approval.authorization?.version ?? null,
        approverGroups: input.approval.approverGroups ?? [],
        approverUsers: input.approval.approverUsers ?? [],
        expiresAt: input.approval.authorization?.expiresAt ?? null,
        originalEnvelopeHash: input.approval.originalEnvelopeHash ?? null,
        originalInput: input.approval.originalInput,
        originalInputHash: input.approval.originalInputHash ?? null,
        requiredApprovals: input.approval.requiredApprovals ?? 1,
        reviewHash: input.approval.reviewHash ?? null,
        separationOfDuties: input.approval.separationOfDuties ?? false,
      }, input.approval.id);
    }
  }

  async reviseApproval(
    approvalId: string,
    input: { input: JsonObject; reason?: string },
    options: { auth?: AuthContext; idempotencyKey?: string; source?: ApprovalDecisionSource } = {},
  ): Promise<{
    approval: ApprovalRecord;
    supersededApproval: ApprovalRecord;
    supersededToolCall: ToolCallRecord;
    toolCall: ToolCallRecord;
  }> {
    if (!this.preparedActionLifecycle) {
      throw new ActionContractUnavailableError('Prepared-action revisions are not available in this edition.');
    }
    const authoritative = await this.loadApprovalState(approvalId, options.auth);
    const replayingFinalizedRevision =
      Boolean(options.idempotencyKey) &&
      authoritative.approval.status === 'superseded' &&
      Boolean(authoritative.approval.supersededAt) &&
      Boolean(authoritative.approval.supersededByApprovalId);
    const approval = replayingFinalizedRevision
      ? authoritative.approval
      : await this.expireApprovalIfNeeded(
          authoritative.approval,
          authoritative.toolCall,
          options.auth,
        );
    const toolCall = authoritative.toolCall;
    if (
      !replayingFinalizedRevision &&
      (approval.status !== 'pending' || toolCall.status !== 'pending_approval')
    ) {
      throw new ConflictError(`Approval is already ${approval.status}.`);
    }
    this.assertCanDecideApproval(approval, options.auth);
    if (!toolCall.actionEnvelope?.preparedAction) {
      throw new ActionContractUnavailableError(
        'Only server-prepared actions can use the revision endpoint.',
      );
    }
    await this.preparedActionLifecycle.assertRevisionAllowed(toolCall);
    const revision = await this.preparedActionLifecycle.revisionContext(toolCall);
    if (revision.editMode === 'original_only') {
      throw new ConflictError('This exact action permits approval of the original input only; reject and resubmit a new proposal.');
    }
    const envelope = this.actionEnvelopeForToolCall(toolCall);
    const actor = actorForDecision(undefined, options.auth);
    const revisionAt = replayingFinalizedRevision
      ? approval.supersededAt!
      : this.now().toISOString();
    const submitted = await this.submitToolCall(
      {
        action: {
          context: envelope.context,
          executionMode: envelope.executionMode,
          operation: envelope.operation,
          protocol: envelope.protocol,
          source: envelope.source,
        },
        agentId: toolCall.agentId,
        input: input.input,
        metadata: {
          ...toolCall.metadata,
          approvalRevision: {
            fromApprovalId: approval.id,
            fromIntentId: revision.intentId,
            fromToolCallId: toolCall.id,
          },
        },
        reason: input.reason ?? `Revision of approval ${approval.id}.`,
        requestedBy: actor,
        toolName: toolCall.toolName,
      },
      {
        actionContractId: revision.contractId,
        auth: options.auth,
        connectionId: revision.connectionId,
        forceApproval: true,
        idempotencyKey: options.idempotencyKey
          ? `approval-revision:${approval.id}:${options.idempotencyKey}`
          : undefined,
        revision: {
          createdAt: revisionAt,
          createdBy: actor,
          fromApprovalId: approval.id,
          fromIntentId: revision.intentId,
          fromToolCallId: toolCall.id,
          supersededAt: revisionAt,
        },
        supersedesIntentId: revision.intentId,
      },
    );
    if (!submitted.approval || !submitted.revision || submitted.toolCall.status !== 'pending_approval') {
      throw new ConflictError('A native-action revision must create a separate pending approval.');
    }
    const {
      supersededApproval,
      supersededToolCall,
    } = submitted.revision;
    const replacementApproval = submitted.approval;
    const replacementToolCall = submitted.toolCall;
    await this.recordPreparedRevisionPublishedBestEffort({
      actor,
      approval: replacementApproval,
      auth: options.auth,
      supersededApproval,
      supersededToolCall,
      toolCall: replacementToolCall,
    });
    await this.syncApprovalPresentationBestEffort(
      supersededApproval,
      supersededToolCall,
      submitted.revision.outcome === 'created'
        ? {
            actor,
            auth: options.auth,
            decidedAt: supersededApproval.supersededAt ?? revisionAt,
            source: approvalDecisionSource(options.source, options.auth),
          }
        : undefined,
    );
    if (submitted.revision.outcome === 'created') {
      await this.notifyApprovalRequired(
        replacementToolCall,
        replacementApproval,
        actor,
        options.auth,
      );
    }
    return {
      approval: replacementApproval,
      supersededApproval,
      supersededToolCall,
      toolCall: replacementToolCall,
    };
  }

  async rejectApproval(
    approvalId: string,
    input: { approvalNonce?: string; rejectedBy?: string; reason?: string },
    auth?: AuthContext,
    options: ApprovalDecisionOptions = {},
  ): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
    const initial = await this.loadApprovalState(approvalId, auth);
    this.assertCanDecideApproval(initial.approval, auth);
    const initialApproval = await this.expireApprovalIfNeeded(initial.approval, initial.toolCall, auth);
    if (initialApproval.status !== 'pending') {
      throw initial.approval.status === 'pending' && initialApproval.status === 'expired'
        ? new ApprovalPresentationSynchronizedConflictError('Approval is already expired')
        : new ConflictError(`Approval is already ${initialApproval.status}`);
    }
    this.assertClientApprovalNonce(initialApproval, input.approvalNonce);

    const authoritative = await this.loadApprovalState(approvalId, auth);
    const approval = await this.expireApprovalIfNeeded(authoritative.approval, authoritative.toolCall, auth);
    const toolCall = authoritative.toolCall;
    if (approval.status !== 'pending') {
      throw authoritative.approval.status === 'pending' && approval.status === 'expired'
        ? new ApprovalPresentationSynchronizedConflictError('Approval is already expired')
        : new ConflictError(`Approval is already ${approval.status}`);
    }
    const now = this.now().toISOString();
    const actor = actorForDecision(input.rejectedBy, auth);
    const source = approvalDecisionSource(options.source, auth);
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
      throw new ApprovalPresentationSynchronizedConflictError('Approval authorization has expired.');
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

    const resolution: ApprovalResolutionContext = {
      actor,
      auth,
      decidedAt: updatedApproval.finalizedAt ?? now,
      reason: input.reason,
      source,
    };
    try {
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
        data: { reason: input.reason ?? null, source },
      });
      this.telemetry('approval.rejected', telemetryForToolCall(updatedToolCall, {
        'approval.id': approval.id,
        'approval.status': updatedApproval.status,
        status: updatedToolCall.status,
      }));
    } finally {
      await this.syncApprovalPresentationBestEffort(updatedApproval, updatedToolCall, resolution);
    }

    return { approval: updatedApproval, toolCall: updatedToolCall };
  }

  async cancelApproval(
    approvalId: string,
    input: { approvalNonce?: string; cancelledBy?: string; reason?: string },
    auth?: AuthContext,
    options: ApprovalDecisionOptions = {},
  ): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
    const initial = await this.loadApprovalState(approvalId, auth);
    this.assertCanDecideApproval(initial.approval, auth);
    const initialApproval = await this.expireApprovalIfNeeded(initial.approval, initial.toolCall, auth);
    if (initialApproval.status !== 'pending') {
      throw initial.approval.status === 'pending' && initialApproval.status === 'expired'
        ? new ApprovalPresentationSynchronizedConflictError('Approval is already expired')
        : new ConflictError(`Approval is already ${initialApproval.status}`);
    }
    this.assertClientApprovalNonce(initialApproval, input.approvalNonce);

    const authoritative = await this.loadApprovalState(approvalId, auth);
    const approval = await this.expireApprovalIfNeeded(authoritative.approval, authoritative.toolCall, auth);
    const toolCall = authoritative.toolCall;
    if (approval.status !== 'pending') {
      throw authoritative.approval.status === 'pending' && approval.status === 'expired'
        ? new ApprovalPresentationSynchronizedConflictError('Approval is already expired')
        : new ConflictError(`Approval is already ${approval.status}`);
    }
    this.assertCanDecideApproval(approval, auth);
    this.assertClientApprovalNonce(approval, input.approvalNonce);

    const now = this.now().toISOString();
    const actor = actorForDecision(input.cancelledBy, auth);
    const source = approvalDecisionSource(options.source, auth);
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
      throw new ApprovalPresentationSynchronizedConflictError('Approval authorization has expired.');
    }
    if (transition.outcome === 'replayed') {
      throw new ConflictError('Approval authorization nonce has already been consumed.');
    }
    if (transition.outcome === 'already_final') {
      throw new ConflictError(`Approval is already ${transition.approval?.status ?? 'finalized'}`);
    }
    const updatedApproval = transition.approval!;
    let updatedToolCall = toolCall;
    const resolution: ApprovalResolutionContext = {
      actor,
      auth,
      decidedAt: updatedApproval.finalizedAt ?? now,
      reason: input.reason,
      source,
    };
    try {
      updatedToolCall = await this.terminalizeToolCall(toolCall, now);
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
          source,
        },
      });
      this.telemetry('approval.cancelled', telemetryForToolCall(updatedToolCall, {
        'approval.id': approval.id,
        'approval.status': updatedApproval.status,
        status: updatedToolCall.status,
      }));
    } finally {
      await this.syncApprovalPresentationBestEffort(updatedApproval, updatedToolCall, resolution);
    }
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
    let updatedToolCall = toolCall;
    const resolution: ApprovalResolutionContext = {
      actor: 'actionproxy:approval-expiry',
      decidedAt: approval.expiredAt ?? approval.updatedAt,
      source: 'system',
    };
    try {
      updatedToolCall = await this.terminalizeToolCall(toolCall, approval.expiredAt ?? approval.updatedAt);
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
          source: 'system',
        },
      });
      this.telemetry('approval.expired', telemetryForToolCall(updatedToolCall, {
        'approval.id': approval.id,
        'approval.status': approval.status,
        status: updatedToolCall.status,
      }));
    } finally {
      await this.syncApprovalPresentationBestEffort(approval, updatedToolCall, resolution);
    }
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
    auditId?: string,
  ): Promise<void> {
    await this.audit(type, {
      actor,
      approvalId: attempt.binding.approvalId ?? undefined,
      auth,
      id: auditId,
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
    const receipt = this.prepareActionReceipt(input);
    await this.deps.store.createActionReceipt(receipt);
    await this.recordActionReceiptCreated(receipt, input);
    return receipt;
  }

  private prepareActionReceipt(input: {
    actor: string;
    approval?: ApprovalRecord;
    auth?: AuthContext;
    decisionKind: 'human_approval' | 'policy_allow';
    input: JsonObject;
    reviewHash?: string;
    toolCall: ToolCallRecord;
  }, options: { deterministicSeed?: string; issuedAt?: string } = {}): ActionReceiptRecord {
    const now = options.issuedAt ?? new Date().toISOString();
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
      id: options.deterministicSeed
        ? `receipt_${hashJson({ kind: 'prepared-external-receipt', seed: options.deterministicSeed }).slice(0, 32)}`
        : `receipt_${randomUUID()}`,
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
    return signReceipt(this.deps.receiptSigningSecret ?? 'local-dev-execution-grant-secret', unsigned);
  }

  private async recordActionReceiptCreated(
    receipt: ActionReceiptRecord,
    input: {
      actor: string;
      approval?: ApprovalRecord;
      auth?: AuthContext;
      toolCall: ToolCallRecord;
    },
    options: { auditId?: string; emitTelemetry?: boolean } = {},
  ): Promise<void> {
    await this.audit('receipt.created', {
      toolCallId: input.toolCall.id,
      approvalId: input.approval?.id,
      actor: input.actor,
      auth: input.auth,
      id: options.auditId,
      inputHash: receipt.approvedInputHash,
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
    if (options.emitTelemetry !== false) {
      this.telemetry('receipt.created', telemetryForToolCall(input.toolCall, {
        'receipt.hash': receipt.receiptHash,
        'receipt.id': receipt.id,
      }));
    }
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
      const approvalWorkspaceId =
        approval.workspaceId ?? toolCall.workspaceId ?? auth?.workspaceId ?? this.deps.workspaceId ?? 'default';
      if (approval.workspaceId && toolCall.workspaceId && approval.workspaceId !== toolCall.workspaceId) {
        throw new ConflictError('Approval notification workspace binding does not match its tool call.');
      }
      const resolved =
        resolvedRecipients ??
        (await this.resolveApprovalRecipients(
          rule ?? this.evaluatePolicy(toolCall.toolName, policyContextFromToolCall(toolCall)).rule,
          approvalWorkspaceId,
        ));
      const recipients = resolved === undefined
        ? undefined
        : approvalNotificationRecipientsFor(approval, resolved);
      if (recipients !== undefined && recipients.length === 0) {
        return [
          await this.recordApprovalDelivery(
            toolCall,
            approval,
            {
              channelId: 'approval-recipient-resolution',
              error: 'No enabled recipient remains within this approval\'s frozen authorization.',
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
      try {
        for (const delivery of deliveries) {
          records.push(await this.recordApprovalDelivery(toolCall, approval, delivery, actor, auth));
        }
      } finally {
        // A decision can win while a provider send is still in flight. Re-read only
        // after the complete delivery batch has been persisted so one bounded sync
        // repairs every newly recorded Telegram card, even with many recipients.
        await this.syncTerminalPresentationAfterDeliveryPersistence(approval, toolCall);
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

  private async syncTerminalPresentationAfterDeliveryPersistence(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
  ): Promise<void> {
    try {
      const authoritativeApproval = await this.deps.store.getApproval(approval.id);
      if (!authoritativeApproval || authoritativeApproval.status === 'pending') return;
      const authoritativeToolCall =
        await this.deps.store.getToolCall(authoritativeApproval.toolCallId) ?? toolCall;
      await this.syncApprovalPresentationBestEffort(authoritativeApproval, authoritativeToolCall);
    } catch {
      // Persisted delivery and approval state remain authoritative. A read or
      // provider projection failure must not turn notification delivery into a
      // failed submission or trigger a surprise replacement message.
    }
  }

  async syncApprovalPresentation(
    approvalId: string,
    resolution?: ApprovalResolutionContext,
    reference?: ApprovalPresentationReference,
    options: {
      auth?: AuthContext;
      repair?: boolean;
      repairUntrackedReference?: boolean;
    } = {},
  ): Promise<{ approval: ApprovalRecord; resolution: ApprovalResolutionContext; toolCall: ToolCallRecord }> {
    const approval = await this.deps.store.getApproval(approvalId);
    if (!approval) throw new NotFoundError(`Approval not found: ${approvalId}`);
    assertWorkspace(approval.workspaceId, options.auth);
    this.assertCanDecideApproval(approval, options.auth);
    const toolCall = await this.deps.store.getToolCall(approval.toolCallId);
    if (!toolCall) throw new NotFoundError(`Tool call not found: ${approval.toolCallId}`);
    assertWorkspace(toolCall.workspaceId, options.auth);
    const deliveries = await this.deps.store.listApprovalDeliveries(approval.id);
    const matchingReference = reference
      ? deliveries.find((delivery) =>
          delivery.channelId === reference.channelId &&
          delivery.destination === reference.destination &&
          delivery.messageId === reference.messageId &&
          delivery.provider === reference.provider,
        )
      : undefined;
    const fallbackDelivery = reference && !matchingReference
      ? {
          approvalId: approval.id,
          channelId: reference.channelId,
          createdAt: this.now().toISOString(),
          data: {},
          destination: reference.destination,
          id: `delivery_untracked_${hashJson({ approvalId, ...reference }).slice(0, 32)}`,
          messageId: reference.messageId,
          provider: reference.provider,
          status: 'sent' as const,
          toolCallId: toolCall.id,
          updatedAt: this.now().toISOString(),
          workspaceId: approval.workspaceId,
        }
      : undefined;
    const resolved = resolution ?? await this.resolveApprovalResolution(approval, toolCall);
    if (options.repair !== false) {
      await this.syncApprovalPresentationBestEffort(
        approval,
        toolCall,
        resolved,
        fallbackDelivery ? [...deliveries, fallbackDelivery] : deliveries,
      );
    } else if (options.repairUntrackedReference && fallbackDelivery) {
      // An expiry-observing callback may already have reconciled every stored
      // card. Still repair the clicked coordinates when Telegram supplied an
      // older/untracked card, without repeating the full provider batch.
      await this.syncApprovalPresentationBestEffort(
        approval,
        toolCall,
        resolved,
        [fallbackDelivery],
      );
    }
    return { approval, resolution: resolved, toolCall };
  }

  private async syncApprovalPresentationBestEffort(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
    resolution?: ApprovalResolutionContext,
    deliveriesOverride?: ApprovalDeliveryRecord[],
  ): Promise<void> {
    const syncPresentation = this.deps.approvalNotifier?.syncApprovalPresentation?.bind(
      this.deps.approvalNotifier,
    );
    if (approval.status === 'pending' || !syncPresentation) return;

    const work: ApprovalPresentationSyncWork = {
      approval,
      deliveriesOverride,
      includeStoredDeliveries: deliveriesOverride === undefined,
      resolution,
      syncPresentation,
      toolCall,
    };
    const active = this.approvalPresentationSyncs.get(approval.id);
    if (active) {
      if (!active.acceptingTrailing) {
        // A trailing provider pass is already running, so its immutable request
        // cannot absorb a newly supplied callback coordinate. Wait for this
        // bounded batch, then let concurrent late arrivals form a new
        // coalesced batch instead of silently dropping their repair.
        await active.promise;
        await this.syncApprovalPresentationBestEffort(
          approval,
          toolCall,
          resolution,
          deliveriesOverride,
        );
        return;
      }
      // Coalesce a burst of stale callbacks or post-send repairs into at most
      // one trailing pass. This prevents a Telegram outage from creating an
      // unbounded queue of sequential three-second waits.
      active.trailing = mergeApprovalPresentationSyncWork(active.trailing, work);
      await active.promise;
      return;
    }

    const state = {} as ApprovalPresentationSyncState;
    state.acceptingTrailing = true;
    const drain = Promise.resolve().then(async () => {
      await this.performApprovalPresentationSync(
        work.approval,
        work.toolCall,
        work.resolution,
        work.deliveriesOverride,
        work.includeStoredDeliveries,
        work.syncPresentation,
      );
      // Snapshot one coalesced trailing request. Any later calls see the same
      // active promise and merge into this work before it begins.
      const trailing = state.trailing;
      state.trailing = undefined;
      state.acceptingTrailing = false;
      if (trailing) {
        await this.performApprovalPresentationSync(
          trailing.approval,
          trailing.toolCall,
          trailing.resolution,
          trailing.deliveriesOverride,
          trailing.includeStoredDeliveries,
          trailing.syncPresentation,
        );
      }
    });
    state.promise = drain.finally(() => {
      if (this.approvalPresentationSyncs.get(approval.id) === state) {
        this.approvalPresentationSyncs.delete(approval.id);
      }
    });
    this.approvalPresentationSyncs.set(approval.id, state);
    await state.promise;
  }

  private async performApprovalPresentationSync(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
    resolution?: ApprovalResolutionContext,
    deliveriesOverride?: ApprovalDeliveryRecord[],
    includeStoredDeliveries = deliveriesOverride === undefined,
    syncPresentation?: NonNullable<ApprovalNotifier['syncApprovalPresentation']>,
  ): Promise<void> {
    try {
      if (!syncPresentation) return;
      const storedDeliveries = includeStoredDeliveries
        ? await this.deps.store.listApprovalDeliveries(approval.id)
        : [];
      const deliveries = [
        ...new Map(
          [...storedDeliveries, ...(deliveriesOverride ?? [])]
            .map((delivery) => [delivery.id, delivery]),
        ).values(),
      ];
      if (deliveries.length === 0) return;
      const resolved = resolution ?? await this.resolveApprovalResolution(approval, toolCall);
      const attemptedAt = this.now().toISOString();
      const results = await withPresentationTimeout(
        syncPresentation({
          approval,
          deliveries,
          resolution: resolved,
          toolCall,
        }),
        deliveries,
      );
      await Promise.all(results.map((result) => this.recordApprovalPresentationResult(
        approval,
        toolCall,
        deliveries,
        result,
        attemptedAt,
      )));
    } catch {
      // Presentation synchronization is a non-authoritative projection. Approval,
      // authorization, and execution outcomes must never depend on Telegram.
    }
  }

  private async resolveApprovalResolution(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
  ): Promise<ApprovalResolutionContext> {
    const fallback = approvalResolutionFor(approval);
    if (approval.status === 'approved' || approval.status === 'expired') return fallback;

    try {
      const eventType = approval.status === 'rejected'
        ? 'approval.rejected'
        : approval.status === 'cancelled'
          ? 'approval.cancelled'
          : 'approval.superseded';
      const events = await this.deps.auditStore.list('all', {
        toolCallId: toolCall.id,
        workspaceId: toolCall.workspaceId,
      });
      const event = events.find((candidate) =>
        candidate.approvalId === approval.id && candidate.type === eventType,
      );
      if (!event) return fallback;
      const source = isApprovalDecisionSource(event.data.source)
        ? event.data.source
        : approvalDecisionSource(undefined, event.auth);
      return {
        actor: event.actor ?? fallback.actor,
        auth: event.auth,
        decidedAt: fallback.decidedAt,
        reason: typeof event.data.reason === 'string' ? event.data.reason : fallback.reason,
        source,
      };
    } catch {
      return fallback;
    }
  }

  private async recordApprovalPresentationResult(
    approval: ApprovalRecord,
    toolCall: ToolCallRecord,
    deliveries: ApprovalDeliveryRecord[],
    result: ApprovalPresentationResult,
    attemptedAt: string,
  ): Promise<void> {
    const delivery = deliveries.find((candidate) => candidate.id === result.deliveryId);
    if (!delivery) return;
    const completedAt = this.now().toISOString();
    const presentation: JsonObject = result.status === 'updated'
      ? {
          attemptedAt,
          result: 'updated',
          syncedAt: completedAt,
          targetStatus: approval.status,
          version: 1,
        }
      : {
          attemptedAt,
          error: sanitizePresentationError(result.error),
          result: 'failed',
          targetStatus: approval.status,
          version: 1,
        };
    const persisted = !delivery.id.startsWith('delivery_untracked_');
    const updated: ApprovalDeliveryRecord = {
      ...delivery,
      data: {
        ...delivery.data,
        telegramPresentation: presentation,
      },
      updatedAt: completedAt,
    };
    if (persisted) await this.deps.store.updateApprovalDelivery(updated);
    await this.audit(
      result.status === 'updated'
        ? 'approval_notification.presentation_updated'
        : 'approval_notification.presentation_update_failed',
      {
        actor: 'actionproxy:approval-notification',
        approvalId: approval.id,
        data: deliveryAuditData(updated),
        inputHash: toolCall.inputHash,
        policyVersionHash: toolCall.policyVersionHash,
        policyVersionId: toolCall.policyVersionId,
        toolCallId: toolCall.id,
        workspaceId: toolCall.workspaceId,
      },
    );
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
      id?: string;
      toolCallId?: string;
      approvalId?: string;
      actor?: string;
      auth?: AuthContext;
      data: JsonObject;
      inputHash?: string;
      policyVersionHash?: string;
      policyVersionId?: string;
      timestamp?: string;
      workspaceId?: string;
    },
  ): Promise<void> {
    await this.deps.auditStore.append({
      id: payload.id ?? `audit_${randomUUID()}`,
      type,
      workspaceId: payload.workspaceId ?? payload.auth?.workspaceId ?? this.deps.workspaceId,
      toolCallId: payload.toolCallId,
      approvalId: payload.approvalId,
      actor: payload.actor,
      auth: payload.auth,
      inputHash: payload.inputHash,
      policyVersionHash: payload.policyVersionHash,
      policyVersionId: payload.policyVersionId,
      timestamp: payload.timestamp ?? new Date().toISOString(),
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

function mergeApprovalPresentationSyncWork(
  current: ApprovalPresentationSyncWork | undefined,
  incoming: ApprovalPresentationSyncWork,
): ApprovalPresentationSyncWork {
  if (!current) return incoming;
  const overrides = [...(current.deliveriesOverride ?? []), ...(incoming.deliveriesOverride ?? [])];
  const deliveriesOverride = overrides.length
    ? [
        ...new Map(
          overrides.map((delivery) => [delivery.id, delivery]),
        ).values(),
      ]
    : undefined;
  return {
    ...incoming,
    deliveriesOverride,
    includeStoredDeliveries: current.includeStoredDeliveries || incoming.includeStoredDeliveries,
    resolution: incoming.resolution ?? current.resolution,
  };
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

function approvalNotificationRecipientsFor(
  approval: ApprovalRecord,
  resolvedRecipients: ApprovalNotificationRecipient[],
): ApprovalNotificationRecipient[] {
  // Addresses and channel identifiers may be refreshed, but authorization identity
  // is frozen when the approval is published. Never disclose the payload to a
  // directory principal that was not part of that immutable authorization set.
  if (approval.approverUsers === undefined) return [];
  const authorizedPrincipalIds = new Set(approval.approverUsers);
  return resolvedRecipients.filter((recipient) => authorizedPrincipalIds.has(recipient.principalId));
}

function requiredPreparedApproval(candidate: PendingApprovalCandidate | undefined): PendingApprovalCandidate {
  if (!candidate) {
    throw new ActionContractUnavailableError('Prepared action did not produce a frozen pending approval.');
  }
  return candidate;
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
  if (input.inputDecision) {
    if (input.editedInput !== undefined) {
      const representationsConflict = input.inputDecision.mode === 'original'
        ? input.editedInput !== null
        : input.editedInput === null || hashJson(input.inputDecision.input) !== hashJson(input.editedInput);
      if (representationsConflict) {
        throw new ConflictError('Approval input decision representations conflict.');
      }
    }
    return input.inputDecision;
  }
  if (input.editedInput !== undefined && input.editedInput !== null) {
    return { input: input.editedInput, mode: 'edited' };
  }
  return { mode: 'original' };
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function metadataWithPreparedGovernance(
  metadata: JsonObject | undefined,
  prepared: PreparedActionSubmission,
): JsonObject {
  const sanitized: JsonObject = { ...(metadata ?? {}) };
  for (const key of [
    'amount',
    'approverGroup',
    'currency',
    'customerVisible',
    'operationKind',
    'recipientDomain',
    'riskKind',
  ]) {
    delete sanitized[key];
  }
  return {
    ...sanitized,
    customerVisible: prepared.governance.customerVisible,
    operationKind: prepared.governance.operationKind,
    requiredScopes: [...prepared.governance.requiredScopes],
    riskKind: prepared.governance.risk,
  };
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

function approvalDecisionSource(
  supplied: ApprovalDecisionSource | undefined,
  auth: AuthContext | undefined,
): ApprovalDecisionSource {
  if (supplied) return supplied;
  if (auth?.authProvider === 'slack') return 'slack';
  if (auth?.authProvider === 'telegram') return 'telegram';
  return 'actionproxy';
}

function isApprovalDecisionSource(value: unknown): value is ApprovalDecisionSource {
  return value === 'actionproxy' || value === 'slack' || value === 'system' || value === 'telegram';
}

function approvalResolutionFor(approval: ApprovalRecord): ApprovalResolutionContext {
  const finalDecision = [...(approval.decisions ?? [])]
    .sort((left, right) => left.decidedAt.localeCompare(right.decidedAt))
    .at(-1);
  if (approval.status === 'approved') {
    return {
      actor: approval.approvedBy ?? finalDecision?.actor,
      auth: finalDecision?.auth,
      decidedAt: approval.finalizedAt ?? finalDecision?.decidedAt ?? approval.updatedAt,
      source: finalDecision?.source ?? approvalDecisionSource(undefined, finalDecision?.auth),
    };
  }
  if (approval.status === 'rejected') {
    return {
      actor: approval.rejectedBy,
      decidedAt: approval.finalizedAt ?? approval.updatedAt,
      reason: approval.rejectionReason,
      source: 'actionproxy',
    };
  }
  if (approval.status === 'cancelled') {
    return {
      actor: approval.cancelledBy,
      decidedAt: approval.cancelledAt ?? approval.finalizedAt ?? approval.updatedAt,
      reason: approval.cancellationReason,
      source: 'actionproxy',
    };
  }
  if (approval.status === 'expired') {
    return {
      actor: 'actionproxy:approval-expiry',
      decidedAt: approval.expiredAt ?? approval.finalizedAt ?? approval.updatedAt,
      source: 'system',
    };
  }
  return {
    decidedAt: approval.supersededAt ?? approval.finalizedAt ?? approval.updatedAt,
    source: 'actionproxy',
  };
}

async function withPresentationTimeout(
  operation: Promise<ApprovalPresentationResult[]>,
  deliveries: ApprovalDeliveryRecord[],
): Promise<ApprovalPresentationResult[]> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<ApprovalPresentationResult[]>((resolve) => {
    timeout = setTimeout(() => resolve(deliveries
      .filter((delivery) => delivery.provider === 'telegram' && delivery.status === 'sent')
      .map((delivery) => ({
      deliveryId: delivery.id,
      error: 'Approval notification presentation update timed out.',
      status: 'failed' as const,
      }))), 3_100);
  });
  try {
    return await Promise.race([operation, timedOut]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function sanitizePresentationError(error: string | undefined): string {
  const normalized = (error ?? 'Unknown presentation update error.')
    .replace(/\b(?:bot)?\d{5,}:[A-Za-z0-9_-]{10,}\b/gu, 'bot[redacted]')
    .replace(/[\r\n\t]+/gu, ' ')
    .trim();
  return normalized.slice(0, 500) || 'Unknown presentation update error.';
}

function assertWorkspace(workspaceId: string | undefined, auth: AuthContext | undefined): void {
  if (!auth || auth.authProvider === 'none') return;
  if ((workspaceId ?? 'default') !== auth.workspaceId) {
    throw new ForbiddenError('Requested object is not in this workspace.');
  }
}
