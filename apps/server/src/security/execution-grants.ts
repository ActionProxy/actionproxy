import { randomUUID } from 'node:crypto';
import type { ExecutionGrantsConfig } from '../config';
import { ConflictError, ForbiddenError, NotFoundError } from '../errors';
import type {
  ActionReceiptRecord,
  AuthContext,
  ExecutionGrantRecord,
  JsonObject,
  RemediationDescriptor,
  ResultDeliveryMetadataV1,
  ToolCallRecord,
} from '../models';
import type { AuditStore } from '../storage/audit-store';
import type {
  AtomicGrantDispatchInput,
  AtomicGrantDispatchResult,
  Store,
} from '../storage/store';
import { hmacSha256Hex, randomToken, stableStringify, hashJson, safeEqual } from './crypto';
import { verifyReceipt } from './action-receipts';
import type { TelemetryAttributes, TelemetryRecorder } from '../telemetry/telemetry';
import {
  executionAttemptOutcome,
  type ExecutionAttemptRecordV1,
  type ExecutionAttemptTerminalState,
} from '../contracts/execution-attempt';
import {
  approvalAuthorizationExpired,
  approvalAuthorizationMismatch,
  isValidApprovalAuthorization,
} from '../contracts/approval-authorization';
import {
  buildExecutionAuthorizationBinding,
  DEFAULT_EXECUTION_AUTHORIZATION_TTL_MS,
  ExecutionAuthorizationError,
  type ExecutionAuthorizationAuthority,
  type ExecutionAuthorizationProjectionV1,
} from '../contracts/execution-authorization';
import { canonicalJsonStringify, hashCanonicalJson } from '../contracts/action-request';
import { deriveInfluenceScopeId } from './influence-scope';
import {
  validContentInfluenceBindingHash,
  validatedContentExposureRevisionGuard,
} from '../contracts/content-influence';
import {
  NativeExecutionAuthorizationError,
  type NativeExecutionAuthorization,
  type NativeExecutionAuthorizationVerifier,
} from '../contracts/native-execution-authorization';

export interface ConsumeExecutionGrantInput {
  input: JsonObject;
  policyVersionHash?: string;
  toolCallId: string;
  toolName: string;
}

export interface ReportExecutionGrantOutcomeInput {
  error?: string;
  remediation?: RemediationDescriptor;
  result?: JsonObject;
  resultDelivery?: ResultDeliveryMetadataV1;
  status: 'cancelled' | 'failed' | 'succeeded' | 'timed_out' | 'unknown_outcome';
}

export interface PrepareExecutionGrantInput {
  actor: string;
  auth?: AuthContext;
  /** Server-owned stable seed used only by replayable publication paths. */
  deterministicSeed?: string;
  issuedAt?: string;
  receipt?: ActionReceiptRecord;
  toolCall: ToolCallRecord;
  ttlSeconds?: number;
}

export interface GrantDispatchRequest {
  atomicInput: AtomicGrantDispatchInput;
  attempt: ExecutionAttemptRecordV1;
  grant: ExecutionGrantRecord;
  toolCall: ToolCallRecord;
}

/**
 * Connector-neutral seam for extending the final durable dispatch transition.
 * Community uses the generic store transaction; private editions may install
 * one coordinator before serving requests.
 */
export interface GrantDispatchCoordinator {
  dispatch(request: Readonly<GrantDispatchRequest>): Promise<AtomicGrantDispatchResult>;
}

export class ExecutionGrantService {
  private grantDispatchCoordinator?: GrantDispatchCoordinator;
  private preparedNativeWriteRequired?: (toolName: string) => boolean;

  constructor(
    private readonly config: ExecutionGrantsConfig,
    private readonly store: Store,
    private readonly auditStore: AuditStore,
    private readonly telemetry: TelemetryRecorder | undefined,
    private readonly currentPolicyVersionHash: () => string | undefined,
    private readonly executionAuthorizations: ExecutionAuthorizationAuthority,
    private readonly beforeDispatch?: (
      toolCall: ToolCallRecord,
      input: JsonObject,
      auth: AuthContext,
    ) => Promise<void> | void,
    private readonly nativeExecutionAuthorizations?: NativeExecutionAuthorizationVerifier,
  ) {}

  installPreparedNativeWriteRequirement(classifier: (toolName: string) => boolean): void {
    if (this.preparedNativeWriteRequired && this.preparedNativeWriteRequired !== classifier) {
      throw new Error('Prepared native-write grant requirement is already installed.');
    }
    this.preparedNativeWriteRequired = classifier;
  }

  installGrantDispatchCoordinator(coordinator: GrantDispatchCoordinator): void {
    if (this.grantDispatchCoordinator) {
      throw new Error('Grant dispatch coordinator is already installed.');
    }
    this.grantDispatchCoordinator = coordinator;
  }

  async createGrant(input: {
    actor: string;
    auth?: AuthContext;
    receipt?: ActionReceiptRecord;
    toolCall: ToolCallRecord;
    ttlSeconds?: number;
  }): Promise<ExecutionGrantRecord> {
    const signed = this.prepareGrant(input);
    await this.store.createExecutionGrant(signed);
    const attempt = await this.store.getExecutionAttemptByToolCallId(signed.workspaceId, signed.toolCallId);
    if (!attempt || attempt.state !== 'reserved' || !attemptMatchesGrant(attempt, signed, { requireGrantBinding: false })) {
      throw new ConflictError('Execution grant is not bound to a current reserved execution attempt.');
    }
    const binding = await this.store.bindExecutionAttemptGrantAtomically({
      attemptId: attempt.id,
      grantId: signed.id,
      reservationOwner: attempt.reservationOwner,
      updatedAt: signed.createdAt,
      workspaceId: signed.workspaceId,
    });
    if (
      binding.outcome !== 'bound' &&
      !(binding.outcome === 'already_bound' && binding.attempt?.grantId === signed.id)
    ) {
      throw new ConflictError('Execution grant could not bind its reserved execution attempt.');
    }
    await this.recordPreparedGrantCreated(signed, input);
    return signed;
  }

  /** Builds and signs a grant without persisting it, for one atomic lifecycle publication. */
  prepareGrant(input: PrepareExecutionGrantInput): ExecutionGrantRecord {
    const now = new Date(input.issuedAt ?? Date.now());
    if (!Number.isFinite(now.getTime())) throw new Error('Execution grant issuedAt must be a valid timestamp.');
    const expiresAt = new Date(now.getTime() + (input.ttlSeconds ?? this.config.ttlSeconds) * 1000).toISOString();
    const deterministic = input.deterministicSeed
      ? hmacSha256Hex(this.config.secret, `prepared-execution-grant:${input.deterministicSeed}`)
      : undefined;
    const grant: ExecutionGrantRecord = {
      actor: input.actor,
      approvedEnvelopeHash: input.receipt?.approvedEnvelopeHash,
      approvedInputHash: input.receipt?.approvedInputHash,
      auth: input.auth,
      createdAt: now.toISOString(),
      expiresAt,
      id: deterministic ? `grant_${deterministic.slice(0, 32)}` : `grant_${randomUUID()}`,
      inputHash: input.toolCall.inputHash ?? hashJson(input.toolCall.input),
      nonce: deterministic ? deterministic.slice(32) : randomToken(18),
      policyVersionHash: input.toolCall.policyVersionHash,
      receiptHash: input.receipt?.receiptHash,
      receiptId: input.receipt?.id,
      signature: '',
      toolCallId: input.toolCall.id,
      toolName: input.toolCall.toolName,
      workspaceId: input.toolCall.workspaceId ?? input.auth?.workspaceId ?? 'default',
    };
    return { ...grant, signature: signGrant(this.config.secret, grant) };
  }

  /** Emits the post-commit audit/telemetry for a grant published by a store transaction. */
  async recordPreparedGrantCreated(
    signed: ExecutionGrantRecord,
    input: Pick<PrepareExecutionGrantInput, 'actor' | 'auth'> & {
      auditId?: string;
      emitTelemetry?: boolean;
    },
  ): Promise<void> {
    await this.auditStore.append({
      actor: input.actor,
      auth: input.auth,
      data: {
        expiresAt: signed.expiresAt,
        grantId: signed.id,
        receiptHash: signed.receiptHash ?? null,
        receiptId: signed.receiptId ?? null,
        inputHash: signed.inputHash,
        toolName: signed.toolName,
      },
      id: input.auditId ?? `audit_${randomUUID()}`,
      inputHash: signed.inputHash,
      policyVersionHash: signed.policyVersionHash,
      timestamp: signed.createdAt,
      toolCallId: signed.toolCallId,
      type: 'execution_grant.created',
      workspaceId: signed.workspaceId,
    });
    if (input.emitTelemetry !== false) {
      this.recordTelemetry('execution_grant.created', telemetryForGrant(signed, { 'grant.status': 'created' }));
    }
  }

  async consumeGrant(
    grantId: string,
    input: ConsumeExecutionGrantInput,
    auth: AuthContext,
    continuation: {
      nativeExecutionAuthorization?: NativeExecutionAuthorization;
      wrapperSessionId?: string;
    } = {},
  ): Promise<ExecutionGrantRecord> {
    let dispatchedAttempt: ExecutionAttemptRecordV1 | undefined;
    let consumedGrant: ExecutionGrantRecord | undefined;
    let consumedAuthorization: ExecutionAuthorizationProjectionV1 | undefined;
    let inputHash: string | undefined;
    try {
      const grant = await this.store.getExecutionGrant(grantId);
      if (!grant) throw new NotFoundError(`Execution grant not found: ${grantId}`);
      if (grant.workspaceId !== auth.workspaceId) throw new ForbiddenError('Execution grant is not in this workspace.');
      if (grant.consumedAt) throw new ConflictError('Execution grant has already been consumed.');
      if (Date.parse(grant.expiresAt) <= Date.now()) throw new ConflictError('Execution grant has expired.');
      if (grant.toolCallId !== input.toolCallId || grant.toolName !== input.toolName) {
        throw new ForbiddenError('Execution grant does not match the requested tool call.');
      }
      const activePolicyVersionHash = this.currentPolicyVersionHash?.();
      if (grant.policyVersionHash && !activePolicyVersionHash) {
        throw new ForbiddenError('Execution grant cannot be dispatched because the active policy identity is unavailable.');
      }
      if (
        grant.policyVersionHash &&
        activePolicyVersionHash &&
        grant.policyVersionHash !== activePolicyVersionHash
      ) {
        throw new ForbiddenError('Execution grant policy version is no longer active.');
      }
      if (grant.policyVersionHash && input.policyVersionHash && grant.policyVersionHash !== input.policyVersionHash) {
        throw new ForbiddenError('Execution grant policy version does not match.');
      }
      inputHash = hashJson(input.input);
      if (grant.inputHash !== inputHash) throw new ForbiddenError('Execution grant input hash does not match.');
      if (!safeEqual(grant.signature, signGrant(this.config.secret, grant))) {
        throw new ForbiddenError('Execution grant signature is invalid.');
      }
      let receipt: ActionReceiptRecord | undefined;
      if (grant.receiptId) {
        receipt = await this.store.getActionReceipt(grant.receiptId);
        if (!receipt) throw new ForbiddenError('Execution grant receipt was not found.');
        if (!verifyReceipt(this.config.secret, receipt)) throw new ForbiddenError('Execution grant receipt signature is invalid.');
        if (grant.receiptHash && grant.receiptHash !== receipt.receiptHash) {
          throw new ForbiddenError('Execution grant receipt hash does not match.');
        }
        if (grant.approvedInputHash && grant.approvedInputHash !== receipt.approvedInputHash) {
          throw new ForbiddenError('Execution grant approved input hash does not match.');
        }
        if (grant.approvedEnvelopeHash && grant.approvedEnvelopeHash !== receipt.approvedEnvelopeHash) {
          throw new ForbiddenError('Execution grant approved envelope hash does not match.');
        }
      }

      const attempt = await this.store.getExecutionAttemptByToolCallId(grant.workspaceId, grant.toolCallId);
      if (!attempt || attempt.state !== 'reserved' || !attemptMatchesGrant(attempt, grant, { requireGrantBinding: true })) {
        throw new ConflictError('Execution grant is not bound to a current reserved execution attempt.');
      }
      const toolCall = await this.store.getToolCall(grant.toolCallId);
      if (!toolCall) throw new ForbiddenError('Execution grant tool call was not found.');
      if (this.preparedNativeWriteRequired?.(toolCall.toolName) && !toolCall.actionEnvelope?.preparedAction) {
        throw new ForbiddenError(
          'Legacy native-write grants cannot execute in prepared-action mode. Reject and resubmit the action.',
        );
      }
      if (toolCall.actionEnvelope?.preparedAction && !this.grantDispatchCoordinator) {
        throw new ForbiddenError(
          'Prepared action dispatch is unavailable because its server dispatch coordinator is not installed.',
        );
      }
      if (continuation.nativeExecutionAuthorization) {
        const intentHash = toolCall.actionEnvelope?.preparedAction?.intentHash;
        if (!intentHash || !this.nativeExecutionAuthorizations) {
          throw new ForbiddenError('Native execution authorization is unavailable for this action.');
        }
        try {
          this.nativeExecutionAuthorizations.consume(
            continuation.nativeExecutionAuthorization,
            {
              attemptId: attempt.id,
              grantId: grant.id,
              intentHash,
              phase: 'dispatch',
              toolCallId: toolCall.id,
              version: 'actionproxy.native-execution-binding.v1',
              workspaceId: grant.workspaceId,
            },
          );
        } catch (error) {
          if (error instanceof NativeExecutionAuthorizationError) {
            throw new ForbiddenError(`Native execution authorization was rejected: ${error.code}.`);
          }
          throw error;
        }
      } else {
        if (toolCall.actionEnvelope?.preparedAction) {
          throw new ForbiddenError(
            'Prepared native actions require server-owned native execution authorization.',
          );
        }
        assertMcpAdapterAuthorization(toolCall, auth, continuation.wrapperSessionId);
      }
      const toolCallMismatch = currentToolCallMismatch(toolCall, attempt, grant);
      if (toolCallMismatch) {
        throw new ForbiddenError(`Execution grant tool-call authorization is no longer current: ${toolCallMismatch}.`);
      }
      const receiptMismatch = currentReceiptMismatch(receipt, toolCall, attempt, grant);
      if (receiptMismatch) {
        throw new ForbiddenError(`Execution grant receipt authorization is no longer current: ${receiptMismatch}.`);
      }
      const approval = attempt.binding.approvalId
        ? await this.store.getApproval(attempt.binding.approvalId)
        : undefined;
      if (attempt.binding.approvalId) {
        const approvalMismatch = currentApprovalMismatch(approval, toolCall, attempt, grant);
        if (approvalMismatch) {
          throw new ForbiddenError(`Execution grant approval authorization is no longer current: ${approvalMismatch}.`);
        }
      }
      if (!this.executionAuthorizations) {
        throw new ForbiddenError('Execution grant cannot be dispatched because execution authorization is unavailable.');
      }
      await this.beforeDispatch?.(toolCall, input.input, auth);
      const grantTtlMs = Date.parse(grant.expiresAt) - Date.now();
      if (grantTtlMs <= 0) throw new ConflictError('Execution grant has expired.');
      try {
        const authorizationBinding = buildExecutionAuthorizationBinding({ approval, attempt, toolCall });
        const authorization = this.executionAuthorizations.issue({
          binding: authorizationBinding,
          ttlMs: Math.min(DEFAULT_EXECUTION_AUTHORIZATION_TTL_MS, grantTtlMs),
        });
        // There is deliberately no await or caller-controlled code between
        // issuing, consuming, and entering the durable dispatch transition.
        consumedAuthorization = this.executionAuthorizations.consume(authorization, authorizationBinding);
      } catch (error) {
        if (error instanceof ExecutionAuthorizationError) {
          throw new ForbiddenError(`Execution grant authorization was rejected: ${error.code}.`);
        }
        throw error;
      }
      const atomicInput: AtomicGrantDispatchInput = {
        attemptId: attempt.id,
        dispatchedAt: new Date().toISOString(),
        grantId: grant.id,
        reservationOwner: attempt.reservationOwner,
        toolCallId: grant.toolCallId,
        workspaceId: grant.workspaceId,
        contentExposureRevision: contentExposureRevisionGuard(toolCall),
      };
      const dispatch = this.grantDispatchCoordinator
        ? await this.grantDispatchCoordinator.dispatch({ atomicInput, attempt, grant, toolCall })
        : await this.store.consumeExecutionGrantAndDispatchAttemptAtomically(atomicInput);
      if (dispatch.outcome === 'grant_not_found') throw new NotFoundError(`Execution grant not found: ${grantId}`);
      if (dispatch.outcome === 'grant_already_consumed') {
        throw new ConflictError('Execution grant has already been consumed.');
      }
      if (dispatch.outcome === 'content_influence_mismatch') {
        await this.appendAuditBestEffort({
          actor: 'actionproxy:content-influence',
          auth,
          data: {
            expectedExposureRevision: toolCall.contentInfluence?.exposureRevision ?? null,
            influenceScopeId: toolCall.contentInfluence?.influenceScope.id ?? null,
            reason: 'atomic_dispatch_revision_mismatch',
            storedBindingHash: toolCall.contentInfluence?.bindingHash ?? null,
          },
          id: `audit_${randomUUID()}`,
          inputHash,
          policyVersionHash: grant.policyVersionHash,
          timestamp: new Date().toISOString(),
          toolCallId: grant.toolCallId,
          type: 'content.influence_binding_stale',
          workspaceId: grant.workspaceId,
        });
        throw new ForbiddenError('Content-influence evidence changed at the dispatch boundary.');
      }
      if (dispatch.outcome !== 'dispatched' || !dispatch.grant || !dispatch.attempt) {
        throw new ConflictError('Execution grant could not reserve a current execution attempt.');
      }
      consumedGrant = dispatch.grant;
      dispatchedAttempt = dispatch.attempt;
    } catch (error) {
      await this.appendAuditBestEffort({
        actor: auth.email ?? auth.principalId,
        auth,
        data: {
          error: error instanceof Error ? error.message : String(error),
          grantId,
          toolName: input.toolName,
        },
        id: `audit_${randomUUID()}`,
        inputHash: inputHash ?? hashJson(input.input),
        policyVersionHash: input.policyVersionHash,
        timestamp: new Date().toISOString(),
        toolCallId: input.toolCallId,
        type: 'execution_grant.rejected',
        workspaceId: auth.workspaceId,
      });
      this.recordTelemetry('execution_grant.rejected', {
        'grant.id': grantId,
        'grant.status': 'rejected',
        'policy.version.hash': input.policyVersionHash,
        'tool.name': input.toolName,
        'tool_call.id': input.toolCallId,
        'workspace.id': auth.workspaceId,
      });
      throw error;
    }

    // The grant and attempt are already durably transitioned. Evidence export
    // failure must not turn that winning dispatch into a rejected/retryable one.
    await this.appendAuditBestEffort({
      actor: auth.principalId,
      auth,
      data: { grantId, inputHash, toolName: consumedGrant.toolName },
      id: `audit_${randomUUID()}`,
      inputHash,
      policyVersionHash: consumedGrant.policyVersionHash,
      timestamp: dispatchedAttempt.dispatchedAt ?? dispatchedAttempt.updatedAt,
      toolCallId: consumedGrant.toolCallId,
      type: 'execution_grant.consumed',
      workspaceId: consumedGrant.workspaceId,
    });
    await this.appendAuditBestEffort({
      actor: auth.principalId,
      auth,
      data: {
        attemptId: dispatchedAttempt.id,
        attemptNumber: dispatchedAttempt.attemptNumber,
        executionAuthorization: {
          authorizationId: consumedAuthorization.authorizationId,
          capabilities: consumedAuthorization.capabilities,
          executorId: consumedAuthorization.binding.executor.id,
          expiresAt: consumedAuthorization.expiresAt,
          issuedAt: consumedAuthorization.issuedAt,
          version: consumedAuthorization.version,
        },
        executorId: dispatchedAttempt.executorId,
        grantId,
        state: dispatchedAttempt.state,
      },
      id: `audit_${randomUUID()}`,
      inputHash: dispatchedAttempt.inputHash,
      policyVersionHash: dispatchedAttempt.binding.policyVersionHash ?? undefined,
      timestamp: dispatchedAttempt.dispatchedAt ?? dispatchedAttempt.updatedAt,
      toolCallId: dispatchedAttempt.toolCallId,
      type: 'execution.attempt_dispatched',
      workspaceId: dispatchedAttempt.workspaceId,
    });
    this.recordTelemetry('execution_grant.consumed', telemetryForGrant(consumedGrant, { 'grant.status': 'consumed' }));
    return consumedGrant;
  }

  async reportOutcome(
    grantId: string,
    input: ReportExecutionGrantOutcomeInput,
    auth: AuthContext,
    continuation: {
      nativeExecutionAuthorization?: NativeExecutionAuthorization;
      wrapperSessionId?: string;
    } = {},
  ): Promise<{
    attempt: ExecutionAttemptRecordV1;
    grant: ExecutionGrantRecord;
    receipt?: ActionReceiptRecord;
    toolCall: ToolCallRecord;
  }> {
    const grant = await this.store.getExecutionGrant(grantId);
    if (!grant) throw new NotFoundError(`Execution grant not found: ${grantId}`);
    if (grant.workspaceId !== auth.workspaceId) throw new ForbiddenError('Execution grant is not in this workspace.');
    if (!grant.consumedAt) throw new ConflictError('Execution grant has not been consumed.');
    if (!safeEqual(grant.signature, signGrant(this.config.secret, grant))) {
      throw new ForbiddenError('Execution grant signature is invalid.');
    }

    const toolCall = await this.store.getToolCall(grant.toolCallId);
    if (!toolCall) throw new NotFoundError(`Tool call not found: ${grant.toolCallId}`);
    if ((toolCall.workspaceId ?? 'default') !== auth.workspaceId) throw new ForbiddenError('Tool call is not in this workspace.');
    if (this.preparedNativeWriteRequired?.(toolCall.toolName) && !toolCall.actionEnvelope?.preparedAction) {
      throw new ForbiddenError(
        'Legacy native-write grants cannot record an outcome in prepared-action mode. Reject and resubmit the action.',
      );
    }
    const attempt = await this.store.getExecutionAttemptByToolCallId(grant.workspaceId, grant.toolCallId);
    if (!attempt || !attemptMatchesGrant(attempt, grant, { requireGrantBinding: true })) {
      throw new ConflictError('Execution grant is not bound to its execution attempt.');
    }
    if (continuation.nativeExecutionAuthorization) {
      const intentHash = toolCall.actionEnvelope?.preparedAction?.intentHash;
      if (!intentHash || !this.nativeExecutionAuthorizations) {
        throw new ForbiddenError('Native execution outcome authorization is unavailable for this action.');
      }
      try {
        this.nativeExecutionAuthorizations.consume(
          continuation.nativeExecutionAuthorization,
          {
            attemptId: attempt.id,
            grantId: grant.id,
            intentHash,
            phase: 'outcome',
            toolCallId: toolCall.id,
            version: 'actionproxy.native-execution-binding.v1',
            workspaceId: grant.workspaceId,
          },
        );
      } catch (error) {
        if (error instanceof NativeExecutionAuthorizationError) {
          throw new ForbiddenError(`Native execution outcome authorization was rejected: ${error.code}.`);
        }
        throw error;
      }
    } else {
      if (toolCall.actionEnvelope?.preparedAction) {
        throw new ForbiddenError(
          'Prepared native action outcomes require server-owned native execution authorization.',
        );
      }
      assertMcpAdapterAuthorization(toolCall, auth, continuation.wrapperSessionId);
    }
    const toolCallMismatch = currentToolCallMismatch(toolCall, attempt, grant, {
      allowAuthorizedTerminalRecovery: attempt.state !== 'dispatched',
    });
    if (toolCallMismatch) {
      throw new ForbiddenError(`Execution grant tool-call authorization is no longer current: ${toolCallMismatch}.`);
    }
    const classifiedMcpOutcome = !continuation.nativeExecutionAuthorization && requiresMcpResultDelivery(toolCall);
    if (
      classifiedMcpOutcome &&
      (input.status === 'cancelled' || input.status === 'timed_out' || input.status === 'unknown_outcome')
    ) {
      if (input.result !== undefined || input.resultDelivery !== undefined) {
        throw new ForbiddenError('MCP transport outcomes cannot include model-visible child content.');
      }
      input = { ...input, error: staticMcpTransportOutcomeError(input.status) };
    }
    if (classifiedMcpOutcome && input.status === 'failed' && input.result === undefined) {
      throw new ForbiddenError('A classified MCP error result requires the exact child result and delivery evidence.');
    }
    const resultDelivery = validateResultDelivery(input);
    const mcpOutcomeHasModelVisibleResult = input.status === 'succeeded' || input.result !== undefined;
    if (
      classifiedMcpOutcome &&
      mcpOutcomeHasModelVisibleResult &&
      (!resultDelivery || resultDelivery.modelVisible !== true)
    ) {
      throw new ForbiddenError('Classified MCP outcomes require model-visible bounded result-delivery evidence.');
    }

    const existingReceipt = grant.receiptId ? await this.store.getActionReceipt(grant.receiptId) : undefined;
    if (grant.receiptId && !existingReceipt) throw new ForbiddenError('Execution grant receipt was not found.');
    if (existingReceipt) {
      if (!verifyReceipt(this.config.secret, existingReceipt)) throw new ForbiddenError('Execution grant receipt signature is invalid.');
      if (grant.receiptHash && grant.receiptHash !== existingReceipt.receiptHash) {
        throw new ForbiddenError('Execution grant receipt hash does not match.');
      }
      if (grant.approvedInputHash && grant.approvedInputHash !== existingReceipt.approvedInputHash) {
        throw new ForbiddenError('Execution grant approved input hash does not match.');
      }
      if (grant.approvedEnvelopeHash && grant.approvedEnvelopeHash !== existingReceipt.approvedEnvelopeHash) {
        throw new ForbiddenError('Execution grant approved envelope hash does not match.');
      }
    }
    const terminalState = attemptStateForReport(input.status);
    const legacyOutcome = legacyOutcomeForReport(input);
    if (
      existingReceipt?.outcome &&
      (!sameLegacyOutcome(existingReceipt.outcome, legacyOutcome) ||
        stableStringify(existingReceipt.outcome.resultDelivery ?? null) !== stableStringify(resultDelivery ?? null))
    ) {
      throw new ConflictError('Execution outcome has already been recorded.');
    }

    const now = attempt.outcome?.recordedAt ?? new Date().toISOString();
    const normalizedOutcome = executionAttemptOutcome(terminalState, {
      errorClass: legacyOutcome.errorClass,
      errorCode: legacyOutcome.errorCode,
      errorMessage: legacyOutcome.error,
      remediation: input.status === 'succeeded' ? input.remediation : undefined,
      recordedAt: now,
      result: input.status === 'succeeded' ? input.result ?? { ok: true } : input.result,
      resultDelivery,
    });
    const candidateReceiptOutcome: NonNullable<ActionReceiptRecord['outcome']> = {
      auth,
      error: legacyOutcome.status === 'failed' ? legacyOutcome.error : undefined,
      recordedAt: now,
      recordedBy: auth.email ?? auth.principalId,
      remediation: input.status === 'succeeded' ? input.remediation : undefined,
      result: input.status === 'succeeded' ? input.result ?? { ok: true } : undefined,
      resultDelivery,
      status: legacyOutcome.status,
    };
    const exposureRequired = requiresContentExposureBeforeDelivery(toolCall, resultDelivery);
    const terminalToolCall: ToolCallRecord = {
      ...toolCall,
      error: legacyOutcome.status === 'failed' ? legacyOutcome.error : undefined,
      resultDelivery,
      resultWithheld: exposureRequired,
      result:
        input.status === 'succeeded'
          ? {
              ...(isJsonObject(toolCall.result) ? toolCall.result : {}),
              externalExecutionOutcome: input.result ?? { ok: true },
            }
          : toolCall.result,
      status: input.status === 'succeeded' ? 'executed' : 'failed',
      updatedAt: now,
    };
    let completedAttempt: ExecutionAttemptRecordV1;
    let updatedReceipt: ActionReceiptRecord | undefined;
    let deliveredToolCall: ToolCallRecord;
    const recordPreparedKnownOutcome = Boolean(
      toolCall.actionEnvelope?.preparedAction &&
      (terminalState === 'succeeded' || terminalState === 'failed_after_dispatch'),
    );
    if (recordPreparedKnownOutcome) {
      if (!existingReceipt) {
        throw new ForbiddenError('Prepared native action receipt is unavailable.');
      }
      const recording = attempt.state === 'dispatched'
        ? await this.store.recordKnownExternalExecutionOutcomeAtomically({
            attemptId: attempt.id,
            attemptOutcome: normalizedOutcome,
            receiptOutcome: candidateReceiptOutcome,
            reservationOwner: attempt.reservationOwner,
            toolCall: terminalToolCall,
            workspaceId: attempt.workspaceId,
          })
        : await this.store.adoptKnownExternalExecutionOutcomeAtomically({
            attemptId: attempt.id,
            receipt: { ...existingReceipt, outcome: candidateReceiptOutcome },
            toolCall: terminalToolCall,
            workspaceId: attempt.workspaceId,
          });
      if (recording.outcome === 'not_found') throw new NotFoundError(`Execution attempt not found: ${attempt.id}`);
      if (recording.outcome === 'owner_mismatch') {
        throw new ForbiddenError('Execution attempt reservation owner does not match.');
      }
      if (recording.outcome === 'binding_mismatch') {
        throw new ForbiddenError('Prepared native outcome no longer matches its signed execution binding.');
      }
      if (recording.outcome === 'reconciliation_required') {
        throw new ConflictError('Execution outcome requires reconciliation and will not be retried automatically.');
      }
      if (recording.outcome === 'state_mismatch') {
        throw new ConflictError('Execution attempt has not been dispatched.');
      }
      if (recording.outcome === 'conflict') {
        throw new ConflictError('Execution outcome has already been recorded.');
      }
      if (!recording.attempt || !recording.receipt || !recording.toolCall) {
        throw new ConflictError('Prepared native outcome could not be recorded atomically.');
      }
      completedAttempt = recording.attempt;
      updatedReceipt = recording.receipt;
      deliveredToolCall = recording.toolCall;
    } else {
      const transition = await this.store.transitionExecutionAttemptAtomically({
        attemptId: attempt.id,
        expectedState: 'dispatched',
        nextState: terminalState,
        outcome: normalizedOutcome,
        reservationOwner: attempt.reservationOwner,
        transitionedAt: now,
        workspaceId: attempt.workspaceId,
      });
      if (transition.outcome === 'not_found') throw new NotFoundError(`Execution attempt not found: ${attempt.id}`);
      if (transition.outcome === 'owner_mismatch') {
        throw new ForbiddenError('Execution attempt reservation owner does not match.');
      }
      if (transition.outcome === 'state_mismatch') {
        throw new ConflictError('Execution attempt has not been dispatched.');
      }
      let replay = transition.outcome === 'replay';
      let transitionedAttempt = transition.attempt;
      if (transition.outcome === 'already_terminal') {
        const current = await this.store.getExecutionAttempt(attempt.id);
        if (!current || !sameAttemptOutcome(current, normalizedOutcome)) {
          throw new ConflictError('Execution outcome has already been recorded.');
        }
        transitionedAttempt = current;
        replay = true;
      }
      if (
        (transition.outcome !== 'transitioned' && transition.outcome !== 'replay' && transition.outcome !== 'already_terminal') ||
        !transitionedAttempt
      ) {
        throw new ConflictError('Execution outcome could not be recorded.');
      }
      completedAttempt = transitionedAttempt;
      const receiptOutcomeWrite = existingReceipt
        ? await this.store.recordActionReceiptOutcomeAtomically({
            outcome: candidateReceiptOutcome,
            receiptId: existingReceipt.id,
          })
        : undefined;
      if (receiptOutcomeWrite?.outcome === 'not_found') {
        throw new ForbiddenError('Execution grant receipt disappeared while recording its outcome.');
      }
      updatedReceipt = receiptOutcomeWrite?.receipt;
      if (
        updatedReceipt?.outcome &&
        (!sameLegacyOutcome(updatedReceipt.outcome, legacyOutcome) ||
          stableStringify(updatedReceipt.outcome.resultDelivery ?? null) !== stableStringify(resultDelivery ?? null))
      ) {
        throw new ConflictError('Execution outcome has already been recorded.');
      }
      const terminalToolCallAlreadyPersisted = replay && toolCall.status !== 'authorized';
      deliveredToolCall = terminalToolCallAlreadyPersisted ? toolCall : terminalToolCall;
      if (!terminalToolCallAlreadyPersisted) await this.store.updateToolCall(terminalToolCall);
    }
    if (exposureRequired && deliveredToolCall.resultWithheld !== false) {
      let withheldReason = 'content_exposure_persistence_failed';
      try {
        await this.recordContentExposureBeforeDelivery(deliveredToolCall, resultDelivery, auth);
        withheldReason = 'result_release_state_persistence_failed';
        deliveredToolCall = { ...deliveredToolCall, resultWithheld: false, updatedAt: new Date().toISOString() };
        await this.store.updateToolCall(deliveredToolCall);
      } catch {
        await this.appendAuditBestEffort({
          actor: 'actionproxy:content-influence',
          auth,
          data: {
            influenceScopeId: deliveredToolCall.influenceScopeId ?? null,
            reason: withheldReason,
            sourceToolCallId: deliveredToolCall.id,
          },
          id: `audit_${randomUUID()}`,
          inputHash: grant.inputHash,
          policyVersionHash: grant.policyVersionHash,
          timestamp: new Date().toISOString(),
          toolCallId: grant.toolCallId,
          type: 'content.result_withheld',
          workspaceId: grant.workspaceId,
        });
        throw new ConflictError(
          'The downstream outcome is known, but ActionProxy withheld the result because content-exposure evidence could not be recorded.',
        );
      }
    }
    // A terminal attempt is authoritative even if the previous process stopped
    // after recording the provider receipt but before projecting the tool call
    // or exporting every audit event. Exact outcome replays therefore always
    // reconcile missing terminal evidence. Deterministic event ids and the
    // AuditStore append-once contract make this bounded and safe when identical
    // reporters race, without scanning an audit log whose size is unbounded.
    const outcomeActor = updatedReceipt?.outcome?.recordedBy ?? auth.email ?? auth.principalId;
    const outcomeAuth = updatedReceipt?.outcome?.auth ?? auth;
    await this.appendAuditBestEffort({
      actor: outcomeActor,
      auth: outcomeAuth,
      data: {
        error: legacyOutcome.status === 'failed' ? legacyOutcome.error : null,
        grantId,
        receiptHash: updatedReceipt?.receiptHash ?? grant.receiptHash ?? null,
        receiptId: updatedReceipt?.id ?? grant.receiptId ?? null,
        remediation: input.status === 'succeeded' ? input.remediation ?? null : null,
        result: input.status === 'succeeded' ? input.result ?? { ok: true } : null,
        resultDelivery: resultDelivery ?? null,
        status: legacyOutcome.status,
      },
      id: terminalAuditId(completedAttempt.id, 'receipt.outcome_recorded'),
      inputHash: grant.inputHash,
      policyVersionHash: grant.policyVersionHash,
      timestamp: now,
      toolCallId: grant.toolCallId,
      type: 'receipt.outcome_recorded',
      workspaceId: grant.workspaceId,
    });
    await this.appendAuditBestEffort({
      actor: outcomeActor,
      auth: outcomeAuth,
      data:
        input.status === 'succeeded'
          ? { externalExecution: true, grantId, receiptId: grant.receiptId ?? null, result: input.result ?? { ok: true } }
          : { error: legacyOutcome.error, externalExecution: true, grantId, receiptId: grant.receiptId ?? null },
      id: terminalAuditId(
        completedAttempt.id,
        input.status === 'succeeded' ? 'tool_call.executed' : 'tool_call.failed',
      ),
      inputHash: grant.inputHash,
      policyVersionHash: grant.policyVersionHash,
      timestamp: now,
      toolCallId: grant.toolCallId,
      type: input.status === 'succeeded' ? 'tool_call.executed' : 'tool_call.failed',
      workspaceId: grant.workspaceId,
    });
    await this.appendAuditBestEffort({
      actor: outcomeActor,
      auth: outcomeAuth,
      data: {
        attemptId: completedAttempt.id,
        attemptNumber: completedAttempt.attemptNumber,
        certainty: completedAttempt.outcome?.certainty ?? null,
        errorClass: completedAttempt.outcome?.errorClass ?? null,
        errorCode: completedAttempt.outcome?.errorCode ?? null,
        grantId,
        remediationHash: completedAttempt.outcome?.remediationHash ?? null,
        resultDeliveryHash: completedAttempt.outcome?.resultDeliveryHash ?? null,
        resultHash: completedAttempt.outcome?.resultHash ?? null,
        retryDisposition: completedAttempt.outcome?.retryDisposition ?? null,
        state: completedAttempt.state,
      },
      id: terminalAuditId(completedAttempt.id, 'execution.attempt_completed'),
      inputHash: completedAttempt.inputHash,
      policyVersionHash: completedAttempt.binding.policyVersionHash ?? undefined,
      timestamp: completedAttempt.completedAt ?? completedAttempt.updatedAt,
      toolCallId: completedAttempt.toolCallId,
      type: 'execution.attempt_completed',
      workspaceId: completedAttempt.workspaceId,
    });
    this.recordTelemetry('receipt.outcome_recorded', telemetryForGrant(grant, {
      'error.present': legacyOutcome.status === 'failed',
      'execution.status': completedAttempt.state,
      'receipt.hash': updatedReceipt?.receiptHash ?? grant.receiptHash,
      'receipt.id': updatedReceipt?.id ?? grant.receiptId,
    }));
    this.recordTelemetry(input.status === 'succeeded' ? 'tool_call.executed' : 'tool_call.failed', telemetryForGrant(grant, {
      'error.present': legacyOutcome.status === 'failed',
      'execution.status': completedAttempt.state,
      status: deliveredToolCall.status,
    }));
    return { attempt: completedAttempt, grant, receipt: updatedReceipt, toolCall: deliveredToolCall };
  }

  private async recordContentExposureBeforeDelivery(
    toolCall: ToolCallRecord,
    resultDelivery: ResultDeliveryMetadataV1 | undefined,
    auth: AuthContext,
  ): Promise<void> {
    const source = toolCall.resultSource;
    if (!resultDelivery?.modelVisible || !source || source === 'none') return;
    const influenceScopeId = toolCall.influenceScopeId;
    if (!influenceScopeId || !/^influence_[a-f0-9]{64}$/u.test(influenceScopeId)) {
      throw new ForbiddenError('Verified influence-scope evidence is unavailable for this MCP result.');
    }
    const outcome = await this.store.recordContentExposure({
      influenceScopeId,
      integrity: source.integrity,
      observedAt: new Date().toISOString(),
      policyVersionHash: toolCall.policyVersionHash ?? this.currentPolicyVersionHash() ?? 'unknown',
      sourceId: source.sourceId,
      sourceToolCallId: toolCall.id,
      workspaceId: toolCall.workspaceId ?? auth.workspaceId,
    });
    if (outcome === 'conflict') {
      throw new ForbiddenError('Existing content-exposure evidence conflicts with the frozen result source.');
    }
    await this.auditStore.append({
      actor: auth.email ?? auth.principalId,
      auth,
      data: {
        influenceScopeId,
        instructionAuthority: 'none',
        integrity: source.integrity,
        recordOutcome: outcome,
        resultByteCount: resultDelivery.byteCount,
        resultHash: resultDelivery.canonicalResultHash,
        sourceId: source.sourceId ?? null,
        sourceToolCallId: toolCall.id,
      },
      id: `audit_content_exposure_${hashJson({ influenceScopeId, sourceToolCallId: toolCall.id })}`,
      inputHash: toolCall.inputHash,
      policyVersionHash: toolCall.policyVersionHash,
      policyVersionId: toolCall.policyVersionId,
      timestamp: new Date().toISOString(),
      toolCallId: toolCall.id,
      type: 'content.exposure_recorded',
      workspaceId: toolCall.workspaceId ?? auth.workspaceId,
    });
  }

  private async appendAuditBestEffort(event: Parameters<AuditStore['append']>[0]): Promise<void> {
    try {
      await this.auditStore.append(event);
    } catch {
      // The durable attempt transition remains authoritative. A secondary
      // evidence export failure must not create a false retry opportunity.
    }
  }

  private recordTelemetry(name: string, attributes: TelemetryAttributes): void {
    void this.telemetry?.recordLifecycle(name, attributes).catch(() => undefined);
  }
}

function assertMcpAdapterAuthorization(
  toolCall: ToolCallRecord,
  auth: AuthContext,
  wrapperSessionId?: string,
): void {
  const source = canonicalMcpSource(toolCall.decisionTrace);
  const hasVerifiedScope = typeof toolCall.influenceScopeId === 'string' &&
    /^influence_[a-f0-9]{64}$/u.test(toolCall.influenceScopeId);
  if (source?.type !== 'mcp') {
    if (hasVerifiedScope) {
      throw new ForbiddenError('MCP execution grant has inconsistent authoritative source evidence.');
    }
    return;
  }
  const authoritativeScopeId = authoritativeInfluenceScopeId(toolCall);
  if (!hasVerifiedScope || !authoritativeScopeId) {
    throw new ForbiddenError('MCP execution grant lacks consistent verified influence-scope evidence.');
  }
  if (!source.adapterId?.startsWith('mcp-stdio:')) {
    throw new ForbiddenError('External MCP execution grants require the authenticated stdio wrapper adapter.');
  }

  const originating = toolCall.requestedByAuth;
  const sameClient = !originating?.clientId || Boolean(auth.clientId && auth.clientId === originating.clientId);
  const samePrincipal = originating?.principalId === auth.principalId;
  if (!originating || !sameClient || !samePrincipal || originating.workspaceId !== auth.workspaceId) {
    throw new ForbiddenError('MCP execution grant belongs to another authenticated adapter.');
  }
  if (!wrapperSessionId) {
    throw new ForbiddenError('MCP execution grant requires its originating wrapper session.');
  }
  const expectedScopeId = deriveInfluenceScopeId({
    adapterId: source.adapterId,
    principalId: auth.principalId,
    protocol: 'mcp',
    transport: 'stdio',
    transportSessionId: wrapperSessionId,
    workspaceId: auth.workspaceId,
  });
  if (authoritativeScopeId !== expectedScopeId) {
    throw new ForbiddenError('MCP execution grant belongs to another verified influence scope.');
  }
}

function terminalAuditId(attemptId: string, type: string): string {
  return `audit_terminal_${hashJson({ attemptId, type })}`;
}

function authoritativeInfluenceScopeId(toolCall: ToolCallRecord): string | undefined {
  const decisionTrace = toolCall.decisionTrace;
  if (!isJsonObject(decisionTrace) || !isJsonObject(decisionTrace.canonicalRequestEvidence)) return undefined;
  const evidence = decisionTrace.canonicalRequestEvidence;
  const source = isJsonObject(evidence.source) && isJsonObject(evidence.source.value)
    ? evidence.source.value
    : undefined;
  const protocol = isJsonObject(evidence.sourceProtocol) ? evidence.sourceProtocol.value : undefined;
  const tenant = isJsonObject(evidence.tenant) && isJsonObject(evidence.tenant.value)
    ? evidence.tenant.value
    : undefined;
  const session = isJsonObject(evidence.session) ? evidence.session : undefined;
  const sessionProvenance = session && isJsonObject(session.provenance) ? session.provenance : undefined;
  const sessionValue = session && isJsonObject(session.value) ? session.value : undefined;
  const influenceScopeId = toolCall.influenceScopeId;
  if (
    source?.type !== 'mcp' ||
    typeof source.adapterId !== 'string' ||
    protocol !== 'mcp' ||
    tenant?.id !== (toolCall.workspaceId ?? 'default') ||
    session?.present !== true ||
    sessionProvenance?.source !== 'actionproxy.verified-mcp-influence-scope' ||
    !['derived', 'externally_verified', 'trusted'].includes(String(sessionProvenance?.trust)) ||
    sessionValue?.sessionId !== influenceScopeId ||
    typeof influenceScopeId !== 'string' ||
    !/^influence_[a-f0-9]{64}$/u.test(influenceScopeId) ||
    toolCall.actionEnvelope?.protocol !== 'mcp' ||
    toolCall.actionEnvelope.source.type !== 'mcp' ||
    toolCall.actionEnvelope.source.id !== source.adapterId
  ) {
    return undefined;
  }
  return influenceScopeId;
}

function canonicalMcpSource(decisionTrace: unknown): { adapterId?: string; type?: string } | undefined {
  if (!isJsonObject(decisionTrace) || !isJsonObject(decisionTrace.canonicalRequestEvidence)) return undefined;
  const sourceField = decisionTrace.canonicalRequestEvidence.source;
  if (!isJsonObject(sourceField) || !isJsonObject(sourceField.value)) return undefined;
  return {
    adapterId: typeof sourceField.value.adapterId === 'string' ? sourceField.value.adapterId : undefined,
    type: typeof sourceField.value.type === 'string' ? sourceField.value.type : undefined,
  };
}

function requiresMcpResultDelivery(toolCall: ToolCallRecord): boolean {
  return canonicalMcpSource(toolCall.decisionTrace)?.type === 'mcp' &&
    Boolean(toolCall.resultSource && toolCall.resultSource !== 'none');
}

function contentExposureRevisionGuard(toolCall: ToolCallRecord): {
  influenceScopeId: string;
  revision: number;
} | undefined {
  return validatedContentExposureRevisionGuard(toolCall.contentInfluence, authoritativeInfluenceScopeId(toolCall));
}

function requiresContentExposureBeforeDelivery(
  toolCall: ToolCallRecord,
  delivery: ResultDeliveryMetadataV1 | undefined,
): boolean {
  return Boolean(
    delivery?.modelVisible === true &&
    toolCall.resultSource &&
    toolCall.resultSource !== 'none',
  );
}

function validateResultDelivery(
  input: ReportExecutionGrantOutcomeInput,
): ResultDeliveryMetadataV1 | undefined {
  const delivery = input.resultDelivery;
  if (!delivery) return undefined;
  if (!input.result) {
    throw new ForbiddenError('Result-delivery evidence requires the exact downstream result.');
  }
  const canonical = canonicalJsonStringify(input.result);
  const byteCount = Buffer.byteLength(canonical, 'utf8');
  const canonicalResultHash = hashCanonicalJson(input.result);
  if (delivery.byteCount !== byteCount || delivery.canonicalResultHash !== canonicalResultHash) {
    throw new ForbiddenError('Result-delivery evidence does not match the exact downstream result.');
  }
  return { ...delivery };
}

function telemetryForGrant(grant: ExecutionGrantRecord, attributes: TelemetryAttributes = {}): TelemetryAttributes {
  return {
    'grant.id': grant.id,
    'input.hash': grant.inputHash,
    'policy.version.hash': grant.policyVersionHash,
    'receipt.hash': grant.receiptHash,
    'receipt.id': grant.receiptId,
    'tool.name': grant.toolName,
    'tool_call.id': grant.toolCallId,
    'workspace.id': grant.workspaceId,
    ...attributes,
  };
}

function signGrant(secret: string, grant: ExecutionGrantRecord): string {
  return hmacSha256Hex(
    secret,
    stableStringify({
      actor: grant.actor,
      expiresAt: grant.expiresAt,
      id: grant.id,
      inputHash: grant.inputHash,
      nonce: grant.nonce,
      approvedEnvelopeHash: grant.approvedEnvelopeHash,
      approvedInputHash: grant.approvedInputHash,
      policyVersionHash: grant.policyVersionHash,
      receiptHash: grant.receiptHash,
      receiptId: grant.receiptId,
      toolCallId: grant.toolCallId,
      toolName: grant.toolName,
      workspaceId: grant.workspaceId,
    }),
  );
}

function sameLegacyOutcome(
  existing: NonNullable<ActionReceiptRecord['outcome']>,
  input: ReturnType<typeof legacyOutcomeForReport>,
): boolean {
  return (
    existing.status === input.status &&
    (existing.error ?? undefined) === (input.status === 'failed' ? input.error : undefined) &&
    stableStringify(existing.remediation ?? null) ===
      stableStringify(input.status === 'succeeded' ? input.remediation ?? null : null) &&
    stableStringify(existing.result ?? null) === stableStringify(input.status === 'succeeded' ? input.result ?? { ok: true } : null)
  );
}

function attemptStateForReport(status: ReportExecutionGrantOutcomeInput['status']): ExecutionAttemptTerminalState {
  if (status === 'succeeded') return 'succeeded';
  if (status === 'failed') return 'failed_after_dispatch';
  return status;
}

function staticMcpTransportOutcomeError(
  status: Extract<ReportExecutionGrantOutcomeInput['status'], 'cancelled' | 'timed_out' | 'unknown_outcome'>,
): string {
  if (status === 'timed_out') return 'Downstream MCP transport timed out after dispatch.';
  if (status === 'cancelled') return 'Downstream MCP execution was cancelled after dispatch.';
  return 'Downstream MCP transport failed after dispatch.';
}

function legacyOutcomeForReport(input: ReportExecutionGrantOutcomeInput): {
  error?: string;
  errorClass?: string;
  errorCode?: string;
  remediation?: RemediationDescriptor;
  result?: JsonObject;
  status: 'failed' | 'succeeded';
} {
  if (input.status === 'succeeded') {
    return {
      remediation: input.remediation,
      result: input.result ?? { ok: true },
      status: 'succeeded',
    };
  }
  const defaults = {
    cancelled: ['execution_cancelled', 'External execution was cancelled.'],
    failed: ['external_execution_error', 'External execution failed.'],
    timed_out: ['execution_timeout', 'External execution timed out.'],
    unknown_outcome: ['unknown_execution_outcome', 'External execution outcome is unknown.'],
  } as const;
  const [errorCode, defaultMessage] = defaults[input.status];
  return {
    error: input.error ?? defaultMessage,
    errorClass: errorCode,
    errorCode,
    status: 'failed',
  };
}

function attemptMatchesGrant(
  attempt: ExecutionAttemptRecordV1,
  grant: ExecutionGrantRecord,
  options: { requireGrantBinding: boolean },
): boolean {
  return (
    attempt.executionMode === 'external_grant' &&
    attempt.executorId === 'actionproxy.external-runner' &&
    attempt.providerIdempotency === 'none' &&
    attempt.retryPolicy === 'never_automatic' &&
    attempt.workspaceId === grant.workspaceId &&
    attempt.toolCallId === grant.toolCallId &&
    attempt.inputHash === grant.inputHash &&
    attempt.binding.actionEnvelopeHash === (grant.approvedEnvelopeHash ?? null) &&
    attempt.binding.policyVersionHash === (grant.policyVersionHash ?? null) &&
    attempt.binding.receiptHash === (grant.receiptHash ?? null) &&
    attempt.binding.receiptId === (grant.receiptId ?? null) &&
    (!options.requireGrantBinding || attempt.grantId === grant.id)
  );
}

function currentToolCallMismatch(
  toolCall: ToolCallRecord,
  attempt: ExecutionAttemptRecordV1,
  grant: ExecutionGrantRecord,
  options: { allowAuthorizedTerminalRecovery?: boolean } = {},
): string | undefined {
  const decision = decisionIdentity(toolCall);
  const storedInputHash = toolCall.inputHash ?? hashJson(toolCall.input);
  if ((toolCall.workspaceId ?? 'default') !== grant.workspaceId) return 'tenant_mismatch';
  if (toolCall.id !== grant.toolCallId || toolCall.id !== attempt.toolCallId) return 'tool_call_id_mismatch';
  if (toolCall.toolName !== grant.toolName) return 'tool_name_mismatch';
  if (
    toolCall.status !== 'authorized' &&
    !(options.allowAuthorizedTerminalRecovery && ['executed', 'failed'].includes(toolCall.status))
  ) return 'tool_call_status_mismatch';
  if (requiresMcpResultDelivery(toolCall) && toolCall.status === 'authorized' && toolCall.resultWithheld !== true) {
    return 'classified_result_not_prewithheld';
  }
  if (toolCall.decision !== 'allow' && toolCall.decision !== 'require_approval') return 'decision_outcome_mismatch';
  if (storedInputHash !== hashJson(toolCall.input) || storedInputHash !== grant.inputHash) return 'input_hash_mismatch';
  if (toolCall.actionEnvelope) {
    if (toolCall.actionEnvelope.executionMode !== 'external_grant') return 'execution_mode_mismatch';
    if (toolCall.actionEnvelope.toolName !== toolCall.toolName) return 'action_envelope_tool_mismatch';
    if (toolCall.actionEnvelope.inputHash !== storedInputHash) return 'action_envelope_input_mismatch';
    if (toolCall.actionEnvelope.envelopeHash !== hashJson({ ...toolCall.actionEnvelope, envelopeHash: undefined })) {
      return 'action_envelope_integrity_mismatch';
    }
  }
  if ((toolCall.actionEnvelopeHash ?? null) !== attempt.binding.actionEnvelopeHash) {
    return 'action_envelope_hash_mismatch';
  }
  if ((toolCall.canonicalActionRequestHash ?? null) !== attempt.binding.canonicalActionRequestHash) {
    return 'canonical_request_hash_mismatch';
  }
  if ((toolCall.canonicalActionRequestVersion ?? null) !== attempt.binding.canonicalActionRequestVersion) {
    return 'canonical_request_version_mismatch';
  }
  if ((toolCall.canonicalDecisionInputHash ?? decision?.decisionInputHash ?? null) !== attempt.binding.canonicalDecisionInputHash) {
    return 'decision_input_hash_mismatch';
  }
  if (toolCall.decisionTrace?.decisionV1 !== undefined && !decision) return 'decision_trace_malformed';
  if ((decision?.decisionId ?? null) !== attempt.binding.decisionId) return 'decision_id_mismatch';
  if ((decision?.version ?? null) !== attempt.binding.decisionVersion) return 'decision_version_mismatch';
  if (decision && decision.outcome !== toolCall.decision) return 'decision_trace_outcome_mismatch';
  if ((toolCall.policyVersionHash ?? null) !== attempt.binding.policyVersionHash) return 'policy_hash_mismatch';
  const contentInfluenceBindingHash = validContentInfluenceBindingHash(toolCall.contentInfluence);
  if (toolCall.contentInfluence && !contentInfluenceBindingHash) return 'content_influence_binding_invalid';
  if ((contentInfluenceBindingHash ?? null) !== (attempt.binding.contentInfluenceBindingHash ?? null)) {
    return 'content_influence_binding_mismatch';
  }
  if ((toolCall.influenceScopeId ?? null) !== (attempt.binding.influenceScopeId ?? null)) {
    return 'influence_scope_mismatch';
  }
  if (hashJson(toolCall.resultSource ?? null) !== attempt.binding.resultSourceHash) {
    return 'result_source_mismatch';
  }
  return undefined;
}

function currentReceiptMismatch(
  receipt: ActionReceiptRecord | undefined,
  toolCall: ToolCallRecord,
  attempt: ExecutionAttemptRecordV1,
  grant: ExecutionGrantRecord,
): string | undefined {
  if (!receipt) {
    return grant.receiptId || attempt.binding.receiptId ? 'receipt_not_found' : undefined;
  }
  if (receipt.workspaceId !== attempt.workspaceId) return 'receipt_tenant_mismatch';
  if (receipt.toolCallId !== toolCall.id || receipt.id !== attempt.binding.receiptId) return 'receipt_identity_mismatch';
  if (receipt.toolName !== toolCall.toolName) return 'receipt_tool_mismatch';
  if (receipt.executionMode !== 'external_grant') return 'receipt_execution_mode_mismatch';
  if (receipt.expiresAt && Date.parse(receipt.expiresAt) <= Date.now()) return 'receipt_expired';
  if (receipt.receiptHash !== attempt.binding.receiptHash || receipt.receiptHash !== grant.receiptHash) {
    return 'receipt_hash_mismatch';
  }
  if (receipt.approvedInputHash !== attempt.inputHash || receipt.approvedInputHash !== grant.inputHash) {
    return 'receipt_input_hash_mismatch';
  }
  if (
    receipt.approvedEnvelopeHash !== attempt.binding.actionEnvelopeHash ||
    receipt.approvedEnvelopeHash !== grant.approvedEnvelopeHash
  ) {
    return 'receipt_envelope_hash_mismatch';
  }
  if (receipt.policyDecision !== toolCall.decision) return 'receipt_decision_mismatch';
  if (receipt.policyVersionHash !== toolCall.policyVersionHash) return 'receipt_policy_hash_mismatch';
  if ((receipt.policyVersionId ?? null) !== (toolCall.policyVersionId ?? null)) return 'receipt_policy_version_mismatch';
  if ((receipt.approvalId ?? null) !== attempt.binding.approvalId) return 'receipt_approval_mismatch';
  return undefined;
}

function currentApprovalMismatch(
  approval: Awaited<ReturnType<Store['getApproval']>>,
  toolCall: ToolCallRecord,
  attempt: ExecutionAttemptRecordV1,
  grant: ExecutionGrantRecord,
): string | undefined {
  if (!approval) return 'approval_not_found';
  if (approval.status !== 'approved') return 'approval_status_mismatch';
  if (approval.authorizationConsumedReason !== 'approved' || !approval.authorizationConsumedAt) {
    return 'approval_nonce_not_consumed';
  }
  if (!approval.authorization || !isValidApprovalAuthorization(approval.authorization)) {
    return 'approval_authorization_invalid';
  }
  if (approvalAuthorizationExpired(approval.authorization)) return 'approval_authorization_expired';
  if (approval.authorization.authorizationHash !== attempt.binding.approvalAuthorizationHash) {
    return 'approval_authorization_hash_mismatch';
  }
  if (approval.authorization.nonce !== attempt.binding.approvalAuthorizationNonce) {
    return 'approval_authorization_nonce_mismatch';
  }
  if ((approval.workspaceId ?? 'default') !== attempt.workspaceId) return 'approval_tenant_mismatch';
  if (approval.toolCallId !== toolCall.id || approval.id !== attempt.binding.approvalId) {
    return 'approval_identity_mismatch';
  }
  if (approval.approvedInputHash !== grant.inputHash || approval.approvedInputHash !== attempt.inputHash) {
    return 'approved_input_hash_mismatch';
  }
  if (
    (approval.approvedEnvelopeHash ?? null) !== attempt.binding.actionEnvelopeHash ||
    (approval.approvedEnvelopeHash ?? null) !== (grant.approvedEnvelopeHash ?? null)
  ) {
    return 'approved_envelope_hash_mismatch';
  }

  const originalToolCall: ToolCallRecord = {
    ...toolCall,
    actionEnvelopeHash: approval.originalEnvelopeHash,
    input: approval.originalInput,
    inputHash: approval.originalInputHash,
    status: 'pending_approval',
  };
  return approvalAuthorizationMismatch(approval.authorization, approval, originalToolCall);
}

function decisionIdentity(toolCall: ToolCallRecord): {
  decisionId: string;
  decisionInputHash: string;
  outcome: ToolCallRecord['decision'];
  version: 'actionproxy.decision.v1';
} | undefined {
  const candidate = toolCall.decisionTrace?.decisionV1;
  if (!isJsonObject(candidate) || candidate.version !== 'actionproxy.decision.v1') return undefined;
  if (
    typeof candidate.decisionId !== 'string' ||
    typeof candidate.decisionInputHash !== 'string' ||
    typeof candidate.requestId !== 'string' ||
    typeof candidate.tenantId !== 'string' ||
    (candidate.outcome !== 'allow' && candidate.outcome !== 'deny' && candidate.outcome !== 'require_approval')
  ) {
    return undefined;
  }
  if (
    candidate.requestId !== toolCall.id ||
    candidate.tenantId !== (toolCall.workspaceId ?? 'default') ||
    candidate.decisionInputHash !== toolCall.canonicalDecisionInputHash ||
    candidate.outcome !== toolCall.decision ||
    !isJsonObject(candidate.policy) ||
    !isJsonObject(candidate.policy.provider) ||
    candidate.policy.digest !== toolCall.policyVersionHash ||
    candidate.policy.version !== toolCall.policyVersionId ||
    candidate.policy.provider.status !== 'ok'
  ) {
    return undefined;
  }
  try {
    const identityMaterial = {
      approvalRequirements: candidate.approvalRequirements,
      decisionInputHash: candidate.decisionInputHash,
      matchedPolicies: candidate.matchedPolicies,
      obligations: candidate.obligations,
      outcome: candidate.outcome,
      policy: {
        digest: candidate.policy.digest,
        digestAlgorithm: candidate.policy.digestAlgorithm,
        providerId: candidate.policy.provider.id,
        providerVersion: candidate.policy.provider.version,
        schemaVersion: candidate.policy.schemaVersion,
        status: candidate.policy.provider.status,
        version: candidate.policy.version,
      },
      reasonCodes: candidate.reasonCodes,
      requestId: candidate.requestId,
      tenantId: candidate.tenantId,
      version: candidate.version,
    };
    if (candidate.decisionId !== `decision_${hashCanonicalJson(identityMaterial)}`) return undefined;
  } catch {
    return undefined;
  }
  return {
    decisionId: candidate.decisionId,
    decisionInputHash: candidate.decisionInputHash,
    outcome: candidate.outcome,
    version: candidate.version,
  };
}

function sameAttemptOutcome(
  attempt: ExecutionAttemptRecordV1,
  candidate: ReturnType<typeof executionAttemptOutcome>,
): boolean {
  const outcome = attempt.outcome;
  return (
    attempt.state === candidate.status &&
    outcome !== undefined &&
    outcome.status === candidate.status &&
    outcome.certainty === candidate.certainty &&
    outcome.errorClass === candidate.errorClass &&
    outcome.errorCode === candidate.errorCode &&
    outcome.errorMessage === candidate.errorMessage &&
    outcome.remediationHash === candidate.remediationHash &&
    outcome.resultDeliveryHash === candidate.resultDeliveryHash &&
    outcome.resultHash === candidate.resultHash &&
    outcome.retryDisposition === candidate.retryDisposition
  );
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
