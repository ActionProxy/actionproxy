import type { AuthContext, SubmitToolCallRequest, ToolCallRecord } from '../models';
import { normalizeActionEnvelope } from '../security/action-envelope';
import { hashJson } from '../security/crypto';
import type { ApproverDirectoryService } from '../services/approver-directory';
import type {
  ContentIntegrity,
  PolicyEvaluation,
  PolicyFile,
  PolicyRule,
  PolicyTraceMatchType,
  PolicyTraceRuleEvaluation,
} from './policy-types';
import { evaluateContentInfluence } from './content-influence';
import {
  buildContentInfluenceEvidence,
  type ContentInfluenceEvidenceV1,
} from '../contracts/content-influence';
import type { PolicyEvaluationContext } from './evaluate-policy';
import { buildActionProxyDecision, type ActionProxyDecisionV1 } from '../contracts/decision';
import {
  createYamlPolicyProvider,
  evaluatePolicyProvider,
  type DeterministicPolicyProvider,
  type PolicyProviderEvaluation,
} from './policy-provider';
import {
  CANONICAL_ACTION_REQUEST_VERSION,
  CanonicalizationError,
  canonicalActionRequestEvidence,
  canonicalJsonStringify,
  deriveCanonicalPolicyContext,
  normalizeActionRequest,
  type CanonicalActionRequest,
  type CanonicalActionRequestEvidence,
  type CanonicalPolicyContext,
  type HttpActionIngress,
} from '../contracts/action-request';

export interface PolicyDecisionTrace {
  actionEnvelopeHash?: string;
  canonicalActionRequestHash?: string;
  canonicalActionRequestVersion?: string;
  canonicalDecisionInputHash?: string;
  canonicalPolicyContext?: CanonicalPolicyContext;
  canonicalRequestEvidence?: CanonicalActionRequestEvidence;
  contentInfluence?: ContentInfluenceEvidenceV1;
  decisionV1?: ActionProxyDecisionV1;
  approverResolution: PolicyTraceApproverResolution;
  decision: 'allow' | 'deny' | 'require_approval';
  fallbackPath: PolicyTraceMatchType[];
  inputHash?: string;
  matchType: PolicyTraceMatchType;
  matchedRule: string;
  policyReason: string;
  policyRisk: string;
  policyVersionHash?: string;
  policyVersionId?: string;
  ruleEvaluations: PolicyTraceRuleEvaluation[];
  storedDecision?: 'allow' | 'deny' | 'require_approval';
  toolCallId?: string;
  toolName: string;
}

export interface PolicyTraceApproverResolution {
  configuredGroups: string[];
  configuredUsers: string[];
  defaultApproversUsed: boolean;
  notificationChannels: string[];
  requiredApprovals: number;
  resolvedRecipientCount?: number;
  resolvedUserIds?: string[];
  separationOfDuties: boolean;
  status: 'not_required' | 'not_resolved' | 'resolved' | 'resolved_empty';
}

export async function tracePolicyForSubmit(input: {
  approverDirectory?: ApproverDirectoryService;
  auth?: AuthContext;
  policy: PolicyFile;
  policyVersionHash?: string;
  policyVersionId?: string;
  request: SubmitToolCallRequest;
  workspaceId: string;
  ingress?: HttpActionIngress;
  policyProvider?: DeterministicPolicyProvider;
  providerEvaluation?: PolicyProviderEvaluation;
  contentInfluence?: {
    observedIntegrities?: readonly ContentIntegrity[];
    scopeVerified: boolean;
  };
}): Promise<PolicyDecisionTrace> {
  const actor = actorForSubmit(input.request, input.auth);
  const actionEnvelope = normalizeActionEnvelope({ actor, auth: input.auth, request: input.request });
  const canonicalActionRequest = input.ingress
    ? normalizeActionRequest({
        auth: input.auth,
        ingress: input.ingress,
        receivedAt: new Date().toISOString(),
        request: input.request,
        requestId: 'policy_simulation',
        workspaceId: input.workspaceId,
      })
    : undefined;
  const context = canonicalActionRequest
    ? policyContextFromCanonicalActionRequest(canonicalActionRequest)
    : policyContextFromSubmit(input.request);
  const baseProviderEvaluation = input.providerEvaluation ?? evaluatePolicyProvider(
    input.policyProvider ?? createYamlPolicyProvider(input.policy, input),
    { context, toolName: input.request.toolName },
  );
  const selectedInfluence = baseProviderEvaluation.trace.evaluation.rule.influence;
  const influenceEvaluation = input.contentInfluence && selectedInfluence
    ? evaluateContentInfluence(baseProviderEvaluation.trace.evaluation, input.contentInfluence)
    : undefined;
  const effectiveEvaluation = influenceEvaluation
    ? effectiveContentInfluenceEvaluation(baseProviderEvaluation.trace.evaluation, influenceEvaluation)
    : baseProviderEvaluation.trace.evaluation;
  const providerEvaluation = providerEvaluationWithEvaluation(baseProviderEvaluation, effectiveEvaluation);
  const trace = providerEvaluation.trace;
  const contentInfluence = influenceEvaluation && selectedInfluence
    ? buildContentInfluenceEvidence({
        evaluatedAt: canonicalActionRequest?.receivedAt.value ?? new Date().toISOString(),
        evaluation: influenceEvaluation,
        policyVersionHash: input.policyVersionHash ?? providerEvaluation.descriptor.policyDigest ?? hashFallback(input.policy),
        policyVersionId: input.policyVersionId,
        selectedRule: selectedInfluence,
      })
    : undefined;

  return {
    actionEnvelopeHash: actionEnvelope.envelopeHash,
    canonicalActionRequestHash: canonicalActionRequest?.integrity.requestHash,
    canonicalActionRequestVersion: canonicalActionRequest?.version,
    canonicalDecisionInputHash: canonicalActionRequest?.integrity.decisionInputHash,
    canonicalPolicyContext: canonicalActionRequest?.context.policy,
    canonicalRequestEvidence: canonicalActionRequest
      ? canonicalActionRequestEvidence(canonicalActionRequest)
      : undefined,
    contentInfluence,
    decisionV1: canonicalActionRequest
      ? buildActionProxyDecision({
          decidedAt: canonicalActionRequest.receivedAt.value!,
          decisionInputHash: canonicalActionRequest.integrity.decisionInputHash,
          providerEvaluation,
          requestId: canonicalActionRequest.requestId.value!,
          tenantId: canonicalActionRequest.tenant.value!.id,
        })
      : undefined,
    approverResolution: await approverResolution(trace.evaluation.rule, trace.decision, input.workspaceId, input.approverDirectory),
    decision: trace.decision,
    fallbackPath: trace.fallbackPath,
    inputHash: actionEnvelope.inputHash,
    matchType: trace.matchType,
    matchedRule: trace.matchedRule,
    policyReason: trace.evaluation.reason,
    policyRisk: trace.evaluation.risk,
    policyVersionHash: input.policyVersionHash,
    policyVersionId: input.policyVersionId,
    ruleEvaluations: trace.ruleEvaluations,
    toolName: input.request.toolName,
  };
}

function effectiveContentInfluenceEvaluation(
  base: PolicyEvaluation,
  influence: ReturnType<typeof evaluateContentInfluence>,
): PolicyEvaluation {
  if (influence.effectiveDecision === base.decision) return base;
  return {
    ...base,
    approval: influence.effectiveApproval,
    decision: influence.effectiveDecision,
    reason: `${base.reason} Content observed in this verified influence scope requires a stricter decision.`,
    rule: { ...base.rule, approval: influence.effectiveApproval },
  };
}

function providerEvaluationWithEvaluation(
  provider: PolicyProviderEvaluation,
  evaluation: PolicyEvaluation,
): PolicyProviderEvaluation {
  if (provider.trace.evaluation.decision === evaluation.decision) return provider;
  return {
    ...provider,
    trace: { ...provider.trace, decision: evaluation.decision, evaluation },
  };
}

function hashFallback(policy: PolicyFile): string {
  return hashJson(policy);
}

export async function tracePolicyForToolCall(input: {
  approverDirectory?: ApproverDirectoryService;
  policy: PolicyFile;
  policyVersionHash?: string;
  policyVersionId?: string;
  policyProvider?: DeterministicPolicyProvider;
  providerEvaluation?: PolicyProviderEvaluation;
  toolCall: ToolCallRecord;
}): Promise<PolicyDecisionTrace> {
  const context = policyContextFromToolCall(input.toolCall);
  const providerEvaluation = input.providerEvaluation ?? evaluatePolicyProvider(
    input.policyProvider ?? createYamlPolicyProvider(input.policy, {
      policyVersionHash: input.toolCall.policyVersionHash ?? input.policyVersionHash,
      policyVersionId: input.toolCall.policyVersionId ?? input.policyVersionId,
    }),
    { context, toolName: input.toolCall.toolName },
  );
  const trace = providerEvaluation.trace;
  const decisionV1 =
    input.toolCall.canonicalActionRequestVersion === CANONICAL_ACTION_REQUEST_VERSION &&
    input.toolCall.canonicalDecisionInputHash
      ? buildActionProxyDecision({
          decidedAt: input.toolCall.createdAt,
          decisionInputHash: input.toolCall.canonicalDecisionInputHash,
          providerEvaluation,
          requestId: input.toolCall.id,
          tenantId: input.toolCall.workspaceId ?? 'default',
        })
      : undefined;

  return {
    actionEnvelopeHash: input.toolCall.actionEnvelopeHash,
    canonicalActionRequestHash: input.toolCall.canonicalActionRequestHash,
    canonicalActionRequestVersion: input.toolCall.canonicalActionRequestVersion,
    canonicalDecisionInputHash: input.toolCall.canonicalDecisionInputHash,
    canonicalPolicyContext: input.toolCall.canonicalPolicyContext,
    decisionV1,
    approverResolution: await approverResolution(
      trace.evaluation.rule,
      trace.decision,
      input.toolCall.workspaceId ?? 'default',
      input.approverDirectory,
    ),
    decision: trace.decision,
    fallbackPath: trace.fallbackPath,
    inputHash: input.toolCall.inputHash,
    matchType: trace.matchType,
    matchedRule: trace.matchedRule,
    policyReason: trace.evaluation.reason,
    policyRisk: trace.evaluation.risk,
    policyVersionHash: input.toolCall.policyVersionHash ?? input.policyVersionHash,
    policyVersionId: input.toolCall.policyVersionId ?? input.policyVersionId,
    ruleEvaluations: trace.ruleEvaluations,
    storedDecision: input.toolCall.decision,
    toolCallId: input.toolCall.id,
    toolName: input.toolCall.toolName,
  };
}

export function policyContextFromSubmit(request: SubmitToolCallRequest): PolicyEvaluationContext {
  const metadata = request.metadata ?? {};
  return {
    amount: numberMetadata(metadata.amount) ?? numberMetadata(request.input.amount) ?? numberMetadata(request.input.amountCents),
    approverGroup: stringMetadata(metadata.approverGroup),
    currency: stringMetadata(metadata.currency ?? request.input.currency),
    customerVisible: booleanMetadata(metadata.customerVisible),
    input: request.input,
    metadata,
    operationKind: request.action?.operation?.kind ?? stringMetadata(metadata.operationKind),
    recipientDomain: stringMetadata(metadata.recipientDomain),
    risk: request.action?.context?.risk ?? stringMetadata(metadata.riskKind),
  };
}

export function policyContextFromCanonicalActionRequest(request: CanonicalActionRequest): PolicyEvaluationContext {
  return policyContextFromCanonicalFields(request.context.policy, request.arguments.value ?? {});
}

export function policyContextFromToolCall(toolCall: ToolCallRecord): PolicyEvaluationContext {
  if (toolCall.canonicalActionRequestVersion === CANONICAL_ACTION_REQUEST_VERSION) {
    const context = validatedFrozenCanonicalPolicyContext(toolCall);
    return policyContextFromCanonicalFields(context, toolCall.input);
  }
  const metadata = toolCall.metadata ?? {};
  return {
    amount: numberMetadata(metadata.amount) ?? numberMetadata(toolCall.input.amount) ?? numberMetadata(toolCall.input.amountCents),
    approverGroup: stringMetadata(metadata.approverGroup),
    currency: stringMetadata(metadata.currency ?? toolCall.input.currency),
    customerVisible: booleanMetadata(metadata.customerVisible),
    input: toolCall.input,
    metadata,
    operationKind: toolCall.actionEnvelope?.operation.kind ?? stringMetadata(metadata.operationKind),
    recipientDomain: stringMetadata(metadata.recipientDomain),
    risk: toolCall.actionEnvelope?.context.risk ?? stringMetadata(metadata.riskKind),
  };
}

const canonicalPolicyFields: readonly (keyof CanonicalPolicyContext)[] = [
  'amount',
  'approverGroup',
  'currency',
  'customerVisible',
  'operationKind',
  'recipientDomain',
  'risk',
];

/**
 * A canonical-v1 tool call must be re-evaluated from the policy context that
 * was frozen at ingress. Re-deriving it from mutable projections discards the
 * server-owned risk/visibility/operation fields supplied by native contracts.
 * The input itself is deliberately supplied by the caller above so approval
 * and dispatch revalidation still evaluate the exact finalized input.
 */
function validatedFrozenCanonicalPolicyContext(toolCall: ToolCallRecord): CanonicalPolicyContext {
  const context = toolCall.canonicalPolicyContext;
  if (!isCanonicalPolicyContext(context)) {
    throw new CanonicalizationError('Canonical tool call has no valid frozen policy context.');
  }

  const traced = toolCall.decisionTrace?.canonicalPolicyContext;
  if (toolCall.decisionTrace && !isCanonicalPolicyContext(traced)) {
    throw new CanonicalizationError('Canonical decision trace has no valid frozen policy context.');
  }
  if (traced && hashJson(traced) !== hashJson(context)) {
    throw new CanonicalizationError('Canonical policy context no longer matches its decision trace.');
  }

  const binding = toolCall.actionEnvelope?.preparedAction;
  if (binding) {
    const expectedSource = `action-contract:${binding.contractId}@${binding.contractVersion}`;
    for (const field of ['customerVisible', 'operationKind', 'risk'] as const) {
      const value = context[field];
      if (
        !value.present ||
        value.provenance.trust !== 'trusted' ||
        value.provenance.source !== expectedSource
      ) {
        throw new CanonicalizationError(
          `Prepared action has no trusted frozen ${field} policy binding.`,
        );
      }
    }
    if (typeof context.customerVisible.value !== 'boolean') {
      throw new CanonicalizationError('Prepared action customerVisible policy binding is invalid.');
    }
    if (
      typeof context.operationKind.value !== 'string' ||
      !['custom', 'delete', 'external_send', 'financial', 'read', 'write']
        .includes(context.operationKind.value)
    ) {
      throw new CanonicalizationError('Prepared action operationKind policy binding is invalid.');
    }
    if (typeof context.risk.value !== 'string' || !context.risk.value.trim()) {
      throw new CanonicalizationError('Prepared action risk policy binding is invalid.');
    }
  }
  return context;
}

function isCanonicalPolicyContext(value: unknown): value is CanonicalPolicyContext {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value).sort();
  if (
    keys.length !== canonicalPolicyFields.length ||
    canonicalPolicyFields.some((field, index) => keys[index] !== field)
  ) return false;
  return canonicalPolicyFields.every((field) => isCanonicalPolicyField(value[field]));
}

function isCanonicalPolicyField(value: unknown): value is CanonicalPolicyContext[keyof CanonicalPolicyContext] {
  if (!isRecord(value) || typeof value.present !== 'boolean' || !isRecord(value.provenance)) return false;
  if (
    typeof value.provenance.source !== 'string' ||
    !value.provenance.source.trim() ||
    !['asserted', 'derived', 'externally_verified', 'trusted'].includes(
      String(value.provenance.trust),
    )
  ) return false;
  const hasValue = Object.prototype.hasOwnProperty.call(value, 'value');
  if (value.present !== hasValue) return false;
  try {
    canonicalJsonStringify(value);
    return true;
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function policyContextFromCanonicalFields(
  context: CanonicalPolicyContext,
  input: Record<string, unknown>,
): PolicyEvaluationContext {
  return {
    amount: numberMetadata(canonicalValue(context.amount)),
    approverGroup: stringMetadata(canonicalValue(context.approverGroup)),
    currency: stringMetadata(canonicalValue(context.currency)),
    customerVisible: booleanMetadata(canonicalValue(context.customerVisible)),
    input,
    operationKind: stringMetadata(canonicalValue(context.operationKind)),
    recipientDomain: stringMetadata(canonicalValue(context.recipientDomain)),
    risk: stringMetadata(canonicalValue(context.risk)),
  };
}

function canonicalValue(field: { present: boolean; value?: unknown }): unknown {
  return field.present ? field.value : undefined;
}

async function approverResolution(
  rule: PolicyRule,
  decision: PolicyDecisionTrace['decision'],
  workspaceId: string,
  approverDirectory?: ApproverDirectoryService,
): Promise<PolicyTraceApproverResolution> {
  const configuredGroups = rule.approvers?.groups ?? [];
  const configuredUsers = rule.approvers?.users ?? [];
  const base = {
    configuredGroups,
    configuredUsers,
    defaultApproversUsed: configuredGroups.length === 0 && configuredUsers.length === 0,
    notificationChannels: rule.notify?.channels ?? [],
    requiredApprovals: rule.approvers?.requiredApprovals ?? 1,
    separationOfDuties: rule.approvers?.separationOfDuties ?? false,
  };
  if (decision !== 'require_approval') return { ...base, status: 'not_required' };
  if (!approverDirectory) return { ...base, status: 'not_resolved' };

  const recipients = await approverDirectory.resolveRecipients(rule, workspaceId);
  const resolvedUserIds = recipients.map((recipient) => recipient.userId);
  return {
    ...base,
    resolvedRecipientCount: recipients.length,
    resolvedUserIds,
    status: recipients.length > 0 ? 'resolved' : 'resolved_empty',
  };
}

function actorForSubmit(request: SubmitToolCallRequest, auth: AuthContext | undefined): string {
  if (!auth || auth.authProvider === 'none') return request.requestedBy;
  return auth.email ?? auth.principalId;
}

function stringMetadata(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function numberMetadata(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function booleanMetadata(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}
