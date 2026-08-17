/**
 * Read-only projections produced by the ActionProxy server.
 *
 * These declarations intentionally contain no constructors, canonicalizers,
 * hash helpers, authorization tokens, or authority interfaces. SDK callers
 * may inspect server evidence, but they cannot use this package to mint
 * trusted context, public hashes, or executor authority.
 */

export type CanonicalActionRequestVersionV1 = 'actionproxy.action-request.v1';
export type CanonicalJsonVersionV1 = 'actionproxy.canonical-json.v1';
export type ActionProxyDecisionVersionV1 = 'actionproxy.decision.v1';
export type ApprovalAuthorizationVersionV1 = 'actionproxy.approval-authorization.v1';
export type ExecutionAttemptVersionV1 = 'actionproxy.execution-attempt.v1';
export type ExecutionAuthorizationVersionV1 = 'actionproxy.execution-authorization.v1';
export type ExecutorCapabilitiesVersionV1 = 'actionproxy.executor-capabilities.v1';
export type CanonicalTrustClassification = 'asserted' | 'derived' | 'externally_verified' | 'trusted';

export interface CanonicalFieldProvenance {
  readonly source: string;
  readonly trust: CanonicalTrustClassification;
}

export interface CanonicalSourcedField<T> {
  readonly present: boolean;
  readonly provenance: CanonicalFieldProvenance;
  readonly value?: T;
}

export type CanonicalPolicyField =
  | 'amount'
  | 'approverGroup'
  | 'currency'
  | 'customerVisible'
  | 'operationKind'
  | 'recipientDomain'
  | 'risk';

export type CanonicalPolicyContextV1 = Readonly<
  Record<CanonicalPolicyField, CanonicalSourcedField<unknown>>
>;

export interface CanonicalActionActorEvidenceV1 {
  readonly authProvider?: 'api_key' | 'none' | 'oidc_jwt' | 'slack' | 'telegram' | 'tunnel_single_user';
  readonly displayName?: string;
  readonly email?: string;
  readonly id: string;
  readonly type: 'local' | 'service_account' | 'slack' | 'telegram' | 'unknown' | 'user';
}

/** The minimized canonical-request evidence included in server decision traces. */
export interface CanonicalActionRequestEvidenceV1 {
  readonly actor: CanonicalSourcedField<CanonicalActionActorEvidenceV1>;
  readonly agent: CanonicalSourcedField<{
    readonly id: string;
    readonly name?: string;
    readonly verification: 'asserted' | 'externally_verified';
  }>;
  readonly environment: CanonicalSourcedField<'local' | 'self_hosted'>;
  readonly session: CanonicalSourcedField<{
    readonly runId?: string;
    readonly sessionId?: string;
  }>;
  readonly source: CanonicalSourcedField<{
    readonly adapterId?: string;
    readonly type: 'http' | 'mcp';
  }>;
  readonly sourceProtocol: CanonicalSourcedField<'actionproxy_http' | 'mcp'>;
  readonly tenant: CanonicalSourcedField<{ readonly id: string }>;
  readonly version: CanonicalActionRequestVersionV1;
}

/** Finite, server-issued approval authorization evidence. No issuer is exposed by the SDK. */
export interface ApprovalAuthorizationEvidenceV1 {
  readonly authorizationHash: string;
  readonly binding: {
    readonly action: {
      readonly originalEnvelopeHash: string;
      readonly originalInputHash: string;
      readonly reviewHash: string;
    };
    readonly approval: {
      readonly approvalId: string;
      readonly requestedBy: string;
      readonly requestedByPrincipalId: string | null;
      readonly tenantId: string;
      readonly toolCallId: string;
    };
    readonly decision: {
      readonly decisionId: string | null;
      readonly outcome: 'allow' | 'deny' | 'require_approval';
      readonly version: ActionProxyDecisionVersionV1 | null;
    };
    readonly policy: {
      readonly digest: string | null;
      readonly evaluatorVersion: string | null;
      readonly legacyVersionHash: string;
      readonly legacyVersionId: string | null;
      readonly providerId: string | null;
      readonly providerVersion: string | null;
      readonly version: string | null;
    };
    readonly request: {
      readonly decisionInputHash: string | null;
      readonly requestHash: string | null;
      readonly version: CanonicalActionRequestVersionV1 | null;
    };
    readonly requirements: {
      readonly eligibleGroups: readonly string[];
      readonly eligibleUsers: readonly string[] | null;
      readonly requiredApprovals: number;
      readonly separationOfDuties: boolean;
    };
  };
  readonly expiresAt: string;
  readonly issuedAt: string;
  readonly nonce: string;
  readonly version: ApprovalAuthorizationVersionV1;
}

export type DecisionReasonCodeV1 =
  | 'policy_conditional_fallback'
  | 'policy_match_default'
  | 'policy_match_exact'
  | 'policy_match_wildcard'
  | 'policy_outcome_allow'
  | 'policy_outcome_deny'
  | 'policy_outcome_require_approval'
  | 'policy_provider_error'
  | 'policy_provider_invalid_output'
  | 'policy_provider_unavailable'
  | 'policy_provider_version_missing';

export type DecisionObligationV1 =
  | 'do_not_execute'
  | 'record_decision_evidence'
  | 'require_human_approval'
  | 'revalidate_policy_before_execution';

export type PolicyTraceMatchTypeV1 =
  | 'default'
  | 'exact'
  | 'provider_failure'
  | 'wildcard';

/** Deterministic decision evidence authored by the server policy boundary. */
export interface ActionProxyDecisionV1 {
  readonly approvalRequirements: {
    readonly eligibleGroups: readonly string[];
    readonly eligibleUsers: readonly string[];
    readonly expirationRequired: false;
    readonly expiresAt: null;
    readonly modificationBehavior: 'revalidate_and_rebind';
    readonly rejectionBehavior: 'terminal';
    readonly required: boolean;
    readonly requiredApprovals: number;
    readonly separationOfDuties: boolean;
  };
  readonly decidedAt: string;
  readonly decisionId: string;
  readonly decisionInputHash: string;
  readonly evaluatorVersion: string | null;
  readonly matchedPolicies: readonly {
    readonly digestAlgorithm: 'sha256';
    readonly matchType: PolicyTraceMatchTypeV1;
    readonly policyDigest: string;
    readonly policyVersion: string;
    readonly providerId: string;
    readonly ruleId: string;
  }[];
  readonly obligations: readonly DecisionObligationV1[];
  readonly outcome: 'allow' | 'deny' | 'require_approval';
  readonly policy: {
    readonly digest: string | null;
    readonly digestAlgorithm: 'sha256' | null;
    readonly provider: {
      readonly id: string;
      readonly status: 'failure' | 'ok';
      readonly version: string | null;
    };
    readonly schemaVersion: string | null;
    readonly version: string | null;
  };
  readonly reasonCodes: readonly DecisionReasonCodeV1[];
  readonly requestId: string;
  readonly tenantId: string;
  readonly version: ActionProxyDecisionVersionV1;
}

export interface PolicyTraceConditionEvaluationV1 {
  readonly actual?: unknown;
  readonly expected: unknown;
  readonly key: string;
  readonly matched: boolean;
}

export interface PolicyTraceRuleEvaluationV1 {
  readonly conditions: readonly PolicyTraceConditionEvaluationV1[];
  readonly conditionsMatched: boolean;
  readonly exists: boolean;
  readonly matchType: PolicyTraceMatchTypeV1;
  readonly pattern: string;
  readonly prefixMatched?: boolean;
  readonly selected: boolean;
}

/** Current server decision-trace response, including additive v1 projections. */
export interface PolicyDecisionTraceV1 {
  readonly actionEnvelopeHash?: string;
  readonly approverResolution: {
    readonly configuredGroups: readonly string[];
    readonly configuredUsers: readonly string[];
    readonly defaultApproversUsed: boolean;
    readonly notificationChannels: readonly string[];
    readonly requiredApprovals: number;
    readonly resolvedRecipientCount?: number;
    readonly resolvedUserIds?: readonly string[];
    readonly separationOfDuties: boolean;
    readonly status: 'not_required' | 'not_resolved' | 'resolved' | 'resolved_empty';
  };
  readonly canonicalActionRequestHash?: string;
  readonly canonicalActionRequestVersion?: CanonicalActionRequestVersionV1;
  readonly canonicalDecisionInputHash?: string;
  readonly canonicalPolicyContext?: CanonicalPolicyContextV1;
  readonly canonicalRequestEvidence?: CanonicalActionRequestEvidenceV1;
  readonly decision: 'allow' | 'deny' | 'require_approval';
  readonly decisionV1?: ActionProxyDecisionV1;
  readonly fallbackPath: readonly PolicyTraceMatchTypeV1[];
  readonly inputHash?: string;
  readonly matchedRule: string;
  readonly matchType: PolicyTraceMatchTypeV1;
  readonly policyReason: string;
  readonly policyRisk: string;
  readonly policyVersionHash?: string;
  readonly policyVersionId?: string;
  readonly ruleEvaluations: readonly PolicyTraceRuleEvaluationV1[];
  readonly storedDecision?: 'allow' | 'deny' | 'require_approval';
  readonly toolCallId?: string;
  readonly toolName: string;
}

export type ExecutionAttemptStateV1 =
  | 'reserved'
  | 'dispatched'
  | 'succeeded'
  | 'failed_before_dispatch'
  | 'failed_after_dispatch'
  | 'timed_out'
  | 'cancelled'
  | 'unknown_outcome';

export type ExecutionAttemptTerminalStateV1 = Exclude<ExecutionAttemptStateV1, 'dispatched' | 'reserved'>;
export type ExecutionRetryDispositionV1 =
  | 'none'
  | 'explicit_new_attempt_required'
  | 'manual_reconciliation_required';

export interface ExecutionAttemptBindingV1 {
  readonly actionEnvelopeHash: string | null;
  readonly approvalAuthorizationHash: string | null;
  readonly approvalAuthorizationNonce: string | null;
  readonly approvalId: string | null;
  readonly canonicalActionRequestHash: string | null;
  readonly canonicalActionRequestVersion: CanonicalActionRequestVersionV1 | null;
  readonly canonicalDecisionInputHash: string | null;
  readonly decisionId: string | null;
  readonly decisionVersion: ActionProxyDecisionVersionV1 | null;
  readonly policyVersionHash: string | null;
  readonly receiptHash: string | null;
  readonly receiptId: string | null;
}

export interface ExecutionAttemptOutcomeV1 {
  readonly certainty: 'known' | 'unknown';
  readonly errorClass: string | null;
  readonly errorCode: string | null;
  readonly errorMessage: string | null;
  readonly remediationHash: string | null;
  readonly recordedAt: string;
  readonly resultDeliveryHash: string | null;
  readonly resultHash: string | null;
  readonly retryDisposition: ExecutionRetryDispositionV1;
  readonly status: ExecutionAttemptTerminalStateV1;
}

/** Durable execution-attempt evidence returned by the server read endpoint. */
export interface ExecutionAttemptRecordV1 {
  readonly attemptNumber: number;
  readonly binding: ExecutionAttemptBindingV1;
  readonly completedAt?: string;
  readonly dispatchedAt?: string;
  readonly executionMode: 'external_grant' | 'local_mock';
  readonly executorId: 'actionproxy.external-runner' | 'actionproxy.local-tool-registry';
  readonly grantId?: string;
  readonly id: string;
  readonly inputHash: string;
  readonly outcome?: ExecutionAttemptOutcomeV1;
  readonly providerIdempotency: 'none';
  readonly reservedAt: string;
  readonly reservationOwner: string;
  readonly retryPolicy: 'never_automatic';
  readonly state: ExecutionAttemptStateV1;
  readonly toolCallId: string;
  readonly updatedAt: string;
  readonly version: ExecutionAttemptVersionV1;
  readonly workspaceId: string;
}

/** Conservative, server-authored capability evidence. It does not grant authority. */
export interface ExecutorCapabilitiesEvidenceV1 {
  readonly automaticRetry: { readonly supported: false };
  readonly cancellation: { readonly supported: false };
  readonly credentialCustody: {
    readonly acceptsRawCredentials: false;
    readonly mode: 'executor_boundary_only';
  };
  readonly providerIdempotency: { readonly supported: false };
  readonly reconciliation: { readonly supported: false };
  readonly timeout: { readonly enforced: false; readonly timeoutMs: null };
  readonly version: ExecutorCapabilitiesVersionV1;
}

export interface ExecutionAuthorizationBindingEvidenceV1 {
  readonly action: {
    readonly actionEnvelopeHash: string;
    readonly inputHash: string;
    readonly toolName: string;
  };
  readonly approval: {
    readonly approvalId: string | null;
    readonly authorizationHash: string | null;
    readonly authorizationNonce: string | null;
    readonly receiptHash: string | null;
    readonly receiptId: string | null;
  };
  readonly decision: {
    readonly decisionId: string | null;
    readonly decisionInputHash: string | null;
    readonly outcome: 'allow' | 'deny' | 'require_approval';
    readonly version: ActionProxyDecisionVersionV1 | null;
  };
  readonly execution: {
    readonly attemptId: string;
    readonly attemptNumber: number;
    readonly grantId: string | null;
    readonly mode: 'external_grant' | 'local_mock';
  };
  readonly executor: {
    readonly id: 'actionproxy.external-runner' | 'actionproxy.local-tool-registry';
  };
  readonly policy: {
    readonly digest: string | null;
    readonly evaluatorVersion: string | null;
    readonly providerId: string | null;
    readonly providerVersion: string | null;
    readonly version: string | null;
    readonly versionHash: string;
  };
  readonly request: {
    readonly canonicalActionRequestHash: string | null;
    readonly canonicalActionRequestVersion: CanonicalActionRequestVersionV1 | null;
    readonly toolCallId: string;
  };
  readonly tenant: { readonly workspaceId: string };
}

/**
 * Minimized server-produced evidence for a consumed executor authorization.
 * This is not the opaque process-local ExecutionAuthorization token and the
 * SDK intentionally exposes no API that can create, serialize, or consume it.
 */
export interface ExecutionAuthorizationEvidenceV1 {
  readonly authorizationId: string;
  readonly binding: ExecutionAuthorizationBindingEvidenceV1;
  readonly capabilities: ExecutorCapabilitiesEvidenceV1;
  readonly expiresAt: string;
  readonly issuedAt: string;
  readonly version: ExecutionAuthorizationVersionV1;
}
