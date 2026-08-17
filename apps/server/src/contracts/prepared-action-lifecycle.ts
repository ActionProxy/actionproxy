import type {
  ActionEnvelope,
  ActionOperationKind,
  ActionResourceHint,
  AuthContext,
  IdempotencyRecord,
  JsonObject,
  PreparedActionEnvelopeBindingV1,
  SubmitToolCallRequest,
  ApprovalRecord,
  ToolCallRecord,
} from '../models';

export interface PreparedActionSubmissionContext {
  /** Trusted internal selector. HTTP/MCP request bodies cannot set it. */
  actionContractId?: string;
  /** Trusted stable connected-account identity. Never contains a token. */
  connectionId?: string;
  idempotencyKey?: string;
  now: string;
  supersedesIntentId?: string;
  toolCallId: string;
  workspaceId: string;
  auth?: AuthContext;
}

export interface PreparedActionSubmission {
  binding: PreparedActionEnvelopeBindingV1;
  connectionId: string;
  effectiveInput: JsonObject;
  governance: {
    customerVisible: boolean;
    executionMode: 'external_grant';
    operationKind: ActionOperationKind;
    requiredScopes: string[];
    risk: string;
  };
  resources: ActionResourceHint[];
}

export type PreparedActionPersistenceResult =
  | {
      approval?: ApprovalRecord;
      outcome: 'created' | 'replay';
      prepared: PreparedActionSubmission;
      toolCall: ToolCallRecord;
    }
  | {
      approval?: ApprovalRecord;
      outcome: 'conflict';
      toolCall?: ToolCallRecord;
    };

export type PreparedApprovalPublicationResult =
  | {
      approval: ApprovalRecord;
      outcome: 'created' | 'replay';
      toolCall: ToolCallRecord;
    }
  | {
      approval?: ApprovalRecord;
      outcome: 'conflict';
      toolCall?: ToolCallRecord;
    };

export interface PreparedActionReviewProjection {
  connection: JsonObject;
  contract: JsonObject;
  effectiveInput: JsonObject;
  governance: JsonObject;
  intentHash: string;
  materialEffects: JsonObject[];
  proposalInput: JsonObject;
  resources: ActionResourceHint[];
  transformations: JsonObject[];
}

export interface PreparedActionRevisionContext {
  connectionId: string;
  contractId: string;
  editMode: 'original_only' | 'revision_required';
  intentId: string;
}

export interface PreparedActionRevisionLink {
  createdAt: string;
  createdBy: string;
  fromApprovalId: string;
  fromToolCallId: string;
  toApprovalId: string;
  toToolCallId: string;
  workspaceId: string;
}

export interface PreparedActionRevisionPersistenceInput {
  approval: ApprovalRecord;
  createdAt: string;
  createdBy: string;
  fromApprovalId: string;
  fromIntentId: string;
  fromToolCallId: string;
  idempotency?: IdempotencyRecord;
  prepared: PreparedActionSubmission;
  supersededAt: string;
  toolCall: ToolCallRecord;
}

export type PreparedActionRevisionFinalizationResult =
  | { outcome: 'conflict' }
  | {
      outcome: 'created' | 'replay';
      replacementApproval: ApprovalRecord;
      replacementToolCall: ToolCallRecord;
      supersededApproval: ApprovalRecord;
      supersededToolCall: ToolCallRecord;
    };

/**
 * Optional prepared-action lifecycle seam. Core stays connector-agnostic while
 * an edition-owned registry prepares and persists actions before policy.
 */
export interface PreparedActionLifecycle {
  assertRevisionAllowed(toolCall: ToolCallRecord): Promise<void>;
  isPreparedAction(toolName: string): boolean;
  prepareSubmission(
    request: SubmitToolCallRequest,
    context: PreparedActionSubmissionContext,
  ): Promise<PreparedActionSubmission | undefined>;
  persistSubmission(input: {
    approval?: ApprovalRecord;
    idempotency?: IdempotencyRecord;
    prepared: PreparedActionSubmission;
    toolCall: ToolCallRecord;
  }): Promise<PreparedActionPersistenceResult>;
  persistRevision(
    input: PreparedActionRevisionPersistenceInput,
  ): Promise<PreparedActionRevisionFinalizationResult>;
  preparedApprovalId(toolCall: ToolCallRecord): string;
  publishApproval(input: {
    approval: ApprovalRecord;
    toolCall: ToolCallRecord;
  }): Promise<PreparedApprovalPublicationResult>;
  assertApprovalCurrent(toolCall: ToolCallRecord, approvedInput: JsonObject): Promise<void>;
  assertDispatchCurrent(toolCall: ToolCallRecord, approvedInput: JsonObject): Promise<void>;
  finalizeRevision(
    link: PreparedActionRevisionLink,
  ): Promise<PreparedActionRevisionFinalizationResult>;
  revisionContext(toolCall: ToolCallRecord): Promise<PreparedActionRevisionContext>;
  reviewProjection(toolCall: ToolCallRecord): Promise<PreparedActionReviewProjection | undefined>;
}

export function actionEnvelopeWithPreparedAction(
  envelope: ActionEnvelope,
  prepared: PreparedActionSubmission,
  hashEnvelope: (value: unknown) => string,
): ActionEnvelope {
  const { envelopeHash: _previousEnvelopeHash, ...baseEnvelope } = envelope;
  const material: Omit<ActionEnvelope, 'envelopeHash'> = {
    ...baseEnvelope,
    input: prepared.effectiveInput,
    inputHash: hashEnvelope(prepared.effectiveInput),
    preparedAction: prepared.binding,
    resources: prepared.resources.length ? prepared.resources : undefined,
  };
  return { ...material, envelopeHash: hashEnvelope(material) };
}

export class InvalidActionInputError extends Error {
  readonly code = 'invalid_action_input';

  constructor(
    message: string,
    readonly issues: Array<{ code: string; message: string; path: string[] }> = [],
  ) {
    super(message);
    this.name = 'InvalidActionInputError';
  }
}

export class ActionContractUnavailableError extends Error {
  readonly code = 'action_contract_unavailable';

  constructor(message: string) {
    super(message);
    this.name = 'ActionContractUnavailableError';
  }
}

export class PreparedIntentMismatchError extends Error {
  readonly code = 'prepared_intent_mismatch';

  constructor(message: string) {
    super(message);
    this.name = 'PreparedIntentMismatchError';
  }
}

export class ProviderStateChangedError extends Error {
  readonly code = 'provider_state_changed';

  constructor(message: string) {
    super(message);
    this.name = 'ProviderStateChangedError';
  }
}

export type PreparedActionEditDisposition = 'original_only' | 'revision_required';

/**
 * Connector-neutral signal raised when an immutable, server-prepared action
 * receives an inline edit. Transport-specific codes and copy are projected by
 * the private edition; Community never needs to know a connector or runtime.
 */
export class PreparedActionEditConflict extends Error {
  constructor(readonly disposition: PreparedActionEditDisposition) {
    super('Inline editing is not permitted for this server-prepared action.');
    this.name = 'PreparedActionEditConflict';
  }
}
