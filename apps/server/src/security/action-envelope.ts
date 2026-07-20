import type {
  ActionActor,
  ActionEnvelope,
  ActionExecutionMode,
  ActionProtocol,
  AuthContext,
  JsonObject,
  SubmitToolCallRequest,
} from '../models';
import { hashJson } from './crypto';

export interface NormalizeActionEnvelopeInput {
  actor: string;
  auth?: AuthContext;
  request: SubmitToolCallRequest;
}

export function normalizeActionEnvelope(input: NormalizeActionEnvelopeInput): ActionEnvelope {
  const request = input.request;
  const action = request.action;
  const metadata = request.metadata ?? {};
  const protocol = action?.protocol ?? protocolFromMetadata(metadata);
  const source = {
    type: action?.source?.type ?? sourceTypeFromMetadata(metadata, protocol),
    id: action?.source?.id ?? stringFromMetadata(metadata, 'sourceId') ?? stringFromMetadata(metadata, 'mcpServer'),
    name: action?.source?.name ?? stringFromMetadata(metadata, 'source') ?? stringFromMetadata(metadata, 'mcpServer'),
    metadata: action?.source?.metadata,
  };
  const contextMetadata = isJsonObject(action?.context?.metadata) ? action?.context?.metadata : undefined;
  const envelopeWithoutHash = {
    actor: actionActor(input.actor, input.auth),
    agent: {
      id: request.agentId,
      name: stringFromMetadata(metadata, 'agentName'),
    },
    context: {
      dataClassification: action?.context?.dataClassification,
      metadata: contextMetadata,
      reason: action?.context?.reason ?? request.reason,
      reversibility: action?.context?.reversibility,
      risk: action?.context?.risk,
      sideEffects: action?.context?.sideEffects,
    },
    executionMode: action?.executionMode ?? executionModeFromMetadata(metadata),
    input: request.input,
    inputHash: hashJson(request.input),
    operation: {
      kind: action?.operation?.kind,
      name: action?.operation?.name ?? stringFromMetadata(metadata, 'operation') ?? request.toolName,
    },
    protocol,
    resources: action?.resources?.length ? action.resources : undefined,
    source,
    toolName: request.toolName,
    version: 'actionproxy.action.v1' as const,
  };

  return {
    ...envelopeWithoutHash,
    envelopeHash: hashJson(envelopeWithoutHash),
  };
}

export function reviewHashFor(input: {
  actionEnvelopeHash: string;
  approvalId: string;
  policyVersionHash?: string;
  toolCallId: string;
}): string {
  return hashJson({
    actionEnvelopeHash: input.actionEnvelopeHash,
    approvalId: input.approvalId,
    policyVersionHash: input.policyVersionHash,
    toolCallId: input.toolCallId,
    version: 'actionproxy.review.v1',
  });
}

export function actionEnvelopeForInput(envelope: ActionEnvelope, input: JsonObject): ActionEnvelope {
  const updated = {
    ...envelope,
    input,
    inputHash: hashJson(input),
  };
  return {
    ...updated,
    envelopeHash: hashJson({ ...updated, envelopeHash: undefined }),
  };
}

function actionActor(actor: string, auth: AuthContext | undefined): ActionActor {
  if (!auth || auth.authProvider === 'none') {
    return {
      id: actor,
      type: 'local',
    };
  }

  return {
    authProvider: auth.authProvider,
    displayName: auth.displayName,
    email: auth.email,
    id: auth.principalId,
    type: auth.principalType,
  };
}

function protocolFromMetadata(metadata: JsonObject): ActionProtocol {
  if (metadata.source === 'mcp-wrapper' || typeof metadata.mcpServer === 'string' || typeof metadata.mcpTool === 'string') {
    return 'mcp';
  }
  if (metadata.source === 'cli') return 'cli';
  if (metadata.source === 'webhook') return 'webhook';
  return 'actionproxy_http';
}

function sourceTypeFromMetadata(metadata: JsonObject, protocol: ActionProtocol): string {
  if (typeof metadata.source === 'string') return metadata.source;
  if (protocol === 'mcp') return 'mcp-wrapper';
  return 'http';
}

function executionModeFromMetadata(metadata: JsonObject): ActionExecutionMode {
  if (metadata.actionproxyExecution !== undefined) {
    return metadata.actionproxyExecution === 'external' ? 'external_grant' : 'local_mock';
  }
  if (isJsonObject(metadata.actionproxy) && metadata.actionproxy.executionMode !== undefined) {
    return metadata.actionproxy.executionMode === 'external' ? 'external_grant' : 'local_mock';
  }
  return 'local_mock';
}

function stringFromMetadata(metadata: JsonObject, key: string): string | undefined {
  const value = metadata[key];
  return typeof value === 'string' && value.trim() ? value : undefined;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
