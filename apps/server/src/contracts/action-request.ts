import type {
  ActionActor,
  ActionExecutionMode,
  ActionOperationKind,
  ActionProtocol,
  ActionResourceHint,
  AuthContext,
  JsonObject,
  SubmitToolCallRequest,
} from '../models';
import { sha256Hex } from '../security/crypto';

export const CANONICAL_ACTION_REQUEST_VERSION = 'actionproxy.action-request.v1' as const;
export const CANONICAL_JSON_VERSION = 'actionproxy.canonical-json.v1' as const;

export type TrustClassification = 'asserted' | 'derived' | 'externally_verified' | 'trusted';

export interface FieldProvenance {
  source: string;
  trust: TrustClassification;
}

export interface SourcedField<T> {
  present: boolean;
  provenance: FieldProvenance;
  value?: T;
}

export type CanonicalPolicyField =
  | 'amount'
  | 'approverGroup'
  | 'currency'
  | 'customerVisible'
  | 'operationKind'
  | 'recipientDomain'
  | 'risk';

export type CanonicalPolicyContext = Record<CanonicalPolicyField, SourcedField<unknown>>;

export interface CanonicalActionRequest {
  actor: SourcedField<ActionActor>;
  agent: SourcedField<{ id: string; name?: string; verification: 'asserted' | 'externally_verified' }>;
  arguments: SourcedField<JsonObject>;
  context: {
    action: SourcedField<JsonObject>;
    metadata: SourcedField<JsonObject>;
    policy: CanonicalPolicyContext;
    rationale: SourcedField<string>;
  };
  credentialReference: SourcedField<string>;
  environment: SourcedField<'local' | 'self_hosted'>;
  executionMode: SourcedField<ActionExecutionMode>;
  idempotencyKey: SourcedField<string>;
  integrity: {
    algorithm: 'sha256';
    canonicalization: typeof CANONICAL_JSON_VERSION;
    decisionInputHash: string;
    requestHash: string;
  };
  operation: SourcedField<{ kind?: ActionOperationKind; name: string }>;
  receivedAt: SourcedField<string>;
  requestId: SourcedField<string>;
  resources: SourcedField<ActionResourceHint[]>;
  session: SourcedField<{ runId?: string; sessionId?: string }>;
  source: SourcedField<{ adapterId?: string; type: 'http' | 'mcp' }>;
  sourceProtocol: SourcedField<ActionProtocol>;
  tenant: SourcedField<{ id: string }>;
  tool: SourcedField<{ name: string }>;
  version: typeof CANONICAL_ACTION_REQUEST_VERSION;
}

export interface CanonicalActionRequestEvidence {
  actor: SourcedField<ActionActor>;
  agent: CanonicalActionRequest['agent'];
  environment: CanonicalActionRequest['environment'];
  session: CanonicalActionRequest['session'];
  source: CanonicalActionRequest['source'];
  sourceProtocol: CanonicalActionRequest['sourceProtocol'];
  tenant: CanonicalActionRequest['tenant'];
  version: typeof CANONICAL_ACTION_REQUEST_VERSION;
}

export interface HttpActionIngress {
  environment: 'local' | 'self_hosted';
  protocol: 'actionproxy_http';
  source: 'http';
}

export interface McpActionIngress {
  adapterId: string;
  adapterSource: string;
  adapterTrust: 'derived' | 'externally_verified' | 'trusted';
  agent: {
    id: string;
    name?: string;
    source: string;
    trust: 'derived' | 'externally_verified';
  };
  environment: 'local' | 'self_hosted';
  idempotency: {
    source: string;
    trust: 'derived' | 'externally_verified' | 'trusted';
  };
  protocol: 'mcp';
  session?: {
    runId?: string;
    sessionId?: string;
    source: string;
    trust: 'derived' | 'externally_verified' | 'trusted';
  };
  source: 'mcp';
}

export type CanonicalActionIngress = HttpActionIngress | McpActionIngress;

export interface NormalizeActionRequestInput {
  auth?: AuthContext;
  idempotencyKey?: string;
  ingress: CanonicalActionIngress;
  receivedAt: string;
  request: SubmitToolCallRequest;
  requestId: string;
  workspaceId: string;
}

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalizationError';
  }
}

export class DuplicateJsonKeyError extends CanonicalizationError {
  constructor(key: string, path: string) {
    super(`Duplicate JSON key ${JSON.stringify(key)} at ${path}.`);
    this.name = 'DuplicateJsonKeyError';
  }
}

export function normalizeActionRequest(input: NormalizeActionRequestInput): CanonicalActionRequest {
  if (input.auth && input.auth.workspaceId !== input.workspaceId) {
    throw new CanonicalizationError('Authenticated tenant does not match the server-resolved workspace.');
  }
  const request = input.request;
  const metadata = request.metadata ?? {};
  const actor = actorField(request, input.auth);
  const policy = deriveCanonicalPolicyContext(request.toolName, request.input, input.auth);
  const base = {
    actor,
    agent: input.ingress.source === 'mcp'
      ? sourced(
          {
            id: input.ingress.agent.id,
            name: input.ingress.agent.name,
            verification: input.ingress.agent.trust === 'externally_verified'
              ? 'externally_verified' as const
              : 'asserted' as const,
          },
          input.ingress.agent.trust,
          input.ingress.agent.source,
        )
      : sourced(
          {
            id: request.agentId,
            name: optionalString(metadata.agentName),
            verification: 'asserted' as const,
          },
          'asserted',
          'body.agentId',
        ),
    arguments: sourced(request.input, 'asserted', 'body.input'),
    context: {
      action: sourced(request.action?.context ?? {}, 'asserted', 'body.action.context'),
      metadata: sourced(metadata, 'asserted', 'body.metadata'),
      policy,
      rationale: sourced(request.reason, 'asserted', 'body.reason'),
    },
    credentialReference: absent<string>('trusted', 'server.credential-resolver.not-resolved'),
    environment: sourced(input.ingress.environment, 'trusted', 'server.deployment.mode'),
    executionMode: sourced(
      request.action?.executionMode ?? executionModeFromMetadata(metadata),
      'asserted',
      request.action?.executionMode ? 'body.action.executionMode' : 'body.metadata.executionMode',
    ),
    idempotencyKey: input.idempotencyKey
      ? sourced(
          input.idempotencyKey,
          input.ingress.source === 'mcp' ? input.ingress.idempotency.trust : 'asserted',
          input.ingress.source === 'mcp' ? input.ingress.idempotency.source : 'header.idempotency-key',
        )
      : absent<string>(
          input.ingress.source === 'mcp' ? input.ingress.idempotency.trust : 'asserted',
          input.ingress.source === 'mcp' ? input.ingress.idempotency.source : 'header.idempotency-key',
        ),
    operation: sourced(
      { name: request.toolName },
      'derived',
      'normalizer.tool-name-to-operation',
    ),
    receivedAt: sourced(input.receivedAt, 'derived', 'server.clock'),
    requestId: sourced(input.requestId, 'derived', 'server.request-id'),
    resources: request.action?.resources?.length
      ? sourced(request.action.resources, 'asserted', 'body.action.resources')
      : absent<ActionResourceHint[]>('asserted', 'body.action.resources'),
    session: input.ingress.source === 'mcp' && input.ingress.session
      ? sourced(
          { runId: input.ingress.session.runId, sessionId: input.ingress.session.sessionId },
          input.ingress.session.trust,
          input.ingress.session.source,
        )
      : sessionField(metadata),
    source: sourced(
      input.ingress.source === 'mcp'
        ? { adapterId: input.ingress.adapterId, type: 'mcp' as const }
        : { type: 'http' as const },
      input.ingress.source === 'mcp' ? input.ingress.adapterTrust : 'derived',
      input.ingress.source === 'mcp' ? input.ingress.adapterSource : 'http.route-adapter',
    ),
    sourceProtocol: sourced(
      input.ingress.protocol,
      'derived',
      input.ingress.source === 'mcp' ? 'mcp.transport-adapter' : 'http.route-adapter',
    ),
    tenant: sourced(
      { id: input.workspaceId },
      input.auth && input.auth.authProvider !== 'none' ? 'externally_verified' : 'trusted',
      input.auth && input.auth.authProvider !== 'none' ? 'auth.workspaceId' : 'server.workspaceId',
    ),
    tool: sourced({ name: request.toolName }, 'asserted', 'body.toolName'),
    version: CANONICAL_ACTION_REQUEST_VERSION,
  };

  // Validate every asserted JSON field before any hash becomes authoritative.
  canonicalJsonStringify(base.arguments.value);
  canonicalJsonStringify(base.context.action.value);
  canonicalJsonStringify(base.context.metadata.value);
  if (base.resources.present) canonicalJsonStringify(base.resources.value);

  const decisionInputHash = hashCanonicalJson(decisionInputMaterial(base));
  const requestHash = hashCanonicalJson(base);
  return {
    ...base,
    integrity: {
      algorithm: 'sha256',
      canonicalization: CANONICAL_JSON_VERSION,
      decisionInputHash,
      requestHash,
    },
  };
}

export function deriveCanonicalPolicyContext(
  _toolName: string,
  input: JsonObject,
  auth?: AuthContext,
): CanonicalPolicyContext {
  const amount = finiteNumber(input.amount) ?? finiteNumber(input.amountCents);
  const currency = optionalString(input.currency);
  const recipientDomain = derivedRecipientDomain(input);
  return {
    amount: amount === undefined
      ? absent<number>('derived', 'arguments.amount|amountCents')
      : sourced(amount, 'derived', 'arguments.amount|amountCents'),
    approverGroup: absent<string>(
      auth && auth.authProvider !== 'none' ? 'externally_verified' : 'trusted',
      auth && auth.authProvider !== 'none' ? 'auth.groups.no-single-group-selected' : 'server.no-verified-approver-group',
    ),
    currency: currency
      ? sourced(currency, 'derived', 'arguments.currency')
      : absent<string>('derived', 'arguments.currency'),
    customerVisible: absent<boolean>('trusted', 'server.customer-visibility.not-resolved'),
    operationKind: absent<ActionOperationKind>('derived', 'normalizer.operation-kind.unmapped'),
    recipientDomain: recipientDomain
      ? sourced(recipientDomain, 'derived', 'arguments.recipients')
      : absent<string>('derived', 'arguments.recipients'),
    risk: absent<string>('trusted', 'policy.rule.risk'),
  };
}

export function canonicalActionRequestEvidence(request: CanonicalActionRequest): CanonicalActionRequestEvidence {
  return {
    actor: request.actor,
    agent: request.agent,
    environment: request.environment,
    session: request.session,
    source: request.source,
    sourceProtocol: request.sourceProtocol,
    tenant: request.tenant,
    version: request.version,
  };
}

export function canonicalJsonStringify(value: unknown): string {
  return serializeCanonicalJson(value, '$', new Set<object>());
}

export function hashCanonicalJson(value: unknown): string {
  return sha256Hex(canonicalJsonStringify(value));
}

export function assertNoDuplicateJsonKeys(json: string): void {
  let index = 0;

  function whitespace(): void {
    while (/\s/u.test(json[index] ?? '')) index += 1;
  }

  function value(path: string): void {
    whitespace();
    const token = json[index];
    if (token === '{') return object(path);
    if (token === '[') return array(path);
    if (token === '"') {
      string();
      return;
    }
    if (json.startsWith('true', index)) return void (index += 4);
    if (json.startsWith('false', index)) return void (index += 5);
    if (json.startsWith('null', index)) return void (index += 4);
    const number = json.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u)?.[0];
    if (number) return void (index += number.length);
    throw new CanonicalizationError(`Invalid JSON token at byte ${index}.`);
  }

  function object(path: string): void {
    index += 1;
    whitespace();
    const keys = new Set<string>();
    if (json[index] === '}') return void (index += 1);
    while (index < json.length) {
      whitespace();
      if (json[index] !== '"') throw new CanonicalizationError(`Expected object key at byte ${index}.`);
      const key = string();
      if (keys.has(key)) throw new DuplicateJsonKeyError(key, path);
      keys.add(key);
      whitespace();
      if (json[index] !== ':') throw new CanonicalizationError(`Expected colon at byte ${index}.`);
      index += 1;
      value(`${path}.${key}`);
      whitespace();
      if (json[index] === '}') return void (index += 1);
      if (json[index] !== ',') throw new CanonicalizationError(`Expected comma at byte ${index}.`);
      index += 1;
    }
    throw new CanonicalizationError(`Unterminated object at ${path}.`);
  }

  function array(path: string): void {
    index += 1;
    whitespace();
    if (json[index] === ']') return void (index += 1);
    let item = 0;
    while (index < json.length) {
      value(`${path}[${item}]`);
      item += 1;
      whitespace();
      if (json[index] === ']') return void (index += 1);
      if (json[index] !== ',') throw new CanonicalizationError(`Expected comma at byte ${index}.`);
      index += 1;
    }
    throw new CanonicalizationError(`Unterminated array at ${path}.`);
  }

  function string(): string {
    const start = index;
    index += 1;
    while (index < json.length) {
      const token = json[index];
      if (token === '"') {
        index += 1;
        return JSON.parse(json.slice(start, index)) as string;
      }
      if (token === '\\') {
        index += 2;
        continue;
      }
      if (token === undefined || token.charCodeAt(0) < 0x20) {
        throw new CanonicalizationError(`Invalid JSON string at byte ${index}.`);
      }
      index += 1;
    }
    throw new CanonicalizationError(`Unterminated JSON string at byte ${start}.`);
  }

  value('$');
  whitespace();
  if (index !== json.length) throw new CanonicalizationError(`Unexpected JSON content at byte ${index}.`);
}

function decisionInputMaterial(input: Omit<CanonicalActionRequest, 'integrity'>): unknown {
  return {
    actor: input.actor,
    agent: input.agent,
    arguments: input.arguments,
    context: { policy: input.context.policy },
    credentialReference: input.credentialReference,
    environment: input.environment,
    executionMode: input.executionMode,
    operation: input.operation,
    resources: input.resources,
    source: input.source,
    sourceProtocol: input.sourceProtocol,
    tenant: input.tenant,
    tool: input.tool,
    version: input.version,
  };
}

function actorField(request: SubmitToolCallRequest, auth?: AuthContext): SourcedField<ActionActor> {
  if (auth) {
    return sourced(
      {
        authProvider: auth.authProvider,
        displayName: auth.displayName,
        email: auth.email,
        id: auth.principalId,
        type: auth.principalType,
      },
      auth.authProvider === 'none' ? 'trusted' : 'externally_verified',
      auth.authProvider === 'none' ? 'server.local-auth.principal' : 'auth.principal',
    );
  }
  return sourced({ id: request.requestedBy, type: 'local' }, 'asserted', 'body.requestedBy');
}

function sessionField(metadata: JsonObject): SourcedField<{ runId?: string; sessionId?: string }> {
  const runId = optionalString(metadata.runId);
  const sessionId = optionalString(metadata.sessionId);
  if (!runId && !sessionId) return absent('asserted', 'body.metadata.runId|sessionId');
  return sourced({ runId, sessionId }, 'asserted', 'body.metadata.runId|sessionId');
}

function sourced<T>(value: T, trust: TrustClassification, source: string): SourcedField<T> {
  return { present: true, provenance: { source, trust }, value };
}

function absent<T>(trust: TrustClassification, source: string): SourcedField<T> {
  return { present: false, provenance: { source, trust } };
}

function serializeCanonicalJson(value: unknown, path: string, seen: Set<object>): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new CanonicalizationError(`Non-finite number at ${path}.`);
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (value === undefined) throw new CanonicalizationError(`Undefined value at ${path}.`);
  if (typeof value !== 'object') throw new CanonicalizationError(`Unsupported ${typeof value} value at ${path}.`);
  if (seen.has(value)) throw new CanonicalizationError(`Cyclic value at ${path}.`);
  seen.add(value);
  try {
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new CanonicalizationError(`Symbol-keyed property at ${path}.`);
    }
    if (Array.isArray(value)) {
      const items: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.prototype.hasOwnProperty.call(value, index)) {
          throw new CanonicalizationError(`Sparse array element at ${path}[${index}].`);
        }
        items.push(serializeCanonicalJson(value[index], `${path}[${index}]`, seen));
      }
      return `[${items.join(',')}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new CanonicalizationError(`Non-plain object at ${path}.`);
    }
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
    return `{${entries
      .map(([key, item]) => `${JSON.stringify(key)}:${serializeCanonicalJson(item, `${path}.${key}`, seen)}`)
      .join(',')}}`;
  } finally {
    seen.delete(value);
  }
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

function finiteNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function derivedRecipientDomain(input: JsonObject): 'external' | undefined {
  const recipients = [input.to, input.cc, input.bcc, input.recipient];
  return recipients.some(hasRecipient) ? 'external' : undefined;
}

function hasRecipient(value: unknown): boolean {
  if (typeof value === 'string') return value.trim().length > 0;
  return Array.isArray(value) && value.some((item) => typeof item === 'string' && item.trim().length > 0);
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
