import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { AuthContext, SubmitToolCallRequest } from '../models';
import {
  CanonicalizationError,
  DuplicateJsonKeyError,
  assertNoDuplicateJsonKeys,
  canonicalJsonStringify,
  hashCanonicalJson,
  normalizeActionRequest,
} from './action-request';

const verifiedAuth: AuthContext = {
  authProvider: 'oidc_jwt',
  displayName: 'Verified User',
  email: 'verified@example.com',
  groups: ['finance-approvers'],
  principalId: 'subject_123',
  principalType: 'user',
  scopes: ['tool_call:submit'],
  workspaceId: 'workspace_verified',
};

const vectors = JSON.parse(
  fs.readFileSync(path.resolve('../../fixtures/contracts/action-request-v1.json'), 'utf8'),
) as {
  canonicalJsonVectors: Array<{ canonical: string; sha256: string; values: unknown[] }>;
  httpRequestVector: {
    expected: { decisionInputHash: string; requestHash: string };
    ingress: { environment: 'self_hosted'; protocol: 'actionproxy_http'; source: 'http' };
    receivedAt: string;
    request: SubmitToolCallRequest;
    requestId: string;
    workspaceId: string;
  };
  rawIngressRejections: Array<{ json: string }>;
};

describe('canonical JSON v1', () => {
  it('has stable golden serialization and hashes for ordering, arrays, Unicode, null, and numbers', () => {
    for (const vector of vectors.canonicalJsonVectors) {
      for (const value of vector.values) {
        expect(canonicalJsonStringify(value)).toBe(vector.canonical);
        expect(hashCanonicalJson(value)).toBe(vector.sha256);
      }
    }
    expect(canonicalJsonStringify({ z: null, a: [3, -0, 'é'] })).toBe('{"a":[3,0,"é"],"z":null}');
    expect(hashCanonicalJson({ text: 'é' })).not.toBe(hashCanonicalJson({ text: 'e\u0301' }));
    expect(hashCanonicalJson({ value: null })).not.toBe(hashCanonicalJson({}));
  });

  it('rejects values that JSON ingress cannot represent unambiguously', () => {
    expect(() => canonicalJsonStringify([undefined])).toThrow(CanonicalizationError);
    expect(() => canonicalJsonStringify(new Array(1))).toThrow('Sparse array element at $[0]');
    expect(() => canonicalJsonStringify([, 'value'])).toThrow('Sparse array element at $[0]');
    expect(() => canonicalJsonStringify({ [Symbol('hidden')]: 'value' })).toThrow('Symbol-keyed property at $');
    const symbolArray = ['value'];
    Object.assign(symbolArray, { [Symbol('hidden')]: true });
    expect(() => canonicalJsonStringify(symbolArray)).toThrow('Symbol-keyed property at $');
    expect(() => canonicalJsonStringify({ value: Number.NaN })).toThrow('Non-finite number');
    expect(() => canonicalJsonStringify({ value: 1n })).toThrow('Unsupported bigint');
    expect(() => canonicalJsonStringify({ value: new Date('2026-07-11T00:00:00.000Z') })).toThrow('Non-plain object');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalJsonStringify(cyclic)).toThrow('Cyclic value');
  });

  it('rejects duplicate object keys at any nesting level', () => {
    expect(() => assertNoDuplicateJsonKeys('{"tool":"one","tool":"two"}')).toThrow(DuplicateJsonKeyError);
    for (const vector of vectors.rawIngressRejections) {
      expect(() => assertNoDuplicateJsonKeys(vector.json)).toThrow(DuplicateJsonKeyError);
    }
    expect(() => assertNoDuplicateJsonKeys('{"input":{"to":"a","to":"b"}}')).toThrow(
      'Duplicate JSON key "to" at $.input',
    );
    expect(() => assertNoDuplicateJsonKeys('{"left":{"id":1},"right":{"id":2}}')).not.toThrow();
    expect(() => assertNoDuplicateJsonKeys('{"a":1,"\\u0061":2}')).toThrow('Duplicate JSON key "a" at $');
  });
});

describe('HTTP canonical action request v1', () => {
  it('matches the stable golden decision and request hashes', () => {
    const normalized = normalizeActionRequest(vectors.httpRequestVector);

    expect(normalized.integrity).toEqual({
      algorithm: 'sha256',
      canonicalization: 'actionproxy.canonical-json.v1',
      ...vectors.httpRequestVector.expected,
    });
  });

  it('derives trusted HTTP, tenant, actor, and environment fields while labeling agent and hints asserted', () => {
    const normalized = normalizeActionRequest({
      auth: verifiedAuth,
      ingress: { environment: 'self_hosted', protocol: 'actionproxy_http', source: 'http' },
      receivedAt: '2026-07-11T00:00:00.000Z',
      request: forgedRequest(),
      requestId: 'request_verified',
      workspaceId: verifiedAuth.workspaceId,
    });

    expect(normalized.tenant).toMatchObject({
      provenance: { source: 'auth.workspaceId', trust: 'externally_verified' },
      value: { id: 'workspace_verified' },
    });
    expect(normalized.actor).toMatchObject({
      provenance: { source: 'auth.principal', trust: 'externally_verified' },
      value: { id: 'subject_123' },
    });
    expect(normalized.agent).toMatchObject({
      provenance: { trust: 'asserted' },
      value: { id: 'forged-agent', verification: 'asserted' },
    });
    expect(normalized.sourceProtocol).toMatchObject({
      provenance: { trust: 'derived' },
      value: 'actionproxy_http',
    });
    expect(normalized.environment).toMatchObject({
      provenance: { trust: 'trusted' },
      value: 'self_hosted',
    });
    expect(normalized.context.policy.risk.present).toBe(false);
    expect(normalized.context.policy.operationKind.present).toBe(false);
    expect(normalized.context.policy.customerVisible.present).toBe(false);
  });

  it('rejects inconsistent trusted auth and server workspace state', () => {
    expect(() =>
      normalizeActionRequest({
        auth: verifiedAuth,
        ingress: { environment: 'self_hosted', protocol: 'actionproxy_http', source: 'http' },
        receivedAt: '2026-07-11T00:00:00.000Z',
        request: forgedRequest(),
        requestId: 'request_tenant_mismatch',
        workspaceId: 'workspace_forged',
      }),
    ).toThrow('Authenticated tenant does not match the server-resolved workspace');
  });

  it('records the configured single-user tunnel identity as server-trusted, not externally verified', () => {
    const normalized = normalizeActionRequest({
      auth: {
        ...verifiedAuth,
        authProvider: 'tunnel_single_user',
        clientId: 'tunnel_0123456789abcdef0123456789abcdef',
        groups: [],
        principalId: 'local-admin',
      },
      ingress: { environment: 'local', protocol: 'actionproxy_http', source: 'http' },
      receivedAt: '2026-08-09T00:00:00.000Z',
      request: forgedRequest(),
      requestId: 'request_tunnel_single_user',
      workspaceId: verifiedAuth.workspaceId,
    });

    expect(normalized.actor).toMatchObject({
      provenance: {
        source: 'server.tunnel-single-user.principal',
        trust: 'trusted',
      },
      value: { authProvider: 'tunnel_single_user', id: 'local-admin' },
    });
    expect(normalized.tenant).toMatchObject({
      provenance: {
        source: 'server.tunnel-single-user.workspaceId',
        trust: 'trusted',
      },
      value: { id: verifiedAuth.workspaceId },
    });
    expect(normalized.context.policy.approverGroup).toMatchObject({
      present: false,
      provenance: {
        source: 'server.tunnel-single-user.no-approver-group',
        trust: 'trusted',
      },
    });
  });

  it('uses server-owned prepared-action governance instead of caller-asserted policy and execution hints', () => {
    const request = forgedRequest();
    request.action = {
      context: { risk: 'caller_claimed_safe' },
      executionMode: 'local_mock',
      operation: { kind: 'read', name: 'caller-claimed-read' },
      resources: [{ id: 'caller-resource', type: 'caller_asserted' }],
    };
    const normalized = normalizeActionRequest({
      auth: verifiedAuth,
      ingress: { environment: 'self_hosted', protocol: 'actionproxy_http', source: 'http' },
      receivedAt: '2026-08-10T00:00:00.000Z',
      request,
      requestId: 'request_prepared_governance',
      trustedCredentialReference: {
        source: 'prepared-intent:intent_1',
        value: 'connection_google_company_1',
      },
      trustedExecutionMode: {
        source: 'action-contract:google.drive.share_file@1',
        value: 'external_grant',
      },
      trustedOperation: {
        source: 'action-contract:google.drive.share_file@1',
        value: { kind: 'write', name: 'google.drive.share_file' },
      },
      trustedPolicy: {
        customerVisible: true,
        operationKind: 'write',
        risk: 'external_write',
        source: 'action-contract:google.drive.share_file@1',
      },
      trustedResources: {
        source: 'action-contract:google.drive.share_file@1',
        value: [{ id: 'file_1', type: 'drive_file' }],
      },
      workspaceId: verifiedAuth.workspaceId,
    });

    expect(normalized.credentialReference).toMatchObject({
      provenance: { source: 'prepared-intent:intent_1', trust: 'trusted' },
      value: 'connection_google_company_1',
    });
    expect(normalized.executionMode).toMatchObject({
      provenance: { source: 'action-contract:google.drive.share_file@1', trust: 'trusted' },
      value: 'external_grant',
    });
    expect(normalized.operation).toMatchObject({
      provenance: { source: 'action-contract:google.drive.share_file@1', trust: 'trusted' },
      value: { kind: 'write', name: 'google.drive.share_file' },
    });
    expect(normalized.context.policy).toMatchObject({
      customerVisible: {
        present: true,
        provenance: { source: 'action-contract:google.drive.share_file@1', trust: 'trusted' },
        value: true,
      },
      operationKind: {
        present: true,
        provenance: { source: 'action-contract:google.drive.share_file@1', trust: 'trusted' },
        value: 'write',
      },
      risk: {
        present: true,
        provenance: { source: 'action-contract:google.drive.share_file@1', trust: 'trusted' },
        value: 'external_write',
      },
    });
    expect(normalized.resources).toMatchObject({
      provenance: { source: 'action-contract:google.drive.share_file@1', trust: 'derived' },
      value: [{ id: 'file_1', type: 'drive_file' }],
    });
    expect(normalized.operation.value).not.toEqual(request.action.operation);
    expect(normalized.resources.value).not.toEqual(request.action.resources);
  });
});

describe('MCP canonical action request v1 adapter', () => {
  it('derives protocol, adapter, agent, session, idempotency, tenant, actor, and environment from transport state', () => {
    const normalized = normalizeActionRequest({
      auth: { ...verifiedAuth, clientId: 'chatgpt-client-1' },
      idempotencyKey: 'mcp-v1:request-hash',
      ingress: {
        adapterId: 'oauth-client:chatgpt-client-1',
        adapterSource: 'oauth.client_id',
        adapterTrust: 'externally_verified',
        agent: {
          id: 'mcp:chatgpt-client-1',
          name: 'Authenticated MCP client',
          source: 'oauth.client_id',
          trust: 'externally_verified',
        },
        environment: 'self_hosted',
        idempotency: { source: 'mcp.session+jsonrpc-id', trust: 'derived' },
        protocol: 'mcp',
        session: {
          sessionId: 'session-server-created',
          source: 'mcp.signed-session',
          trust: 'trusted',
        },
        source: 'mcp',
      },
      receivedAt: '2026-07-12T00:00:00.000Z',
      request: forgedRequest(),
      requestId: 'request_mcp_verified',
      workspaceId: verifiedAuth.workspaceId,
    });

    expect(normalized.tenant.value).toEqual({ id: 'workspace_verified' });
    expect(normalized.actor.value?.id).toBe('subject_123');
    expect(normalized.agent).toMatchObject({
      provenance: { source: 'oauth.client_id', trust: 'externally_verified' },
      value: { id: 'mcp:chatgpt-client-1', verification: 'externally_verified' },
    });
    expect(normalized.source).toMatchObject({
      provenance: { source: 'oauth.client_id', trust: 'externally_verified' },
      value: { adapterId: 'oauth-client:chatgpt-client-1', type: 'mcp' },
    });
    expect(normalized.sourceProtocol.value).toBe('mcp');
    expect(normalized.environment.value).toBe('self_hosted');
    expect(normalized.session).toMatchObject({
      provenance: { source: 'mcp.signed-session', trust: 'trusted' },
      value: { sessionId: 'session-server-created' },
    });
    expect(normalized.idempotencyKey).toMatchObject({
      provenance: { source: 'mcp.session+jsonrpc-id', trust: 'derived' },
      value: 'mcp-v1:request-hash',
    });

    expect(normalized.context.metadata.value).toMatchObject({ tenantId: 'forged-tenant' });
    expect(normalized.tenant.value).not.toEqual({ id: 'forged-tenant' });
    expect(normalized.agent.value?.id).not.toBe('forged-agent');
    expect(normalized.sourceProtocol.value).toBe('mcp');
  });

  it('keeps MCP transport identity and idempotency out of caller metadata authority', () => {
    const first = normalizeActionRequest({
      auth: { ...verifiedAuth, clientId: 'client-a' },
      idempotencyKey: 'mcp-v1:key-a',
      ingress: {
        adapterId: 'oauth-client:client-a',
        adapterSource: 'oauth.client_id',
        adapterTrust: 'externally_verified',
        agent: { id: 'mcp:client-a', source: 'oauth.client_id', trust: 'externally_verified' },
        environment: 'self_hosted',
        idempotency: { source: 'mcp.session+jsonrpc-id', trust: 'derived' },
        protocol: 'mcp',
        source: 'mcp',
      },
      receivedAt: '2026-07-12T00:00:00.000Z',
      request: forgedRequest(),
      requestId: 'request_mcp_a',
      workspaceId: verifiedAuth.workspaceId,
    });
    const mutated = normalizeActionRequest({
      auth: { ...verifiedAuth, clientId: 'client-a' },
      idempotencyKey: 'mcp-v1:key-a',
      ingress: {
        adapterId: 'oauth-client:client-a',
        adapterSource: 'oauth.client_id',
        adapterTrust: 'externally_verified',
        agent: { id: 'mcp:client-a', source: 'oauth.client_id', trust: 'externally_verified' },
        environment: 'self_hosted',
        idempotency: { source: 'mcp.session+jsonrpc-id', trust: 'derived' },
        protocol: 'mcp',
        source: 'mcp',
      },
      receivedAt: '2026-07-12T00:00:00.000Z',
      request: {
        ...forgedRequest(),
        metadata: {
          ...forgedRequest().metadata,
          adapterId: 'forged-adapter',
          idempotencyKey: 'forged-key',
          sourceProtocol: 'actionproxy_http',
        },
      },
      requestId: 'request_mcp_a',
      workspaceId: verifiedAuth.workspaceId,
    });

    expect(mutated.source).toEqual(first.source);
    expect(mutated.sourceProtocol).toEqual(first.sourceProtocol);
    expect(mutated.idempotencyKey).toEqual(first.idempotencyKey);
    expect(mutated.tenant).toEqual(first.tenant);
    expect(mutated.actor).toEqual(first.actor);
  });
});

function forgedRequest(): SubmitToolCallRequest {
  return {
    action: {
      context: { risk: 'safe' },
      operation: { kind: 'read', name: 'forged.read' },
      protocol: 'mcp',
      source: { type: 'trusted-internal-adapter' },
    },
    agentId: 'forged-agent',
    input: { amount: 500, currency: 'USD', to: 'customer@example.com' },
    metadata: {
      actor: 'admin@example.com',
      agentVerification: 'externally_verified',
      customerVisible: false,
      environment: 'local',
      operationKind: 'read',
      riskKind: 'safe',
      source: 'mcp-wrapper',
      tenantId: 'forged-tenant',
    },
    reason: 'Forged context attempt',
    requestedBy: 'forged-actor@example.com',
    toolName: 'gmail.send_email',
  };
}
