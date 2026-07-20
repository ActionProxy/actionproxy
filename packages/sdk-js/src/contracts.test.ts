import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import * as publicApi from './index';
import { ActionProxyApiError, ActionProxyClient } from './index';
import type {
  ActionProxyFetch,
  ExecutionAttemptRecordV1,
  ExecutionAuthorizationEvidenceV1,
  JsonObject,
  SubmitToolCallInput,
} from './index';
import type { ActionProxyFetchResponse } from './types';

type ScenarioFlow =
  | 'submit'
  | 'submit-and-approve'
  | 'submit-and-mutate-external-input'
  | 'submit-and-report-unknown'
  | 'submit-and-run-external'
  | 'submit-conflict'
  | 'submit-twice'
  | 'submit-with-failing-provider';

interface ConformanceScenario {
  approval?: JsonObject;
  conflictingInput?: JsonObject;
  expected: Record<string, unknown> & {
    decision?: 'allow' | 'deny' | 'require_approval';
    httpStatus: number;
    toolCallStatus?: string;
  };
  fault?: { policyProvider: 'throws' };
  flow: ScenarioFlow;
  idempotencyKey?: string;
  mutatedInput?: JsonObject;
  name: string;
  outcome?: JsonObject;
  request: SubmitToolCallInput;
}

interface ConformanceFixture {
  contractVersions: {
    approvalAuthorization: string;
    canonicalRequest: string;
    decision: string;
    executionAttempt: string;
    executionAuthorization: string;
    executorCapabilities: string;
  };
  scenarios: ConformanceScenario[];
  version: string;
}

const fixtureDirectory = path.resolve(process.cwd(), '../../fixtures/contracts');
const actionRequestFixture = readFixture<{ canonicalization: string; version: string }>('action-request-v1.json');
const approvalFixture = readFixture<{ version: string }>('approval-authorization-v1.json');
const decisionFixture = readFixture<{ scenarios: Array<{ expected: { reasonCodes: string[] } }>; version: string }>(
  'decision-v1.json',
);
const attemptFixture = readFixture<{ reserved: unknown; version: string }>('execution-attempt-v1.json');
const authorizationFixture = readFixture<{ capabilities: unknown; projection: unknown; version: string }>(
  'execution-authorization-v1.json',
);
const conformanceFixture = readFixture<ConformanceFixture>('http-sdk-conformance-v1.json');

describe('frozen ActionProxy HTTP/SDK contracts', () => {
  it('consumes the frozen request, decision, approval, attempt, and executor evidence vocabulary', () => {
    expect(conformanceFixture.version).toBe('actionproxy.http-sdk-conformance.v1');
    expect(conformanceFixture.contractVersions).toEqual({
      approvalAuthorization: approvalFixture.version,
      canonicalRequest: actionRequestFixture.version,
      decision: decisionFixture.version,
      executionAttempt: attemptFixture.version,
      executionAuthorization: authorizationFixture.version,
      executorCapabilities: 'actionproxy.executor-capabilities.v1',
    });
    expect(actionRequestFixture.canonicalization).toBe('actionproxy.canonical-json.v1');
    expect(decisionFixture.scenarios.flatMap((scenario) => scenario.expected.reasonCodes)).toContain(
      'policy_outcome_require_approval',
    );

    const attempt = attemptFixture.reserved as ExecutionAttemptRecordV1;
    const authorizationEvidence = authorizationFixture.projection as ExecutionAuthorizationEvidenceV1;
    expect(attempt).toMatchObject({
      providerIdempotency: 'none',
      retryPolicy: 'never_automatic',
      version: conformanceFixture.contractVersions.executionAttempt,
    });
    expect(authorizationEvidence).toMatchObject({
      capabilities: authorizationFixture.capabilities,
      version: conformanceFixture.contractVersions.executionAuthorization,
    });
    expect(JSON.stringify(authorizationEvidence)).not.toContain('executionAuthorizationToken');

    const runtimeExports = Object.keys(publicApi);
    for (const forbiddenExport of [
      'ExecutionAuthorization',
      'buildExecutionAuthorizationBinding',
      'canonicalJsonStringify',
      'createExecutionAuthorizationAuthority',
      'hashCanonicalJson',
    ]) {
      expect(runtimeExports, forbiddenExport).not.toContain(forbiddenExport);
    }
  });

  it('keeps the shared scenario corpus closed and exhaustively recognized by the SDK harness', () => {
    expect(conformanceFixture.scenarios.map(({ flow, name }) => ({ flow, name }))).toEqual([
      { flow: 'submit', name: 'allow' },
      { flow: 'submit', name: 'deny' },
      { flow: 'submit', name: 'require-approval' },
      { flow: 'submit-and-approve', name: 'approval-execution' },
      { flow: 'submit-and-run-external', name: 'external-grant' },
      { flow: 'submit-twice', name: 'same-request-replay' },
      { flow: 'submit-conflict', name: 'payload-conflict' },
      { flow: 'submit-with-failing-provider', name: 'policy-provider-failure' },
      { flow: 'submit-and-mutate-external-input', name: 'external-input-mutation-rejection' },
      { flow: 'submit-and-report-unknown', name: 'unknown-outcome-non-retry' },
    ]);

    for (const testCase of conformanceFixture.scenarios) {
      switch (testCase.flow) {
        case 'submit':
        case 'submit-twice':
          expect(testCase.request.toolName, testCase.name).toBeTruthy();
          break;
        case 'submit-and-approve':
          expect(testCase.approval, testCase.name).toBeDefined();
          break;
        case 'submit-and-mutate-external-input':
          expect(testCase.mutatedInput, testCase.name).toBeDefined();
          break;
        case 'submit-and-report-unknown':
        case 'submit-and-run-external':
          expect(testCase.outcome, testCase.name).toBeDefined();
          break;
        case 'submit-conflict':
          expect(testCase.conflictingInput, testCase.name).toBeDefined();
          break;
        case 'submit-with-failing-provider':
          expect(testCase.fault, testCase.name).toEqual({ policyProvider: 'throws' });
          break;
        default:
          assertNever(testCase.flow);
      }
    }
  });

  it('passes allow, deny, approval-required, and provider-failure projections through without minting authority', async () => {
    for (const name of ['allow', 'deny', 'require-approval', 'policy-provider-failure']) {
      const testCase = scenario(name);
      const fetchMock = vi.fn<ActionProxyFetch>(async (_url, init) => {
        const body = JSON.parse(init?.body ?? '{}') as Record<string, unknown>;
        expect(body, name).toEqual(testCase.request);
        for (const forbidden of [
          'actor',
          'canonicalActionRequestHash',
          'canonicalDecisionInputHash',
          'environment',
          'executionAuthorization',
          'sourceProtocol',
          'tenantId',
          'workspaceId',
        ]) {
          expect(body, `${name}:${forbidden}`).not.toHaveProperty(forbidden);
        }
        return jsonResponse(submitProjection(testCase));
      });
      const client = new ActionProxyClient({ baseUrl: 'http://actionproxy.test', fetch: fetchMock });

      const result = await client.submitToolCall(testCase.request);

      expect(result).toMatchObject({
        decision: testCase.expected.decision,
        status: testCase.expected.toolCallStatus,
        toolCall: {
          canonicalActionRequestVersion: conformanceFixture.contractVersions.canonicalRequest,
          decisionTrace: {
            decisionV1: {
              outcome: testCase.expected.decision,
              version: conformanceFixture.contractVersions.decision,
            },
          },
        },
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    }
  });

  it('carries replay identity only in Idempotency-Key and surfaces payload conflict', async () => {
    const replayCase = scenario('same-request-replay');
    const conflictCase = scenario('payload-conflict');
    const seen = new Map<string, string>();
    const fetchMock = vi.fn<ActionProxyFetch>(async (_url, init) => {
      const key = init?.headers?.['idempotency-key'];
      expect(key).toBeTruthy();
      const body = init?.body ?? '';
      const previous = seen.get(key!);
      if (previous !== undefined && previous !== body) return jsonResponse({ error: 'conflict' }, 409);
      seen.set(key!, body);
      return jsonResponse(submitProjection(key === replayCase.idempotencyKey ? replayCase : conflictCase));
    });
    const client = new ActionProxyClient({ baseUrl: 'http://actionproxy.test', fetch: fetchMock });

    const first = await client.submitToolCall(replayCase.request, { idempotencyKey: replayCase.idempotencyKey });
    const replay = await client.submitToolCall(replayCase.request, { idempotencyKey: replayCase.idempotencyKey });
    expect(replay.id).toBe(first.id);

    await client.submitToolCall(conflictCase.request, { idempotencyKey: conflictCase.idempotencyKey });
    await expect(
      client.submitToolCall(
        { ...conflictCase.request, input: conflictCase.conflictingInput! },
        { idempotencyKey: conflictCase.idempotencyKey },
      ),
    ).rejects.toMatchObject({ body: { error: 'conflict' }, status: 409 } satisfies Partial<ActionProxyApiError>);

    for (const [, init] of fetchMock.mock.calls) {
      const body = JSON.parse(init?.body ?? '{}') as Record<string, unknown>;
      expect(body).not.toHaveProperty('idempotencyKey');
    }
  });

  it('keeps approval, external grant, mutation, and unknown-outcome authority on the server', async () => {
    const approvalCase = scenario('approval-execution');
    const externalCase = scenario('external-grant');
    const mutationCase = scenario('external-input-mutation-rejection');
    const unknownCase = scenario('unknown-outcome-non-retry');
    const requests: Array<{ body?: string; url: string }> = [];
    const fetchMock = vi.fn<ActionProxyFetch>(async (url, init) => {
      requests.push({ body: init?.body, url });
      if (url.endsWith('/approve')) {
        return jsonResponse({
          approval: { ...approvalCase.approval, id: 'approval_fixture', originalInput: approvalCase.request.input, status: 'approved' },
          toolCall: toolCallProjection(approvalCase, 'executed'),
        });
      }
      if (url.includes('/grant_mutation/consume')) return jsonResponse({ error: 'forbidden' }, 403);
      if (url.includes('/grant_unknown/consume')) return jsonResponse({ error: 'conflict' }, 409);
      if (url.endsWith('/outcome')) {
        return jsonResponse({
          grant: grantProjection(url.includes('grant_unknown') ? 'grant_unknown' : 'grant_external'),
          ok: true,
          toolCall: toolCallProjection(
            url.includes('grant_unknown') ? unknownCase : externalCase,
            url.includes('grant_unknown') ? 'failed' : 'executed',
          ),
        });
      }
      return jsonResponse({ grant: grantProjection('grant_external'), ok: true });
    });
    const client = new ActionProxyClient({ baseUrl: 'http://actionproxy.test', fetch: fetchMock });

    await expect(client.approveApproval('approval_fixture', approvalCase.approval as { approvedBy: string })).resolves.toMatchObject({
      approval: { status: 'approved' },
      toolCall: { status: 'executed' },
    });
    await expect(
      client.consumeExecutionGrant('grant_external', {
        input: externalCase.request.input,
        toolCallId: 'toolcall_external-grant',
        toolName: externalCase.request.toolName,
      }),
    ).resolves.toMatchObject({ ok: true });
    await expect(client.reportExecutionGrantOutcome('grant_external', externalCase.outcome as never)).resolves.toMatchObject({
      toolCall: { status: 'executed' },
    });
    await expect(
      client.consumeExecutionGrant('grant_mutation', {
        input: mutationCase.mutatedInput!,
        toolCallId: 'toolcall_external-input-mutation-rejection',
        toolName: mutationCase.request.toolName,
      }),
    ).rejects.toMatchObject({ status: 403 });
    await expect(client.reportExecutionGrantOutcome('grant_unknown', unknownCase.outcome as never)).resolves.toMatchObject({
      toolCall: { status: 'failed' },
    });
    await expect(
      client.consumeExecutionGrant('grant_unknown', {
        input: unknownCase.request.input,
        toolCallId: 'toolcall_unknown-outcome-non-retry',
        toolName: unknownCase.request.toolName,
      }),
    ).rejects.toMatchObject({ status: 409 });

    expect(requests).toHaveLength(6);
    expect(requests.map(({ body }) => body).filter(Boolean).join('\n')).not.toContain('executionAuthorization');
  });
});

function scenario(name: string): ConformanceScenario {
  const testCase = conformanceFixture.scenarios.find((candidate) => candidate.name === name);
  if (!testCase) throw new Error(`Missing SDK conformance scenario: ${name}`);
  return testCase;
}

function submitProjection(testCase: ConformanceScenario) {
  const toolCall = toolCallProjection(testCase, testCase.expected.toolCallStatus ?? 'submitted');
  return {
    approval: testCase.expected.decision === 'require_approval' ? { id: `approval_${testCase.name}`, status: 'pending' } : undefined,
    decision: testCase.expected.decision,
    id: toolCall.id,
    status: testCase.expected.toolCallStatus,
    toolCall,
  };
}

function toolCallProjection(testCase: ConformanceScenario, status: string) {
  return {
    agentId: testCase.request.agentId,
    canonicalActionRequestHash: `server_request_hash_${testCase.name}`,
    canonicalActionRequestVersion: conformanceFixture.contractVersions.canonicalRequest,
    canonicalDecisionInputHash: `server_decision_input_hash_${testCase.name}`,
    createdAt: '2026-07-12T00:00:00.000Z',
    decision: testCase.expected.decision,
    decisionTrace: {
      decisionV1: {
        outcome: testCase.expected.decision,
        reasonCodes: testCase.expected.reasonCodes ?? [],
        version: conformanceFixture.contractVersions.decision,
      },
    },
    id: `toolcall_${testCase.name}`,
    input: testCase.request.input,
    metadata: testCase.request.metadata ?? {},
    reason: testCase.request.reason,
    requestedBy: testCase.request.requestedBy,
    status,
    toolName: testCase.request.toolName,
    updatedAt: '2026-07-12T00:00:00.000Z',
  };
}

function grantProjection(id: string) {
  return {
    expiresAt: '2026-07-12T00:05:00.000Z',
    id,
    inputHash: 'server_input_hash',
    toolCallId: `toolcall_${id}`,
    toolName: 'docs.search',
  };
}

function jsonResponse(body: unknown, status = 200): ActionProxyFetchResponse {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) };
}

function readFixture<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(fixtureDirectory, name), 'utf8')) as T;
}

function assertNever(value: never): never {
  throw new Error(`Unhandled SDK conformance flow: ${String(value)}`);
}
