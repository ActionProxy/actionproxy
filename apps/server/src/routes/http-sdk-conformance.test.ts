import fs from 'node:fs';
import path from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { APPROVAL_AUTHORIZATION_VERSION } from '../contracts/approval-authorization';
import { CANONICAL_ACTION_REQUEST_VERSION } from '../contracts/action-request';
import { ACTIONPROXY_DECISION_VERSION } from '../contracts/decision';
import {
  createExecutionAuthorizationAuthority,
  EXECUTION_AUTHORIZATION_VERSION,
  EXECUTOR_CAPABILITIES_VERSION,
} from '../contracts/execution-authorization';
import { EXECUTION_ATTEMPT_VERSION } from '../contracts/execution-attempt';
import type { AuditEvent, JsonObject, SubmitToolCallRequest } from '../models';
import { createYamlPolicyProvider, type DeterministicPolicyProvider } from '../policy/policy-provider';
import { loadPolicy } from '../policy/load-policy';
import { hashJson } from '../security/crypto';
import { ExecutionGrantService } from '../security/execution-grants';
import { ActionProxyService } from '../services/action-gate';
import { ToolRegistry } from '../services/tool-registry';
import type { AuditListFilters, AuditListLimit, AuditStore } from '../storage/audit-store';
import { MemoryStore } from '../storage/memory-store';
import { registerApprovalRoutes } from './approvals';
import { registerExecutionGrantRoutes } from './execution-grants';
import { registerToolCallRoutes } from './tool-calls';

interface ConformanceExpected {
  approvalStatus?: string;
  attemptCount?: number;
  attemptState?: string;
  authorizedDispatches?: number;
  conflictHttpStatus?: number;
  consumeHttpStatus?: number;
  decision?: string;
  error?: string;
  finalToolCallStatus?: string;
  httpStatus: number;
  mutationHttpStatus?: number;
  outcomeHttpStatus?: number;
  reasonCodes?: string[];
  replayHttpStatus?: number;
  retryConsumeHttpStatus?: number;
  retryDisposition?: string;
  sameRequestId?: boolean;
  toolCallStatus?: string;
}

type ConformanceFlow =
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
  expected: ConformanceExpected;
  fault?: { policyProvider: 'throws' };
  flow: ConformanceFlow;
  idempotencyKey?: string;
  mutatedInput?: JsonObject;
  name: string;
  outcome?: JsonObject;
  request: SubmitToolCallRequest;
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

const fixture = JSON.parse(
  fs.readFileSync(path.resolve(process.cwd(), '../../fixtures/contracts/http-sdk-conformance-v1.json'), 'utf8'),
) as ConformanceFixture;

const signingKey = 'http-sdk-conformance-signing-key';
const policyPath = path.resolve('src/policies/default.policy.yaml');
// `authorizedDispatches` counts observed local closure calls or successful
// one-time external grant/attempt dispatch transitions, never SDK callbacks.
const exercisedScenarios: Array<{ flow: ConformanceFlow; name: string }> = [
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
] as const;

describe('actionproxy.http-sdk-conformance.v1 server boundary', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('references the frozen server-created contract vocabulary', () => {
    expect(fixture.version).toBe('actionproxy.http-sdk-conformance.v1');
    expect(fixture.contractVersions).toEqual({
      approvalAuthorization: APPROVAL_AUTHORIZATION_VERSION,
      canonicalRequest: CANONICAL_ACTION_REQUEST_VERSION,
      decision: ACTIONPROXY_DECISION_VERSION,
      executionAttempt: EXECUTION_ATTEMPT_VERSION,
      executionAuthorization: EXECUTION_AUTHORIZATION_VERSION,
      executorCapabilities: EXECUTOR_CAPABILITIES_VERSION,
    });
    expect(fixture.scenarios.map(({ flow, name }) => ({ flow, name }))).toEqual(exercisedScenarios);
  });

  it('keeps allow, deny, and require-approval HTTP outcomes conformant without alternate execution paths', async () => {
    const harness = await makeHarness();
    app = harness.app;

    for (const name of ['allow', 'deny', 'require-approval']) {
      const testCase = scenario(name);
      const callsBefore = harness.localExecutor.mock.calls.length;
      const response = await submit(app, testCase);
      const body = response.json();

      expect(response.statusCode, name).toBe(testCase.expected.httpStatus);
      expect(body, name).toMatchObject({
        decision: testCase.expected.decision,
        status: testCase.expected.toolCallStatus,
        toolCall: {
          canonicalActionRequestVersion: fixture.contractVersions.canonicalRequest,
          decisionTrace: {
            decisionV1: {
              outcome: testCase.expected.decision,
              version: fixture.contractVersions.decision,
            },
          },
        },
      });
      expect(JSON.stringify(body), name).not.toContain('executionAuthorization');

      const attempts = await listAttempts(app, body.id);
      if (testCase.expected.attemptState) {
        expect(attempts, name).toMatchObject([
          { state: testCase.expected.attemptState, version: fixture.contractVersions.executionAttempt },
        ]);
      } else {
        expect(attempts, name).toHaveLength(testCase.expected.attemptCount ?? 0);
      }
      expect(harness.localExecutor.mock.calls.length - callsBefore, name).toBe(
        expectedNumber(testCase, 'authorizedDispatches'),
      );
    }
  });

  it('executes an approval-required action only after the compatible approval endpoint finalizes it', async () => {
    const testCase = scenario('approval-execution');
    const harness = await makeHarness();
    app = harness.app;

    const submitted = await submit(app, testCase);
    const submittedBody = submitted.json();
    expect(submitted.statusCode).toBe(testCase.expected.httpStatus);
    expect(submittedBody).toMatchObject({ decision: 'require_approval', status: 'pending_approval' });
    expect(harness.localExecutor).not.toHaveBeenCalled();

    const approved = await app.inject({
      method: 'POST',
      payload: testCase.approval,
      url: `/v1/approvals/${submittedBody.approval.id}/approve`,
    });

    expect(approved.statusCode).toBe(200);
    expect(approved.json()).toMatchObject({
      approval: { status: testCase.expected.approvalStatus },
      toolCall: { status: testCase.expected.toolCallStatus },
    });
    expect(harness.localExecutor).toHaveBeenCalledTimes(expectedNumber(testCase, 'authorizedDispatches'));
    expect(await listAttempts(app, submittedBody.id)).toMatchObject([
      { state: testCase.expected.attemptState, version: fixture.contractVersions.executionAttempt },
    ]);
  });

  it('keeps same-request replay and conflicting payload behavior behind Idempotency-Key', async () => {
    const harness = await makeHarness();
    app = harness.app;

    const replayCase = scenario('same-request-replay');
    const first = await submit(app, replayCase);
    const replay = await submit(app, replayCase);
    expect(first.statusCode).toBe(replayCase.expected.httpStatus);
    expect(replay.statusCode).toBe(replayCase.expected.replayHttpStatus);
    expect(replay.json().id).toBe(first.json().id);
    expect(await listAttempts(app, first.json().id)).toHaveLength(expectedNumber(replayCase, 'attemptCount'));
    expect(harness.localExecutor).toHaveBeenCalledTimes(expectedNumber(replayCase, 'authorizedDispatches'));

    const conflictCase = scenario('payload-conflict');
    const reserved = await submit(app, conflictCase);
    const conflict = await app.inject({
      headers: { 'idempotency-key': conflictCase.idempotencyKey },
      method: 'POST',
      payload: { ...conflictCase.request, input: conflictCase.conflictingInput },
      url: '/v1/tool-calls',
    });
    expect(reserved.statusCode).toBe(conflictCase.expected.httpStatus);
    expect(conflict.statusCode).toBe(conflictCase.expected.conflictHttpStatus);
    expect(conflict.json()).toMatchObject({ error: conflictCase.expected.error });
    expect(await listAttempts(app, reserved.json().id)).toHaveLength(expectedNumber(conflictCase, 'attemptCount'));
    expect(harness.localExecutor).toHaveBeenCalledTimes(
      expectedNumber(replayCase, 'authorizedDispatches') +
      expectedNumber(conflictCase, 'authorizedDispatches'),
    );
  });

  it('fails a throwing policy provider closed at the real HTTP route without invoking an executor', async () => {
    const testCase = scenario('policy-provider-failure');
    expect(testCase.fault).toEqual({ policyProvider: 'throws' });
    const policy = loadPolicy(policyPath);
    const policyDigest = hashJson(policy);
    const baseProvider = createYamlPolicyProvider(policy, {
      policyVersionHash: policyDigest,
      policyVersionId: `policy_${policyDigest.slice(0, 16)}`,
    });
    const provider: DeterministicPolicyProvider = {
      descriptor: baseProvider.descriptor,
      evaluate: () => {
        throw new Error('provider diagnostic that must not reach the response');
      },
    };
    const harness = await makeHarness(provider);
    app = harness.app;

    const response = await submit(app, testCase);
    const body = response.json();

    expect(response.statusCode).toBe(testCase.expected.httpStatus);
    expect(body).toMatchObject({
      decision: testCase.expected.decision,
      status: testCase.expected.toolCallStatus,
      toolCall: {
        decisionTrace: {
          decisionV1: {
            reasonCodes: testCase.expected.reasonCodes,
            version: fixture.contractVersions.decision,
          },
        },
      },
    });
    expect(JSON.stringify(body)).not.toContain('provider diagnostic');
    expect(await listAttempts(app, body.id)).toHaveLength(expectedNumber(testCase, 'attemptCount'));
    expect(harness.localExecutor).toHaveBeenCalledTimes(expectedNumber(testCase, 'authorizedDispatches'));
  });

  it('preserves the external grant consume and outcome response while keeping authorization server-side', async () => {
    const testCase = scenario('external-grant');
    const harness = await makeHarness();
    app = harness.app;
    const submitted = await submit(app, testCase);
    const body = submitted.json();

    expect(submitted.statusCode).toBe(testCase.expected.httpStatus);
    expect(body).toMatchObject({ decision: testCase.expected.decision, status: testCase.expected.toolCallStatus });
    const grant = body.result.grant;
    const consumed = await consumeGrant(app, body, grant, testCase.request.input);
    expect(consumed.statusCode).toBe(testCase.expected.consumeHttpStatus);
    expect(consumed.json()).toMatchObject({ grant: { id: grant.id }, ok: true });
    expect(consumed.json()).not.toHaveProperty('executionAuthorization');
    // A successful consume is the server-authorized dispatch seam. The test does
    // not claim that ActionProxy ran a downstream SDK callback itself.
    const authorizedExternalDispatches = consumed.statusCode === 200 ? 1 : 0;

    const outcome = await app.inject({
      method: 'POST',
      payload: testCase.outcome,
      url: `/v1/execution-grants/${grant.id}/outcome`,
    });
    expect(outcome.statusCode).toBe(testCase.expected.outcomeHttpStatus);
    expect(outcome.json()).toMatchObject({ toolCall: { status: testCase.expected.finalToolCallStatus } });
    expect(await listAttempts(app, body.id)).toMatchObject([
      { state: testCase.expected.attemptState, version: fixture.contractVersions.executionAttempt },
    ]);
    expect(authorizedExternalDispatches).toBe(expectedNumber(testCase, 'authorizedDispatches'));
    expect(harness.localExecutor).not.toHaveBeenCalled();
  });

  it('rejects exact-input mutation before external dispatch', async () => {
    const testCase = scenario('external-input-mutation-rejection');
    const harness = await makeHarness();
    app = harness.app;
    const submitted = await submit(app, testCase);
    const body = submitted.json();
    const grant = body.result.grant;

    const mutation = await consumeGrant(app, body, grant, testCase.mutatedInput!);

    expect(mutation.statusCode).toBe(testCase.expected.mutationHttpStatus);
    expect(mutation.json()).toMatchObject({ error: 'forbidden' });
    expect(await listAttempts(app, body.id)).toMatchObject([{ state: testCase.expected.attemptState }]);
    expect(harness.localExecutor).not.toHaveBeenCalled();
    expect(expectedNumber(testCase, 'authorizedDispatches')).toBe(0);
  });

  it('records an unknown outcome and makes the consumed grant unavailable for retry', async () => {
    const testCase = scenario('unknown-outcome-non-retry');
    const harness = await makeHarness();
    app = harness.app;
    const submitted = await submit(app, testCase);
    const body = submitted.json();
    const grant = body.result.grant;
    let authorizedExternalDispatches = 0;

    const consumed = await consumeGrant(app, body, grant, testCase.request.input);
    expect(consumed.statusCode).toBe(testCase.expected.consumeHttpStatus);
    if (consumed.statusCode === 200) authorizedExternalDispatches += 1;

    const outcome = await app.inject({
      method: 'POST',
      payload: testCase.outcome,
      url: `/v1/execution-grants/${grant.id}/outcome`,
    });
    expect(outcome.statusCode).toBe(testCase.expected.outcomeHttpStatus);
    expect(outcome.json()).toMatchObject({ toolCall: { status: testCase.expected.finalToolCallStatus } });

    const retry = await consumeGrant(app, body, grant, testCase.request.input);
    expect(retry.statusCode).toBe(testCase.expected.retryConsumeHttpStatus);
    expect(retry.json()).toMatchObject({ error: 'conflict' });

    const replayedSubmission = await submit(app, testCase);
    expect(replayedSubmission.statusCode).toBe(testCase.expected.httpStatus);
    expect(replayedSubmission.json().id).toBe(body.id);
    expect(authorizedExternalDispatches).toBe(expectedNumber(testCase, 'authorizedDispatches'));
    const attempts = await listAttempts(app, body.id);
    expect(attempts).toHaveLength(1);
    expect(attempts).toMatchObject([
      {
        outcome: { retryDisposition: testCase.expected.retryDisposition },
        state: testCase.expected.attemptState,
      },
    ]);
  });
});

async function makeHarness(policyProvider?: DeterministicPolicyProvider) {
  const policy = loadPolicy(policyPath);
  const policyVersionHash = hashJson(policy);
  const policyVersionId = `policy_${policyVersionHash.slice(0, 16)}`;
  const store = new MemoryStore();
  const auditStore = new CapturingAuditStore();
  const executionAuthorizations = createExecutionAuthorizationAuthority();
  const tools = new ToolRegistry(executionAuthorizations);
  const localExecutor = vi.fn(async (input: JsonObject) => ({ input, ok: true }));
  tools.register('docs.search', localExecutor);
  tools.register('gmail.send_email', localExecutor);
  const executionGrants = new ExecutionGrantService(
    { secret: signingKey, ttlSeconds: 300 },
    store,
    auditStore,
    undefined,
    () => policyVersionHash,
    executionAuthorizations,
  );
  const service = new ActionProxyService({
    auditStore,
    executionAuthorizations,
    executionGrants,
    localExecutionMode: 'mock',
    policy,
    policyProvider,
    policyVersionHash,
    policyVersionId,
    receiptSigningSecret: signingKey,
    store,
    tools,
    workspaceId: 'default',
  });
  const app = Fastify({ logger: false });
  await registerToolCallRoutes(app, service);
  await registerApprovalRoutes(app, service);
  await registerExecutionGrantRoutes(app, executionGrants);
  return { app, auditStore, localExecutor, store };
}

function scenario(name: string): ConformanceScenario {
  const testCase = fixture.scenarios.find((candidate) => candidate.name === name);
  if (!testCase) throw new Error(`Missing HTTP/SDK conformance scenario: ${name}`);
  return testCase;
}

function expectedNumber(
  testCase: ConformanceScenario,
  field: 'attemptCount' | 'authorizedDispatches',
): number {
  const value = testCase.expected[field];
  if (typeof value !== 'number') {
    throw new Error(`Scenario ${testCase.name} is missing numeric expected.${field}`);
  }
  return value;
}

function submit(server: FastifyInstance, testCase: ConformanceScenario) {
  return server.inject({
    headers: testCase.idempotencyKey ? { 'idempotency-key': testCase.idempotencyKey } : undefined,
    method: 'POST',
    payload: testCase.request,
    url: '/v1/tool-calls',
  });
}

async function listAttempts(server: FastifyInstance, toolCallId: string): Promise<JsonObject[]> {
  const response = await server.inject({
    method: 'GET',
    url: `/v1/tool-calls/${toolCallId}/execution-attempts`,
  });
  expect(response.statusCode).toBe(200);
  return response.json().attempts as JsonObject[];
}

function consumeGrant(
  server: FastifyInstance,
  toolCallResponse: JsonObject,
  grant: JsonObject,
  input: JsonObject,
) {
  return server.inject({
    method: 'POST',
    payload: {
      input,
      policyVersionHash: grant.policyVersionHash,
      toolCallId: toolCallResponse.id,
      toolName: grant.toolName,
    },
    url: `/v1/execution-grants/${grant.id}/consume`,
  });
}

class CapturingAuditStore implements AuditStore {
  readonly events: AuditEvent[] = [];

  async append(event: AuditEvent): Promise<void> {
    if (this.events.some((existing) => existing.id === event.id)) return;
    this.events.push(event);
  }

  async list(_limit?: AuditListLimit, _filters?: AuditListFilters): Promise<AuditEvent[]> {
    return [...this.events].reverse();
  }
}
