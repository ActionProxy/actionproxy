import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ToolCallRecord } from '../models';
import {
  buildExecutionAttempt,
  EXECUTION_ATTEMPT_VERSION,
  executionAttemptOutcome,
  type ExecutionAttemptTerminalState,
} from './execution-attempt';

interface Fixture {
  hashVector: { remediationHash: string; resultHash: string };
  reserved: unknown;
  terminalOutcomeMatrix: Record<
    ExecutionAttemptTerminalState,
    { certainty: string; remediationHash: string | null; retryDisposition: string }
  >;
  version: string;
}

const fixture = JSON.parse(
  fs.readFileSync(path.resolve(process.cwd(), '../../fixtures/contracts/execution-attempt-v1.json'), 'utf8'),
) as Fixture;

describe('actionproxy.execution-attempt.v1', () => {
  it('builds the stable additive reservation fixture without changing an existing hash contract', () => {
    const toolCall: ToolCallRecord = {
      actionEnvelopeHash: 'envelope_fixture_hash',
      agentId: 'agent_fixture',
      canonicalActionRequestHash: 'request_fixture_hash',
      canonicalActionRequestVersion: 'actionproxy.action-request.v1',
      canonicalDecisionInputHash: 'decision_input_fixture_hash',
      createdAt: '2026-07-12T00:00:00.000Z',
      decisionTrace: {
        decisionV1: { decisionId: 'decision_fixture_id', version: 'actionproxy.decision.v1' },
      },
      id: 'toolcall_fixture',
      input: { query: 'fixture' },
      inputHash: 'input_fixture_hash',
      metadata: {},
      policyVersionHash: 'policy_fixture_hash',
      reason: 'Fixture',
      requestedBy: 'actor_fixture',
      status: 'submitted',
      toolName: 'docs.search',
      updatedAt: '2026-07-12T00:00:00.000Z',
      workspaceId: 'tenant_fixture',
    };

    expect(fixture.version).toBe(EXECUTION_ATTEMPT_VERSION);
    expect(
      buildExecutionAttempt({
        executionMode: 'local_mock',
        id: 'attempt_fixture',
        inputHash: 'input_fixture_hash',
        now: '2026-07-12T00:00:00.000Z',
        reservationOwner: 'reservation_fixture',
        toolCall,
      }),
    ).toEqual(fixture.reserved);
  });

  it('classifies every terminal outcome without authorizing an automatic retry', () => {
    const states: ExecutionAttemptTerminalState[] = [
      'succeeded',
      'failed_before_dispatch',
      'failed_after_dispatch',
      'timed_out',
      'cancelled',
      'unknown_outcome',
    ];

    for (const state of states) {
      const outcome = executionAttemptOutcome(state, { recordedAt: '2026-07-12T00:00:01.000Z' });
      expect(outcome).toMatchObject({ status: state, ...fixture.terminalOutcomeMatrix[state] });
      expect(outcome.retryDisposition).not.toContain('automatic');
    }
  });

  it('binds remediation separately from the normalized result', () => {
    const outcome = executionAttemptOutcome('succeeded', {
      recordedAt: '2026-07-12T00:00:01.000Z',
      remediation: {
        kind: 'soft_revert',
        reason: 'Restore the previous snapshot.',
        status: 'available',
        toolName: 'docs.restore_snapshot',
      },
      result: { rows: 1 },
    });

    expect(outcome.resultHash).toBe(fixture.hashVector.resultHash);
    expect(outcome.remediationHash).toBe(fixture.hashVector.remediationHash);
    expect(outcome.remediationHash).not.toBe(outcome.resultHash);
  });
});
