import { describe, expect, it } from 'vitest';
import { normalizeActionEnvelope } from './action-envelope';
import type { SubmitToolCallRequest } from '../models';

function request(metadata: SubmitToolCallRequest['metadata'] = {}): SubmitToolCallRequest {
  return {
    agentId: 'demo-agent',
    input: { body: 'Hello', to: 'customer@example.com' },
    metadata,
    reason: 'Send a controlled reply',
    requestedBy: 'dev@example.com',
    toolName: 'gmail.send_email',
  };
}

describe('normalizeActionEnvelope', () => {
  it('creates new ActionProxy envelopes for current submissions', () => {
    const envelope = normalizeActionEnvelope({
      actor: 'dev@example.com',
      request: request({ actionproxyExecution: 'external' }),
    });

    expect(envelope.version).toBe('actionproxy.action.v1');
    expect(envelope.protocol).toBe('actionproxy_http');
    expect(envelope.executionMode).toBe('external_grant');
    expect(envelope.envelopeHash).toBe('04231b4fb802d9f09bb504c166c31afe125b79fe706d5881a5819053cdea508e');
  });

  it('accepts ActionProxy external execution metadata', () => {
    const envelope = normalizeActionEnvelope({
      actor: 'dev@example.com',
      request: request({ actionproxyExecution: 'external' }),
    });

    expect(envelope.executionMode).toBe('external_grant');
  });

  it('prefers an explicit action execution mode over metadata', () => {
    const envelope = normalizeActionEnvelope({
      actor: 'dev@example.com',
      request: {
        ...request({ actionproxyExecution: 'external' }),
        action: { executionMode: 'local_mock' },
      },
    });

    expect(envelope.executionMode).toBe('local_mock');
  });

});
