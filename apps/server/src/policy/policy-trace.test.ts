import { describe, expect, it } from 'vitest';
import type { ToolCallRecord } from '../models';
import {
  normalizeActionRequest,
  type CanonicalPolicyContext,
} from '../contracts/action-request';
import { evaluatePolicy } from './evaluate-policy';
import type { PolicyFile } from './policy-types';
import { policyContextFromToolCall } from './policy-trace';

describe('canonical tool-call policy context', () => {
  it('keeps contract-owned conditional fields frozen while using the finalized input', () => {
    const toolCall = preparedCanonicalToolCall();
    const finalizedInput = {
      body: 'Approved body with\ttabs\r\nand Unicode e\u0301',
      subject: 'Approved subject',
      to: 'approved@example.com',
    };
    const context = policyContextFromToolCall({
      ...toolCall,
      input: finalizedInput,
      metadata: {
        customerVisible: false,
        operationKind: 'read',
        riskKind: 'safe',
      },
    });

    expect(context).toMatchObject({
      customerVisible: true,
      input: finalizedInput,
      operationKind: 'external_send',
      risk: 'external_communication',
    });
    expect(evaluatePolicy(conditionalPolicy(), toolCall.toolName, context)).toMatchObject({
      decision: 'require_approval',
      matchedRule: toolCall.toolName,
    });
  });

  it('fails approval and dispatch revalidation closed when frozen policy evidence is missing or changed', () => {
    const toolCall = preparedCanonicalToolCall();
    expect(() => policyContextFromToolCall({
      ...toolCall,
      canonicalPolicyContext: undefined,
    })).toThrow('no valid frozen policy context');

    expect(() => policyContextFromToolCall({
      ...toolCall,
      canonicalPolicyContext: {
        ...toolCall.canonicalPolicyContext!,
        risk: {
          ...toolCall.canonicalPolicyContext!.risk,
          value: 'safe',
        },
      },
    })).toThrow('no longer matches its decision trace');

    expect(() => policyContextFromToolCall({
      ...toolCall,
      canonicalPolicyContext: {
        ...toolCall.canonicalPolicyContext!,
        operationKind: {
          present: true,
          provenance: { source: 'body.metadata.operationKind', trust: 'asserted' },
          value: 'read',
        },
      },
      decisionTrace: undefined,
    })).toThrow('no trusted frozen operationKind policy binding');
  });
});

function preparedCanonicalToolCall(): ToolCallRecord {
  const contractId = 'actionproxy.prepared-test.v1';
  const contractVersion = '1';
  const source = `action-contract:${contractId}@${contractVersion}`;
  const input = {
    body: 'Exact body',
    subject: 'Exact subject',
    to: 'recipient@example.com',
  };
  const canonical = normalizeActionRequest({
    ingress: { environment: 'local', protocol: 'actionproxy_http', source: 'http' },
    receivedAt: '2026-08-11T00:00:00.000Z',
    request: {
      agentId: 'direct_action',
      input,
      reason: 'Exact email',
      requestedBy: 'local-admin',
      toolName: 'notifications.deliver',
    },
    requestId: 'toolcall_policy_context',
    trustedCredentialReference: {
      source: 'prepared-intent:intent_policy_context',
      value: 'connection_google_company',
    },
    trustedExecutionMode: { source, value: 'external_grant' },
    trustedOperation: {
      source,
      value: { kind: 'external_send', name: 'notifications.deliver' },
    },
    trustedPolicy: {
      customerVisible: true,
      operationKind: 'external_send',
      risk: 'external_communication',
      source,
    },
    trustedResources: {
      source,
      value: [{ id: 'recipient@example.com', type: 'external.recipient' }],
    },
    workspaceId: 'default',
  });
  const frozen = structuredClone(canonical.context.policy) as CanonicalPolicyContext;
  return {
    actionEnvelope: {
      actor: { id: 'local-admin', type: 'local' },
      agent: { id: 'direct_action' },
      context: { reason: 'Exact email' },
      envelopeHash: 'envelope_policy_context',
      executionMode: 'external_grant',
      input,
      inputHash: 'input_policy_context',
      operation: { kind: 'external_send', name: 'notifications.deliver' },
      preparedAction: {
        adapterId: 'google_workspace',
        adapterVersion: 'google-v1',
        contractHash: 'contract_hash',
        contractId,
        contractVersion,
        intentHash: 'intent_hash',
        intentId: 'intent_policy_context',
        operationHash: 'operation_hash',
        serializerVersion: 'gmail-v1',
        version: 'actionproxy.prepared-action-binding.v1',
      },
      protocol: 'actionproxy_http',
      source: { type: 'http' },
      toolName: 'notifications.deliver',
      version: 'actionproxy.action.v1',
    },
    agentId: 'direct_action',
    canonicalActionRequestHash: canonical.integrity.requestHash,
    canonicalActionRequestVersion: canonical.version,
    canonicalDecisionInputHash: canonical.integrity.decisionInputHash,
    canonicalPolicyContext: frozen,
    createdAt: '2026-08-11T00:00:00.000Z',
    decision: 'require_approval',
    decisionTrace: { canonicalPolicyContext: structuredClone(frozen) },
    id: 'toolcall_policy_context',
    input,
    metadata: {},
    reason: 'Exact email',
    requestedBy: 'local-admin',
    status: 'pending_approval',
    toolName: 'notifications.deliver',
    updatedAt: '2026-08-11T00:00:00.000Z',
    workspaceId: 'default',
  };
}

function conditionalPolicy(): PolicyFile {
  return {
    default: { approval: 'deny', risk: 'unknown' },
    tools: {
      'notifications.deliver': {
        approval: 'required',
        conditions: {
          customerVisible: true,
          operationKind: 'external_send',
          risk: 'external_communication',
        },
        risk: 'external_communication',
      },
    },
    version: 1,
  };
}
