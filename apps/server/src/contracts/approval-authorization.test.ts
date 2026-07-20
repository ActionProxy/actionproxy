import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ToolCallRecord } from '../models';
import {
  approvalAuthorizationMismatch,
  buildApprovalAuthorization,
  isValidApprovalAuthorization,
  type BuildApprovalAuthorizationInput,
} from './approval-authorization';

interface FixtureCorpus {
  vectors: Array<{
    expected: {
      authorizationHash: string;
      eligibleGroups: string[];
      eligibleUsers: string[];
    };
    input: Omit<BuildApprovalAuthorizationInput, 'toolCall'> & { toolCall: ToolCallRecord };
    name: string;
  }>;
  version: string;
}

const fixture = JSON.parse(
  fs.readFileSync(path.resolve(process.cwd(), '../../fixtures/contracts/approval-authorization-v1.json'), 'utf8'),
) as FixtureCorpus;

describe('actionproxy.approval-authorization.v1', () => {
  it('matches the reusable deterministic binding fixture', () => {
    expect(fixture.version).toBe('actionproxy.approval-authorization.v1');
    for (const vector of fixture.vectors) {
      const authorization = buildApprovalAuthorization(vector.input);
      expect(authorization.authorizationHash, vector.name).toBe(vector.expected.authorizationHash);
      expect(authorization.binding.requirements.eligibleGroups).toEqual(vector.expected.eligibleGroups);
      expect(authorization.binding.requirements.eligibleUsers).toEqual(vector.expected.eligibleUsers);
      expect(isValidApprovalAuthorization(authorization)).toBe(true);
    }
  });

  it('invalidates the authorization hash after mutation', () => {
    const authorization = buildApprovalAuthorization(fixture.vectors[0]!.input);
    const mutated = {
      ...authorization,
      binding: {
        ...authorization.binding,
        action: { ...authorization.binding.action, originalInputHash: 'mutated' },
      },
    };

    expect(isValidApprovalAuthorization(mutated)).toBe(false);
  });

  it('detects drift in associated approval and tool-call identities', () => {
    const input = fixture.vectors[0]!.input;
    const authorization = buildApprovalAuthorization(input);
    const approval = {
      approverGroups: input.approverGroups,
      approverUsers: input.approverUsers,
      authorization,
      createdAt: input.issuedAt,
      id: input.approvalId,
      originalEnvelopeHash: input.originalEnvelopeHash,
      originalInput: input.toolCall.input,
      originalInputHash: input.originalInputHash,
      requestedBy: input.requestedBy,
      requestedByAuth: { principalId: input.requestedByPrincipalId },
      requiredApprovals: input.requiredApprovals,
      reviewHash: input.reviewHash,
      separationOfDuties: input.separationOfDuties,
      status: 'pending' as const,
      toolCallId: input.toolCall.id,
      updatedAt: input.issuedAt,
      workspaceId: input.toolCall.workspaceId,
    };

    expect(approvalAuthorizationMismatch(authorization, approval as never, input.toolCall)).toBeUndefined();
    expect(
      approvalAuthorizationMismatch(authorization, approval as never, {
        ...input.toolCall,
        canonicalActionRequestHash: 'mutated',
      }),
    ).toBe('request_hash_mismatch');
  });
});
