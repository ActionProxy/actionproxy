import { describe, expect, it } from 'vitest';
import {
  APPROVER_EFFECTIVE_IDENTITY_UNIQUE_INDEX,
  APPROVER_PRINCIPAL_UNIQUE_INDEX,
  approverEffectiveIdentity,
  isPostgresApproverPrincipalUniqueViolation,
  isSqliteApproverPrincipalUniqueViolation,
} from './approver-principal-constraint';

describe('approver effective identity constraint mapping', () => {
  it('uses the directory id for an absent or empty principal', () => {
    expect(approverEffectiveIdentity({ id: 'u_legacy' })).toBe('u_legacy');
    expect(approverEffectiveIdentity({ id: 'u_legacy', principalId: '' })).toBe(
      'u_legacy',
    );
    expect(
      approverEffectiveIdentity({ id: 'u_mapped', principalId: 'oidc|operator' }),
    ).toBe('oidc|operator');
  });

  it('recognizes both SQLite principal and expression-index violations', () => {
    expect(
      isSqliteApproverPrincipalUniqueViolation(
        new Error(
          'UNIQUE constraint failed: approver_users.workspace_id, approver_users.principal_id',
        ),
      ),
    ).toBe(true);
    expect(
      isSqliteApproverPrincipalUniqueViolation(
        new Error(
          `UNIQUE constraint failed: index '${APPROVER_EFFECTIVE_IDENTITY_UNIQUE_INDEX}'`,
        ),
      ),
    ).toBe(true);
  });

  it('recognizes both Postgres unique-index constraint names', () => {
    expect(
      isPostgresApproverPrincipalUniqueViolation({
        code: '23505',
        constraint: APPROVER_PRINCIPAL_UNIQUE_INDEX,
      }),
    ).toBe(true);
    expect(
      isPostgresApproverPrincipalUniqueViolation({
        code: '23505',
        constraint: APPROVER_EFFECTIVE_IDENTITY_UNIQUE_INDEX,
      }),
    ).toBe(true);
    expect(
      isPostgresApproverPrincipalUniqueViolation({
        code: '23505',
        constraint: 'unrelated_unique_index',
      }),
    ).toBe(false);
  });
});
