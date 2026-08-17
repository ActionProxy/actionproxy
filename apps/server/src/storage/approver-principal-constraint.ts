import type { ApproverUserRecord } from '../models';

export const APPROVER_PRINCIPAL_UNIQUE_INDEX = 'uq_approver_users_workspace_principal';
export const APPROVER_EFFECTIVE_IDENTITY_UNIQUE_INDEX =
  'uq_approver_users_workspace_effective_identity';
export const APPROVER_PRINCIPAL_CONFLICT_MESSAGE =
  'Approver authorization identity conflicts with an existing directory user.';

export class ApproverPrincipalConflictError extends Error {
  constructor() {
    super(APPROVER_PRINCIPAL_CONFLICT_MESSAGE);
    this.name = 'ApproverPrincipalConflictError';
  }
}

export function assertApproverPrincipalAvailable(
  users: Iterable<Pick<ApproverUserRecord, 'id' | 'principalId' | 'workspaceId'>>,
  record: Pick<ApproverUserRecord, 'id' | 'principalId' | 'workspaceId'>,
): void {
  const effectiveIdentity = approverEffectiveIdentity(record);
  for (const existing of users) {
    if (
      existing.workspaceId === record.workspaceId &&
      existing.id !== record.id &&
      approverEffectiveIdentity(existing) === effectiveIdentity
    ) {
      throw new ApproverPrincipalConflictError();
    }
  }
}

export function approverEffectiveIdentity(
  record: Pick<ApproverUserRecord, 'id' | 'principalId'>,
): string {
  return record.principalId === undefined || record.principalId === ''
    ? record.id
    : record.principalId;
}

export function isSqliteApproverPrincipalUniqueViolation(error: unknown): boolean {
  const message = errorMessage(error);
  return (
    /UNIQUE constraint failed:\s*approver_users\.workspace_id,\s*approver_users\.principal_id/u.test(
      message,
    ) ||
    message.includes(
      `UNIQUE constraint failed: index '${APPROVER_EFFECTIVE_IDENTITY_UNIQUE_INDEX}'`,
    )
  );
}

export function isPostgresApproverPrincipalUniqueViolation(error: unknown): boolean {
  if (!isRecord(error)) return false;
  return (
    error.code === '23505' &&
    (error.constraint === APPROVER_PRINCIPAL_UNIQUE_INDEX ||
      error.constraint === APPROVER_EFFECTIVE_IDENTITY_UNIQUE_INDEX)
  );
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (isRecord(error) && typeof error.message === 'string') return error.message;
  return '';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
