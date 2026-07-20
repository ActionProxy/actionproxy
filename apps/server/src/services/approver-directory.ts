import type { ApproverGroupRecord, ApproverUserRecord, AuthContext } from '../models';
import { ConflictError, NotFoundError } from '../errors';
import type { PolicyFile, PolicyRule } from '../policy/policy-types';
import type { Store } from '../storage/store';

export interface ApprovalNotificationRecipient {
  displayName: string;
  email?: string;
  groups: string[];
  principalId: string;
  slackUserId?: string;
  telegramChatId?: string;
  telegramUsername?: string;
  telegramUserId?: string;
  userId: string;
}

export interface UpsertApproverUserInput {
  defaultApprover?: boolean;
  displayName?: string;
  email?: string;
  enabled?: boolean;
  groups?: string[];
  principalId?: string;
  slackUserId?: string;
  telegramChatId?: string;
  telegramUsername?: string;
  telegramUserId?: string;
}

export interface UpsertApproverGroupInput {
  description?: string;
  displayName?: string;
  enabled?: boolean;
}

export class ApproverDirectoryService {
  constructor(private readonly store: Store) {}

  async list(workspaceId: string): Promise<{ groups: ApproverGroupRecord[]; users: ApproverUserRecord[] }> {
    const [groups, users] = await Promise.all([
      this.store.listApproverGroups(workspaceId),
      this.store.listApproverUsers(workspaceId),
    ]);
    return { groups, users };
  }

  async getUser(workspaceId: string, id: string): Promise<ApproverUserRecord | undefined> {
    return this.store.getApproverUser(workspaceId, id);
  }

  async getGroup(workspaceId: string, id: string): Promise<ApproverGroupRecord | undefined> {
    return this.store.getApproverGroup(workspaceId, id);
  }

  async createUser(workspaceId: string, input: UpsertApproverUserInput): Promise<ApproverUserRecord> {
    const id = await this.nextGeneratedDirectoryId(workspaceId, 'u', input.displayName, 'approver');
    return this.upsertUser(workspaceId, id, input);
  }

  async upsertUser(workspaceId: string, id: string, input: UpsertApproverUserInput): Promise<ApproverUserRecord> {
    const existing = await this.store.getApproverUser(workspaceId, id);
    const now = new Date().toISOString();
    const principalId = blankToUndefined(input.principalId) ?? existing?.principalId;
    await this.assertUniqueAuthorizationIdentity(workspaceId, id, principalId);
    const record: ApproverUserRecord = {
      createdAt: existing?.createdAt ?? now,
      defaultApprover: input.defaultApprover ?? existing?.defaultApprover ?? false,
      displayName: blankToUndefined(input.displayName) ?? existing?.displayName ?? id,
      email: blankToUndefined(input.email) ?? existing?.email,
      enabled: input.enabled ?? existing?.enabled ?? true,
      groups: uniqueStrings(input.groups ?? existing?.groups ?? []),
      id,
      principalId,
      slackUserId: blankToUndefined(input.slackUserId) ?? existing?.slackUserId,
      telegramChatId: blankToUndefined(input.telegramChatId) ?? existing?.telegramChatId,
      telegramUsername: normalizeTelegramUsername(input.telegramUsername) ?? existing?.telegramUsername,
      telegramUserId: blankToUndefined(input.telegramUserId) ?? existing?.telegramUserId,
      updatedAt: now,
      workspaceId,
    };
    return this.store.upsertApproverUser(record);
  }

  async connectTelegramUser(
    workspaceId: string,
    id: string,
    input: { telegramChatId: string; telegramUsername?: string; telegramUserId: string },
  ): Promise<ApproverUserRecord> {
    const existing = await this.store.getApproverUser(workspaceId, id);
    if (!existing) throw new NotFoundError(`Approver user not found: ${id}`);

    return this.store.upsertApproverUser({
      ...existing,
      telegramChatId: input.telegramChatId,
      telegramUsername: normalizeTelegramUsername(input.telegramUsername) ?? existing.telegramUsername,
      telegramUserId: input.telegramUserId,
      updatedAt: new Date().toISOString(),
    });
  }

  async disconnectTelegramUser(workspaceId: string, id: string): Promise<ApproverUserRecord> {
    const existing = await this.store.getApproverUser(workspaceId, id);
    if (!existing) throw new NotFoundError(`Approver user not found: ${id}`);

    return this.store.upsertApproverUser({
      ...existing,
      telegramChatId: undefined,
      telegramUserId: undefined,
      updatedAt: new Date().toISOString(),
    });
  }

  async disableUser(workspaceId: string, id: string): Promise<ApproverUserRecord> {
    const existing = await this.store.getApproverUser(workspaceId, id);
    if (!existing) {
      return this.upsertUser(workspaceId, id, { displayName: id, enabled: false });
    }
    return this.store.upsertApproverUser({ ...existing, enabled: false, updatedAt: new Date().toISOString() });
  }

  async deleteUser(workspaceId: string, id: string): Promise<ApproverUserRecord> {
    const existing = await this.store.getApproverUser(workspaceId, id);
    if (!existing) throw new NotFoundError(`Approver user not found: ${id}`);

    await this.store.deleteApproverUser(workspaceId, id);
    return existing;
  }

  async createGroup(workspaceId: string, input: UpsertApproverGroupInput): Promise<ApproverGroupRecord> {
    const id = await this.nextGeneratedDirectoryId(workspaceId, 'g', input.displayName, 'group');
    return this.upsertGroup(workspaceId, id, input);
  }

  async upsertGroup(workspaceId: string, id: string, input: UpsertApproverGroupInput): Promise<ApproverGroupRecord> {
    const existing = await this.store.getApproverGroup(workspaceId, id);
    const now = new Date().toISOString();
    const record: ApproverGroupRecord = {
      createdAt: existing?.createdAt ?? now,
      description: blankToUndefined(input.description) ?? existing?.description,
      displayName: blankToUndefined(input.displayName) ?? existing?.displayName ?? id,
      enabled: input.enabled ?? existing?.enabled ?? true,
      id,
      updatedAt: now,
      workspaceId,
    };
    return this.store.upsertApproverGroup(record);
  }

  async disableGroup(workspaceId: string, id: string): Promise<ApproverGroupRecord> {
    const existing = await this.store.getApproverGroup(workspaceId, id);
    if (!existing) {
      return this.upsertGroup(workspaceId, id, { displayName: id, enabled: false });
    }
    return this.store.upsertApproverGroup({ ...existing, enabled: false, updatedAt: new Date().toISOString() });
  }

  async deleteGroup(workspaceId: string, id: string): Promise<ApproverGroupRecord> {
    const existing = await this.store.getApproverGroup(workspaceId, id);
    if (!existing) throw new NotFoundError(`Approver group not found: ${id}`);

    const now = new Date().toISOString();
    const users = await this.store.listApproverUsers(workspaceId);
    await Promise.all(
      users
        .filter((user) => user.groups.includes(id))
        .map((user) =>
          this.store.upsertApproverUser({
            ...user,
            groups: user.groups.filter((groupId) => groupId !== id),
            updatedAt: now,
          }),
        ),
    );
    await this.store.deleteApproverGroup(workspaceId, id);
    return existing;
  }

  async resolveRecipients(rule: PolicyRule, workspaceId: string): Promise<ApprovalNotificationRecipient[]> {
    const [allUsers, allGroups] = await Promise.all([
      this.store.listApproverUsers(workspaceId),
      this.store.listApproverGroups(workspaceId),
    ]);
    const enabledUsers = allUsers.filter((user) => user.enabled);
    const enabledGroups = new Set(allGroups.filter((group) => group.enabled).map((group) => group.id));
    const requestedUsers = new Set(rule.approvers?.users ?? []);
    const requestedGroups = new Set(rule.approvers?.groups ?? []);
    const hasExplicitRecipients = requestedUsers.size > 0 || requestedGroups.size > 0;

    const recipients = enabledUsers.filter((user) => {
      if (!hasExplicitRecipients) return user.defaultApprover;
      if (requestedUsers.has(user.id)) return true;
      return user.groups.some((group) => requestedGroups.has(group) && enabledGroups.has(group));
    });

    return recipients.map(userToRecipient).sort((left, right) => left.displayName.localeCompare(right.displayName));
  }

  async validatePolicy(policy: PolicyFile, workspaceId: string): Promise<void> {
    const [users, groups] = await Promise.all([
      this.store.listApproverUsers(workspaceId),
      this.store.listApproverGroups(workspaceId),
    ]);
    const enabledUsers = new Set(users.filter((user) => user.enabled).map((user) => user.id));
    const enabledGroups = new Set(groups.filter((group) => group.enabled).map((group) => group.id));

    for (const [pattern, rule] of policyRules(policy)) {
      for (const userId of rule.approvers?.users ?? []) {
        if (!enabledUsers.has(userId)) {
          throw new Error(`Policy rule ${pattern} references unknown or disabled approver user: ${userId}`);
        }
      }
      for (const groupId of rule.approvers?.groups ?? []) {
        if (!enabledGroups.has(groupId)) {
          throw new Error(`Policy rule ${pattern} references unknown or disabled approver group: ${groupId}`);
        }
      }
    }
  }

  async findEnabledUserBySlackUserId(workspaceId: string, slackUserId: string): Promise<ApproverUserRecord | undefined> {
    return (await this.store.listApproverUsers(workspaceId)).find(
      (user) => user.enabled && user.slackUserId === slackUserId,
    );
  }

  async findEnabledUserByTelegramUserId(
    workspaceId: string,
    telegramUserId: string,
  ): Promise<ApproverUserRecord | undefined> {
    return (await this.store.listApproverUsers(workspaceId)).find(
      (user) => user.enabled && user.telegramUserId === telegramUserId,
    );
  }

  async findEnabledUserByTelegramUsername(
    workspaceId: string,
    telegramUsername: string,
  ): Promise<ApproverUserRecord | undefined> {
    const normalizedUsername = normalizeTelegramUsername(telegramUsername);
    if (!normalizedUsername) return undefined;

    return (await this.store.listApproverUsers(workspaceId)).find(
      (user) => user.enabled && normalizeTelegramUsername(user.telegramUsername) === normalizedUsername,
    );
  }

  slackAuthContext(user: ApproverUserRecord): AuthContext {
    return {
      authProvider: 'slack',
      displayName: user.displayName,
      email: user.email,
      groups: user.groups,
      principalId: authorizationPrincipalId(user),
      principalType: 'slack',
      scopes: ['approval:read', 'approval:approve', 'approval:reject'],
      workspaceId: user.workspaceId,
    };
  }

  telegramAuthContext(user: ApproverUserRecord): AuthContext {
    return {
      authProvider: 'telegram',
      displayName: user.displayName,
      email: user.email,
      groups: user.groups,
      principalId: authorizationPrincipalId(user),
      principalType: 'telegram',
      scopes: ['approval:read', 'approval:approve', 'approval:reject'],
      workspaceId: user.workspaceId,
    };
  }

  private async nextGeneratedDirectoryId(
    workspaceId: string,
    prefix: 'g' | 'u',
    displayName: string | undefined,
    fallback: string,
  ): Promise<string> {
    const [users, groups] = await Promise.all([
      this.store.listApproverUsers(workspaceId),
      this.store.listApproverGroups(workspaceId),
    ]);
    const existingIds = new Set([
      ...users.flatMap((user) => [user.id, authorizationPrincipalId(user)]),
      ...groups.map((group) => group.id),
    ]);
    const base = `${prefix}_${slugForId(displayName, fallback)}`;
    let candidate = base;
    for (let suffix = 2; suffix <= 10_000; suffix += 1) {
      if (!existingIds.has(candidate)) return candidate;
      candidate = `${base}_${suffix}`;
    }
    throw new ConflictError(`Could not allocate a unique approver directory id for ${base}.`);
  }

  private async assertUniqueAuthorizationIdentity(
    workspaceId: string,
    id: string,
    principalId: string | undefined,
  ): Promise<void> {
    const proposedIdentifiers = new Set([id, principalId ?? id]);
    const conflict = (await this.store.listApproverUsers(workspaceId)).find(
      (user) =>
        user.id !== id &&
        [user.id, authorizationPrincipalId(user)].some((identifier) => proposedIdentifiers.has(identifier)),
    );
    if (conflict) {
      throw new ConflictError(
        `Approver authorization identity conflicts with existing directory user: ${conflict.id}`,
      );
    }
  }
}

function userToRecipient(user: ApproverUserRecord): ApprovalNotificationRecipient {
  return {
    displayName: user.displayName,
    email: user.email,
    groups: user.groups,
    principalId: authorizationPrincipalId(user),
    slackUserId: user.slackUserId,
    telegramChatId: user.telegramChatId,
    telegramUsername: user.telegramUsername,
    telegramUserId: user.telegramUserId,
    userId: user.id,
  };
}

function authorizationPrincipalId(user: ApproverUserRecord): string {
  return blankToUndefined(user.principalId) ?? user.id;
}

function policyRules(policy: PolicyFile): Array<[string, PolicyRule]> {
  return [['default', policy.default], ...Object.entries(policy.tools)];
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort();
}

function blankToUndefined(value: string | undefined): string | undefined {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function slugForId(value: string | undefined, fallback: string): string {
  return (
    blankToUndefined(value)
      ?.toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '') || fallback
  );
}

export function normalizeTelegramUsername(value: string | undefined): string | undefined {
  const trimmed = blankToUndefined(value);
  if (!trimmed) return undefined;
  return trimmed.replace(/^@+/, '').trim().toLowerCase() || undefined;
}
