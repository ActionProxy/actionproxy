import { describe, expect, it } from 'vitest';
import { ApproverDirectoryService } from './approver-directory';
import { MemoryStore } from '../storage/memory-store';

describe('ApproverDirectoryService', () => {
  it('creates users and groups with generated unique ids', async () => {
    const directory = new ApproverDirectoryService(new MemoryStore());
    const firstUser = await directory.createUser('default', { displayName: 'Alice Manager' });
    const secondUser = await directory.createUser('default', { displayName: 'Alice Manager' });
    const firstGroup = await directory.createGroup('default', { displayName: 'Alice Manager' });
    const secondGroup = await directory.createGroup('default', { displayName: 'Alice Manager' });

    expect(firstUser).toMatchObject({ displayName: 'Alice Manager', id: 'u_alice_manager' });
    expect(secondUser).toMatchObject({ displayName: 'Alice Manager', id: 'u_alice_manager_2' });
    expect(firstGroup).toMatchObject({ displayName: 'Alice Manager', id: 'g_alice_manager' });
    expect(secondGroup).toMatchObject({ displayName: 'Alice Manager', id: 'g_alice_manager_2' });
  });

  it('resolves explicit users and groups, deduplicating enabled users', async () => {
    const directory = new ApproverDirectoryService(new MemoryStore());
    await directory.upsertGroup('default', 'support-managers', { displayName: 'Support managers' });
    await directory.upsertGroup('default', 'disabled-team', { displayName: 'Disabled team', enabled: false });
    await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      email: 'alice@example.com',
      groups: ['support-managers'],
      principalId: 'oidc|alice',
      slackUserId: 'U_ALICE',
      telegramChatId: '222',
      telegramUsername: '@Alice',
      telegramUserId: '111',
    });
    await directory.upsertUser('default', 'u_bob', {
      displayName: 'Bob',
      email: 'bob@example.com',
      groups: ['support-managers', 'disabled-team'],
    });
    await directory.upsertUser('default', 'u_disabled', {
      displayName: 'Disabled',
      email: 'disabled@example.com',
      enabled: false,
      groups: ['support-managers'],
    });

    await expect(
      directory.resolveRecipients(
        {
          approval: 'required',
          approvers: {
            groups: ['support-managers', 'disabled-team'],
            users: ['u_alice'],
          },
        },
        'default',
      ),
    ).resolves.toEqual([
      expect.objectContaining({
        email: 'alice@example.com',
        principalId: 'oidc|alice',
        slackUserId: 'U_ALICE',
        telegramChatId: '222',
        telegramUsername: 'alice',
        telegramUserId: '111',
        userId: 'u_alice',
      }),
      expect.objectContaining({ email: 'bob@example.com', userId: 'u_bob' }),
    ]);
  });

  it('uses default approvers when policy omits users and groups', async () => {
    const directory = new ApproverDirectoryService(new MemoryStore());
    await directory.upsertUser('default', 'u_alice', {
      defaultApprover: true,
      displayName: 'Alice',
      email: 'alice@example.com',
    });
    await directory.upsertUser('default', 'u_bob', {
      defaultApprover: false,
      displayName: 'Bob',
      email: 'bob@example.com',
    });

    await expect(directory.resolveRecipients({ approval: 'required' }, 'default')).resolves.toEqual([
      expect.objectContaining({ email: 'alice@example.com', userId: 'u_alice' }),
    ]);
  });

  it('uses the mapped principal for HTTP, Slack, and Telegram approval authority with a legacy fallback', async () => {
    const directory = new ApproverDirectoryService(new MemoryStore());
    const mapped = await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      principalId: 'oidc|alice',
    });
    const legacy = await directory.upsertUser('default', 'u_legacy', { displayName: 'Legacy approver' });

    expect(directory.slackAuthContext(mapped)).toMatchObject({
      authProvider: 'slack',
      principalId: 'oidc|alice',
      principalType: 'slack',
    });
    expect(directory.telegramAuthContext(mapped)).toMatchObject({
      authProvider: 'telegram',
      principalId: 'oidc|alice',
      principalType: 'telegram',
    });
    expect(directory.slackAuthContext(legacy).principalId).toBe('u_legacy');
    expect(directory.telegramAuthContext(legacy).principalId).toBe('u_legacy');
  });

  it('rejects ambiguous authorization identities across directory ids and mapped principals', async () => {
    const directory = new ApproverDirectoryService(new MemoryStore());
    await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      principalId: 'oidc|alice',
    });

    await expect(
      directory.upsertUser('default', 'u_bob', { displayName: 'Bob', principalId: 'oidc|alice' }),
    ).rejects.toThrow('authorization identity conflicts');
    await expect(
      directory.upsertUser('default', 'oidc|alice', { displayName: 'Legacy collision' }),
    ).rejects.toThrow('authorization identity conflicts');
  });

  it('validates policy references against enabled directory records', async () => {
    const directory = new ApproverDirectoryService(new MemoryStore());
    await directory.upsertGroup('default', 'support-managers', { displayName: 'Support managers' });
    await directory.upsertUser('default', 'u_alice', { displayName: 'Alice', email: 'alice@example.com' });

    await expect(
      directory.validatePolicy(
        {
          default: { approval: 'required' },
          tools: {
            'gmail.send_email': {
              approval: 'required',
              approvers: { groups: ['support-managers'], users: ['u_alice'] },
            },
          },
          version: 1,
        },
        'default',
      ),
    ).resolves.toBeUndefined();

    await expect(
      directory.validatePolicy(
        {
          default: { approval: 'required' },
          tools: {
            'gmail.send_email': {
              approval: 'required',
              approvers: { users: ['u_missing'] },
            },
          },
          version: 1,
        },
        'default',
      ),
    ).rejects.toThrow('unknown or disabled approver user: u_missing');
  });

  it('disconnects Telegram without removing the saved username', async () => {
    const directory = new ApproverDirectoryService(new MemoryStore());
    await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      telegramChatId: '222',
      telegramUsername: '@Alice',
      telegramUserId: '111',
    });

    const disconnected = await directory.disconnectTelegramUser('default', 'u_alice');

    expect(disconnected).toMatchObject({
      id: 'u_alice',
      telegramUsername: 'alice',
    });
    expect(disconnected.telegramChatId).toBeUndefined();
    expect(disconnected.telegramUserId).toBeUndefined();
  });

  it('deletes approver users from the directory', async () => {
    const directory = new ApproverDirectoryService(new MemoryStore());
    await directory.upsertUser('default', 'u_alice', { displayName: 'Alice' });

    const deleted = await directory.deleteUser('default', 'u_alice');

    expect(deleted).toMatchObject({ displayName: 'Alice', id: 'u_alice' });
    await expect(directory.getUser('default', 'u_alice')).resolves.toBeUndefined();
  });

  it('deletes approver groups and removes them from assigned users', async () => {
    const directory = new ApproverDirectoryService(new MemoryStore());
    await directory.upsertGroup('default', 'support-managers', { displayName: 'Support managers' });
    await directory.upsertUser('default', 'u_alice', {
      displayName: 'Alice',
      groups: ['support-managers', 'security-reviewers'],
    });

    const deleted = await directory.deleteGroup('default', 'support-managers');
    const alice = await directory.getUser('default', 'u_alice');
    const list = await directory.list('default');

    expect(deleted).toMatchObject({ displayName: 'Support managers', id: 'support-managers' });
    expect(list.groups).toEqual([]);
    expect(alice?.groups).toEqual(['security-reviewers']);
  });
});
