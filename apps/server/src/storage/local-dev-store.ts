import fs from 'node:fs';
import path from 'node:path';
import type { ApproverGroupRecord, ApproverUserRecord } from '../models';
import { MemoryStore } from './memory-store';

interface ApproverDirectoryFile {
  groups: ApproverGroupRecord[];
  updatedAt: string;
  users: ApproverUserRecord[];
  version: 1;
}

export class LocalDevStore extends MemoryStore {
  private readonly approverDirectoryPath: string;
  private readonly persistedApproverUsers = new Map<string, ApproverUserRecord>();
  private readonly persistedApproverGroups = new Map<string, ApproverGroupRecord>();

  constructor(approverDirectoryPath: string) {
    super();
    this.approverDirectoryPath = path.resolve(approverDirectoryPath);
    this.loadApproverDirectory();
  }

  override async upsertApproverUser(record: ApproverUserRecord): Promise<ApproverUserRecord> {
    this.persistedApproverUsers.set(workspaceKey(record.workspaceId, record.id), record);
    this.persistApproverDirectory();
    return record;
  }

  override async getApproverUser(workspaceId: string, id: string): Promise<ApproverUserRecord | undefined> {
    return this.persistedApproverUsers.get(workspaceKey(workspaceId, id));
  }

  override async listApproverUsers(workspaceId: string): Promise<ApproverUserRecord[]> {
    return [...this.persistedApproverUsers.values()]
      .filter((user) => user.workspaceId === workspaceId)
      .sort((left, right) => left.displayName.localeCompare(right.displayName));
  }

  override async deleteApproverUser(workspaceId: string, id: string): Promise<boolean> {
    const deleted = this.persistedApproverUsers.delete(workspaceKey(workspaceId, id));
    if (deleted) this.persistApproverDirectory();
    return deleted;
  }

  override async upsertApproverGroup(record: ApproverGroupRecord): Promise<ApproverGroupRecord> {
    this.persistedApproverGroups.set(workspaceKey(record.workspaceId, record.id), record);
    this.persistApproverDirectory();
    return record;
  }

  override async getApproverGroup(workspaceId: string, id: string): Promise<ApproverGroupRecord | undefined> {
    return this.persistedApproverGroups.get(workspaceKey(workspaceId, id));
  }

  override async listApproverGroups(workspaceId: string): Promise<ApproverGroupRecord[]> {
    return [...this.persistedApproverGroups.values()]
      .filter((group) => group.workspaceId === workspaceId)
      .sort((left, right) => left.displayName.localeCompare(right.displayName));
  }

  override async deleteApproverGroup(workspaceId: string, id: string): Promise<boolean> {
    const deleted = this.persistedApproverGroups.delete(workspaceKey(workspaceId, id));
    if (deleted) this.persistApproverDirectory();
    return deleted;
  }

  private loadApproverDirectory(): void {
    if (!fs.existsSync(this.approverDirectoryPath)) return;

    const parsed = JSON.parse(fs.readFileSync(this.approverDirectoryPath, 'utf8')) as unknown;
    const directory = parseApproverDirectoryFile(parsed, this.approverDirectoryPath);
    for (const user of directory.users) {
      this.persistedApproverUsers.set(workspaceKey(user.workspaceId, user.id), user);
    }
    for (const group of directory.groups) {
      this.persistedApproverGroups.set(workspaceKey(group.workspaceId, group.id), group);
    }
  }

  private persistApproverDirectory(): void {
    const directory: ApproverDirectoryFile = {
      groups: [...this.persistedApproverGroups.values()].sort(directoryRecordSort),
      updatedAt: new Date().toISOString(),
      users: [...this.persistedApproverUsers.values()].sort(directoryRecordSort),
      version: 1,
    };
    writeJsonFileAtomic(this.approverDirectoryPath, directory);
  }
}

function parseApproverDirectoryFile(value: unknown, filePath: string): ApproverDirectoryFile {
  if (!isRecord(value) || value.version !== 1 || !Array.isArray(value.users) || !Array.isArray(value.groups)) {
    throw new Error(`Invalid approver directory file: ${filePath}`);
  }

  return {
    groups: value.groups.map((group) => parseApproverGroupRecord(group, filePath)),
    updatedAt: typeof value.updatedAt === 'string' ? value.updatedAt : new Date(0).toISOString(),
    users: value.users.map((user) => parseApproverUserRecord(user, filePath)),
    version: 1,
  };
}

function parseApproverUserRecord(value: unknown, filePath: string): ApproverUserRecord {
  if (!isRecord(value)) throw new Error(`Invalid approver user in ${filePath}`);
  const groups = value.groups;
  if (
    typeof value.id !== 'string' ||
    typeof value.workspaceId !== 'string' ||
    typeof value.displayName !== 'string' ||
    !Array.isArray(groups) ||
    !groups.every((group) => typeof group === 'string') ||
    typeof value.defaultApprover !== 'boolean' ||
    typeof value.enabled !== 'boolean' ||
    typeof value.createdAt !== 'string' ||
    typeof value.updatedAt !== 'string'
  ) {
    throw new Error(`Invalid approver user in ${filePath}`);
  }

  return {
    createdAt: value.createdAt,
    defaultApprover: value.defaultApprover,
    displayName: value.displayName,
    email: optionalString(value.email),
    enabled: value.enabled,
    groups,
    id: value.id,
    principalId: optionalString(value.principalId),
    slackUserId: optionalString(value.slackUserId),
    telegramChatId: optionalString(value.telegramChatId),
    telegramUsername: optionalString(value.telegramUsername),
    telegramUserId: optionalString(value.telegramUserId),
    updatedAt: value.updatedAt,
    workspaceId: value.workspaceId,
  };
}

function parseApproverGroupRecord(value: unknown, filePath: string): ApproverGroupRecord {
  if (!isRecord(value)) throw new Error(`Invalid approver group in ${filePath}`);
  if (
    typeof value.id !== 'string' ||
    typeof value.workspaceId !== 'string' ||
    typeof value.displayName !== 'string' ||
    typeof value.enabled !== 'boolean' ||
    typeof value.createdAt !== 'string' ||
    typeof value.updatedAt !== 'string'
  ) {
    throw new Error(`Invalid approver group in ${filePath}`);
  }

  return {
    createdAt: value.createdAt,
    description: optionalString(value.description),
    displayName: value.displayName,
    enabled: value.enabled,
    id: value.id,
    updatedAt: value.updatedAt,
    workspaceId: value.workspaceId,
  };
}

function writeJsonFileAtomic(filePath: string, value: ApproverDirectoryFile): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { mode: 0o700, recursive: true });
  chmodIfPossible(dir, 0o700);

  const tempPath = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`);
  try {
    fs.writeFileSync(tempPath, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    chmodIfPossible(tempPath, 0o600);
    fs.renameSync(tempPath, filePath);
    chmodIfPossible(filePath, 0o600);
  } catch (error) {
    try {
      fs.unlinkSync(tempPath);
    } catch {
      // Best effort cleanup after a failed atomic write.
    }
    throw error;
  }
}

function directoryRecordSort<T extends { id: string; workspaceId: string }>(left: T, right: T): number {
  return `${left.workspaceId}:${left.id}`.localeCompare(`${right.workspaceId}:${right.id}`);
}

function chmodIfPossible(filePath: string, mode: number): void {
  try {
    fs.chmodSync(filePath, mode);
  } catch {
    // Some filesystems do not support POSIX modes; the write path remains atomic.
  }
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function workspaceKey(workspaceId: string, id: string): string {
  return `${workspaceId}:${id}`;
}
