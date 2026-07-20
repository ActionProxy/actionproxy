import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';

const describeIfSqlite = hasSqliteCli() ? describe : describe.skip;
let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('local dev app storage', () => {
  it('keeps the approver directory across memory-mode app restarts', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-local-dev-app-test-'));

    app = await makeMemoryApp(dataDir);
    const created = await app.inject({
      method: 'POST',
      payload: { displayName: 'Alice Manager', email: 'alice@example.com', defaultApprover: true },
      url: '/v1/approvers/users',
    });
    expect(created.statusCode).toBe(201);
    const userId = created.json().user.id as string;
    await app.close();

    app = await makeMemoryApp(dataDir);
    const listed = await app.inject({ method: 'GET', url: '/v1/approvers' });

    expect(listed.statusCode).toBe(200);
    expect(listed.json().users).toEqual([
      expect.objectContaining({
        defaultApprover: true,
        displayName: 'Alice Manager',
        email: 'alice@example.com',
        id: userId,
      }),
    ]);
  });
});

describeIfSqlite('durable app storage', () => {
  it('keeps approval and audit state across app restarts with sqlite storage', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-sqlite-app-test-'));
    const sqlitePath = path.join(tempDir, 'actionproxy.sqlite');

    app = await makeSqliteApp(tempDir, sqlitePath);
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'demo-agent',
        input: { body: 'Thanks', subject: 'Update', to: 'customer@example.com' },
        reason: 'Send email',
        requestedBy: 'dev@example.com',
        toolName: 'gmail.send_email',
      },
      url: '/v1/tool-calls',
    });
    const submittedBody = submitted.json();
    const approvalId = submittedBody.approval.id as string;
    await app.close();

    app = await makeSqliteApp(tempDir, sqlitePath);
    const pending = await app.inject({ method: 'GET', url: '/v1/approvals/pending' });
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=20' });

    expect(pending.json().approvals).toMatchObject([{ id: approvalId, status: 'pending' }]);
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ approvalId, type: 'approval.created' }),
        expect.objectContaining({ toolCallId: submittedBody.id, type: 'policy.require_approval' }),
      ]),
    );

    const approved = await app.inject({
      method: 'POST',
      payload: { approvedBy: 'manager@example.com' },
      url: `/v1/approvals/${approvalId}/approve`,
    });

    expect(approved.statusCode).toBe(200);
    expect(approved.json().toolCall).toMatchObject({
      result: { ok: true, tool: 'gmail.send_email', to: 'customer@example.com' },
      status: 'executed',
    });
  });
});

async function makeMemoryApp(dataDir: string): Promise<FastifyInstance> {
  return buildApp({
    dataDir,
    host: '127.0.0.1',
    localExecution: { mode: 'mock' },
    logLevel: 'silent',
    policyPath: path.resolve('src/policies/default.policy.yaml'),
    port: 0,
    storage: {
      mode: 'memory',
      sqlitePath: path.join(dataDir, 'actionproxy.sqlite'),
    },
  });
}

async function makeSqliteApp(dataDir: string, sqlitePath: string): Promise<FastifyInstance> {
  return buildApp({
    dataDir,
    host: '127.0.0.1',
    localExecution: { mode: 'mock' },
    logLevel: 'silent',
    policyPath: path.resolve('src/policies/default.policy.yaml'),
    port: 0,
    storage: {
      mode: 'sqlite',
      sqlitePath,
    },
  });
}

function hasSqliteCli(): boolean {
  try {
    execFileSync('sqlite3', ['-version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
