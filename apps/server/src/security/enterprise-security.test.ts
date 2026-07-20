import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { AppConfig, AuthConfig } from '../config';
import { buildApp } from '../app';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('enterprise security controls', () => {
  it.each(['none', 'api_key', 'oidc_jwt'] as const)(
    'keeps MCP stdio discovery disabled while profile save and YAML generation work in %s auth mode',
    async (authMode) => {
      const auth = mcpAuthSetup(authMode);
      app = await makeApp({ authMode, oidc: auth.oidc });
      const saved = await app.inject({
        headers: auth.headers,
        method: 'PUT',
        payload: {
          actionproxy: { baseUrl: 'http://localhost:8787' },
          server: { command: 'this-command-must-not-spawn', name: `disabled-${authMode}` },
        },
        url: `/v1/integrations/mcp-wrapper/profiles/disabled-${authMode}`,
      });
      const yaml = await app.inject({
        headers: auth.headers,
        method: 'GET',
        url: `/v1/integrations/mcp-wrapper/profiles/disabled-${authMode}/yaml`,
      });
      const sync = await app.inject({
        headers: auth.headers,
        method: 'POST',
        url: `/v1/integrations/mcp-wrapper/profiles/disabled-${authMode}/sync-tools`,
      });

      expect(saved.statusCode).toBe(200);
      expect(yaml.statusCode).toBe(200);
      expect(sync.statusCode).toBe(409);
      expect(sync.json()).toMatchObject({ error: 'mcp_stdio_discovery_disabled' });
    },
  );

  it.each(['none', 'api_key', 'oidc_jwt'] as const)(
    'allows explicitly opted-in MCP stdio discovery in %s auth mode',
    async (authMode) => {
      const auth = mcpAuthSetup(authMode);
      app = await makeApp({ authMode, mcpStdioDiscoveryEnabled: true, oidc: auth.oidc });
      const profileId = `enabled-${authMode}`;
      const serverPath = path.resolve('../../examples/mcp-demo/server.mjs');
      const saved = await app.inject({
        headers: auth.headers,
        method: 'PUT',
        payload: {
          actionproxy: { baseUrl: 'http://localhost:8787' },
          server: { args: [serverPath], command: process.execPath, name: profileId },
        },
        url: `/v1/integrations/mcp-wrapper/profiles/${profileId}`,
      });
      const sync = await app.inject({
        headers: auth.headers,
        method: 'POST',
        url: `/v1/integrations/mcp-wrapper/profiles/${profileId}/sync-tools`,
      });

      expect(saved.statusCode).toBe(200);
      expect(sync.statusCode).toBe(200);
      expect(sync.json().tools).toEqual(
        expect.arrayContaining([expect.objectContaining({ name: 'docs.search' })]),
      );
    },
  );

  it('requires auth in API key mode and stores only hashed API keys', async () => {
    app = await makeApp({ authMode: 'api_key' });

    const unauthenticated = await app.inject({ method: 'GET', url: '/v1/tool-calls' });
    expect(unauthenticated.statusCode).toBe(401);

    const createdAccount = await app.inject({
      headers: bootstrapHeaders(),
      method: 'POST',
      payload: {
        groups: ['agents'],
        name: 'demo-agent',
        scopes: ['tool_call:submit', 'tool_call:read'],
      },
      url: '/v1/service-accounts',
    });
    expect(createdAccount.statusCode).toBe(200);
    const serviceAccountId = createdAccount.json().serviceAccount.id as string;

    const createdKey = await app.inject({
      headers: bootstrapHeaders(),
      method: 'POST',
      payload: {},
      url: `/v1/service-accounts/${serviceAccountId}/keys`,
    });
    const keyBody = createdKey.json();
    expect(createdKey.statusCode).toBe(200);
    expect(keyBody.token).toMatch(/^apx_/);
    expect(JSON.stringify(keyBody)).not.toContain('keyHash');

    const me = await app.inject({ headers: bearerHeaders(keyBody.token), method: 'GET', url: '/v1/me' });
    expect(me.statusCode).toBe(200);
    expect(me.json().auth).toMatchObject({ principalId: serviceAccountId, principalType: 'service_account' });
  });

  it('fails closed for malformed OIDC bearer tokens', async () => {
    app = await makeApp({ authMode: 'oidc_jwt' });

    const response = await app.inject({
      headers: bearerHeaders('not-a-jwt'),
      method: 'GET',
      url: '/v1/me',
    });

    expect(response.statusCode).toBe(401);
  });

  it('accepts valid OIDC JWTs and enforces their scoped authorization', async () => {
    const { jwksJson, token } = signedJwt({
      aud: 'actionproxy-api',
      email: 'alice@example.com',
      exp: Math.floor(Date.now() / 1000) + 300,
      groups: ['support-managers'],
      iss: 'https://issuer.example.com',
      name: 'Alice Admin',
      scope: 'tool_call:read',
      sub: 'user_alice',
    });
    app = await makeApp({
      authMode: 'oidc_jwt',
      oidc: {
        audience: 'actionproxy-api',
        issuer: 'https://issuer.example.com',
        jwksJson,
      },
    });

    const me = await app.inject({
      headers: bearerHeaders(token),
      method: 'GET',
      url: '/v1/me',
    });
    expect(me.statusCode).toBe(200);
    expect(me.json().auth).toMatchObject({
      authProvider: 'oidc_jwt',
      displayName: 'Alice Admin',
      email: 'alice@example.com',
      groups: ['support-managers'],
      principalId: 'user_alice',
      scopes: ['tool_call:read'],
    });

    const scopedRead = await app.inject({
      headers: bearerHeaders(token),
      method: 'GET',
      url: '/v1/tool-calls',
    });
    expect(scopedRead.statusCode).toBe(200);

    const missingScope = await app.inject({
      headers: bearerHeaders(token),
      method: 'GET',
      url: '/v1/audit',
    });
    expect(missingScope.statusCode).toBe(403);
    expect(missingScope.json().message).toContain('audit:read');
  });

  it('binds directory approvers to exact OIDC principals instead of generated directory ids', async () => {
    const { jwksJson, tokens } = signedJwts([
      {
        aud: 'actionproxy-api',
        email: 'alice@example.com',
        exp: Math.floor(Date.now() / 1000) + 300,
        iss: 'https://issuer.example.com',
        scope: 'admin:approvers tool_call:submit tool_call:read approval:read approval:approve',
        sub: 'oidc|alice',
      },
      {
        aud: 'actionproxy-api',
        email: 'mallory@example.com',
        exp: Math.floor(Date.now() / 1000) + 300,
        iss: 'https://issuer.example.com',
        scope: 'approval:read approval:approve',
        sub: 'oidc|mallory',
      },
    ]);
    const [aliceToken, malloryToken] = tokens;
    app = await makeApp({
      authMode: 'oidc_jwt',
      oidc: {
        audience: 'actionproxy-api',
        issuer: 'https://issuer.example.com',
        jwksJson,
      },
    });

    const createdApprover = await app.inject({
      headers: bearerHeaders(aliceToken!),
      method: 'POST',
      payload: {
        defaultApprover: true,
        displayName: 'Alice Approver',
        email: 'alice@example.com',
        principalId: 'oidc|alice',
      },
      url: '/v1/approvers/users',
    });
    expect(createdApprover.statusCode).toBe(201);
    expect(createdApprover.json().user).toMatchObject({
      id: 'u_alice_approver',
      principalId: 'oidc|alice',
    });

    const submitted = await app.inject({
      headers: bearerHeaders(aliceToken!),
      method: 'POST',
      payload: {
        agentId: 'oidc-agent',
        input: { body: 'Thanks', subject: 'Update', to: 'customer@example.com' },
        reason: 'Send a customer update',
        toolName: 'gmail.send_email',
      },
      url: '/v1/tool-calls',
    });
    expect(submitted.statusCode).toBe(200);
    expect(submitted.json().approval).toMatchObject({ status: 'pending' });
    const approvalId = submitted.json().approval.id as string;

    const unrelatedApproval = await app.inject({
      headers: bearerHeaders(malloryToken!),
      method: 'POST',
      payload: {},
      url: `/v1/approvals/${approvalId}/approve`,
    });
    expect(unrelatedApproval.statusCode).toBe(403);
    expect(unrelatedApproval.json().message).toContain('not an allowed approver');

    const aliceApproval = await app.inject({
      headers: bearerHeaders(aliceToken!),
      method: 'POST',
      payload: {},
      url: `/v1/approvals/${approvalId}/approve`,
    });
    expect(aliceApproval.statusCode).toBe(200);
    expect(aliceApproval.json().toolCall.status).toBe('executed');
  });

  it('applies security headers, strict CORS, and per-route rate limits', async () => {
    app = await makeApp({
      allowedCorsOrigins: ['https://console.example.com'],
      rateLimit: { max: 2, windowMs: 60_000 },
    });

    const allowedOrigin = await app.inject({
      headers: { origin: 'https://console.example.com' },
      method: 'GET',
      url: '/health',
    });
    expect(allowedOrigin.statusCode).toBe(200);
    expect(allowedOrigin.headers['access-control-allow-origin']).toBe('https://console.example.com');
    expect(allowedOrigin.headers['content-security-policy']).toContain("default-src 'none'");
    expect(allowedOrigin.headers['x-frame-options']).toBe('DENY');

    const blockedOrigin = await app.inject({
      headers: { origin: 'https://evil.example.com' },
      method: 'GET',
      url: '/health',
    });
    expect(blockedOrigin.statusCode).toBe(200);
    expect(blockedOrigin.headers['access-control-allow-origin']).toBeUndefined();

    const first = await app.inject({ method: 'GET', url: '/v1/me' });
    const second = await app.inject({ method: 'GET', url: '/v1/me' });
    const third = await app.inject({ method: 'GET', url: '/v1/me' });
    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    expect(third.statusCode).toBe(429);
  });

  it('enforces approver groups and separation of duties', async () => {
    const policyPath = writePolicy({
      'gmail.send_email': [
        '    approval: required',
        '    risk: external_communication',
        '    reason: Email requires approval.',
        '    approvers:',
        '      groups: [support-managers]',
        '      separationOfDuties: true',
      ],
    });
    app = await makeApp({ authMode: 'api_key', policyPath });

    const submitterToken = await createServiceAccountKey(app, {
      groups: ['support-managers'],
      name: 'submitter',
      scopes: ['tool_call:submit', 'tool_call:read', 'approval:read', 'approval:approve'],
    });
    const approverToken = await createServiceAccountKey(app, {
      groups: ['support-managers'],
      name: 'manager',
      scopes: ['approval:read', 'approval:approve', 'tool_call:read'],
    });
    const outsiderToken = await createServiceAccountKey(app, {
      groups: ['finance'],
      name: 'outsider',
      scopes: ['approval:read', 'approval:approve'],
    });

    const submitted = await app.inject({
      headers: bearerHeaders(submitterToken),
      method: 'POST',
      payload: {
        agentId: 'demo-agent',
        input: { body: 'Thanks', subject: 'Update', to: 'customer@example.com' },
        reason: 'Send email',
        toolName: 'gmail.send_email',
      },
      url: '/v1/tool-calls',
    });
    const approvalId = submitted.json().approval.id as string;

    const selfApproval = await app.inject({
      headers: bearerHeaders(submitterToken),
      method: 'POST',
      payload: {},
      url: `/v1/approvals/${approvalId}/approve`,
    });
    expect(selfApproval.statusCode).toBe(403);

    const outsiderApproval = await app.inject({
      headers: bearerHeaders(outsiderToken),
      method: 'POST',
      payload: {},
      url: `/v1/approvals/${approvalId}/approve`,
    });
    expect(outsiderApproval.statusCode).toBe(403);

    const managerApproval = await app.inject({
      headers: bearerHeaders(approverToken),
      method: 'POST',
      payload: {},
      url: `/v1/approvals/${approvalId}/approve`,
    });
    expect(managerApproval.statusCode).toBe(200);
    expect(managerApproval.json().toolCall.status).toBe('executed');
  });

  it('issues and consumes signed external execution grants once', async () => {
    app = await makeApp();
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'mcp-wrapper',
        input: { query: 'refund' },
        metadata: { actionproxyExecution: 'external' },
        reason: 'Authorize external read',
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });
    const body = submitted.json();
    expect(body.toolCall.status).toBe('authorized');
    const grant = body.toolCall.result.grant;
    const receipt = body.toolCall.result.receipt;
    expect(grant.id).toMatch(/^grant_/);
    expect(receipt.id).toMatch(/^receipt_/);
    expect(grant.receiptId).toBe(receipt.id);
    expect(grant.receiptHash).toBe(receipt.receiptHash);

    const fetchedReceipt = await app.inject({ method: 'GET', url: `/v1/receipts/${receipt.id}` });
    expect(fetchedReceipt.statusCode).toBe(200);
    expect(fetchedReceipt.json().receipt).toMatchObject({
      approvedInputHash: receipt.approvedInputHash,
      decisionKind: 'policy_allow',
      receiptHash: receipt.receiptHash,
      toolCallId: body.id,
    });

    const consumed = await app.inject({
      method: 'POST',
      payload: {
        input: { query: 'refund' },
        policyVersionHash: grant.policyVersionHash,
        toolCallId: body.id,
        toolName: 'docs.search',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(consumed.statusCode).toBe(200);
    expect(consumed.json().grant.receiptId).toBe(receipt.id);

    const outcome = await app.inject({
      method: 'POST',
      payload: {
        result: { rows: 1 },
        status: 'succeeded',
      },
      url: `/v1/execution-grants/${grant.id}/outcome`,
    });
    expect(outcome.statusCode).toBe(200);
    expect(outcome.json().receipt.outcome).toMatchObject({ result: { rows: 1 }, status: 'succeeded' });
    expect(outcome.json().toolCall.status).toBe('executed');

    const idempotentOutcome = await app.inject({
      method: 'POST',
      payload: {
        result: { rows: 1 },
        status: 'succeeded',
      },
      url: `/v1/execution-grants/${grant.id}/outcome`,
    });
    expect(idempotentOutcome.statusCode).toBe(200);

    const replay = await app.inject({
      method: 'POST',
      payload: {
        input: { query: 'refund' },
        toolCallId: body.id,
        toolName: 'docs.search',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(replay.statusCode).toBe(409);
  });

  it('rejects an issued execution grant when its policy version is no longer active', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-grant-policy-revalidation-'));
    const policyPath = path.join(tempDir, 'policy.yaml');
    fs.copyFileSync(path.resolve('src/policies/default.policy.yaml'), policyPath);
    app = await makeApp({ policyPath });
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'mcp-wrapper',
        input: { query: 'refund' },
        metadata: { actionproxyExecution: 'external' },
        reason: 'Authorize external read',
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });
    const body = submitted.json();
    const grant = body.toolCall.result.grant;

    const policyUpdate = await app.inject({
      method: 'PUT',
      payload: {
        default: { approval: 'required', reason: 'Unknown tools require approval.', risk: 'unknown' },
        tools: {
          'docs.search': { approval: 'deny', reason: 'Emergency deny.', risk: 'restricted' },
        },
        version: 2,
      },
      url: '/v1/policy',
    });
    expect(policyUpdate.statusCode).toBe(200);

    const consumed = await app.inject({
      method: 'POST',
      payload: {
        input: { query: 'refund' },
        policyVersionHash: grant.policyVersionHash,
        toolCallId: body.id,
        toolName: 'docs.search',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(consumed.statusCode).toBe(403);
    expect(consumed.json().message).toContain('policy version is no longer active');

    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=100' });
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          toolCallId: body.id,
          type: 'execution_grant.rejected',
        }),
      ]),
    );
  });

  it('rejects execution grant consumption when caller details do not match the grant', async () => {
    app = await makeApp();
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'mcp-wrapper',
        input: { query: 'refund' },
        metadata: { actionproxyExecution: 'external' },
        reason: 'Authorize external read',
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });
    const body = submitted.json();
    const grant = body.toolCall.result.grant;

    const wrongTool = await app.inject({
      method: 'POST',
      payload: {
        input: { query: 'refund' },
        policyVersionHash: grant.policyVersionHash,
        toolCallId: body.id,
        toolName: 'docs.other_search',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(wrongTool.statusCode).toBe(403);
    expect(wrongTool.json().message).toContain('does not match the requested tool call');

    const wrongToolCall = await app.inject({
      method: 'POST',
      payload: {
        input: { query: 'refund' },
        policyVersionHash: grant.policyVersionHash,
        toolCallId: 'toolcall_other',
        toolName: 'docs.search',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(wrongToolCall.statusCode).toBe(403);
    expect(wrongToolCall.json().message).toContain('does not match the requested tool call');

    const wrongPolicy = await app.inject({
      method: 'POST',
      payload: {
        input: { query: 'refund' },
        policyVersionHash: 'policy_hash_other',
        toolCallId: body.id,
        toolName: 'docs.search',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(wrongPolicy.statusCode).toBe(403);
    expect(wrongPolicy.json().message).toContain('policy version does not match');

    const malformedOutcome = await app.inject({
      method: 'POST',
      payload: {
        status: 'done',
      },
      url: `/v1/execution-grants/${grant.id}/outcome`,
    });
    expect(malformedOutcome.statusCode).toBe(400);
    expect(malformedOutcome.json()).toMatchObject({ error: 'invalid_request' });

    const consumed = await app.inject({
      method: 'POST',
      payload: {
        input: { query: 'refund' },
        policyVersionHash: grant.policyVersionHash,
        toolCallId: body.id,
        toolName: 'docs.search',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(consumed.statusCode).toBe(200);
  });

  for (const storage of durableRaceStorageCases()) {
    const raceIt = storage.available ? it : it.skip;
    raceIt(`allows exactly one concurrent execution-grant consumption with ${storage.mode} storage`, async () => {
      app = await makeApp({ storageMode: storage.mode });
      const submitted = await app.inject({
        method: 'POST',
        payload: {
          agentId: 'mcp-wrapper',
          input: { query: 'refund' },
          metadata: { actionproxyExecution: 'external' },
          reason: 'Authorize concurrent grant consumption',
          requestedBy: 'dev@example.com',
          toolName: 'docs.search',
        },
        url: '/v1/tool-calls',
      });
      const body = submitted.json();
      const grant = body.toolCall.result.grant;
      const payload = {
        input: { query: 'refund' },
        policyVersionHash: grant.policyVersionHash,
        toolCallId: body.id,
        toolName: 'docs.search',
      };

      const responses = await Promise.all(
        Array.from({ length: 12 }, () =>
          app!.inject({
            method: 'POST',
            payload,
            url: `/v1/execution-grants/${grant.id}/consume`,
          }),
        ),
      );

      expect(responses.filter((response) => response.statusCode === 200)).toHaveLength(1);
      expect(responses.filter((response) => response.statusCode === 409)).toHaveLength(11);
    });
  }

  it('rejects edited input with a clear conflict when multiple approvals are required', async () => {
    const policyPath = writePolicy({
      'gmail.send_email': [
        '    approval: required',
        '    risk: external_communication',
        '    reason: Two reviewers must approve the original payload.',
        '    approvers:',
        '      requiredApprovals: 2',
      ],
    });
    app = await makeApp({ policyPath });
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'demo-agent',
        input: { subject: 'Original', to: 'customer@example.com' },
        reason: 'Exercise multi-approver edit rejection',
        requestedBy: 'dev@example.com',
        toolName: 'gmail.send_email',
      },
      url: '/v1/tool-calls',
    });

    const response = await app.inject({
      method: 'POST',
      payload: {
        approvedBy: 'manager@example.com',
        editedInput: { subject: 'Edited', to: 'customer@example.com' },
      },
      url: `/v1/approvals/${submitted.json().approval.id}/approve`,
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({
      error: 'conflict',
      message: 'Edited input is not supported when requiredApprovals is greater than 1.',
    });
  });

  it('records external remediation descriptors and exposes remediation plans', async () => {
    app = await makeApp();
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'mcp-wrapper',
        input: { query: 'refund' },
        metadata: { actionproxyExecution: 'external' },
        reason: 'Authorize external read',
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });
    const body = submitted.json();
    const grant = body.toolCall.result.grant;

    const consumed = await app.inject({
      method: 'POST',
      payload: {
        input: { query: 'refund' },
        policyVersionHash: grant.policyVersionHash,
        toolCallId: body.id,
        toolName: 'docs.search',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(consumed.statusCode).toBe(200);

    const outcome = await app.inject({
      method: 'POST',
      payload: {
        remediation: {
          evidence: { downstreamRunId: 'run_123', previousSnapshotId: 'snapshot_1' },
          input: { snapshotId: 'snapshot_1' },
          kind: 'soft_revert',
          reason: 'Restore the downstream record from the runner-provided snapshot.',
          status: 'available',
          toolName: 'docs.restore_snapshot',
        },
        result: { rows: 1 },
        status: 'succeeded',
      },
      url: `/v1/execution-grants/${grant.id}/outcome`,
    });
    expect(outcome.statusCode).toBe(200);
    expect(outcome.json().receipt.outcome.remediation).toMatchObject({
      kind: 'soft_revert',
      status: 'available',
      toolName: 'docs.restore_snapshot',
    });

    const plan = await app.inject({ method: 'GET', url: `/v1/tool-calls/${body.id}/remediation-plan` });
    expect(plan.statusCode).toBe(200);
    expect(plan.json().remediation).toMatchObject({
      evidence: { downstreamRunId: 'run_123', previousSnapshotId: 'snapshot_1' },
      input: { snapshotId: 'snapshot_1' },
      kind: 'soft_revert',
      status: 'available',
      toolName: 'docs.restore_snapshot',
    });
  });

  it('rejects external execution outcomes before grant consumption', async () => {
    app = await makeApp();
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'mcp-wrapper',
        input: { query: 'refund' },
        metadata: { actionproxyExecution: 'external' },
        reason: 'Authorize external read',
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });
    const body = submitted.json();
    const grant = body.toolCall.result.grant;

    const outcome = await app.inject({
      method: 'POST',
      payload: {
        result: { rows: 1 },
        status: 'succeeded',
      },
      url: `/v1/execution-grants/${grant.id}/outcome`,
    });

    expect(outcome.statusCode).toBe(409);
    expect(outcome.json().message).toContain('has not been consumed');
  });

  it('records failed external execution outcomes and rejects conflicting rewrites', async () => {
    app = await makeApp();
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'mcp-wrapper',
        input: { query: 'refund' },
        metadata: { actionproxyExecution: 'external' },
        reason: 'Authorize external read',
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });
    const body = submitted.json();
    const grant = body.toolCall.result.grant;

    const consumed = await app.inject({
      method: 'POST',
      payload: {
        input: { query: 'refund' },
        policyVersionHash: grant.policyVersionHash,
        toolCallId: body.id,
        toolName: 'docs.search',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(consumed.statusCode).toBe(200);

    const failed = await app.inject({
      method: 'POST',
      payload: {
        error: 'Downstream timeout',
        status: 'failed',
      },
      url: `/v1/execution-grants/${grant.id}/outcome`,
    });
    expect(failed.statusCode).toBe(200);
    expect(failed.json().receipt.outcome).toMatchObject({ error: 'Downstream timeout', status: 'failed' });
    expect(failed.json().toolCall).toMatchObject({ error: 'Downstream timeout', status: 'failed' });

    const conflictingRewrite = await app.inject({
      method: 'POST',
      payload: {
        result: { rows: 1 },
        status: 'succeeded',
      },
      url: `/v1/execution-grants/${grant.id}/outcome`,
    });
    expect(conflictingRewrite.statusCode).toBe(409);
  });

  it('renders trusted review from the action envelope and rejects stale review hashes', async () => {
    app = await makeApp();
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        action: {
          operation: { kind: 'external_send', name: 'Send customer email' },
          protocol: 'actionproxy_http',
          resources: [{ id: 'customer_123', name: 'Customer 123', type: 'customer' }],
          source: { name: 'test-agent', type: 'sdk' },
        },
        agentId: 'demo-agent',
        input: { body: 'Hello', subject: 'Update', to: 'customer@example.com' },
        reason: 'Send email',
        requestedBy: 'dev@example.com',
        toolName: 'gmail.send_email',
      },
      url: '/v1/tool-calls',
    });
    const approvalId = submitted.json().approval.id as string;

    const review = await app.inject({ method: 'GET', url: `/v1/approvals/${approvalId}/review` });
    expect(review.statusCode).toBe(200);
    expect(review.json()).toMatchObject({
      actionEnvelope: {
        operation: { kind: 'external_send', name: 'Send customer email' },
        protocol: 'actionproxy_http',
        resources: [{ id: 'customer_123', name: 'Customer 123', type: 'customer' }],
        toolName: 'gmail.send_email',
      },
      proposerRationaleTrust: 'untrusted',
    });

    const staleDecision = await app.inject({
      method: 'POST',
      payload: {
        approvedBy: 'manager@example.com',
        inputDecision: { mode: 'original' },
        reviewHash: 'review_stale',
      },
      url: `/v1/approvals/${approvalId}/approve`,
    });
    expect(staleDecision.statusCode).toBe(409);

    const approved = await app.inject({
      method: 'POST',
      payload: {
        approvedBy: 'manager@example.com',
        inputDecision: { mode: 'original' },
        reviewHash: review.json().reviewHash,
      },
      url: `/v1/approvals/${approvalId}/approve`,
    });
    expect(approved.statusCode).toBe(200);
    expect(approved.json().approval.reviewHash).toBe(review.json().reviewHash);
    expect(approved.json().approval.approvedInputHash).toBe(review.json().actionEnvelope.inputHash);
  });

  it('binds external execution grants to the approved input payload', async () => {
    app = await makeApp();
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'mcp-wrapper',
        input: { body: 'Original', subject: 'Original', to: 'customer@example.com' },
        metadata: { actionproxyExecution: 'external' },
        reason: 'Authorize approved email',
        requestedBy: 'dev@example.com',
        toolName: 'gmail.send_email',
      },
      url: '/v1/tool-calls',
    });
    const approvalId = submitted.json().approval.id as string;
    const editedInput = { body: 'Edited', subject: 'Approved update', to: 'customer@example.com' };
    const approved = await app.inject({
      method: 'POST',
      payload: {
        approvedBy: 'manager@example.com',
        editedInput,
      },
      url: `/v1/approvals/${approvalId}/approve`,
    });
    const approvedBody = approved.json();
    const grant = approvedBody.toolCall.result.grant;

    const wrongPayload = await app.inject({
      method: 'POST',
      payload: {
        input: { body: 'Original', subject: 'Original', to: 'customer@example.com' },
        policyVersionHash: grant.policyVersionHash,
        toolCallId: approvedBody.toolCall.id,
        toolName: 'gmail.send_email',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(wrongPayload.statusCode).toBe(403);

    const consumed = await app.inject({
      method: 'POST',
      payload: {
        input: editedInput,
        policyVersionHash: grant.policyVersionHash,
        toolCallId: approvedBody.toolCall.id,
        toolName: 'gmail.send_email',
      },
      url: `/v1/execution-grants/${grant.id}/consume`,
    });
    expect(consumed.statusCode).toBe(200);
  });

  it('verifies hash-chained audit events and redacts sensitive reads', async () => {
    app = await makeApp();
    await app.inject({
      method: 'POST',
      payload: {
        agentId: 'demo-agent',
        input: { query: 'refund', token: 'secret-token' },
        reason: 'Search docs',
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });

    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=20' });
    const auditText = JSON.stringify(audit.json());
    expect(audit.statusCode).toBe(200);
    expect(auditText).toContain('[REDACTED]');
    expect(auditText).not.toContain('secret-token');

    const verification = await app.inject({ method: 'GET', url: '/v1/audit/verify' });
    expect(verification.statusCode).toBe(200);
    expect(verification.json()).toMatchObject({ valid: true });
  });
});

async function createServiceAccountKey(
  server: FastifyInstance,
  input: { groups: string[]; name: string; scopes: string[] },
): Promise<string> {
  const createdAccount = await server.inject({
    headers: bootstrapHeaders(),
    method: 'POST',
    payload: input,
    url: '/v1/service-accounts',
  });
  const serviceAccountId = createdAccount.json().serviceAccount.id as string;
  const createdKey = await server.inject({
    headers: bootstrapHeaders(),
    method: 'POST',
    payload: {},
    url: `/v1/service-accounts/${serviceAccountId}/keys`,
  });
  return createdKey.json().token as string;
}

interface MakeAppOptions {
  allowedCorsOrigins?: string[];
  authMode?: 'api_key' | 'none' | 'oidc_jwt';
  oidc?: Partial<AuthConfig['oidc']>;
  mcpStdioDiscoveryEnabled?: boolean;
  policyPath?: string;
  rateLimit?: { max: number; windowMs: number };
  storageMode?: 'memory' | 'sqlite';
}

async function makeApp(options: MakeAppOptions = {}): Promise<FastifyInstance> {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-enterprise-security-test-'));
  const config: AppConfig = {
    auth: {
      allowedCorsOrigins: options.allowedCorsOrigins ?? [],
      bootstrapAdminApiKey: 'test-bootstrap-key',
      mode: options.authMode ?? 'none',
      oidc: {
        emailClaim: 'email',
        groupsClaim: 'groups',
        nameClaim: 'name',
        scopesClaim: 'scope',
        ...options.oidc,
      },
      rateLimit: {
        max: options.rateLimit?.max ?? 1000,
        windowMs: options.rateLimit?.windowMs ?? 60_000,
      },
      slackUserMap: {},
      workspaceId: 'default',
    },
    dataDir,
    executionGrants: {
      secret: 'test-execution-grant-secret',
      ttlSeconds: 300,
    },
    host: '127.0.0.1',
    localExecution: { mode: 'mock' },
    logLevel: 'silent',
    mcp: { stdioDiscoveryEnabled: options.mcpStdioDiscoveryEnabled ?? false },
    policyPath: options.policyPath ?? path.resolve('src/policies/default.policy.yaml'),
    port: 0,
    storage: options.storageMode
      ? {
          mode: options.storageMode,
          sqlitePath: path.join(dataDir, 'actionproxy.sqlite'),
        }
      : undefined,
  };
  return buildApp(config);
}

function durableRaceStorageCases(): Array<{ available: boolean; mode: 'memory' | 'sqlite' }> {
  return [
    { available: true, mode: 'memory' },
    { available: hasSqliteCli(), mode: 'sqlite' },
  ];
}

function hasSqliteCli(): boolean {
  try {
    execFileSync('sqlite3', ['-version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function mcpAuthSetup(authMode: NonNullable<MakeAppOptions['authMode']>): {
  headers: Record<string, string>;
  oidc?: Partial<AuthConfig['oidc']>;
} {
  if (authMode === 'none') return { headers: {} };
  if (authMode === 'api_key') return { headers: bootstrapHeaders() };

  const { jwksJson, token } = signedJwt({
    aud: 'actionproxy-api',
    exp: Math.floor(Date.now() / 1000) + 300,
    iss: 'https://issuer.example.com',
    scope: 'admin:integrations',
    sub: 'mcp-admin',
  });
  return {
    headers: bearerHeaders(token),
    oidc: {
      audience: 'actionproxy-api',
      issuer: 'https://issuer.example.com',
      jwksJson,
    },
  };
}

function writePolicy(tools: Record<string, string[]>): string {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-enterprise-policy-'));
  const policyPath = path.join(tempDir, 'policy.yaml');
  const lines = [
    'version: 2',
    '',
    'default:',
    '  approval: required',
    '  risk: unknown',
    '  reason: Unknown tools require approval.',
    '',
    'tools:',
  ];
  for (const [toolName, ruleLines] of Object.entries(tools)) {
    lines.push(`  ${toolName}:`, ...ruleLines);
  }
  fs.writeFileSync(policyPath, `${lines.join('\n')}\n`, 'utf8');
  return policyPath;
}

function signedJwt(payload: Record<string, unknown>): { jwksJson: string; token: string } {
  const result = signedJwts([payload]);
  return { jwksJson: result.jwksJson, token: result.tokens[0]! };
}

function signedJwts(payloads: Record<string, unknown>[]): { jwksJson: string; tokens: string[] } {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'test-rsa-key';
  const header = { alg: 'RS256', kid, typ: 'JWT' };
  const encodedHeader = base64UrlJson(header);
  const publicJwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  return {
    jwksJson: JSON.stringify({ keys: [{ ...publicJwk, alg: 'RS256', kid, use: 'sig' }] }),
    tokens: payloads.map((payload) => {
      const encodedPayload = base64UrlJson(payload);
      const signedValue = `${encodedHeader}.${encodedPayload}`;
      const signer = createSign('RSA-SHA256');
      signer.update(signedValue);
      signer.end();
      return `${signedValue}.${signer.sign(privateKey).toString('base64url')}`;
    }),
  };
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function bootstrapHeaders(): Record<string, string> {
  return bearerHeaders('test-bootstrap-key');
}

function bearerHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}
