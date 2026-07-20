import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('policy routes', () => {
  it('returns a sanitized policy summary with exact, wildcard, and default decisions', async () => {
    app = await buildApp({
      dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-test-')),
      host: '127.0.0.1',
      localExecution: { mode: 'mock' },
      logLevel: 'silent',
      policyPath: path.resolve('src/policies/default.policy.yaml'),
      port: 0,
    });

    const response = await app.inject({ method: 'GET', url: '/v1/policy/summary' });
    const body = response.json();

    expect(response.statusCode).toBe(200);
    expect(body.defaultRule).toMatchObject({
      approval: 'required',
      decision: 'require_approval',
      matchType: 'default',
      pattern: 'default',
      resultSource: { integrity: 'unknown' },
    });
    expect(body.rules).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          decision: 'allow',
          matchType: 'exact',
          pattern: 'docs.search',
          resultSource: { integrity: 'organization_managed', sourceId: 'local-docs' },
        }),
        expect.objectContaining({
          influence: {
            allowFrom: ['none', 'organization_managed', 'verified_publisher'],
            otherwise: 'required',
          },
          pattern: 'jira.create_issue',
        }),
        expect.objectContaining({ decision: 'require_approval', matchType: 'wildcard', pattern: 'payments.*' }),
        expect.objectContaining({ decision: 'deny', matchType: 'exact', pattern: 'dangerous.delete_customer' }),
      ]),
    );
  });

  it('returns Community policy presets and typed condition keys', async () => {
    app = await buildApp({
      dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-presets-test-')),
      host: '127.0.0.1',
      localExecution: { mode: 'mock' },
      logLevel: 'silent',
      policyPath: path.resolve('src/policies/default.policy.yaml'),
      port: 0,
    });

    const response = await app.inject({ method: 'GET', url: '/v1/policy/presets' });
    const body = response.json();

    expect(response.statusCode).toBe(200);
    expect(body.conditions).toEqual([
      'approverGroup',
      'amount',
      'customerVisible',
      'operationKind',
      'recipientDomain',
      'risk',
    ]);
    expect(body.presets).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'safe_default', title: 'Safe default' }),
        expect.objectContaining({ id: 'strict', title: 'Strict' }),
        expect.objectContaining({ id: 'fast_internal', title: 'Fast internal' }),
      ]),
    );
    expect(body.presets.find((preset: { id: string }) => preset.id === 'safe_default').rules).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          pattern: 'docs.search',
          resultSource: { integrity: 'organization_managed', sourceId: 'local-docs-demo' },
        }),
      ]),
    );
    expect(body.presets.find((preset: { id: string }) => preset.id === 'fast_internal').rules).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          influence: {
            allowFrom: ['none', 'organization_managed'],
            otherwise: 'required',
          },
          pattern: 'jira.create_issue',
        }),
      ]),
    );
  });

  it('updates policy YAML and applies new decisions without restart', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-update-test-'));
    const policyPath = path.join(tempDir, 'policy.yaml');
    fs.writeFileSync(
      policyPath,
      [
        'version: 1',
        '',
        'default:',
        '  approval: required',
        '  risk: unknown',
        '  reason: Unknown tools require approval.',
        '',
        'tools:',
        '  gmail.send_email:',
        '    approval: required',
        '    risk: external_communication',
        '    reason: Email requires approval.',
        '',
      ].join('\n'),
      'utf8',
    );
    app = await buildApp({
      dataDir: tempDir,
      host: '127.0.0.1',
      localExecution: { mode: 'mock' },
      logLevel: 'silent',
      policyPath,
      port: 0,
    });

    const update = await app.inject({
      method: 'PUT',
      payload: {
        default: {
          approval: 'required',
          reason: 'Unknown tools require approval.',
          risk: 'unknown',
        },
        tools: {
          'docs.search': {
            approval: 'never',
            reason: 'Search can run locally.',
            risk: 'read_only',
          },
        },
        version: 1,
      },
      url: '/v1/policy',
    });
    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'demo-agent',
        input: { query: 'refund policy' },
        reason: 'Search docs',
        requestedBy: 'dev@example.com',
        toolName: 'docs.search',
      },
      url: '/v1/tool-calls',
    });
    const email = await app.inject({
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
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=20' });
    const written = fs.readFileSync(policyPath, 'utf8');

    expect(update.statusCode).toBe(200);
    expect(update.json().summary.rules).toEqual([
      expect.objectContaining({ decision: 'allow', pattern: 'docs.search' }),
    ]);
    expect(submitted.json()).toMatchObject({ decision: 'allow', status: 'executed' });
    expect(email.json()).toMatchObject({ decision: 'require_approval', status: 'pending_approval' });
    expect(written).toContain('docs.search:');
    expect(written).not.toContain('gmail.send_email:');
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor: 'local-admin',
          data: expect.objectContaining({ addedRules: ['docs.search'], removedRules: ['gmail.send_email'] }),
          type: 'policy.updated',
        }),
      ]),
    );
  });

  it('keeps existing decision traces pinned when policy changes without restart', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-trace-pin-test-'));
    const policyPath = path.join(tempDir, 'policy.yaml');
    fs.writeFileSync(
      policyPath,
      [
        'version: 1',
        '',
        'default:',
        '  approval: required',
        '  risk: unknown',
        '  reason: Unknown tools require approval.',
        '',
        'tools:',
        '  gmail.send_email:',
        '    approval: required',
        '    risk: external_communication',
        '    reason: Email requires approval.',
        '',
      ].join('\n'),
      'utf8',
    );
    app = await buildApp({
      dataDir: tempDir,
      host: '127.0.0.1',
      localExecution: { mode: 'mock' },
      logLevel: 'silent',
      policyPath,
      port: 0,
    });

    const original = await app.inject({
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
    const originalBody = original.json();
    const originalRecord = await app.inject({
      method: 'GET',
      url: `/v1/tool-calls/${originalBody.id}`,
    });
    const originalPolicyVersionHash = originalRecord.json().policyVersionHash;
    const updatedPolicy = await app.inject({
      method: 'PUT',
      payload: {
        default: {
          approval: 'required',
          reason: 'Unknown tools require approval.',
          risk: 'unknown',
        },
        tools: {
          'gmail.send_email': {
            approval: 'never',
            reason: 'Email sending is allowed for this test policy.',
            risk: 'external_communication',
          },
        },
        version: 1,
      },
      url: '/v1/policy',
    });
    const trace = await app.inject({
      method: 'GET',
      url: `/v1/tool-calls/${originalBody.id}/decision-trace`,
    });
    const next = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'demo-agent',
        input: { body: 'Thanks again', subject: 'Update', to: 'customer@example.com' },
        reason: 'Send email again',
        requestedBy: 'dev@example.com',
        toolName: 'gmail.send_email',
      },
      url: '/v1/tool-calls',
    });
    const nextRecord = await app.inject({
      method: 'GET',
      url: `/v1/tool-calls/${next.json().id}`,
    });

    expect(originalBody).toMatchObject({ decision: 'require_approval', status: 'pending_approval' });
    expect(originalPolicyVersionHash).toEqual(expect.any(String));
    expect(updatedPolicy.statusCode).toBe(200);
    expect(trace.json()).toMatchObject({
      decision: 'require_approval',
      matchedRule: 'gmail.send_email',
      policyReason: 'Email requires approval.',
      policyVersionHash: originalPolicyVersionHash,
      storedDecision: 'require_approval',
      toolCallId: originalBody.id,
    });
    expect(next.json()).toMatchObject({ decision: 'allow', status: 'executed' });
    expect(nextRecord.json().policyVersionHash).not.toBe(originalPolicyVersionHash);
  });

  it('simulates policy decisions without persisting tool calls, approvals, or audit events', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-simulate-test-'));
    app = await buildApp({
      dataDir: tempDir,
      host: '127.0.0.1',
      localExecution: { mode: 'mock' },
      logLevel: 'silent',
      policyPath: writePolicy(tempDir),
      port: 0,
    });

    const simulated = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'support-agent',
        input: {
          apiToken: 'super-secret-token',
          body: 'Thanks for writing in.',
          to: 'customer@example.com',
        },
        metadata: {
          customerVisible: true,
        },
        policyYaml: [
          'version: 1',
          '',
          'default:',
          '  approval: required',
          '  risk: unknown',
          '  reason: Unknown tools require approval.',
          '',
          'tools:',
          '  messages.public_reply:',
          '    approval: required',
          '    risk: external_communication',
          '    reason: Customer-visible replies require approval.',
          '    conditions:',
          '      customerVisible: true',
          '      operationKind: external_send',
          '',
        ].join('\n'),
        reason: 'Draft customer reply',
        requestedBy: 'dev@example.com',
        toolName: 'messages.public_reply',
      },
      url: '/v1/policy/simulate',
    });
    const toolCalls = await app.inject({ method: 'GET', url: '/v1/tool-calls' });
    const pending = await app.inject({ method: 'GET', url: '/v1/approvals/pending' });
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=20' });

    expect(simulated.statusCode).toBe(200);
    expect(simulated.json()).toMatchObject({
      sideEffects: false,
      trace: {
        canonicalActionRequestVersion: 'actionproxy.action-request.v1',
        decision: 'require_approval',
        decisionV1: {
          matchedPolicies: [expect.objectContaining({ matchType: 'default', ruleId: 'default' })],
          obligations: ['record_decision_evidence', 'require_human_approval', 'revalidate_policy_before_execution'],
          outcome: 'require_approval',
          reasonCodes: ['policy_outcome_require_approval', 'policy_match_default', 'policy_conditional_fallback'],
          version: 'actionproxy.decision.v1',
        },
        fallbackPath: ['exact', 'default'],
        matchType: 'default',
        matchedRule: 'default',
        policyReason: 'Unknown tools require approval.',
      },
    });
    expect(simulated.json().trace.ruleEvaluations[0]).toMatchObject({
      conditionsMatched: false,
      pattern: 'messages.public_reply',
      selected: false,
    });
    expect(simulated.json().trace.ruleEvaluations[0].conditions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: 'customerVisible', matched: false }),
        expect.objectContaining({ key: 'operationKind', matched: false }),
      ]),
    );
    expect(JSON.stringify(simulated.json())).not.toContain('super-secret-token');
    expect(toolCalls.json().toolCalls).toEqual([]);
    expect(pending.json().approvals).toEqual([]);
    expect(audit.json().events).toEqual([]);
  });

  it('simulates guarded actions with an unverified HTTP scope as unknown and never widens authority', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-influence-simulate-test-'));
    app = await buildApp({
      dataDir: tempDir,
      host: '127.0.0.1',
      localExecution: { mode: 'mock' },
      logLevel: 'silent',
      policyPath: writePolicy(tempDir),
      port: 0,
    });

    const simulated = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'research-agent',
        input: { note: 'proposed note' },
        policy: {
          default: { approval: 'required', risk: 'unknown' },
          tools: {
            'research.notes.append': {
              approval: 'never',
              influence: { allowFrom: ['none', 'organization_managed'], otherwise: 'required' },
              resultSource: 'none',
              risk: 'low_risk_write',
            },
          },
          version: 1,
        },
        reason: 'Simulate a guarded note',
        requestedBy: 'dev@example.com',
        toolName: 'research.notes.append',
      },
      url: '/v1/policy/simulate',
    });

    expect(simulated.statusCode).toBe(200);
    expect(simulated.json()).toMatchObject({
      sideEffects: false,
      trace: {
        contentInfluence: {
          baseDecision: 'allow',
          effectiveDecision: 'require_approval',
          influenceScope: { verified: false },
          observedSources: ['unknown'],
          selectedRule: { allowFrom: ['none', 'organization_managed'], otherwise: 'required' },
          version: 'actionproxy.content-influence.v1',
        },
        decision: 'require_approval',
        decisionV1: { outcome: 'require_approval' },
      },
    });
  });

  it('simulates explicitly hypothetical verified influence scopes without producing binding evidence', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-hypothetical-influence-test-'));
    app = await buildApp({
      dataDir: tempDir,
      host: '127.0.0.1',
      localExecution: { mode: 'mock' },
      logLevel: 'silent',
      policyPath: writePolicy(tempDir),
      port: 0,
    });
    const payload = {
      agentId: 'research-agent',
      input: { note: 'proposed note' },
      policy: {
        default: { approval: 'required', risk: 'unknown' },
        tools: {
          'research.notes.append': {
            approval: 'never',
            influence: { allowFrom: ['none', 'organization_managed'], otherwise: 'required' },
            resultSource: 'none',
            risk: 'low_risk_write',
          },
        },
        version: 1,
      },
      reason: 'Simulate a guarded note',
      requestedBy: 'dev@example.com',
      toolName: 'research.notes.append',
    };

    const managed = await app.inject({
      method: 'POST',
      payload: {
        ...payload,
        hypotheticalContentInfluence: {
          observedIntegrities: ['organization_managed'],
          scopeVerified: true,
        },
      },
      url: '/v1/policy/simulate',
    });
    const publicContent = await app.inject({
      method: 'POST',
      payload: {
        ...payload,
        hypotheticalContentInfluence: {
          observedIntegrities: ['public_untrusted'],
          scopeVerified: true,
        },
      },
      url: '/v1/policy/simulate',
    });
    const verifiedWithoutExposure = await app.inject({
      method: 'POST',
      payload: {
        ...payload,
        hypotheticalContentInfluence: { scopeVerified: true },
      },
      url: '/v1/policy/simulate',
    });
    const contradictory = await app.inject({
      method: 'POST',
      payload: {
        ...payload,
        hypotheticalContentInfluence: {
          observedIntegrities: ['public_untrusted'],
          scopeVerified: false,
        },
      },
      url: '/v1/policy/simulate',
    });
    const toolCalls = await app.inject({ method: 'GET', url: '/v1/tool-calls' });

    expect(managed.statusCode).toBe(200);
    expect(managed.json()).toMatchObject({
      hypotheticalContentInfluence: {
        evaluation: {
          applied: true,
          baseDecision: 'allow',
          effectiveDecision: 'allow',
          observedSources: ['organization_managed'],
          selectedRule: { allowFrom: ['none', 'organization_managed'], otherwise: 'required' },
        },
        hypothetical: true,
        requested: { observedIntegrities: ['organization_managed'], scopeVerified: true },
        version: 'actionproxy.policy-simulation-content-influence.v1',
      },
      sideEffects: false,
      trace: { decision: 'allow', decisionV1: { outcome: 'allow' } },
    });
    expect(managed.json().trace.contentInfluence).toBeUndefined();

    expect(publicContent.statusCode).toBe(200);
    expect(publicContent.json()).toMatchObject({
      hypotheticalContentInfluence: {
        evaluation: {
          applied: true,
          baseDecision: 'allow',
          effectiveDecision: 'require_approval',
          observedSources: ['public_untrusted'],
        },
        hypothetical: true,
      },
      sideEffects: false,
      trace: { decision: 'require_approval', decisionV1: { outcome: 'require_approval' } },
    });
    expect(publicContent.json().trace.contentInfluence).toBeUndefined();
    expect(verifiedWithoutExposure.statusCode).toBe(200);
    expect(verifiedWithoutExposure.json()).toMatchObject({
      hypotheticalContentInfluence: {
        evaluation: { effectiveDecision: 'allow', observedSources: ['none'] },
        requested: { observedIntegrities: [], scopeVerified: true },
      },
      trace: { decision: 'allow' },
    });
    expect(contradictory.statusCode).toBe(400);
    expect(contradictory.json()).toMatchObject({ error: 'invalid_request' });
    expect(toolCalls.json().toolCalls).toEqual([]);
  });

  it('rejects an unclassified open-world read in policy updates and draft simulations', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-open-world-validation-test-'));
    app = await buildApp({
      dataDir: tempDir,
      host: '127.0.0.1',
      localExecution: { mode: 'mock' },
      logLevel: 'silent',
      policyPath: writePolicy(tempDir),
      port: 0,
    });
    const invalidPolicy = {
      default: { approval: 'required', risk: 'unknown' },
      tools: {
        'web.fetch': { approval: 'required', risk: 'open_world_read' },
      },
      version: 1,
    };

    const update = await app.inject({ method: 'PUT', payload: invalidPolicy, url: '/v1/policy' });
    const simulation = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'research-agent',
        input: { url: 'https://public.example' },
        policy: invalidPolicy,
        reason: 'Simulate an open-world read',
        toolName: 'web.fetch',
      },
      url: '/v1/policy/simulate',
    });

    expect(update.statusCode).toBe(400);
    expect(update.json()).toMatchObject({
      error: 'invalid_policy',
      message: expect.stringContaining('open_world_read requires resultSource.integrity public_untrusted'),
    });
    expect(simulation.statusCode).toBe(400);
    expect(simulation.json()).toMatchObject({
      error: 'invalid_policy_simulation',
      message: expect.stringContaining('open_world_read requires resultSource.integrity public_untrusted'),
    });
  });

  it('rejects policy updates that reference unknown or disabled approvers', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-approver-validation-test-'));
    app = await buildApp({
      dataDir: tempDir,
      host: '127.0.0.1',
      localExecution: { mode: 'mock' },
      logLevel: 'silent',
      policyPath: writePolicy(tempDir),
      port: 0,
    });

    const unknownUser = await app.inject({
      method: 'PUT',
      payload: policyWithApprovalRouting({ users: ['u_missing'] }),
      url: '/v1/policy',
    });
    expect(unknownUser.statusCode).toBe(400);
    expect(unknownUser.json()).toMatchObject({
      error: 'invalid_policy',
      message: expect.stringContaining('unknown or disabled approver user: u_missing'),
    });

    const createdGroup = await app.inject({
      method: 'POST',
      payload: { displayName: 'Support managers' },
      url: '/v1/approvers/groups',
    });
    const groupId = createdGroup.json().group.id as string;
    const disabledGroup = await app.inject({
      method: 'PUT',
      payload: { enabled: false },
      url: `/v1/approvers/groups/${groupId}`,
    });
    expect(createdGroup.statusCode).toBe(201);
    expect(disabledGroup.statusCode).toBe(200);

    const disabledGroupPolicy = await app.inject({
      method: 'PUT',
      payload: policyWithApprovalRouting({ groups: [groupId] }),
      url: '/v1/policy',
    });
    expect(disabledGroupPolicy.statusCode).toBe(400);
    expect(disabledGroupPolicy.json()).toMatchObject({
      error: 'invalid_policy',
      message: expect.stringContaining(`unknown or disabled approver group: ${groupId}`),
    });

    const summary = await app.inject({ method: 'GET', url: '/v1/policy/summary' });
    expect(summary.json().rules).toEqual([]);
  });

  it('lists uncovered runtime tools and applies detector suggestions to YAML policy', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-detector-route-test-'));
    const policyPath = writePolicy(tempDir);
    app = await buildApp({
      dataDir: tempDir,
      host: '127.0.0.1',
      localExecution: { mode: 'disabled' },
      logLevel: 'silent',
      policyPath,
      port: 0,
    });

    const submitted = await app.inject({
      method: 'POST',
      payload: {
        agentId: 'crm-agent',
        input: { query: 'acme' },
        metadata: { actionproxyExecution: 'external' },
        reason: 'Search CRM accounts',
        requestedBy: 'dev@example.com',
        toolName: 'crm.search_accounts',
      },
      url: '/v1/tool-calls',
    });
    const detector = await app.inject({ method: 'GET', url: '/v1/policy/detector' });
    const observedTool = detector.json().tools.find((tool: { toolName: string }) => tool.toolName === 'crm.search_accounts');
    const applied = await app.inject({ method: 'POST', url: `/v1/policy/detector/${observedTool.id}/apply` });
    const duplicate = await app.inject({ method: 'POST', url: `/v1/policy/detector/${observedTool.id}/apply` });
    const refreshed = await app.inject({ method: 'GET', url: '/v1/policy/detector' });
    const written = fs.readFileSync(policyPath, 'utf8');

    expect(submitted.json()).toMatchObject({ decision: 'require_approval', status: 'pending_approval' });
    expect(observedTool).toMatchObject({
      coverage: { matchedRule: 'default', status: 'uncovered' },
      status: 'unresolved',
      suggestion: {
        approval: 'required',
        pattern: 'crm.search_accounts',
        resultSource: { integrity: 'unknown' },
        risk: 'unreviewed_read',
      },
    });
    expect(applied.statusCode).toBe(200);
    expect(duplicate.statusCode).toBe(409);
    expect(applied.json().policy.tools['crm.search_accounts']).toMatchObject({
      approval: 'required',
      resultSource: { integrity: 'unknown' },
      risk: 'unreviewed_read',
    });
    expect(refreshed.json().tools).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          coverage: expect.objectContaining({ matchedRule: 'crm.search_accounts', status: 'covered' }),
          status: 'resolved',
          toolName: 'crm.search_accounts',
        }),
      ]),
    );
    expect(written).toContain('crm.search_accounts:');
    expect(written).toContain('resultSource:');
  });

  it('does not increment detector call count for idempotency-key retries', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-detector-idempotency-test-'));
    app = await buildApp({
      dataDir: tempDir,
      host: '127.0.0.1',
      localExecution: { mode: 'disabled' },
      logLevel: 'silent',
      policyPath: writePolicy(tempDir),
      port: 0,
    });
    const payload = {
      agentId: 'message-agent',
      input: { body: 'hello', to: 'user@example.com' },
      metadata: { actionproxyExecution: 'external' },
      reason: 'Send a message',
      requestedBy: 'dev@example.com',
      toolName: 'messaging.send_message',
    };

    await app.inject({ headers: { 'idempotency-key': 'retry-1' }, method: 'POST', payload, url: '/v1/tool-calls' });
    await app.inject({ headers: { 'idempotency-key': 'retry-1' }, method: 'POST', payload, url: '/v1/tool-calls' });
    const detector = await app.inject({ method: 'GET', url: '/v1/policy/detector' });

    expect(detector.json().tools).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          callCount: 1,
          toolName: 'messaging.send_message',
        }),
      ]),
    );
  });

  it('dismisses detector observations and audits the review', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-detector-dismiss-test-'));
    const auditPath = tempDir;
    app = await buildApp({
      dataDir: auditPath,
      host: '127.0.0.1',
      localExecution: { mode: 'disabled' },
      logLevel: 'silent',
      policyPath: writePolicy(tempDir),
      port: 0,
    });
    await app.inject({
      method: 'POST',
      payload: {
        agentId: 'cleanup-agent',
        input: { customerId: 'cus_123' },
        metadata: { actionproxyExecution: 'external' },
        reason: 'Delete customer',
        requestedBy: 'dev@example.com',
        toolName: 'crm.delete_customer',
      },
      url: '/v1/tool-calls',
    });
    const detector = await app.inject({ method: 'GET', url: '/v1/policy/detector' });
    const observedTool = detector.json().tools.find((tool: { toolName: string }) => tool.toolName === 'crm.delete_customer');

    const dismissed = await app.inject({ method: 'POST', url: `/v1/policy/detector/${observedTool.id}/dismiss` });
    const audit = await app.inject({ method: 'GET', url: '/v1/audit?limit=20' });

    expect(dismissed.statusCode).toBe(200);
    expect(dismissed.json().observedTool).toMatchObject({ status: 'dismissed', toolName: 'crm.delete_customer' });
    expect(audit.json().events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          data: expect.objectContaining({ toolName: 'crm.delete_customer' }),
          type: 'policy_detector.dismissed',
        }),
      ]),
    );
  });
});

function writePolicy(tempDir: string): string {
  const policyPath = path.join(tempDir, 'policy.yaml');
  fs.writeFileSync(
    policyPath,
    [
      'version: 1',
      '',
      'default:',
      '  approval: required',
      '  risk: unknown',
      '  reason: Unknown tools require approval.',
      '',
      'tools: {}',
      '',
    ].join('\n'),
    'utf8',
  );
  return policyPath;
}

function policyWithApprovalRouting(approvers: { groups?: string[]; users?: string[] }) {
  return {
    default: {
      approval: 'required',
      reason: 'Unknown tools require approval.',
      risk: 'unknown',
    },
    tools: {
      'gmail.send_email': {
        approval: 'required',
        approvers,
        reason: 'Email requires approval.',
        risk: 'external_communication',
      },
    },
    version: 1,
  };
}
