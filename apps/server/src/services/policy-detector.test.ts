import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { JsonlAuditStore } from '../storage/jsonl-audit-store';
import { MemoryStore } from '../storage/memory-store';
import type { PolicyFile } from '../policy/policy-types';
import { PolicyDetectorService, coverageForPolicy, suggestionForToolName } from './policy-detector';

const policy: PolicyFile = {
  default: { approval: 'required', reason: 'Unknown tools require approval.', risk: 'unknown' },
  tools: {
    'docs.search': { approval: 'never', risk: 'read_only' },
    'salesforce.*': { approval: 'required', risk: 'data_change' },
  },
  version: 1,
};

describe('PolicyDetectorService', () => {
  it('treats default policy matches as uncovered', () => {
    expect(coverageForPolicy(policy, 'docs.search')).toMatchObject({
      matchedRule: 'docs.search',
      status: 'covered',
    });
    expect(coverageForPolicy(policy, 'unknown.tool')).toMatchObject({
      matchedRule: 'default',
      status: 'uncovered',
    });
    expect(coverageForPolicy(policy, 'salesforce.update_account')).toMatchObject({
      matchedRule: 'salesforce.*',
      matchType: 'wildcard',
      status: 'covered',
    });
  });

  it('suggests deterministic policy rules from tool names', () => {
    expect(suggestionForToolName('docs.search')).toMatchObject({
      approval: 'required',
      resultSource: { integrity: 'unknown' },
      risk: 'unreviewed_read',
    });
    expect(suggestionForToolName('web.fetch')).toMatchObject({
      approval: 'required',
      resultSource: { integrity: 'public_untrusted' },
      risk: 'open_world_read',
    });
    expect(suggestionForToolName('http.get')).toMatchObject({
      approval: 'required',
      resultSource: { integrity: 'public_untrusted' },
      risk: 'open_world_read',
    });
    expect(suggestionForToolName('browser.delete_url')).toMatchObject({ approval: 'deny', risk: 'destructive' });
    expect(suggestionForToolName('web.post_message')).toMatchObject({
      approval: 'required',
      risk: 'external_communication',
    });
    expect(suggestionForToolName('web.update_page')).toMatchObject({ approval: 'required', risk: 'data_change' });
    expect(suggestionForToolName('gmail.send_email')).toMatchObject({
      approval: 'required',
      risk: 'external_communication',
    });
    expect(suggestionForToolName('jira.create_issue')).toMatchObject({ approval: 'required', risk: 'data_change' });
    expect(suggestionForToolName('dangerous.delete_customer')).toMatchObject({ approval: 'deny', risk: 'destructive' });
    expect(suggestionForToolName('vault.rotate_token')).toMatchObject({ approval: 'deny', risk: 'credential_sensitive' });
  });

  it('never treats a Google provider name alone as organization-managed content', () => {
    const genericSearch = suggestionForToolName('google.search');
    const openWebFetch = suggestionForToolName('google.web.fetch');

    expect(genericSearch).toMatchObject({
      approval: 'required',
      resultSource: { integrity: 'unknown' },
      risk: 'unreviewed_read',
    });
    expect(openWebFetch).toMatchObject({
      approval: 'required',
      resultSource: { integrity: 'public_untrusted' },
      risk: 'open_world_read',
    });
    expect(JSON.stringify([genericSearch, openWebFetch])).not.toContain('organization_managed');
  });

  it('records runtime observations without storing raw inputs', async () => {
    const detector = makeDetector();

    const observed = await detector.observeTool({
      agentId: 'support-agent',
      input: { query: 'refund policy', nested: { count: 1 } },
      policy,
      source: 'runtime',
      toolName: 'docs.lookup',
      workspaceId: 'default',
    });

    expect(observed).toMatchObject({
      callCount: 1,
      coverage: { status: 'uncovered' },
      sourceIds: { agentIds: ['support-agent'] },
      sources: ['runtime'],
      status: 'unresolved',
      suggestion: {
        approval: 'required',
        resultSource: { integrity: 'unknown' },
        risk: 'unreviewed_read',
      },
    });
    expect(JSON.stringify(observed)).not.toContain('refund policy');
  });

  it('flags schema changes for review', async () => {
    const detector = makeDetector();
    await detector.observeTool({
      input: { id: '123' },
      policy,
      source: 'runtime',
      toolName: 'docs.get',
      workspaceId: 'default',
    });

    const changed = await detector.observeTool({
      input: { id: '123', includeHistory: true },
      policy,
      source: 'runtime',
      toolName: 'docs.get',
      workspaceId: 'default',
    });

    expect(changed.status).toBe('unresolved');
    expect(changed.schemaHash).toEqual(expect.any(String));
    expect(changed.schemaChange).toMatchObject({
      currentSchemaHash: changed.schemaHash,
      previousSchemaHash: expect.any(String),
      reviewState: 'needs_review',
    });
  });

  it('keeps dismissed schema changes reviewed on subsequent observations', async () => {
    const detector = makeDetector();
    await detector.observeTool({
      input: { id: '123' },
      policy,
      source: 'runtime',
      toolName: 'docs.get',
      workspaceId: 'default',
    });
    const changed = await detector.observeTool({
      input: { id: '123', includeHistory: true },
      policy,
      source: 'runtime',
      toolName: 'docs.get',
      workspaceId: 'default',
    });

    const dismissed = await detector.dismiss(changed.id, localAuth(), policy);
    const observedAgain = await detector.observeTool({
      input: { id: '456', includeHistory: false },
      policy,
      source: 'runtime',
      toolName: 'docs.get',
      workspaceId: 'default',
    });

    expect(dismissed.status).toBe('dismissed');
    expect(dismissed.schemaChange?.reviewState).toBe('reviewed');
    expect(observedAgain.status).toBe('dismissed');
    expect(observedAgain.schemaChange?.reviewState).toBe('reviewed');
  });

  it('marks schema changes reviewed when policy coverage is refreshed after apply', async () => {
    const detector = makeDetector();
    await detector.observeTool({
      input: { id: '123' },
      policy,
      source: 'runtime',
      toolName: 'crm.update_contact',
      workspaceId: 'default',
    });
    const changed = await detector.observeTool({
      input: { id: '123', email: 'customer@example.com' },
      policy,
      source: 'runtime',
      toolName: 'crm.update_contact',
      workspaceId: 'default',
    });
    const policyWithExactRule: PolicyFile = {
      ...policy,
      tools: {
        ...policy.tools,
        'crm.update_contact': { approval: 'required', risk: 'data_change' },
      },
    };

    await detector.refreshPolicyCoverage(policyWithExactRule, 'default');
    const listed = await detector.list('default', policyWithExactRule);
    const record = listed.tools.find((tool) => tool.id === changed.id);

    expect(record).toMatchObject({
      coverage: { status: 'covered' },
      schemaChange: { reviewState: 'reviewed' },
      status: 'resolved',
    });
  });

  it('upgrades suggestions to wildcard after three same-prefix uncovered tools', async () => {
    const detector = makeDetector();
    for (const toolName of ['crm.search_accounts', 'crm.lookup_contact', 'crm.list_cases']) {
      await detector.observeTool({ policy, source: 'mcp_discovery', toolName, workspaceId: 'default' });
    }

    const list = await detector.list('default', policy);

    expect(list.unresolvedCount).toBe(3);
    expect(list.tools).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          toolName: 'crm.search_accounts',
          suggestion: expect.objectContaining({ pattern: 'crm.*', patternType: 'wildcard' }),
        }),
      ]),
    );
  });

  it('carries source classification into detector-built policy rules', async () => {
    const detector = makeDetector();
    const observed = await detector.observeTool({
      policy,
      source: 'mcp_discovery',
      toolName: 'browser.fetch_url',
      workspaceId: 'default',
    });

    expect(detector.buildRule(observed, {}, policy)).toEqual({
      pattern: 'browser.fetch_url',
      rule: {
        approval: 'required',
        reason: 'Open-world reads can return untrusted content and should require review until their source handling is configured.',
        resultSource: { integrity: 'public_untrusted' },
        risk: 'open_world_read',
      },
    });
  });
});

function localAuth() {
  return {
    authProvider: 'none' as const,
    displayName: 'Local Admin',
    groups: [],
    principalId: 'local-admin',
    principalType: 'user' as const,
    scopes: [],
    workspaceId: 'default',
  };
}

function makeDetector(): PolicyDetectorService {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-policy-detector-test-'));
  return new PolicyDetectorService(new MemoryStore(), new JsonlAuditStore(dataDir));
}
