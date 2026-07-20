import { describe, expect, it } from 'vitest';
import { evaluatePolicy } from './evaluate-policy';
import type { PolicyFile } from './policy-types';

const policy: PolicyFile = {
  version: 1,
  default: { approval: 'required', risk: 'unknown', reason: 'Default approval' },
  tools: {
    'docs.search': { approval: 'never', risk: 'read_only', reason: 'Read only' },
    'gmail.send_email': { approval: 'required', risk: 'external', reason: 'External' },
    'dangerous.delete_customer': { approval: 'deny', risk: 'destructive', reason: 'Blocked' },
    'records.search': { approval: 'never', risk: 'read_only', reason: 'Read only' },
    'code.merge_change': { approval: 'required', risk: 'code_change', reason: 'Code change' },
    'records.delete_account': { approval: 'deny', risk: 'destructive', reason: 'Blocked record delete' },
    'records.*': { approval: 'required', risk: 'record_write', reason: 'Record write' },
    'channels.delete': { approval: 'deny', risk: 'destructive', reason: 'Blocked channel delete' },
    'payments.create_refund': { approval: 'required', risk: 'financial_write', reason: 'Financial write' },
  },
};

describe('evaluatePolicy', () => {
  it('allows approval never rules', () => {
    const result = evaluatePolicy(policy, 'docs.search');
    expect(result.decision).toBe('allow');
    expect(result.risk).toBe('read_only');
  });

  it('requires approval for required rules', () => {
    const result = evaluatePolicy(policy, 'gmail.send_email');
    expect(result.decision).toBe('require_approval');
  });

  it('denies deny rules', () => {
    const result = evaluatePolicy(policy, 'dangerous.delete_customer');
    expect(result.decision).toBe('deny');
  });

  it('uses wildcard rules', () => {
    const result = evaluatePolicy(policy, 'records.update_account');
    expect(result.decision).toBe('require_approval');
    expect(result.matchedRule).toBe('records.*');
  });

  it('evaluates configured read tools as allowed', () => {
    const result = evaluatePolicy(policy, 'records.search');
    expect(result.decision).toBe('allow');
    expect(result.risk).toBe('read_only');
  });

  it('evaluates configured write tools as approval-required', () => {
    expect(evaluatePolicy(policy, 'code.merge_change').decision).toBe('require_approval');
    expect(evaluatePolicy(policy, 'payments.create_refund').decision).toBe('require_approval');
  });

  it('evaluates configured destructive tools as denied', () => {
    expect(evaluatePolicy(policy, 'channels.delete').decision).toBe('deny');
  });

  it('prefers exact deny rules over wildcard approval rules', () => {
    const result = evaluatePolicy(policy, 'records.delete_account');
    expect(result.decision).toBe('deny');
    expect(result.matchedRule).toBe('records.delete_account');
  });

  it('uses default for unknown tools', () => {
    const result = evaluatePolicy(policy, 'unknown.tool');
    expect(result.decision).toBe('require_approval');
    expect(result.matchedRule).toBe('default');
  });

  it('matches typed conditions before falling back', () => {
    const conditionalPolicy: PolicyFile = {
      version: 1,
      default: { approval: 'never', risk: 'low', reason: 'Default allow' },
      tools: {
        'messages.reply': {
          approval: 'required',
          conditions: { customerVisible: true, operationKind: 'external_send' },
          reason: 'Customer replies need review',
          risk: 'external',
        },
      },
    };
    expect(evaluatePolicy(conditionalPolicy, 'messages.reply', {
      customerVisible: true,
      operationKind: 'external_send',
    }).decision).toBe('require_approval');
    expect(evaluatePolicy(conditionalPolicy, 'messages.reply', {
      customerVisible: true,
      operationKind: 'write',
    }).decision).toBe('allow');
  });

  it('supports recipient and amount conditions', () => {
    const conditionalPolicy: PolicyFile = {
      version: 1,
      default: { approval: 'never', risk: 'low', reason: 'Default allow' },
      tools: {
        'payments.execute_refund': {
          approval: 'required',
          conditions: { amount: { gte: 100 } },
          reason: 'Large refund',
          risk: 'financial',
        },
        'messages.send_email': {
          approval: 'required',
          conditions: { recipientDomain: 'external' },
          reason: 'External email',
          risk: 'external',
        },
      },
    };
    expect(evaluatePolicy(conditionalPolicy, 'payments.execute_refund', {
      input: { amount: 125 },
    }).decision).toBe('require_approval');
    expect(evaluatePolicy(conditionalPolicy, 'payments.execute_refund', {
      input: { amount: 25 },
    }).decision).toBe('allow');
    expect(evaluatePolicy(conditionalPolicy, 'messages.send_email', {
      input: { to: 'customer@example.com' },
      metadata: { internalDomain: 'company.test' },
    }).decision).toBe('require_approval');
  });
});
