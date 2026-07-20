import type { ApprovalMode, PolicyInfluenceGuard, PolicyRule } from './policy-types';

export interface PolicyPresetRule {
  approval: ApprovalMode;
  conditions?: Record<string, unknown>;
  influence?: PolicyInfluenceGuard;
  pattern: string;
  reason: string;
  resultSource?: PolicyRule['resultSource'];
  risk: string;
}

export interface PolicyPreset {
  description: string;
  id: 'fast_internal' | 'safe_default' | 'strict';
  rules: PolicyPresetRule[];
  title: string;
}

/** Presets use only the deterministic Community demo tools. */
export const communityPolicyPresets: PolicyPreset[] = [
  {
    description:
      'Allow reviewed reads, require approval for external messages and record changes, and deny destructive actions.',
    id: 'safe_default',
    rules: [
      {
        approval: 'never',
        pattern: 'docs.search',
        reason: 'The bundled document search is read-only.',
        resultSource: {
          integrity: 'organization_managed',
          sourceId: 'local-docs-demo',
        },
        risk: 'read_only',
      },
      {
        approval: 'required',
        pattern: 'gmail.send_email',
        reason: 'External messages require human review.',
        risk: 'external_communication',
      },
      {
        approval: 'required',
        pattern: 'salesforce.update_opportunity',
        reason: 'Record changes require human review.',
        risk: 'record_update',
      },
      {
        approval: 'deny',
        pattern: 'dangerous.delete_customer',
        reason: 'Destructive customer deletion is blocked.',
        risk: 'destructive',
      },
    ],
    title: 'Safe default',
  },
  {
    description:
      'Allow only the reviewed read-only demo and require approval for every other known non-destructive demo action.',
    id: 'strict',
    rules: [
      {
        approval: 'never',
        pattern: 'docs.search',
        reason: 'The bundled document search is read-only.',
        resultSource: {
          integrity: 'organization_managed',
          sourceId: 'local-docs-demo',
        },
        risk: 'read_only',
      },
      {
        approval: 'required',
        pattern: 'gmail.*',
        reason: 'Strict mode reviews every email action.',
        risk: 'sensitive_write',
      },
      {
        approval: 'required',
        pattern: 'salesforce.*',
        reason: 'Strict mode reviews every CRM action.',
        risk: 'sensitive_write',
      },
      {
        approval: 'deny',
        pattern: 'dangerous.*',
        reason: 'Destructive actions are blocked.',
        risk: 'destructive',
      },
    ],
    title: 'Strict',
  },
  {
    description:
      'Allow reviewed internal demo work while still requiring approval for external messages and CRM changes.',
    id: 'fast_internal',
    rules: [
      {
        approval: 'never',
        influence: {
          allowFrom: ['none', 'organization_managed'],
          otherwise: 'required',
        },
        pattern: 'jira.create_issue',
        reason: 'Internal issue creation can proceed from reviewed context.',
        risk: 'low_risk_write',
      },
      {
        approval: 'required',
        pattern: 'gmail.send_email',
        reason: 'External messages still require human review.',
        risk: 'external_communication',
      },
      {
        approval: 'required',
        pattern: 'salesforce.update_opportunity',
        reason: 'CRM changes still require human review.',
        risk: 'record_update',
      },
      {
        approval: 'deny',
        pattern: 'dangerous.delete_customer',
        reason: 'Destructive actions remain blocked.',
        risk: 'destructive',
      },
    ],
    title: 'Fast internal',
  },
];
