import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import YAML from 'yaml';
import { z } from 'zod';
import { evaluatePolicy } from '../policy/evaluate-policy';
import { parsePolicy } from '../policy/load-policy';
import type { PolicyManager } from '../policy/policy-manager';
import { tracePolicyForSubmit, type PolicyDecisionTrace } from '../policy/policy-trace';
import { communityPolicyPresets } from '../policy/presets';
import {
  contentIntegrityValues,
  type ContentInfluenceSource,
  type ContentIntegrity,
  type PolicyFile,
  type PolicyRule,
} from '../policy/policy-types';
import { hashJson } from '../security/crypto';
import { requireScope } from '../security/scopes';
import type { ApproverDirectoryService } from '../services/approver-directory';
import type { PolicyDetectorService } from '../services/policy-detector';
import type { AuditStore } from '../storage/audit-store';
import { authContext } from './route-utils';

export interface PolicySummaryRule {
  approval: PolicyRule['approval'];
  decision: ReturnType<typeof evaluatePolicy>['decision'];
  influence?: PolicyRule['influence'];
  matchType: 'default' | 'exact' | 'wildcard';
  pattern: string;
  reason: string;
  resultSource?: PolicyRule['resultSource'];
  risk: string;
}

export function summarizePolicy(policy: PolicyFile): { defaultRule: PolicySummaryRule; rules: PolicySummaryRule[]; version: number } {
  const defaultEvaluation = evaluatePolicy({ ...policy, tools: {} }, '__actionproxy_unknown_tool__');
  const defaultRule: PolicySummaryRule = {
    approval: policy.default.approval,
    decision: defaultEvaluation.decision,
    influence: policy.default.influence,
    matchType: 'default',
    pattern: 'default',
    reason: defaultEvaluation.reason,
    resultSource: policy.default.resultSource,
    risk: defaultEvaluation.risk,
  };

  const rules = Object.entries(policy.tools).map(([pattern, rule]) => summarizeRule(pattern, rule));

  return { defaultRule, rules, version: policy.version };
}

function summarizeRule(pattern: string, rule: PolicyRule): PolicySummaryRule {
  return {
    approval: rule.approval,
    decision: decisionForApproval(rule.approval),
    influence: rule.influence,
    matchType: pattern.endsWith('.*') ? 'wildcard' : 'exact',
    pattern,
    reason: rule.reason ?? fallbackReason(rule.approval),
    resultSource: rule.resultSource,
    risk: rule.risk ?? 'unknown',
  };
}

function decisionForApproval(approval: PolicyRule['approval']): ReturnType<typeof evaluatePolicy>['decision'] {
  if (approval === 'never') return 'allow';
  if (approval === 'required') return 'require_approval';
  return 'deny';
}

function fallbackReason(approval: PolicyRule['approval']): string {
  if (approval === 'never') return 'Policy allowed this tool.';
  if (approval === 'required') return 'Policy requires approval for this tool.';
  return 'Policy denied this tool.';
}

const hypotheticalContentInfluenceSchema = z.object({
  observedIntegrities: z.array(z.enum(contentIntegrityValues))
    .max(contentIntegrityValues.length)
    .refine((values) => new Set(values).size === values.length, 'observedIntegrities values must be unique.')
    .default([]),
  scopeVerified: z.boolean(),
}).strict().superRefine((value, context) => {
  if (!value.scopeVerified && value.observedIntegrities.length > 0) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'observedIntegrities require scopeVerified true.',
      path: ['observedIntegrities'],
    });
  }
});

const policySimulationSchema = z.object({
  action: z
    .object({
      context: z.record(z.unknown()).optional(),
      executionMode: z.enum(['external_grant', 'local_mock']).optional(),
      operation: z
        .object({
          kind: z.enum(['custom', 'delete', 'external_send', 'financial', 'read', 'write']).optional(),
          name: z.string().min(1).optional(),
        })
        .optional(),
      protocol: z
        .enum([
          'actionproxy_http',
          'cli',
          'custom',
          'langgraph',
          'mcp',
          'n8n',
          'openai_tools',
          'webhook',
        ])
        .optional(),
      resources: z
        .array(
          z.object({
            id: z.string().optional(),
            metadata: z.record(z.unknown()).optional(),
            name: z.string().optional(),
            type: z.string().min(1),
            url: z.string().optional(),
          }),
        )
        .optional(),
      source: z
        .object({
          id: z.string().optional(),
          metadata: z.record(z.unknown()).optional(),
          name: z.string().optional(),
          type: z.string().min(1).optional(),
        })
        .optional(),
    })
    .optional(),
  agentId: z.string().min(1),
  hypotheticalContentInfluence: hypotheticalContentInfluenceSchema.optional(),
  input: z.record(z.unknown()),
  metadata: z.record(z.unknown()).optional(),
  policy: z.unknown().optional(),
  policyYaml: z.string().optional(),
  reason: z.string().min(1),
  requestedBy: z.string().min(1).default('authenticated-principal'),
  toolName: z.string().min(1),
});

export async function registerPolicyRoutes(
  app: FastifyInstance,
  policyManager: PolicyManager,
  auditStore: AuditStore,
  options: {
    approverDirectory?: ApproverDirectoryService;
    environment?: 'local' | 'self_hosted';
    policyDetector?: PolicyDetectorService;
  } = {},
): Promise<void> {
  app.get('/v1/policy', async (request) => {
    requireScope(authContext(request), 'policy:read');
    return policyManager.getPolicy();
  });

  app.get('/v1/policy/summary', async (request) => {
    requireScope(authContext(request), 'policy:read');
    return summarizePolicy(policyManager.getPolicy());
  });

  app.get('/v1/policy/presets', async (request) => {
    requireScope(authContext(request), 'policy:read');
    return {
      conditions: [
        'approverGroup',
        'amount',
        'customerVisible',
        'operationKind',
        'recipientDomain',
        'risk',
      ],
      presets: communityPolicyPresets,
    };
  });

  app.post('/v1/policy/simulate', async (request, reply) => {
    const parsed = policySimulationSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid_request', details: parsed.error.flatten() });
    }
    const hasDraftPolicy = parsed.data.policy !== undefined || parsed.data.policyYaml !== undefined;
    const auth = requireScope(authContext(request), hasDraftPolicy ? 'policy:write' : 'policy:read');

    try {
      const policy = hasDraftPolicy ? parsePolicySimulationDraft(parsed.data.policy, parsed.data.policyYaml) : policyManager.getPolicy();
      const policyVersionHash = hashJson(policy);
      const trace = await tracePolicyForSubmit({
        approverDirectory: options.approverDirectory,
        auth,
        policy,
        policyVersionHash,
        policyVersionId: `policy_${policyVersionHash.slice(0, 16)}`,
        request: {
          action: parsed.data.action,
          agentId: parsed.data.agentId,
          input: parsed.data.input,
          metadata: parsed.data.metadata,
          reason: parsed.data.reason,
          requestedBy: parsed.data.requestedBy,
          toolName: parsed.data.toolName,
        },
        contentInfluence: parsed.data.hypotheticalContentInfluence ?? { scopeVerified: false },
        workspaceId: auth.workspaceId,
        ingress: {
          environment: options.environment ?? 'local',
          protocol: 'actionproxy_http',
          source: 'http',
        },
      });
      if (parsed.data.hypotheticalContentInfluence) {
        return {
          sideEffects: false,
          ...hypotheticalInfluenceSimulation(trace, parsed.data.hypotheticalContentInfluence),
        };
      }
      return { sideEffects: false, trace };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return reply.status(400).send({ error: 'invalid_policy_simulation', message });
    }
  });

  app.put('/v1/policy', async (request, reply) => {
    const auth = requireScope(authContext(request), 'policy:write');
    try {
      const nextPolicy = parsePolicy(request.body);
      await options.approverDirectory?.validatePolicy(nextPolicy, auth.workspaceId);
      const previousPolicy = policyManager.getPolicy();
      const previousPatterns = Object.keys(previousPolicy.tools);
      const policy = policyManager.replacePolicy(nextPolicy);
      const nextPatterns = Object.keys(policy.tools);
      await options.policyDetector?.refreshPolicyCoverage(policy, auth.workspaceId);

      await auditStore.append({
        actor: auth.email ?? auth.principalId,
        auth,
        data: {
          addedRules: nextPatterns.filter((pattern) => !previousPatterns.includes(pattern)),
          removedRules: previousPatterns.filter((pattern) => !nextPatterns.includes(pattern)),
          ruleCount: nextPatterns.length,
          version: policy.version,
        },
        id: `audit_${randomUUID()}`,
        timestamp: new Date().toISOString(),
        type: 'policy.updated',
        workspaceId: auth.workspaceId,
      });

      return { policy, summary: summarizePolicy(policy) };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return reply.status(400).send({ error: 'invalid_policy', message });
    }
  });
}

function hypotheticalInfluenceSimulation(
  trace: PolicyDecisionTrace,
  input: { observedIntegrities: ContentIntegrity[]; scopeVerified: boolean },
): {
  hypotheticalContentInfluence: {
    evaluation: {
      applied: boolean;
      baseDecision: PolicyDecisionTrace['decision'];
      effectiveDecision: PolicyDecisionTrace['decision'];
      observedSources: ContentInfluenceSource[];
      selectedRule?: PolicyRule['influence'];
    };
    hypothetical: true;
    requested: { observedIntegrities: ContentIntegrity[]; scopeVerified: boolean };
    version: 'actionproxy.policy-simulation-content-influence.v1';
  };
  trace: Omit<PolicyDecisionTrace, 'contentInfluence'>;
} {
  const { contentInfluence, ...traceWithoutBindingEvidence } = trace;
  const observedSources: ContentInfluenceSource[] = contentInfluence?.observedSources ?? (
    input.scopeVerified
      ? input.observedIntegrities.length > 0 ? [...input.observedIntegrities] : ['none']
      : ['unknown']
  );
  return {
    hypotheticalContentInfluence: {
      evaluation: {
        applied: contentInfluence !== undefined,
        baseDecision: contentInfluence?.baseDecision ?? trace.decision,
        effectiveDecision: trace.decision,
        observedSources,
        selectedRule: contentInfluence?.selectedRule,
      },
      hypothetical: true,
      requested: {
        observedIntegrities: [...input.observedIntegrities],
        scopeVerified: input.scopeVerified,
      },
      version: 'actionproxy.policy-simulation-content-influence.v1',
    },
    trace: traceWithoutBindingEvidence,
  };
}

function parsePolicySimulationDraft(policy: unknown, policyYaml: string | undefined): PolicyFile {
  if (policyYaml !== undefined) {
    return parsePolicy(YAML.parse(policyYaml) as unknown);
  }
  return parsePolicy(policy);
}
