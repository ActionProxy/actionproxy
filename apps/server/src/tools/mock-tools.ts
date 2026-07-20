import type { ToolRegistry } from '../services/tool-registry';

export function registerMockTools(registry: ToolRegistry): void {
  registry.register('docs.search', async (input) => {
    return {
      ok: true,
      tool: 'docs.search',
      query: input.query ?? null,
      results: [
        {
          title: 'Refund policy',
          snippet: 'Refund requests are reviewed within 5 business days.',
        },
      ],
    };
  });

  registry.register('jira.create_issue', async (input) => {
    return {
      ok: true,
      tool: 'jira.create_issue',
      issueKey: 'DEMO-123',
      summary: input.summary ?? 'Demo issue',
    };
  });

  registry.register('gmail.send_email', async (input) => {
    return {
      ok: true,
      tool: 'gmail.send_email',
      messageId: 'mock_msg_123',
      to: input.to ?? null,
      subject: input.subject ?? null,
      note: 'Mock email only. No real email was sent.',
    };
  });

  registry.register('payments.issue_refund', async (input) => {
    return {
      amount: input.amount ?? null,
      currency: input.currency ?? null,
      destination: input.destination ?? null,
      note: 'Deterministic simulation only. No payment provider was contacted.',
      ok: true,
      order_id: input.order_id ?? null,
      refundId: `sim_refund_${String(input.order_id ?? 'unknown')}_${String(input.amount ?? 'unknown')}`,
      status: 'simulated',
      tool: 'payments.issue_refund',
    };
  });

  registry.register('salesforce.update_opportunity', async (input) => {
    const opportunityId = input.opportunityId ?? 'mock_opp_123';
    const updatedFields = isObject(input.fields) ? input.fields : {};
    const previousFields = {
      nextStep: 'Review current contract terms',
      stageName: 'Qualification',
    };

    return {
      actionproxy: {
        remediation: {
          evidence: {
            objectType: 'Opportunity',
            previousFields,
            updatedFields,
          },
          input: {
            fields: previousFields,
            opportunityId,
          },
          kind: 'exact_revert',
          metadata: {
            source: 'local_mock',
          },
          reason: 'Restore the Salesforce opportunity fields captured before the mock update.',
          status: 'available',
          toolName: 'salesforce.restore_opportunity',
        },
      },
      ok: true,
      tool: 'salesforce.update_opportunity',
      opportunityId,
      previousFields,
      updatedFields,
      note: 'Mock CRM update only. No real CRM was changed.',
    };
  });

  registry.register('salesforce.restore_opportunity', async (input) => {
    return {
      ok: true,
      tool: 'salesforce.restore_opportunity',
      opportunityId: input.opportunityId ?? 'mock_opp_123',
      restoredFields: input.fields ?? {},
      note: 'Mock CRM restore only. No real CRM was changed.',
    };
  });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
