const baseUrl = process.env.ACTIONPROXY_BASE_URL ?? 'http://127.0.0.1:8787';

const steps = [
  {
    name: 'Search support policy',
    toolName: 'docs.search',
    input: { query: 'refund policy for delayed shipment' },
    reason: 'Find policy context for a customer support reply',
  },
  {
    name: 'Propose customer email',
    toolName: 'gmail.send_email',
    input: {
      to: 'customer@example.com',
      subject: 'Refund policy update',
      body: 'Thanks for contacting us. Based on our policy, your delayed shipment qualifies for review.',
    },
    reason: 'Send customer response drafted by the support agent',
  },
  {
    name: 'Attempt unsafe customer deletion',
    toolName: 'dangerous.delete_customer',
    input: { customerId: 'cus_123' },
    reason: 'Show that destructive actions are blocked by policy',
  },
];

async function submitToolCall(step) {
  const response = await fetch(`${baseUrl}/v1/tool-calls`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      toolName: step.toolName,
      input: step.input,
      requestedBy: 'demo-agent@example.com',
      agentId: 'customer-support-demo-agent',
      reason: step.reason,
      metadata: { demo: 'customer-support-agent', step: step.name },
    }),
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`ActionProxy request failed: ${response.status} ${JSON.stringify(body)}`);
  }
  return body;
}

async function main() {
  console.log(`ActionProxy demo agent using ${baseUrl}`);
  console.log('Open the dashboard at http://127.0.0.1:5173 to watch the lifecycle.\n');

  for (const step of steps) {
    console.log(`Agent step: ${step.name}`);
    console.log(`Tool: ${step.toolName}`);
    const result = await submitToolCall(step);
    console.log(JSON.stringify(result, null, 2));

    if (result.status === 'pending_approval') {
      console.log('\nApproval required.');
      console.log(`Approval id: ${result.approval.id}`);
      console.log('Approve or reject it in the dashboard, then inspect the audit timeline.\n');
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
