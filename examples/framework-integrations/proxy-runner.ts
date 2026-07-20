import type { ActionProxyClient, JsonObject, ToolCallRecord } from '@actionproxy/sdk-js';

export interface ProxyToolRunOptions<TInput extends JsonObject, TResult> {
  agentId: string;
  client: ActionProxyClient;
  execute: (input: TInput) => Promise<TResult>;
  input: TInput;
  reason: string;
  requestedBy: string;
  toolName: string;
  wait?: {
    intervalMs?: number;
    timeoutMs?: number;
  };
}

export async function authorizeAndRunExternalTool<TInput extends JsonObject, TResult>(
  options: ProxyToolRunOptions<TInput, TResult>,
): Promise<{ result: TResult; toolCall: ToolCallRecord<TInput> }> {
  const submitted = await options.client.submitToolCall<TInput>({
    agentId: options.agentId,
    input: options.input,
    metadata: { actionproxyExecution: 'external', source: 'framework-integration-example' },
    reason: options.reason,
    requestedBy: options.requestedBy,
    toolName: options.toolName,
  });

  const toolCall =
    submitted.status === 'pending_approval'
      ? await options.client.waitForToolCall<TInput>(submitted.id, {
          intervalMs: options.wait?.intervalMs ?? 1000,
          timeoutMs: options.wait?.timeoutMs ?? 120_000,
        })
      : submitted.toolCall;

  if (toolCall.status !== 'authorized' && toolCall.status !== 'executed') {
    throw new Error(`ActionProxy did not authorize ${options.toolName}. Final status: ${toolCall.status}.`);
  }

  const grant = executionGrantFromResult(toolCall.result);
  if (!grant) {
    throw new Error(`ActionProxy authorized ${options.toolName} without an execution grant.`);
  }

  await options.client.consumeExecutionGrant<TInput>(grant.id, {
    input: toolCall.input,
    policyVersionHash: grant.policyVersionHash,
    toolCallId: toolCall.id,
    toolName: options.toolName,
  });

  let result: TResult;
  try {
    result = await options.execute(toolCall.input);
  } catch (error) {
    await options.client.reportExecutionGrantOutcome(grant.id, {
      error: error instanceof Error ? error.message : String(error),
      status: 'failed',
    });
    throw error;
  }

  const reported = await options.client.reportExecutionGrantOutcome<TInput>(grant.id, {
    result: isRecord(result) ? result : { value: result },
    status: 'succeeded',
  });

  return {
    result,
    toolCall: reported.toolCall,
  };
}

function executionGrantFromResult(result: unknown): { id: string; policyVersionHash?: string } | undefined {
  if (!isRecord(result) || !isRecord(result.grant) || typeof result.grant.id !== 'string') return undefined;
  return {
    id: result.grant.id,
    policyVersionHash: typeof result.grant.policyVersionHash === 'string' ? result.grant.policyVersionHash : undefined,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
