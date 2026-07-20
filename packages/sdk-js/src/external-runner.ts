import type {
  ConsumeExecutionGrantResponse,
  JsonObject,
  ReportExecutionGrantOutcomeResponse,
  RunExternalActionInput,
  RunExternalActionResult,
  SubmitToolCallInput,
  ToolCallRecord,
} from './types';

export class ActionProxyExternalActionError extends Error {
  constructor(
    message: string,
    readonly toolCall?: ToolCallRecord,
    readonly causeError?: unknown,
  ) {
    super(message);
    this.name = 'ActionProxyExternalActionError';
  }
}

export async function runExternalAction<TInput extends JsonObject = JsonObject, TResult extends JsonObject = JsonObject>(
  input: RunExternalActionInput<TInput, TResult>,
): Promise<RunExternalActionResult<TInput, TResult>> {
  const request: SubmitToolCallInput<TInput> = {
    action: {
      ...(input.action ?? {}),
      executionMode: input.action?.executionMode ?? 'external_grant',
    },
    agentId: input.agentId,
    input: input.input,
    metadata: {
      ...(input.metadata ?? {}),
      actionproxyExecution: input.metadata?.actionproxyExecution ?? 'external',
    },
    reason: input.reason,
    requestedBy: input.requestedBy,
    toolName: input.toolName,
  };
  const submitted = input.idempotencyKey === undefined
    ? await input.client.submitToolCall<TInput>(request)
    : await input.client.submitToolCall<TInput>(request, { idempotencyKey: input.idempotencyKey });
  const finalToolCall = await input.client.waitForToolCall<TInput>(submitted.id, {
    until: input.wait?.until ?? ['authorized', 'blocked', 'rejected', 'failed'],
    ...input.wait,
  });

  if (finalToolCall.status !== 'authorized') {
    throw new ActionProxyExternalActionError(
      `ActionProxy did not authorize ${input.toolName}. Final status: ${finalToolCall.status}.`,
      finalToolCall,
    );
  }

  const grant = grantFromToolCall(finalToolCall);
  if (!grant) {
    throw new ActionProxyExternalActionError(`ActionProxy authorized ${input.toolName} without an execution grant.`, finalToolCall);
  }

  const consumed = await input.client.consumeExecutionGrant<TInput>(grant.id, {
    input: finalToolCall.input,
    policyVersionHash: finalToolCall.policyVersionHash,
    toolCallId: finalToolCall.id,
    toolName: finalToolCall.toolName,
  });

  let result: TResult;
  try {
    result = await input.execute(finalToolCall.input, { consumed, toolCall: finalToolCall });
  } catch (error) {
    await input.client.reportExecutionGrantOutcome<TInput>(grant.id, {
      error: error instanceof Error ? error.message : String(error),
      status: 'unknown_outcome',
    });
    throw new ActionProxyExternalActionError(
      `Downstream execution outcome is unknown for ${input.toolName}; reconcile before retrying.`,
      finalToolCall,
      error,
    );
  }

  const outcome = await input.client.reportExecutionGrantOutcome<TInput>(grant.id, {
    result,
    status: 'succeeded',
  });
  return {
    consumed,
    outcome: outcome as ReportExecutionGrantOutcomeResponse<TInput>,
    result,
    submitted,
    toolCall: outcome.toolCall,
  };
}

function grantFromToolCall(toolCall: ToolCallRecord): { id: string } | undefined {
  const result = toolCall.result;
  if (!isRecord(result)) return undefined;
  const grant = result.grant;
  if (!isRecord(grant) || typeof grant.id !== 'string') return undefined;
  return { id: grant.id };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
