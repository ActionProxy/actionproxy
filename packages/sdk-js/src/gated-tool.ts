import type {
  GatedTool,
  GatedToolCallOptions,
  GatedToolConfig,
  JsonObject,
  SubmitToolCallResponse,
} from './types';

export function gatedTool<TInput extends JsonObject = JsonObject>(config: GatedToolConfig<TInput>): GatedTool<TInput> {
  return async (input: TInput, options: GatedToolCallOptions = {}) => {
    const request = {
      agentId: config.agentId,
      input,
      metadata: resolveMetadata(config, input, options),
      reason: resolveReason(config, input, options),
      requestedBy: config.requestedBy,
      toolName: config.toolName,
    };
    const idempotencyKey = resolveIdempotencyKey(config, input, options);
    const response = idempotencyKey === undefined
      ? await config.client.submitToolCall(request)
      : await config.client.submitToolCall(request, { idempotencyKey });

    if (!(options.waitForFinalStatus ?? config.waitForFinalStatus)) {
      return response;
    }

    const toolCall = await config.client.waitForToolCall(response.id, options.wait ?? config.wait);
    return mergeToolCall(response, toolCall);
  };
}

function resolveIdempotencyKey<TInput extends JsonObject>(
  config: GatedToolConfig<TInput>,
  input: TInput,
  options: GatedToolCallOptions,
): string | undefined {
  if (options.idempotencyKey !== undefined) return options.idempotencyKey;
  if (typeof config.idempotencyKey === 'function') return config.idempotencyKey(input);
  return config.idempotencyKey;
}

function resolveReason<TInput extends JsonObject>(
  config: GatedToolConfig<TInput>,
  input: TInput,
  options: GatedToolCallOptions,
): string {
  if (options.reason) return options.reason;
  if (typeof config.reason === 'function') return config.reason(input);
  if (config.reason) return config.reason;
  return `Call ${config.toolName}`;
}

function resolveMetadata<TInput extends JsonObject>(
  config: GatedToolConfig<TInput>,
  input: TInput,
  options: GatedToolCallOptions,
): JsonObject | undefined {
  if (options.metadata) return options.metadata;
  if (typeof config.metadata === 'function') return config.metadata(input);
  return config.metadata;
}

function mergeToolCall<TInput extends JsonObject>(
  response: SubmitToolCallResponse<TInput>,
  toolCall: SubmitToolCallResponse<TInput>['toolCall'],
): SubmitToolCallResponse<TInput> {
  return {
    ...response,
    decision: toolCall.decision,
    error: toolCall.error,
    result: toolCall.result,
    risk: toolCall.risk,
    status: toolCall.status,
    toolCall,
  };
}
