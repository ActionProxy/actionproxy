import type { ResultDeliveryMetadataV1, ToolCallStatus } from '../models';

export const WITHHELD_MODEL_RESULT_MESSAGE =
  'ActionProxy withheld the downstream result because required content-exposure evidence was not durably recorded.';

export interface ResultVisibilityState {
  resultDelivery?: ResultDeliveryMetadataV1;
  resultWithheld?: boolean;
  status: ToolCallStatus;
}

/**
 * Classified MCP calls start withheld before dispatch. Pending approval and
 * execution-grant control data remain usable; terminal provider content does not
 * become visible until exposure evidence has been persisted.
 */
export function isModelVisibleResultWithheld(toolCall: ResultVisibilityState): boolean {
  return Boolean(
    toolCall.resultWithheld &&
    (toolCall.status === 'executed' || toolCall.resultDelivery?.modelVisible === true),
  );
}
