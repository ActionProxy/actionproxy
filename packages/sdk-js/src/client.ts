import type {
  ActionProxyClientOptions,
  ActionProxyFetch,
  ApprovalRecord,
  AuditExportResponse,
  AuditEvent,
  ApproveApprovalInput,
  CancelApprovalInput,
  ConsumeExecutionGrantInput,
  ConsumeExecutionGrantResponse,
  ExportAuditEventsOptions,
  JsonObject,
  ListAuditEventsOptions,
  ListToolCallsOptions,
  RejectApprovalInput,
  ReportExecutionGrantOutcomeInput,
  ReportExecutionGrantOutcomeResponse,
  RemediationPlan,
  SubmitRemediationInput,
  SubmitRemediationResponse,
  SubmitToolCallInput,
  SubmitToolCallOptions,
  SubmitToolCallResponse,
  ToolCallRecord,
  ToolCallStatus,
  WaitForToolCallOptions,
} from './types';
import type { ExecutionAttemptRecordV1, PolicyDecisionTraceV1 } from './contracts';

const DEFAULT_TERMINAL_STATUSES: ToolCallStatus[] = ['authorized', 'executed', 'blocked', 'rejected', 'failed'];
const DEFAULT_POLL_INTERVAL_MS = 500;
const DEFAULT_TIMEOUT_MS = 30_000;

export class ActionProxyApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: unknown,
  ) {
    super(message);
    this.name = 'ActionProxyApiError';
  }
}

export class ActionProxyClient {
  private readonly baseUrl: string;
  private readonly fetchFn: ActionProxyFetch;

  constructor(private readonly options: ActionProxyClientOptions) {
    if (!options.baseUrl.trim()) {
      throw new Error('ActionProxy baseUrl is required.');
    }

    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.fetchFn = options.fetch ?? getGlobalFetch();
  }

  async submitToolCall<TInput extends JsonObject = JsonObject>(
    input: SubmitToolCallInput<TInput>,
    options: SubmitToolCallOptions = {},
  ): Promise<SubmitToolCallResponse<TInput>> {
    return this.request<SubmitToolCallResponse<TInput>>('/v1/tool-calls', {
      body: input,
      headers: idempotencyHeaders(options.idempotencyKey),
      method: 'POST',
    });
  }

  async getToolCall<TInput extends JsonObject = JsonObject>(id: string): Promise<ToolCallRecord<TInput>> {
    return this.request<ToolCallRecord<TInput>>(`/v1/tool-calls/${encodeURIComponent(id)}`);
  }

  async listToolCalls<TInput extends JsonObject = JsonObject>(
    options: ListToolCallsOptions = {},
  ): Promise<ToolCallRecord<TInput>[]> {
    const query = new URLSearchParams();
    if (options.decision) query.set('decision', options.decision);
    if (options.limit !== undefined) query.set('limit', String(options.limit));
    if (options.runId) query.set('runId', options.runId);
    if (options.sessionId) query.set('sessionId', options.sessionId);
    if (options.status) query.set('status', options.status);
    if (options.toolName) query.set('toolName', options.toolName);

    const suffix = query.size > 0 ? `?${query.toString()}` : '';
    const response = await this.request<{ toolCalls: ToolCallRecord<TInput>[] }>(`/v1/tool-calls${suffix}`);
    return response.toolCalls;
  }

  async listAuditEvents(options: ListAuditEventsOptions = {}): Promise<AuditEvent[]> {
    const query = new URLSearchParams();
    if (options.from) query.set('from', options.from);
    if (options.limit !== undefined) query.set('limit', String(options.limit));
    if (options.to) query.set('to', options.to);
    if (options.toolCallId) query.set('toolCallId', options.toolCallId);

    const suffix = query.size > 0 ? `?${query.toString()}` : '';
    const response = await this.request<{ events: AuditEvent[] }>(`/v1/audit${suffix}`);
    return response.events;
  }

  async exportAuditEvents(options: ExportAuditEventsOptions = {}): Promise<AuditExportResponse> {
    const query = new URLSearchParams();
    if (options.from) query.set('from', options.from);
    if (options.to) query.set('to', options.to);
    if (options.toolCallId) query.set('toolCallId', options.toolCallId);

    const suffix = query.size > 0 ? `?${query.toString()}` : '';
    return this.request<AuditExportResponse>(`/v1/audit/export${suffix}`);
  }

  async getDecisionTrace(id: string): Promise<PolicyDecisionTraceV1> {
    return this.request<PolicyDecisionTraceV1>(
      `/v1/tool-calls/${encodeURIComponent(id)}/decision-trace`,
    );
  }

  async listExecutionAttempts(id: string): Promise<ExecutionAttemptRecordV1[]> {
    const response = await this.request<{ attempts: ExecutionAttemptRecordV1[] }>(
      `/v1/tool-calls/${encodeURIComponent(id)}/execution-attempts`,
    );
    return response.attempts;
  }

  async listPendingApprovals<TInput extends JsonObject = JsonObject>(): Promise<ApprovalRecord<TInput>[]> {
    const response = await this.request<{ approvals: ApprovalRecord<TInput>[] }>('/v1/approvals/pending');
    return response.approvals;
  }

  async approveApproval<TInput extends JsonObject = JsonObject>(
    approvalId: string,
    input: ApproveApprovalInput<TInput>,
  ): Promise<{ approval: ApprovalRecord<TInput>; toolCall: ToolCallRecord<TInput> }> {
    return this.request(`/v1/approvals/${encodeURIComponent(approvalId)}/approve`, {
      body: input,
      method: 'POST',
    });
  }

  async rejectApproval<TInput extends JsonObject = JsonObject>(
    approvalId: string,
    input: RejectApprovalInput,
  ): Promise<{ approval: ApprovalRecord<TInput>; toolCall: ToolCallRecord<TInput> }> {
    return this.request(`/v1/approvals/${encodeURIComponent(approvalId)}/reject`, {
      body: input,
      method: 'POST',
    });
  }

  async cancelApproval<TInput extends JsonObject = JsonObject>(
    approvalId: string,
    input: CancelApprovalInput,
  ): Promise<{ approval: ApprovalRecord<TInput>; toolCall: ToolCallRecord<TInput> }> {
    return this.request(`/v1/approvals/${encodeURIComponent(approvalId)}/cancel`, {
      body: input,
      method: 'POST',
    });
  }

  async consumeExecutionGrant<TInput extends JsonObject = JsonObject>(
    grantId: string,
    input: ConsumeExecutionGrantInput<TInput>,
  ): Promise<ConsumeExecutionGrantResponse> {
    return this.request(`/v1/execution-grants/${encodeURIComponent(grantId)}/consume`, {
      body: input,
      method: 'POST',
    });
  }

  async reportExecutionGrantOutcome<TInput extends JsonObject = JsonObject>(
    grantId: string,
    input: ReportExecutionGrantOutcomeInput,
  ): Promise<ReportExecutionGrantOutcomeResponse<TInput>> {
    return this.request(`/v1/execution-grants/${encodeURIComponent(grantId)}/outcome`, {
      body: input,
      method: 'POST',
    });
  }

  async getRemediationPlan<TInput extends JsonObject = JsonObject>(toolCallId: string): Promise<RemediationPlan<TInput>> {
    return this.request<RemediationPlan<TInput>>(`/v1/tool-calls/${encodeURIComponent(toolCallId)}/remediation-plan`);
  }

  async submitRemediation<TInput extends JsonObject = JsonObject>(
    toolCallId: string,
    input: SubmitRemediationInput<TInput> = {},
  ): Promise<SubmitRemediationResponse<TInput>> {
    return this.request(`/v1/tool-calls/${encodeURIComponent(toolCallId)}/remediation`, {
      body: input,
      method: 'POST',
    });
  }

  async waitForToolCall<TInput extends JsonObject = JsonObject>(
    id: string,
    options: WaitForToolCallOptions = {},
  ): Promise<ToolCallRecord<TInput>> {
    const intervalMs = options.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const terminalStatuses = new Set(options.until ?? DEFAULT_TERMINAL_STATUSES);
    const start = Date.now();

    while (true) {
      const toolCall = await this.getToolCall<TInput>(id);
      if (terminalStatuses.has(toolCall.status)) {
        return toolCall;
      }

      if (Date.now() - start >= timeoutMs) {
        throw new Error(`Timed out waiting for ActionProxy tool call ${id}. Last status: ${toolCall.status}.`);
      }

      await delay(intervalMs);
    }
  }

  private async request<T>(
    path: string,
    init: {
      body?: unknown;
      headers?: Record<string, string>;
      method?: 'GET' | 'POST';
    } = {},
  ): Promise<T> {
    const response = await this.fetchFn(`${this.baseUrl}${path}`, {
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      headers: this.headers(init.headers),
      method: init.method ?? 'GET',
    });
    const text = await response.text();
    const body = parseBody(text);

    if (!response.ok) {
      throw new ActionProxyApiError(formatErrorMessage(response.status, body, text), response.status, body);
    }

    return body as T;
  }

  private headers(additional: Record<string, string> = {}): Record<string, string> {
    return {
      'content-type': 'application/json',
      ...(this.options.apiKey ? { authorization: `Bearer ${this.options.apiKey}` } : {}),
      ...additional,
    };
  }
}

function idempotencyHeaders(idempotencyKey: string | undefined): Record<string, string> {
  if (idempotencyKey === undefined) return {};
  if (
    idempotencyKey.length === 0 ||
    idempotencyKey.trim() !== idempotencyKey ||
    /\p{Cc}/u.test(idempotencyKey)
  ) {
    throw new Error('ActionProxy idempotencyKey must be a non-empty, header-safe string.');
  }
  return { 'idempotency-key': idempotencyKey };
}

function getGlobalFetch(): ActionProxyFetch {
  if (typeof fetch !== 'function') {
    throw new Error('No global fetch implementation is available. Pass fetch in ActionProxyClient options.');
  }

  return fetch as ActionProxyFetch;
}

function parseBody(text: string): unknown {
  if (!text) return undefined;

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function formatErrorMessage(status: number, body: unknown, fallback: string): string {
  if (isErrorBody(body)) {
    return `ActionProxy request failed: ${status} ${body.error}`;
  }

  return `ActionProxy request failed: ${status}${fallback ? ` ${fallback}` : ''}`;
}

function isErrorBody(value: unknown): value is { error: string } {
  return typeof value === 'object' && value !== null && 'error' in value && typeof value.error === 'string';
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
