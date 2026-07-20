import type {
  ApprovalRecord,
  ApprovalReview,
  ApproverDirectoryResponse,
  AuditEvent,
  AuthorizedActionSummary,
  DashboardData,
  HealthResponse,
  IntegrationStatusResponse,
  JsonObject,
  PolicyDecisionTrace,
  PolicyDetectorResponse,
  PolicyFile,
  PolicySimulationResponse,
  PolicySummary,
  ToolCallRecord,
  ToolIntegrationId,
  ToolIntegrationStatus,
} from "../types";

export const actionProxyApiTokenStorageKey = "actionproxy.apiToken";

export interface SubmitToolCallBody {
  agentId: string;
  input: JsonObject;
  metadata?: JsonObject;
  reason: string;
  requestedBy: string;
  toolName: string;
}

export interface SubmitToolCallResponse {
  approval?: { id: string; status: string };
  decision?: string;
  error?: string;
  id: string;
  reason?: string;
  result?: unknown;
  risk?: string;
  status: string;
  toolCall?: ToolCallRecord;
}

export interface PolicySimulationBody {
  agentId: string;
  hypotheticalContentInfluence?: {
    observedIntegrities?: Array<
      | "organization_managed"
      | "verified_publisher"
      | "authenticated_external"
      | "public_untrusted"
      | "unknown"
    >;
    scopeVerified: boolean;
  };
  input: JsonObject;
  metadata?: JsonObject;
  policy?: PolicyFile;
  policyYaml?: string;
  reason: string;
  requestedBy?: string;
  toolName: string;
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: requestHeaders(init),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message =
      typeof body === "object" && body && "message" in body
        ? String(body.message)
        : `Request failed: ${response.status}`;
    throw new Error(message);
  }
  return body as T;
}

function requestHeaders(init?: RequestInit): HeadersInit | undefined {
  const headers: Record<string, string> = {};
  if (init?.body) headers["content-type"] = "application/json";
  const token = currentApiToken();
  if (token) headers.authorization = `Bearer ${token}`;
  return { ...headers, ...headersObject(init?.headers) };
}

function headersObject(
  headers: HeadersInit | undefined,
): Record<string, string> {
  if (!headers) return {};
  if (headers instanceof Headers) return Object.fromEntries(headers.entries());
  if (Array.isArray(headers)) return Object.fromEntries(headers);
  return headers;
}

export function currentApiToken(): string | undefined {
  const envToken = import.meta.env.VITE_ACTIONPROXY_API_TOKEN?.trim();
  if (envToken) return envToken;
  if (typeof window === "undefined") return undefined;
  return (
    window.sessionStorage.getItem(actionProxyApiTokenStorageKey)?.trim() ||
    undefined
  );
}

export function saveApiToken(token: string): void {
  if (typeof window === "undefined") return;
  window.sessionStorage.setItem(actionProxyApiTokenStorageKey, token.trim());
}

export function clearApiToken(): void {
  if (typeof window === "undefined") return;
  window.sessionStorage.removeItem(actionProxyApiTokenStorageKey);
}

export async function fetchHealth(): Promise<HealthResponse | null> {
  return requestJson<HealthResponse>("/health").catch(() => null);
}

export async function fetchToolCalls(): Promise<ToolCallRecord[]> {
  return requestJson<{ toolCalls: ToolCallRecord[] }>(
    "/v1/tool-calls?limit=100",
  ).then((body) => body.toolCalls);
}

export async function fetchToolCall(id: string): Promise<ToolCallRecord> {
  return requestJson<ToolCallRecord>(
    `/v1/tool-calls/${encodeURIComponent(id)}`,
  );
}

export async function fetchToolCallDecisionTrace(
  id: string,
): Promise<PolicyDecisionTrace> {
  return requestJson<PolicyDecisionTrace>(
    `/v1/tool-calls/${encodeURIComponent(id)}/decision-trace`,
  );
}

export async function fetchPendingApprovals(): Promise<ApprovalRecord[]> {
  return requestJson<{ approvals: ApprovalRecord[] }>(
    "/v1/approvals/pending",
  ).then((body) => body.approvals);
}

export async function fetchApproval(
  id: string,
): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
  return requestJson(`/v1/approvals/${encodeURIComponent(id)}`);
}

export async function fetchApprovalReview(id: string): Promise<ApprovalReview> {
  return requestJson(`/v1/approvals/${encodeURIComponent(id)}/review`);
}

export async function fetchAuthorizedActions(): Promise<
  AuthorizedActionSummary[]
> {
  return requestJson<{ authorizedActions: AuthorizedActionSummary[] }>(
    "/v1/authorized-actions?limit=100&status=all",
  ).then((body) => body.authorizedActions);
}

export async function fetchAuditEvents(limit = 500): Promise<AuditEvent[]> {
  return requestJson<{ events: AuditEvent[] }>(`/v1/audit?limit=${limit}`).then(
    (body) => body.events,
  );
}

export function buildAuditExportUrl(format: "json" | "siem" = "json"): string {
  return `/v1/audit/export?format=${format}`;
}

export async function fetchPolicySummary(): Promise<PolicySummary | null> {
  return requestJson<PolicySummary>("/v1/policy/summary").catch(() => null);
}

export async function fetchPolicyFile(): Promise<PolicyFile | null> {
  return requestJson<PolicyFile>("/v1/policy").catch(() => null);
}

export async function fetchPolicyDetector(): Promise<PolicyDetectorResponse | null> {
  return requestJson<PolicyDetectorResponse>("/v1/policy/detector").catch(
    () => null,
  );
}

export async function fetchIntegrations(): Promise<IntegrationStatusResponse | null> {
  return requestJson<IntegrationStatusResponse>("/v1/integrations").catch(
    () => null,
  );
}

export async function fetchApprovers(): Promise<ApproverDirectoryResponse | null> {
  return requestJson<ApproverDirectoryResponse>("/v1/approvers").catch(
    () => null,
  );
}

export async function fetchDashboardData(): Promise<DashboardData> {
  const [
    health,
    toolCalls,
    pendingApprovals,
    auditEvents,
    authorizedActions,
    policy,
    policyFile,
    policyDetector,
    integrations,
    approvers,
  ] = await Promise.all([
    fetchHealth(),
    fetchToolCalls(),
    fetchPendingApprovals(),
    fetchAuditEvents(),
    fetchAuthorizedActions(),
    fetchPolicySummary(),
    fetchPolicyFile(),
    fetchPolicyDetector(),
    fetchIntegrations(),
    fetchApprovers(),
  ]);
  return {
    approvers,
    auditEvents,
    authorizedActions,
    health,
    integrations,
    pendingApprovals,
    policy,
    policyDetector,
    policyFile,
    toolCalls,
  };
}

export async function submitToolCall(
  body: SubmitToolCallBody,
): Promise<SubmitToolCallResponse> {
  return requestJson("/v1/tool-calls", {
    body: JSON.stringify(body),
    method: "POST",
  });
}

export async function approveApproval(
  id: string,
  input: {
    approvedBy: string;
    editedInput?: JsonObject;
    inputDecision?:
      | { mode: "edited"; input: JsonObject }
      | { mode: "original" };
    note?: string;
    reviewHash?: string;
  },
): Promise<void> {
  await requestJson(`/v1/approvals/${encodeURIComponent(id)}/approve`, {
    body: JSON.stringify(input),
    method: "POST",
  });
}

export async function rejectApproval(
  id: string,
  input: { reason?: string; rejectedBy: string },
): Promise<void> {
  await requestJson(`/v1/approvals/${encodeURIComponent(id)}/reject`, {
    body: JSON.stringify(input),
    method: "POST",
  });
}

export async function savePolicy(
  policy: PolicyFile,
): Promise<{ policy: PolicyFile; summary: PolicySummary }> {
  return requestJson("/v1/policy", {
    body: JSON.stringify(policy),
    method: "PUT",
  });
}

export async function simulatePolicy(
  body: PolicySimulationBody,
): Promise<PolicySimulationResponse> {
  return requestJson("/v1/policy/simulate", {
    body: JSON.stringify(body),
    method: "POST",
  });
}

export async function saveToolIntegration(
  id: ToolIntegrationId,
  input: {
    displayName?: string;
    enabled?: boolean;
    values?: Record<string, string>;
  },
): Promise<{ integration: ToolIntegrationStatus }> {
  return requestJson(`/v1/integrations/tools/${encodeURIComponent(id)}`, {
    body: JSON.stringify(input),
    method: "PUT",
  });
}
