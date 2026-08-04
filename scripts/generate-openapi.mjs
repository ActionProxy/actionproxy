#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const OPENAPI_ARTIFACT = "openapi/actionproxy.openapi.json";

export const COMMUNITY_ROUTE_SOURCES = Object.freeze([
  "apps/server/src/integrations/slack/slack-routes.ts",
  "apps/server/src/integrations/telegram/telegram-routes.ts",
  "apps/server/src/routes/approvals.ts",
  "apps/server/src/routes/approvers.ts",
  "apps/server/src/routes/audit.ts",
  "apps/server/src/routes/auth.ts",
  "apps/server/src/routes/authorized-actions.ts",
  "apps/server/src/routes/dashboard.ts",
  "apps/server/src/routes/execution-grants.ts",
  "apps/server/src/routes/health.ts",
  "apps/server/src/routes/integrations.ts",
  "apps/server/src/routes/mcp.ts",
  "apps/server/src/routes/policy-detector.ts",
  "apps/server/src/routes/policy.ts",
  "apps/server/src/routes/quickstart-status.ts",
  "apps/server/src/routes/receipts.ts",
  "apps/server/src/routes/tool-calls.ts",
]);

const JSON_OBJECT = { additionalProperties: true, type: "object" };
const STRING_ID = { minLength: 1, type: "string" };
const UUID_V4 = {
  pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
  type: "string",
};

const route = (method, routePath, tag, summary, options = {}) =>
  Object.freeze({ method, path: routePath, summary, tag, ...options });

/**
 * The explicit list is intentional. Generation fails closed when a Community
 * Fastify route is added or removed without an OpenAPI decision.
 */
export const COMMUNITY_HTTP_OPERATIONS = Object.freeze([
  route("get", "/health", "System", "Check server health", { auth: false, success: "Health" }),
  route("get", "/v1/me", "Authentication", "Inspect the authenticated principal", { success: "Me" }),
  route("post", "/v1/service-accounts", "Authentication", "Create a service account", { body: "CreateServiceAccount" }),
  route("post", "/v1/service-accounts/{id}/keys", "Authentication", "Create a service-account API key", { body: "CreateApiKey", bodyOptional: true }),

  route("get", "/v1/tool-calls", "Tool calls", "List governed tool calls", { query: "toolCalls", success: "ToolCallList" }),
  route("post", "/v1/tool-calls", "Tool calls", "Submit a governed tool call", { body: "SubmitToolCall", headers: ["idempotency"], success: "ToolCallSubmission" }),
  route("get", "/v1/tool-calls/{id}", "Tool calls", "Get a governed tool call", { success: "ToolCall" }),
  route("get", "/v1/tool-calls/{id}/decision-trace", "Tool calls", "Get the policy decision trace"),
  route("get", "/v1/tool-calls/{id}/execution-attempts", "Tool calls", "List execution attempts for a tool call"),
  route("get", "/v1/tool-calls/{id}/remediation-plan", "Tool calls", "Get a remediation plan"),
  route("post", "/v1/tool-calls/{id}/remediation", "Tool calls", "Submit a remediation attempt", { body: "SubmitRemediation", headers: ["idempotency"] }),
  route("post", "/v1/mcp/tool-calls", "MCP adapter", "Submit a tool call from the authenticated stdio MCP adapter", { body: "SubmitToolCall", headers: ["idempotencyRequired", "mcpSessionRequired"], success: "ToolCallSubmission" }),
  route("get", "/v1/mcp/tool-calls/{id}", "MCP adapter", "Get MCP-adapter tool-call status", { headers: ["mcpSessionRequired"], success: "ToolCall" }),

  route("get", "/v1/approvals/pending", "Approvals", "List pending approvals", { success: "ApprovalList" }),
  route("get", "/v1/approvals/{id}", "Approvals", "Get an approval and its tool call", { success: "ApprovalDetail" }),
  route("get", "/v1/approvals/{id}/review", "Approvals", "Get a freshness-bound approval review"),
  route("post", "/v1/approvals/{id}/approve", "Approvals", "Approve an exact proposal", { body: "ApproveApproval", success: "ApprovalDecisionResponse" }),
  route("post", "/v1/approvals/{id}/reject", "Approvals", "Reject a pending proposal", { body: "RejectApproval", success: "ApprovalDecisionResponse" }),
  route("post", "/v1/approvals/{id}/cancel", "Approvals", "Cancel a pending proposal", { body: "CancelApproval", success: "ApprovalDecisionResponse" }),
  route("post", "/v1/approvals/{id}/notifications/resend", "Approvals", "Resend approval notifications"),

  route("get", "/v1/audit", "Audit", "List audit events", { query: "audit" }),
  route("get", "/v1/audit/export", "Audit", "Export filtered audit events", { query: "auditExport", successContentTypes: ["application/json", "application/x-ndjson"] }),
  route("get", "/v1/audit/verify", "Audit", "Verify the local audit hash chain", { query: "auditVerify", success: "AuditVerification" }),
  route("get", "/v1/receipts/{id}", "Audit", "Get an action receipt"),
  route("get", "/v1/authorized-actions", "Execution", "List authorized external actions", { query: "authorizedActions" }),
  route("post", "/v1/execution-grants/{id}/consume", "Execution", "Consume a single-use execution grant", { body: "ConsumeExecutionGrant", headers: ["wrapperSession"] }),
  route("post", "/v1/execution-grants/{id}/outcome", "Execution", "Report an external execution outcome", { body: "ReportExecutionOutcome", headers: ["wrapperSession"] }),

  route("get", "/v1/policy", "Policy", "Get the active policy", { success: "PolicyFile" }),
  route("put", "/v1/policy", "Policy", "Replace the active policy", { body: "PolicyFile" }),
  route("get", "/v1/policy/summary", "Policy", "Get a normalized policy summary"),
  route("get", "/v1/policy/presets", "Policy", "List Community policy presets"),
  route("post", "/v1/policy/simulate", "Policy", "Simulate policy without side effects", { body: "PolicySimulation" }),
  route("get", "/v1/policy/detector", "Policy detector", "List observed policy gaps"),
  route("post", "/v1/policy/detector/{id}/apply", "Policy detector", "Apply an observed-tool rule", { body: "ApplyDetectedPolicy", bodyOptional: true }),
  route("post", "/v1/policy/detector/{id}/dismiss", "Policy detector", "Dismiss an observed policy gap"),

  route("get", "/v1/approvers", "Approvers", "List approver users and groups"),
  route("post", "/v1/approvers/users", "Approvers", "Create an approver user", { body: "ApproverUserInput", successStatus: "201" }),
  route("put", "/v1/approvers/users/{id}", "Approvers", "Update an approver user", { body: "ApproverUserInput" }),
  route("delete", "/v1/approvers/users/{id}", "Approvers", "Delete an approver user"),
  route("post", "/v1/approvers/users/{id}/telegram-connect", "Approvers", "Create a Telegram connection link"),
  route("post", "/v1/approvers/users/{id}/telegram-connect/poll", "Approvers", "Poll a Telegram approver connection"),
  route("delete", "/v1/approvers/users/{id}/telegram-connection", "Approvers", "Disconnect an approver from Telegram"),
  route("post", "/v1/approvers/groups", "Approvers", "Create an approver group", { body: "ApproverGroupInput", successStatus: "201" }),
  route("put", "/v1/approvers/groups/{id}", "Approvers", "Update an approver group", { body: "ApproverGroupInput" }),
  route("delete", "/v1/approvers/groups/{id}", "Approvers", "Delete an approver group"),

  route("get", "/v1/integrations", "Local integrations", "Get local integration status"),
  route("put", "/v1/integrations/slack", "Local integrations", "Configure local Slack delivery", { body: "SlackIntegrationUpdate" }),
  route("post", "/v1/integrations/slack/test", "Local integrations", "Test local Slack delivery"),
  route("put", "/v1/integrations/telegram", "Local integrations", "Configure local Telegram delivery", { body: "TelegramIntegrationUpdate" }),
  route("post", "/v1/integrations/telegram/test", "Local integrations", "Test local Telegram delivery", { body: "TelegramIntegrationTest", bodyOptional: true }),
  route("put", "/v1/integrations/email", "Local integrations", "Configure local email delivery", { body: "EmailIntegrationUpdate" }),
  route("post", "/v1/integrations/email/test", "Local integrations", "Test local email delivery"),
  route("put", "/v1/integrations/tools/{id}", "Local integrations", "Configure a local tool integration", { body: "ToolIntegrationUpdate" }),
  route("put", "/v1/integrations/mcp-wrapper/profiles/{id}", "Local integrations", "Save an MCP wrapper profile", { body: "McpWrapperProfile" }),
  route("get", "/v1/integrations/mcp-wrapper/profiles/{id}/yaml", "Local integrations", "Get generated YAML for an MCP wrapper profile"),
  route("post", "/v1/integrations/mcp-wrapper/profiles/{id}/sync-tools", "Local integrations", "Discover tools for an MCP wrapper profile"),
  route("get", "/v1/dashboard/overview", "Operator console", "Get the local operator overview", { query: "dashboard" }),

  route("post", "/v1/slack/interactions", "Approval webhooks", "Receive a signed Slack interaction", { auth: false, bodyContentType: "application/x-www-form-urlencoded", body: "SlackInteractionBody", bodyOptional: true, headers: ["slackSignature", "slackTimestamp"] }),
  route("post", "/v1/telegram/webhook", "Approval webhooks", "Receive a Telegram Bot API webhook", { auth: false, body: "TelegramWebhookUpdate", bodyOptional: true, headers: ["telegramSecret"] }),

  route("get", "/.well-known/oauth-protected-resource", "MCP HTTP", "Get MCP protected-resource metadata", { auth: false, availability: "Requires ACTIONPROXY_MCP_HTTP_ENABLED=true." }),
  route("get", "/.well-known/oauth-protected-resource/mcp", "MCP HTTP", "Get MCP protected-resource metadata for /mcp", { auth: false, availability: "Requires ACTIONPROXY_MCP_HTTP_ENABLED=true." }),
  route("get", "/mcp", "MCP HTTP", "Reject unsupported MCP SSE reads", { authRequired: true, availability: "Requires ACTIONPROXY_MCP_HTTP_ENABLED=true and an OAuth bearer with verified client identity.", successStatus: "405" }),
  route("delete", "/mcp", "MCP HTTP", "Reject unsupported MCP session deletion", { authRequired: true, availability: "Requires ACTIONPROXY_MCP_HTTP_ENABLED=true and an OAuth bearer with verified client identity.", successStatus: "405" }),
  route("post", "/mcp", "MCP HTTP", "Exchange one MCP Streamable HTTP JSON-RPC message", { authRequired: true, availability: "Requires ACTIONPROXY_MCP_HTTP_ENABLED=true and an OAuth bearer with verified client identity.", body: "JsonRpcRequest", headers: ["mcpAccept", "mcpProtocol", "mcpSession"] }),

  route("get", "/v1/demo/quickstart/status/{sessionId}", "Quickstart", "Read an ephemeral Quickstart status snapshot", { auth: false, availability: "Registered only in explicit local Quickstart mode.", success: "QuickstartStatus" }),
  route("put", "/v1/demo/quickstart/status/{sessionId}", "Quickstart", "Update an ephemeral Quickstart status snapshot", { auth: false, availability: "Registered only in explicit local Quickstart mode; intended for the concierge launcher, not browser code.", body: "QuickstartStatusUpdate", headers: ["quickstartToken"], success: "QuickstartStatus" }),
]);

const queryParameters = Object.freeze({
  audit: [
    query("format", { enum: ["json", "siem"], type: "string" }),
    query("from", { format: "date-time", type: "string" }),
    query("limit", { maximum: 5000, minimum: 1, type: "integer" }),
    query("toolCallId", STRING_ID),
    query("to", { format: "date-time", type: "string" }),
  ],
  auditExport: [
    query("format", { enum: ["json", "siem"], type: "string" }),
    query("from", { format: "date-time", type: "string" }),
    query("toolCallId", STRING_ID),
    query("to", { format: "date-time", type: "string" }),
  ],
  auditVerify: [query("limit", { maximum: 10000, minimum: 1, type: "integer" })],
  authorizedActions: [
    query("limit", { default: 100, maximum: 1000, minimum: 1, type: "integer" }),
    query("status", { default: "waiting", enum: ["all", "completed", "consumed", "expired", "failed", "waiting"], type: "string" }),
  ],
  dashboard: [query("window", { default: "24h", enum: ["24h", "7d", "30d"], type: "string" })],
  toolCalls: [
    query("decision", { enum: ["allow", "require_approval", "deny"], type: "string" }),
    query("limit", { maximum: 1000, minimum: 1, type: "integer" }),
    query("runId", STRING_ID),
    query("sessionId", STRING_ID),
    query("status", { enum: ["submitted", "authorized", "executed", "pending_approval", "blocked", "rejected", "failed"], type: "string" }),
    query("toolName", STRING_ID),
  ],
});

const headerParameters = Object.freeze({
  idempotency: header("Idempotency-Key", { maxLength: 512, minLength: 1, type: "string" }, false, "Deduplicates a submission."),
  idempotencyRequired: header("Idempotency-Key", { maxLength: 512, minLength: 1, type: "string" }, true, "Required transport request identifier for the stdio MCP adapter."),
  mcpAccept: header("Accept", { type: "string" }, true, "Must accept both application/json and text/event-stream."),
  mcpProtocol: header("MCP-Protocol-Version", { type: "string" }, false, "Required after MCP initialization."),
  mcpSession: header("MCP-Session-Id", { type: "string" }, false, "MCP Streamable HTTP session identifier."),
  mcpSessionRequired: header("X-ActionProxy-MCP-Session-Id", { format: "uuid", type: "string" }, true, "Authenticated stdio MCP wrapper session UUID."),
  quickstartToken: header("X-ActionProxy-Quickstart-Token", STRING_ID, true, "Session-owned update token. It is never exposed to browser code."),
  slackSignature: header("X-Slack-Signature", STRING_ID, true, "Slack request signature."),
  slackTimestamp: header("X-Slack-Request-Timestamp", STRING_ID, true, "Slack request timestamp."),
  telegramSecret: header("X-Telegram-Bot-Api-Secret-Token", STRING_ID, true, "Configured Telegram webhook secret."),
  wrapperSession: header("X-ActionProxy-MCP-Session-Id", { format: "uuid", type: "string" }, false, "Required only when continuing an authenticated stdio MCP wrapper action."),
});

export function buildOpenApiDocument() {
  assertOperationDefinitions();
  const paths = {};
  for (const definition of [...COMMUNITY_HTTP_OPERATIONS].sort(compareOperation)) {
    paths[definition.path] ??= {};
    paths[definition.path][definition.method] = buildOperation(definition);
  }

  return {
    openapi: "3.1.0",
    jsonSchemaDialect: "https://json-schema.org/draft/2020-12/schema",
    info: {
      title: "ActionProxy Community HTTP API",
      version: "0.1.0",
      description: "The self-hosted Community API for submitting governed tool calls, reviewing approvals, executing exact authorized actions, and verifying local audit evidence. Static web routes and routes outside the Community boundary are intentionally excluded.",
      license: { name: "Apache-2.0", identifier: "Apache-2.0" },
    },
    servers: [{ url: "http://127.0.0.1:8787", description: "Default loopback development server" }],
    tags: [...new Set(COMMUNITY_HTTP_OPERATIONS.map(({ tag }) => tag))]
      .sort()
      .map((name) => ({ name })),
    paths,
    components: {
      securitySchemes: {
        bearerAuth: {
          scheme: "bearer",
          type: "http",
          description: "A service-account API key or OIDC access token, depending on AUTH_MODE. Omit only when AUTH_MODE=none.",
        },
      },
      schemas: componentSchemas(),
    },
  };
}

export function serializeOpenApiDocument() {
  return `${JSON.stringify(buildOpenApiDocument(), null, 2)}\n`;
}

export function normalizeFastifyRoute(method, routePath) {
  return `${method.toLowerCase()} ${routePath.replace(/:([A-Za-z0-9_]+)/gu, "{$1}")}`;
}

export function operationKeys() {
  return COMMUNITY_HTTP_OPERATIONS.map(({ method, path: routePath }) => `${method} ${routePath}`).sort();
}

function buildOperation(definition) {
  const parameters = [
    ...pathParameters(definition.path),
    ...(definition.query ? queryParameters[definition.query] : []),
    ...(definition.headers ?? []).map((name) => headerParameters[name]),
  ];
  const operation = {
    operationId: operationId(definition.method, definition.path),
    summary: definition.summary,
    tags: [definition.tag],
    security: definition.auth === false
      ? []
      : definition.authRequired
        ? [{ bearerAuth: [] }]
        : [{ bearerAuth: [] }, {}],
    responses: responsesFor(definition),
  };
  if (parameters.length > 0) operation.parameters = parameters;
  if (definition.body) {
    operation.requestBody = {
      required: definition.bodyOptional !== true,
      content: {
        [definition.bodyContentType ?? "application/json"]: {
          schema: schemaRef(definition.body),
        },
      },
    };
  }
  if (definition.availability) {
    operation.description = definition.availability;
    operation["x-actionproxy-availability"] = definition.availability;
  }
  return operation;
}

function responsesFor(definition) {
  const successStatus = definition.successStatus ?? (definition.method === "post" && definition.successStatus === undefined ? "200" : "200");
  const successTypes = definition.successContentTypes ?? ["application/json"];
  const content = Object.fromEntries(successTypes.map((contentType) => [
    contentType,
    {
      schema: contentType === "application/x-ndjson" || contentType === "application/yaml"
        ? { type: "string" }
        : definition.success
          ? schemaRef(definition.success)
          : schemaRef("JsonObject"),
    },
  ]));
  const responses = {
    [successStatus]: { description: successStatus === "201" ? "Created" : successStatus === "405" ? "Method intentionally unsupported" : "Successful response", content },
  };
  if (
    definition.auth !== false ||
    definition.headers?.some((name) => ["quickstartToken", "slackSignature", "slackTimestamp", "telegramSecret"].includes(name))
  ) {
    responses["401"] = { description: "Authentication required or invalid", content: jsonContent(schemaRef("Error")) };
  }
  if (definition.auth !== false) {
    responses["403"] = { description: "The principal lacks the required scope or resource access", content: jsonContent(schemaRef("Error")) };
  }
  if (definition.path.includes("{") || definition.availability) {
    responses["404"] = { description: "Resource not found", content: jsonContent(schemaRef("Error")) };
  }
  if (definition.body || definition.query || definition.headers?.some((name) => name.endsWith("Required"))) {
    responses["400"] = { description: "Request validation failed", content: jsonContent(schemaRef("Error")) };
  }
  return responses;
}

function componentSchemas() {
  const action = {
    additionalProperties: false,
    properties: {
      context: JSON_OBJECT,
      executionMode: { enum: ["external_grant", "local_mock"], type: "string" },
      operation: {
        additionalProperties: false,
        properties: {
          kind: { enum: ["custom", "delete", "external_send", "financial", "read", "write"], type: "string" },
          name: STRING_ID,
        },
        type: "object",
      },
      protocol: { enum: ["actionproxy_http", "cli", "custom", "langgraph", "mcp", "n8n", "openai_tools", "webhook"], type: "string" },
      resources: {
        items: {
          properties: { id: { type: "string" }, metadata: JSON_OBJECT, name: { type: "string" }, type: STRING_ID, url: { type: "string" } },
          required: ["type"],
          type: "object",
        },
        type: "array",
      },
      source: {
        properties: { id: { type: "string" }, metadata: JSON_OBJECT, name: { type: "string" }, type: STRING_ID },
        type: "object",
      },
    },
    type: "object",
  };
  return {
    ActionDescriptor: action,
    ApplyDetectedPolicy: { additionalProperties: false, properties: { approval: { enum: ["deny", "never", "required"], type: "string" }, pattern: { pattern: "^[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)*(?:\\.\\*)?$", type: "string" }, reason: { type: "string" }, risk: { type: "string" } }, type: "object" },
    Approval: approvalSchema(),
    ApprovalDecisionResponse: { properties: { approval: schemaRef("Approval"), toolCall: schemaRef("ToolCall") }, required: ["approval", "toolCall"], type: "object" },
    ApprovalDetail: { properties: { approval: schemaRef("Approval"), toolCall: schemaRef("ToolCall") }, required: ["approval", "toolCall"], type: "object" },
    ApprovalList: { properties: { approvals: { items: schemaRef("Approval"), type: "array" } }, required: ["approvals"], type: "object" },
    ApproveApproval: {
      properties: {
        approvalNonce: STRING_ID,
        approvedBy: STRING_ID,
        editedInput: { oneOf: [JSON_OBJECT, { type: "null" }] },
        inputDecision: { oneOf: [{ properties: { mode: { const: "original" } }, required: ["mode"], type: "object" }, { properties: { input: JSON_OBJECT, mode: { const: "edited" } }, required: ["input", "mode"], type: "object" }] },
        note: { type: "string" },
        reviewHash: STRING_ID,
      },
      type: "object",
    },
    ApproverGroupInput: { properties: { description: { type: "string" }, displayName: { type: "string" }, enabled: { type: "boolean" } }, type: "object" },
    ApproverUserInput: { properties: { defaultApprover: { type: "boolean" }, displayName: { type: "string" }, email: { oneOf: [{ format: "email", type: "string" }, { const: "" }] }, enabled: { type: "boolean" }, groups: { items: STRING_ID, type: "array" }, principalId: { maxLength: 512, minLength: 1, type: "string" }, slackUserId: { type: "string" }, telegramChatId: { type: "string" }, telegramUsername: { type: "string" }, telegramUserId: { type: "string" } }, type: "object" },
    AuditVerification: { additionalProperties: false, properties: { checked: { minimum: 0, type: "integer" }, errors: { items: { additionalProperties: false, properties: { eventId: { type: "string" }, index: { minimum: 0, type: "integer" }, reason: { enum: ["previous_event_hash_mismatch", "missing_event_hash", "event_hash_mismatch"], type: "string" } }, required: ["eventId", "index", "reason"], type: "object" }, type: "array" }, firstEventHash: { pattern: "^[a-f0-9]{64}$", type: "string" }, lastEventHash: { pattern: "^[a-f0-9]{64}$", type: "string" }, valid: { type: "boolean" } }, required: ["checked", "errors", "valid"], type: "object" },
    AuthContext: { properties: { authProvider: { enum: ["api_key", "none", "oidc_jwt", "slack", "telegram"], type: "string" }, clientId: { type: "string" }, displayName: { type: "string" }, email: { type: "string" }, groups: { items: { type: "string" }, type: "array" }, principalId: { type: "string" }, principalType: { enum: ["local", "service_account", "slack", "telegram", "user"], type: "string" }, scopes: { items: { type: "string" }, type: "array" }, workspaceId: { type: "string" } }, required: ["authProvider", "displayName", "groups", "principalId", "principalType", "scopes", "workspaceId"], type: "object" },
    CancelApproval: { properties: { approvalNonce: STRING_ID, cancelledBy: STRING_ID, reason: { type: "string" } }, type: "object" },
    ConsumeExecutionGrant: { properties: { input: JSON_OBJECT, policyVersionHash: { type: "string" }, toolCallId: STRING_ID, toolName: STRING_ID }, required: ["input", "toolCallId", "toolName"], type: "object" },
    CreateApiKey: { properties: { scopes: { items: STRING_ID, type: "array" } }, type: "object" },
    CreateServiceAccount: { properties: { description: { type: "string" }, groups: { items: STRING_ID, type: "array" }, name: STRING_ID, scopes: { items: STRING_ID, type: "array" } }, required: ["name"], type: "object" },
    EmailIntegrationUpdate: { additionalProperties: false, properties: { approvalRecipient: { type: "string" }, enabled: { type: "boolean" }, from: { type: "string" }, publicBaseUrl: { type: "string" }, smtp: { additionalProperties: false, properties: { host: { type: "string" }, password: { format: "password", type: "string", writeOnly: true }, port: { minimum: 1, type: "integer" }, secure: { type: "boolean" }, username: { type: "string" } }, type: "object" }, transport: { enum: ["outbox", "smtp"], type: "string" } }, type: "object" },
    Error: { properties: { details: JSON_OBJECT, error: STRING_ID, message: { type: "string" } }, required: ["error"], type: "object" },
    Health: { additionalProperties: false, properties: { ok: { const: true }, service: { const: "actionproxy-server" } }, required: ["ok", "service"], type: "object" },
    JsonObject: JSON_OBJECT,
    JsonRpcRequest: { additionalProperties: false, properties: { id: { oneOf: [{ maxLength: 512, minLength: 1, type: "string" }, { type: "integer" }] }, jsonrpc: { const: "2.0" }, method: { maxLength: 256, minLength: 1, type: "string" }, params: true }, required: ["jsonrpc", "method"], type: "object" },
    McpWrapperConfig: { $ref: "../schemas/actionproxy.mcp-wrapper.v1.schema.json" },
    McpWrapperProfile: {
      additionalProperties: false,
      properties: {
        actionproxy: { additionalProperties: false, properties: { agentId: { type: "string" }, approvalPollIntervalMs: { minimum: 1, type: "integer" }, approvalTimeoutMs: { minimum: 1, type: "integer" }, baseUrl: STRING_ID, bearerTokenEnv: { pattern: "^[A-Za-z_][A-Za-z0-9_]*$", type: "string" }, requestedBy: { type: "string" }, requestTimeoutMs: { minimum: 1, type: "integer" } }, required: ["baseUrl"], type: "object" },
        id: { type: "string" },
        name: { type: "string" },
        policies: { additionalProperties: { properties: { approval: { enum: ["deny", "never", "required"], type: "string" } }, required: ["approval"], type: "object" }, type: "object" },
        server: { additionalProperties: false, properties: { args: { items: { type: "string" }, type: "array" }, command: STRING_ID, cwd: { type: "string" }, env: { additionalProperties: { type: "string" }, type: "object" }, name: STRING_ID, requestTimeoutMs: { minimum: 1, type: "integer" } }, required: ["command", "name"], type: "object" },
      },
      required: ["actionproxy", "server"],
      type: "object",
    },
    Me: { properties: { auth: schemaRef("AuthContext"), availableScopes: { items: { type: "string" }, type: "array" } }, required: ["auth", "availableScopes"], type: "object" },
    PolicyFile: { $ref: "../schemas/actionproxy.policy.v1.schema.json" },
    PolicySimulation: { properties: { action, agentId: STRING_ID, hypotheticalContentInfluence: { additionalProperties: false, properties: { observedIntegrities: { items: { enum: ["organization_managed", "verified_publisher", "authenticated_external", "public_untrusted", "unknown"], type: "string" }, maxItems: 5, type: "array", uniqueItems: true }, scopeVerified: { type: "boolean" } }, required: ["scopeVerified"], type: "object" }, input: JSON_OBJECT, metadata: JSON_OBJECT, policy: true, policyYaml: { type: "string" }, reason: STRING_ID, requestedBy: { default: "authenticated-principal", minLength: 1, type: "string" }, toolName: STRING_ID }, required: ["agentId", "input", "reason", "toolName"], type: "object" },
    QuickstartStatusUpdate: quickstartStatusSchema(),
    QuickstartStatus: quickstartStatusSchema(true),
    RejectApproval: { properties: { approvalNonce: STRING_ID, reason: { type: "string" }, rejectedBy: STRING_ID }, type: "object" },
    ReportExecutionOutcome: { additionalProperties: false, properties: { error: { type: "string" }, remediation: JSON_OBJECT, result: JSON_OBJECT, resultDelivery: { additionalProperties: false, properties: { byteCount: { maximum: 16777216, minimum: 0, type: "integer" }, canonicalResultHash: { pattern: "^[a-f0-9]{64}$", type: "string" }, modelVisible: { type: "boolean" }, version: { const: "actionproxy.result-delivery.v1" } }, required: ["byteCount", "canonicalResultHash", "modelVisible", "version"], type: "object" }, status: { enum: ["cancelled", "failed", "succeeded", "timed_out", "unknown_outcome"], type: "string" } }, required: ["status"], type: "object" },
    SlackIntegrationUpdate: { additionalProperties: false, properties: { approvalChannelId: { type: "string" }, botToken: { format: "password", type: "string", writeOnly: true }, enabled: { type: "boolean" }, publicBaseUrl: { type: "string" }, signingSecret: { format: "password", type: "string", writeOnly: true } }, type: "object" },
    SlackInteractionBody: { description: "Raw Slack application/x-www-form-urlencoded interaction payload.", type: "string" },
    SubmitRemediation: { properties: { agentId: STRING_ID, input: JSON_OBJECT, metadata: JSON_OBJECT, reason: STRING_ID, requestedBy: STRING_ID }, type: "object" },
    SubmitToolCall: { additionalProperties: false, properties: { action, agentId: STRING_ID, input: JSON_OBJECT, metadata: JSON_OBJECT, reason: STRING_ID, requestedBy: { default: "authenticated-principal", minLength: 1, type: "string" }, toolName: STRING_ID }, required: ["agentId", "input", "reason", "toolName"], type: "object" },
    TelegramIntegrationTest: { additionalProperties: false, properties: { userId: { maxLength: 120, minLength: 1, type: "string" } }, type: "object" },
    TelegramIntegrationUpdate: { additionalProperties: false, properties: { approvalChatId: { type: "string" }, botToken: { format: "password", type: "string", writeOnly: true }, enabled: { type: "boolean" }, publicBaseUrl: { type: "string" }, webhookSecret: { format: "password", type: "string", writeOnly: true } }, type: "object" },
    TelegramWebhookUpdate: JSON_OBJECT,
    ToolIntegrationUpdate: { additionalProperties: false, properties: { displayName: { type: "string" }, enabled: { type: "boolean" }, values: { additionalProperties: { type: "string" }, type: "object" } }, type: "object" },
    ToolCall: toolCallSchema(),
    ToolCallList: { properties: { toolCalls: { items: schemaRef("ToolCall"), type: "array" } }, required: ["toolCalls"], type: "object" },
    ToolCallSubmission: { properties: { approval: { properties: { id: STRING_ID, status: { enum: ["pending", "approved", "cancelled", "expired", "rejected"], type: "string" } }, required: ["id", "status"], type: "object" }, decision: { enum: ["allow", "require_approval", "deny"], type: "string" }, error: { type: "string" }, id: STRING_ID, reason: { type: "string" }, result: true, risk: { type: "string" }, status: { enum: ["submitted", "authorized", "executed", "pending_approval", "blocked", "rejected", "failed"], type: "string" } }, required: ["decision", "id", "status"], type: "object" },
  };
}

function approvalSchema() {
  return {
    additionalProperties: true,
    properties: {
      approvedBy: { type: "string" },
      cancelledAt: { format: "date-time", type: "string" },
      cancelledBy: { type: "string" },
      cancellationReason: { type: "string" },
      createdAt: { format: "date-time", type: "string" },
      editedInput: JSON_OBJECT,
      expiredAt: { format: "date-time", type: "string" },
      id: STRING_ID,
      note: { type: "string" },
      originalInput: JSON_OBJECT,
      rejectedBy: { type: "string" },
      rejectionReason: { type: "string" },
      requestedBy: { type: "string" },
      status: { enum: ["pending", "approved", "cancelled", "expired", "rejected"], type: "string" },
      toolCallId: STRING_ID,
      updatedAt: { format: "date-time", type: "string" },
      workspaceId: { type: "string" },
    },
    required: ["createdAt", "id", "originalInput", "requestedBy", "status", "toolCallId", "updatedAt"],
    type: "object",
  };
}

function toolCallSchema() {
  return {
    additionalProperties: true,
    properties: {
      agentId: STRING_ID,
      createdAt: { format: "date-time", type: "string" },
      decision: { enum: ["allow", "require_approval", "deny"], type: "string" },
      error: { type: "string" },
      id: STRING_ID,
      input: JSON_OBJECT,
      metadata: JSON_OBJECT,
      policyReason: { type: "string" },
      reason: STRING_ID,
      requestedBy: STRING_ID,
      result: true,
      risk: { type: "string" },
      status: { enum: ["submitted", "authorized", "executed", "pending_approval", "blocked", "rejected", "failed"], type: "string" },
      toolName: STRING_ID,
      updatedAt: { format: "date-time", type: "string" },
      workspaceId: { type: "string" },
    },
    required: ["agentId", "createdAt", "id", "input", "metadata", "reason", "requestedBy", "status", "toolName", "updatedAt"],
    type: "object",
  };
}

function quickstartStatusSchema(includeServerTimestamps = false) {
  const checkIds = ["node", "docker_cli", "docker_daemon", "compose", "gateway", "storage", "loopback", "tool_discovery", "tunnel_client", "tunnel_doctor", "tunnel_readiness"];
  const schema = {
    additionalProperties: false,
    properties: {
      approvalTimeoutMs: { const: 300000 },
      checks: { items: { additionalProperties: false, properties: { id: { enum: checkIds, type: "string" }, remediationCode: { enum: ["unsupported_os", "unsupported_node", "docker_missing", "docker_not_running", "compose_missing", "gateway_unhealthy", "storage_not_sqlite", "non_loopback_binding", "runtime_key_in_docker", "tool_discovery_mismatch", "tunnel_client_missing", "tunnel_client_incompatible", "tunnel_access_failed", "tunnel_not_ready", "tunnel_disconnected"], type: "string" }, state: { enum: ["pending", "running", "pass", "action_required", "fail"], type: "string" } }, required: ["id", "state"], type: "object" }, maxItems: checkIds.length, type: "array" },
      journey: { enum: ["local", "chatgpt"], type: "string" },
      schemaVersion: { const: "actionproxy.quickstart.v1" },
      sessionId: UUID_V4,
      setupDetails: { additionalProperties: false, properties: { composeVersion: { type: "string" }, dockerVersion: { type: "string" }, nodeVersion: { type: "string" }, port: { maximum: 65535, minimum: 1024, type: "integer" }, projectName: { pattern: "^actionproxy-first-run-[a-f0-9]{10}$", type: "string" }, runtimeKeyExcludedFromDocker: { type: "boolean" } }, required: ["composeVersion", "dockerVersion", "nodeVersion", "port", "projectName"], type: "object" },
      setupStage: { enum: ["gateway_starting", "gateway_ready", "tunnel_checking", "tunnel_ready", "tunnel_stopped", "failed"], type: "string" },
      tunnelUiUrl: { format: "uri", type: "string" },
    },
    required: ["approvalTimeoutMs", "checks", "journey", "schemaVersion", "sessionId", "setupStage"],
    type: "object",
  };
  if (includeServerTimestamps) {
    schema.properties.startedAt = { format: "date-time", type: "string" };
    schema.properties.updatedAt = { format: "date-time", type: "string" };
    schema.required.push("startedAt", "updatedAt");
  }
  return schema;
}

function pathParameters(routePath) {
  return [...routePath.matchAll(/\{([^}]+)\}/gu)].map(([, name]) => ({
    in: "path",
    name,
    required: true,
    schema: name === "sessionId" ? UUID_V4 : STRING_ID,
  }));
}

function query(name, schema) {
  return { in: "query", name, required: false, schema };
}

function header(name, schema, required, description) {
  return { description, in: "header", name, required, schema };
}

function schemaRef(name) {
  return { $ref: `#/components/schemas/${name}` };
}

function jsonContent(schema) {
  return { "application/json": { schema } };
}

function operationId(method, routePath) {
  const words = routePath
    .replace(/[{}]/gu, "")
    .split(/[^A-Za-z0-9]+/u)
    .filter(Boolean)
    .map((word) => `${word[0].toUpperCase()}${word.slice(1)}`);
  return `${method}${words.join("")}`;
}

function compareOperation(left, right) {
  return compareText(left.path, right.path) || compareText(left.method, right.method);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertOperationDefinitions() {
  const seenKeys = new Set();
  const seenIds = new Set();
  for (const definition of COMMUNITY_HTTP_OPERATIONS) {
    const key = `${definition.method} ${definition.path}`;
    if (seenKeys.has(key)) throw new Error(`Duplicate Community HTTP operation: ${key}`);
    seenKeys.add(key);
    const id = operationId(definition.method, definition.path);
    if (seenIds.has(id)) throw new Error(`Duplicate OpenAPI operationId: ${id}`);
    seenIds.add(id);
    if (definition.query && !queryParameters[definition.query]) throw new Error(`Unknown query parameter set: ${definition.query}`);
    for (const headerName of definition.headers ?? []) {
      if (!headerParameters[headerName]) throw new Error(`Unknown header parameter: ${headerName}`);
    }
  }
}

async function main(argv) {
  const mode = argv.length === 0 ? "write" : argv.length === 1 && argv[0] === "--check" ? "check" : undefined;
  if (!mode) {
    console.error("Usage: node scripts/generate-openapi.mjs [--check]");
    process.exitCode = 2;
    return;
  }
  const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const artifactPath = path.join(repositoryRoot, OPENAPI_ARTIFACT);
  const expected = serializeOpenApiDocument();
  if (mode === "write") {
    await mkdir(path.dirname(artifactPath), { recursive: true });
    await writeFile(artifactPath, expected, "utf8");
    console.log(`Wrote ${OPENAPI_ARTIFACT}`);
    return;
  }
  let actual;
  try {
    actual = await readFile(artifactPath, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    console.error(`${OPENAPI_ARTIFACT} is missing. Run: corepack pnpm openapi:generate`);
    process.exitCode = 1;
    return;
  }
  if (actual !== expected) {
    console.error(`${OPENAPI_ARTIFACT} is stale. Run: corepack pnpm openapi:generate`);
    process.exitCode = 1;
    return;
  }
  console.log(`OpenAPI contract is current: ${OPENAPI_ARTIFACT}`);
}

const invokedAsScript = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) {
  await main(process.argv.slice(2));
}
