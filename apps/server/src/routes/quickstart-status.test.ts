import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../app";
import type { AppConfig } from "../config";
import {
  QuickstartStatusService,
  quickstartApprovalTimeoutMs,
  quickstartSchemaVersion,
  type QuickstartStatusUpdate,
} from "../services/quickstart-status";

const policyPath = path.resolve("src/policies/default.policy.yaml");
const sessionId = "550e8400-e29b-41d4-a716-446655440000";
const updateToken = "test-quickstart-update-token-1234567890";
const originToken = "test-quickstart-origin-token-123456789";
let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe("Quickstart status routes", () => {
  it("returns 404 when explicit Quickstart mode is disabled", async () => {
    app = await buildApp(appConfig());

    const response = await app.inject({
      method: "GET",
      url: `/v1/demo/quickstart/status/${sessionId}`,
    });

    expect(response.statusCode).toBe(404);
  });

  it("keeps an enabled session private until its authenticated first update", async () => {
    app = await buildApp(appConfig(true));

    const missing = await app.inject({
      method: "GET",
      url: `/v1/demo/quickstart/status/${sessionId}`,
    });
    const wrongSession = await app.inject({
      method: "PUT",
      url: "/v1/demo/quickstart/status/550e8400-e29b-41d4-a716-446655440001",
      headers: { "x-actionproxy-quickstart-token": updateToken },
      payload: gatewayUpdate(),
    });
    const missingToken = await app.inject({
      method: "PUT",
      url: `/v1/demo/quickstart/status/${sessionId}`,
      payload: gatewayUpdate(),
    });
    const wrongToken = await app.inject({
      method: "PUT",
      url: `/v1/demo/quickstart/status/${sessionId}`,
      headers: { "x-actionproxy-quickstart-token": "x".repeat(32) },
      payload: gatewayUpdate(),
    });

    expect(missing.statusCode).toBe(404);
    expect(wrongSession.statusCode).toBe(404);
    expect(missingToken.statusCode).toBe(401);
    expect(wrongToken.statusCode).toBe(401);
    expect(wrongToken.body).not.toContain(updateToken);
  });

  it("stores an allowlisted snapshot with server timestamps and no audit event", async () => {
    app = await buildApp(appConfig(true));
    const auditBefore = await app.inject({
      method: "GET",
      url: "/v1/audit?limit=100",
    });

    const update = await app.inject({
      method: "PUT",
      url: `/v1/demo/quickstart/status/${sessionId}`,
      headers: { "x-actionproxy-quickstart-token": updateToken },
      payload: gatewayUpdate(),
    });
    const read = await app.inject({
      method: "GET",
      url: `/v1/demo/quickstart/status/${sessionId}`,
    });
    const auditAfter = await app.inject({
      method: "GET",
      url: "/v1/audit?limit=100",
    });

    expect(update.statusCode).toBe(200);
    expect(update.headers["cache-control"]).toBe("no-store");
    expect(update.json()).toMatchObject({
      ...gatewayUpdate(),
      startedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/u),
      updatedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/u),
    });
    expect(read.statusCode).toBe(200);
    expect(read.headers["cache-control"]).toBe("no-store");
    expect(read.json()).toEqual(update.json());
    expect(read.body).not.toContain(updateToken);
    expect(auditAfter.json()).toEqual(auditBefore.json());
  });

  it("rejects unrecognized fields, checks, remediation codes, unsafe setup details, and remote URLs", async () => {
    app = await buildApp(appConfig(true));
    const request = (payload: Record<string, unknown>) =>
      app!.inject({
        method: "PUT",
        url: `/v1/demo/quickstart/status/${sessionId}`,
        headers: { "x-actionproxy-quickstart-token": updateToken },
        payload,
      });

    const [
      serverTimestamp,
      unknownCheck,
      unknownRemediation,
      duplicate,
      unknownSetupField,
      unsafeVersion,
      unsafeProject,
      unsafePort,
      url,
    ] = await Promise.all([
      request({ ...gatewayUpdate(), startedAt: new Date().toISOString() }),
      request({
        ...gatewayUpdate(),
        checks: [{ id: "environment_dump", state: "pass" }],
      }),
      request({
        ...gatewayUpdate(),
        checks: [
          {
            id: "gateway",
            remediationCode: "print_arbitrary_output",
            state: "fail",
          },
        ],
      }),
      request({
        ...gatewayUpdate(),
        checks: [
          { id: "gateway", state: "pass" },
          { id: "gateway", state: "pass" },
        ],
      }),
      request({
        ...gatewayUpdate(),
        setupDetails: {
          ...gatewayUpdate().setupDetails,
          arbitraryDiagnostic: "/private/path",
        },
      }),
      request({
        ...gatewayUpdate(),
        setupDetails: {
          ...gatewayUpdate().setupDetails!,
          dockerVersion: "Docker 28.1.1\nSECRET=value",
        },
      }),
      request({
        ...gatewayUpdate(),
        setupDetails: {
          ...gatewayUpdate().setupDetails!,
          projectName: "actionproxy-first-run-not-owned",
        },
      }),
      request({
        ...gatewayUpdate(),
        setupDetails: {
          ...gatewayUpdate().setupDetails!,
          port: 80,
        },
      }),
      request({
        ...gatewayUpdate(),
        journey: "chatgpt",
        tunnelUiUrl: "http://127.0.0.1.example.com/ui",
      }),
    ]);

    expect([
      serverTimestamp.statusCode,
      unknownCheck.statusCode,
      unknownRemediation.statusCode,
      duplicate.statusCode,
      unknownSetupField.statusCode,
      unsafeVersion.statusCode,
      unsafeProject.statusCode,
      unsafePort.statusCode,
      url.statusCode,
    ]).toEqual([400, 400, 400, 400, 400, 400, 400, 400, 400]);
  });

  it("requires the body session to match the configured route session", async () => {
    app = await buildApp(appConfig(true));

    const response = await app.inject({
      method: "PUT",
      url: `/v1/demo/quickstart/status/${sessionId}`,
      headers: { "x-actionproxy-quickstart-token": updateToken },
      payload: {
        ...gatewayUpdate(),
        sessionId: "550e8400-e29b-41d4-a716-446655440001",
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: "invalid_request" });
  });

  it("binds the runtime-key Docker proof only to verified ChatGPT tunnel status", async () => {
    app = await buildApp(appConfig(true));
    const request = (payload: QuickstartStatusUpdate) =>
      app!.inject({
        method: "PUT",
        url: `/v1/demo/quickstart/status/${sessionId}`,
        headers: { "x-actionproxy-quickstart-token": updateToken },
        payload,
      });

    const localClaim = await request({
      ...gatewayUpdate(),
      setupDetails: {
        ...setupDetails(),
        runtimeKeyExcludedFromDocker: true,
      },
    });
    const readyWithoutProof = await request({
      ...tunnelReadyUpdate(),
      setupDetails: setupDetails(),
    });

    expect(localClaim.statusCode).toBe(400);
    expect(readyWithoutProof.statusCode).toBe(400);
  });

  it("derives Quickstart tunnel provenance only on the MCP adapter with its distinct private header", async () => {
    app = await buildApp(appConfig(true));
    const payload = {
      agentId: "forged-chatgpt-agent",
      input: { query: "refund policy" },
      metadata: {
        actionproxyQuickstartOrigin: "secure_mcp_tunnel",
        actionproxyQuickstartSessionId: sessionId,
      },
      reason: "Test the server-derived Quickstart marker.",
      requestedBy: "tester@example.local",
      toolName: "docs.search",
    };

    const ordinary = await app.inject({
      method: "POST",
      url: "/v1/tool-calls",
      headers: { "x-actionproxy-quickstart-origin-token": originToken },
      payload,
    });
    const statusTokenAttempt = await app.inject({
      method: "POST",
      url: "/v1/mcp/tool-calls",
      headers: {
        "idempotency-key": "quickstart-status-token-attempt",
        "x-actionproxy-mcp-session-id": sessionId,
        "x-actionproxy-quickstart-origin-token": updateToken,
      },
      payload,
    });
    const verified = await app.inject({
      method: "POST",
      url: "/v1/mcp/tool-calls",
      headers: {
        "idempotency-key": "quickstart-origin-token-proof",
        "x-actionproxy-mcp-session-id": sessionId,
        "x-actionproxy-quickstart-origin-token": originToken,
      },
      payload,
    });

    expect(ordinary.statusCode).toBe(200);
    expect(ordinary.json().toolCall.metadata).not.toHaveProperty(
      "actionproxyQuickstartOrigin",
    );
    expect(statusTokenAttempt.statusCode).toBe(200);
    expect(statusTokenAttempt.json().toolCall.metadata).not.toHaveProperty(
      "actionproxyQuickstartOrigin",
    );
    expect(verified.statusCode).toBe(200);
    expect(verified.json().toolCall.metadata).toMatchObject({
      actionproxyQuickstartOrigin: "secure_mcp_tunnel",
      actionproxyQuickstartSessionId: sessionId,
    });
  });
});

describe("QuickstartStatusService", () => {
  it("preserves the first server timestamp and refreshes the heartbeat timestamp", () => {
    let now = new Date("2026-08-02T08:00:00.000Z");
    const service = new QuickstartStatusService({
      now: () => now,
      sessionId,
      updateToken,
    });

    const first = service.update(gatewayUpdate());
    now = new Date("2026-08-02T08:00:05.000Z");
    const second = service.update(gatewayUpdate());

    expect(first.startedAt).toBe("2026-08-02T08:00:00.000Z");
    expect(second.startedAt).toBe(first.startedAt);
    expect(second.updatedAt).toBe("2026-08-02T08:00:05.000Z");
  });

  it("copies setup details on update and read", () => {
    const service = new QuickstartStatusService({
      sessionId,
      updateToken,
    });
    const input = gatewayUpdate();
    const stored = service.update(input);

    input.setupDetails!.projectName = "actionproxy-first-run-ffffffffff";
    stored.setupDetails!.port = 65535;

    expect(service.get(sessionId)?.setupDetails).toEqual(setupDetails());
  });

  it("derives a disconnected tunnel after a stale heartbeat without mutating the snapshot", () => {
    let now = new Date("2026-08-02T08:00:00.000Z");
    const service = new QuickstartStatusService({
      now: () => now,
      sessionId,
      updateToken,
    });
    const ready = tunnelReadyUpdate();
    service.update(ready);

    now = new Date("2026-08-02T08:00:15.001Z");
    const stale = service.get(sessionId);

    expect(stale).toMatchObject({
      setupStage: "tunnel_stopped",
      updatedAt: "2026-08-02T08:00:00.000Z",
    });
    expect(
      stale?.checks.find((check) => check.id === "tunnel_readiness"),
    ).toEqual({
      id: "tunnel_readiness",
      remediationCode: "tunnel_disconnected",
      state: "action_required",
    });
    expect(ready.checks[0]).toEqual({
      id: "tunnel_readiness",
      state: "pass",
    });

    service.update(ready);
    expect(service.get(sessionId)?.setupStage).toBe("tunnel_ready");
  });
});

function appConfig(quickstart = false): AppConfig {
  return {
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), "actionproxy-quickstart-")),
    host: "127.0.0.1",
    localExecution: { mode: "mock" },
    logLevel: "silent",
    policyPath,
    port: 0,
    quickstart: quickstart
      ? { enabled: true, originToken, sessionId, updateToken }
      : { enabled: false },
  };
}

function gatewayUpdate(): QuickstartStatusUpdate {
  return {
    approvalTimeoutMs: quickstartApprovalTimeoutMs,
    checks: [
      { id: "gateway", state: "pass" },
      { id: "storage", state: "pass" },
      { id: "loopback", state: "pass" },
      { id: "tool_discovery", state: "pass" },
    ],
    journey: "local",
    schemaVersion: quickstartSchemaVersion,
    sessionId,
    setupDetails: setupDetails(),
    setupStage: "gateway_ready",
  };
}

function tunnelReadyUpdate(): QuickstartStatusUpdate {
  return {
    approvalTimeoutMs: quickstartApprovalTimeoutMs,
    checks: [{ id: "tunnel_readiness", state: "pass" }],
    journey: "chatgpt",
    schemaVersion: quickstartSchemaVersion,
    sessionId,
    setupDetails: {
      ...setupDetails(),
      runtimeKeyExcludedFromDocker: true,
    },
    setupStage: "tunnel_ready",
    tunnelUiUrl: "http://127.0.0.1:43123/ui",
  };
}

function setupDetails() {
  return {
    composeVersion: "v2.35.1-desktop.1",
    dockerVersion: "28.1.1",
    nodeVersion: "24.11.0",
    port: 18787,
    projectName: "actionproxy-first-run-0123456789",
  };
}
