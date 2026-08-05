import { afterEach, describe, expect, it, vi } from "vitest";
import {
  actionProxyApiTokenStorageKey,
  clearApiToken,
  currentApiToken,
  fetchAuditVerification,
  fetchQuickstartStatus,
  saveApiToken,
  simulatePolicy,
  submitToolCall,
} from "./actionproxy-client";

afterEach(() => {
  delete (import.meta.env as Record<string, string | undefined>)
    .VITE_ACTIONPROXY_API_TOKEN;
  vi.unstubAllGlobals();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe("ActionProxy web client auth", () => {
  it("keeps and clears a browser API token only for the current tab session", () => {
    saveApiToken("  apx_browser_token  ");

    expect(window.sessionStorage.getItem(actionProxyApiTokenStorageKey)).toBe(
      "apx_browser_token",
    );
    expect(
      window.localStorage.getItem(actionProxyApiTokenStorageKey),
    ).toBeNull();
    expect(currentApiToken()).toBe("apx_browser_token");

    clearApiToken();

    expect(currentApiToken()).toBeUndefined();
  });

  it("sends the saved API token as a bearer token with JSON requests", async () => {
    saveApiToken("apx_browser_token");
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ id: "call_1", status: "executed" }), {
          headers: { "content-type": "application/json" },
          status: 200,
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await submitToolCall({
      agentId: "agent_support",
      input: { customerId: "cus_123" },
      reason: "Draft follow-up",
      requestedBy: "operator@example.com",
      toolName: "docs.search",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const firstCall = fetchMock.mock.calls[0];
    if (!firstCall) throw new Error("Expected fetch to be called.");
    const init = firstCall[1] as RequestInit | undefined;
    expect(init?.headers).toMatchObject({
      authorization: "Bearer apx_browser_token",
      "content-type": "application/json",
    });
  });

  it("uses the ActionProxy Vite API token when configured", () => {
    (import.meta.env as Record<string, string>).VITE_ACTIONPROXY_API_TOKEN =
      " new-token ";

    expect(currentApiToken()).toBe("new-token");
  });

  it("sends hypothetical content influence only as policy-simulation input", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ sideEffects: false, trace: {} }), {
          headers: { "content-type": "application/json" },
          status: 200,
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await simulatePolicy({
      agentId: "policy-simulator",
      hypotheticalContentInfluence: {
        observedIntegrities: ["public_untrusted"],
        scopeVerified: true,
      },
      input: { note: "proposed note" },
      reason: "Test influence policy",
      toolName: "research.notes.append",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/policy/simulate",
      expect.objectContaining({
        body: JSON.stringify({
          agentId: "policy-simulator",
          hypotheticalContentInfluence: {
            observedIntegrities: ["public_untrusted"],
            scopeVerified: true,
          },
          input: { note: "proposed note" },
          reason: "Test influence policy",
          toolName: "research.notes.append",
        }),
        method: "POST",
      }),
    );
  });

  it("loads audit verification through the authenticated JSON client", async () => {
    saveApiToken("apx_browser_token");
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ checked: 12, errors: [], valid: true }), {
        headers: { "content-type": "application/json" },
        status: 200,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchAuditVerification()).resolves.toMatchObject({
      checked: 12,
      valid: true,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/audit/verify",
      expect.objectContaining({
        headers: expect.objectContaining({
          authorization: "Bearer apx_browser_token",
        }),
      }),
    );
  });

  it("accepts a valid quickstart status and treats a missing session as absent", async () => {
    const sessionId = "123e4567-e89b-42d3-a456-426614174000";
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(quickstartStatus(sessionId)),
          { headers: { "content-type": "application/json" }, status: 200 },
        ),
      )
      .mockResolvedValueOnce(new Response("", { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchQuickstartStatus(sessionId)).resolves.toEqual(
      quickstartStatus(sessionId),
    );
    await expect(fetchQuickstartStatus(sessionId)).resolves.toBeNull();
  });

  it("rejects untrusted quickstart status fields before rendering them", async () => {
    const sessionId = "123e4567-e89b-42d3-a456-426614174000";
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...quickstartStatus(sessionId),
            tunnelUiUrl: "http://localhost:4040/?runtime_key=secret",
          }),
          { headers: { "content-type": "application/json" }, status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...quickstartStatus(sessionId),
            setupStage: "unexpected_stage",
          }),
          { headers: { "content-type": "application/json" }, status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...quickstartStatus(sessionId),
            setupDetails: {
              ...quickstartStatus(sessionId).setupDetails,
              diagnostic: "arbitrary subprocess output",
            },
          }),
          { headers: { "content-type": "application/json" }, status: 200 },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchQuickstartStatus(sessionId)).rejects.toThrow(
      "unsafe tunnel UI URL",
    );
    await expect(fetchQuickstartStatus(sessionId)).rejects.toThrow(
      "Quickstart status is invalid",
    );
    await expect(fetchQuickstartStatus(sessionId)).rejects.toThrow(
      "Quickstart setup details are invalid",
    );
  });
});

function quickstartStatus(sessionId: string) {
  return {
    approvalTimeoutMs: 300_000,
    checks: [
      { id: "gateway", state: "pass" as const },
      { id: "tunnel_readiness", state: "pass" as const },
    ],
    journey: "chatgpt" as const,
    schemaVersion: "actionproxy.quickstart.v1",
    sessionId,
    setupDetails: {
      composeVersion: "2.35.1",
      dockerVersion: "28.1.1",
      nodeVersion: "24.11.0",
      port: 18787,
      projectName: "actionproxy-first-run-0123456789",
      runtimeKeyExcludedFromDocker: true,
    },
    setupStage: "tunnel_ready" as const,
    startedAt: "2026-08-02T08:00:00.000Z",
    tunnelUiUrl: "http://127.0.0.1:4040",
    updatedAt: "2026-08-02T08:00:01.000Z",
  };
}
