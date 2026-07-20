import { afterEach, describe, expect, it, vi } from "vitest";
import {
  actionProxyApiTokenStorageKey,
  clearApiToken,
  currentApiToken,
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
});
