import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApprovalRecord, DashboardData, ToolCallRecord } from "../types";
import { Dashboard } from "./Dashboard";

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  window.location.hash = "#/";
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("fixed Community dashboard", () => {
  it("exposes only the seven Community surfaces and a real not-found route", async () => {
    const { rerender } = render(
      <Dashboard data={data} loading={false} onRefresh={vi.fn()} />,
    );
    const nav = screen.getByRole("navigation", { name: "Admin view" });

    expect(within(nav).getAllByRole("link")).toHaveLength(7);
    expect(
      within(nav).queryByRole("link", { name: /agents/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Run the lifecycle" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Connect an agent or host" }),
    ).toBeInTheDocument();
    const hardening = screen
      .getByRole("heading", { name: "Harden self-hosting" })
      .closest("section");
    expect(hardening).not.toBeNull();
    expect(
      within(hardening!).getByRole("link", { name: /Durable storage/ }),
    ).toBeInTheDocument();
    expect(
      within(hardening!).getByRole("link", { name: /^Authentication/ }),
    ).toBeInTheDocument();
    expect(
      within(hardening!).getByRole("link", { name: /Approval channels/ }),
    ).toBeInTheDocument();
    expect(
      within(hardening!).getByRole("link", { name: /Audit verification/ }),
    ).toBeInTheDocument();

    window.location.hash = "#/agents";
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    rerender(<Dashboard data={data} loading={false} onRefresh={vi.fn()} />);

    expect(
      await screen.findByRole("heading", { name: "Page not found" }),
    ).toBeInTheDocument();
    expect(document.querySelector(".not-found-panel p")).toHaveTextContent(
      "The Community console has no #/agents view.",
    );
  });

  it("starts with a focused local journey and lets the user choose ChatGPT", async () => {
    const user = userEvent.setup();
    window.location.hash = "#/demo";
    render(<Dashboard data={data} loading={false} onRefresh={vi.fn()} />);

    expect(
      screen.getByRole("heading", {
        name: "See ActionProxy control a tool call",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Local lifecycle proof" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Connect ChatGPT" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /Run the local proof/ }),
    ).toHaveAttribute("href", "#/demo?journey=local");

    await user.click(screen.getByRole("link", { name: /Connect ChatGPT/ }));
    const tunnel = await screen.findByRole("heading", {
      name: "Connect ChatGPT",
    });
    const tunnelPanel = tunnel.closest("section");
    expect(tunnelPanel).not.toBeNull();
    expect(
      screen.queryByRole("heading", { name: "Local lifecycle proof" }),
    ).not.toBeInTheDocument();
    expect(tunnelPanel).toHaveTextContent("./actionproxy chatgpt");
    expect(tunnelPanel).toHaveTextContent("Setup not checked");
    expect(tunnelPanel).toHaveTextContent(
      "Installation happens only after you choose I in Terminal or explicitly run the local install command.",
    );
    expect(tunnelPanel).toHaveTextContent(
      "This browser cannot install software or start processes",
    );
    expect(tunnelPanel).toHaveTextContent("./actionproxy doctor --chatgpt");
    expect(tunnelPanel).toHaveTextContent(
      "performs no ActionProxy state mutation or download",
    );
    expect(tunnelPanel).toHaveTextContent("./actionproxy tunnel-client remove");
    expect(
      within(tunnelPanel!).getByRole("button", {
        name: "Copy allowed search prompt",
      }),
    ).toBeDisabled();
    expect(
      within(tunnelPanel!)
        .getByRole("list", {
          name: "ChatGPT Quickstart progress",
        })
        .querySelector('[aria-current="step"]'),
    ).toHaveTextContent("Local gateway");
    await user.click(
      within(tunnelPanel!).getByText(
        "Access requirements and exact mock tools",
      ),
    );
    expect(
      within(tunnelPanel!).getByRole("heading", {
        name: "Confirm access first",
      }),
    ).toBeInTheDocument();
    expect(tunnelPanel).toHaveTextContent(
      "ChatGPT workspace access and OpenAI Platform tunnel permissions are separate",
    );
    expect(tunnelPanel).toHaveTextContent("target ChatGPT workspace");
    expect(
      within(tunnelPanel!).getByRole("heading", {
        name: "Exactly three mock tools",
      }),
    ).toBeInTheDocument();
    for (const tool of [
      "docs.search",
      "gmail.send_email",
      "dangerous.delete_customer",
    ]) {
      expect(within(tunnelPanel!).getByText(tool)).toBeInTheDocument();
    }
    expect(
      within(tunnelPanel!).getByRole("link", {
        name: /ChatGPT app settings/,
      }),
    ).toHaveAttribute("href", "https://chatgpt.com/plugins");
    expect(
      within(tunnelPanel!).getByRole("link", {
        name: /Latest public tunnel-client release/,
      }),
    ).toHaveAttribute(
      "href",
      "https://github.com/openai/tunnel-client/releases/latest",
    );
    await user.click(within(tunnelPanel!).getByText("Manual tunnel setup"));
    expect(tunnelPanel).toHaveTextContent(
      "prefer to install tunnel-client yourself",
    );
    expect(tunnelPanel).toHaveTextContent(
      "External setup links reviewed 2026-08-03.",
    );
    expect(
      within(tunnelPanel!).queryByLabelText(/runtime key/i),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: /manual mcp action catalog/i }),
    ).not.toBeInTheDocument();
  });

  it("drops a local companion session when switching to the ChatGPT journey", async () => {
    const user = userEvent.setup();
    const sessionId = "123e4567-e89b-42d3-a456-426614174000";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({
          approvalTimeoutMs: 300_000,
          checks: [
            { id: "gateway", state: "pass" },
            { id: "storage", state: "pass" },
          ],
          journey: "local",
          schemaVersion: "actionproxy.quickstart.v1",
          sessionId,
          setupStage: "gateway_ready",
          startedAt: "2026-08-02T08:00:00.000Z",
          updatedAt: "2026-08-02T08:00:01.000Z",
        }),
      ),
    );
    window.location.hash = `#/demo?journey=local&session=${sessionId}`;
    render(<Dashboard data={data} loading={false} onRefresh={vi.fn()} />);

    expect(
      screen.getByRole("link", { name: /Run the local proof/ }),
    ).toHaveAttribute("href", `#/demo?journey=local&session=${sessionId}`);
    const chatGptLink = screen.getByRole("link", {
      name: /Connect ChatGPT/,
    });
    expect(chatGptLink).toHaveAttribute("href", "#/demo?journey=chatgpt");
    await user.click(chatGptLink);

    expect(window.location.hash).toBe("#/demo?journey=chatgpt");
    const tunnelPanel = (
      await screen.findByRole("heading", { name: "Connect ChatGPT" })
    ).closest("section");
    expect(tunnelPanel).toHaveTextContent("./actionproxy chatgpt");
    expect(tunnelPanel).toHaveTextContent("Setup not checked");
  });

  it("rejects a mismatched local status on a manual ChatGPT deep link", async () => {
    const sessionId = "123e4567-e89b-42d3-a456-426614174000";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({
          approvalTimeoutMs: 300_000,
          checks: [{ id: "gateway", state: "pass" }],
          journey: "local",
          schemaVersion: "actionproxy.quickstart.v1",
          sessionId,
          setupStage: "gateway_ready",
          startedAt: "2026-08-02T08:00:00.000Z",
          updatedAt: "2026-08-02T08:00:01.000Z",
        }),
      ),
    );
    window.location.hash = `#/demo?journey=chatgpt&session=${sessionId}`;
    render(<Dashboard data={data} loading={false} onRefresh={vi.fn()} />);

    expect(
      await screen.findByText(/belongs to a different Quickstart journey/u),
    ).toBeInTheDocument();
    expect(screen.getAllByText("./actionproxy chatgpt").length).toBeGreaterThan(
      0,
    );
    expect(
      screen.queryByRole("heading", { name: "Secure tunnel ready" }),
    ).not.toBeInTheDocument();
  });

  it("uses companion status to scope a deep-linked ChatGPT proof session", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const sessionId = "123e4567-e89b-42d3-a456-426614174000";
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            approvalTimeoutMs: 300_000,
            checks: [
              { id: "gateway", state: "pass" },
              { id: "tunnel_readiness", state: "pass" },
            ],
            journey: "chatgpt",
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
            setupStage: "tunnel_ready",
            startedAt: "2026-08-02T08:00:00.000Z",
            tunnelUiUrl: "http://127.0.0.1:4040",
            updatedAt: "2026-08-02T08:00:01.000Z",
          }),
          { headers: { "content-type": "application/json" }, status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    window.location.hash = `#/demo?journey=chatgpt&session=${sessionId}`;
    render(
      <Dashboard
        data={{ ...data, toolCalls: oldTunnelCalls }}
        loading={false}
        onRefresh={vi.fn()}
      />,
    );

    expect(
      await screen.findByRole("heading", {
        name: "Secure tunnel ready",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Secure tunnel ready" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("ChatGPT tool calls").closest("li"),
    ).toHaveAttribute("aria-current", "step");
    expect(screen.getByText("0/3 complete")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy allowed search prompt" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", {
        name: "Copy approval-required email prompt",
      }),
    ).toBeDisabled();
    expect(
      screen.queryByText(/Use ActionProxy to send a demo email/u),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy denied deletion prompt" }),
    ).toBeDisabled();
    await user.click(screen.getByText("Setup details"));
    expect(screen.getByText("actionproxy-first-run-0123456789")).toBeVisible();
    expect(screen.getByText("18787")).toBeVisible();
    await user.click(
      screen.getByRole("button", { name: "Copy allowed search prompt" }),
    );
    expect(screen.getByText("Listening for docs.search")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      `/v1/demo/quickstart/status/${sessionId}`,
      expect.any(Object),
    );
  });

  it("keeps official access help visible while the terminal configures the tunnel", async () => {
    const sessionId = "423e4567-e89b-42d3-a456-426614174000";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({
          approvalTimeoutMs: 300_000,
          checks: [
            { id: "gateway", state: "pass" },
            { id: "tunnel_client", state: "pass" },
            { id: "tunnel_doctor", state: "running" },
          ],
          journey: "chatgpt",
          schemaVersion: "actionproxy.quickstart.v1",
          sessionId,
          setupDetails: {
            composeVersion: "2.35.1",
            dockerVersion: "28.1.1",
            nodeVersion: "24.11.0",
            port: 18787,
            projectName: "actionproxy-first-run-0123456789",
          },
          setupStage: "tunnel_checking",
          startedAt: "2026-08-02T08:00:00.000Z",
          updatedAt: "2026-08-02T08:00:01.000Z",
        }),
      ),
    );
    window.location.hash = `#/demo?journey=chatgpt&session=${sessionId}`;

    render(<Dashboard data={data} loading={false} onRefresh={vi.fn()} />);

    const support = (
      await screen.findByRole("heading", {
        name: "Finish secure-tunnel setup in Terminal",
      })
    ).closest<HTMLElement>(".chatgpt-setup-support");
    expect(support).not.toBeNull();
    expect(support).toHaveTextContent(
      "guides tunnel access, explicit-consent installation and rechecking",
    );
    expect(support).toHaveTextContent(
      "never asks for the tunnel ID or runtime key",
    );
    expect(support).toHaveTextContent(
      "Installation happens only after you choose I in Terminal or explicitly run the local install command.",
    );
    expect(support).toHaveTextContent(
      "This browser cannot install software or start processes",
    );
    expect(support).toHaveTextContent("./actionproxy doctor --chatgpt");
    expect(support).toHaveTextContent("remains read-only");
    expect(support).toHaveTextContent("./actionproxy tunnel-client remove");
    expect(support).toHaveTextContent("Tunnels Read + Use");
    expect(
      within(support!).getByRole("link", { name: /Platform tunnel settings/i }),
    ).toHaveAttribute(
      "href",
      "https://platform.openai.com/settings/organization/tunnels",
    );
    expect(
      within(support!).getByRole("link", { name: /Developer-mode guidance/i }),
    ).toBeInTheDocument();
    expect(
      within(support!).getByRole("button", { name: "Copy admin request" }),
    ).toBeEnabled();
    expect(
      within(support!).queryByLabelText(/runtime key/i),
    ).not.toBeInTheDocument();
  });

  it.each([
    [
      "gateway_ready",
      "Continue secure-tunnel setup",
      "The previous launcher paused before starting the secure tunnel.",
    ],
    [
      "tunnel_stopped",
      "Reconnect secure tunnel",
      "The secure tunnel is no longer connected.",
    ],
    [
      "failed",
      "Retry secure-tunnel setup",
      "The launcher reported a setup failure and has stopped.",
    ],
  ] as const)(
    "offers an exact terminal recovery when ChatGPT setup is %s",
    async (setupStage, heading, explanation) => {
      const sessionId = "523e4567-e89b-42d3-a456-426614174000";
      vi.stubGlobal(
        "fetch",
        vi.fn(async () =>
          jsonResponse({
            approvalTimeoutMs: 300_000,
            checks: [
              { id: "gateway", state: "pass" },
              {
                id: "tunnel_readiness",
                remediationCode: "tunnel_disconnected",
                state: setupStage === "failed" ? "fail" : "action_required",
              },
            ],
            journey: "chatgpt",
            schemaVersion: "actionproxy.quickstart.v1",
            sessionId,
            setupDetails: {
              composeVersion: "2.35.1",
              dockerVersion: "28.1.1",
              nodeVersion: "24.11.0",
              port: 18787,
              projectName: "actionproxy-first-run-0123456789",
            },
            setupStage,
            startedAt: "2026-08-02T08:00:00.000Z",
            updatedAt: "2026-08-02T08:00:01.000Z",
          }),
        ),
      );
      window.location.hash = `#/demo?journey=chatgpt&session=${sessionId}`;

      render(<Dashboard data={data} loading={false} onRefresh={vi.fn()} />);

      const support = (
        await screen.findByRole("heading", { name: heading })
      ).closest<HTMLElement>(".chatgpt-setup-support");
      expect(support).not.toBeNull();
      expect(support).toHaveTextContent(explanation);
      expect(support).toHaveTextContent("./actionproxy chatgpt");
      expect(support).toHaveTextContent(
        "local gateway and audit evidence remain available",
      );
      expect(support).not.toHaveTextContent("current action");
    },
  );

  it("shows live companion readiness for a deep-linked local proof", async () => {
    const sessionId = "323e4567-e89b-42d3-a456-426614174000";
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        approvalTimeoutMs: 300_000,
        checks: [{ id: "gateway", state: "pass" }],
        journey: "local",
        schemaVersion: "actionproxy.quickstart.v1",
        sessionId,
        setupStage: "gateway_ready",
        startedAt: "2026-08-02T08:00:00.000Z",
        updatedAt: "2026-08-02T08:00:01.000Z",
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    window.location.hash = `#/demo?journey=local&session=${sessionId}`;

    render(<Dashboard data={data} loading={false} onRefresh={vi.fn()} />);

    expect(
      await screen.findByRole("heading", { name: "Local gateway ready" }),
    ).toBeInTheDocument();
    expect(screen.getByText(`Session ${sessionId}`)).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Local lifecycle proof" }),
    ).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      `/v1/demo/quickstart/status/${sessionId}`,
      expect.any(Object),
    );
  });

  it("unlocks verified ChatGPT proof only after exact audit invariants pass", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const sessionId = "223e4567-e89b-42d3-a456-426614174000";
    const sessionStartedAt = new Date(Date.now() - 60_000);
    const proofCalls = [
      oldTunnelCall("docs.search", "executed", "allow", 0),
      oldTunnelCall("gmail.send_email", "rejected", "require_approval", 1),
      oldTunnelCall("dangerous.delete_customer", "blocked", "deny", 2),
    ].map((call, index) => ({
      ...call,
      createdAt: new Date(
        sessionStartedAt.getTime() + (index + 1) * 1_000,
      ).toISOString(),
      id: `proof_call_${index}`,
      metadata: {
        ...call.metadata,
        actionproxyQuickstartSessionId: sessionId,
      },
      updatedAt: new Date(
        sessionStartedAt.getTime() + (index + 1) * 1_000,
      ).toISOString(),
    }));
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/v1/audit/verify")
        return jsonResponse({ checked: 24, errors: [], valid: true });
      return jsonResponse({
        approvalTimeoutMs: 300_000,
        checks: [
          { id: "gateway", state: "pass" },
          { id: "tunnel_readiness", state: "pass" },
        ],
        journey: "chatgpt",
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
        setupStage: "tunnel_ready",
        startedAt: sessionStartedAt.toISOString(),
        tunnelUiUrl: "http://127.0.0.1:4040",
        updatedAt: new Date().toISOString(),
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    window.location.hash = `#/demo?journey=chatgpt&session=${sessionId}`;
    render(
      <Dashboard
        data={{
          ...data,
          auditEvents: [
            auditEvent("audit_search_policy", "policy.allow", "proof_call_0"),
            auditEvent("audit_search", "tool_call.executed", "proof_call_0"),
            auditEvent(
              "audit_email_policy",
              "policy.require_approval",
              "proof_call_1",
            ),
            auditEvent(
              "audit_email_created",
              "approval.created",
              "proof_call_1",
            ),
            auditEvent("audit_email", "approval.rejected", "proof_call_1"),
            auditEvent("audit_delete", "policy.deny", "proof_call_2"),
          ],
          toolCalls: proofCalls,
        }}
        loading={false}
        onRefresh={vi.fn()}
      />,
    );

    expect(
      await screen.findByRole("heading", {
        name: "You governed three Quickstart MCP tool calls from your Mac",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Email rejected by you; no execution occurred."),
    ).toBeInTheDocument();
    expect(screen.getByText("./actionproxy stop")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy sanitized proof" }),
    ).toBeEnabled();
    expect(
      screen.getByText(/ActionProxy verified the local MCP path/i),
    ).toHaveTextContent("Confirm the upstream ChatGPT result");
    expect(
      screen.getByText(/ChatGPT may show its own confirmation/u),
    ).toHaveTextContent("separate from the ActionProxy policy decision");
    await user.click(
      screen.getByRole("button", { name: "Copy sanitized proof" }),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("ActionProxy Quickstart MCP proof (local)"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("Confirm the upstream ChatGPT result"),
    );
    await user.click(screen.getByRole("button", { name: "Start a new proof" }));
    expect(
      screen.queryByRole("heading", {
        name: "You governed three Quickstart MCP tool calls from your Mac",
      }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("0/3 complete")).toBeInTheDocument();
  });

  it("keeps a paused effect prominent and returns its reviewer to Quickstart", () => {
    const originalTitle = document.title;
    const sessionId = "123e4567-e89b-42d3-a456-426614174000";
    const pendingData: DashboardData = {
      ...data,
      pendingApprovals: [
        {
          createdAt: "2026-08-02T08:00:01.000Z",
          id: "approval_email",
          originalInput: { to: "customer@example.com" },
          requestedBy: "local-demo@example.com",
          status: "pending",
          toolCallId: "call_email",
          updatedAt: "2026-08-02T08:00:01.000Z",
        },
      ],
      toolCalls: [
        {
          agentId: "customer-support-agent",
          createdAt: "2026-08-02T08:00:01.000Z",
          decision: "require_approval",
          id: "call_email",
          input: { to: "customer@example.com" },
          metadata: {
            demo: "customer-support-agent",
            demoQuickstartGuided: true,
            demoQuickstartSessionId: sessionId,
          },
          reason: "Propose a mock customer email",
          requestedBy: "local-demo@example.com",
          status: "pending_approval",
          toolName: "gmail.send_email",
          updatedAt: "2026-08-02T08:00:01.000Z",
        },
      ],
    };
    window.location.hash = "#/audit";
    const { unmount } = render(
      <Dashboard data={pendingData} loading={false} onRefresh={vi.fn()} />,
    );

    const message = screen.getByText("Action paused. Nothing has executed.");
    const banner = message.closest(".quickstart-pending-banner");
    expect(banner).not.toBeNull();
    expect(
      within(banner as HTMLElement).getByRole("link", {
        name: "Review approval",
      }),
    ).toHaveAttribute(
      "href",
      "#/approvals/approval_email?returnTo=%23%2Fdemo%3Fjourney%3Dlocal%26session%3D123e4567-e89b-42d3-a456-426614174000%26guided%3D1",
    );
    expect(document.title).toBe("Approval waiting · ActionProxy");

    unmount();
    expect(document.title).toBe(originalTitle);
  });

  it("returns a trusted tunnel approval to its metadata-bound session from another route", () => {
    const sessionId = "423e4567-e89b-42d3-a456-426614174000";
    const approval: ApprovalRecord = {
      createdAt: "2026-08-02T08:00:01.000Z",
      id: "tunnel_approval",
      originalInput: { to: "customer@example.com" },
      requestedBy: "chatgpt-tunnel-demo",
      status: "pending",
      toolCallId: "tunnel_email",
      updatedAt: "2026-08-02T08:00:01.000Z",
    };
    const toolCall: ToolCallRecord = {
      agentId: "actionproxy-chatgpt-tunnel-demo",
      createdAt: "2026-08-02T08:00:01.000Z",
      decision: "require_approval",
      id: "tunnel_email",
      input: { to: "customer@example.com" },
      metadata: {
        actionproxyQuickstartOrigin: "secure_mcp_tunnel",
        actionproxyQuickstartSessionId: sessionId,
      },
      reason: "Propose a mock customer email",
      requestedBy: "chatgpt-tunnel-demo",
      status: "pending_approval",
      toolName: "gmail.send_email",
      updatedAt: "2026-08-02T08:00:01.000Z",
    };
    window.location.hash = "#/audit";
    const { rerender } = render(
      <Dashboard
        data={{
          ...data,
          pendingApprovals: [approval],
          toolCalls: [toolCall],
        }}
        loading={false}
        onRefresh={vi.fn()}
      />,
    );

    expect(
      screen.getByRole("link", { name: "Review approval" }),
    ).toHaveAttribute(
      "href",
      `#/approvals/tunnel_approval?returnTo=%23%2Fdemo%3Fjourney%3Dchatgpt%26session%3D${sessionId}`,
    );

    rerender(
      <Dashboard
        data={{
          ...data,
          pendingApprovals: [approval],
          toolCalls: [
            {
              ...toolCall,
              metadata: {
                ...toolCall.metadata,
                actionproxyQuickstartSessionId: "invalid",
              },
            },
          ],
        }}
        loading={false}
        onRefresh={vi.fn()}
      />,
    );
    expect(
      screen.getByRole("link", { name: "Review approval" }),
    ).toHaveAttribute("href", "#/approvals/tunnel_approval");
  });

  it("renders a human-first email review and blocks stale decisions", async () => {
    const user = userEvent.setup();
    let record = emailApprovalRecord();
    let reviewLoads = 0;
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/review")) {
          reviewLoads += 1;
          return jsonResponse(
            emailApprovalReview(record, reviewLoads === 1 ? "stale" : "fresh"),
          );
        }
        if (init?.method === "POST" && url.endsWith("/reject")) {
          record = {
            approval: { ...record.approval, status: "rejected" },
            toolCall: { ...record.toolCall, status: "rejected" },
          };
          return jsonResponse(record);
        }
        if (url === "/v1/approvals/approval_email") {
          return jsonResponse(record);
        }
        throw new Error(`Unexpected request: ${url}`);
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    window.location.hash =
      "#/approvals/approval_email?returnTo=%23%2Fdemo%3Fjourney%3Dlocal";
    render(
      <Dashboard
        data={emailApprovalDashboardData()}
        loading={false}
        onRefresh={vi.fn()}
      />,
    );

    expect(
      await screen.findByRole("heading", {
        name: "Review the proposed email",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("customer@example.com")).toBeInTheDocument();
    expect(screen.getByText("Refund update")).toBeInTheDocument();
    expect(screen.getByText("Your request is ready.")).toBeInTheDocument();
    expect(
      within(screen.getByLabelText("Proposal source chain")).getByText(
        "ActionProxy",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Nothing has executed yet.", { exact: true }),
    ).toBeInTheDocument();
    expect(
      screen
        .getByText("Technical details and integrity evidence")
        .closest("details"),
    ).not.toHaveAttribute("open");
    expect(
      screen.getByRole("button", { name: "Approve exact proposal" }),
    ).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Refresh review" }));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Approve exact proposal" }),
      ).toBeEnabled(),
    );
    await user.click(screen.getByRole("button", { name: "Reject" }));
    expect(
      fetchMock.mock.calls.filter((call) => call[1]?.method === "POST"),
    ).toHaveLength(0);
    const reason = screen.getByLabelText("Rejection reason");
    expect(reason).toHaveFocus();
    await user.type(reason, "The message needs another review.");
    await user.click(screen.getByRole("button", { name: "Confirm rejection" }));

    expect(
      await screen.findByText("Rejected. Nothing was sent."),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Return now" })).toHaveAttribute(
      "href",
      "#/demo?journey=local",
    );
  });

  it("describes only the locally verified MCP provenance while an approved tunnel call finishes", async () => {
    const sessionId = "523e4567-e89b-42d3-a456-426614174000";
    const base = emailApprovalRecord();
    const record = {
      approval: { ...base.approval, status: "approved" as const },
      toolCall: {
        ...base.toolCall,
        agentId: "actionproxy-chatgpt-tunnel-demo",
        metadata: {
          actionproxyQuickstartOrigin: "secure_mcp_tunnel",
          actionproxyQuickstartSessionId: sessionId,
        },
        requestedBy: "chatgpt-tunnel-demo",
        status: "authorized" as const,
      },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/review"))
          return jsonResponse(emailApprovalReview(record, "fresh"));
        if (url === "/v1/approvals/approval_email") return jsonResponse(record);
        throw new Error(`Unexpected request: ${url}`);
      }),
    );
    window.location.hash = "#/approvals/approval_email";

    render(
      <Dashboard
        data={{ ...data, toolCalls: [record.toolCall] }}
        loading={false}
        onRefresh={vi.fn()}
      />,
    );

    expect(
      await screen.findByText(
        "Approved; the MCP client is finishing the mock call",
      ),
    ).toBeInTheDocument();
    const chain = screen.getByLabelText("Proposal source chain");
    expect(
      within(chain).getByText("Quickstart MCP request"),
    ).toBeInTheDocument();
    expect(within(chain).getByText("ActionProxy")).toBeInTheDocument();
    expect(within(chain).queryByText("ChatGPT")).not.toBeInTheDocument();
    expect(
      within(chain).queryByText("Secure MCP Tunnel"),
    ).not.toBeInTheDocument();
  });

  it.each([
    ["a javascript URL", "javascript:alert(1)"],
    ["an external URL", "https://evil.example/#/demo?journey=local"],
    ["an invalid session", "#/demo?journey=local&session=bad"],
    [
      "an encoded query injection",
      "#/demo?journey=local%26next%3Djavascript%3Aalert(1)",
    ],
    ["malformed encoding", "#/demo?journey=%E0%A4%A"],
    ["duplicate journey values", "#/demo?journey=local&journey=chatgpt"],
  ])(
    "ignores %s supplied as an approval return target",
    async (_label, returnTo) => {
      const base = emailApprovalRecord();
      const record = {
        approval: { ...base.approval, status: "rejected" as const },
        toolCall: { ...base.toolCall, status: "rejected" as const },
      };
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.endsWith("/review"))
            return jsonResponse(emailApprovalReview(record, "fresh"));
          if (url === "/v1/approvals/approval_email")
            return jsonResponse(record);
          throw new Error(`Unexpected request: ${url}`);
        }),
      );
      window.location.hash = `#/approvals/approval_email?returnTo=${encodeURIComponent(returnTo)}`;

      render(
        <Dashboard
          data={{ ...data, pendingApprovals: [], toolCalls: [record.toolCall] }}
          loading={false}
          onRefresh={vi.fn()}
        />,
      );

      expect(
        await screen.findByRole("link", { name: "Return now" }),
      ).toHaveAttribute("href", "#/demo?journey=local");
    },
  );

  it.each([
    [
      "local",
      "#/demo?guided=1&session=623e4567-e89b-42d3-a456-426614174000&journey=local",
      "#/demo?journey=local&session=623e4567-e89b-42d3-a456-426614174000&guided=1",
    ],
    [
      "chatgpt",
      "#/demo?session=723e4567-e89b-42d3-a456-426614174000&journey=chatgpt",
      "#/demo?journey=chatgpt&session=723e4567-e89b-42d3-a456-426614174000",
    ],
  ])(
    "canonically reconstructs an encoded %s approval return target",
    async (_journey, returnTo, expectedHref) => {
      const base = emailApprovalRecord();
      const record = {
        approval: { ...base.approval, status: "rejected" as const },
        toolCall: { ...base.toolCall, status: "rejected" as const },
      };
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.endsWith("/review"))
            return jsonResponse(emailApprovalReview(record, "fresh"));
          if (url === "/v1/approvals/approval_email")
            return jsonResponse(record);
          throw new Error(`Unexpected request: ${url}`);
        }),
      );
      window.location.hash = `#/approvals/approval_email?returnTo=${encodeURIComponent(returnTo)}`;

      render(
        <Dashboard
          data={{ ...data, pendingApprovals: [], toolCalls: [record.toolCall] }}
          loading={false}
          onRefresh={vi.fn()}
        />,
      );

      expect(
        await screen.findByRole("link", { name: "Return now" }),
      ).toHaveAttribute("href", expectedHref);
    },
  );

  it("shows a retry action when dashboard refresh fails", async () => {
    const user = userEvent.setup();
    const refresh = vi.fn();
    render(
      <Dashboard
        data={data}
        error="Gateway unavailable"
        loading={false}
        onRefresh={refresh}
      />,
    );

    expect(screen.getByRole("alert")).toHaveTextContent("Gateway unavailable");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("labels retained data as stale and confirms restart recovery", () => {
    const { rerender } = render(
      <Dashboard
        data={data}
        error="Gateway restarting"
        lastSuccessfulRefreshAt="2026-07-19T12:00:00.000Z"
        loading={false}
        onRefresh={vi.fn()}
        snapshotState="stale"
      />,
    );

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Showing the last successful gateway snapshot",
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Gateway restarting");

    rerender(
      <Dashboard
        data={data}
        loading={false}
        onRefresh={vi.fn()}
        snapshotState="recovered"
      />,
    );

    expect(screen.getByRole("status")).toHaveTextContent(
      "Gateway connection restored",
    );
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("preserves content-source and influence policy fields during an unrelated edit", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn().mockResolvedValue({
      json: () =>
        Promise.resolve({ policy: data.policyFile, summary: data.policy }),
      ok: true,
    });
    vi.stubGlobal("fetch", fetchMock);
    window.location.hash = "#/policy";
    render(<Dashboard data={data} loading={false} onRefresh={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Add rule" }));
    const editor = screen
      .getByRole("heading", { name: "Add policy rule" })
      .closest("form");
    expect(editor).not.toBeNull();
    await user.type(
      within(editor!).getByLabelText("Tool pattern"),
      "jira.create_issue",
    );
    await user.click(
      within(editor!).getByRole("button", { name: "Save rule" }),
    );

    const savedPolicy = JSON.parse(
      fetchMock.mock.calls[0]?.[1]?.body as string,
    );
    expect(savedPolicy.default.resultSource).toEqual({ integrity: "unknown" });
    expect(savedPolicy.tools["company.docs.search"].resultSource).toEqual({
      integrity: "organization_managed",
      sourceId: "company-docs",
    });
    expect(savedPolicy.tools["research.notes.append"].influence).toEqual({
      allowFrom: ["none", "organization_managed", "verified_publisher"],
      otherwise: "required",
    });
  });
});

const data: DashboardData = {
  auditEvents: [],
  approvers: null,
  authorizedActions: [],
  health: { ok: true, service: "actionproxy-server" },
  integrations: null,
  pendingApprovals: [],
  policy: {
    defaultRule: {
      approval: "required",
      decision: "require_approval",
      matchType: "default",
      pattern: "default",
      reason: "Unknown tools require approval.",
      resultSource: { integrity: "unknown" },
      risk: "unknown",
    },
    rules: [],
    version: 1,
  },
  policyDetector: { tools: [], unresolvedCount: 0 },
  policyFile: {
    default: {
      approval: "required",
      reason: "Unknown tools require approval.",
      resultSource: { integrity: "unknown" },
      risk: "unknown",
    },
    tools: {
      "company.docs.search": {
        approval: "never",
        reason: "Reviewed internal search.",
        resultSource: {
          integrity: "organization_managed",
          sourceId: "company-docs",
        },
        risk: "closed_world_read",
      },
      "research.notes.append": {
        approval: "never",
        influence: {
          allowFrom: ["none", "organization_managed", "verified_publisher"],
          otherwise: "required",
        },
        reason: "Append an internal research note.",
        resultSource: "none",
        risk: "low_risk_write",
      },
    },
    version: 1,
  },
  toolCalls: [],
};

const oldTunnelCalls: DashboardData["toolCalls"] = [
  oldTunnelCall("docs.search", "executed", "allow", 0),
  oldTunnelCall("gmail.send_email", "executed", "allow", 1),
  oldTunnelCall("dangerous.delete_customer", "blocked", "deny", 2),
];

function oldTunnelCall(
  toolName: string,
  status: "executed" | "blocked" | "rejected",
  decision: "allow" | "deny" | "require_approval",
  index: number,
): DashboardData["toolCalls"][number] {
  return {
    agentId: "actionproxy-chatgpt-tunnel-demo",
    createdAt: `2026-08-01T08:00:0${index}.000Z`,
    decision,
    id: `old_tunnel_call_${index}`,
    input: {},
    metadata: {
      actionproxyQuickstartOrigin: "secure_mcp_tunnel",
      actionproxyQuickstartSessionId: "old-quickstart-session",
      mcpServer: "chatgpt-tunnel-demo",
    },
    reason: "Old tunnel fixture",
    requestedBy: "chatgpt-tunnel-demo",
    status,
    toolName,
    updatedAt: `2026-08-01T08:00:0${index}.000Z`,
  };
}

function auditEvent(id: string, type: string, toolCallId: string) {
  return {
    data: {},
    id,
    timestamp: "2026-08-03T08:00:04.000Z",
    toolCallId,
    type,
  };
}

function emailApprovalDashboardData(): DashboardData {
  const record = emailApprovalRecord();
  return {
    ...data,
    pendingApprovals: [record.approval],
    toolCalls: [record.toolCall],
  };
}

function emailApprovalRecord(): {
  approval: ApprovalRecord;
  toolCall: ToolCallRecord;
} {
  return {
    approval: {
      createdAt: "2026-08-02T08:00:01.000Z",
      id: "approval_email",
      originalInput: {
        body: "Your request is ready.",
        subject: "Refund update",
        to: "customer@example.com",
      },
      originalInputHash: "hash_input",
      requestedBy: "demo-agent@example.com",
      status: "pending",
      toolCallId: "call_email",
      updatedAt: "2026-08-02T08:00:01.000Z",
    },
    toolCall: {
      agentId: "customer-support-demo-agent",
      createdAt: "2026-08-02T08:00:01.000Z",
      decision: "require_approval",
      id: "call_email",
      input: {
        body: "Your request is ready.",
        subject: "Refund update",
        to: "customer@example.com",
      },
      inputHash: "hash_input",
      metadata: { demo: "customer-support-agent" },
      policyReason: "External email requires a human decision.",
      reason: "Draft the requested refund update",
      requestedBy: "demo-agent@example.com",
      risk: "external_communication",
      status: "pending_approval",
      toolName: "gmail.send_email",
      updatedAt: "2026-08-02T08:00:01.000Z",
    },
  };
}

function emailApprovalReview(
  record: ReturnType<typeof emailApprovalRecord>,
  state: "fresh" | "stale",
) {
  return {
    ...record,
    actionEnvelope: {
      actor: { id: "demo-agent@example.com", type: "user" },
      agent: {
        id: "customer-support-demo-agent",
        name: "Customer-support demo agent",
      },
      context: { reason: record.toolCall.reason },
      envelopeHash: "hash_envelope",
      executionMode: "local_mock",
      input: record.approval.originalInput,
      inputHash: "hash_input",
      operation: { kind: "external_send", name: "gmail.send_email" },
      protocol: "actionproxy_http",
      source: { name: "Customer-support demo agent", type: "agent" },
      toolName: "gmail.send_email",
      version: "actionproxy.action.v1",
    },
    freshness: {
      expiresAt: "2026-08-02T08:05:00.000Z",
      renderedAt: "2026-08-02T08:01:00.000Z",
      state,
      warnings:
        state === "stale"
          ? [
              {
                code: "policy_changed",
                message: "Policy changed after this review was rendered.",
                severity: "stale",
              },
            ]
          : [],
    },
    policy: {
      decision: "require_approval",
      reason: "External email requires a human decision.",
      risk: "external_communication",
    },
    proposerRationaleTrust: "untrusted",
    reviewHash: "hash_review",
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
    status: 200,
  });
}
