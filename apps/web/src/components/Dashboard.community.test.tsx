import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DashboardData } from "../types";
import { Dashboard } from "./Dashboard";

afterEach(() => {
  cleanup();
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

  it("puts the zero-credential lifecycle before the optional ChatGPT tunnel", async () => {
    window.location.hash = "#/demo";
    render(<Dashboard data={data} loading={false} onRefresh={vi.fn()} />);

    const demo = screen.getByRole("heading", { name: "Agent demo" });
    const tunnel = screen.getByRole("heading", { name: "Connect ChatGPT" });
    expect(
      demo.compareDocumentPosition(tunnel) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      screen.queryByRole("heading", { name: /manual mcp action catalog/i }),
    ).not.toBeInTheDocument();
  });

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
