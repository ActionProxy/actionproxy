import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentDemoPanel } from "./AgentDemoPanel";
import type { DashboardData, ToolCallRecord } from "../types";
import { submitToolCall } from "../lib/actionproxy-client";

vi.mock("../lib/actionproxy-client", async () => {
  const actual = await vi.importActual<
    typeof import("../lib/actionproxy-client")
  >("../lib/actionproxy-client");
  return {
    ...actual,
    submitToolCall: vi.fn(),
  };
});

const emptyData: DashboardData = {
  auditEvents: [],
  approvers: null,
  authorizedActions: [],
  health: { ok: true, service: "actionproxy-server" },
  integrations: null,
  pendingApprovals: [],
  policy: null,
  policyDetector: null,
  policyFile: null,
  toolCalls: [],
};

const executedDocsCall: ToolCallRecord = {
  agentId: "customer-support-demo-agent",
  createdAt: "2026-06-18T09:00:00.000Z",
  decision: "allow",
  id: "toolcall_docs",
  input: { query: "refund policy for delayed shipment" },
  metadata: { demo: "customer-support-agent", visualStep: "search-docs" },
  reason: "Find policy context for a customer support reply",
  requestedBy: "demo-agent@example.com",
  risk: "read_only",
  status: "executed",
  toolName: "docs.search",
  updatedAt: "2026-06-18T09:00:00.000Z",
};

const approvedEmailData: DashboardData = {
  ...emptyData,
  toolCalls: [
    executedDocsCall,
    {
      agentId: "customer-support-demo-agent",
      createdAt: "2026-06-18T10:00:00.000Z",
      decision: "require_approval",
      id: "toolcall_email",
      input: { to: "customer@example.com" },
      metadata: { demo: "customer-support-agent", visualStep: "send-email" },
      reason: "Send customer response drafted by the support agent",
      requestedBy: "demo-agent@example.com",
      risk: "external_communication",
      status: "executed",
      toolName: "gmail.send_email",
      updatedAt: "2026-06-18T10:01:00.000Z",
    },
  ],
};

const executedDocsData: DashboardData = {
  ...emptyData,
  toolCalls: [executedDocsCall],
};

const rejectedEmailData: DashboardData = {
  ...emptyData,
  toolCalls: [
    executedDocsCall,
    {
      agentId: "customer-support-demo-agent",
      createdAt: "2026-06-18T10:00:00.000Z",
      decision: "require_approval",
      id: "toolcall_email",
      input: { to: "customer@example.com" },
      metadata: { demo: "customer-support-agent", visualStep: "send-email" },
      reason: "Send customer response drafted by the support agent",
      requestedBy: "demo-agent@example.com",
      risk: "external_communication",
      status: "rejected",
      toolName: "gmail.send_email",
      updatedAt: "2026-06-18T10:01:00.000Z",
    },
  ],
};

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.clearAllMocks();
});

describe("AgentDemoPanel", () => {
  it("renders the customer-support demo agent steps", () => {
    render(<AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />);

    expect(
      screen.getByRole("heading", { name: "Local lifecycle proof" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Search support policy")).toBeInTheDocument();
    expect(screen.getByText("Propose customer email")).toBeInTheDocument();
    expect(
      screen.getByText("Attempt unsafe customer deletion"),
    ).toBeInTheDocument();
  });

  it("keeps the step-by-step control behind a disclosure", async () => {
    const user = userEvent.setup();
    render(<AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />);

    const controls = screen.getByText("Run step by step").closest("details");
    expect(controls).not.toHaveAttribute("open");
    await user.click(screen.getByText("Run step by step"));
    expect(
      within(controls as HTMLElement).getByRole("button", {
        name: "Run next step",
      }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Run guided proof" }),
    ).toBeEnabled();
  });

  it("runs the next agent step through ActionProxy and visualizes the result", async () => {
    const user = userEvent.setup();
    const onRefresh = vi.fn();
    vi.mocked(submitToolCall).mockResolvedValue({
      decision: "allow",
      id: "toolcall_docs",
      result: { ok: true },
      status: "executed",
    });

    render(<AgentDemoPanel data={emptyData} onRefresh={onRefresh} />);

    await user.click(screen.getByText("Run step by step"));
    await user.click(screen.getByRole("button", { name: "Run next step" }));

    expect(submitToolCall).toHaveBeenCalledWith(
      expect.objectContaining({
        agentId: "customer-support-demo-agent",
        requestedBy: "demo-agent@example.com",
        toolName: "docs.search",
      }),
    );
    expect(onRefresh).toHaveBeenCalled();
    const firstStep = screen
      .getByText("Search support policy")
      .closest("article");
    expect(firstStep).not.toBeNull();
    expect(
      within(firstStep as HTMLElement).getByText("Complete"),
    ).toBeInTheDocument();
    expect(
      within(firstStep as HTMLElement).getByText("Gateway response"),
    ).toBeInTheDocument();
  });

  it("reconstructs stored run IDs from live gateway state after remounting", async () => {
    const user = userEvent.setup();
    vi.mocked(submitToolCall).mockResolvedValue({
      decision: "allow",
      id: "toolcall_docs",
      result: { ok: true },
      status: "executed",
    });

    const { unmount } = render(
      <AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />,
    );

    await user.click(screen.getByText("Run step by step"));
    await user.click(screen.getByRole("button", { name: "Run next step" }));
    expect(
      within(
        screen
          .getByText("Search support policy")
          .closest("article") as HTMLElement,
      ).getByText("Complete"),
    ).toBeInTheDocument();

    unmount();
    render(<AgentDemoPanel data={executedDocsData} onRefresh={vi.fn()} />);

    const firstStep = screen
      .getByText("Search support policy")
      .closest("article");
    expect(firstStep).not.toBeNull();
    await waitFor(() =>
      expect(
        within(firstStep as HTMLElement).getByText("Complete"),
      ).toBeInTheDocument(),
    );
    expect(
      within(firstStep as HTMLElement)
        .getByText("Gateway response")
        .closest("details"),
    ).not.toHaveAttribute("open");
    expect(
      JSON.parse(
        window.localStorage.getItem("actionproxy.agentDemoRuns.v1") ?? "{}",
      ),
    ).toEqual({ "search-docs": { toolCallId: "toolcall_docs" } });
  });

  it("does not let historic records or another proof namespace complete a concierge session", async () => {
    const sessionId = "323e4567-e89b-42d3-a456-426614174000";
    const storageKey = `actionproxy.agentDemoRuns.v1.${sessionId}`;
    const storedIds = {
      "delete-customer": { toolCallId: "toolcall_delete" },
      "search-docs": { toolCallId: "toolcall_docs" },
      "send-email": {
        approvalId: "approval_email",
        toolCallId: "toolcall_email",
      },
    };
    window.localStorage.setItem(
      "actionproxy.agentDemoRuns.v1",
      JSON.stringify(storedIds),
    );
    window.localStorage.setItem(
      "actionproxy.agentDemoRuns.v1.old-session",
      JSON.stringify(storedIds),
    );
    window.localStorage.setItem(storageKey, JSON.stringify(storedIds));
    const onProofStateChange = vi.fn();
    const historicData: DashboardData = {
      ...emptyData,
      toolCalls: [
        ...approvedEmailData.toolCalls,
        {
          agentId: "customer-support-demo-agent",
          createdAt: "2026-06-18T10:02:00.000Z",
          decision: "deny",
          id: "toolcall_delete",
          input: { customerId: "cus_123" },
          metadata: {
            demo: "customer-support-agent",
            visualStep: "delete-customer",
          },
          reason: "Show that destructive actions are blocked by policy",
          requestedBy: "demo-agent@example.com",
          risk: "destructive",
          status: "blocked",
          toolName: "dangerous.delete_customer",
          updatedAt: "2026-06-18T10:02:00.000Z",
        },
      ],
    };

    render(
      <AgentDemoPanel
        data={historicData}
        onProofStateChange={onProofStateChange}
        onRefresh={vi.fn()}
        sessionId={sessionId}
        sessionStartedAt="2026-08-02T08:00:00.000Z"
      />,
    );

    for (const title of [
      "Search support policy",
      "Propose customer email",
      "Attempt unsafe customer deletion",
    ]) {
      expect(within(step(title)).getByText("Ready")).toBeInTheDocument();
    }
    await waitFor(() =>
      expect(onProofStateChange).toHaveBeenLastCalledWith(false),
    );
    expect(
      window.localStorage.getItem("actionproxy.agentDemoRuns.v1"),
    ).toBeNull();
    expect(
      window.localStorage.getItem("actionproxy.agentDemoRuns.v1.old-session"),
    ).toBeNull();
    expect(JSON.parse(window.localStorage.getItem(storageKey) ?? "{}")).toEqual(
      storedIds,
    );
  });

  it("pauses the full demo when a step needs approval", async () => {
    const user = userEvent.setup();
    const sessionId = "123e4567-e89b-42d3-a456-426614174000";
    const storageKey = `actionproxy.agentDemoRuns.v1.${sessionId}`;
    vi.mocked(submitToolCall)
      .mockResolvedValueOnce({
        decision: "allow",
        id: "toolcall_docs",
        result: { ok: true },
        status: "executed",
      })
      .mockResolvedValueOnce({
        approval: { id: "approval_email", status: "pending" },
        decision: "require_approval",
        id: "toolcall_email",
        status: "pending_approval",
      });

    render(
      <AgentDemoPanel
        data={emptyData}
        onRefresh={vi.fn()}
        returnTo={`#/demo?journey=local&session=${sessionId}`}
        sessionId={sessionId}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Run guided proof" }));

    expect(submitToolCall).toHaveBeenCalledTimes(2);
    expect(submitToolCall).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        metadata: expect.objectContaining({
          demoQuickstartGuided: true,
          demoQuickstartSessionId: sessionId,
        }),
        toolName: "gmail.send_email",
      }),
    );
    expect(submitToolCall).not.toHaveBeenCalledWith(
      expect.objectContaining({ toolName: "dangerous.delete_customer" }),
    );
    expect(
      within(step("Search support policy")).getByText("Complete"),
    ).toBeInTheDocument();
    expect(
      within(step("Propose customer email")).getByText("Needs approval"),
    ).toBeInTheDocument();
    expect(
      within(step("Propose customer email")).getByText(
        "Paused as designed—no email was sent.",
      ),
    ).toBeInTheDocument();
    expect(
      within(step("Propose customer email")).getByRole("link", {
        name: "Review this approval",
      }),
    ).toHaveAttribute(
      "href",
      "#/approvals/approval_email?returnTo=%23%2Fdemo%3Fjourney%3Dlocal%26session%3D123e4567-e89b-42d3-a456-426614174000%26guided%3D1",
    );
    expect(
      within(step("Attempt unsafe customer deletion")).getByText("Ready"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Run guided proof" }),
    ).toBeDisabled();
    expect(
      window.localStorage.getItem(storageKey),
    ).not.toContain("result");
    expect(
      window.localStorage.getItem(storageKey),
    ).not.toContain("response");
    expect(
      JSON.parse(
        window.localStorage.getItem(storageKey) ?? "{}",
      ),
    ).toEqual({
      "search-docs": { toolCallId: "toolcall_docs" },
      "send-email": {
        approvalId: "approval_email",
        toolCallId: "toolcall_email",
      },
    });
    expect(
      window.localStorage.getItem("actionproxy.agentDemoAutoContinue.v1"),
    ).toBeNull();
  });

  it("automatically continues the sequence after a pending approval reaches a terminal state", async () => {
    const user = userEvent.setup();
    vi.mocked(submitToolCall)
      .mockResolvedValueOnce({
        decision: "allow",
        id: "toolcall_docs",
        result: { ok: true },
        status: "executed",
      })
      .mockResolvedValueOnce({
        approval: { id: "approval_email", status: "pending" },
        decision: "require_approval",
        id: "toolcall_email",
        status: "pending_approval",
      })
      .mockResolvedValueOnce({
        decision: "deny",
        id: "toolcall_delete",
        status: "blocked",
      });

    const { rerender } = render(
      <AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />,
    );

    await user.click(screen.getByRole("button", { name: "Run guided proof" }));
    rerender(<AgentDemoPanel data={approvedEmailData} onRefresh={vi.fn()} />);

    await waitFor(() => expect(submitToolCall).toHaveBeenCalledTimes(3));
    expect(submitToolCall).toHaveBeenLastCalledWith(
      expect.objectContaining({ toolName: "dangerous.delete_customer" }),
    );
    expect(
      within(step("Propose customer email")).getByText("Complete"),
    ).toBeInTheDocument();
    expect(
      within(step("Attempt unsafe customer deletion")).getByText("Blocked"),
    ).toBeInTheDocument();
  });

  it("automatically continues the sequence after a pending approval is rejected", async () => {
    const user = userEvent.setup();
    vi.mocked(submitToolCall)
      .mockResolvedValueOnce({
        decision: "allow",
        id: "toolcall_docs",
        result: { ok: true },
        status: "executed",
      })
      .mockResolvedValueOnce({
        approval: { id: "approval_email", status: "pending" },
        decision: "require_approval",
        id: "toolcall_email",
        status: "pending_approval",
      })
      .mockResolvedValueOnce({
        decision: "deny",
        id: "toolcall_delete",
        status: "blocked",
      });

    const { rerender } = render(
      <AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />,
    );

    await user.click(screen.getByRole("button", { name: "Run guided proof" }));
    rerender(<AgentDemoPanel data={rejectedEmailData} onRefresh={vi.fn()} />);

    await waitFor(() => expect(submitToolCall).toHaveBeenCalledTimes(3));
    expect(submitToolCall).toHaveBeenLastCalledWith(
      expect.objectContaining({ toolName: "dangerous.delete_customer" }),
    );
    expect(
      within(step("Propose customer email")).getByText("Rejected"),
    ).toBeInTheDocument();
    expect(
      within(step("Attempt unsafe customer deletion")).getByText("Blocked"),
    ).toBeInTheDocument();
  });

  it("ignores stored UI state and retains only generated identifiers", async () => {
    const user = userEvent.setup();
    window.localStorage.setItem(
      "actionproxy.agentDemoRuns.v1",
      JSON.stringify({
        "search-docs": {
          error: "untrusted diagnostic",
          response: { payload: "must not survive" },
          state: "running",
          toolCallId: "toolcall_docs",
        },
      }),
    );
    window.localStorage.setItem("actionproxy.agentDemoAutoContinue.v1", "true");

    render(<AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />);

    expect(
      within(step("Search support policy")).getByText("Ready"),
    ).toBeInTheDocument();
    expect(
      within(step("Search support policy")).queryByText("untrusted diagnostic"),
    ).not.toBeInTheDocument();
    expect(
      JSON.parse(
        window.localStorage.getItem("actionproxy.agentDemoRuns.v1") ?? "{}",
      ),
    ).toEqual({ "search-docs": { toolCallId: "toolcall_docs" } });
    await waitFor(() =>
      expect(
        window.localStorage.getItem("actionproxy.agentDemoAutoContinue.v1"),
      ).toBeNull(),
    );
    await user.click(screen.getByText("Run step by step"));
    expect(screen.getByRole("button", { name: "Run next step" })).toBeEnabled();
  });
});

function step(title: string): HTMLElement {
  const element = screen.getByText(title).closest("article");
  expect(element).not.toBeNull();
  return element as HTMLElement;
}
