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
import type { DashboardData } from "../types";
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

const approvedEmailData: DashboardData = {
  ...emptyData,
  toolCalls: [
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

const rejectedEmailData: DashboardData = {
  ...emptyData,
  toolCalls: [
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
      screen.getByRole("heading", { name: "Agent demo" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Search support policy")).toBeInTheDocument();
    expect(screen.getByText("Propose customer email")).toBeInTheDocument();
    expect(
      screen.getByText("Attempt unsafe customer deletion"),
    ).toBeInTheDocument();
  });

  it("only enables the next sequential step", () => {
    render(<AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />);

    expect(
      within(step("Search support policy")).getByRole("button", {
        name: "Run",
      }),
    ).toBeEnabled();
    expect(
      within(step("Propose customer email")).getByRole("button", {
        name: "Run",
      }),
    ).toBeDisabled();
    expect(
      within(step("Attempt unsafe customer deletion")).getByRole("button", {
        name: "Run",
      }),
    ).toBeDisabled();
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

    await user.click(screen.getByRole("button", { name: "Run next" }));

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

  it("keeps completed demo state after the panel unmounts and remounts", async () => {
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

    await user.click(screen.getByRole("button", { name: "Run next" }));
    expect(
      within(
        screen
          .getByText("Search support policy")
          .closest("article") as HTMLElement,
      ).getByText("Complete"),
    ).toBeInTheDocument();

    unmount();
    render(<AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />);

    const firstStep = screen
      .getByText("Search support policy")
      .closest("article");
    expect(firstStep).not.toBeNull();
    expect(
      within(firstStep as HTMLElement).getByText("Complete"),
    ).toBeInTheDocument();
    expect(
      within(firstStep as HTMLElement).queryByText("Gateway response"),
    ).not.toBeInTheDocument();
  });

  it("pauses the full demo when a step needs approval", async () => {
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
      });

    render(<AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: "Run full demo" }));

    expect(submitToolCall).toHaveBeenCalledTimes(2);
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
    ).toHaveAttribute("href", "#/approvals/approval_email");
    expect(
      within(step("Attempt unsafe customer deletion")).getByText("Ready"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Run full demo" }),
    ).toBeDisabled();
    expect(
      window.localStorage.getItem("actionproxy.agentDemoRuns.v1"),
    ).not.toContain("result");
    expect(
      window.localStorage.getItem("actionproxy.agentDemoRuns.v1"),
    ).not.toContain("response");
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

    await user.click(screen.getByRole("button", { name: "Run full demo" }));
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

    await user.click(screen.getByRole("button", { name: "Run full demo" }));
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

  it("recovers stale running state from storage as retryable error state", () => {
    window.localStorage.setItem(
      "actionproxy.agentDemoRuns.v1",
      JSON.stringify({
        "search-docs": { state: "running", toolCallId: "toolcall_docs" },
      }),
    );

    render(<AgentDemoPanel data={emptyData} onRefresh={vi.fn()} />);

    expect(
      within(step("Search support policy")).getByText("Error"),
    ).toBeInTheDocument();
    expect(
      within(step("Search support policy")).getByText(
        "The previous run was interrupted.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run next" })).toBeEnabled();
  });
});

function step(title: string): HTMLElement {
  const element = screen.getByText(title).closest("article");
  expect(element).not.toBeNull();
  return element as HTMLElement;
}
