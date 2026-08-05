import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { fetchDashboardData, saveApiToken } from "./lib/actionproxy-client";

vi.mock("./components/Dashboard", () => ({
  Dashboard: ({
    error,
    loading,
    onRefresh,
    snapshotState,
  }: {
    error?: string | null;
    loading: boolean;
    onRefresh: () => Promise<void> | void;
    snapshotState?: string;
  }) => (
    <div data-testid="dashboard-shell">
      Community dashboard shell
      <span data-testid="snapshot-state">{snapshotState}</span>
      <span data-testid="loading-state">{loading ? "loading" : "idle"}</span>
      {error && <span data-testid="dashboard-error">{error}</span>}
      <button type="button" onClick={() => void onRefresh()}>
        Refresh probe
      </button>
    </div>
  ),
}));

vi.mock("./lib/actionproxy-client", () => ({
  clearApiToken: vi.fn(),
  fetchDashboardData: vi.fn(async () => ({})),
  saveApiToken: vi.fn(),
}));

beforeEach(() => {
  window.history.pushState({}, "", "/");
  vi.mocked(fetchDashboardData).mockResolvedValue(
    {} as Awaited<ReturnType<typeof fetchDashboardData>>,
  );
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("fixed Community app shell", () => {
  it("renders the fixed Community console at the root", async () => {
    render(<App />);

    expect(await screen.findByTestId("dashboard-shell")).toHaveTextContent(
      "Community dashboard shell",
    );
    expect(fetchDashboardData).toHaveBeenCalledTimes(1);
  });

  it("renders the same Community console at the bundled /app path", async () => {
    window.history.pushState({}, "", "/app");

    render(<App />);

    expect(await screen.findByTestId("dashboard-shell")).toBeInTheDocument();
  });

  it("shows a self-hosted access-token prompt when API auth is required", async () => {
    vi.mocked(fetchDashboardData)
      .mockRejectedValueOnce(new Error("Bearer authentication is required."))
      .mockResolvedValueOnce(
        {} as Awaited<ReturnType<typeof fetchDashboardData>>,
      );

    render(<App />);

    expect(
      await screen.findByRole("heading", { name: "Enter access token" }),
    ).toBeInTheDocument();
    expect(screen.getByText("ActionProxy Community")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Access token"), {
      target: { value: "apx_test_token" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    await waitFor(() =>
      expect(saveApiToken).toHaveBeenCalledWith("apx_test_token"),
    );
    await waitFor(() =>
      expect(screen.getByTestId("dashboard-shell")).toBeInTheDocument(),
    );
  });

  it("marks a retained snapshot stale and reports recovery after the gateway returns", async () => {
    render(<App />);

    expect(await screen.findByTestId("snapshot-state")).toHaveTextContent(
      "ready",
    );

    vi.mocked(fetchDashboardData).mockRejectedValueOnce(
      new Error("Gateway restarting"),
    );
    fireEvent.click(screen.getByRole("button", { name: "Refresh probe" }));

    await waitFor(() =>
      expect(screen.getByTestId("snapshot-state")).toHaveTextContent("stale"),
    );
    expect(screen.getByTestId("dashboard-error")).toHaveTextContent(
      "Gateway restarting",
    );

    vi.mocked(fetchDashboardData).mockResolvedValueOnce(
      {} as Awaited<ReturnType<typeof fetchDashboardData>>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Refresh probe" }));

    await waitFor(() =>
      expect(screen.getByTestId("snapshot-state")).toHaveTextContent(
        "recovered",
      ),
    );
    expect(screen.queryByTestId("dashboard-error")).not.toBeInTheDocument();
  });

  it("keeps scheduled background refreshes visually silent", async () => {
    vi.useFakeTimers();
    try {
      render(<App />);
      await act(async () => {});

      expect(screen.getByTestId("loading-state")).toHaveTextContent("idle");

      let completeBackgroundRefresh: (
        data: Awaited<ReturnType<typeof fetchDashboardData>>,
      ) => void = () => undefined;
      vi.mocked(fetchDashboardData).mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            completeBackgroundRefresh = resolve;
          }),
      );

      act(() => vi.advanceTimersByTime(5_000));

      expect(fetchDashboardData).toHaveBeenCalledTimes(2);
      expect(screen.getByTestId("loading-state")).toHaveTextContent("idle");

      await act(async () => {
        completeBackgroundRefresh(
          {} as Awaited<ReturnType<typeof fetchDashboardData>>,
        );
      });
      expect(screen.getByTestId("loading-state")).toHaveTextContent("idle");
    } finally {
      vi.useRealTimers();
    }
  });

  it("refreshes silently when the operator returns to the browser", async () => {
    render(<App />);
    await screen.findByTestId("dashboard-shell");
    await waitFor(() => expect(fetchDashboardData).toHaveBeenCalledTimes(1));
    vi.mocked(fetchDashboardData).mockClear();

    window.dispatchEvent(new Event("focus"));

    await waitFor(() => expect(fetchDashboardData).toHaveBeenCalledTimes(1));
    expect(screen.getByTestId("loading-state")).toHaveTextContent("idle");
  });
});
