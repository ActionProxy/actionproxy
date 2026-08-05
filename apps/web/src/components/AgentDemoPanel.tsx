import {
  Bot,
  Check,
  Circle,
  Play,
  RotateCcw,
  ShieldAlert,
  StepForward,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { DashboardData, JsonObject, ToolCallRecord } from "../types";
import {
  submitToolCall,
  type SubmitToolCallResponse,
} from "../lib/actionproxy-client";

interface AgentDemoPanelProps {
  data: DashboardData;
  guided?: boolean;
  loading?: boolean;
  onProofStateChange?: (ready: boolean) => void;
  onRefresh: () => Promise<void> | void;
  returnTo?: string;
  sessionId?: string;
  sessionStartedAt?: string;
}

type StepState =
  | "blocked"
  | "complete"
  | "error"
  | "idle"
  | "needs_approval"
  | "rejected"
  | "running";

const quickstartSessionIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

interface AgentStep {
  expected: string;
  id: string;
  input: JsonObject;
  reason: string;
  title: string;
  toolName: string;
  thought: string;
}

interface StepRun {
  approvalId?: string;
  error?: string;
  response?: SubmitToolCallResponse;
  state: StepState;
  toolCallId?: string;
}

const demoRunsStoragePrefix = "actionproxy.agentDemoRuns.v1";

const agentSteps: AgentStep[] = [
  {
    expected: "Allowed and executed immediately",
    id: "search-docs",
    input: { query: "refund policy for delayed shipment" },
    reason: "Find policy context for a customer support reply",
    thought:
      "The customer is asking about a delayed shipment, so the agent first needs policy context.",
    title: "Search support policy",
    toolName: "docs.search",
  },
  {
    expected: "Queued for human approval",
    id: "send-email",
    input: {
      body: "Thanks for contacting us. Based on our policy, your delayed shipment qualifies for review.",
      subject: "Refund policy update",
      to: "customer@example.com",
    },
    reason: "Send customer response drafted by the support agent",
    thought:
      "The agent drafts an external customer email, which should not send without review.",
    title: "Propose customer email",
    toolName: "gmail.send_email",
  },
  {
    expected: "Blocked by policy",
    id: "delete-customer",
    input: { customerId: "cus_123" },
    reason: "Show that destructive actions are blocked by policy",
    thought:
      "The agent attempts a destructive action to prove ActionProxy can stop unsafe proposals.",
    title: "Attempt unsafe customer deletion",
    toolName: "dangerous.delete_customer",
  },
];

function prettyJson(value: unknown): string {
  return JSON.stringify(redactSecretLikeValues(value ?? null), null, 2);
}

function redactSecretLikeValues(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSecretLikeValues);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
      key,
      /(?:authorization|cookie|password|secret|token)$/iu.test(
        key.replaceAll(/[-_\s]/g, ""),
      )
        ? "[REDACTED]"
        : redactSecretLikeValues(entry),
    ]),
  );
}

export function AgentDemoPanel({
  data,
  guided = false,
  loading = false,
  onProofStateChange,
  onRefresh,
  returnTo = "#/demo?journey=local",
  sessionId,
  sessionStartedAt,
}: AgentDemoPanelProps) {
  const storageKey = demoRunsStorageKey(sessionId);
  const proofStartedAt = sessionId ? (sessionStartedAt ?? "") : undefined;
  const [runs, setRunsState] = useState<Record<string, StepRun>>(() =>
    loadStoredRuns(storageKey),
  );
  const [autoContinueFullDemo, setAutoContinueFullDemoState] = useState(guided);
  const [runningAll, setRunningAll] = useState(false);
  const hasUnresolvedStoredRun = Object.values(runs).some(
    (run) =>
      Boolean(run.toolCallId) &&
      !findLiveToolCall(data.toolCalls, run.toolCallId, proofStartedAt),
  );

  useEffect(() => {
    clearLegacyAutoContinueStorage();
    clearOtherDemoRunStorage(storageKey);
  }, [storageKey]);

  useEffect(() => {
    setRunsState((current) => {
      const synced = syncRunsWithLiveToolCalls(
        current,
        data.toolCalls,
        proofStartedAt,
      );
      if (synced === current) return current;
      saveStoredRuns(storageKey, synced);
      return synced;
    });
  }, [data.toolCalls, proofStartedAt, storageKey]);

  const nextStep = useMemo(
    () => findNextRunnableStep(runs, data, proofStartedAt),
    [data, proofStartedAt, runs],
  );
  const lifecycleComplete = useMemo(() => {
    const searchCall = findLiveToolCall(
      data.toolCalls,
      runs[agentSteps[0]!.id]?.toolCallId,
      proofStartedAt,
    );
    const emailCall = findLiveToolCall(
      data.toolCalls,
      runs[agentSteps[1]!.id]?.toolCallId,
      proofStartedAt,
    );
    const deleteCall = findLiveToolCall(
      data.toolCalls,
      runs[agentSteps[2]!.id]?.toolCallId,
      proofStartedAt,
    );
    return (
      searchCall?.status === "executed" &&
      (emailCall?.status === "executed" || emailCall?.status === "rejected") &&
      deleteCall?.status === "blocked"
    );
  }, [data, proofStartedAt, runs]);

  useEffect(() => {
    if (
      !autoContinueFullDemo ||
      loading ||
      hasUnresolvedStoredRun ||
      runningAll ||
      !nextStep
    )
      return;
    void runAll();
  }, [
    autoContinueFullDemo,
    hasUnresolvedStoredRun,
    loading,
    nextStep,
    runningAll,
  ]);

  useEffect(() => {
    onProofStateChange?.(lifecycleComplete);
  }, [lifecycleComplete, onProofStateChange]);

  async function runStep(
    step: AgentStep,
    guidedRun = autoContinueFullDemo || guided,
  ): Promise<StepRun> {
    setRuns((current) => ({ ...current, [step.id]: { state: "running" } }));
    try {
      const response = await submitToolCall({
        agentId: "customer-support-demo-agent",
        input: step.input,
        metadata: {
          demo: "customer-support-agent",
          ...(sessionId && quickstartSessionIdPattern.test(sessionId)
            ? {
                demoQuickstartGuided: guidedRun,
                demoQuickstartSessionId: sessionId,
              }
            : {}),
          visualStep: step.id,
        },
        reason: step.reason,
        requestedBy: "demo-agent@example.com",
        toolName: step.toolName,
      });
      const nextRun: StepRun = {
        approvalId: response.approval?.id,
        response,
        state: stateFromResponse(response),
        toolCallId: response.id,
      };
      setRuns((current) => ({
        ...current,
        [step.id]: nextRun,
      }));
      await onRefresh();
      return nextRun;
    } catch (caught) {
      const nextRun: StepRun = {
        error: caught instanceof Error ? caught.message : String(caught),
        state: "error",
      };
      setRuns((current) => ({
        ...current,
        [step.id]: nextRun,
      }));
      return nextRun;
    }
  }

  async function runNext() {
    if (nextStep) await runStep(nextStep);
  }

  async function runAll() {
    if (loading) return;
    setAutoContinueFullDemo(true);
    setRunningAll(true);
    let shouldKeepAutoContinuing = false;
    try {
      let currentRuns = runs;
      for (const step of agentSteps) {
        const state = resolveStepState(step, currentRuns, data, proofStartedAt);
        if (canAdvancePastState(state)) continue;
        if (!canRunState(state)) {
          shouldKeepAutoContinuing = true;
          break;
        }

        const nextRun = await runStep(step, true);
        currentRuns = { ...currentRuns, [step.id]: nextRun };
        if (nextRun.state === "error") break;
        if (!canAdvancePastState(nextRun.state)) {
          shouldKeepAutoContinuing = true;
          break;
        }
      }
    } finally {
      setRunningAll(false);
      if (!shouldKeepAutoContinuing) setAutoContinueFullDemo(false);
    }
  }

  function setRuns(
    update: (current: Record<string, StepRun>) => Record<string, StepRun>,
  ) {
    setRunsState((current) => {
      const next = update(current);
      saveStoredRuns(storageKey, next);
      return next;
    });
  }

  function resetRuns() {
    clearStoredRuns(storageKey);
    setAutoContinueFullDemoState(false);
    replaceGuidedRoute(returnTo, false);
    setRunsState({});
  }

  function setAutoContinueFullDemo(value: boolean) {
    setAutoContinueFullDemoState(value);
    if (value) replaceGuidedRoute(returnTo, true);
  }

  const approvalReturnTo = autoContinueFullDemo
    ? withGuidedQuery(returnTo, true)
    : returnTo;

  return (
    <section
      className="panel agent-demo-panel"
      aria-labelledby="agent-demo-heading"
    >
      <div className="panel-header">
        <h2 id="agent-demo-heading">
          <span aria-hidden="true">
            <Bot size={18} />
          </span>
          Local lifecycle proof
        </h2>
        <div className="panel-actions">
          <button
            type="button"
            onClick={() => void runAll()}
            disabled={loading || !nextStep || runningAll}
          >
            <Play size={18} aria-hidden="true" />
            Run guided proof
          </button>
          <button
            className="secondary"
            type="button"
            onClick={resetRuns}
            disabled={runningAll}
          >
            <RotateCcw size={18} aria-hidden="true" />
            Start a new proof
          </button>
        </div>
      </div>

      <details className="agent-step-controls">
        <summary>Run step by step</summary>
        <button
          className="secondary"
          type="button"
          onClick={() => void runNext()}
          disabled={loading || !nextStep || runningAll}
        >
          <StepForward size={18} aria-hidden="true" />
          Run next step
        </button>
      </details>

      <div
        className="agent-flow"
        aria-label="Customer support demo agent steps"
      >
        {agentSteps.map((step, index) => (
          <AgentStepRow
            data={data}
            index={index + 1}
            key={step.id}
            run={runs[step.id]}
            sessionStartedAt={proofStartedAt}
            step={step}
            returnTo={approvalReturnTo}
          />
        ))}
      </div>
    </section>
  );
}

function AgentStepRow({
  data,
  index,
  returnTo,
  run,
  sessionStartedAt,
  step,
}: {
  data: DashboardData;
  index: number;
  returnTo: string;
  run?: StepRun;
  sessionStartedAt?: string;
  step: AgentStep;
}) {
  const liveToolCall = findLiveToolCall(
    data.toolCalls,
    run?.toolCallId,
    sessionStartedAt,
  );
  const state = liveToolCall
    ? stateFromToolCall(liveToolCall)
    : (run?.state ?? "idle");
  const response = liveToolCall ?? run?.response?.toolCall ?? run?.response;
  const approvalId =
    run?.approvalId ??
    (liveToolCall
      ? data.pendingApprovals.find(
          (candidate) => candidate.toolCallId === liveToolCall.id,
        )?.id
      : undefined);

  return (
    <article className={`agent-step ${state}`}>
      <div className="agent-step-marker" aria-hidden="true">
        {iconForState(state)}
      </div>
      <div className="agent-step-main">
        <div className="agent-step-title">
          <span>Step {index}</span>
          <strong>{step.title}</strong>
          <StatusPill state={state} />
        </div>
        <p>{step.thought}</p>
        <div className="agent-step-meta">
          <span>
            Tool <code>{step.toolName}</code>
          </span>
          <span>{step.expected}</span>
        </div>
        <details>
          <summary>Payload</summary>
          <pre>{prettyJson(step.input)}</pre>
        </details>
        {state === "needs_approval" && (
          <div className="demo-pause-note" role="status">
            <strong>Paused as designed—no email was sent.</strong>
            <span>
              ActionProxy is holding the exact proposal until a human approves
              or rejects it.
            </span>
            {approvalId && (
              <a
                className="text-link"
                href={`#/approvals/${encodeURIComponent(approvalId)}?returnTo=${encodeURIComponent(returnTo)}`}
              >
                Review this approval
              </a>
            )}
          </div>
        )}
        {run?.error && <p className="field-error">{run.error}</p>}
        {response && (
          <details>
            <summary>Gateway response</summary>
            <pre>{prettyJson(response)}</pre>
          </details>
        )}
      </div>
    </article>
  );
}

function StatusPill({ state }: { state: StepState }) {
  const labelByState: Record<StepState, string> = {
    blocked: "Blocked",
    complete: "Complete",
    error: "Error",
    idle: "Ready",
    needs_approval: "Needs approval",
    rejected: "Rejected",
    running: "Running",
  };
  return <span className={`agent-status ${state}`}>{labelByState[state]}</span>;
}

function findLiveToolCall(
  toolCalls: ToolCallRecord[],
  id?: string,
  sessionStartedAt?: string,
): ToolCallRecord | undefined {
  if (!id) return undefined;
  return toolCalls.find(
    (toolCall) =>
      toolCall.id === id &&
      isCurrentSessionCall(toolCall.createdAt, sessionStartedAt),
  );
}

function isCurrentSessionCall(
  createdAt: string,
  sessionStartedAt?: string,
): boolean {
  if (!sessionStartedAt) return true;
  const created = Date.parse(createdAt);
  const started = Date.parse(sessionStartedAt);
  return (
    Number.isFinite(created) && Number.isFinite(started) && created >= started
  );
}

function stateFromResponse(response: SubmitToolCallResponse): StepState {
  if (response.status === "blocked") return "blocked";
  if (response.status === "pending_approval") return "needs_approval";
  if (response.status === "failed") return "error";
  return "complete";
}

function stateFromToolCall(toolCall: ToolCallRecord): StepState {
  if (toolCall.status === "blocked") return "blocked";
  if (toolCall.status === "pending_approval") return "needs_approval";
  if (toolCall.status === "failed") return "error";
  if (toolCall.status === "rejected") return "rejected";
  if (toolCall.status === "executed") return "complete";
  return "running";
}

function iconForState(state: StepState) {
  if (state === "complete") return <Check size={18} />;
  if (state === "blocked" || state === "error" || state === "rejected")
    return <ShieldAlert size={18} />;
  return <Circle size={18} />;
}

function findNextRunnableStep(
  runs: Record<string, StepRun>,
  data: DashboardData,
  sessionStartedAt?: string,
): AgentStep | undefined {
  for (const step of agentSteps) {
    const state = resolveStepState(step, runs, data, sessionStartedAt);
    if (canRunState(state)) return step;
    if (!canAdvancePastState(state)) return undefined;
  }
  return undefined;
}

function resolveStepState(
  step: AgentStep,
  runs: Record<string, StepRun>,
  data: DashboardData,
  sessionStartedAt?: string,
): StepState {
  const run = runs[step.id];
  const liveToolCall = findLiveToolCall(
    data.toolCalls,
    run?.toolCallId,
    sessionStartedAt,
  );
  return liveToolCall
    ? stateFromToolCall(liveToolCall)
    : (run?.state ?? "idle");
}

function canRunState(state: StepState): boolean {
  return state === "idle" || state === "error";
}

function canAdvancePastState(state: StepState): boolean {
  return state === "complete" || state === "blocked" || state === "rejected";
}

function syncRunsWithLiveToolCalls(
  runs: Record<string, StepRun>,
  toolCalls: ToolCallRecord[],
  sessionStartedAt?: string,
): Record<string, StepRun> {
  let changed = false;
  const nextRuns: Record<string, StepRun> = { ...runs };

  for (const [stepId, run] of Object.entries(runs)) {
    const liveToolCall = findLiveToolCall(
      toolCalls,
      run.toolCallId,
      sessionStartedAt,
    );
    if (!liveToolCall) continue;

    const state = stateFromToolCall(liveToolCall);
    if (state !== run.state) {
      nextRuns[stepId] = { ...run, state };
      changed = true;
    }
  }

  return changed ? nextRuns : runs;
}

function demoRunsStorageKey(sessionId?: string): string {
  return sessionId
    ? `${demoRunsStoragePrefix}.${encodeURIComponent(sessionId)}`
    : demoRunsStoragePrefix;
}

function loadStoredRuns(storageKey: string): Record<string, StepRun> {
  if (typeof window === "undefined") return {};

  try {
    const storedRuns = window.localStorage.getItem(storageKey);
    if (!storedRuns) return {};
    const parsed = JSON.parse(storedRuns) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      clearStoredRuns(storageKey);
      return {};
    }
    const sanitized = sanitizeStoredRuns(parsed);
    saveStoredRuns(storageKey, sanitized);
    return sanitized;
  } catch {
    clearStoredRuns(storageKey);
    return {};
  }
}

function sanitizeStoredRuns(value: unknown): Record<string, StepRun> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};

  const runs: Record<string, StepRun> = {};
  for (const [stepId, maybeRun] of Object.entries(value)) {
    if (!agentSteps.some((step) => step.id === stepId)) continue;
    if (!maybeRun || typeof maybeRun !== "object" || Array.isArray(maybeRun))
      continue;
    const run = maybeRun as Partial<StepRun>;
    const approvalId = sanitizeStoredId(run.approvalId);
    const toolCallId = sanitizeStoredId(run.toolCallId);
    if (!approvalId && !toolCallId) continue;
    runs[stepId] = {
      approvalId,
      state: "idle",
      toolCallId,
    };
  }

  return runs;
}

function sanitizeStoredId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const id = value.trim();
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(id) ? id : undefined;
}

function saveStoredRuns(storageKey: string, runs: Record<string, StepRun>) {
  if (typeof window === "undefined") return;

  try {
    const progressOnly = Object.fromEntries(
      Object.entries(runs)
        .filter(([, run]) => run.approvalId || run.toolCallId)
        .map(([stepId, run]) => [
          stepId,
          {
            approvalId: run.approvalId,
            toolCallId: run.toolCallId,
          },
        ]),
    );
    window.localStorage.setItem(storageKey, JSON.stringify(progressOnly));
  } catch {
    // Browser storage is a convenience for route persistence; demo execution still works without it.
  }
}

function clearStoredRuns(storageKey: string) {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.removeItem(storageKey);
  } catch {
    // Ignore unavailable storage.
  }
}

function clearOtherDemoRunStorage(activeStorageKey: string) {
  if (typeof window === "undefined") return;

  try {
    const staleKeys: string[] = [];
    for (let index = 0; index < window.localStorage.length; index += 1) {
      const key = window.localStorage.key(index);
      if (
        key &&
        key !== activeStorageKey &&
        (key === demoRunsStoragePrefix ||
          key.startsWith(`${demoRunsStoragePrefix}.`))
      ) {
        staleKeys.push(key);
      }
    }
    for (const key of staleKeys) window.localStorage.removeItem(key);
  } catch {
    // Ignore unavailable storage.
  }
}

function clearLegacyAutoContinueStorage() {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.removeItem("actionproxy.agentDemoAutoContinue.v1");
  } catch {
    // Ignore unavailable storage.
  }
}

function withGuidedQuery(returnTo: string, guided: boolean): string {
  const [path, rawQuery = ""] = returnTo.split("?", 2);
  const query = new URLSearchParams(rawQuery);
  if (guided) query.set("guided", "1");
  else query.delete("guided");
  const serialized = query.toString();
  return serialized ? `${path}?${serialized}` : path!;
}

function replaceGuidedRoute(returnTo: string, guided: boolean) {
  if (typeof window === "undefined") return;
  const next = withGuidedQuery(returnTo, guided);
  if (window.location.hash === next) return;
  window.history.replaceState(window.history.state, "", next);
  window.dispatchEvent(new HashChangeEvent("hashchange"));
}
