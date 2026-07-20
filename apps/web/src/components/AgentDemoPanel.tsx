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
  onRefresh: () => Promise<void> | void;
}

type StepState =
  | "blocked"
  | "complete"
  | "error"
  | "idle"
  | "needs_approval"
  | "rejected"
  | "running";

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

const demoRunsStorageKey = "actionproxy.agentDemoRuns.v1";
const demoAutoContinueStorageKey = "actionproxy.agentDemoAutoContinue.v1";
const stepStates: StepState[] = [
  "blocked",
  "complete",
  "error",
  "idle",
  "needs_approval",
  "rejected",
  "running",
];

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

export function AgentDemoPanel({ data, onRefresh }: AgentDemoPanelProps) {
  const [runs, setRunsState] =
    useState<Record<string, StepRun>>(loadStoredRuns);
  const [autoContinueFullDemo, setAutoContinueFullDemoState] = useState(
    loadStoredAutoContinue,
  );
  const [runningAll, setRunningAll] = useState(false);

  useEffect(() => {
    setRunsState((current) => {
      const synced = syncRunsWithLiveToolCalls(current, data.toolCalls);
      if (synced === current) return current;
      saveStoredRuns(synced);
      return synced;
    });
  }, [data.toolCalls]);

  const nextStep = useMemo(
    () => findNextRunnableStep(runs, data),
    [data, runs],
  );
  const lifecycleComplete = useMemo(() => {
    const searchState = resolveStepState(agentSteps[0]!, runs, data);
    const emailState = resolveStepState(agentSteps[1]!, runs, data);
    const deleteState = resolveStepState(agentSteps[2]!, runs, data);
    return (
      searchState === "complete" &&
      (emailState === "complete" || emailState === "rejected") &&
      deleteState === "blocked"
    );
  }, [data, runs]);

  useEffect(() => {
    if (!autoContinueFullDemo || runningAll || !nextStep) return;
    void runAll();
  }, [autoContinueFullDemo, nextStep, runningAll]);

  async function runStep(step: AgentStep): Promise<StepRun> {
    setRuns((current) => ({ ...current, [step.id]: { state: "running" } }));
    try {
      const response = await submitToolCall({
        agentId: "customer-support-demo-agent",
        input: step.input,
        metadata: { demo: "customer-support-agent", visualStep: step.id },
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
    setAutoContinueFullDemo(true);
    setRunningAll(true);
    let shouldKeepAutoContinuing = false;
    try {
      let currentRuns = runs;
      for (const step of agentSteps) {
        const state = resolveStepState(step, currentRuns, data);
        if (canAdvancePastState(state)) continue;
        if (!canRunState(state)) {
          shouldKeepAutoContinuing = true;
          break;
        }

        const nextRun = await runStep(step);
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
      saveStoredRuns(next);
      return next;
    });
  }

  function resetRuns() {
    clearStoredRuns();
    setAutoContinueFullDemo(false);
    setRunsState({});
  }

  function setAutoContinueFullDemo(value: boolean) {
    setAutoContinueFullDemoState(value);
    saveStoredAutoContinue(value);
  }

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
          Agent demo
        </h2>
        <div className="panel-actions">
          <button
            type="button"
            onClick={() => void runNext()}
            disabled={!nextStep || runningAll}
          >
            <StepForward size={18} aria-hidden="true" />
            Run next
          </button>
          <button
            type="button"
            onClick={() => void runAll()}
            disabled={!nextStep || runningAll}
          >
            <Play size={18} aria-hidden="true" />
            Run full demo
          </button>
          <button
            className="secondary"
            type="button"
            onClick={resetRuns}
            disabled={runningAll}
          >
            <RotateCcw size={18} aria-hidden="true" />
            Reset view
          </button>
        </div>
      </div>

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
            canRun={nextStep?.id === step.id && !runningAll}
            step={step}
            onRun={() => void runStep(step)}
          />
        ))}
      </div>

      {lifecycleComplete && (
        <div className="demo-completion-summary" role="status">
          <div>
            <Check size={18} aria-hidden="true" />
            <span>
              <strong>Lifecycle complete.</strong> Search was allowed, the email
              required a human decision, and deletion was denied.
            </span>
          </div>
          <a className="text-link" href="#/audit">
            Inspect the audit evidence
          </a>
        </div>
      )}
    </section>
  );
}

function AgentStepRow({
  canRun,
  data,
  index,
  onRun,
  run,
  step,
}: {
  canRun: boolean;
  data: DashboardData;
  index: number;
  onRun: () => void;
  run?: StepRun;
  step: AgentStep;
}) {
  const liveToolCall = findLiveToolCall(data.toolCalls, run?.toolCallId);
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
          {run?.approvalId && <span>Approval {run.approvalId}</span>}
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
                href={`#/approvals/${encodeURIComponent(approvalId)}`}
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
      <button
        className="secondary agent-step-run"
        type="button"
        onClick={onRun}
        disabled={!canRun || state === "running"}
      >
        <Play size={16} aria-hidden="true" />
        Run
      </button>
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
): ToolCallRecord | undefined {
  if (!id) return undefined;
  return toolCalls.find((toolCall) => toolCall.id === id);
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
): AgentStep | undefined {
  for (const step of agentSteps) {
    const state = resolveStepState(step, runs, data);
    if (canRunState(state)) return step;
    if (!canAdvancePastState(state)) return undefined;
  }
  return undefined;
}

function resolveStepState(
  step: AgentStep,
  runs: Record<string, StepRun>,
  data: DashboardData,
): StepState {
  const run = runs[step.id];
  const liveToolCall = findLiveToolCall(data.toolCalls, run?.toolCallId);
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
): Record<string, StepRun> {
  let changed = false;
  const nextRuns: Record<string, StepRun> = { ...runs };

  for (const [stepId, run] of Object.entries(runs)) {
    const liveToolCall = findLiveToolCall(toolCalls, run.toolCallId);
    if (!liveToolCall) continue;

    const state = stateFromToolCall(liveToolCall);
    if (state !== run.state) {
      nextRuns[stepId] = { ...run, state };
      changed = true;
    }
  }

  return changed ? nextRuns : runs;
}

function loadStoredRuns(): Record<string, StepRun> {
  if (typeof window === "undefined") return {};

  try {
    const storedRuns = window.localStorage.getItem(demoRunsStorageKey);
    if (!storedRuns) return {};
    const parsed = JSON.parse(storedRuns) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return {};
    return sanitizeStoredRuns(parsed);
  } catch {
    return {};
  }
}

function loadStoredAutoContinue(): boolean {
  if (typeof window === "undefined") return false;

  try {
    return window.localStorage.getItem(demoAutoContinueStorageKey) === "true";
  } catch {
    return false;
  }
}

function sanitizeStoredRuns(value: unknown): Record<string, StepRun> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};

  const runs: Record<string, StepRun> = {};
  for (const [stepId, maybeRun] of Object.entries(value)) {
    if (!maybeRun || typeof maybeRun !== "object" || Array.isArray(maybeRun))
      continue;
    const run = maybeRun as Partial<StepRun>;
    if (!run.state || !stepStates.includes(run.state)) continue;
    runs[stepId] = {
      approvalId:
        typeof run.approvalId === "string" ? run.approvalId : undefined,
      error:
        run.state === "running"
          ? "The previous run was interrupted."
          : undefined,
      state: run.state === "running" ? "error" : run.state,
      toolCallId:
        typeof run.toolCallId === "string" ? run.toolCallId : undefined,
    };
  }

  return runs;
}

function saveStoredRuns(runs: Record<string, StepRun>) {
  if (typeof window === "undefined") return;

  try {
    const progressOnly = Object.fromEntries(
      Object.entries(runs).map(([stepId, run]) => [
        stepId,
        {
          approvalId: run.approvalId,
          state: run.state,
          toolCallId: run.toolCallId,
        },
      ]),
    );
    window.localStorage.setItem(
      demoRunsStorageKey,
      JSON.stringify(progressOnly),
    );
  } catch {
    // Browser storage is a convenience for route persistence; demo execution still works without it.
  }
}

function clearStoredRuns() {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.removeItem(demoRunsStorageKey);
  } catch {
    // Ignore unavailable storage.
  }
}

function saveStoredAutoContinue(value: boolean) {
  if (typeof window === "undefined") return;

  try {
    if (value) {
      window.localStorage.setItem(demoAutoContinueStorageKey, "true");
    } else {
      window.localStorage.removeItem(demoAutoContinueStorageKey);
    }
  } catch {
    // Ignore unavailable storage.
  }
}
