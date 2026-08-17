import {
  Activity,
  Beaker,
  Bell,
  Bot,
  Check,
  Circle,
  ClipboardCheck,
  Copy,
  Database,
  ExternalLink,
  FileSearch,
  Gauge,
  History,
  Plug,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  TriangleAlert,
} from "lucide-react";
import {
  Fragment,
  type CSSProperties,
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import openAiLinks from "../../../../examples/chatgpt-tunnel/openai-links.json";
import type {
  ApprovalRecord,
  ApprovalReview,
  AuditVerification,
  AuditEvent,
  DashboardData,
  JsonObject,
  McpWrapperProfileSummary,
  PolicyDecision,
  QuickstartJourney,
  QuickstartStatus,
  ToolCallRecord,
} from "../types";
import {
  approveApproval,
  buildAuditExportUrl,
  fetchApproval,
  fetchApprovalReview,
  fetchAuditVerification,
  fetchQuickstartStatus,
  fetchToolCall,
  rejectApproval,
} from "../lib/actionproxy-client";
import { AgentDemoPanel } from "./AgentDemoPanel";
import { PolicyEditor } from "./PolicyEditor";
import { ToolIntegrationsCard } from "./ToolIntegrationsCard";

interface DashboardProps {
  data: DashboardData;
  error?: string | null;
  lastSuccessfulRefreshAt?: string | null;
  loading: boolean;
  onRefresh: () => Promise<void> | void;
  snapshotState?: DashboardSnapshotState;
}

export type DashboardSnapshotState =
  | "loading"
  | "ready"
  | "recovered"
  | "stale"
  | "unavailable";

type CommunityRoute =
  | { name: "overview" }
  | { name: "approvals" }
  | {
      name: "approvalDetail";
      id: string;
      returnTarget?: QuickstartReturnTarget;
    }
  | { name: "authorized" }
  | { name: "audit" }
  | { name: "policy" }
  | { name: "integrations" }
  | {
      name: "demo";
      guided?: boolean;
      journey?: QuickstartJourney;
      sessionId?: string;
    }
  | { name: "toolCallDetail"; id: string }
  | { name: "notFound"; requestedPath: string };

type QuickstartReturnTarget = {
  guided?: true;
  journey?: QuickstartJourney;
  sessionId?: string;
};

const navigation = [
  {
    description: "Start with the local lifecycle and current gateway posture.",
    href: "#/",
    icon: Gauge,
    label: "Overview",
    route: "overview",
  },
  {
    description: "Inspect append-only lifecycle evidence.",
    href: "#/audit",
    icon: History,
    label: "Audit",
    route: "audit",
  },
  {
    description: "Approve or reject exact pending inputs.",
    href: "#/approvals",
    icon: ClipboardCheck,
    label: "Approvals",
    route: "approvals",
  },
  {
    description: "Inspect one-use grants waiting for an external runner.",
    href: "#/authorized",
    icon: Terminal,
    label: "Runner queue",
    route: "authorized",
  },
  {
    description: "Review and edit local policy rules.",
    href: "#/policy",
    icon: ShieldAlert,
    label: "Policy",
    route: "policy",
  },
  {
    description: "Configure approval channels, MCP profiles, and local mocks.",
    href: "#/integrations",
    icon: Plug,
    label: "Integrations",
    route: "integrations",
  },
  {
    description:
      "Run the deterministic local lifecycle and optional ChatGPT tunnel.",
    href: "#/demo",
    icon: Beaker,
    label: "Quickstart",
    route: "demo",
  },
] as const;

export function Dashboard({
  data,
  error,
  lastSuccessfulRefreshAt,
  loading,
  onRefresh,
  snapshotState = "ready",
}: DashboardProps) {
  const route = useCommunityRoute();
  const [actionError, setActionError] = useState<string | null>(null);
  const waitingApproval = findWaitingApproval(data, route);

  useEffect(() => {
    const previousTitle = document.title;
    document.title = waitingApproval
      ? "Approval waiting · ActionProxy"
      : "ActionProxy — AI tool-call approval gateway";
    return () => {
      document.title = previousTitle;
    };
  }, [waitingApproval]);

  async function runAction(action: () => Promise<void>) {
    setActionError(null);
    try {
      await action();
      await onRefresh();
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : String(caught));
    }
  }

  return (
    <main className="dashboard-shell">
      <div className="dashboard-chrome">
        <header className="topbar">
          <div>
            <p className="eyebrow">ActionProxy Community</p>
            <h1>AI tool-call approval gateway</h1>
            <p className="topbar-subtitle">{routeTitle(route)}</p>
            <div className="environment-badges" aria-label="Gateway posture">
              <span>
                {data.health?.ok ? "Local server online" : "Server unavailable"}
              </span>
              <span>
                {data.policy
                  ? `Policy v${data.policy.version}`
                  : "Policy unavailable"}
              </span>
              <span>{data.pendingApprovals.length} pending</span>
            </div>
          </div>
          <div className="topbar-actions">
            <span
              className={`health-pill ${data.health?.ok ? "healthy" : "offline"}`}
            >
              {data.health?.ok ? "Server online" : "Server offline"}
            </span>
            <button
              className="icon-button"
              aria-label="Refresh gateway data"
              onClick={() => void onRefresh()}
              type="button"
            >
              <RefreshCw size={18} aria-hidden="true" />
            </button>
          </div>
        </header>

        <nav
          className="view-tabs"
          aria-label="Admin view"
          style={{ "--view-tab-count": navigation.length } as CSSProperties}
        >
          {navigation.map((item) => {
            const Icon = item.icon;
            const active =
              route.name === item.route ||
              (item.route === "approvals" && route.name === "approvalDetail");
            const count =
              item.route === "approvals" ? data.pendingApprovals.length : 0;
            return (
              <a
                aria-current={active ? "page" : undefined}
                className={active ? "active" : undefined}
                href={item.href}
                key={item.href}
                title={item.description}
              >
                <Icon size={18} aria-hidden="true" />
                <span>{item.label}</span>
                {count > 0 && (
                  <span
                    className="nav-badge"
                    aria-label={`${count} pending ${count === 1 ? "approval" : "approvals"}`}
                  >
                    {count}
                  </span>
                )}
              </a>
            );
          })}
        </nav>
      </div>

      {waitingApproval &&
        !(
          route.name === "approvalDetail" &&
          route.id === waitingApproval.approval.id
        ) && (
          <div className="quickstart-pending-banner" role="status">
            <div>
              <ShieldAlert size={18} aria-hidden="true" />
              <span>
                <strong>Action paused. Nothing has executed.</strong> Review the
                exact {waitingApproval.toolCall.toolName} proposal.
              </span>
            </div>
            <a
              href={approvalHref(
                waitingApproval.approval.id,
                waitingApproval.returnTo,
              )}
            >
              Review approval
            </a>
          </div>
        )}

      {loading && (
        <p className="loading-state" role="status">
          Refreshing gateway data…
        </p>
      )}
      {snapshotState === "recovered" && (
        <div className="snapshot-banner recovered" role="status">
          <ShieldCheck size={18} aria-hidden="true" />
          <span>
            Gateway connection restored. Tool calls, pending approvals, and
            audit evidence were reloaded.
          </span>
        </div>
      )}
      {(error || actionError) && (
        <div className="banner dashboard-error-banner" role="alert">
          <span>
            {snapshotState === "stale" && (
              <strong>
                Showing the last successful gateway snapshot
                {lastSuccessfulRefreshAt
                  ? ` from ${formatDate(lastSuccessfulRefreshAt)}`
                  : ""}{" "}
                while reconnecting.{" "}
              </strong>
            )}
            {error ?? actionError}
          </span>
          <button
            className="secondary"
            type="button"
            onClick={() => void onRefresh()}
          >
            <RefreshCw size={16} aria-hidden="true" /> Retry
          </button>
        </div>
      )}

      {route.name === "overview" && <Overview data={data} />}
      {route.name === "approvals" && <Approvals data={data} />}
      {route.name === "approvalDetail" && (
        <ApprovalDetail
          data={data}
          id={route.id}
          onAction={runAction}
          returnTarget={route.returnTarget}
        />
      )}
      {route.name === "authorized" && <RunnerQueue data={data} />}
      {route.name === "audit" && <AuditLog events={data.auditEvents} />}
      {route.name === "policy" && (
        <PolicyPage data={data} onAction={runAction} />
      )}
      {route.name === "integrations" && (
        <Integrations data={data} onAction={runAction} />
      )}
      {route.name === "demo" && (
        <DemoLab
          data={data}
          loading={loading}
          onRefresh={onRefresh}
          route={route}
        />
      )}
      {route.name === "toolCallDetail" && (
        <ToolCallDetail data={data} id={route.id} />
      )}
      {route.name === "notFound" && (
        <NotFound requestedPath={route.requestedPath} />
      )}
    </main>
  );
}

function Overview({ data }: { data: DashboardData }) {
  const lifecycle = lifecycleState(data);
  const profiles = mcpProfiles(data);
  const readyChannels =
    data.integrations?.approvalChannels?.items.filter(
      (channel) => channel.status === "ready",
    ).length ?? 0;
  return (
    <>
      <section
        className="overview-command-center"
        aria-label="Gateway overview"
      >
        <div className="command-copy">
          <span className="command-kicker">Developer preview</span>
          <h2>Control tool calls before they cause side effects</h2>
          <p>
            Run the deterministic lifecycle first. Connect an agent only after
            allow, approval, denial, and audit custody are clear.
          </p>
        </div>
        <div className="command-metrics">
          <Metric
            href="#/approvals"
            label="Pending approvals"
            value={data.pendingApprovals.length}
          />
          <Metric
            href="#/authorized"
            label="Runner grants"
            value={data.authorizedActions.length}
          />
          <Metric
            href="#/audit"
            label="Audit events"
            value={data.auditEvents.length}
          />
          <Metric
            href="#/policy"
            label="Policy rules"
            value={data.policy?.rules.length ?? 0}
          />
        </div>
      </section>

      <section
        className="setup-checklist"
        aria-labelledby="community-onboarding-heading"
      >
        <div className="setup-checklist-header">
          <div>
            <span className="command-kicker">Start here</span>
            <h2 id="community-onboarding-heading">
              Prove the gateway, then connect and harden it
            </h2>
          </div>
          <Status
            label={
              lifecycle.complete
                ? "Lifecycle complete"
                : lifecycle.approval
                  ? "Decision needed"
                  : "Ready to run"
            }
            tone={
              lifecycle.complete
                ? "good"
                : lifecycle.approval
                  ? "pending"
                  : "neutral"
            }
          />
        </div>
        <div className="setup-goal-list">
          <SetupGoal
            index={1}
            title="Run the lifecycle"
            description="No external account or credential is required."
          >
            <SetupLink
              href={
                lifecycle.approval
                  ? `#/approvals/${encodeURIComponent(lifecycle.approval.id)}`
                  : "#/demo?journey=local"
              }
              label={
                lifecycle.complete
                  ? "Lifecycle complete"
                  : lifecycle.approval
                    ? "Review the paused email"
                    : "Run the guided demo"
              }
              description={
                lifecycle.approval
                  ? "Paused as designed—no email was sent."
                  : "Prove immediate allow, approval custody, and destructive denial."
              }
              tone={
                lifecycle.complete
                  ? "complete"
                  : lifecycle.approval
                    ? "needs-action"
                    : "recommended"
              }
            />
            <SetupLink
              href="#/audit"
              label="Inspect audit evidence"
              description={`${data.auditEvents.length} append-only events are available.`}
              tone={data.auditEvents.length ? "complete" : "recommended"}
            />
          </SetupGoal>
          <SetupGoal
            index={2}
            title="Connect an agent or host"
            description="Choose one host path; ChatGPT is optional."
          >
            <SetupLink
              href="#/authorized"
              label="SDK or external runner"
              description="Use proxy mode and one-use execution grants."
              tone={data.authorizedActions.length ? "complete" : "recommended"}
            />
            <SetupLink
              href="#/integrations"
              label="Generic MCP wrapper"
              description={
                profiles.length
                  ? `${profiles.length} profile configured.`
                  : "Create a profile and discover downstream tools."
              }
              tone={profiles.length ? "complete" : "recommended"}
            />
            <SetupLink
              href="#/demo?journey=chatgpt"
              label="Secure MCP Tunnel"
              description="Optionally connect the exact three-tool fixture to ChatGPT."
              tone={hasTunnelActivity(data) ? "complete" : "recommended"}
            />
          </SetupGoal>
          <SetupGoal
            index={3}
            title="Harden self-hosting"
            description="Replace local demo defaults before production evaluation."
          >
            <SetupLink
              href="#/audit"
              label="Durable storage"
              description="Use SQLite or Postgres, then confirm approvals and audit evidence survive restart."
              tone="recommended"
            />
            <SetupLink
              href="#/policy"
              label="Authentication"
              description="Require scoped access before exposing the console or API beyond loopback."
              tone="recommended"
            />
            <SetupLink
              href="#/integrations"
              label="Approval channels"
              description={
                readyChannels
                  ? `${readyChannels} channel ready.`
                  : "The web queue is built in; external channels are optional."
              }
              tone={readyChannels ? "complete" : "recommended"}
            />
            <SetupLink
              href="#/audit"
              label="Audit verification"
              description="Verify the append-only hash chain after restart and before relying on exported evidence."
              tone="recommended"
            />
          </SetupGoal>
        </div>
      </section>

      <section
        className="panel page-panel"
        aria-labelledby="recent-calls-heading"
      >
        <PanelHeading
          icon={<Activity size={18} />}
          title="Recent governed tool calls"
          id="recent-calls-heading"
        />
        <ToolCallTable calls={data.toolCalls.slice(0, 12)} />
      </section>
    </>
  );
}

function Metric({
  href,
  label,
  value,
}: {
  href: string;
  label: string;
  value: number;
}) {
  return (
    <a className="command-metric neutral" href={href}>
      <strong>{value}</strong>
      <span>{label}</span>
    </a>
  );
}

function SetupGoal({
  children,
  description,
  index,
  title,
}: {
  children: ReactNode;
  description: string;
  index: number;
  title: string;
}) {
  return (
    <section className="setup-goal" aria-labelledby={`setup-goal-${index}`}>
      <div className="setup-goal-heading">
        <span aria-hidden="true">{index}</span>
        <div>
          <h3 id={`setup-goal-${index}`}>{title}</h3>
          <p>{description}</p>
        </div>
      </div>
      <div className="setup-checklist-grid">{children}</div>
    </section>
  );
}

function SetupLink({
  description,
  href,
  label,
  tone,
}: {
  description: string;
  href: string;
  label: string;
  tone: "complete" | "needs-action" | "recommended";
}) {
  return (
    <a className={`setup-checklist-item ${tone}`} href={href}>
      <span className="setup-checklist-icon">
        <Check size={18} aria-hidden="true" />
      </span>
      <span>
        <strong>{label}</strong>
        <small>{description}</small>
      </span>
    </a>
  );
}

function Approvals({ data }: { data: DashboardData }) {
  return (
    <section
      className="panel page-panel"
      aria-labelledby="pending-approvals-heading"
    >
      <PanelHeading
        icon={<ClipboardCheck size={18} />}
        id="pending-approvals-heading"
        title="Pending approvals"
      />
      {data.pendingApprovals.length ? (
        <div className="approval-list">
          {data.pendingApprovals.map((approval) => {
            const call = data.toolCalls.find(
              (candidate) => candidate.id === approval.toolCallId,
            );
            return (
              <a
                className="approval-item"
                href={`#/approvals/${encodeURIComponent(approval.id)}`}
                key={approval.id}
              >
                <div>
                  <strong>{call?.toolName ?? approval.toolCallId}</strong>
                  <p>{call?.reason ?? "Review exact proposed input."}</p>
                </div>
                <Status label="Needs decision" tone="pending" />
              </a>
            );
          })}
        </div>
      ) : (
        <Empty
          title="No approvals waiting"
          body="Approval-required calls appear here before execution."
        />
      )}
    </section>
  );
}

function ApprovalDetail({
  data,
  id,
  onAction,
  returnTarget,
}: {
  data: DashboardData;
  id: string;
  onAction: (action: () => Promise<void>) => Promise<void>;
  returnTarget?: QuickstartReturnTarget;
}) {
  const listed = data.pendingApprovals.find((approval) => approval.id === id);
  const [record, setRecord] = useState<{
    approval: ApprovalRecord;
    toolCall: ToolCallRecord;
  } | null>(null);
  const [review, setReview] = useState<ApprovalReview | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reviewLoading, setReviewLoading] = useState(true);
  const completedRecord =
    record && record.approval.status !== "pending" ? record : null;
  const approval = completedRecord?.approval ?? listed ?? record?.approval;
  const toolCall =
    completedRecord?.toolCall ??
    data.toolCalls.find((call) => call.id === approval?.toolCallId) ??
    record?.toolCall;
  const [inputText, setInputText] = useState("");
  const [actor, setActor] = useState("local-reviewer@example.com");
  const [reason, setReason] = useState("");
  const [decisionState, setDecisionState] = useState<
    "idle" | "composing_rejection" | "approving" | "rejecting"
  >("idle");
  const [completedDecision, setCompletedDecision] = useState<
    "approved" | "rejected" | null
  >(null);
  const [proposedInputHash, setProposedInputHash] = useState<string>();

  const loadReview = useCallback(async () => {
    setReviewLoading(true);
    setLoadError(null);
    try {
      const [nextRecord, nextReview] = await Promise.all([
        fetchApproval(id),
        fetchApprovalReview(id),
      ]);
      setRecord(nextRecord);
      setReview(nextReview);
    } catch (caught) {
      setLoadError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setReviewLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void loadReview();
  }, [loadReview]);

  useEffect(() => {
    if (approval && !inputText)
      setInputText(prettyJson(approval.editedInput ?? approval.originalInput));
  }, [approval, inputText]);

  useEffect(() => {
    const parsed = parseJsonObject(inputText);
    if (!parsed.ok) {
      setProposedInputHash(undefined);
      return;
    }
    let active = true;
    void hashJsonForDisplay(parsed.value).then((hash) => {
      if (active) setProposedInputHash(hash);
    });
    return () => {
      active = false;
    };
  }, [inputText]);

  async function reconcileRecordedDecision() {
    try {
      const [nextRecord, nextReview] = await Promise.all([
        fetchApproval(id),
        fetchApprovalReview(id),
      ]);
      setRecord(nextRecord);
      setReview(nextReview);
      if (
        nextRecord.approval.status === "approved" &&
        !isTerminalToolCallStatus(nextRecord.toolCall.status)
      ) {
        const terminal = await pollApprovalOutcome(id, nextRecord, setRecord);
        if (terminal.toolCall.status === "executed")
          setCompletedDecision("approved");
        return terminal;
      }
      if (
        nextRecord.approval.status === "approved" &&
        nextRecord.toolCall.status === "executed"
      )
        setCompletedDecision("approved");
      if (nextRecord.approval.status === "rejected")
        setCompletedDecision("rejected");
      return nextRecord;
    } catch (caught) {
      setLoadError(caught instanceof Error ? caught.message : String(caught));
      return null;
    }
  }

  async function approve() {
    if (!approval || !review || review.freshness.state === "stale") return;
    const parsed = parseJsonObject(inputText);
    if (!parsed.ok) {
      setLoadError(parsed.error);
      return;
    }
    const edited =
      JSON.stringify(parsed.value) !== JSON.stringify(approval.originalInput);
    setDecisionState("approving");
    let submitted:
      | { approval: ApprovalRecord; toolCall: ToolCallRecord }
      | undefined;
    await onAction(async () => {
      submitted = await approveApproval(approval.id, {
        approvedBy: actor,
        editedInput: edited ? parsed.value : undefined,
        inputDecision: edited
          ? { input: parsed.value, mode: "edited" }
          : { mode: "original" },
        reviewHash: review?.reviewHash,
      });
    });
    if (!submitted) {
      const reconciled = await reconcileRecordedDecision();
      if (reconciled?.approval.status === "pending")
        setLoadError(
          "The proposal is still pending. Refresh the review and try again.",
        );
      setDecisionState("idle");
      return;
    }
    let nextRecord = submitted;
    setRecord(nextRecord);
    if (
      nextRecord.approval.status === "approved" &&
      !isTerminalToolCallStatus(nextRecord.toolCall.status)
    ) {
      nextRecord = await pollApprovalOutcome(
        approval.id,
        nextRecord,
        setRecord,
      );
    }
    if (
      nextRecord.approval.status === "approved" &&
      nextRecord.toolCall.status === "executed"
    ) {
      setCompletedDecision("approved");
    } else if (nextRecord.toolCall.status === "failed") {
      setLoadError(
        "Approval was recorded, but tool execution failed. Inspect the audit evidence before retrying.",
      );
    }
    setDecisionState("idle");
  }

  async function reject() {
    if (
      !approval ||
      !review ||
      !reason.trim() ||
      review.freshness.state === "stale"
    )
      return;
    setDecisionState("rejecting");
    let submitted:
      | { approval: ApprovalRecord; toolCall: ToolCallRecord }
      | undefined;
    await onAction(async () => {
      submitted = await rejectApproval(approval.id, {
        reason: reason.trim(),
        rejectedBy: actor,
      });
    });
    if (!submitted) {
      const reconciled = await reconcileRecordedDecision();
      if (reconciled?.approval.status === "pending") {
        setLoadError(
          "The proposal is still pending. Refresh the review and try again.",
        );
        setDecisionState("composing_rejection");
      } else {
        setDecisionState("idle");
      }
      return;
    }
    setRecord(submitted);
    if (submitted.approval.status === "rejected") {
      setCompletedDecision("rejected");
    }
    setDecisionState("idle");
  }

  useEffect(() => {
    if (!completedDecision || !toolCall || !isQuickstartCall(toolCall)) return;
    const target = returnTarget
      ? quickstartReturnHref(returnTarget)
      : quickstartHref(toolCall);
    const timeout = window.setTimeout(() => {
      window.location.hash = target;
    }, 3_500);
    return () => window.clearTimeout(timeout);
  }, [completedDecision, returnTarget, toolCall]);

  if (loadError && !approval) return <ErrorState message={loadError} />;
  if (!approval || !toolCall) return <p role="status">Loading approval…</p>;

  const isEmail = toolCall.toolName === "gmail.send_email";
  const demoOrigin = isQuickstartCall(toolCall);
  const parsedInput = parseJsonObject(inputText);
  const proposedInput = parsedInput.ok
    ? parsedInput.value
    : approval.originalInput;
  const edited =
    JSON.stringify(proposedInput) !== JSON.stringify(approval.originalInput);
  const stale = review?.freshness.state === "stale";
  const decisionsDisabled =
    approval.status !== "pending" ||
    !review ||
    Boolean(stale) ||
    reviewLoading ||
    decisionState === "approving" ||
    decisionState === "rejecting";
  const resolvedDecision =
    completedDecision ??
    (approval.status === "rejected"
      ? "rejected"
      : approval.status === "approved" && toolCall.status === "executed"
        ? "approved"
        : null);
  const sourceLabel =
    review?.actionEnvelope?.source.name ??
    review?.actionEnvelope?.agent.name ??
    toolCall.agentId;
  const destinationLabel =
    review?.actionEnvelope?.executionMode === "local_mock" ||
    toolCall.metadata?.demo
      ? "Local mock email tool"
      : toolCall.toolName;
  const sourceChain = isTunnelCall(toolCall)
    ? ["Quickstart MCP request", "ActionProxy"]
    : [sourceLabel, "ActionProxy", destinationLabel];

  return (
    <section
      className="panel page-panel approval-detail"
      aria-labelledby="approval-detail-heading"
    >
      <PanelHeading
        icon={<ClipboardCheck size={18} />}
        id="approval-detail-heading"
        title={isEmail ? "Review the proposed email" : "Review proposed action"}
      />
      {loadError && (
        <p className="field-error" role="alert">
          {loadError}
        </p>
      )}
      <div className="record-title">
        <div>
          <code>{toolCall.toolName}</code>
          <p>{toolCall.reason}</p>
        </div>
        <Status
          label={
            approval.status === "pending"
              ? "Waiting for your decision"
              : approval.status
          }
          tone={
            approval.status === "approved"
              ? "good"
              : approval.status === "pending"
                ? "pending"
                : "bad"
          }
        />
      </div>
      {approval.status === "pending" && (
        <div className="approval-safety-note" role="status">
          <ShieldAlert size={19} aria-hidden="true" />
          <span>
            <strong>Nothing has executed yet.</strong> ActionProxy paused this
            exact proposal before {destinationLabel} ran.
          </span>
        </div>
      )}
      <div className="approval-source-chain" aria-label="Proposal source chain">
        {sourceChain.map((step, index) => (
          <Fragment key={`${step}-${index}`}>
            {index > 0 && (
              <span className="approval-source-arrow" aria-hidden="true">
                →
              </span>
            )}
            <span className="approval-source-node">{step}</span>
          </Fragment>
        ))}
      </div>
      {isEmail && (
        <section
          className="email-approval-preview"
          aria-labelledby="email-preview-heading"
        >
          <div className="email-preview-heading">
            <h2 id="email-preview-heading">Email waiting for review</h2>
            {edited && (
              <Status label="Edited in technical details" tone="pending" />
            )}
          </div>
          <dl>
            <div>
              <dt>To</dt>
              <dd>{readableInputValue(proposedInput.to)}</dd>
            </div>
            <div>
              <dt>Subject</dt>
              <dd>{readableInputValue(proposedInput.subject)}</dd>
            </div>
            <div className="email-body-field">
              <dt>Body</dt>
              <dd>{readableInputValue(proposedInput.body)}</dd>
            </div>
          </dl>
        </section>
      )}
      <section
        className="approval-policy-reason"
        aria-labelledby="approval-policy-heading"
      >
        <h2 id="approval-policy-heading">Why approval is required</h2>
        <p>
          {review?.policy.reason ??
            toolCall.policyReason ??
            "Policy requires a human decision before this tool can execute."}
        </p>
        <small>
          Risk: {review?.policy.risk ?? toolCall.risk ?? "not classified"} ·
          Agent rationale (untrusted): {toolCall.reason}
        </small>
      </section>
      {review && review.freshness.state !== "fresh" && (
        <div
          className={`approval-freshness ${review.freshness.state}`}
          role={review.freshness.state === "stale" ? "alert" : "status"}
        >
          <div>
            <strong>
              {review.freshness.state === "stale"
                ? "This review is stale. Decisions are disabled."
                : "Review conditions changed—check these warnings."}
            </strong>
            <ul>
              {review.freshness.warnings.map((warning) => (
                <li key={warning.code}>{warning.message}</li>
              ))}
            </ul>
          </div>
          <button
            className="secondary"
            disabled={reviewLoading}
            onClick={() => void loadReview()}
            type="button"
          >
            <RefreshCw size={16} aria-hidden="true" />
            {reviewLoading ? "Refreshing…" : "Refresh review"}
          </button>
        </div>
      )}
      {resolvedDecision && (
        <div className={`approval-result ${resolvedDecision}`} role="status">
          <div>
            {resolvedDecision === "approved" ? (
              <Check size={18} aria-hidden="true" />
            ) : (
              <ShieldAlert size={18} aria-hidden="true" />
            )}
            <span>
              <strong>
                {resolvedDecision === "approved"
                  ? toolCall.status === "executed"
                    ? "Executed successfully exactly once."
                    : "Approved; waiting for terminal execution."
                  : "Rejected. Nothing was sent."}
              </strong>{" "}
              {resolvedDecision === "approved"
                ? "ActionProxy preserved the reviewed input and recorded the outcome."
                : "ActionProxy closed the proposal without downstream execution."}
            </span>
          </div>
          {demoOrigin && (
            <>
              <a
                className="button-link"
                href={
                  returnTarget
                    ? quickstartReturnHref(returnTarget)
                    : quickstartHref(toolCall)
                }
              >
                Return now
              </a>
              {completedDecision && <small>Returning automatically…</small>}
            </>
          )}
        </div>
      )}
      {approval.status === "approved" && !resolvedDecision && (
        <div className="approval-result pending" role="status">
          <div>
            <RefreshCw size={18} aria-hidden="true" />
            <span>
              <strong>
                {isTunnelCall(toolCall)
                  ? "Approved; the MCP client is finishing the mock call"
                  : "Approved; ActionProxy is finishing the mock call"}
              </strong>{" "}
              Authorized is not the same as executed; this page is polling for
              the terminal result.
            </span>
          </div>
        </div>
      )}
      {(approval.status === "cancelled" || approval.status === "expired") && (
        <div className="approval-result rejected" role="status">
          <div>
            <ShieldAlert size={18} aria-hidden="true" />
            <span>
              <strong>Proposal {approval.status}. Nothing executed.</strong>{" "}
              Reload the originating workflow before proposing another action.
            </span>
          </div>
          {demoOrigin && (
            <a
              className="button-link"
              href={
                returnTarget
                  ? quickstartReturnHref(returnTarget)
                  : quickstartHref(toolCall)
              }
            >
              Return now
            </a>
          )}
        </div>
      )}
      {approval.status === "pending" && (
        <div
          className="approval-form"
          aria-busy={
            decisionState === "approving" || decisionState === "rejecting"
          }
        >
          <label>
            Decision recorded as
            <input
              aria-label="Decision actor"
              value={actor}
              onChange={(event) => setActor(event.target.value)}
            />
          </label>
          <div className="form-actions">
            <button
              type="button"
              disabled={!actor.trim() || decisionsDisabled}
              onClick={() => void approve()}
            >
              <Check size={18} aria-hidden="true" />
              {decisionState === "approving"
                ? "Approving…"
                : edited
                  ? "Approve edited proposal"
                  : "Approve exact proposal"}
            </button>
            <button
              className="secondary danger-action"
              type="button"
              disabled={!actor.trim() || decisionsDisabled}
              onClick={() => setDecisionState("composing_rejection")}
            >
              Reject
            </button>
          </div>
          {decisionState === "composing_rejection" ||
          decisionState === "rejecting" ? (
            <form
              className="approval-rejection-panel"
              onSubmit={(event) => {
                event.preventDefault();
                void reject();
              }}
            >
              <label>
                Why are you rejecting this proposal?
                <input
                  aria-label="Rejection reason"
                  autoFocus
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                />
              </label>
              <div className="form-actions">
                <button
                  className="danger-confirm"
                  disabled={!reason.trim() || decisionState === "rejecting"}
                  type="submit"
                >
                  {decisionState === "rejecting"
                    ? "Rejecting…"
                    : "Confirm rejection"}
                </button>
                <button
                  className="secondary"
                  disabled={decisionState === "rejecting"}
                  onClick={() => setDecisionState("idle")}
                  type="button"
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : null}
        </div>
      )}
      <details className="approval-technical-details">
        <summary>Technical details and integrity evidence</summary>
        <section
          className="payload-section"
          aria-labelledby="approval-input-heading"
        >
          <h2 id="approval-input-heading">Approval input comparison</h2>
          <div className="approval-input-comparison">
            <article className="payload-compare-card">
              <strong>Original input</strong>
              <pre>{prettyJson(approval.originalInput)}</pre>
              <small>
                Input hash:{" "}
                {approval.originalInputHash ??
                  toolCall.inputHash ??
                  "not recorded"}
              </small>
            </article>
            <article className="payload-compare-card">
              <strong>Proposed approved input</strong>
              <textarea
                aria-label="Approved input JSON"
                disabled={approval.status !== "pending"}
                value={inputText}
                onChange={(event) => setInputText(event.target.value)}
              />
              <small>Edits are retained beside the original payload.</small>
              <small>
                {edited ? "Edited" : "Proposed"} input hash:{" "}
                {approval.approvedInputHash ??
                  proposedInputHash ??
                  "computed when submitted"}
              </small>
            </article>
          </div>
          <dl className="detail-grid approval-evidence-grid">
            <div>
              <dt>Approval</dt>
              <dd>{approval.id}</dd>
            </div>
            <div>
              <dt>Tool call</dt>
              <dd>{toolCall.id}</dd>
            </div>
            <div>
              <dt>Review hash</dt>
              <dd>{review?.reviewHash ?? "loading"}</dd>
            </div>
            <div>
              <dt>Envelope hash</dt>
              <dd>
                {review?.actionEnvelope?.envelopeHash ??
                  toolCall.actionEnvelopeHash ??
                  "not recorded"}
              </dd>
            </div>
            <div>
              <dt>Protocol</dt>
              <dd>{review?.actionEnvelope?.protocol ?? "not recorded"}</dd>
            </div>
            <div>
              <dt>Execution mode</dt>
              <dd>{review?.actionEnvelope?.executionMode ?? "not recorded"}</dd>
            </div>
          </dl>
        </section>
        {toolCall.contentInfluence && (
          <ContentInfluence evidence={toolCall.contentInfluence} />
        )}
      </details>
    </section>
  );
}

function ContentInfluence({
  evidence,
}: {
  evidence: NonNullable<ToolCallRecord["contentInfluence"]>;
}) {
  return (
    <section
      className="content-influence-panel"
      aria-labelledby="content-influence-heading"
    >
      <h2 id="content-influence-heading">Content influence</h2>
      <p>
        Observed source integrity changed the decision from{" "}
        <strong>{evidence.baseDecision}</strong> to{" "}
        <strong>{evidence.effectiveDecision}</strong>.
      </p>
      <p>
        Sources: {evidence.observedSources.join(", ") || "none"} · Scope{" "}
        {evidence.influenceScope.verified ? "verified" : "unverified"}
      </p>
    </section>
  );
}

function readableInputValue(value: unknown): string {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  return "Not provided";
}

function isTerminalToolCallStatus(status: ToolCallRecord["status"]): boolean {
  return ["blocked", "executed", "failed", "rejected"].includes(status);
}

async function pollApprovalOutcome(
  approvalId: string,
  initial: { approval: ApprovalRecord; toolCall: ToolCallRecord },
  onUpdate: (record: {
    approval: ApprovalRecord;
    toolCall: ToolCallRecord;
  }) => void,
): Promise<{ approval: ApprovalRecord; toolCall: ToolCallRecord }> {
  let current = initial;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (isTerminalToolCallStatus(current.toolCall.status)) return current;
    await new Promise((resolve) => window.setTimeout(resolve, 500));
    try {
      current = await fetchApproval(approvalId);
      onUpdate(current);
    } catch {
      // The dashboard also refreshes on focus and every five seconds. Keep the
      // last authoritative record and let the operator retry a manual refresh.
    }
  }
  return current;
}

function RunnerQueue({ data }: { data: DashboardData }) {
  return (
    <section className="panel page-panel" aria-labelledby="runner-heading">
      <PanelHeading
        icon={<Terminal size={18} />}
        id="runner-heading"
        title="External runner queue"
      />
      {data.authorizedActions.length ? (
        <div className="authorized-action-list">
          {data.authorizedActions.map((entry) => (
            <article className="authorized-action-card" key={entry.grant.id}>
              <div className="record-title">
                <code>{entry.toolCall.toolName}</code>
                <Status
                  label={entry.status}
                  tone={
                    entry.status === "failed" || entry.status === "expired"
                      ? "bad"
                      : entry.status === "waiting"
                        ? "pending"
                        : "good"
                  }
                />
              </div>
              <dl className="detail-grid">
                <div>
                  <dt>Grant</dt>
                  <dd>{entry.grant.id}</dd>
                </div>
                <div>
                  <dt>Expires</dt>
                  <dd>{formatDate(entry.grant.expiresAt)}</dd>
                </div>
                <div>
                  <dt>Tool call</dt>
                  <dd>
                    <a
                      href={`#/tool-calls/${encodeURIComponent(entry.toolCall.id)}`}
                    >
                      {entry.toolCall.id}
                    </a>
                  </dd>
                </div>
              </dl>
            </article>
          ))}
        </div>
      ) : (
        <Empty
          title="No runner grants"
          body="Authorized external actions appear here until consumed or expired."
        />
      )}
    </section>
  );
}

function AuditLog({ events }: { events: AuditEvent[] }) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const groups = useMemo(() => groupAudit(events, query), [events, query]);
  return (
    <section
      className="panel page-panel audit-page"
      aria-labelledby="audit-heading"
    >
      <PanelHeading
        icon={<History size={18} />}
        id="audit-heading"
        title="Audit log"
      />
      <div className="audit-toolbar">
        <label>
          Audit search
          <input
            aria-label="Audit search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Tool call, approval, actor, or event"
          />
        </label>
        <div className="link-row">
          <a className="text-link" href={buildAuditExportUrl("json")}>
            Export JSON
          </a>
          <a className="text-link" href={buildAuditExportUrl("siem")}>
            Export SIEM
          </a>
        </div>
      </div>
      {groups.length ? (
        <div className="audit-group-list">
          {groups.map((group) => {
            const expanded = open.has(group.id);
            return (
              <article className="audit-group" key={group.id}>
                <div className="audit-group-header">
                  <div>
                    <strong>{group.id}</strong>
                    <span>
                      {group.events.length} lifecycle{" "}
                      {group.events.length === 1 ? "event" : "events"}
                    </span>
                  </div>
                  <button
                    aria-expanded={expanded}
                    className="secondary"
                    onClick={() =>
                      setOpen((current) => toggleSet(current, group.id))
                    }
                    type="button"
                  >
                    {expanded
                      ? "Hide events"
                      : `Show ${group.events.length} ${group.events.length === 1 ? "event" : "events"}`}
                  </button>
                </div>
                {expanded && (
                  <div className="audit-timeline">
                    {group.events.map((event) => (
                      <details className="timeline-event" key={event.id}>
                        <summary>
                          <code>{event.type}</code>
                          <span>{formatDate(event.timestamp)}</span>
                        </summary>
                        <pre>{prettyJson(event)}</pre>
                      </details>
                    ))}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      ) : (
        <Empty
          title="No matching audit events"
          body={
            query
              ? "Clear the search or wait for new lifecycle evidence."
              : "Events appear after the first tool call."
          }
        />
      )}
    </section>
  );
}

function PolicyPage({
  data,
  onAction,
}: {
  data: DashboardData;
  onAction: (action: () => Promise<void>) => Promise<void>;
}) {
  const profiles = mcpProfiles(data);
  return (
    <PolicyEditor
      approvers={data.approvers}
      discoveredTools={profiles.flatMap((profile) => profile.discoveredTools)}
      notificationChannels={data.integrations?.approvalChannels?.items ?? []}
      observedTools={data.policyDetector?.tools ?? []}
      onAction={onAction}
      policyFile={data.policyFile}
      policySummary={data.policy}
    />
  );
}

function Integrations({
  data,
  onAction,
}: {
  data: DashboardData;
  onAction: (action: () => Promise<void>) => Promise<void>;
}) {
  const profiles = mcpProfiles(data);
  const tools =
    data.integrations?.localDemoTools ?? data.integrations?.tools ?? [];
  const channels = data.integrations?.approvalChannels?.items ?? [];
  return (
    <div className="integrations-layout">
      <section
        className="integration-section"
        aria-labelledby="channels-heading"
      >
        <PanelHeading
          icon={<Bell size={18} />}
          id="channels-heading"
          title="Approval channels"
        />
        {channels.length ? (
          <div className="approval-channel-list">
            {channels.map((channel) => (
              <article className="approval-channel-card" key={channel.id}>
                <div className="record-title">
                  <strong>{channel.displayName}</strong>
                  <Status
                    label={channel.status}
                    tone={
                      channel.status === "ready"
                        ? "good"
                        : channel.enabled
                          ? "pending"
                          : "neutral"
                    }
                  />
                </div>
                <p>{channel.description}</p>
              </article>
            ))}
          </div>
        ) : (
          <Empty
            title="Web approval queue is available"
            body="External notification channels are optional for the local lifecycle."
          />
        )}
      </section>
      <section
        className="integration-section"
        aria-labelledby="approvers-heading"
      >
        <PanelHeading
          icon={<ClipboardCheck size={18} />}
          id="approvers-heading"
          title="Approvers"
        />
        {data.approvers?.users.length ? (
          <ul>
            {data.approvers.users.map((user) => (
              <li key={user.id}>
                {user.displayName}
                {user.email ? ` · ${user.email}` : ""}
              </li>
            ))}
          </ul>
        ) : (
          <p className="empty">
            No explicit approver directory is configured; local policy defaults
            apply.
          </p>
        )}
      </section>
      <details className="integration-section integration-disclosure developer-sources-section">
        <summary>
          <PanelHeading
            icon={<Terminal size={18} />}
            id="mcp-heading"
            title="Downstream MCP wrapper"
          />
        </summary>
        <div className="integration-disclosure-content">
          {profiles.length ? (
            <div className="mcp-profile-list">
              {profiles.map((profile) => (
                <article className="mcp-profile-card" key={profile.id}>
                  <strong>{profile.name ?? profile.id}</strong>
                  <code>{profile.server.command}</code>
                  <span>{profile.discoveredTools.length} discovered tools</span>
                </article>
              ))}
            </div>
          ) : (
            <Empty
              title="No MCP profiles"
              body="Create a wrapper profile through the integration API, then sync tools/list metadata."
            />
          )}
        </div>
      </details>
      <details className="integration-section integration-disclosure demo-tools-section">
        <summary>
          <PanelHeading
            icon={<Database size={18} />}
            id="mock-tools-heading"
            title="Local mock demo tools"
          />
        </summary>
        <ToolIntegrationsCard
          integrations={tools}
          onAction={onAction}
          showHeading={false}
        />
      </details>
    </div>
  );
}

function DemoLab({
  data,
  loading,
  onRefresh,
  route,
}: {
  data: DashboardData;
  loading: boolean;
  onRefresh: () => Promise<void> | void;
  route: Extract<CommunityRoute, { name: "demo" }>;
}) {
  const journey = route.journey ?? "local";
  const [localProofReady, setLocalProofReady] = useState(false);
  const localQuickstart = useQuickstartStatus(
    journey === "local" ? route.sessionId : undefined,
  );
  const localStatus =
    localQuickstart.status?.journey === "local" &&
    localQuickstart.status.sessionId === route.sessionId
      ? localQuickstart.status
      : null;
  useEffect(() => {
    setLocalProofReady(false);
  }, [journey, route.sessionId]);
  const localReturnToBase = route.sessionId
    ? `#/demo?journey=local&session=${encodeURIComponent(route.sessionId)}`
    : "#/demo?journey=local";
  const localReturnTo = route.guided
    ? `${localReturnToBase}&guided=1`
    : localReturnToBase;
  return (
    <>
      <section
        className="panel quickstart-chooser"
        aria-labelledby="quickstart-heading"
      >
        <div>
          <span className="command-kicker">First-run companion</span>
          <h2 id="quickstart-heading">
            {route.sessionId
              ? "What do you want to prove?"
              : "See ActionProxy control a tool call"}
          </h2>
          <p>
            Everything here is local and simulated. No email is sent, no
            customer is changed, and no SaaS account is connected.
          </p>
        </div>
        <div className="quickstart-choice-grid">
          <a
            aria-current={journey === "local" ? "step" : undefined}
            className={journey === "local" ? "active" : undefined}
            href={
              journey === "local" && route.sessionId
                ? `#/demo?journey=local&session=${encodeURIComponent(route.sessionId)}`
                : "#/demo?journey=local"
            }
          >
            <strong>Run the local proof</strong>
            <span>No account or credential</span>
            <small>Allow → human approval → deny</small>
          </a>
          <a
            aria-current={journey === "chatgpt" ? "step" : undefined}
            className={journey === "chatgpt" ? "active" : undefined}
            href={
              journey === "chatgpt" && route.sessionId
                ? `#/demo?journey=chatgpt&session=${encodeURIComponent(route.sessionId)}`
                : "#/demo?journey=chatgpt"
            }
          >
            <strong>Connect ChatGPT</strong>
            <span>Secure MCP Tunnel · eligible workspace required</span>
            <small>Live external-host proof</small>
          </a>
        </div>
      </section>
      <section className="demo-lab-notice" aria-label="Local demo notice">
        <span>
          <Beaker size={18} aria-hidden="true" />
          Mock-only quickstart
        </span>
        <strong>
          Nothing here sends a real email or deletes a customer. Local
          unauthenticated mode is not a production identity boundary.
        </strong>
      </section>
      {journey === "local" ? (
        <>
          {route.sessionId && (
            <LocalQuickstartCompanion
              quickstart={localQuickstart}
              sessionId={route.sessionId}
              status={localStatus}
            />
          )}
          <AgentDemoPanel
            data={data}
            guided={route.guided}
            key={`local-proof-${route.sessionId ?? "legacy"}`}
            loading={
              loading ||
              Boolean(
                route.sessionId && (localQuickstart.loading || !localStatus),
              )
            }
            onProofStateChange={setLocalProofReady}
            onRefresh={onRefresh}
            returnTo={localReturnTo}
            sessionId={route.sessionId}
            sessionStartedAt={localStatus?.startedAt}
          />
          <QuickstartAuditProof ready={localProofReady} />
        </>
      ) : (
        <ChatGptTunnelPanel
          data={data}
          onRefresh={onRefresh}
          sessionId={route.sessionId}
        />
      )}
    </>
  );
}

function LocalQuickstartCompanion({
  quickstart,
  sessionId,
  status,
}: {
  quickstart: ReturnType<typeof useQuickstartStatus>;
  sessionId: string;
  status: QuickstartStatus | null;
}) {
  return (
    <div className="local-quickstart-runtime">
      <QuickstartRuntimeStatus
        error={
          quickstart.status && quickstart.status.journey !== "local"
            ? "This companion session belongs to a different Quickstart journey."
            : quickstart.error
        }
        loading={quickstart.loading}
        status={status}
      />
      {!quickstart.loading && !status && !quickstart.error && (
        <div className="quickstart-runtime-status failed" role="status">
          <ShieldAlert size={18} aria-hidden="true" />
          No live local companion status was found. Rerun{" "}
          <code>./actionproxy local</code>.
        </div>
      )}
    </div>
  );
}

const tunnelIdPattern = /^tunnel_[0-9a-f]{32}$/u;
const quickstartSessionIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const tunnelPrompts = [
  [
    "Allowed search",
    "Use ActionProxy to search the demo docs for the refund policy.",
  ],
  [
    "Approval-required email",
    'Use ActionProxy to send a demo email to customer@example.com with subject "Refund update" and body "Your request is ready." Wait while I approve it in ActionProxy.',
  ],
  [
    "Denied deletion",
    "Use ActionProxy to delete customer cus_123 as a policy test.",
  ],
] as const;
const tunnelTools = [
  ["docs.search", "Allowed and executed immediately"],
  ["gmail.send_email", "Paused for ActionProxy approval"],
  ["dangerous.delete_customer", "Denied before downstream execution"],
] as const;
const firstRunCommand = "./actionproxy chatgpt";
const tunnelClientDoctorCommand = "./actionproxy doctor --chatgpt";
const tunnelClientRemoveCommand = "./actionproxy tunnel-client remove";
const chatGptProofStartStoragePrefix =
  "actionproxy.quickstart.chatgpt.proof-start.";
const adminAccessRequest =
  "I’m testing ActionProxy locally with OpenAI Secure MCP Tunnel. Please allow developer mode in the target ChatGPT workspace, grant my Platform account Tunnels Read + Use, and associate the test tunnel with that workspace. The demonstration exposes only three simulated tools and connects no production systems.";

function ChatGptTunnelPanel({
  data,
  onRefresh,
  sessionId,
}: {
  data: DashboardData;
  onRefresh: () => Promise<void> | void;
  sessionId?: string;
}) {
  const [tunnelId, setTunnelId] = useState("");
  const [copied, setCopied] = useState("");
  const [auditVerified, setAuditVerified] = useState(false);
  const [attemptedPrompt, setAttemptedPrompt] = useState<{
    index: number;
    nonce: number;
  } | null>(null);
  const [recoveryIndex, setRecoveryIndex] = useState<number | null>(null);
  const [proofStartedAt, setProofStartedAt] = useState<string | null>(() =>
    readChatGptProofStart(sessionId),
  );
  const quickstart = useQuickstartStatus(sessionId);
  const statusMismatch = Boolean(
    quickstart.status &&
    (quickstart.status.journey !== "chatgpt" ||
      quickstart.status.sessionId !== sessionId),
  );
  const status = statusMismatch ? null : quickstart.status;
  const quickstartError = statusMismatch
    ? "This companion session belongs to a different Quickstart journey. Run ./actionproxy chatgpt to start a ChatGPT session."
    : quickstart.error;
  const valid = tunnelIdPattern.test(tunnelId);
  const command = valid
    ? `corepack pnpm demo:chatgpt:tunnel -- --tunnel-id ${tunnelId}`
    : "";
  const proofCutoff = status
    ? Math.max(
        Date.parse(status.startedAt),
        proofStartedAt ? Date.parse(proofStartedAt) : 0,
      )
    : Number.POSITIVE_INFINITY;
  const tunnelCalls = data.toolCalls.filter(
    (call) =>
      isTunnelCall(call) &&
      call.metadata?.actionproxyQuickstartSessionId === sessionId &&
      Date.parse(call.createdAt) >= proofCutoff,
  );
  const searchCalls = tunnelCalls.filter(
    (call) => call.toolName === "docs.search",
  );
  const emailCalls = tunnelCalls.filter(
    (call) => call.toolName === "gmail.send_email",
  );
  const deletionCalls = tunnelCalls.filter(
    (call) => call.toolName === "dangerous.delete_customer",
  );
  const search = latestToolCall(searchCalls, "docs.search");
  const email = latestToolCall(emailCalls, "gmail.send_email");
  const deletion = latestToolCall(deletionCalls, "dangerous.delete_customer");
  const pending = data.pendingApprovals.find(
    (approval) => email?.id === approval.toolCallId,
  );
  const searchComplete = search?.status === "executed";
  const emailComplete =
    email?.status === "executed" || email?.status === "rejected";
  const deletionComplete = deletion?.status === "blocked";
  const duplicateCalls = [searchCalls, emailCalls, deletionCalls].some(
    (calls) => calls.length > 1,
  );
  const lifecycleComplete =
    !duplicateCalls && searchComplete && emailComplete && deletionComplete;
  const emailApprovalEvent = email
    ? data.auditEvents.find(
        (event) =>
          event.toolCallId === email.id && event.type === "approval.approved",
      )
    : undefined;
  const emailInputDecision =
    emailApprovalEvent?.data.inputDecision === "edited"
      ? "edited"
      : emailApprovalEvent?.data.inputDecision === "original"
        ? "original"
        : "unknown";
  const auditInvariantsValid = Boolean(
    lifecycleComplete &&
    search &&
    email &&
    deletion &&
    countAuditEvents(data.auditEvents, search.id, "policy.allow") === 1 &&
    countAuditEvents(data.auditEvents, search.id, "tool_call.executed") === 1 &&
    countAuditEvents(data.auditEvents, email.id, "policy.require_approval") ===
      1 &&
    countAuditEvents(data.auditEvents, email.id, "approval.created") === 1 &&
    (email.status === "executed"
      ? countAuditEvents(data.auditEvents, email.id, "approval.approved") ===
          1 &&
        countAuditEvents(
          data.auditEvents,
          email.id,
          "execution.attempt_dispatched",
        ) === 1 &&
        countAuditEvents(data.auditEvents, email.id, "tool_call.executed") ===
          1 &&
        emailInputDecision !== "unknown"
      : countAuditEvents(data.auditEvents, email.id, "approval.rejected") ===
          1 &&
        countAuditEvents(
          data.auditEvents,
          email.id,
          "execution.attempt_dispatched",
        ) === 0 &&
        countAuditEvents(data.auditEvents, email.id, "tool_call.executed") ===
          0) &&
    countAuditEvents(data.auditEvents, deletion.id, "policy.deny") === 1 &&
    countAuditEvents(
      data.auditEvents,
      deletion.id,
      "execution.attempt_dispatched",
    ) === 0 &&
    countAuditEvents(data.auditEvents, deletion.id, "tool_call.executed") === 0,
  );
  const tunnelReady = status?.setupStage === "tunnel_ready";
  const returnTo = sessionId
    ? `#/demo?journey=chatgpt&session=${encodeURIComponent(sessionId)}`
    : "#/demo?journey=chatgpt";
  const observedCalls = [search, email, deletion];

  useEffect(() => {
    if (pending) void onRefresh();
  }, [pending?.id]);

  useEffect(() => {
    setAttemptedPrompt(null);
    setRecoveryIndex(null);
    setProofStartedAt(readChatGptProofStart(sessionId));
  }, [sessionId]);

  useEffect(() => {
    if (!attemptedPrompt || observedCalls[attemptedPrompt.index]) return;
    const timeout = window.setTimeout(
      () => setRecoveryIndex(attemptedPrompt.index),
      30_000,
    );
    return () => window.clearTimeout(timeout);
  }, [attemptedPrompt, search?.id, email?.id, deletion?.id]);

  async function copy(id: string, value: string) {
    await navigator.clipboard?.writeText(value);
    setCopied(id);
  }
  async function copyPrompt(index: number, label: string, prompt: string) {
    await copy(label, prompt);
    setRecoveryIndex(null);
    setAttemptedPrompt({ index, nonce: Date.now() });
  }
  function startNewProof() {
    if (!sessionId) return;
    const startedAt = new Date().toISOString();
    window.localStorage.setItem(
      `${chatGptProofStartStoragePrefix}${sessionId}`,
      startedAt,
    );
    setProofStartedAt(startedAt);
    setAuditVerified(false);
    setAttemptedPrompt(null);
    setRecoveryIndex(null);
  }
  return (
    <section
      className="chatgpt-tunnel-panel"
      aria-labelledby="connect-chatgpt-heading"
    >
      <div className="chatgpt-tunnel-heading-row">
        <PanelHeading
          icon={<Bot size={18} />}
          id="connect-chatgpt-heading"
          title="Connect ChatGPT"
        />
        <Status
          label={
            pending
              ? "Approval waiting"
              : lifecycleComplete && auditVerified
                ? "Live proof complete"
                : duplicateCalls
                  ? "Duplicate calls need review"
                  : lifecycleComplete
                    ? "Verifying final audit proof"
                    : tunnelCalls.length > 0
                      ? "Quickstart MCP activity seen"
                      : status
                        ? quickstartStageLabel(status)
                        : sessionId && quickstart.loading
                          ? "Checking companion"
                          : "Setup not checked"
          }
          tone={
            pending
              ? "pending"
              : lifecycleComplete && auditVerified
                ? "good"
                : duplicateCalls ||
                    status?.setupStage === "failed" ||
                    quickstart.error
                  ? "bad"
                  : status?.setupStage === "tunnel_ready"
                    ? "good"
                    : "neutral"
          }
        />
      </div>
      <div
        className="chatgpt-tunnel-architecture"
        aria-label="ChatGPT tunnel architecture"
      >
        <code>ChatGPT</code>
        <span>→</span>
        <code>OpenAI Secure MCP Tunnel</code>
        <span>→</span>
        <code>ActionProxy wrapper</code>
        <span>→</span>
        <code>local mock tools</code>
      </div>
      <p className="chatgpt-tunnel-boundary">
        Demo boundary: all three tools are simulated, unauthenticated local mode
        is not a production identity boundary, and the browser never receives
        the tunnel runtime key.
      </p>
      <QuickstartStepper
        auditVerified={auditVerified}
        completedCalls={
          [searchComplete, emailComplete, deletionComplete].filter(Boolean)
            .length
        }
        duplicateCalls={duplicateCalls}
        lifecycleComplete={lifecycleComplete}
        status={status}
      />
      {sessionId && (
        <QuickstartRuntimeStatus
          error={quickstartError}
          loading={quickstart.loading}
          status={status}
        />
      )}
      {!status && (!sessionId || !quickstart.loading) && (
        <>
          <div className="chatgpt-tunnel-setup-grid">
            <div className="chatgpt-tunnel-launcher">
              <span className="command-kicker">Recommended</span>
              <h3>Run the first-run companion</h3>
              <p>
                From the downloaded ActionProxy folder, run one command. It
                checks this Mac, starts the local gateway, and prints a private
                deep link back to this page.
              </p>
              <TunnelClientAuthorityNote />
              <div className="chatgpt-tunnel-command">
                <code>{firstRunCommand}</code>
                <button
                  className="secondary"
                  onClick={() => void copy("first-run", firstRunCommand)}
                  type="button"
                >
                  {copied === "first-run" ? "Copied" : "Copy first-run command"}
                </button>
              </div>
              <p className="chatgpt-tunnel-connect-note">
                If a workspace administrator controls developer mode or tunnel
                permissions, send them the precise request below.
              </p>
              <blockquote className="chatgpt-admin-request">
                {adminAccessRequest}
              </blockquote>
              <button
                className="secondary"
                onClick={() => void copy("admin-request", adminAccessRequest)}
                type="button"
              >
                {copied === "admin-request"
                  ? "Request copied"
                  : "Copy admin request"}
              </button>
              {sessionId && (
                <p className="chatgpt-session-missing" role="status">
                  {statusMismatch ? (
                    <>
                      This link belongs to another Quickstart journey. Run{" "}
                      <code>{firstRunCommand}</code> to create a ChatGPT
                      session.
                    </>
                  ) : (
                    <>
                      No live companion status was found for{" "}
                      <code>{sessionId}</code>. Restart the printed first-run
                      command or use a new session.
                    </>
                  )}
                </p>
              )}
            </div>
            <ChatGptAccessLinks />
          </div>
          <details className="chatgpt-manual-setup">
            <summary>Manual tunnel setup</summary>
            <div className="chatgpt-tunnel-launcher">
              <p>
                Use this fallback if you prefer to install tunnel-client
                yourself or intentionally want to launch the legacy tunnel
                command. The reviewed official release and configuration links
                remain available on this page.
              </p>
              <label htmlFor="chatgpt-tunnel-id">OpenAI tunnel ID</label>
              <input
                id="chatgpt-tunnel-id"
                aria-invalid={Boolean(tunnelId) && !valid}
                autoComplete="off"
                placeholder="tunnel_..."
                spellCheck={false}
                value={tunnelId}
                onChange={(event) => setTunnelId(event.target.value)}
              />
              <small>
                The ID stays only in this tab. Keep the runtime key in the
                terminal; never paste it into this page.
              </small>
              <div className="chatgpt-tunnel-command">
                <code>
                  {command ||
                    "Enter a valid tunnel_... ID to generate the launcher command."}
                </code>
                <button
                  className="secondary"
                  disabled={!command}
                  onClick={() => void copy("command", command)}
                  type="button"
                >
                  {copied === "command" ? "Copied" : "Copy manual command"}
                </button>
              </div>
            </div>
          </details>
        </>
      )}
      {status && status.setupStage !== "tunnel_ready" && (
        <div className="chatgpt-app-step chatgpt-setup-support">
          <div>
            <span className="command-kicker">
              {status.setupStage === "failed"
                ? "Action needed"
                : status.setupStage === "tunnel_stopped"
                  ? "Connection lost"
                  : status.setupStage === "gateway_ready"
                    ? "Setup paused"
                    : "Current"}
            </span>
            <h3>
              {status.setupStage === "failed"
                ? "Retry secure-tunnel setup"
                : status.setupStage === "tunnel_stopped"
                  ? "Reconnect secure tunnel"
                  : status.setupStage === "gateway_ready"
                    ? "Continue secure-tunnel setup"
                    : "Finish secure-tunnel setup in Terminal"}
            </h3>
            {status.setupStage === "failed" ? (
              <p>
                The launcher reported a setup failure and has stopped. Follow
                its remediation, then rerun <code>./actionproxy chatgpt</code>.
                The verified local gateway and audit evidence remain available.
              </p>
            ) : status.setupStage === "tunnel_stopped" ? (
              <p>
                The secure tunnel is no longer connected. Rerun{" "}
                <code>./actionproxy chatgpt</code> in Terminal to reconnect. The
                local gateway and audit evidence remain available.
              </p>
            ) : status.setupStage === "gateway_ready" ? (
              <p>
                The previous launcher paused before starting the secure tunnel.
                Rerun <code>./actionproxy chatgpt</code> in Terminal to
                continue. The local gateway and audit evidence remain available.
              </p>
            ) : (
              <p>
                The First Run terminal now guides tunnel access,
                explicit-consent installation and rechecking of{" "}
                <code>tunnel-client</code>, and private runtime-key input.
                Return there for the current action; this browser remains
                read-only and never asks for the tunnel ID or runtime key.
              </p>
            )}
            <TunnelClientAuthorityNote />
            <blockquote className="chatgpt-admin-request">
              {adminAccessRequest}
            </blockquote>
            <button
              className="secondary"
              onClick={() => void copy("admin-request", adminAccessRequest)}
              type="button"
            >
              {copied === "admin-request"
                ? "Request copied"
                : "Copy admin request"}
            </button>
          </div>
          <ChatGptAccessLinks />
        </div>
      )}
      {status?.setupStage === "tunnel_ready" && (
        <>
          <div className="chatgpt-tunnel-ready" role="status">
            <ShieldCheck size={19} aria-hidden="true" />
            <div>
              <h3>Secure tunnel ready</h3>
              <p>
                Keep the Quickstart terminal open while testing. The gateway
                remains local; OpenAI Secure MCP Tunnel is the only remote
                transport used by this demonstration.
              </p>
            </div>
          </div>
          <div className="chatgpt-app-step">
            <div>
              <span className="command-kicker">Next</span>
              <h3>Add ActionProxy in ChatGPT</h3>
              <p>
                Create a developer-mode app, choose <strong>Tunnel</strong>{" "}
                under
                <strong> Connection</strong>, and select this session's tunnel.
              </p>
            </div>
            <ChatGptAccessLinks compact />
          </div>
        </>
      )}
      <details className="chatgpt-tunnel-details">
        <summary>Access requirements and exact mock tools</summary>
        <div className="chatgpt-tunnel-access">
          <h3>Confirm access first</h3>
          <p>
            ChatGPT workspace access and OpenAI Platform tunnel permissions are
            separate.
          </p>
          <ol>
            <li>
              Developer mode must be available and enabled for the target
              ChatGPT workspace and user.
            </li>
            <li>
              Running the tunnel needs Tunnels <strong>Read + Use</strong>.
              Creating or editing one also needs <strong>Manage</strong>.
            </li>
            <li>
              Associate the tunnel with the target ChatGPT workspace. Platform
              organization access alone is not enough.
            </li>
          </ol>
        </div>
        <div className="chatgpt-tunnel-tools">
          <h3>Exactly three mock tools</h3>
          <ul>
            {tunnelTools.map(([tool, behavior]) => (
              <li key={tool}>
                <code>{tool}</code>
                <span>{behavior}</span>
              </li>
            ))}
          </ul>
        </div>
      </details>
      <div className="chatgpt-tunnel-prompts" aria-label="ChatGPT proof steps">
        <div className="chatgpt-prompt-heading">
          <div>
            <span className="command-kicker">Live proof</span>
            <h3>Try one policy path at a time</h3>
          </div>
          <span>
            {
              [searchComplete, emailComplete, deletionComplete].filter(Boolean)
                .length
            }
            /3 complete
          </span>
        </div>
        {tunnelPrompts.map(([label, prompt], index) => {
          const call = observedCalls[index];
          const complete = [searchComplete, emailComplete, deletionComplete][
            index
          ];
          const unlocked =
            tunnelReady &&
            (index === 0 ||
              (index === 1 && searchComplete) ||
              (index === 2 && emailComplete));
          const waiting =
            Boolean(call) &&
            !complete &&
            call?.status !== "failed" &&
            call?.status !== "rejected";
          const state = complete
            ? "complete"
            : waiting
              ? "waiting"
              : unlocked
                ? "active"
                : "locked";
          return (
            <article className={`chatgpt-tunnel-prompt ${state}`} key={label}>
              <div className="chatgpt-prompt-index" aria-hidden="true">
                {complete ? <Check size={16} /> : index + 1}
              </div>
              <div>
                <strong>{label}</strong>
                <span>
                  {state === "locked"
                    ? "This prompt appears after the previous proof step completes."
                    : prompt}
                </span>
                <small>
                  {promptStateLabel(state, call, index, attemptedPrompt?.index)}
                </small>
                {index === 2 && state !== "locked" && (
                  <small>
                    ChatGPT may show its own confirmation. That is separate from
                    the ActionProxy policy decision recorded here.
                  </small>
                )}
              </div>
              {index === 1 && pending ? (
                <a
                  className="button-link compact"
                  href={approvalHref(pending.id, returnTo)}
                >
                  Review
                </a>
              ) : (
                <button
                  aria-label={`Copy ${label.toLowerCase()} prompt`}
                  className="secondary icon-button"
                  disabled={state !== "active"}
                  onClick={() => void copyPrompt(index, label, prompt)}
                  type="button"
                >
                  {copied === label ? <Check size={16} /> : <Copy size={16} />}
                </button>
              )}
            </article>
          );
        })}
      </div>
      {recoveryIndex !== null && !observedCalls[recoveryIndex] && (
        <div className="chatgpt-no-call-recovery" role="status">
          <div>
            <ShieldAlert size={18} aria-hidden="true" />
            <span>
              <strong>
                No {tunnelPrompts[recoveryIndex]?.[0].toLowerCase()} call
                arrived after 30 seconds.
              </strong>
            </span>
          </div>
          <ol>
            <li>Confirm the ActionProxy app is enabled in this chat.</li>
            <li>
              If you refreshed the app definition, start a new ChatGPT
              conversation.
            </li>
            <li>
              Ask ChatGPT to explicitly invoke{" "}
              <code>{tunnelTools[recoveryIndex]?.[0]}</code>.
            </li>
            <li>
              Run the local proof to isolate ChatGPT from gateway problems.
            </li>
          </ol>
          <div className="quickstart-proof-actions">
            {status?.tunnelUiUrl && (
              <a
                className="text-link"
                href={status.tunnelUiUrl}
                rel="noreferrer"
                target="_blank"
              >
                Check tunnel health
              </a>
            )}
            <button
              className="secondary"
              onClick={() => {
                const entry = tunnelPrompts[recoveryIndex];
                if (entry) void copyPrompt(recoveryIndex, entry[0], entry[1]);
              }}
              type="button"
            >
              Copy this prompt again
            </button>
          </div>
        </div>
      )}
      {pending && email && (
        <PendingChatGptApproval
          approvalId={pending.id}
          approvalTimeoutMs={status?.approvalTimeoutMs ?? 300_000}
          createdAt={email.createdAt}
          returnTo={returnTo}
        />
      )}
      <QuickstartAuditProof
        chatGptProof={{
          auditInvariantsValid,
          deletion,
          email,
          emailInputDecision,
          search,
        }}
        onVerifiedChange={setAuditVerified}
        onStartNewProof={sessionId ? startNewProof : undefined}
        ready={auditInvariantsValid}
      />
    </section>
  );
}

function ChatGptAccessLinks({ compact = false }: { compact?: boolean }) {
  const links = compact
    ? [openAiLinks.links.chatgptAppSettings, openAiLinks.links.tunnelSettings]
    : [
        openAiLinks.links.chatgptAppSettings,
        openAiLinks.links.tunnelSettings,
        openAiLinks.links.developerMode,
        openAiLinks.links.secureMcpTunnel,
        openAiLinks.links.tunnelClientReleases,
        openAiLinks.links.tunnelClientConfiguration,
      ];
  return (
    <div className={compact ? "chatgpt-link-row compact" : "chatgpt-link-row"}>
      {links.map((link) => (
        <a
          className="text-link"
          href={link.url}
          key={link.url}
          rel="noreferrer"
          target="_blank"
        >
          {link.label} <ExternalLink size={14} aria-hidden="true" />
        </a>
      ))}
      <small>External setup links reviewed {openAiLinks.reviewedAt}.</small>
    </div>
  );
}

function TunnelClientAuthorityNote() {
  return (
    <p className="chatgpt-tunnel-connect-note">
      Installation happens only after you choose I in Terminal or explicitly run
      the local install command. This browser cannot install software or start
      processes, and <code>{tunnelClientDoctorCommand}</code> performs no
      ActionProxy state mutation or download. Manual installation remains
      available; remove the checkout-local copy with{" "}
      <code>{tunnelClientRemoveCommand}</code>.
    </p>
  );
}

function QuickstartStepper({
  auditVerified,
  completedCalls,
  duplicateCalls,
  lifecycleComplete,
  status,
}: {
  auditVerified: boolean;
  completedCalls: number;
  duplicateCalls: boolean;
  lifecycleComplete: boolean;
  status: QuickstartStatus | null;
}) {
  const gatewayReady =
    status?.checks.some(
      (check) => check.id === "gateway" && check.state === "pass",
    ) ?? false;
  const tunnelReady = status?.setupStage === "tunnel_ready";
  const current = !gatewayReady
    ? 0
    : !tunnelReady
      ? 1
      : !lifecycleComplete
        ? 2
        : 3;
  const steps = [
    {
      label: "Local gateway",
      status: gatewayReady
        ? "Complete"
        : status
          ? "Current"
          : "Setup not checked",
    },
    {
      label: "Secure tunnel",
      status: tunnelReady
        ? "Complete"
        : gatewayReady
          ? "Current"
          : "Not started",
    },
    {
      label: "ChatGPT tool calls",
      status: duplicateCalls
        ? "Duplicate calls detected"
        : lifecycleComplete
          ? "Complete"
          : tunnelReady
            ? `Current · ${completedCalls}/3 governed outcomes`
            : "Not started",
    },
    {
      label: "Verified proof",
      status: auditVerified
        ? "Complete"
        : lifecycleComplete
          ? "Current"
          : "Not started",
    },
  ];
  return (
    <ol className="quickstart-stepper" aria-label="ChatGPT Quickstart progress">
      {steps.map((step, index) => (
        <li
          aria-current={
            index === current && !auditVerified ? "step" : undefined
          }
          className={
            index < current || auditVerified
              ? "complete"
              : index === current
                ? "current"
                : "upcoming"
          }
          key={step.label}
        >
          <span aria-hidden="true">
            {index < current || auditVerified ? <Check size={14} /> : index + 1}
          </span>
          <div>
            <strong>{step.label}</strong>
            <small>{step.status}</small>
          </div>
        </li>
      ))}
    </ol>
  );
}

function QuickstartRuntimeStatus({
  error,
  loading,
  status,
}: {
  error: string | null;
  loading: boolean;
  status: QuickstartStatus | null;
}) {
  if (loading && !status) {
    return (
      <div className="quickstart-runtime-status" role="status">
        <RefreshCw size={18} aria-hidden="true" />
        Checking the local first-run companion…
      </div>
    );
  }
  if (error) {
    return (
      <div className="quickstart-runtime-status failed" role="alert">
        <ShieldAlert size={18} aria-hidden="true" />
        <span>
          <strong>Companion status unavailable.</strong> {error}
        </span>
      </div>
    );
  }
  if (!status) return null;
  const runtimeKeyDockerState =
    status.setupDetails?.runtimeKeyExcludedFromDocker === true
      ? "pass"
      : status.setupDetails?.runtimeKeyExcludedFromDocker === false
        ? "fail"
        : "pending";
  return (
    <section
      className="quickstart-runtime-card"
      aria-labelledby="runtime-status-heading"
    >
      <div className="quickstart-runtime-heading">
        <div>
          <span className="command-kicker">Local readiness</span>
          <h3 id="runtime-status-heading">{quickstartStageLabel(status)}</h3>
        </div>
        <small>Session {status.sessionId}</small>
      </div>
      <ul>
        {status.checks.map((check) => (
          <li className={check.state} key={check.id}>
            {check.state === "pass" ? (
              <Check size={15} aria-hidden="true" />
            ) : check.state === "fail" || check.state === "action_required" ? (
              <ShieldAlert size={15} aria-hidden="true" />
            ) : (
              <Circle size={15} aria-hidden="true" />
            )}
            <span>
              <strong>{quickstartCheckLabel(check.id)}</strong>
              {check.remediationCode && (
                <small>{humanizeCode(check.remediationCode)}</small>
              )}
            </span>
          </li>
        ))}
        {status.journey === "chatgpt" && (
          <li className={runtimeKeyDockerState}>
            {runtimeKeyDockerState === "pass" ? (
              <Check size={15} aria-hidden="true" />
            ) : runtimeKeyDockerState === "fail" ? (
              <ShieldAlert size={15} aria-hidden="true" />
            ) : (
              <Circle size={15} aria-hidden="true" />
            )}
            <span>
              <strong>OpenAI runtime key excluded from Docker</strong>
              <small>
                {runtimeKeyDockerState === "pass"
                  ? "Verified"
                  : runtimeKeyDockerState === "fail"
                    ? "Credential boundary failed"
                    : "Not checked yet"}
              </small>
            </span>
          </li>
        )}
      </ul>
      {status.setupDetails && (
        <details className="quickstart-setup-details">
          <summary>Setup details</summary>
          <dl className="detail-grid">
            <div>
              <dt>Node</dt>
              <dd>{status.setupDetails.nodeVersion}</dd>
            </div>
            <div>
              <dt>Docker engine</dt>
              <dd>{status.setupDetails.dockerVersion}</dd>
            </div>
            <div>
              <dt>Docker Compose</dt>
              <dd>{status.setupDetails.composeVersion}</dd>
            </div>
            <div>
              <dt>Assigned port</dt>
              <dd>{status.setupDetails.port}</dd>
            </div>
            <div>
              <dt>Compose project</dt>
              <dd>
                <code>{status.setupDetails.projectName}</code>
              </dd>
            </div>
          </dl>
        </details>
      )}
      {status.tunnelUiUrl && (
        <a
          className="text-link"
          href={status.tunnelUiUrl}
          rel="noreferrer"
          target="_blank"
        >
          Open tunnel health UI <ExternalLink size={14} aria-hidden="true" />
        </a>
      )}
    </section>
  );
}

function PendingChatGptApproval({
  approvalId,
  approvalTimeoutMs,
  createdAt,
  returnTo,
}: {
  approvalId: string;
  approvalTimeoutMs: number;
  createdAt: string;
  returnTo: string;
}) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(interval);
  }, []);
  const remaining = Math.max(
    0,
    Date.parse(createdAt) + approvalTimeoutMs - now,
  );
  return (
    <div className="chatgpt-approval-callout" role="status">
      <div>
        <ShieldAlert size={19} aria-hidden="true" />
        <span>
          <strong>ChatGPT is waiting for your decision.</strong>
          {remaining > 0
            ? ` About ${formatRemaining(remaining)} remains in this ChatGPT wait window.`
            : " The ChatGPT wait window may have ended; review the proposal, then retry the prompt if needed."}
          {" No mock email has been sent."}
        </span>
      </div>
      <a className="button-link" href={approvalHref(approvalId, returnTo)}>
        Review exact email
      </a>
    </div>
  );
}

function QuickstartAuditProof({
  chatGptProof,
  onVerifiedChange,
  onStartNewProof,
  ready,
}: {
  chatGptProof?: {
    auditInvariantsValid: boolean;
    deletion?: ToolCallRecord;
    email?: ToolCallRecord;
    emailInputDecision: "edited" | "original" | "unknown";
    search?: ToolCallRecord;
  };
  onVerifiedChange?: (valid: boolean) => void;
  onStartNewProof?: () => void;
  ready: boolean;
}) {
  const [verification, setVerification] = useState<AuditVerification | null>(
    null,
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proofCopied, setProofCopied] = useState(false);
  const verify = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const next = await fetchAuditVerification();
      setVerification(next);
      onVerifiedChange?.(next.valid);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      onVerifiedChange?.(false);
    } finally {
      setLoading(false);
    }
  }, [onVerifiedChange]);

  useEffect(() => {
    if (!ready) {
      setVerification(null);
      setError(null);
      onVerifiedChange?.(false);
      return;
    }
    void verify();
  }, [ready, verify, onVerifiedChange]);

  const verified = verification?.valid === true;
  const emailOutcome =
    chatGptProof?.email?.status === "rejected"
      ? "Email rejected by you; no execution occurred."
      : chatGptProof?.emailInputDecision === "edited"
        ? "Edited email approved and executed exactly once."
        : "Exact email approved and executed exactly once.";
  if (verified && chatGptProof?.auditInvariantsValid) {
    const sanitizedProof = [
      "ActionProxy Quickstart MCP proof (local)",
      "Allowed read executed exactly once.",
      emailOutcome,
      "Destructive deletion denied before dispatch.",
      `Local audit hash chain verified (${verification.checked} events checked).`,
      "Locally verified; not externally anchored.",
      "ActionProxy verified the local MCP path and policy outcomes. Confirm the upstream ChatGPT result in the conversation.",
    ].join("\n");
    return (
      <section
        className="quickstart-proof-card chatgpt-verified-proof ready"
        aria-labelledby="quickstart-proof-heading"
      >
        <div>
          <span className="command-kicker">Verified proof</span>
          <h3 id="quickstart-proof-heading">
            You governed three Quickstart MCP tool calls from your Mac
          </h3>
          <ul className="verified-outcome-list">
            <li>
              <Check size={16} aria-hidden="true" /> Allowed read executed
              exactly once.
            </li>
            <li>
              <Check size={16} aria-hidden="true" /> {emailOutcome}
            </li>
            <li>
              <Check size={16} aria-hidden="true" /> Deletion denied before
              dispatch; zero execution attempts.
            </li>
            <li>
              <Check size={16} aria-hidden="true" /> Local append-only hash
              chain verified.
            </li>
          </ul>
          <p>
            Locally verified; not externally anchored. ActionProxy verified the
            local MCP path and policy outcomes. Confirm the upstream ChatGPT
            result in the conversation.
          </p>
          <div className="quickstart-proof-actions">
            <a className="text-link" href="#/audit">
              Inspect this audit trail
            </a>
            <button
              className="secondary"
              onClick={() => {
                void navigator.clipboard?.writeText(sanitizedProof);
                setProofCopied(true);
              }}
              type="button"
            >
              {proofCopied ? "Proof copied" : "Copy sanitized proof"}
            </button>
            {onStartNewProof ? (
              <button
                className="button-link"
                onClick={onStartNewProof}
                type="button"
              >
                Start a new proof
              </button>
            ) : (
              <a className="button-link" href="#/demo?journey=chatgpt">
                Start a new proof
              </a>
            )}
          </div>
          <div className="quickstart-stop-command">
            <span>When finished, stop the local companion:</span>
            <code>./actionproxy stop</code>
          </div>
        </div>
      </section>
    );
  }
  return (
    <section
      className={`quickstart-proof-card ${verified ? "ready" : "waiting"}`}
      aria-labelledby="quickstart-proof-heading"
    >
      <div>
        <span className="command-kicker">Final proof</span>
        <h3 id="quickstart-proof-heading">
          {verified
            ? "Quickstart complete: audit chain verified"
            : verification && !verification.valid
              ? "Tool outcomes observed, but audit verification failed"
              : ready
                ? "Verifying final audit custody"
                : chatGptProof
                  ? "Waiting for exact current-session audit evidence"
                  : "Audit proof unlocks after the lifecycle"}
        </h3>
        <p>
          {verification?.valid
            ? `${verification.checked} append-only events form a valid local hash chain.`
            : verification && !verification.valid
              ? `${verification.errors?.length ?? "Unknown"} audit-chain errors were found.`
              : "Verify the local hash chain, then inspect the human-readable lifecycle evidence."}
        </p>
        {error && <small className="field-error">{error}</small>}
      </div>
      <div className="quickstart-proof-actions">
        <button
          className="secondary"
          disabled={!ready || loading}
          onClick={() => void verify()}
          type="button"
        >
          {loading
            ? "Verifying…"
            : verified
              ? "Verified"
              : verification
                ? "Retry verification"
                : "Verify audit chain"}
        </button>
        <a className="text-link" href="#/audit">
          Inspect evidence
        </a>
      </div>
    </section>
  );
}

function useQuickstartStatus(sessionId?: string) {
  const [status, setStatus] = useState<QuickstartStatus | null>(null);
  const [loading, setLoading] = useState(Boolean(sessionId));
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!sessionId) {
      setStatus(null);
      setLoading(false);
      setError(null);
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const next = await fetchQuickstartStatus(sessionId);
        if (!cancelled) {
          setStatus(next);
          setError(null);
        }
      } catch (caught) {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : String(caught));
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void poll();
    const interval = window.setInterval(() => void poll(), 2_000);
    const refreshOnFocus = () => void poll();
    window.addEventListener("focus", refreshOnFocus);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
      window.removeEventListener("focus", refreshOnFocus);
    };
  }, [sessionId]);
  return { error, loading, status };
}

function ToolCallDetail({ data, id }: { data: DashboardData; id: string }) {
  const listed = data.toolCalls.find((call) => call.id === id);
  const [loaded, setLoaded] = useState<ToolCallRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (listed) return;
    let cancelled = false;
    fetchToolCall(id)
      .then((call) => {
        if (!cancelled) setLoaded(call);
      })
      .catch((caught) => {
        if (!cancelled)
          setError(caught instanceof Error ? caught.message : String(caught));
      });
    return () => {
      cancelled = true;
    };
  }, [id, listed]);
  const call = listed ?? loaded;
  if (error) return <ErrorState message={error} />;
  if (!call) return <p role="status">Loading tool call…</p>;
  return (
    <section className="panel page-panel" aria-labelledby="tool-call-heading">
      <PanelHeading
        icon={<FileSearch size={18} />}
        id="tool-call-heading"
        title="Tool-call record"
      />
      <div className="record-title">
        <code>{call.toolName}</code>
        <Status
          label={call.status}
          tone={
            call.status === "executed"
              ? "good"
              : call.status === "blocked" ||
                  call.status === "failed" ||
                  call.status === "rejected"
                ? "bad"
                : "pending"
          }
        />
      </div>
      <dl className="detail-grid">
        <div>
          <dt>Requested by</dt>
          <dd>{call.requestedBy}</dd>
        </div>
        <div>
          <dt>Agent</dt>
          <dd>{call.agentId}</dd>
        </div>
        <div>
          <dt>Decision</dt>
          <dd>{call.decision ?? "pending"}</dd>
        </div>
        <div>
          <dt>Updated</dt>
          <dd>{formatDate(call.updatedAt)}</dd>
        </div>
      </dl>
      <h2>Exact input</h2>
      <pre>{prettyJson(call.input)}</pre>
      {call.contentInfluence && (
        <ContentInfluence evidence={call.contentInfluence} />
      )}
    </section>
  );
}

function NotFound({ requestedPath }: { requestedPath: string }) {
  return (
    <section className="panel page-panel not-found-panel">
      <PanelHeading
        icon={<FileSearch size={18} />}
        id="not-found-heading"
        title="Page not found"
      />
      <p>
        The Community console has no <code>{requestedPath}</code> view.
      </p>
      <a className="text-link" href="#/">
        Return to overview
      </a>
    </section>
  );
}
function ErrorState({ message }: { message: string }) {
  return (
    <section className="panel page-panel">
      <PanelHeading
        icon={<TriangleAlert size={18} />}
        id="error-heading"
        title="Could not load this record"
      />
      <p className="field-error" role="alert">
        {message}
      </p>
      <a className="text-link" href="#/">
        Return to overview
      </a>
    </section>
  );
}
function Empty({ body, title }: { body: string; title: string }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      <p>{body}</p>
    </div>
  );
}
function PanelHeading({
  icon,
  id,
  title,
}: {
  icon: ReactNode;
  id: string;
  title: string;
}) {
  return (
    <div className="panel-header">
      <h2 id={id}>
        <span aria-hidden="true">{icon}</span>
        {title}
      </h2>
    </div>
  );
}
function Status({
  label,
  tone,
}: {
  label: string;
  tone: "bad" | "good" | "neutral" | "pending";
}) {
  return <span className={`status-badge ${tone}`}>{label}</span>;
}

function ToolCallTable({ calls }: { calls: ToolCallRecord[] }) {
  if (!calls.length)
    return (
      <Empty
        title="No tool calls yet"
        body="Run the local lifecycle to create the first governed records."
      />
    );
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Tool</th>
            <th>Status</th>
            <th>Decision</th>
            <th>Requested by</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
          {calls.map((call) => (
            <tr key={call.id}>
              <td>
                <a href={`#/tool-calls/${encodeURIComponent(call.id)}`}>
                  {call.toolName}
                </a>
              </td>
              <td>{call.status}</td>
              <td>{decisionLabel(call.decision)}</td>
              <td>{call.requestedBy}</td>
              <td>{formatDate(call.updatedAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function decisionLabel(decision?: PolicyDecision) {
  return decision === "allow"
    ? "Allowed"
    : decision === "deny"
      ? "Denied"
      : decision === "require_approval"
        ? "Needs approval"
        : "Pending";
}
function mcpProfiles(data: DashboardData): McpWrapperProfileSummary[] {
  return (
    data.integrations?.downstreamToolSources?.mcpWrapper.profiles ??
    data.integrations?.mcpWrapper.profiles ??
    []
  );
}
function isTunnelCall(call: ToolCallRecord) {
  return trustedQuickstartContext(call)?.journey === "chatgpt";
}
function trustedQuickstartContext(
  call: ToolCallRecord,
): { journey: QuickstartJourney; sessionId: string } | undefined {
  const sessionId = call.metadata?.actionproxyQuickstartSessionId;
  if (
    call.metadata?.actionproxyQuickstartOrigin !== "secure_mcp_tunnel" ||
    typeof sessionId !== "string" ||
    !quickstartSessionIdPattern.test(sessionId)
  ) {
    return undefined;
  }
  return { journey: "chatgpt", sessionId };
}
function isQuickstartCall(call: ToolCallRecord): boolean {
  return isTunnelCall(call) || call.metadata?.demo === "customer-support-agent";
}
function localDemoQuickstartContext(
  call: ToolCallRecord,
): { guided: boolean; sessionId: string } | undefined {
  const sessionId = call.metadata?.demoQuickstartSessionId;
  if (
    call.metadata?.demo !== "customer-support-agent" ||
    typeof sessionId !== "string" ||
    !quickstartSessionIdPattern.test(sessionId)
  ) {
    return undefined;
  }
  // This ordinary HTTP metadata is navigation guidance only. Unlike tunnel
  // provenance, it grants no trust, identity, policy, or execution authority.
  return {
    guided: call.metadata?.demoQuickstartGuided === true,
    sessionId,
  };
}
function latestToolCall(calls: ToolCallRecord[], toolName: string) {
  return calls
    .filter((call) => call.toolName === toolName)
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))[0];
}
function hasTunnelActivity(data: DashboardData) {
  return data.toolCalls.some(isTunnelCall);
}
function findWaitingApproval(data: DashboardData, route: CommunityRoute) {
  const candidates = data.pendingApprovals.flatMap((approval) => {
    const toolCall = data.toolCalls.find(
      (call) => call.id === approval.toolCallId,
    );
    return toolCall
      ? [
          {
            approval,
            returnTo: quickstartReturnForCall(toolCall, route),
            toolCall,
          },
        ]
      : [];
  });
  return (
    candidates.find(
      ({ toolCall }) =>
        toolCall.toolName === "gmail.send_email" &&
        (isTunnelCall(toolCall) ||
          toolCall.metadata?.demo === "customer-support-agent"),
    ) ?? candidates[0]
  );
}
function quickstartReturnForCall(
  call: ToolCallRecord,
  route: CommunityRoute,
): string | undefined {
  const trustedContext = trustedQuickstartContext(call);
  if (trustedContext) {
    return `#/demo?journey=${trustedContext.journey}&session=${encodeURIComponent(trustedContext.sessionId)}`;
  }
  if (call.metadata?.demo === "customer-support-agent") {
    const localContext = localDemoQuickstartContext(call);
    const routeSession =
      route.name === "demo" && route.journey !== "chatgpt"
        ? route.sessionId
        : undefined;
    const sessionId = localContext?.sessionId ?? routeSession;
    const base = sessionId
      ? `#/demo?journey=local&session=${encodeURIComponent(sessionId)}`
      : "#/demo?journey=local";
    const guided =
      localContext?.guided || (route.name === "demo" && route.guided);
    return guided ? `${base}&guided=1` : base;
  }
  return route.name === "demo" ? "#/demo" : undefined;
}
function approvalHref(id: string, returnTo?: string): string {
  const base = `#/approvals/${encodeURIComponent(id)}`;
  return returnTo ? `${base}?returnTo=${encodeURIComponent(returnTo)}` : base;
}
function quickstartHref(call: ToolCallRecord): string {
  const trustedContext = trustedQuickstartContext(call);
  const localContext = localDemoQuickstartContext(call);
  return trustedContext
    ? `#/demo?journey=${trustedContext.journey}&session=${encodeURIComponent(trustedContext.sessionId)}`
    : localContext
      ? `#/demo?journey=local&session=${encodeURIComponent(localContext.sessionId)}${localContext.guided ? "&guided=1" : ""}`
      : call.metadata?.demo === "customer-support-agent"
        ? "#/demo?journey=local"
        : "#/approvals";
}
function parseQuickstartReturnTarget(
  value: string | null,
): QuickstartReturnTarget | undefined {
  if (value === "#/demo") return {};
  if (!value?.startsWith("#/demo?")) return undefined;

  const rawQuery = value.slice("#/demo?".length);
  if (!rawQuery || rawQuery.includes("#")) return undefined;
  const query = new URLSearchParams(rawQuery);
  const allowedNames = new Set(["guided", "journey", "session"]);
  const names = [...query.keys()];
  if (
    names.some(
      (name) => !allowedNames.has(name) || query.getAll(name).length !== 1,
    )
  ) {
    return undefined;
  }

  const requestedJourney = query.get("journey");
  const journey: QuickstartJourney | undefined =
    requestedJourney === "local"
      ? "local"
      : requestedJourney === "chatgpt"
        ? "chatgpt"
        : undefined;
  if (!journey) return undefined;

  const sessionId = query.get("session")?.trim();
  if (sessionId && !quickstartSessionIdPattern.test(sessionId))
    return undefined;

  const guided = query.get("guided");
  if (guided !== null && (guided !== "1" || journey !== "local")) {
    return undefined;
  }

  return {
    ...(guided === "1" ? { guided: true as const } : {}),
    journey,
    ...(sessionId ? { sessionId } : {}),
  };
}
function quickstartReturnHref(target: QuickstartReturnTarget): string {
  const journey =
    target.journey === "local"
      ? "local"
      : target.journey === "chatgpt"
        ? "chatgpt"
        : undefined;
  if (!journey) return "#/demo";
  const query = [`journey=${journey}`];
  if (target.sessionId) {
    query.push(`session=${encodeURIComponent(target.sessionId)}`);
  }
  if (target.guided) query.push("guided=1");
  return `#/demo?${query.join("&")}`;
}
function readChatGptProofStart(sessionId?: string): string | null {
  if (!sessionId || typeof window === "undefined") return null;
  const value = window.localStorage.getItem(
    `${chatGptProofStartStoragePrefix}${sessionId}`,
  );
  return value && Number.isFinite(Date.parse(value)) ? value : null;
}
function promptStateLabel(
  state: "active" | "complete" | "locked" | "waiting",
  call?: ToolCallRecord,
  index?: number,
  attemptedIndex?: number,
): string {
  if (state === "complete")
    return call?.status === "blocked"
      ? "Denied before downstream execution"
      : call?.status === "rejected"
        ? "Rejected by you; no execution occurred."
        : "Observed in this quickstart session";
  if (state === "waiting")
    return call?.status === "pending_approval"
      ? "Waiting for your ActionProxy approval"
      : "Call received; waiting for its terminal outcome";
  if (state === "active")
    return index === attemptedIndex
      ? `Listening for ${index === undefined ? "the ActionProxy tool" : (tunnelTools[index]?.[0] ?? "the ActionProxy tool")}`
      : "Copy this prompt into a new ChatGPT chat";
  return "Complete the previous proof step first";
}
function quickstartStageLabel(status: QuickstartStatus): string {
  const stage = status.setupStage;
  if (stage === "tunnel_checking") {
    const doctor = status.checks.find((check) => check.id === "tunnel_doctor");
    return doctor?.state === "pass"
      ? "Starting Secure MCP Tunnel"
      : "Checking tunnel access";
  }
  const labels: Record<QuickstartStatus["setupStage"], string> = {
    failed: "Setup needs attention",
    gateway_ready: "Local gateway ready",
    gateway_starting: "Starting local gateway",
    tunnel_checking: "Checking tunnel access",
    tunnel_ready: "Tunnel connection ready",
    tunnel_stopped: "Connection lost",
  };
  return labels[stage];
}
function quickstartCheckLabel(id: string): string {
  const labels: Record<string, string> = {
    compose: "Docker Compose",
    docker_cli: "Docker CLI",
    docker_daemon: "Docker Desktop",
    gateway: "ActionProxy gateway",
    loopback: "Loopback-only binding",
    node: "Node.js",
    storage: "Demo storage",
    tool_discovery: "Three governed MCP tools",
    tunnel_client: "OpenAI tunnel client",
    tunnel_doctor: "Tunnel permissions and profile",
    tunnel_readiness: "Tunnel connection",
  };
  return labels[id] ?? humanizeCode(id);
}
function humanizeCode(value: string): string {
  const words = value.replaceAll(/[_-]+/gu, " ").trim();
  return words ? words[0]!.toUpperCase() + words.slice(1) : value;
}
function formatRemaining(milliseconds: number): string {
  const seconds = Math.ceil(milliseconds / 1_000);
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return minutes
    ? `${minutes}:${String(remainder).padStart(2, "0")}`
    : `${remainder} seconds`;
}
function lifecycleState(data: DashboardData) {
  const calls = data.toolCalls.filter(
    (call) => call.metadata?.demo === "customer-support-agent",
  );
  const search = calls.some(
    (call) => call.toolName === "docs.search" && call.status === "executed",
  );
  const email = calls.find((call) => call.toolName === "gmail.send_email");
  const denied = calls.some(
    (call) =>
      call.toolName === "dangerous.delete_customer" &&
      call.status === "blocked",
  );
  const approval = email
    ? data.pendingApprovals.find(
        (candidate) => candidate.toolCallId === email.id,
      )
    : undefined;
  return {
    approval,
    complete:
      search &&
      Boolean(
        email && (email.status === "executed" || email.status === "rejected"),
      ) &&
      denied,
  };
}
function groupAudit(events: AuditEvent[], query: string) {
  const needle = query.trim().toLowerCase();
  const filtered = needle
    ? events.filter((event) =>
        JSON.stringify(event).toLowerCase().includes(needle),
      )
    : events;
  const groups = new Map<string, AuditEvent[]>();
  for (const event of filtered) {
    const id = event.toolCallId ?? event.approvalId ?? "gateway";
    groups.set(id, [...(groups.get(id) ?? []), event]);
  }
  return [...groups.entries()]
    .map(([id, groupEvents]) => ({
      id,
      events: groupEvents.sort((a, b) =>
        a.timestamp.localeCompare(b.timestamp),
      ),
    }))
    .sort((a, b) =>
      (b.events.at(-1)?.timestamp ?? "").localeCompare(
        a.events.at(-1)?.timestamp ?? "",
      ),
    );
}
function countAuditEvents(
  events: AuditEvent[],
  toolCallId: string,
  type: string,
): number {
  return events.filter(
    (event) => event.toolCallId === toolCallId && event.type === type,
  ).length;
}
function toggleSet(current: Set<string>, value: string) {
  const next = new Set(current);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}
function parseJsonObject(
  source: string,
): { ok: true; value: JsonObject } | { error: string; ok: false } {
  try {
    const value = JSON.parse(source) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value))
      return { error: "Input JSON must be an object.", ok: false };
    return { ok: true, value: value as JsonObject };
  } catch {
    return { error: "Input JSON is invalid.", ok: false };
  }
}
function prettyJson(value: unknown) {
  return JSON.stringify(redact(value ?? null), null, 2);
}
async function hashJsonForDisplay(
  value: JsonObject,
): Promise<string | undefined> {
  if (!globalThis.crypto?.subtle) return undefined;
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(stableJsonForHash(value)),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
function stableJsonForHash(value: unknown): string {
  if (value === null || typeof value !== "object")
    return JSON.stringify(value) ?? "null";
  if (Array.isArray(value))
    return `[${value.map((item) => stableJsonForHash(item)).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries
    .map(([key, item]) => `${JSON.stringify(key)}:${stableJsonForHash(item)}`)
    .join(",")}}`;
}
function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
      key,
      /(?:authorization|cookie|password|secret|token)$/iu.test(
        key.replaceAll(/[-_\s]/g, ""),
      )
        ? "[REDACTED]"
        : redact(entry),
    ]),
  );
}
function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

function useCommunityRoute(): CommunityRoute {
  const [route, setRoute] = useState(() => parseRoute(window.location.hash));
  useEffect(() => {
    const update = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", update);
    update();
    return () => window.removeEventListener("hashchange", update);
  }, []);
  return route;
}

function parseRoute(hash: string): CommunityRoute {
  const normalized = hash.replace(/^#\/?/u, "");
  const [rawPath = "", rawQuery = ""] = normalized.split("?", 2);
  const path = rawPath.replace(/\/$/u, "");
  const query = new URLSearchParams(rawQuery);
  const parts = path ? path.split("/").map(decodeURIComponent) : [];
  if (!parts.length) return { name: "overview" };
  if (parts[0] === "approvals" && parts[1] && parts.length === 2) {
    return {
      id: parts[1],
      name: "approvalDetail",
      returnTarget: parseQuickstartReturnTarget(query.get("returnTo")),
    };
  }
  if (parts[0] === "approvals" && parts.length === 1)
    return { name: "approvals" };
  if (parts[0] === "authorized" && parts.length === 1)
    return { name: "authorized" };
  if (parts[0] === "audit" && parts.length === 1) return { name: "audit" };
  if (parts[0] === "policy" && parts.length === 1) return { name: "policy" };
  if (parts[0] === "integrations" && parts.length === 1)
    return { name: "integrations" };
  if (parts[0] === "demo" && parts.length === 1) {
    const journey = query.get("journey");
    const sessionId = query.get("session")?.trim();
    return {
      guided: query.get("guided") === "1" ? true : undefined,
      journey:
        journey === "local" || journey === "chatgpt" ? journey : undefined,
      name: "demo",
      sessionId:
        sessionId && quickstartSessionIdPattern.test(sessionId)
          ? sessionId
          : undefined,
    };
  }
  if (parts[0] === "tool-calls" && parts[1] && parts.length === 2)
    return { id: parts[1], name: "toolCallDetail" };
  return { name: "notFound", requestedPath: `#/${path}` };
}

function routeTitle(route: CommunityRoute) {
  if (route.name === "approvalDetail")
    return "Review one exact proposed action";
  if (route.name === "approvals") return "Pending human decisions";
  if (route.name === "authorized") return "External execution grants";
  if (route.name === "audit") return "Append-only lifecycle evidence";
  if (route.name === "policy") return "Local YAML policy";
  if (route.name === "integrations")
    return "Approval channels, MCP profiles, and local mocks";
  if (route.name === "demo") return "Guided local and ChatGPT quickstart";
  if (route.name === "toolCallDetail") return "Tool-call evidence";
  if (route.name === "notFound") return "Unknown Community route";
  return "Local and self-hosted evaluation";
}
