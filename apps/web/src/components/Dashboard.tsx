import {
  Activity,
  Beaker,
  Bell,
  Bot,
  Check,
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
  type CSSProperties,
  type FormEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useState,
} from "react";
import type {
  ApprovalRecord,
  ApprovalReview,
  AuditEvent,
  DashboardData,
  JsonObject,
  McpWrapperProfileSummary,
  PolicyDecision,
  ToolCallRecord,
} from "../types";
import {
  approveApproval,
  buildAuditExportUrl,
  fetchApproval,
  fetchApprovalReview,
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
  | { name: "approvalDetail"; id: string }
  | { name: "authorized" }
  | { name: "audit" }
  | { name: "policy" }
  | { name: "integrations" }
  | { name: "demo" }
  | { name: "toolCallDetail"; id: string }
  | { name: "notFound"; requestedPath: string };

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
    label: "Demo lab",
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
        <ApprovalDetail data={data} id={route.id} onAction={runAction} />
      )}
      {route.name === "authorized" && <RunnerQueue data={data} />}
      {route.name === "audit" && <AuditLog events={data.auditEvents} />}
      {route.name === "policy" && (
        <PolicyPage data={data} onAction={runAction} />
      )}
      {route.name === "integrations" && (
        <Integrations data={data} onAction={runAction} />
      )}
      {route.name === "demo" && <DemoLab data={data} onRefresh={onRefresh} />}
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
                  : "#/demo"
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
              href="#/demo"
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
}: {
  data: DashboardData;
  id: string;
  onAction: (action: () => Promise<void>) => Promise<void>;
}) {
  const listed = data.pendingApprovals.find((approval) => approval.id === id);
  const [record, setRecord] = useState<{
    approval: ApprovalRecord;
    toolCall: ToolCallRecord;
  } | null>(null);
  const [review, setReview] = useState<ApprovalReview | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const approval = listed ?? record?.approval;
  const toolCall =
    data.toolCalls.find((call) => call.id === approval?.toolCallId) ??
    record?.toolCall;
  const [inputText, setInputText] = useState("");
  const [actor, setActor] = useState("local-reviewer@example.com");
  const [reason, setReason] = useState(
    "Rejected after reviewing the exact proposal.",
  );

  useEffect(() => {
    let cancelled = false;
    setLoadError(null);
    Promise.all([fetchApproval(id), fetchApprovalReview(id)])
      .then(([nextRecord, nextReview]) => {
        if (!cancelled) {
          setRecord(nextRecord);
          setReview(nextReview);
        }
      })
      .catch((caught) => {
        if (!cancelled)
          setLoadError(
            caught instanceof Error ? caught.message : String(caught),
          );
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  useEffect(() => {
    if (approval && !inputText)
      setInputText(prettyJson(approval.originalInput));
  }, [approval, inputText]);

  async function approve(event: FormEvent) {
    event.preventDefault();
    if (!approval) return;
    const parsed = parseJsonObject(inputText);
    if (!parsed.ok) {
      setLoadError(parsed.error);
      return;
    }
    const edited =
      JSON.stringify(parsed.value) !== JSON.stringify(approval.originalInput);
    await onAction(() =>
      approveApproval(approval.id, {
        approvedBy: actor,
        editedInput: edited ? parsed.value : undefined,
        inputDecision: edited
          ? { input: parsed.value, mode: "edited" }
          : { mode: "original" },
        reviewHash: review?.reviewHash,
      }),
    );
  }

  if (loadError && !approval) return <ErrorState message={loadError} />;
  if (!approval || !toolCall) return <p role="status">Loading approval…</p>;

  return (
    <section
      className="panel page-panel approval-detail"
      aria-labelledby="approval-detail-heading"
    >
      <PanelHeading
        icon={<ClipboardCheck size={18} />}
        id="approval-detail-heading"
        title="Approval detail"
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
        <Status label={approval.status} tone="pending" />
      </div>
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
              value={inputText}
              onChange={(event) => setInputText(event.target.value)}
            />
            <small>Edits are retained beside the original payload.</small>
          </article>
        </div>
      </section>
      {toolCall.contentInfluence && (
        <ContentInfluence evidence={toolCall.contentInfluence} />
      )}
      <form className="approval-form" onSubmit={approve}>
        <label>
          Decision actor
          <input
            aria-label="Decision actor"
            value={actor}
            onChange={(event) => setActor(event.target.value)}
          />
        </label>
        <div className="form-actions">
          <button type="submit" disabled={!actor.trim()}>
            <Check size={18} aria-hidden="true" /> Approve
          </button>
          <button
            className="secondary danger-action"
            type="button"
            disabled={!actor.trim()}
            onClick={() =>
              void onAction(() =>
                rejectApproval(approval.id, { reason, rejectedBy: actor }),
              )
            }
          >
            Reject
          </button>
        </div>
        <label>
          Rejection reason
          <input
            aria-label="Rejection reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
      </form>
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
  onRefresh,
}: {
  data: DashboardData;
  onRefresh: () => Promise<void> | void;
}) {
  return (
    <>
      <section className="demo-lab-notice" aria-label="Local demo notice">
        <span>
          <Beaker size={18} aria-hidden="true" />
          Local-only demo lab
        </span>
        <strong>
          The guided lifecycle uses deterministic mock tools. It does not send
          email or delete a customer.
        </strong>
      </section>
      <AgentDemoPanel data={data} onRefresh={onRefresh} />
      <ChatGptTunnelPanel data={data} />
    </>
  );
}

const tunnelIdPattern = /^tunnel_[A-Za-z0-9_-]{8,128}$/u;
const tunnelPrompts = [
  [
    "Allowed search",
    "Use ActionProxy to search the demo docs for the refund policy.",
  ],
  [
    "Approval-required email",
    "Use ActionProxy to send a demo email to customer@example.com. Wait while I approve it in ActionProxy.",
  ],
  [
    "Denied deletion",
    "Use ActionProxy to delete customer cus_123 as a policy test.",
  ],
] as const;

function ChatGptTunnelPanel({ data }: { data: DashboardData }) {
  const [tunnelId, setTunnelId] = useState("");
  const [copied, setCopied] = useState("");
  const valid = tunnelIdPattern.test(tunnelId);
  const command = valid
    ? `corepack pnpm demo:chatgpt:tunnel -- --tunnel-id ${tunnelId}`
    : "";
  const tunnelCalls = data.toolCalls.filter(isTunnelCall);
  const pending = data.pendingApprovals.find((approval) =>
    tunnelCalls.some((call) => call.id === approval.toolCallId),
  );
  async function copy(id: string, value: string) {
    await navigator.clipboard?.writeText(value);
    setCopied(id);
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
              : tunnelCalls.length
                ? "ChatGPT activity seen"
                : "Waiting for first call"
          }
          tone={pending ? "pending" : tunnelCalls.length ? "good" : "neutral"}
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
      <div className="chatgpt-tunnel-setup-grid">
        <div className="chatgpt-tunnel-launcher">
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
          <small>Kept only in this browser tab's memory.</small>
          <div className="chatgpt-tunnel-command" aria-live="polite">
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
              {copied === "command" ? "Copied" : "Copy command"}
            </button>
          </div>
          <a
            className="text-link"
            href="https://platform.openai.com/settings/organization/tunnels"
            rel="noreferrer"
            target="_blank"
          >
            OpenAI Tunnel Settings <ExternalLink size={14} aria-hidden="true" />
          </a>
        </div>
        <div className="chatgpt-tunnel-prompts">
          <h3>Try the policy paths in ChatGPT</h3>
          {tunnelPrompts.map(([label, prompt]) => (
            <article className="chatgpt-tunnel-prompt" key={label}>
              <div>
                <strong>{label}</strong>
                <span>{prompt}</span>
              </div>
              <button
                aria-label={`Copy ${label.toLowerCase()} prompt`}
                className="secondary icon-button"
                onClick={() => void copy(label, prompt)}
                type="button"
              >
                {copied === label ? <Check size={16} /> : <Copy size={16} />}
              </button>
            </article>
          ))}
        </div>
      </div>
      {pending && (
        <a
          className="text-link"
          href={`#/approvals/${encodeURIComponent(pending.id)}`}
        >
          Open pending approval
        </a>
      )}
    </section>
  );
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
  return (
    call.agentId === "actionproxy-chatgpt-tunnel-demo" ||
    call.metadata?.mcpServer === "chatgpt-tunnel-demo"
  );
}
function hasTunnelActivity(data: DashboardData) {
  return data.toolCalls.some(isTunnelCall);
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
  const path =
    hash.replace(/^#\/?/u, "").replace(/\/$/u, "").split("?")[0] ?? "";
  const parts = path ? path.split("/").map(decodeURIComponent) : [];
  if (!parts.length) return { name: "overview" };
  if (parts[0] === "approvals" && parts[1] && parts.length === 2)
    return { id: parts[1], name: "approvalDetail" };
  if (parts[0] === "approvals" && parts.length === 1)
    return { name: "approvals" };
  if (parts[0] === "authorized" && parts.length === 1)
    return { name: "authorized" };
  if (parts[0] === "audit" && parts.length === 1) return { name: "audit" };
  if (parts[0] === "policy" && parts.length === 1) return { name: "policy" };
  if (parts[0] === "integrations" && parts.length === 1)
    return { name: "integrations" };
  if (parts[0] === "demo" && parts.length === 1) return { name: "demo" };
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
  if (route.name === "demo") return "Deterministic local demonstration";
  if (route.name === "toolCallDetail") return "Tool-call evidence";
  if (route.name === "notFound") return "Unknown Community route";
  return "Local and self-hosted evaluation";
}
