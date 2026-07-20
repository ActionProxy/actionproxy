import {
  Beaker,
  BookOpen,
  BriefcaseBusiness,
  ChevronDown,
  ChevronRight,
  Check,
  CreditCard,
  FolderKanban,
  Mail,
  Package,
  Pencil,
  Plus,
  Search as SearchIcon,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";
import { Fragment, type FormEvent } from "react";
import { useEffect, useMemo, useState } from "react";
import type {
  ApprovalChannelStatus,
  ApprovalMode,
  ApproverDirectoryResponse,
  McpDiscoveredTool,
  ObservedToolRecord,
  PolicyDecisionTrace,
  PolicyFile,
  PolicyRule,
  PolicySummary,
  JsonObject,
} from "../types";
import { savePolicy, simulatePolicy } from "../lib/actionproxy-client";

interface PolicyEditorProps {
  approvers?: ApproverDirectoryResponse | null;
  discoveredTools?: McpDiscoveredTool[];
  notificationChannels?: ApprovalChannelStatus[];
  observedTools?: ObservedToolRecord[];
  onAction: (action: () => Promise<void>) => Promise<void>;
  policyFile: PolicyFile | null;
  policySummary: PolicySummary | null;
  simulationSeed?: ObservedToolRecord | null;
}

interface EditableRule {
  advanced: Partial<Omit<PolicyRule, "approval" | "reason" | "risk">>;
  approval: ApprovalMode;
  id: string;
  pattern: string;
  reason: string;
  risk: string;
}

type PolicyEditTarget =
  | { type: "default" }
  | { id: string; isNew?: boolean; type: "rule" };

interface PolicyCategory {
  description: string;
  id: string;
  providers: string[];
  title: string;
}

interface PolicyCategoryGroup {
  category: PolicyCategory;
  observedTools: ObservedToolRecord[];
  rows: [string, PolicyRule][];
}

type PolicyRuleFilter =
  | "all"
  | "allowed"
  | "approval"
  | "denied"
  | "high_risk"
  | "exceptions"
  | "uncovered";

type PolicyCoverageDiagnosticKind =
  | "ambiguous_wildcard"
  | "redundant_exact"
  | "routing_exception"
  | "stricter_exception"
  | "weaker_exception"
  | "wildcard_default";

interface PolicyCoverageDiagnostic {
  kind: PolicyCoverageDiagnosticKind;
  label: string;
  message: string;
  suggestion: string;
}

interface PolicyCoverageAnalysis {
  ambiguousWildcardPairCount: number;
  diagnosticRowCount: number;
  diagnosticsByPattern: Map<string, PolicyCoverageDiagnostic[]>;
  exactExceptionCount: number;
  wildcardDefaultCount: number;
}

const approvalLabels: Record<ApprovalMode, string> = {
  deny: "Deny",
  never: "Allow",
  required: "Require approval",
};

const policyFilterLabels: Record<PolicyRuleFilter, string> = {
  all: "All",
  allowed: "Allowed",
  approval: "Needs approval",
  denied: "Denied",
  high_risk: "High risk",
  exceptions: "Exceptions",
  uncovered: "Needs review",
};

const policyCategories: PolicyCategory[] = [
  {
    description:
      "Read and retrieval namespaces used by the bundled Community demo.",
    id: "read-knowledge",
    providers: ["docs", "research", "web"],
    title: "Read / Knowledge",
  },
  {
    description:
      "Email proposals; the demo uses mock effects unless a runner is configured.",
    id: "communication",
    providers: ["gmail"],
    title: "Communication",
  },
  {
    description: "Issue and work-tracking policy namespaces in the local demo.",
    id: "work-tracking",
    providers: ["jira"],
    title: "Work tracking",
  },
  {
    description:
      "Customer-record updates represented by deterministic mock tools.",
    id: "customer-records",
    providers: ["salesforce"],
    title: "Customer records",
  },
  {
    description:
      "Refund proposals represented by deterministic mock tools.",
    id: "financial",
    providers: ["payments"],
    title: "Financial",
  },
  {
    description: "Prohibited destructive operations used to prove denial.",
    id: "high-risk",
    providers: ["dangerous"],
    title: "High risk",
  },
];

const fallbackPolicyCategory: PolicyCategory = {
  description: "Custom or discovered tool namespaces not in the demo groups.",
  id: "other-tools",
  providers: [],
  title: "Other tools",
};

function validateJsonObject(
  source: string,
):
  | { error?: string; ok: true; value?: JsonObject }
  | { error: string; ok: false } {
  if (!source.trim()) return { ok: true };
  try {
    const parsed = JSON.parse(source) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { error: "JSON must be an object.", ok: false };
    }
    return { ok: true, value: parsed as JsonObject };
  } catch {
    return { error: "JSON is invalid.", ok: false };
  }
}

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

export function PolicyEditor({
  approvers,
  discoveredTools = [],
  notificationChannels = [],
  observedTools = [],
  onAction,
  policyFile,
  policySummary,
  simulationSeed,
}: PolicyEditorProps) {
  const sourcePolicy = useMemo(
    () => policyFile ?? summaryToPolicy(policySummary),
    [policyFile, policySummary],
  );
  const [activeEditor, setActiveEditor] = useState<PolicyEditTarget | null>(
    null,
  );
  const [defaultRule, setDefaultRule] = useState<EditableRule>(() =>
    editableRule("default", sourcePolicy?.default),
  );
  const [dirty, setDirty] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [rules, setRules] = useState<EditableRule[]>(() =>
    policyToRows(sourcePolicy),
  );
  const [version, setVersion] = useState(sourcePolicy?.version ?? 1);

  useEffect(() => {
    if (dirty || activeEditor || !sourcePolicy) return;
    setDefaultRule(editableRule("default", sourcePolicy.default));
    setRules(policyToRows(sourcePolicy));
    setVersion(sourcePolicy.version);
  }, [activeEditor, dirty, sourcePolicy]);

  function markDirty() {
    setDirty(true);
    setFeedback(null);
  }

  const validation = validateRules(rules);
  const activeRule =
    activeEditor?.type === "rule"
      ? rules.find((rule) => rule.id === activeEditor.id)
      : undefined;
  const activeRuleMessage = activeRule
    ? focusedRuleMessage(activeRule, rules)
    : undefined;
  const canSave = Boolean(sourcePolicy && validation.ok && !activeRuleMessage);
  const ruleCount = rules.length;
  const displayPolicy = sourcePolicy
    ? buildPolicy(version, defaultRule, rules)
    : null;

  async function handleSave(event: FormEvent) {
    event.preventDefault();
    if (!canSave) return;
    await persistPolicy(defaultRule, rules);
  }

  async function persistPolicy(
    nextDefaultRule: EditableRule,
    nextRules: EditableRule[],
  ) {
    await onAction(async () => {
      const result = await savePolicy(
        buildPolicy(version, nextDefaultRule, nextRules),
      );
      applySavedPolicy(result.policy);
    });
  }

  function applySavedPolicy(policy: PolicyFile) {
    setDefaultRule(editableRule("default", policy.default));
    setRules(policyToRows(policy));
    setVersion(policy.version);
    setDirty(false);
    setActiveEditor(null);
    setFeedback(
      `Policy saved with ${Object.keys(policy.tools).length} tool rules.`,
    );
  }

  function editDefaultRule() {
    setActiveEditor({ type: "default" });
    setFeedback(null);
  }

  function addRule(
    initial?: Partial<
      Pick<EditableRule, "approval" | "pattern" | "reason" | "risk">
    >,
  ) {
    const id = `rule_${Date.now()}`;
    markDirty();
    setRules((current) => [
      ...current,
      {
        advanced: {},
        approval: initial?.approval ?? "required",
        id,
        pattern: initial?.pattern ?? "",
        reason: initial?.reason ?? "",
        risk: initial?.risk ?? "unknown",
      },
    ]);
    setActiveEditor({ id, isNew: true, type: "rule" });
  }

  function addRuleForCategory(category: PolicyCategory) {
    const providerPrefix = category.providers[0]
      ? `${category.providers[0]}.`
      : "";
    addRule({
      approval: "required",
      pattern: providerPrefix,
      reason:
        category.id === fallbackPolicyCategory.id
          ? ""
          : `Review ${category.title} tools before allowing them.`,
      risk: "unknown",
    });
  }

  function editRule(ruleId: string) {
    setActiveEditor({ id: ruleId, type: "rule" });
    setFeedback(null);
  }

  async function deleteActiveRule() {
    if (!activeRule) return;
    const nextRules = rules.filter((rule) => rule.id !== activeRule.id);
    await persistPolicy(defaultRule, nextRules);
  }

  function cancelEdit() {
    if (!sourcePolicy) return;
    setDefaultRule(editableRule("default", sourcePolicy.default));
    setRules(policyToRows(sourcePolicy));
    setVersion(sourcePolicy.version);
    setDirty(false);
    setActiveEditor(null);
  }

  return (
    <section
      className="panel page-panel policy-editor-page"
      aria-labelledby="policy-heading"
    >
      <div className="panel-header">
        <h2 id="policy-heading">
          <span aria-hidden="true">
            <ShieldAlert size={18} />
          </span>
          Policy
        </h2>
        <div className="policy-editor-toolbar">
          <span className="policy-count">{ruleCount} tool rules</span>
          <button
            disabled={Boolean(activeEditor)}
            type="button"
            onClick={() => addRule()}
          >
            <Plus size={18} aria-hidden="true" />
            Add rule
          </button>
        </div>
      </div>

      {feedback && <p className="success-note">{feedback}</p>}

      {activeEditor?.type === "default" && (
        <form className="policy-focused-editor" onSubmit={handleSave}>
          <div className="policy-focused-editor-header">
            <div>
              <h3>Edit default policy</h3>
              <p>Fallback behavior for tools without a specific rule.</p>
            </div>
            <ApprovalPill approval={defaultRule.approval} />
          </div>
          <div className="form-grid three">
            <label>
              Policy version
              <input
                inputMode="numeric"
                value={version}
                onChange={(event) => {
                  markDirty();
                  setVersion(Number(event.target.value) || 1);
                }}
              />
            </label>
            <label>
              Default approval
              <select
                value={defaultRule.approval}
                onChange={(event) => {
                  markDirty();
                  setDefaultRule((current) => ({
                    ...current,
                    approval: event.target.value as ApprovalMode,
                  }));
                }}
              >
                {approvalOptions()}
              </select>
            </label>
            <label>
              Default risk
              <input
                value={defaultRule.risk}
                onChange={(event) => {
                  markDirty();
                  setDefaultRule((current) => ({
                    ...current,
                    risk: event.target.value,
                  }));
                }}
              />
            </label>
            <label className="wide-field">
              Default reason
              <input
                value={defaultRule.reason}
                onChange={(event) => {
                  markDirty();
                  setDefaultRule((current) => ({
                    ...current,
                    reason: event.target.value,
                  }));
                }}
              />
            </label>
          </div>
          <div className="form-actions">
            <button disabled={!canSave} type="submit">
              <Check size={18} aria-hidden="true" />
              Save default
            </button>
            <button className="secondary" type="button" onClick={cancelEdit}>
              <X size={18} aria-hidden="true" />
              Cancel
            </button>
          </div>
        </form>
      )}

      {activeEditor?.type === "rule" && activeRule && (
        <form className="policy-focused-editor" onSubmit={handleSave}>
          <div className="policy-focused-editor-header">
            <div>
              <h3>
                {activeEditor.isNew ? "Add policy rule" : "Edit policy rule"}
              </h3>
              <p>Changes apply only to this tool pattern.</p>
            </div>
            <ApprovalPill approval={activeRule.approval} />
          </div>
          <div className="form-grid policy-rule-grid">
            <label>
              Tool pattern
              <input
                aria-invalid={!isValidPattern(activeRule.pattern)}
                placeholder="tool.name or provider.*"
                value={activeRule.pattern}
                onChange={(event) => {
                  markDirty();
                  updateRule(setRules, activeRule.id, {
                    pattern: event.target.value,
                  });
                }}
              />
            </label>
            <label>
              Approval
              <select
                value={activeRule.approval}
                onChange={(event) => {
                  markDirty();
                  updateRule(setRules, activeRule.id, {
                    approval: event.target.value as ApprovalMode,
                  });
                }}
              >
                {approvalOptions()}
              </select>
            </label>
            <label>
              Risk
              <input
                value={activeRule.risk}
                onChange={(event) => {
                  markDirty();
                  updateRule(setRules, activeRule.id, {
                    risk: event.target.value,
                  });
                }}
              />
            </label>
            <label className="wide-field">
              Reason
              <input
                value={activeRule.reason}
                onChange={(event) => {
                  markDirty();
                  updateRule(setRules, activeRule.id, {
                    reason: event.target.value,
                  });
                }}
              />
            </label>
          </div>
          {activeRule.approval === "required" &&
            approvers &&
            (approvers.users.length > 0 || approvers.groups.length > 0) && (
              <fieldset className="notify-channel-fieldset">
                <legend>Approvers</legend>
                {approvers.groups.length > 0 && (
                  <div className="checkbox-grid">
                    {approvers.groups.map((group) => {
                      const selected =
                        activeRule.advanced.approvers?.groups?.includes(
                          group.id,
                        ) ?? false;
                      return (
                        <label key={group.id} className="toggle-row">
                          <input
                            checked={selected}
                            disabled={!group.enabled}
                            type="checkbox"
                            onChange={(event) => {
                              markDirty();
                              updateRule(setRules, activeRule.id, {
                                advanced: setApproverGroup(
                                  activeRule.advanced,
                                  group.id,
                                  event.target.checked,
                                ),
                              });
                            }}
                          />
                          {group.displayName}
                        </label>
                      );
                    })}
                  </div>
                )}
                {approvers.users.length > 0 && (
                  <div className="checkbox-grid">
                    {approvers.users.map((user) => {
                      const selected =
                        activeRule.advanced.approvers?.users?.includes(
                          user.id,
                        ) ?? false;
                      return (
                        <label key={user.id} className="toggle-row">
                          <input
                            checked={selected}
                            disabled={!user.enabled}
                            type="checkbox"
                            onChange={(event) => {
                              markDirty();
                              updateRule(setRules, activeRule.id, {
                                advanced: setApproverUser(
                                  activeRule.advanced,
                                  user.id,
                                  event.target.checked,
                                ),
                              });
                            }}
                          />
                          {user.displayName}
                        </label>
                      );
                    })}
                  </div>
                )}
              </fieldset>
            )}
          {activeRule.approval === "required" &&
            notificationChannels.length > 0 && (
              <fieldset className="notify-channel-fieldset">
                <legend>Notify channels</legend>
                <div className="checkbox-grid">
                  {notificationChannels.map((channel) => {
                    const selected =
                      activeRule.advanced.notify?.channels?.includes(
                        channel.id,
                      ) ?? false;
                    return (
                      <label key={channel.id} className="toggle-row">
                        <input
                          checked={selected}
                          type="checkbox"
                          onChange={(event) => {
                            markDirty();
                            updateRule(setRules, activeRule.id, {
                              advanced: setNotifyChannel(
                                activeRule.advanced,
                                channel.id,
                                event.target.checked,
                              ),
                            });
                          }}
                        />
                        {channel.displayName}
                      </label>
                    );
                  })}
                </div>
              </fieldset>
            )}
          {activeRuleMessage && (
            <p className="field-error">{activeRuleMessage}</p>
          )}
          <div className="form-actions">
            <button disabled={!canSave} type="submit">
              <Check size={18} aria-hidden="true" />
              Save rule
            </button>
            {!activeEditor.isNew && (
              <button
                className="secondary danger-action"
                type="button"
                onClick={() => void deleteActiveRule()}
              >
                <Trash2 size={18} aria-hidden="true" />
                Delete rule
              </button>
            )}
            <button className="secondary" type="button" onClick={cancelEdit}>
              <X size={18} aria-hidden="true" />
              Cancel
            </button>
          </div>
        </form>
      )}

      {sourcePolicy && (
        <>
          {discoveredTools.length > 0 && (
            <section
              className="discovered-policy-tools"
              aria-labelledby="discovered-policy-tools-heading"
            >
              <h3 id="discovered-policy-tools-heading">
                Discovered downstream tools
              </h3>
              <div className="discovered-policy-tool-list">
                {discoveredTools.map((tool) => {
                  const exists = rules.some(
                    (rule) => rule.pattern.trim() === tool.name,
                  );
                  return (
                    <button
                      className="secondary"
                      disabled={exists || Boolean(activeEditor)}
                      key={`${tool.profileId}:${tool.name}`}
                      type="button"
                      onClick={() => {
                        const id = `rule_${Date.now()}_${tool.name}`;
                        markDirty();
                        setRules((current) => [
                          ...current,
                          {
                            advanced: {},
                            approval: "required",
                            id,
                            pattern: tool.name,
                            reason: `Approval required for downstream MCP tool ${tool.name}.`,
                            risk: tool.policyCoverage?.risk ?? "unknown",
                          },
                        ]);
                        setActiveEditor({ id, isNew: true, type: "rule" });
                      }}
                    >
                      {exists ? "Rule exists" : "Require approval"}{" "}
                      <code>{tool.name}</code>
                    </button>
                  );
                })}
              </div>
            </section>
          )}

          {!validation.ok && (
            <p className="field-error">{validation.message}</p>
          )}
          <PolicyReadView
            activePattern={activeRule?.pattern}
            editingDisabled={Boolean(activeEditor)}
            observedTools={observedTools}
            onAddRuleForCategory={addRuleForCategory}
            onEditDefault={editDefaultRule}
            onEditRule={editRule}
            policy={displayPolicy ?? sourcePolicy}
            ruleIds={rules.map((rule) => [rule.pattern, rule.id] as const)}
          />
          <PolicySimulator
            policy={displayPolicy ?? sourcePolicy}
            seedTool={simulationSeed}
          />
        </>
      )}
      {!sourcePolicy && <p className="empty">Policy unavailable.</p>}
    </section>
  );
}

function PolicyReadView({
  activePattern,
  editingDisabled,
  observedTools,
  onAddRuleForCategory,
  onEditDefault,
  onEditRule,
  policy,
  ruleIds,
}: {
  activePattern?: string;
  editingDisabled: boolean;
  observedTools: ObservedToolRecord[];
  onAddRuleForCategory: (category: PolicyCategory) => void;
  onEditDefault: () => void;
  onEditRule: (ruleId: string) => void;
  policy: PolicyFile;
  ruleIds: [string, string][];
}) {
  const rows = Object.entries(policy.tools);
  const [collapsedCategories, setCollapsedCategories] = useState<Set<string>>(
    () => new Set(),
  );
  const [expandedRows, setExpandedRows] = useState<Set<string>>(
    () => new Set(),
  );
  const [filter, setFilter] = useState<PolicyRuleFilter>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const normalizedSearchQuery = searchQuery.trim().toLowerCase();
  const actionableObservedTools = observedTools.filter(observedToolNeedsPolicy);
  const coverageAnalysis = policyCoverageAnalysis(rows);
  const filteredRows = rows.filter(
    ([pattern, rule]) =>
      policyRowMatchesFilter(pattern, rule, filter, coverageAnalysis) &&
      policyRowMatchesSearch(pattern, rule, normalizedSearchQuery),
  );
  const filteredObservedTools =
    filter === "all" || filter === "uncovered"
      ? actionableObservedTools.filter((tool) =>
          observedToolMatchesSearch(tool, normalizedSearchQuery),
        )
      : [];
  const groupedRows = groupPolicyItems(filteredRows, filteredObservedTools);
  const ruleIdByPattern = new Map(ruleIds);
  const activeSearch = normalizedSearchQuery.length > 0;
  const filterCounts = policyFilterCounts(
    rows,
    actionableObservedTools,
    coverageAnalysis,
  );
  const visibleItemCount = filteredRows.length + filteredObservedTools.length;
  const coverageSummary = policyCoverageSummary(coverageAnalysis);

  function updateSearchQuery(value: string) {
    setSearchQuery(value);
    if (value.trim()) {
      setCollapsedCategories(new Set());
    }
  }

  function toggleCategory(categoryId: string) {
    setCollapsedCategories((current) => {
      const next = new Set(current);
      if (next.has(categoryId)) {
        next.delete(categoryId);
      } else {
        next.add(categoryId);
      }
      return next;
    });
  }

  function activateFilter(
    nextFilter: PolicyRuleFilter,
    options: { clearSearch?: boolean } = {},
  ) {
    setFilter(nextFilter);
    if (options.clearSearch) {
      setSearchQuery("");
    }
    if (nextFilter === "exceptions") {
      setCollapsedCategories(new Set());
      setExpandedRows(new Set(coverageAnalysis.diagnosticsByPattern.keys()));
    }
  }

  function expandAllCategories() {
    setCollapsedCategories(new Set());
  }

  function collapseAllCategories() {
    setCollapsedCategories(
      new Set(groupedRows.map(({ category }) => category.id)),
    );
  }

  function toggleRowDetails(pattern: string) {
    setExpandedRows((current) => {
      const next = new Set(current);
      if (next.has(pattern)) {
        next.delete(pattern);
      } else {
        next.add(pattern);
      }
      return next;
    });
  }

  return (
    <div className="policy-read-view">
      <section
        className="policy-fallback-card"
        aria-labelledby="default-policy-heading"
      >
        <div className="policy-fallback-header">
          <span className="policy-fallback-icon" aria-hidden="true">
            <ShieldAlert size={18} />
          </span>
          <div>
            <span className="policy-fallback-kicker">Fallback policy</span>
            <h3 id="default-policy-heading">Default for unmatched tools</h3>
            <p>
              Applied only when no exact or wildcard tool rule covers the
              request.
            </p>
          </div>
          <div className="policy-fallback-actions">
            <ApprovalPill approval={policy.default.approval} />
            <button
              className="secondary"
              disabled={editingDisabled}
              type="button"
              onClick={onEditDefault}
            >
              <Pencil size={16} aria-hidden="true" />
              Edit default
            </button>
          </div>
        </div>
        <div className="policy-fallback-grid">
          <div>
            <span>Default risk</span>
            <strong>{policy.default.risk ?? "unknown"}</strong>
          </div>
          <div>
            <span>Policy version</span>
            <strong>{policy.version}</strong>
          </div>
          <div className="policy-fallback-reason">
            <span>Reason</span>
            <p>{policy.default.reason ?? "No reason set."}</p>
          </div>
        </div>
      </section>

      {rows.length ? (
        <>
          <div className="policy-rule-toolbar" aria-label="Policy rule filters">
            <div className="catalog-search policy-search">
              <SearchIcon size={18} aria-hidden="true" />
              <input
                aria-label="Search policy rules"
                placeholder="Search rules, risks, reasons, or approvers"
                value={searchQuery}
                onChange={(event) => updateSearchQuery(event.target.value)}
              />
            </div>
            <div
              className="policy-rule-actions"
              aria-label="Policy rule view controls"
            >
              <span className="policy-count">
                {activeSearch || filter !== "all"
                  ? `${visibleItemCount} shown`
                  : `${rows.length} rules`}
              </span>
              {activeSearch && (
                <button
                  className="secondary"
                  type="button"
                  onClick={() => updateSearchQuery("")}
                >
                  <X size={16} aria-hidden="true" />
                  Clear search
                </button>
              )}
              <button
                className="secondary"
                type="button"
                onClick={expandAllCategories}
              >
                <ChevronDown size={16} aria-hidden="true" />
                Expand all
              </button>
              <button
                className="secondary"
                type="button"
                onClick={collapseAllCategories}
              >
                <ChevronRight size={16} aria-hidden="true" />
                Collapse all
              </button>
            </div>
          </div>
          <div
            className="policy-filter-row"
            aria-label="Policy rule quick filters"
          >
            {(Object.keys(policyFilterLabels) as PolicyRuleFilter[]).map(
              (filterKey) => (
                <button
                  className={filter === filterKey ? "active" : undefined}
                  key={filterKey}
                  type="button"
                  onClick={() => activateFilter(filterKey)}
                >
                  {policyFilterLabels[filterKey]}
                  <span>{filterCounts[filterKey]}</span>
                </button>
              ),
            )}
          </div>
          {coverageAnalysis.diagnosticRowCount > 0 && (
            <button
              aria-label={`Show ${coverageAnalysis.diagnosticRowCount} policy exception rows`}
              className="policy-conflict-summary"
              type="button"
              onClick={() =>
                activateFilter("exceptions", { clearSearch: true })
              }
            >
              <ShieldAlert size={18} aria-hidden="true" />
              <span>{coverageSummary}</span>
              <strong>Review exceptions</strong>
            </button>
          )}
          {visibleItemCount ? (
            <div className="policy-category-list">
              {groupedRows.map(
                ({
                  category,
                  observedTools: categoryObservedTools,
                  rows: categoryRows,
                }) => {
                  const counts = policyCategoryApprovalCounts(categoryRows);
                  const isCollapsed = collapsedCategories.has(category.id);
                  const reviewCount = actionableObservedTools.filter(
                    (tool) =>
                      policyCategoryForPattern(tool.toolName).id ===
                      category.id,
                  ).length;
                  return (
                    <section
                      className="policy-category-card"
                      key={category.id}
                      aria-labelledby={`${category.id}-policy-heading`}
                    >
                      <div className="policy-category-header">
                        <button
                          aria-controls={`${category.id}-policy-rules`}
                          aria-expanded={!isCollapsed}
                          aria-label={`${isCollapsed ? "Expand" : "Collapse"} ${category.title}`}
                          className="policy-category-toggle"
                          type="button"
                          onClick={() => toggleCategory(category.id)}
                        >
                          <span
                            className={`catalog-category-icon ${category.id}`}
                            aria-hidden="true"
                          >
                            <PolicyCategoryIcon categoryId={category.id} />
                          </span>
                          <div>
                            <h3 id={`${category.id}-policy-heading`}>
                              {category.title}
                            </h3>
                            <p>{category.description}</p>
                          </div>
                          <div
                            className="policy-category-counts"
                            aria-label={`${category.title} policy summary`}
                          >
                            <span>{categoryRows.length} rules</span>
                            {counts.never > 0 && (
                              <span>{counts.never} allow</span>
                            )}
                            {counts.required > 0 && (
                              <span>{counts.required} approval</span>
                            )}
                            {counts.deny > 0 && <span>{counts.deny} deny</span>}
                            {reviewCount > 0 && (
                              <span className="needs-review">
                                {reviewCount} need review
                              </span>
                            )}
                          </div>
                          {isCollapsed ? (
                            <ChevronRight size={18} aria-hidden="true" />
                          ) : (
                            <ChevronDown size={18} aria-hidden="true" />
                          )}
                        </button>
                        <button
                          className="secondary policy-category-new-rule"
                          disabled={editingDisabled}
                          type="button"
                          onClick={() => onAddRuleForCategory(category)}
                        >
                          <Plus size={16} aria-hidden="true" />
                          New rule
                        </button>
                      </div>
                      {!isCollapsed && (
                        <div id={`${category.id}-policy-rules`}>
                          {categoryObservedTools.length > 0 && (
                            <div
                              className="policy-category-detector"
                              aria-label={`${category.title} detector observations`}
                            >
                              <div className="policy-category-detector-header">
                                <strong>Policy detector</strong>
                                <span>
                                  {categoryObservedTools.length} need review
                                </span>
                              </div>
                              <div className="policy-observation-list">
                                {categoryObservedTools.map((tool) => (
                                  <article
                                    className="policy-observation"
                                    key={tool.id}
                                  >
                                    <div>
                                      <code>
                                        <HighlightText
                                          query={normalizedSearchQuery}
                                          text={tool.toolName}
                                        />
                                      </code>
                                      <p>{tool.suggestion.reason}</p>
                                    </div>
                                    <div className="policy-observation-meta">
                                      <span>{tool.sources.join(", ")}</span>
                                      <span>{tool.callCount} calls</span>
                                      {tool.schemaHash && (
                                        <span>Schema {tool.schemaHash}</span>
                                      )}
                                      {tool.schemaChange && (
                                        <span>
                                          Schema changed{" "}
                                          {tool.schemaChange.previousSchemaHash}{" "}
                                          {"->"}{" "}
                                          {tool.schemaChange.currentSchemaHash}
                                        </span>
                                      )}
                                      <span>
                                        {
                                          approvalLabels[
                                            tool.suggestion.approval
                                          ]
                                        }
                                      </span>
                                    </div>
                                  </article>
                                ))}
                              </div>
                            </div>
                          )}
                          {categoryRows.length > 0 && (
                            <div className="policy-table-wrap">
                              <table>
                                <thead>
                                  <tr>
                                    <th>Tool pattern</th>
                                    <th>Approval</th>
                                    <th>Risk</th>
                                    <th>Reason</th>
                                    <th>Approvers</th>
                                    <th>Notify</th>
                                    <th>Actions</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {categoryRows.map(([pattern, rule]) => {
                                    const isExpanded =
                                      expandedRows.has(pattern);
                                    const ruleDiagnostics =
                                      coverageAnalysis.diagnosticsByPattern.get(
                                        pattern,
                                      ) ?? [];
                                    const ruleBadge =
                                      policyDiagnosticBadge(ruleDiagnostics);
                                    const relatedObservations =
                                      observedToolsForRule(
                                        pattern,
                                        observedTools,
                                      );
                                    return (
                                      <Fragment key={pattern}>
                                        <tr
                                          className={
                                            activePattern === pattern
                                              ? "active-policy-row"
                                              : undefined
                                          }
                                        >
                                          <td>
                                            <code>
                                              <HighlightText
                                                query={normalizedSearchQuery}
                                                text={pattern}
                                              />
                                            </code>
                                            {ruleBadge && (
                                              <span className="policy-warning-chip">
                                                {ruleBadge}
                                              </span>
                                            )}
                                          </td>
                                          <td>
                                            <ApprovalPill
                                              approval={rule.approval}
                                            />
                                          </td>
                                          <td>
                                            <HighlightText
                                              query={normalizedSearchQuery}
                                              text={rule.risk ?? "unknown"}
                                            />
                                          </td>
                                          <td>
                                            <HighlightText
                                              query={normalizedSearchQuery}
                                              text={rule.reason ?? "-"}
                                            />
                                          </td>
                                          <td>{approverSummary(rule)}</td>
                                          <td>
                                            {rule.notify?.channels?.join(
                                              ", ",
                                            ) || "-"}
                                          </td>
                                          <td>
                                            <div className="policy-row-actions">
                                              <button
                                                className="secondary"
                                                type="button"
                                                onClick={() =>
                                                  toggleRowDetails(pattern)
                                                }
                                              >
                                                {isExpanded ? (
                                                  <ChevronDown
                                                    size={16}
                                                    aria-hidden="true"
                                                  />
                                                ) : (
                                                  <ChevronRight
                                                    size={16}
                                                    aria-hidden="true"
                                                  />
                                                )}
                                                Details
                                              </button>
                                              <button
                                                className="secondary"
                                                disabled={
                                                  editingDisabled ||
                                                  !ruleIdByPattern.get(pattern)
                                                }
                                                type="button"
                                                onClick={() => {
                                                  const ruleId =
                                                    ruleIdByPattern.get(
                                                      pattern,
                                                    );
                                                  if (ruleId)
                                                    onEditRule(ruleId);
                                                }}
                                              >
                                                <Pencil
                                                  size={16}
                                                  aria-hidden="true"
                                                />
                                                Edit
                                              </button>
                                            </div>
                                          </td>
                                        </tr>
                                        {isExpanded && (
                                          <tr className="policy-row-detail">
                                            <td colSpan={7}>
                                              <PolicyRuleDetails
                                                diagnostics={ruleDiagnostics}
                                                observedTools={
                                                  relatedObservations
                                                }
                                                query={normalizedSearchQuery}
                                                rule={rule}
                                              />
                                            </td>
                                          </tr>
                                        )}
                                      </Fragment>
                                    );
                                  })}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      )}
                    </section>
                  );
                },
              )}
            </div>
          ) : (
            <div className="policy-search-empty">
              <strong>
                No matching policy rules or detector observations.
              </strong>
              <button
                className="secondary"
                type="button"
                onClick={() => updateSearchQuery("")}
              >
                <X size={16} aria-hidden="true" />
                Clear search
              </button>
            </div>
          )}
        </>
      ) : (
        <p className="empty">No tool-specific rules are defined.</p>
      )}
    </div>
  );
}

function ApprovalPill({ approval }: { approval: ApprovalMode }) {
  const tone =
    approval === "never" ? "good" : approval === "deny" ? "bad" : "pending";
  return (
    <span className={`status-badge ${tone}`}>{approvalLabels[approval]}</span>
  );
}

function PolicySimulator({
  policy,
  seedTool,
}: {
  policy: PolicyFile;
  seedTool?: ObservedToolRecord | null;
}) {
  const [toolName, setToolName] = useState(
    seedTool?.toolName ?? "gmail.send_email",
  );
  const [inputText, setInputText] = useState(() =>
    prettyJson({
      body: "Thanks for contacting support.",
      subject: "Follow-up",
      to: "customer@example.com",
    }),
  );
  const [metadataText, setMetadataText] = useState(() =>
    prettyJson({ actionproxyExecution: "external" }),
  );
  const [reason, setReason] = useState(
    "Check how policy would decide this action.",
  );
  const [trace, setTrace] = useState<PolicyDecisionTrace | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    if (!seedTool) return;
    setToolName(seedTool.toolName);
  }, [seedTool?.id, seedTool?.toolName]);

  async function runSimulation(event: FormEvent) {
    event.preventDefault();
    const parsedInput = validateJsonObject(inputText);
    if (!parsedInput.ok) {
      setError(`Input: ${parsedInput.error}`);
      return;
    }
    const parsedMetadata = validateJsonObject(metadataText);
    if (!parsedMetadata.ok) {
      setError(`Metadata: ${parsedMetadata.error}`);
      return;
    }
    setError(null);
    setRunning(true);
    try {
      const response = await simulatePolicy({
        agentId: "policy-simulator",
        input: parsedInput.value ?? {},
        metadata: parsedMetadata.value,
        policy,
        reason: reason.trim() || "Policy simulation",
        requestedBy: "local-policy-editor",
        toolName: toolName.trim(),
      });
      setTrace(response.trace);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setRunning(false);
    }
  }

  return (
    <section
      className="policy-simulator-panel"
      aria-labelledby="policy-simulator-heading"
    >
      <div className="section-heading compact">
        <div>
          <h3 id="policy-simulator-heading">Simulate policy</h3>
          <p>Side effects: none.</p>
        </div>
        {seedTool?.schemaChange && (
          <span className="status-badge pending">Schema changed</span>
        )}
      </div>
      {seedTool?.schemaChange && (
        <p className="muted">
          Schema previous{" "}
          <code>{seedTool.schemaChange.previousSchemaHash}</code> current{" "}
          <code>{seedTool.schemaChange.currentSchemaHash}</code>.
        </p>
      )}
      <form className="policy-simulator-form" onSubmit={runSimulation}>
        <div className="form-grid two">
          <label>
            Tool name
            <input
              value={toolName}
              onChange={(event) => setToolName(event.target.value)}
            />
          </label>
          <label>
            Reason
            <input
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>
          <label>
            Input JSON
            <textarea
              rows={6}
              value={inputText}
              onChange={(event) => setInputText(event.target.value)}
            />
          </label>
          <label>
            Metadata JSON
            <textarea
              rows={6}
              value={metadataText}
              onChange={(event) => setMetadataText(event.target.value)}
            />
          </label>
        </div>
        {error && <p className="field-error">{error}</p>}
        <div className="form-actions">
          <button disabled={running || !toolName.trim()} type="submit">
            <Beaker size={16} aria-hidden="true" />
            {running ? "Simulating" : "Simulate"}
          </button>
        </div>
      </form>
      {trace && (
        <div className="policy-simulator-result">
          <dl className="policy-rule-detail-grid">
            <div>
              <dt>Decision</dt>
              <dd>{trace.decision}</dd>
            </div>
            <div>
              <dt>Matched rule</dt>
              <dd>{trace.matchedRule}</dd>
            </div>
            <div>
              <dt>Fallback path</dt>
              <dd>{trace.fallbackPath.join(" -> ")}</dd>
            </div>
            <div>
              <dt>Policy hash</dt>
              <dd>{trace.policyVersionHash ?? "not recorded"}</dd>
            </div>
            <div>
              <dt>Input hash</dt>
              <dd>{trace.inputHash ?? "not recorded"}</dd>
            </div>
            <div>
              <dt>Envelope hash</dt>
              <dd>{trace.actionEnvelopeHash ?? "not recorded"}</dd>
            </div>
          </dl>
          <pre>
            {prettyJson({
              approverResolution: trace.approverResolution,
              ruleEvaluations: trace.ruleEvaluations,
            })}
          </pre>
        </div>
      )}
    </section>
  );
}

function HighlightText({ query, text }: { query: string; text: string }) {
  if (!query) return <>{text}</>;
  const lowerText = text.toLowerCase();
  const lowerQuery = query.toLowerCase();
  const parts: Array<{ highlighted: boolean; value: string }> = [];
  let cursor = 0;
  let matchIndex = lowerText.indexOf(lowerQuery, cursor);

  while (matchIndex !== -1) {
    if (matchIndex > cursor) {
      parts.push({ highlighted: false, value: text.slice(cursor, matchIndex) });
    }
    parts.push({
      highlighted: true,
      value: text.slice(matchIndex, matchIndex + lowerQuery.length),
    });
    cursor = matchIndex + lowerQuery.length;
    matchIndex = lowerText.indexOf(lowerQuery, cursor);
  }

  if (cursor < text.length) {
    parts.push({ highlighted: false, value: text.slice(cursor) });
  }

  return (
    <>
      {parts.map((part, index) =>
        part.highlighted ? (
          <mark className="policy-search-match" key={`${part.value}:${index}`}>
            {part.value}
          </mark>
        ) : (
          <Fragment key={`${part.value}:${index}`}>{part.value}</Fragment>
        ),
      )}
    </>
  );
}

function PolicyRuleDetails({
  diagnostics,
  observedTools,
  query,
  rule,
}: {
  diagnostics: PolicyCoverageDiagnostic[];
  observedTools: ObservedToolRecord[];
  query: string;
  rule: PolicyRule;
}) {
  return (
    <div className="policy-rule-details">
      {diagnostics.length > 0 && (
        <div className="policy-rule-warning-list">
          {diagnostics.map((diagnostic) => (
            <p key={`${diagnostic.kind}:${diagnostic.message}`}>
              <ShieldAlert size={16} aria-hidden="true" />
              <span>
                {diagnostic.message} <strong>{diagnostic.suggestion}</strong>
              </span>
            </p>
          ))}
        </div>
      )}
      <dl className="policy-rule-detail-grid">
        <div>
          <dt>Full reason</dt>
          <dd>
            <HighlightText
              query={query}
              text={rule.reason ?? "No reason set."}
            />
          </dd>
        </div>
        <div>
          <dt>Approvers</dt>
          <dd>{approverSummary(rule)}</dd>
        </div>
        <div>
          <dt>Notify channels</dt>
          <dd>{rule.notify?.channels?.join(", ") || "-"}</dd>
        </div>
        <div>
          <dt>Execution grant</dt>
          <dd>
            {rule.externalExecution
              ? [
                  rule.externalExecution.grantTtlSeconds
                    ? `${rule.externalExecution.grantTtlSeconds}s TTL`
                    : undefined,
                  rule.externalExecution.requireGrantConsumption === false
                    ? "consumption optional"
                    : "consumption required",
                ]
                  .filter(Boolean)
                  .join(", ")
              : "-"}
          </dd>
        </div>
        <div>
          <dt>Result content source</dt>
          <dd>{resultSourceSummary(rule)}</dd>
        </div>
        <div>
          <dt>Content influence</dt>
          <dd>{contentInfluenceSummary(rule)}</dd>
        </div>
      </dl>
      <div className="policy-rule-detector-detail">
        <strong>Detector context</strong>
        {observedTools.length ? (
          <div className="policy-observation-list compact">
            {observedTools.map((tool) => (
              <article className="policy-observation" key={tool.id}>
                <div>
                  <code>
                    <HighlightText query={query} text={tool.toolName} />
                  </code>
                  <p>
                    {tool.coverage.status === "uncovered"
                      ? "Default fallback is handling this tool."
                      : `Covered by ${tool.coverage.matchedRule}.`}
                  </p>
                </div>
                <div className="policy-observation-meta">
                  <span>{tool.sources.join(", ")}</span>
                  <span>{tool.callCount} calls</span>
                  {tool.schemaHash && <span>Schema {tool.schemaHash}</span>}
                  {tool.schemaChange && (
                    <span>
                      Schema changed {tool.schemaChange.previousSchemaHash}{" "}
                      {"->"} {tool.schemaChange.currentSchemaHash}
                    </span>
                  )}
                  <span>{tool.status}</span>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <p>No detector observations are linked to this rule yet.</p>
        )}
      </div>
    </div>
  );
}

function PolicyCategoryIcon({ categoryId }: { categoryId: string }) {
  if (categoryId === "read-knowledge")
    return <BookOpen size={18} aria-hidden="true" />;
  if (categoryId === "communication")
    return <Mail size={18} aria-hidden="true" />;
  if (categoryId === "work-tracking")
    return <FolderKanban size={18} aria-hidden="true" />;
  if (categoryId === "customer-records")
    return <BriefcaseBusiness size={18} aria-hidden="true" />;
  if (categoryId === "financial")
    return <CreditCard size={18} aria-hidden="true" />;
  if (categoryId === "high-risk")
    return <ShieldAlert size={18} aria-hidden="true" />;
  return <Package size={18} aria-hidden="true" />;
}

function approverSummary(rule: PolicyRule): string {
  const parts = [
    ...(rule.approvers?.groups ?? []).map((group) => `group:${group}`),
    ...(rule.approvers?.users ?? []).map((user) => `user:${user}`),
  ];
  return parts.join(", ") || "-";
}

function resultSourceSummary(rule: PolicyRule): string {
  if (rule.resultSource === "none") return "None";
  if (!rule.resultSource) return "Unknown (default)";
  return rule.resultSource.sourceId
    ? `${rule.resultSource.integrity} (${rule.resultSource.sourceId})`
    : rule.resultSource.integrity;
}

function contentInfluenceSummary(rule: PolicyRule): string {
  if (!rule.influence) return "-";
  return `Allow from ${rule.influence.allowFrom.join(", ")}; otherwise ${approvalLabels[rule.influence.otherwise].toLowerCase()}`;
}

function policyRowMatchesFilter(
  pattern: string,
  rule: PolicyRule,
  filter: PolicyRuleFilter,
  coverageAnalysis: PolicyCoverageAnalysis,
): boolean {
  if (filter === "all") return true;
  if (filter === "allowed") return rule.approval === "never";
  if (filter === "approval") return rule.approval === "required";
  if (filter === "denied") return rule.approval === "deny";
  if (filter === "high_risk") return policyRuleIsHighRisk(pattern, rule);
  if (filter === "exceptions")
    return coverageAnalysis.diagnosticsByPattern.has(pattern);
  return false;
}

function policyRowMatchesSearch(
  pattern: string,
  rule: PolicyRule,
  query: string,
): boolean {
  if (!query) return true;
  const category = policyCategoryForPattern(pattern);
  return [
    pattern,
    category.title,
    category.providers.join(" "),
    rule.approval,
    approvalLabels[rule.approval],
    rule.risk ?? "",
    rule.reason ?? "",
    approverSummary(rule),
    resultSourceSummary(rule),
    contentInfluenceSummary(rule),
    ...(rule.notify?.channels ?? []),
  ]
    .join(" ")
    .toLowerCase()
    .includes(query);
}

function observedToolMatchesSearch(
  tool: ObservedToolRecord,
  query: string,
): boolean {
  if (!query) return true;
  return [
    tool.toolName,
    tool.sources.join(" "),
    tool.schemaHash ?? "",
    tool.coverage.matchedRule,
    tool.coverage.reason,
    tool.coverage.risk,
    tool.status,
    tool.suggestion.pattern,
    tool.suggestion.reason,
    tool.suggestion.risk,
  ]
    .join(" ")
    .toLowerCase()
    .includes(query);
}

function groupPolicyItems(
  rows: [string, PolicyRule][],
  observedTools: ObservedToolRecord[],
): PolicyCategoryGroup[] {
  const groups = new Map<string, PolicyCategoryGroup>(
    [...policyCategories, fallbackPolicyCategory].map((category) => [
      category.id,
      { category, observedTools: [], rows: [] },
    ]),
  );

  for (const row of rows) {
    const category = policyCategoryForPattern(row[0]);
    groups.get(category.id)?.rows.push(row);
  }

  for (const tool of observedTools) {
    const category = policyCategoryForPattern(tool.toolName);
    groups.get(category.id)?.observedTools.push(tool);
  }

  return [...groups.values()].filter(
    (group) => group.rows.length > 0 || group.observedTools.length > 0,
  );
}

function policyCategoryForPattern(pattern: string): PolicyCategory {
  const provider =
    pattern.trim().toLowerCase().replace(/\.\*$/, "").split(".")[0] ?? "";
  return (
    policyCategories.find((category) =>
      category.providers.includes(provider),
    ) ?? fallbackPolicyCategory
  );
}

function policyCategoryApprovalCounts(
  rows: [string, PolicyRule][],
): Record<ApprovalMode, number> {
  return rows.reduce<Record<ApprovalMode, number>>(
    (counts, [, rule]) => ({
      ...counts,
      [rule.approval]: counts[rule.approval] + 1,
    }),
    { deny: 0, never: 0, required: 0 },
  );
}

function policyFilterCounts(
  rows: [string, PolicyRule][],
  observedTools: ObservedToolRecord[],
  coverageAnalysis: PolicyCoverageAnalysis,
): Record<PolicyRuleFilter, number> {
  return {
    all: rows.length,
    allowed: rows.filter(([, rule]) => rule.approval === "never").length,
    approval: rows.filter(([, rule]) => rule.approval === "required").length,
    denied: rows.filter(([, rule]) => rule.approval === "deny").length,
    high_risk: rows.filter(([pattern, rule]) =>
      policyRuleIsHighRisk(pattern, rule),
    ).length,
    exceptions: coverageAnalysis.diagnosticRowCount,
    uncovered: observedTools.length,
  };
}

function policyRuleIsHighRisk(pattern: string, rule: PolicyRule): boolean {
  const searchable = [pattern, rule.risk ?? "", rule.reason ?? ""]
    .join(" ")
    .toLowerCase();
  return [
    "credential",
    "destructive",
    "external_communication",
    "financial",
    "secret",
    "token",
  ].some((term) => searchable.includes(term));
}

function observedToolNeedsPolicy(tool: ObservedToolRecord): boolean {
  return (
    tool.status === "unresolved" &&
    (tool.coverage.status === "uncovered" ||
      tool.schemaChange?.reviewState === "needs_review")
  );
}

function policyCoverageAnalysis(
  rows: [string, PolicyRule][],
): PolicyCoverageAnalysis {
  const diagnosticsByPattern = new Map<string, PolicyCoverageDiagnostic[]>();
  const exactRows = rows.filter(([pattern]) => !pattern.endsWith(".*"));
  const wildcardRows = rows.filter(([pattern]) => pattern.endsWith(".*"));
  let exactExceptionCount = 0;
  let wildcardDefaultCount = 0;
  let ambiguousWildcardPairCount = 0;

  for (const [wildcardPattern, wildcardRule] of wildcardRows) {
    const prefix = wildcardPattern.slice(0, -1);
    const coveredExactRows = exactRows.filter(([pattern]) =>
      pattern.startsWith(prefix),
    );
    if (!coveredExactRows.length) continue;

    wildcardDefaultCount += 1;
    exactExceptionCount += coveredExactRows.length;
    addPolicyDiagnostic(diagnosticsByPattern, wildcardPattern, {
      kind: "wildcard_default",
      label: `Default except ${coveredExactRows.length}`,
      message: `${wildcardPattern} applies to matching tools except ${joinPolicyPatterns(coveredExactRows.map(([pattern]) => pattern))}.`,
      suggestion: `Treat ${wildcardPattern} as the default for other ${providerDisplayName(wildcardPattern)} tools.`,
    });

    for (const [exactPattern, exactRule] of coveredExactRows) {
      addPolicyDiagnostic(
        diagnosticsByPattern,
        exactPattern,
        exactExceptionDiagnostic(
          exactPattern,
          exactRule,
          wildcardPattern,
          wildcardRule,
        ),
      );
    }
  }

  for (let index = 0; index < wildcardRows.length; index += 1) {
    for (
      let candidateIndex = index + 1;
      candidateIndex < wildcardRows.length;
      candidateIndex += 1
    ) {
      const [firstPattern] = wildcardRows[index]!;
      const [secondPattern] = wildcardRows[candidateIndex]!;
      if (!wildcardPatternsCanOverlap(firstPattern, secondPattern)) continue;
      ambiguousWildcardPairCount += 1;
      const diagnostic: PolicyCoverageDiagnostic = {
        kind: "ambiguous_wildcard",
        label: "Ambiguous wildcard",
        message: `${firstPattern} and ${secondPattern} can both match the same tools; wildcard precedence depends on policy order.`,
        suggestion:
          "Use one wildcard default or replace the narrower case with exact rules.",
      };
      addPolicyDiagnostic(diagnosticsByPattern, firstPattern, diagnostic);
      addPolicyDiagnostic(diagnosticsByPattern, secondPattern, diagnostic);
    }
  }

  return {
    ambiguousWildcardPairCount,
    diagnosticRowCount: diagnosticsByPattern.size,
    diagnosticsByPattern,
    exactExceptionCount,
    wildcardDefaultCount,
  };
}

function exactExceptionDiagnostic(
  exactPattern: string,
  exactRule: PolicyRule,
  wildcardPattern: string,
  wildcardRule: PolicyRule,
): PolicyCoverageDiagnostic {
  const exactStrictness = approvalStrictness(exactRule.approval);
  const wildcardStrictness = approvalStrictness(wildcardRule.approval);

  if (exactStrictness > wildcardStrictness) {
    return {
      kind: "stricter_exception",
      label: "Exception",
      message: `${exactPattern} is a stricter exception to ${wildcardPattern}.`,
      suggestion: "Keep this stricter exception.",
    };
  }

  if (exactStrictness < wildcardStrictness) {
    return {
      kind: "weaker_exception",
      label: "Exception",
      message: `${exactPattern} is a weaker exception to ${wildcardPattern}.`,
      suggestion:
        "Review carefully: this exception weakens the broader wildcard rule.",
    };
  }

  if (policyRulesEquivalent(exactRule, wildcardRule)) {
    return {
      kind: "redundant_exact",
      label: "Exception",
      message: `${exactPattern} is already covered by ${wildcardPattern} with the same rule settings.`,
      suggestion: `Remove this exact rule and let ${wildcardPattern} cover it.`,
    };
  }

  return {
    kind: "routing_exception",
    label: "Exception",
    message: `${exactPattern} overrides routing or context from ${wildcardPattern}.`,
    suggestion:
      "Keep this exact rule if it needs different routing or audit context.",
  };
}

function addPolicyDiagnostic(
  diagnosticsByPattern: Map<string, PolicyCoverageDiagnostic[]>,
  pattern: string,
  diagnostic: PolicyCoverageDiagnostic,
) {
  diagnosticsByPattern.set(pattern, [
    ...(diagnosticsByPattern.get(pattern) ?? []),
    diagnostic,
  ]);
}

function approvalStrictness(approval: ApprovalMode): number {
  if (approval === "deny") return 3;
  if (approval === "required") return 2;
  return 1;
}

function policyRulesEquivalent(first: PolicyRule, second: PolicyRule): boolean {
  return (
    JSON.stringify(normalizePolicyRule(first)) ===
    JSON.stringify(normalizePolicyRule(second))
  );
}

function normalizePolicyRule(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value
      .map(normalizePolicyRule)
      .sort((first, second) =>
        JSON.stringify(first).localeCompare(JSON.stringify(second)),
      );
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, entryValue]) => entryValue !== undefined)
        .sort(([firstKey], [secondKey]) => firstKey.localeCompare(secondKey))
        .map(([key, entryValue]) => [key, normalizePolicyRule(entryValue)]),
    );
  }
  return value;
}

function wildcardPatternsCanOverlap(
  firstPattern: string,
  secondPattern: string,
): boolean {
  const firstPrefix = firstPattern.slice(0, -1);
  const secondPrefix = secondPattern.slice(0, -1);
  return (
    firstPrefix.startsWith(secondPrefix) || secondPrefix.startsWith(firstPrefix)
  );
}

function policyDiagnosticBadge(
  diagnostics: PolicyCoverageDiagnostic[],
): string | undefined {
  const ambiguousWildcard = diagnostics.find(
    (diagnostic) => diagnostic.kind === "ambiguous_wildcard",
  );
  if (ambiguousWildcard) return ambiguousWildcard.label;
  return diagnostics[0]?.label;
}

function policyCoverageSummary(analysis: PolicyCoverageAnalysis): string {
  const parts: string[] = [];
  if (analysis.wildcardDefaultCount > 0) {
    const wildcardNoun = pluralize("rule", analysis.wildcardDefaultCount);
    const exceptionNoun = pluralize("exception", analysis.exactExceptionCount);
    const verb = analysis.wildcardDefaultCount === 1 ? "has" : "have";
    parts.push(
      `${analysis.wildcardDefaultCount} wildcard ${wildcardNoun} ${verb} ${analysis.exactExceptionCount} exact ${exceptionNoun}.`,
    );
  }
  if (analysis.ambiguousWildcardPairCount > 0) {
    parts.push(
      `${analysis.ambiguousWildcardPairCount} wildcard ${pluralize("pair", analysis.ambiguousWildcardPairCount)} may match the same tools.`,
    );
  }
  return parts.join(" ");
}

function pluralize(word: string, count: number): string {
  return count === 1 ? word : `${word}s`;
}

function joinPolicyPatterns(patterns: string[]): string {
  if (patterns.length <= 1) return patterns[0] ?? "";
  if (patterns.length === 2) return `${patterns[0]} and ${patterns[1]}`;
  return `${patterns.slice(0, -1).join(", ")}, and ${patterns[patterns.length - 1]}`;
}

function providerDisplayName(pattern: string): string {
  const provider =
    pattern.trim().toLowerCase().replace(/\.\*$/, "").split(".")[0] ?? "";
  const providerLabels: Record<string, string> = {
    confluence: "Confluence",
    dangerous: "internal",
    docs: "Docs",
    github: "GitHub",
    gmail: "Gmail",
    google: "Google Workspace",
    google_calendar: "Google Calendar",
    google_drive: "Google Drive",
    hubspot: "HubSpot",
    jira: "Jira",
    notion: "Notion",
    postgres: "Postgres",
    salesforce: "Salesforce",
    slack: "Slack",
    stripe: "Stripe",
  };
  return (
    providerLabels[provider] ??
    (provider
      ? provider.charAt(0).toUpperCase() + provider.slice(1)
      : "matching")
  );
}

function observedToolsForRule(
  pattern: string,
  observedTools: ObservedToolRecord[],
): ObservedToolRecord[] {
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -1);
    return observedTools.filter(
      (tool) =>
        tool.toolName.startsWith(prefix) ||
        tool.coverage.matchedRule === pattern,
    );
  }
  return observedTools.filter(
    (tool) =>
      tool.toolName === pattern || tool.coverage.matchedRule === pattern,
  );
}

function editableRule(pattern: string, rule?: PolicyRule): EditableRule {
  const {
    approval = "required",
    reason = "",
    risk = "unknown",
    ...advanced
  } = rule ?? {};
  return {
    advanced,
    approval,
    id: `rule_${pattern}_${JSON.stringify(rule ?? {})}`,
    pattern,
    reason,
    risk,
  };
}

function policyToRows(policy: PolicyFile | null): EditableRule[] {
  return Object.entries(policy?.tools ?? {}).map(([pattern, rule]) =>
    editableRule(pattern, rule),
  );
}

function summaryToPolicy(summary: PolicySummary | null): PolicyFile | null {
  if (!summary) return null;
  return {
    default: summaryRuleToPolicyRule(summary.defaultRule),
    tools: Object.fromEntries(
      summary.rules.map((rule) => [
        rule.pattern,
        summaryRuleToPolicyRule(rule),
      ]),
    ),
    version: summary.version,
  };
}

function summaryRuleToPolicyRule(
  rule: PolicySummary["defaultRule"],
): PolicyRule {
  return {
    approval: rule.approval,
    influence: rule.influence,
    reason: rule.reason,
    resultSource: rule.resultSource,
    risk: rule.risk,
  };
}

function buildPolicy(
  version: number,
  defaultRule: EditableRule,
  rules: EditableRule[],
): PolicyFile {
  return {
    default: rowToPolicyRule(defaultRule),
    tools: Object.fromEntries(
      rules
        .map((rule) => [rule.pattern.trim(), rowToPolicyRule(rule)] as const)
        .filter(([pattern]) => Boolean(pattern)),
    ),
    version,
  };
}

function rowToPolicyRule(rule: EditableRule): PolicyRule {
  const advanced =
    rule.approval === "required"
      ? rule.advanced
      : { ...rule.advanced, notify: undefined };
  return {
    ...advanced,
    approval: rule.approval,
    reason: blankToUndefined(rule.reason),
    risk: blankToUndefined(rule.risk),
  };
}

function setNotifyChannel(
  advanced: EditableRule["advanced"],
  channelId: string,
  enabled: boolean,
): EditableRule["advanced"] {
  const current = advanced.notify?.channels ?? [];
  const channels = enabled
    ? [...new Set([...current, channelId])]
    : current.filter((candidate) => candidate !== channelId);
  return {
    ...advanced,
    notify: channels.length ? { channels } : undefined,
  };
}

function setApproverUser(
  advanced: EditableRule["advanced"],
  userId: string,
  enabled: boolean,
): EditableRule["advanced"] {
  const current = advanced.approvers?.users ?? [];
  const users = enabled
    ? [...new Set([...current, userId])]
    : current.filter((candidate) => candidate !== userId);
  return withApprovers(advanced, { users });
}

function setApproverGroup(
  advanced: EditableRule["advanced"],
  groupId: string,
  enabled: boolean,
): EditableRule["advanced"] {
  const current = advanced.approvers?.groups ?? [];
  const groups = enabled
    ? [...new Set([...current, groupId])]
    : current.filter((candidate) => candidate !== groupId);
  return withApprovers(advanced, { groups });
}

function withApprovers(
  advanced: EditableRule["advanced"],
  update: { groups?: string[]; users?: string[] },
): EditableRule["advanced"] {
  const approvers = {
    ...advanced.approvers,
    ...update,
  };
  const groups = approvers.groups?.filter(Boolean) ?? [];
  const users = approvers.users?.filter(Boolean) ?? [];
  const nextApprovers = {
    ...approvers,
    groups: groups.length ? groups : undefined,
    users: users.length ? users : undefined,
  };
  const hasApprovers =
    Boolean(nextApprovers.groups?.length) ||
    Boolean(nextApprovers.users?.length) ||
    nextApprovers.requiredApprovals !== undefined ||
    nextApprovers.separationOfDuties !== undefined;
  return {
    ...advanced,
    approvers: hasApprovers ? nextApprovers : undefined,
  };
}

function validateRules(rules: EditableRule[]): {
  message?: string;
  ok: boolean;
} {
  const patterns = rules.map((rule) => rule.pattern.trim()).filter(Boolean);
  const invalid = patterns.find((pattern) => !isValidPattern(pattern));
  if (invalid)
    return { message: `Invalid tool pattern: ${invalid}`, ok: false };

  const duplicates = patterns.filter(
    (pattern, index) => patterns.indexOf(pattern) !== index,
  );
  if (duplicates.length)
    return { message: `Duplicate policy rule: ${duplicates[0]}`, ok: false };

  return { ok: true };
}

function focusedRuleMessage(
  rule: EditableRule,
  rules: EditableRule[],
): string | undefined {
  const pattern = rule.pattern.trim();
  if (!pattern) return "Add a tool pattern before saving this rule.";
  if (!isValidPattern(pattern)) return `Invalid tool pattern: ${pattern}`;
  const duplicate = rules.some(
    (candidate) =>
      candidate.id !== rule.id && candidate.pattern.trim() === pattern,
  );
  if (duplicate) return `Duplicate policy rule: ${pattern}`;
  return undefined;
}

function isValidPattern(pattern: string): boolean {
  return /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*(?:\.\*)?$/.test(pattern.trim());
}

function approvalOptions() {
  return (Object.keys(approvalLabels) as ApprovalMode[]).map((approval) => (
    <option key={approval} value={approval}>
      {approvalLabels[approval]}
    </option>
  ));
}

function updateRule(
  setRules: (updater: (current: EditableRule[]) => EditableRule[]) => void,
  id: string,
  update: Partial<EditableRule>,
) {
  setRules((current) =>
    current.map((rule) => (rule.id === id ? { ...rule, ...update } : rule)),
  );
}

function blankToUndefined(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}
