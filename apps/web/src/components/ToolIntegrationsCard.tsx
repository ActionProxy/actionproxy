import {
  BriefcaseBusiness,
  Check,
  Database,
  FileSearch,
  Mail,
  Ticket,
} from "lucide-react";
import type { FormEvent, ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import { saveToolIntegration } from "../lib/actionproxy-client";
import type {
  IntegrationStatus,
  ToolIntegrationId,
  ToolIntegrationStatus,
} from "../types";

interface ToolIntegrationsCardProps {
  integrations: ToolIntegrationStatus[];
  onAction: (action: () => Promise<void>) => Promise<void>;
  showHeading?: boolean;
}

interface ToolSetupState {
  displayName: string;
  enabled: boolean;
  values: Record<string, string>;
}

const integrationIcons: Record<ToolIntegrationId, ReactNode> = {
  docs: <FileSearch size={18} aria-hidden="true" />,
  gmail: <Mail size={18} aria-hidden="true" />,
  jira: <Ticket size={18} aria-hidden="true" />,
  salesforce: <BriefcaseBusiness size={18} aria-hidden="true" />,
};

export function ToolIntegrationsCard({
  integrations,
  onAction,
  showHeading = true,
}: ToolIntegrationsCardProps) {
  const [dirtyIds, setDirtyIds] = useState<Set<ToolIntegrationId>>(new Set());
  const [feedback, setFeedback] = useState<string | null>(null);
  const [setup, setSetup] = useState<Record<ToolIntegrationId, ToolSetupState>>(
    () => setupFromIntegrations(integrations),
  );

  useEffect(() => {
    if (dirtyIds.size) return;
    setSetup(setupFromIntegrations(integrations));
  }, [dirtyIds.size, integrations]);

  const orderedIntegrations = useMemo(
    () =>
      integrations
        .slice()
        .sort((left, right) => left.name.localeCompare(right.name)),
    [integrations],
  );

  function markDirty(id: ToolIntegrationId) {
    setDirtyIds((current) => new Set(current).add(id));
    setFeedback(null);
  }

  async function handleSave(
    event: FormEvent,
    integration: ToolIntegrationStatus,
  ) {
    event.preventDefault();
    const current = setup[integration.id];
    await onAction(async () => {
      const result = await saveToolIntegration(integration.id, {
        displayName: current.displayName,
        enabled: current.enabled,
        values: current.values,
      });
      setSetup((existing) => ({
        ...existing,
        [integration.id]: setupFromIntegration(result.integration),
      }));
      setDirtyIds((existing) => {
        const next = new Set(existing);
        next.delete(integration.id);
        return next;
      });
      setFeedback(
        `${result.integration.name} setup saved. Status: ${statusLabel(result.integration.status)}.`,
      );
    });
  }

  if (!orderedIntegrations.length) {
    return (
      <section
        aria-label={showHeading ? undefined : "Local mock demo tools"}
        aria-labelledby={showHeading ? "tool-integrations-heading" : undefined}
        className="panel integration-panel tool-integrations-panel"
      >
        {showHeading && (
          <div className="panel-header">
            <h2 id="tool-integrations-heading">
              <span aria-hidden="true">
                <Database size={18} />
              </span>
              Local mock demo tools
            </h2>
          </div>
        )}
        <p className="empty">No local mock demo tools are available.</p>
      </section>
    );
  }

  return (
    <section
      aria-label={showHeading ? undefined : "Local mock demo tools"}
      aria-labelledby={showHeading ? "tool-integrations-heading" : undefined}
      className="panel integration-panel tool-integrations-panel"
    >
      {showHeading && (
        <div className="panel-header">
          <h2 id="tool-integrations-heading">
            <span aria-hidden="true">
              <Database size={18} />
            </span>
            Local mock demo tools
          </h2>
        </div>
      )}

      <div className="tool-integration-grid">
        {orderedIntegrations.map((integration) => {
          const current =
            setup[integration.id] ?? setupFromIntegration(integration);
          return (
            <form
              className="tool-integration-card"
              key={integration.id}
              onSubmit={(event) => void handleSave(event, integration)}
            >
              <div className="tool-integration-title">
                <span className="tool-integration-icon">
                  {integrationIcons[integration.id]}
                </span>
                <div>
                  <h3>{integration.name}</h3>
                  <p>{integration.description}</p>
                </div>
                <StatusPill status={integration.status} />
              </div>

              <label className="toggle-row">
                <input
                  aria-label={`Enable ${integration.name}`}
                  checked={current.enabled}
                  type="checkbox"
                  onChange={(event) => {
                    markDirty(integration.id);
                    setSetup((existing) => ({
                      ...existing,
                      [integration.id]: {
                        ...current,
                        enabled: event.target.checked,
                      },
                    }));
                  }}
                />
                Enabled for local mock setup
              </label>

              <label>
                Display name
                <input
                  aria-label={`${integration.name} display name`}
                  value={current.displayName}
                  onChange={(event) => {
                    markDirty(integration.id);
                    setSetup((existing) => ({
                      ...existing,
                      [integration.id]: {
                        ...current,
                        displayName: event.target.value,
                      },
                    }));
                  }}
                />
              </label>

              <div className="tool-fields">
                {integration.fields.map((field) => (
                  <label key={field.key}>
                    {field.label}
                    <input
                      aria-label={`${integration.name} ${field.label}`}
                      placeholder={field.placeholder}
                      value={current.values[field.key] ?? ""}
                      onChange={(event) => {
                        markDirty(integration.id);
                        setSetup((existing) => ({
                          ...existing,
                          [integration.id]: {
                            ...current,
                            values: {
                              ...current.values,
                              [field.key]: event.target.value,
                            },
                          },
                        }));
                      }}
                    />
                  </label>
                ))}
              </div>

              <div
                className="tool-name-list"
                aria-label={`${integration.name} tools`}
              >
                {integration.tools.map((toolName) => (
                  <code key={toolName}>{toolName}</code>
                ))}
              </div>

              <button type="submit">
                <Check size={18} aria-hidden="true" />
                Save {integration.name}
              </button>
            </form>
          );
        })}
      </div>
      {feedback && <p className="success-note">{feedback}</p>}
    </section>
  );
}

function setupFromIntegrations(
  integrations: ToolIntegrationStatus[],
): Record<ToolIntegrationId, ToolSetupState> {
  return Object.fromEntries(
    integrations.map((integration) => [
      integration.id,
      setupFromIntegration(integration),
    ]),
  ) as Record<ToolIntegrationId, ToolSetupState>;
}

function setupFromIntegration(
  integration: ToolIntegrationStatus,
): ToolSetupState {
  return {
    displayName: integration.displayName,
    enabled: integration.enabled,
    values: Object.fromEntries(
      integration.fields.map((field) => [field.key, field.value ?? ""]),
    ),
  };
}

function StatusPill({ status }: { status: IntegrationStatus }) {
  return (
    <span className={`status-badge ${statusTone(status)}`}>
      {statusLabel(status)}
    </span>
  );
}

function statusLabel(status: IntegrationStatus): string {
  if (status === "ready") return "Ready";
  if (status === "partial") return "Partial";
  return "Disabled";
}

function statusTone(status: IntegrationStatus): "bad" | "good" | "pending" {
  if (status === "ready") return "good";
  if (status === "partial") return "pending";
  return "bad";
}
