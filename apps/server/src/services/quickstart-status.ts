import { sha256Hex, safeEqual } from "../security/crypto";

export const quickstartSchemaVersion = "actionproxy.quickstart.v1" as const;
export const quickstartApprovalTimeoutMs = 300_000 as const;
export const quickstartHeartbeatStaleMs = 15_000;
export const quickstartProjectPattern = /^actionproxy-first-run-[0-9a-f]{10}$/u;
export const quickstartVersionPattern =
  /^v?(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){1,3}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;

export const quickstartJourneys = ["local", "chatgpt"] as const;
export const quickstartSetupStages = [
  "gateway_starting",
  "gateway_ready",
  "tunnel_checking",
  "tunnel_ready",
  "tunnel_stopped",
  "failed",
] as const;
export const quickstartCheckIds = [
  "node",
  "docker_cli",
  "docker_daemon",
  "compose",
  "gateway",
  "storage",
  "loopback",
  "tool_discovery",
  "tunnel_client",
  "tunnel_doctor",
  "tunnel_readiness",
] as const;
export const quickstartCheckStates = [
  "pending",
  "running",
  "pass",
  "action_required",
  "fail",
] as const;
export const quickstartRemediationCodes = [
  "unsupported_os",
  "unsupported_node",
  "docker_missing",
  "docker_not_running",
  "compose_missing",
  "gateway_unhealthy",
  "storage_not_sqlite",
  "non_loopback_binding",
  "runtime_key_in_docker",
  "tool_discovery_mismatch",
  "tunnel_client_missing",
  "tunnel_client_incompatible",
  "tunnel_access_failed",
  "tunnel_not_ready",
  "tunnel_disconnected",
] as const;

export type QuickstartJourney = (typeof quickstartJourneys)[number];
export type QuickstartSetupStage = (typeof quickstartSetupStages)[number];
export type QuickstartCheckId = (typeof quickstartCheckIds)[number];
export type QuickstartCheckState = (typeof quickstartCheckStates)[number];
export type QuickstartRemediationCode =
  (typeof quickstartRemediationCodes)[number];

export interface QuickstartCheck {
  id: QuickstartCheckId;
  remediationCode?: QuickstartRemediationCode;
  state: QuickstartCheckState;
}

export interface QuickstartSetupDetails {
  composeVersion: string;
  dockerVersion: string;
  nodeVersion: string;
  port: number;
  projectName: string;
  runtimeKeyExcludedFromDocker?: boolean;
}

export interface QuickstartStatusUpdate {
  approvalTimeoutMs: typeof quickstartApprovalTimeoutMs;
  checks: QuickstartCheck[];
  journey: QuickstartJourney;
  schemaVersion: typeof quickstartSchemaVersion;
  sessionId: string;
  setupDetails?: QuickstartSetupDetails;
  setupStage: QuickstartSetupStage;
  tunnelUiUrl?: string;
}

export interface QuickstartStatus extends QuickstartStatusUpdate {
  startedAt: string;
  updatedAt: string;
}

export interface QuickstartStatusServiceOptions {
  now?: () => Date;
  sessionId: string;
  updateToken: string;
}

/**
 * Ephemeral transport state for the local first-run UI. This service is
 * deliberately independent of ActionProxy storage and audit interfaces.
 */
export class QuickstartStatusService {
  private readonly now: () => Date;
  private readonly sessionId: string;
  private readonly updateTokenHash: string;
  private status?: QuickstartStatus;

  constructor(options: QuickstartStatusServiceOptions) {
    this.now = options.now ?? (() => new Date());
    this.sessionId = options.sessionId;
    this.updateTokenHash = sha256Hex(options.updateToken);
  }

  hasSession(sessionId: string): boolean {
    return safeEqual(sha256Hex(sessionId), sha256Hex(this.sessionId));
  }

  acceptsUpdateToken(updateToken: string | undefined): boolean {
    if (!updateToken) return false;
    return safeEqual(sha256Hex(updateToken), this.updateTokenHash);
  }

  get(sessionId: string): QuickstartStatus | undefined {
    if (!this.hasSession(sessionId) || !this.status) return undefined;
    return this.statusForRead(this.status);
  }

  update(update: QuickstartStatusUpdate): QuickstartStatus {
    if (!this.hasSession(update.sessionId)) {
      throw new Error("Quickstart status session does not match this service.");
    }
    const now = this.now().toISOString();
    const next: QuickstartStatus = {
      ...update,
      checks: update.checks.map((check) => ({ ...check })),
      setupDetails: update.setupDetails
        ? { ...update.setupDetails }
        : undefined,
      startedAt: this.status?.startedAt ?? now,
      updatedAt: now,
    };
    this.status = next;
    return this.statusForRead(next);
  }

  private statusForRead(status: QuickstartStatus): QuickstartStatus {
    const copy: QuickstartStatus = {
      ...status,
      checks: status.checks.map((check) => ({ ...check })),
      setupDetails: status.setupDetails
        ? { ...status.setupDetails }
        : undefined,
    };
    if (
      copy.setupStage !== "tunnel_ready" ||
      this.now().getTime() - Date.parse(copy.updatedAt) <=
        quickstartHeartbeatStaleMs
    ) {
      return copy;
    }

    copy.setupStage = "tunnel_stopped";
    const readiness = copy.checks.find(
      (check) => check.id === "tunnel_readiness",
    );
    if (readiness) {
      readiness.state = "action_required";
      readiness.remediationCode = "tunnel_disconnected";
    } else {
      copy.checks.push({
        id: "tunnel_readiness",
        remediationCode: "tunnel_disconnected",
        state: "action_required",
      });
    }
    return copy;
  }
}
