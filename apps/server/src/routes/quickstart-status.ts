import type { FastifyInstance } from "fastify";
import { z } from "zod";
import {
  QuickstartStatusService,
  quickstartApprovalTimeoutMs,
  quickstartCheckIds,
  quickstartCheckStates,
  quickstartJourneys,
  quickstartProjectPattern,
  quickstartRemediationCodes,
  quickstartSchemaVersion,
  quickstartSetupStages,
  quickstartVersionPattern,
} from "../services/quickstart-status";
import { headerValue } from "./route-utils";

const quickstartSessionIdSchema = z
  .string()
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const quickstartParamsSchema = z
  .object({ sessionId: quickstartSessionIdSchema })
  .strict();
const quickstartCheckSchema = z
  .object({
    id: z.enum(quickstartCheckIds),
    remediationCode: z.enum(quickstartRemediationCodes).optional(),
    state: z.enum(quickstartCheckStates),
  })
  .strict();
const quickstartVersionSchema = z
  .string()
  .min(3)
  .max(64)
  .regex(quickstartVersionPattern);
const quickstartSetupDetailsSchema = z
  .object({
    composeVersion: quickstartVersionSchema,
    dockerVersion: quickstartVersionSchema,
    nodeVersion: quickstartVersionSchema,
    port: z.number().int().min(1024).max(65535),
    projectName: z.string().regex(quickstartProjectPattern),
    runtimeKeyExcludedFromDocker: z.boolean().optional(),
  })
  .strict();
const quickstartStatusUpdateSchema = z
  .object({
    approvalTimeoutMs: z.literal(quickstartApprovalTimeoutMs),
    checks: z.array(quickstartCheckSchema).max(quickstartCheckIds.length),
    journey: z.enum(quickstartJourneys),
    schemaVersion: z.literal(quickstartSchemaVersion),
    sessionId: quickstartSessionIdSchema,
    setupDetails: quickstartSetupDetailsSchema.optional(),
    setupStage: z.enum(quickstartSetupStages),
    tunnelUiUrl: z.string().refine(isLoopbackHttpUrl).optional(),
  })
  .strict()
  .superRefine((status, context) => {
    const duplicateCheckId = status.checks.find(
      (check, index) =>
        status.checks.findIndex((candidate) => candidate.id === check.id) !==
        index,
    )?.id;
    if (duplicateCheckId) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: `Duplicate Quickstart check: ${duplicateCheckId}`,
        path: ["checks"],
      });
    }

    const tunnelStage = [
      "tunnel_checking",
      "tunnel_ready",
      "tunnel_stopped",
    ].includes(status.setupStage);
    if (status.journey === "local" && tunnelStage) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Local Quickstart journeys cannot publish tunnel stages.",
        path: ["setupStage"],
      });
    }
    if (status.journey === "local" && status.tunnelUiUrl) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Local Quickstart journeys cannot publish a tunnel UI URL.",
        path: ["tunnelUiUrl"],
      });
    }
    if (
      status.journey === "local" &&
      status.setupDetails?.runtimeKeyExcludedFromDocker !== undefined
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "Local Quickstart journeys cannot publish a tunnel runtime-key check.",
        path: ["setupDetails", "runtimeKeyExcludedFromDocker"],
      });
    }
    if (status.setupStage === "tunnel_ready") {
      const readiness = status.checks.find(
        (check) => check.id === "tunnel_readiness",
      );
      if (status.journey !== "chatgpt") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Only ChatGPT Quickstart journeys can become tunnel-ready.",
          path: ["journey"],
        });
      }
      if (readiness?.state !== "pass") {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "Tunnel-ready status requires a passing tunnel_readiness check.",
          path: ["checks"],
        });
      }
      if (!status.tunnelUiUrl) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Tunnel-ready status requires a loopback tunnel UI URL.",
          path: ["tunnelUiUrl"],
        });
      }
      if (status.setupDetails?.runtimeKeyExcludedFromDocker !== true) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "Tunnel-ready status requires proof that the runtime key is excluded from Docker.",
          path: ["setupDetails", "runtimeKeyExcludedFromDocker"],
        });
      }
    }
  });

export async function registerQuickstartStatusRoutes(
  app: FastifyInstance,
  service: QuickstartStatusService,
): Promise<void> {
  app.get("/v1/demo/quickstart/status/:sessionId", async (request, reply) => {
    const params = quickstartParamsSchema.safeParse(request.params);
    if (!params.success || !service.hasSession(params.data.sessionId)) {
      return reply.status(404).send({ error: "not_found" });
    }

    const status = service.get(params.data.sessionId);
    if (!status) return reply.status(404).send({ error: "not_found" });
    return reply.header("cache-control", "no-store").send(status);
  });

  app.put("/v1/demo/quickstart/status/:sessionId", async (request, reply) => {
    const params = quickstartParamsSchema.safeParse(request.params);
    if (!params.success || !service.hasSession(params.data.sessionId)) {
      return reply.status(404).send({ error: "not_found" });
    }

    const updateToken = headerValue(
      request.headers["x-actionproxy-quickstart-token"],
    );
    if (!service.acceptsUpdateToken(updateToken)) {
      return reply.status(401).send({ error: "unauthorized" });
    }

    const update = quickstartStatusUpdateSchema.safeParse(request.body);
    if (!update.success) {
      return reply.status(400).send({
        details: update.error.flatten(),
        error: "invalid_request",
      });
    }
    if (update.data.sessionId !== params.data.sessionId) {
      return reply.status(400).send({
        error: "invalid_request",
        message: "Quickstart session ID must match the request path.",
      });
    }

    return reply
      .header("cache-control", "no-store")
      .send(service.update(update.data));
  });
}

function isLoopbackHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === "http:" &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      (url.hostname === "127.0.0.1" ||
        url.hostname === "localhost" ||
        url.hostname === "[::1]")
    );
  } catch {
    return false;
  }
}
