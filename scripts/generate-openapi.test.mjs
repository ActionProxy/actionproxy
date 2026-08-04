import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildOpenApiDocument,
  COMMUNITY_HTTP_OPERATIONS,
  COMMUNITY_ROUTE_SOURCES,
  normalizeFastifyRoute,
  OPENAPI_ARTIFACT,
  operationKeys,
  serializeOpenApiDocument,
} from "./generate-openapi.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("generated OpenAPI artifact is deterministic and current", async () => {
  const first = serializeOpenApiDocument();
  const second = serializeOpenApiDocument();
  const committed = await readFile(path.join(repositoryRoot, OPENAPI_ARTIFACT), "utf8");

  assert.equal(first, second);
  assert.equal(committed, first);
  assert.deepEqual(JSON.parse(committed), buildOpenApiDocument());

  const output = execFileSync(process.execPath, ["scripts/generate-openapi.mjs", "--check"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  assert.match(output, /OpenAPI contract is current/u);
});

test("OpenAPI operations exactly match the Community Fastify route surface", async () => {
  const actualRoutes = [];
  for (const source of COMMUNITY_ROUTE_SOURCES) {
    const contents = await readFile(path.join(repositoryRoot, source), "utf8");
    for (const match of contents.matchAll(/app\.(get|post|put|patch|delete)\(\s*["']([^"']+)["']/gu)) {
      actualRoutes.push(normalizeFastifyRoute(match[1], match[2]));
    }
  }

  assert.deepEqual([...new Set(actualRoutes)].sort(), operationKeys());
  assert.equal(actualRoutes.length, operationKeys().length, "Community routes must not be registered twice");
});

test("route-source inventory follows Community app composition and excludes static web", async () => {
  const appSource = await readFile(path.join(repositoryRoot, "apps/server/src/app.ts"), "utf8");
  const importedRouteFiles = [...appSource.matchAll(/import \{ register[A-Za-z]+Routes \} from ['"]\.\/routes\/([^'"]+)['"]/gu)]
    .map((match) => `apps/server/src/routes/${match[1]}.ts`)
    .filter((source) => source !== "apps/server/src/routes/web.ts")
    .map((source) => {
      if (source === "apps/server/src/routes/slack.ts") return "apps/server/src/integrations/slack/slack-routes.ts";
      if (source === "apps/server/src/routes/telegram.ts") return "apps/server/src/integrations/telegram/telegram-routes.ts";
      return source;
    })
    .sort();

  assert.deepEqual([...COMMUNITY_ROUTE_SOURCES].sort(), importedRouteFiles);
});

test("contract is OpenAPI 3.1, internally complete, and references canonical config schemas", async () => {
  const document = buildOpenApiDocument();
  assert.equal(document.openapi, "3.1.0");
  assert.equal(document.jsonSchemaDialect, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(document.components.schemas.PolicyFile.$ref, "../schemas/actionproxy.policy.v1.schema.json");
  assert.equal(document.components.schemas.McpWrapperConfig.$ref, "../schemas/actionproxy.mcp-wrapper.v1.schema.json");
  assert.equal(document.components.schemas.McpWrapperProfile.type, "object");

  const [policySchema, mcpSchema] = await Promise.all([
    readJson("schemas/actionproxy.policy.v1.schema.json"),
    readJson("schemas/actionproxy.mcp-wrapper.v1.schema.json"),
  ]);
  assert.equal(policySchema.$id, "https://actionproxy.com/schemas/actionproxy.policy.v1.schema.json");
  assert.equal(mcpSchema.$id, "https://actionproxy.com/schemas/actionproxy.mcp-wrapper.v1.schema.json");

  const operationIds = new Set();
  for (const [routePath, pathItem] of Object.entries(document.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      assert.ok(["get", "post", "put", "patch", "delete"].includes(method));
      assert.ok(operation.summary);
      assert.equal(operation.tags.length, 1);
      assert.ok(operation.responses && Object.keys(operation.responses).length > 0);
      assert.ok(!operationIds.has(operation.operationId), `duplicate operationId ${operation.operationId}`);
      operationIds.add(operation.operationId);

      for (const name of [...routePath.matchAll(/\{([^}]+)\}/gu)].map((match) => match[1])) {
        const parameter = operation.parameters?.find((item) => item.in === "path" && item.name === name);
        assert.ok(parameter, `${method} ${routePath} is missing path parameter ${name}`);
        assert.equal(parameter.required, true);
      }
    }
  }
  assert.equal(operationIds.size, COMMUNITY_HTTP_OPERATIONS.length);

  for (const reference of collectRefs(document)) {
    if (!reference.startsWith("#/components/schemas/")) continue;
    const name = reference.slice("#/components/schemas/".length);
    assert.ok(document.components.schemas[name], `missing internal schema ${name}`);
  }
});

test("contract contains no private platform-only API surface", () => {
  const serialized = serializeOpenApiDocument();
  for (const forbidden of [
    "/v1/agents",
    "/v1/agent-flow-drafts",
    "/v1/integrations/connected-apps",
    "/v1/integrations/business-actions",
    "/v1/system/capabilities",
    "/mcp/chatgpt-work",
    "oauth/callback",
  ]) {
    assert.doesNotMatch(serialized, new RegExp(escapeRegExp(forbidden), "u"));
  }
});

test("generator rejects invalid CLI usage with exit code 2", () => {
  assert.throws(
    () => execFileSync(process.execPath, ["scripts/generate-openapi.mjs", "--unknown"], {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: "pipe",
    }),
    (error) => error?.status === 2 && /Usage:/u.test(error.stderr),
  );
});

async function readJson(relativePath) {
  return JSON.parse(await readFile(path.join(repositoryRoot, relativePath), "utf8"));
}

function collectRefs(value, found = []) {
  if (Array.isArray(value)) {
    for (const child of value) collectRefs(child, found);
    return found;
  }
  if (!value || typeof value !== "object") return found;
  if (typeof value.$ref === "string") found.push(value.$ref);
  for (const child of Object.values(value)) collectRefs(child, found);
  return found;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
