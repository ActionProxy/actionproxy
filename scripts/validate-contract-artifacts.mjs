#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { validate as validateOpenApi } from "@readme/openapi-parser";
import Ajv2020 from "ajv/dist/2020.js";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

export const CONTRACT_ARTIFACTS = Object.freeze({
  mcpWrapperSchema: "schemas/actionproxy.mcp-wrapper.v1.schema.json",
  openApi: "openapi/actionproxy.openapi.json",
  policySchema: "schemas/actionproxy.policy.v1.schema.json",
});

const JSON_SCHEMA_DIALECT =
  "https://json-schema.org/draft/2020-12/schema";

export class ContractArtifactValidationError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "ContractArtifactValidationError";
    this.code = code;
  }
}

export async function validateContractArtifacts(root = repositoryRoot) {
  const canonicalRoot = fs.realpathSync(root);
  const artifacts = new Map();
  for (const relativePath of Object.values(CONTRACT_ARTIFACTS)) {
    artifacts.set(
      relativePath,
      readJsonArtifact(canonicalRoot, relativePath),
    );
  }

  assertReferencesStayLocal(canonicalRoot, artifacts);

  const schemaPaths = [
    CONTRACT_ARTIFACTS.policySchema,
    CONTRACT_ARTIFACTS.mcpWrapperSchema,
  ];
  validateJsonSchemas(
    schemaPaths.map((relativePath) => ({
      relativePath,
      schema: artifacts.get(relativePath),
    })),
  );

  const openApiPath = path.join(canonicalRoot, CONTRACT_ARTIFACTS.openApi);
  let openApiResult;
  try {
    openApiResult = await validateOpenApi(openApiPath);
  } catch (error) {
    throw new ContractArtifactValidationError(
      "OPENAPI_VALIDATION_FAILED",
      `the offline OpenAPI validator could not process ${CONTRACT_ARTIFACTS.openApi}: ${safeErrorName(error)}`,
    );
  }
  if (!openApiResult.valid || openApiResult.specification !== "OpenAPI") {
    throw new ContractArtifactValidationError(
      "OPENAPI_STANDARD_INVALID",
      `${CONTRACT_ARTIFACTS.openApi} failed OpenAPI 3.1 structural or specification validation (${openApiResult.errors?.length ?? 1} error(s))`,
    );
  }
  if ((openApiResult.warnings?.length ?? 0) > 0) {
    throw new ContractArtifactValidationError(
      "OPENAPI_STANDARD_WARNING",
      `${CONTRACT_ARTIFACTS.openApi} produced ${openApiResult.warnings.length} standards warning(s)`,
    );
  }

  return Object.freeze({
    jsonSchemaDialect: JSON_SCHEMA_DIALECT,
    jsonSchemas: Object.freeze([...schemaPaths]),
    openApi: CONTRACT_ARTIFACTS.openApi,
    openApiVersion: artifacts.get(CONTRACT_ARTIFACTS.openApi).openapi,
    referenceMode: "checked-in-local-only",
  });
}

export function assertReferencesStayLocal(root, artifacts) {
  const allowedArtifacts = new Set(Object.values(CONTRACT_ARTIFACTS));
  const scanned = new Set();

  const scan = (relativePath) => {
    if (scanned.has(relativePath)) return;
    scanned.add(relativePath);
    const document = artifacts.get(relativePath);
    if (!document) {
      throw new ContractArtifactValidationError(
        "CONTRACT_REF_BROKEN",
        `${relativePath} is not an available checked-in contract artifact`,
      );
    }

    for (const reference of collectReferences(document)) {
      const { fragment, target } = splitReference(reference, relativePath);
      let targetRelativePath = relativePath;
      if (target !== "") {
        if (
          path.isAbsolute(target) ||
          target.includes("\\") ||
          /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(target)
        ) {
          throw new ContractArtifactValidationError(
            "CONTRACT_REF_NOT_LOCAL",
            `${relativePath} contains a non-local $ref`,
          );
        }
        const resolved = path.resolve(
          root,
          path.dirname(relativePath),
          target,
        );
        if (!isInside(root, resolved)) {
          throw new ContractArtifactValidationError(
            "CONTRACT_REF_NOT_LOCAL",
            `${relativePath} contains a $ref outside the contract root`,
          );
        }
        targetRelativePath = normalizePath(path.relative(root, resolved));
        if (!allowedArtifacts.has(targetRelativePath)) {
          throw new ContractArtifactValidationError(
            "CONTRACT_REF_BROKEN",
            `${relativePath} references an unavailable contract artifact: ${targetRelativePath}`,
          );
        }
      }

      const targetDocument = artifacts.get(targetRelativePath);
      if (!targetDocument) {
        throw new ContractArtifactValidationError(
          "CONTRACT_REF_BROKEN",
          `${relativePath} references a missing contract artifact: ${targetRelativePath}`,
        );
      }
      assertFragmentExists(targetDocument, fragment, relativePath);
      scan(targetRelativePath);
    }
  };

  for (const relativePath of allowedArtifacts) scan(relativePath);
  return true;
}

function readJsonArtifact(root, relativePath) {
  const artifactPath = path.join(root, relativePath);
  let stat;
  try {
    stat = fs.lstatSync(artifactPath);
  } catch {
    throw new ContractArtifactValidationError(
      "CONTRACT_ARTIFACT_MISSING",
      `${relativePath} is missing`,
    );
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new ContractArtifactValidationError(
      "CONTRACT_ARTIFACT_UNSAFE",
      `${relativePath} must be a regular file`,
    );
  }
  try {
    return JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  } catch (error) {
    throw new ContractArtifactValidationError(
      "CONTRACT_JSON_INVALID",
      `${relativePath} is not valid JSON: ${safeErrorName(error)}`,
    );
  }
}

function validateJsonSchemas(entries) {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateFormats: false,
    validateSchema: true,
  });

  for (const { relativePath, schema } of entries) {
    if (schema.$schema !== JSON_SCHEMA_DIALECT) {
      throw new ContractArtifactValidationError(
        "JSON_SCHEMA_DIALECT_INVALID",
        `${relativePath} must declare ${JSON_SCHEMA_DIALECT}`,
      );
    }
    if (!ajv.validateSchema(schema)) {
      throw new ContractArtifactValidationError(
        "JSON_SCHEMA_STANDARD_INVALID",
        `${relativePath} failed draft 2020-12 meta-schema validation: ${formatAjvErrors(ajv.errors)}`,
      );
    }
    try {
      ajv.addSchema(schema);
    } catch (error) {
      throw new ContractArtifactValidationError(
        "JSON_SCHEMA_STANDARD_INVALID",
        `${relativePath} could not be compiled as draft 2020-12: ${safeErrorName(error)}`,
      );
    }
  }

  for (const { relativePath, schema } of entries) {
    try {
      if (!ajv.getSchema(schema.$id)) {
        throw new Error("compiled validator is unavailable");
      }
    } catch (error) {
      throw new ContractArtifactValidationError(
        "JSON_SCHEMA_REF_INVALID",
        `${relativePath} contains an unresolved or invalid schema reference: ${safeErrorName(error)}`,
      );
    }
  }
}

function collectReferences(value, found = []) {
  if (Array.isArray(value)) {
    for (const child of value) collectReferences(child, found);
    return found;
  }
  if (!value || typeof value !== "object") return found;
  if (Object.hasOwn(value, "$ref")) {
    if (typeof value.$ref !== "string" || value.$ref.length === 0) {
      throw new ContractArtifactValidationError(
        "CONTRACT_REF_INVALID",
        "$ref values must be non-empty strings",
      );
    }
    found.push(value.$ref);
  }
  for (const child of Object.values(value)) collectReferences(child, found);
  return found;
}

function splitReference(reference, sourcePath) {
  const hashIndex = reference.indexOf("#");
  const target = hashIndex === -1 ? reference : reference.slice(0, hashIndex);
  const encodedFragment =
    hashIndex === -1 ? "" : reference.slice(hashIndex + 1);
  let fragment;
  try {
    fragment = decodeURIComponent(encodedFragment);
  } catch {
    throw new ContractArtifactValidationError(
      "CONTRACT_REF_INVALID",
      `${sourcePath} contains a $ref with an invalid URI fragment`,
    );
  }
  return { fragment, target };
}

function assertFragmentExists(document, fragment, sourcePath) {
  if (fragment === "") return;
  if (!fragment.startsWith("/")) {
    if (findAnchor(document, fragment)) return;
    throw new ContractArtifactValidationError(
      "CONTRACT_REF_BROKEN",
      `${sourcePath} contains a $ref to an unknown anchor`,
    );
  }

  let current = document;
  for (const encodedSegment of fragment.slice(1).split("/")) {
    if (/~(?:[^01]|$)/u.test(encodedSegment)) {
      throw new ContractArtifactValidationError(
        "CONTRACT_REF_INVALID",
        `${sourcePath} contains an invalid JSON Pointer escape`,
      );
    }
    const segment = encodedSegment.replaceAll("~1", "/").replaceAll("~0", "~");
    if (
      !current ||
      typeof current !== "object" ||
      !Object.hasOwn(current, segment)
    ) {
      throw new ContractArtifactValidationError(
        "CONTRACT_REF_BROKEN",
        `${sourcePath} contains a $ref to a missing JSON Pointer`,
      );
    }
    current = current[segment];
  }
}

function findAnchor(value, anchor) {
  if (Array.isArray(value)) return value.some((child) => findAnchor(child, anchor));
  if (!value || typeof value !== "object") return false;
  if (value.$anchor === anchor || value.$dynamicAnchor === anchor) return true;
  return Object.values(value).some((child) => findAnchor(child, anchor));
}

function formatAjvErrors(errors) {
  if (!Array.isArray(errors) || errors.length === 0) return "unknown error";
  return errors
    .slice(0, 3)
    .map(({ instancePath, keyword }) => `${instancePath || "/"} (${keyword})`)
    .join(", ");
}

function safeErrorName(error) {
  return error instanceof Error && error.name ? error.name : "validation error";
}

function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

function normalizePath(value) {
  return value.split(path.sep).join("/");
}

const isMain =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  if (process.argv.length !== 2) {
    console.error("Usage: node scripts/validate-contract-artifacts.mjs");
    process.exitCode = 2;
  } else {
    try {
      const report = await validateContractArtifacts();
      console.log(
        `Contract artifacts validated offline: OpenAPI ${report.openApiVersion} and ${report.jsonSchemas.length} JSON Schema draft 2020-12 documents; refs are checked-in and local only.`,
      );
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  }
}
