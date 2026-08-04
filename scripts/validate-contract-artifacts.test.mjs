import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  CONTRACT_ARTIFACTS,
  ContractArtifactValidationError,
  validateContractArtifacts,
} from "./validate-contract-artifacts.mjs";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const validatorPath = path.join(
  repositoryRoot,
  "scripts/validate-contract-artifacts.mjs",
);

test("checked-in contracts pass offline standards validation", async () => {
  const report = await validateContractArtifacts(repositoryRoot);
  assert.deepEqual(report, {
    jsonSchemaDialect: "https://json-schema.org/draft/2020-12/schema",
    jsonSchemas: [
      CONTRACT_ARTIFACTS.policySchema,
      CONTRACT_ARTIFACTS.mcpWrapperSchema,
    ],
    openApi: CONTRACT_ARTIFACTS.openApi,
    openApiVersion: "3.1.0",
    referenceMode: "checked-in-local-only",
  });
});

test("standards validators are exact dependency pins in both root manifests", () => {
  const expected = {
    "@readme/openapi-parser": "6.3.0",
    ajv: "8.20.0",
  };
  for (const relativePath of ["package.json", "scripts/public-repo/package.json"]) {
    if (!fs.existsSync(path.join(repositoryRoot, relativePath))) continue;
    const manifest = JSON.parse(
      fs.readFileSync(path.join(repositoryRoot, relativePath), "utf8"),
    );
    assert.deepEqual(
      Object.fromEntries(
        Object.keys(expected).map((name) => [
          name,
          manifest.devDependencies?.[name],
        ]),
      ),
      expected,
    );
  }
  for (const relativePath of [
    "pnpm-workspace.yaml",
    "scripts/public-repo/pnpm-workspace.yaml",
  ]) {
    if (!fs.existsSync(path.join(repositoryRoot, relativePath))) continue;
    assert.match(
      fs.readFileSync(path.join(repositoryRoot, relativePath), "utf8"),
      /^\s*"fast-uri": "3\.1\.5"\s*$/mu,
      `${relativePath} must pin the patched validator URI dependency`,
    );
  }
});

test("malformed OpenAPI fails specification validation", async () => {
  await withFixture(async (fixtureRoot) => {
    mutateJson(fixtureRoot, CONTRACT_ARTIFACTS.openApi, (document) => {
      delete document.info.title;
    });
    await assert.rejects(
      validateContractArtifacts(fixtureRoot),
      hasCode("OPENAPI_STANDARD_INVALID"),
    );
  });
});

test("invalid JSON Schema fails draft 2020-12 meta-schema validation", async () => {
  await withFixture(async (fixtureRoot) => {
    mutateJson(fixtureRoot, CONTRACT_ARTIFACTS.policySchema, (schema) => {
      schema.$defs.approvalMode.type = 42;
    });
    await assert.rejects(
      validateContractArtifacts(fixtureRoot),
      hasCode("JSON_SCHEMA_STANDARD_INVALID"),
    );
  });
});

test("broken local references fail before the OpenAPI parser runs", async () => {
  await withFixture(async (fixtureRoot) => {
    mutateJson(fixtureRoot, CONTRACT_ARTIFACTS.openApi, (document) => {
      document.components.schemas.PolicyFile.$ref =
        "../schemas/missing.policy.schema.json";
    });
    await assert.rejects(
      validateContractArtifacts(fixtureRoot),
      hasCode("CONTRACT_REF_BROKEN"),
    );
  });
});

test("remote references are refused without attempting network resolution", async () => {
  await withFixture(async (fixtureRoot) => {
    mutateJson(fixtureRoot, CONTRACT_ARTIFACTS.openApi, (document) => {
      document.components.schemas.PolicyFile.$ref =
        "https://example.invalid/schema.json";
    });
    await assert.rejects(
      validateContractArtifacts(fixtureRoot),
      hasCode("CONTRACT_REF_NOT_LOCAL"),
    );
  });
});

test("CLI reports offline coverage and rejects unsupported arguments", () => {
  const success = spawnSync(process.execPath, [validatorPath], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  assert.equal(success.status, 0, success.stderr);
  assert.match(success.stdout, /validated offline: OpenAPI 3\.1\.0/u);
  assert.match(success.stdout, /refs are checked-in and local only/u);

  const invalid = spawnSync(process.execPath, [validatorPath, "--unknown"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  assert.equal(invalid.status, 2);
  assert.equal(
    invalid.stderr,
    "Usage: node scripts/validate-contract-artifacts.mjs\n",
  );
});

async function withFixture(run) {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "actionproxy-contract-validation-"),
  );
  try {
    for (const relativePath of Object.values(CONTRACT_ARTIFACTS)) {
      const destination = path.join(fixtureRoot, relativePath);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.copyFileSync(path.join(repositoryRoot, relativePath), destination);
    }
    await run(fixtureRoot);
  } finally {
    fs.rmSync(fixtureRoot, { force: true, recursive: true });
  }
}

function mutateJson(root, relativePath, mutate) {
  const artifactPath = path.join(root, relativePath);
  const value = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  mutate(value);
  fs.writeFileSync(artifactPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function hasCode(expectedCode) {
  return (error) => {
    assert.ok(error instanceof ContractArtifactValidationError);
    assert.equal(error.code, expectedCode);
    return true;
  };
}
