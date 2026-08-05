import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertReleaseVersionFacts,
  checkReleaseVersions,
} from "./check-release-versions.mjs";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const scriptPath = path.join(repositoryRoot, "scripts/check-release-versions.mjs");

test("all versioned release artifacts and intended tags stay aligned", () => {
  const report = checkReleaseVersions(repositoryRoot);
  assert.equal(report.version, "0.1.0");
  assert.equal(report.releaseTag, "v0.1.0");
  assert.ok(report.versionSources.includes("packages/sdk-js/package.json#version"));
  assert.ok(
    report.versionSources.includes("packages/mcp-wrapper/package.json#version"),
  );
  assert.ok(
    report.versionSources.includes(
      "openapi/actionproxy.openapi.json#info.version",
    ),
  );
  assert.ok(
    report.tagSources.some((source) =>
      source.startsWith("scripts/verify-public-export.mjs#"),
    ),
  );
});

test("drift failures are deterministic and name every mismatched artifact", () => {
  const facts = {
    tagFacts: [
      { source: "z-release#tag", value: "v0.3.0" },
      { source: "a-release#tag", value: "v0.2.0" },
    ],
    versionFacts: [
      { source: "z-package#version", value: "0.3.0" },
      { source: "package.json#version", value: "0.1.0" },
      { source: "a-package#version", value: "0.2.0" },
    ],
  };
  let firstMessage = "";
  assert.throws(
    () => assertReleaseVersionFacts(facts),
    (error) => {
      firstMessage = error.message;
      assert.match(error.message, /a-package#version declares 0\.2\.0/u);
      assert.match(error.message, /z-package#version declares 0\.3\.0/u);
      assert.match(error.message, /a-release#tag declares v0\.2\.0/u);
      assert.match(error.message, /z-release#tag declares v0\.3\.0/u);
      return true;
    },
  );
  assert.throws(
    () =>
      assertReleaseVersionFacts({
        tagFacts: [...facts.tagFacts].reverse(),
        versionFacts: [...facts.versionFacts].reverse(),
      }),
    (error) => {
      assert.equal(error.message, firstMessage);
      return true;
    },
  );
});

test("CLI has stable success and invalid-usage exit codes", () => {
  const success = spawnSync(process.execPath, [scriptPath], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  assert.equal(success.status, 0, success.stderr);
  assert.match(success.stdout, /Release versions are consistent: 0\.1\.0/u);

  const invalid = spawnSync(process.execPath, [scriptPath, "--unknown"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  assert.equal(invalid.status, 2);
  assert.equal(
    invalid.stderr,
    "Usage: node scripts/check-release-versions.mjs\n",
  );
});
