#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const semanticVersionPattern =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u;

const packageVersionFiles = [
  ["root package", "package.json", true],
  ["server package", "apps/server/package.json", true],
  ["web package", "apps/web/package.json", true],
  ["SDK package", "packages/sdk-js/package.json", true],
  ["MCP wrapper package", "packages/mcp-wrapper/package.json", true],
  ["canonical public root package", "scripts/public-repo/package.json", false],
  [
    "canonical public server package",
    "scripts/public-repo/server.package.json",
    false,
  ],
  [
    "canonical public web package",
    "scripts/public-repo/web.package.json",
    false,
  ],
  [
    "canonical public SDK package",
    "scripts/public-repo/sdk-js.package.json",
    false,
  ],
  [
    "canonical public MCP wrapper package",
    "scripts/public-repo/mcp-wrapper.package.json",
    false,
  ],
];

const textVersionFiles = [
  {
    label: "First Run CLI",
    minimumMatches: 1,
    pattern: /export const FIRST_RUN_VERSION = "([^"]+)";/gu,
    relativePath: "scripts/first-run.mjs",
    required: true,
  },
  {
    label: "First Run generated MCP starter",
    minimumMatches: 1,
    pattern:
      /serverInfo: \{ name: 'actionproxy-safe-starter', version: '([^']+)' \}/gu,
    relativePath: "scripts/first-run.mjs",
    required: true,
  },
  {
    label: "MCP wrapper protocol identity",
    minimumMatches: 2,
    pattern:
      /(?:clientInfo|serverInfo): \{ name: 'actionproxy-mcp-wrapper', version: '([^']+)' \}/gu,
    relativePath: "packages/mcp-wrapper/src/wrap-server.ts",
    required: true,
  },
  {
    label: "MCP smoke client identity",
    minimumMatches: 1,
    pattern:
      /clientInfo: \{ name: 'actionproxy-mcp-smoke-test', version: '([^']+)' \}/gu,
    relativePath: "examples/mcp-demo/run-smoke-test.mjs",
    required: true,
  },
  {
    firstMatchOnly: true,
    label: "current changelog release",
    minimumMatches: 1,
    pattern: /^## ([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$/gmu,
    relativePath: "CHANGELOG.md",
    required: true,
  },
];

const releaseTagFiles = [
  {
    label: "public-export verifier",
    pattern: /const approvedReleaseTag = ["'](v[^"']+)["'];/gu,
    relativePath: "scripts/verify-public-export.mjs",
    required: true,
  },
  {
    label: "tracked-checkout attestation",
    pattern: /const approvedReleaseTag = ["'](v[^"']+)["'];/gu,
    relativePath: "scripts/attest-public-checkout.mjs",
    required: true,
  },
  {
    label: "public-manifest refresh",
    pattern: /const approvedReleaseTag = ["'](v[^"']+)["'];/gu,
    relativePath: "scripts/refresh-public-manifest.mjs",
    required: true,
  },
  {
    label: "local OSS release verifier",
    pattern: /const expectedReleaseTag = ["'](v[^"']+)["'];/gu,
    relativePath: "scripts/verify-oss-release-local.mjs",
    required: false,
  },
  {
    label: "release workflow",
    minimumMatches: 0,
    pattern: /^\s*ACTIONPROXY_PUBLIC_RELEASE_TAG:\s*(v\S+)\s*$/gmu,
    relativePath: ".github/workflows/security.yml",
    required: false,
  },
];

export function collectReleaseVersionFacts(root = repositoryRoot) {
  const versionFacts = [];
  const tagFacts = [];
  const errors = [];

  for (const [label, relativePath, required] of packageVersionFiles) {
    const filePath = path.join(root, relativePath);
    if (!fs.existsSync(filePath)) {
      if (required) errors.push(`${relativePath} is missing`);
      continue;
    }
    try {
      const manifest = JSON.parse(fs.readFileSync(filePath, "utf8"));
      if (typeof manifest.version !== "string") {
        errors.push(`${relativePath} does not declare a string version`);
        continue;
      }
      versionFacts.push({ label, source: `${relativePath}#version`, value: manifest.version });
    } catch (error) {
      errors.push(
        `${relativePath} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const openApiPath = path.join(root, "openapi/actionproxy.openapi.json");
  try {
    const openApi = JSON.parse(fs.readFileSync(openApiPath, "utf8"));
    if (typeof openApi?.info?.version !== "string") {
      errors.push("openapi/actionproxy.openapi.json does not declare info.version");
    } else {
      versionFacts.push({
        label: "OpenAPI contract",
        source: "openapi/actionproxy.openapi.json#info.version",
        value: openApi.info.version,
      });
    }
  } catch (error) {
    errors.push(
      `openapi/actionproxy.openapi.json cannot be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  collectTextFacts(root, textVersionFiles, versionFacts, errors);
  collectTextFacts(root, releaseTagFiles, tagFacts, errors);

  const publicManifestPath = path.join(root, "PUBLIC_MANIFEST.json");
  if (fs.existsSync(publicManifestPath)) {
    try {
      const manifest = JSON.parse(fs.readFileSync(publicManifestPath, "utf8"));
      if (typeof manifest.releaseTag !== "string") {
        errors.push("PUBLIC_MANIFEST.json does not declare releaseTag");
      } else {
        tagFacts.push({
          label: "public manifest",
          source: "PUBLIC_MANIFEST.json#releaseTag",
          value: manifest.releaseTag,
        });
      }
    } catch (error) {
      errors.push(
        `PUBLIC_MANIFEST.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  return { errors, tagFacts, versionFacts };
}

export function assertReleaseVersionFacts({ errors = [], tagFacts, versionFacts }) {
  const failures = [...errors];
  const orderedVersions = [...versionFacts].sort(compareFacts);
  const orderedTags = [...tagFacts].sort(compareFacts);
  const rootVersion = versionFacts.find(
    ({ source }) => source === "package.json#version",
  )?.value;

  if (!rootVersion) {
    failures.push("package.json#version is the required release baseline");
  } else if (!semanticVersionPattern.test(rootVersion)) {
    failures.push(`package.json#version is not a supported semantic version: ${rootVersion}`);
  }

  if (orderedVersions.length === 0) {
    failures.push("no version-bearing release artifacts were found");
  }
  for (const fact of orderedVersions) {
    if (!semanticVersionPattern.test(fact.value)) {
      failures.push(`${fact.source} has an invalid version: ${fact.value}`);
    } else if (rootVersion && fact.value !== rootVersion) {
      failures.push(
        `${fact.source} declares ${fact.value}; expected ${rootVersion}`,
      );
    }
  }

  const expectedReleaseTag = rootVersion ? `v${rootVersion}` : undefined;
  if (orderedTags.length === 0) {
    failures.push("no intended release-tag artifacts were found");
  }
  for (const fact of orderedTags) {
    if (expectedReleaseTag && fact.value !== expectedReleaseTag) {
      failures.push(
        `${fact.source} declares ${fact.value}; expected ${expectedReleaseTag}`,
      );
    }
  }

  if (failures.length > 0) {
    throw new Error(
      ["Release-version consistency check failed:", ...failures.map((failure) => `- ${failure}`)].join("\n"),
    );
  }

  return {
    releaseTag: expectedReleaseTag,
    tagSources: orderedTags.map(({ source }) => source),
    version: rootVersion,
    versionSources: orderedVersions.map(({ source }) => source),
  };
}

export function checkReleaseVersions(root = repositoryRoot) {
  return assertReleaseVersionFacts(collectReleaseVersionFacts(root));
}

function collectTextFacts(root, specifications, output, errors) {
  for (const specification of specifications) {
    const filePath = path.join(root, specification.relativePath);
    if (!fs.existsSync(filePath)) {
      if (specification.required) {
        errors.push(`${specification.relativePath} is missing`);
      }
      continue;
    }
    const body = fs.readFileSync(filePath, "utf8");
    const matches = [...body.matchAll(specification.pattern)];
    if (matches.length < (specification.minimumMatches ?? 1)) {
      errors.push(
        `${specification.relativePath} does not expose the expected ${specification.label} version marker`,
      );
      continue;
    }
    const selectedMatches = specification.firstMatchOnly
      ? matches.slice(0, 1)
      : matches;
    for (const [index, match] of selectedMatches.entries()) {
      output.push({
        label: specification.label,
        source: `${specification.relativePath}#${specification.label.replaceAll(" ", "-")}-${index + 1}`,
        value: match[1],
      });
    }
  }
}

function compareFacts(left, right) {
  return left.source < right.source ? -1 : left.source > right.source ? 1 : 0;
}

const isMain =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  if (process.argv.length !== 2) {
    console.error("Usage: node scripts/check-release-versions.mjs");
    process.exitCode = 2;
  } else {
    try {
      const report = checkReleaseVersions();
      console.log(
        `Release versions are consistent: ${report.version} (${report.releaseTag}); ${report.versionSources.length} version markers and ${report.tagSources.length} release-tag markers checked.`,
      );
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  }
}
