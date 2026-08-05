#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import {
  comparePublicPaths as comparePaths,
  gitModeFromStat,
  isRegularGitMode,
  isSafePublicPath as isSafeRelativePath,
  parseGitStageRecords,
  PUBLIC_MANIFEST_SCHEMA_VERSION,
} from "./public-manifest.mjs";

const destination = path.resolve(
  process.argv[2] ?? "/tmp/actionproxy-public-export",
);
const strict = process.argv.includes("--strict");
const checkoutMode = process.argv.includes("--checkout");
const jsonOutput = process.argv.includes("--json");
const approvedRepository = "https://github.com/ActionProxy/actionproxy";
const approvedReleaseTag = "v0.1.0";
const verificationReportSchemaVersion = "actionproxy.public-verification.v1";
const failures = [];
let verifiedManifest;
let verificationFiles;
let verificationGitModes;
const markdownAnchorCache = new Map();

const requiredPaths = [
  ".dockerignore",
  ".env.example",
  ".github/ISSUE_TEMPLATE/bug_report.md",
  ".github/ISSUE_TEMPLATE/config.yml",
  ".github/ISSUE_TEMPLATE/feature_request.md",
  ".github/ISSUE_TEMPLATE/good_first_issue.md",
  ".github/dependabot.yml",
  ".github/pull_request_template.md",
  ".github/workflows/security.yml",
  ".gitattributes",
  ".gitignore",
  ".node-version",
  ".nvmrc",
  "AGENTS.md",
  "CHANGELOG.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "Dockerfile",
  "LICENSE",
  "openapi/actionproxy.openapi.json",
  "PUBLIC_MANIFEST.json",
  "README.md",
  "SECURITY.md",
  "SUPPORT.md",
  "actionproxy",
  "apps/server/package.json",
  "apps/server/vitest.config.ts",
  "apps/server/src/app.ts",
  "apps/server/src/community-boundary.test.ts",
  "apps/server/src/index.ts",
  "apps/server/src/routes/quickstart-status.test.ts",
  "apps/server/src/routes/quickstart-status.ts",
  "apps/server/src/services/quickstart-status.ts",
  "apps/server/src/storage/migrations/0001_initial.sql",
  "apps/server/src/storage/migrations/0002_legacy_schema_reconciliation.sql",
  "apps/server/src/storage/migrations/0003_approver_principal_identity.sql",
  "apps/web/index.html",
  "apps/web/package.json",
  "apps/web/src/App.tsx",
  "apps/web/src/community-boundary.test.ts",
  "apps/web/src/components/Dashboard.community.test.tsx",
  "apps/web/tests/e2e/community.spec.ts",
  "apps/web/tests/e2e/community.spec.ts-snapshots/first-run-approval-waiting-desktop-darwin.png",
  "apps/web/tests/e2e/community.spec.ts-snapshots/first-run-chooser-desktop-darwin.png",
  "apps/web/tests/e2e/community.spec.ts-snapshots/first-run-completion-desktop-darwin.png",
  "apps/web/tests/e2e/community.spec.ts-snapshots/first-run-remediation-desktop-darwin.png",
  "apps/web/tests/e2e/community.spec.ts-snapshots/first-run-tunnel-ready-desktop-darwin.png",
  "docs/API_SPEC.md",
  "docs/ADOPTING.md",
  "docs/APPROVAL_CHANNELS.md",
  "docs/ARCHITECTURE.md",
  "docs/CHATGPT_MCP.md",
  "docs/COMMUNITY_CAPABILITIES.md",
  "docs/CONTENT_INFLUENCE_PERFORMANCE.md",
  "docs/EXTERNAL_RUNNERS_MCP.md",
  "docs/OSS_TEST_STATUS.md",
  "docs/POLICY_SPEC.md",
  "docs/PRD.md",
  "docs/SECURITY_MODEL.md",
  "docs/THREAT_MODEL.md",
  "docs/TROUBLESHOOTING.md",
  "examples/README.md",
  "examples/chatgpt-app/README.md",
  "examples/chatgpt-tunnel/README.md",
  "examples/chatgpt-tunnel/actionproxy.mcp.yaml",
  "examples/chatgpt-tunnel/openai-links.json",
  "examples/chatgpt-tunnel/tunnel-client-distribution.json",
  "examples/chatgpt-tunnel/run-tunnel.mjs",
  "examples/chatgpt-tunnel/run-tunnel.test.mjs",
  "examples/google-workspace-mcp-demo/.env.example",
  "examples/google-workspace-mcp-demo/README.md",
  "examples/google-workspace-mcp-demo/actionproxy.mcp.yaml",
  "examples/google-workspace-mcp-demo/actionproxy.policy.yaml",
  "examples/google-workspace-mcp-demo/demo-support.mjs",
  "examples/google-workspace-mcp-demo/google-workspace-mcp-demo.test.mjs",
  "examples/google-workspace-mcp-demo/package.json",
  "examples/google-workspace-mcp-demo/run-gmail-draft-test.mjs",
  "examples/local-curl-demo/README.md",
  "package.json",
  "packages/mcp-wrapper/LICENSE",
  "packages/mcp-wrapper/package.json",
  "packages/mcp-wrapper/src/package-artifacts.test.ts",
  "packages/mcp-wrapper/src/doctor.ts",
  "packages/sdk-js/LICENSE",
  "packages/sdk-js/package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "scripts/attest-public-checkout.mjs",
  "scripts/check-dependency-audit.mjs",
  "scripts/check-release-versions.mjs",
  "scripts/check-release-versions.test.mjs",
  "scripts/check-runtime-licenses.mjs",
  "scripts/check-workflow-actions.mjs",
  "scripts/dev.mjs",
  "scripts/dev.test.mjs",
  "scripts/first-run.mjs",
  "scripts/first-run.test.mjs",
  "scripts/generate-config-schemas.mjs",
  "scripts/generate-config-schemas.test.mjs",
  "scripts/generate-openapi.mjs",
  "scripts/generate-openapi.test.mjs",
  "scripts/public-manifest.mjs",
  "scripts/refresh-public-manifest.mjs",
  "scripts/run-postgres-release-tests.mjs",
  "scripts/run-postgres-release-tests.test.mjs",
  "scripts/scan-public-secrets.mjs",
  "scripts/smoke-community-docker.mjs",
  "scripts/smoke-packaged-mcp-wrapper.mjs",
  "scripts/supply-chain.test.mjs",
  "scripts/validate-contract-artifacts.mjs",
  "scripts/validate-contract-artifacts.test.mjs",
  "scripts/validate-sbom.mjs",
  "scripts/verify-public-export.mjs",
  "schemas/actionproxy.mcp-wrapper.v1.schema.json",
  "schemas/actionproxy.policy.v1.schema.json",
  "schemas/editor-associations.json",
  "tsconfig.base.json",
];

const requiredRootScripts = [
  "benchmark:content-influence",
  "build",
  "contracts:validate",
  "demo:chatgpt",
  "demo:chatgpt:tunnel",
  "demo:gmail-mcp",
  "demo:mcp",
  "demo:mcp:hosts",
  "demo:mcp:manual",
  "dev",
  "dev:proxy:gmail-mcp",
  "dev:proxy",
  "dev:server",
  "dev:web",
  "dev:web:gmail-mcp",
  "docker:build",
  "docker:smoke:community",
  "lint",
  "manifest:refresh",
  "openapi:check",
  "openapi:generate",
  "quickstart",
  "release:versions:check",
  "schemas:check",
  "schemas:generate",
  "smoke:mcp-package",
  "supply-chain:audit",
  "supply-chain:licenses",
  "supply-chain:sbom",
  "test",
  "test:dev",
  "test:e2e",
  "test:e2e:community",
  "test:first-run",
  "test:consumer-conformance",
  "test:contract-validation",
  "test:mcp-hosts",
  "test:openapi",
  "test:postgres:no-skip",
  "test:release-versions",
  "test:schemas",
  "test:supply-chain",
  "verify:oss-boundary",
  "verify:tracked-checkout",
  "workflow:check",
];

const forbiddenPaths = [
  ".git",
  "Makefile",
  "PUBLIC_EXPORT_NOTES.md",
  "codex",
  "planning",
  "private",
  "research",
  "supabase",
  "apps/server/src/e2e-platform-server.ts",
  "apps/server/src/platform-app.ts",
  "apps/server/src/platform-index.ts",
  "apps/server/src/platform-modules.ts",
  "apps/server/src/platform",
  "apps/server/src/private",
  "apps/server/src/integrations/connector-token-crypto.ts",
  "apps/server/src/integrations/google-workspace",
  "apps/server/src/integrations/hubspot",
  "apps/server/src/integrations/stripe",
  "apps/server/src/integrations/teams",
  "apps/server/src/integrations/zendesk",
  "examples/google-workspace-mcp-demo/.env.local",
  "apps/server/src/integrations/slack/slack-connector.ts",
  "apps/server/src/integrations/slack/slack-oauth.ts",
  "apps/server/src/routes/agent-flow-drafts.ts",
  "apps/server/src/routes/agents.ts",
  "apps/server/src/routes/chatgpt-work.ts",
  "apps/server/src/routes/integrations-platform.ts",
  "apps/server/src/routes/system.ts",
  "apps/server/src/routes/task-contracts.ts",
  "apps/server/src/services/agent-flow-builder.ts",
  "apps/server/src/services/agent-run.ts",
  "apps/server/src/services/agent-templates.ts",
  "apps/server/src/services/model-provider.ts",
  "apps/server/src/services/task-contracts.ts",
  "apps/web/content",
  "apps/web/public",
  "apps/web/scripts",
  "apps/web/src/components/MarketingLanding.tsx",
  "apps/web/src/components/comparison-data.ts",
  "apps/web/src/components/generated-public-comparisons.ts",
  "apps/web/src/lib/demo-catalog.ts",
  "apps/web/src/lib/metrics.ts",
  "apps/web/src/marketing-prerender.tsx",
  "apps/web/src/platform",
  "apps/web/src/private",
  "apps/web/src/site",
  "apps/web/tests/site-e2e",
  "docs/CHATGPT_WORK.md",
  "docs/spikes/intent-bound-actions.md",
  "examples/intent-bound-actions",
];

const forbiddenContentRules = [
  [
    /\b(?:TaskContract|taskContractId|task_contract)\b|\/v1\/task-contracts\b|\btask[-_ ]contracts?\b/i,
    "task-contract surface leaked into public export",
  ],
  [
    /\b(?:ActionGateClient|ActionGateApiError|ActionGateExternalActionError|ActionGateClientOptions|ActionGateFetch|ActionGateFetchResponse)\b|\bACTIONGATE_[A-Z0-9_]+\b|\.actiongate\b|\bagk_|\bactiongate(?:_http|-mcp|Execution)?\b|actiongate\.(?:action|receipt)\.v1|\bmetadata\.actiongate\b/i,
    "legacy ActionGate compatibility surface leaked into public export",
  ],
  [
    /\b(?:ACTIONPROXY_EDITION|VITE_ACTIONPROXY_EDITION|ActionProxyEdition)\b/,
    "runtime edition selection leaked into fixed Community export",
  ],
  [
    /\/v1\/integrations\/(?:connected-apps|business-actions)\b|\b(?:ConnectedAppCatalog|BusinessActionCatalog|connectedAppsCatalog|ConnectedAppId|ConnectedAppStatus|ConnectedAppHealth|ConnectedAppRuntime|ConnectedAppScopeStatus|ConnectedAppWorkflowStatus|LocalConnectedAppConfig|LocalConnectedAppOAuthConfig|BusinessActionDefinition|BusinessActionDryRunPreview|BusinessActionInputSpec|BusinessActionPolicyDefault)\b/,
    "connected-app catalog or business-action API leaked into public export",
  ],
  [
    /\b(?:connectedAppId|connected_app_id)\b/,
    "connected-app identity metadata leaked into public export",
  ],
  [
    /\b(?:AgentRunAuthorization(?:Record)?|agentRunAuthorization|agent_run_authorizations?)\b/,
    "platform agent-run authorization model leaked into public export",
  ],
  [
    /\b(?:WorkflowMetrics|workflowMetrics|workflow_metrics)\b/,
    "platform workflow metrics leaked into public export",
  ],
  [
    /\/v1\/system\/capabilities\b/,
    "removed Community capability route leaked into public export",
  ],
  [
    /\b(?:EmailManagedProvider|LocalTeamsIntegrationConfig|ManagedEmailConfig)\b|transport\s*:\s*(?:z\.enum\([^\n]*|[^\n]*)['"]managed['"]|ACTIONPROXY_(?:EMAIL_)?MANAGED_[A-Z0-9_]+/,
    "managed-delivery or Teams configuration leaked into public export",
  ],
  [
    /\/mcp\/chatgpt-work\b|\bchatgpt_work\b|\bACTIONPROXY_CHATGPT_WORK(?:_[A-Z0-9_]+)?\b/i,
    "legacy ChatGPT Work compatibility surface leaked into public export",
  ],
  [
    /\b(?:providerHostStub|platformE2e)\b|\/__actionproxy_e2e\//,
    "platform provider stub or test-only HTTP endpoint leaked into public export",
  ],
  [
    /\b(?:AgentRunService|AgentFlowBuilderService|AgentRunRecord|CompanyAgentRecord|CustomAgentFlowRecord|UserConnectedAccountRecord)\b|\b(?:agent_runs|company_agents|custom_agent_flows|user_connected_accounts)\b/,
    "platform agent or connected-account model leaked into public export",
  ],
  [
    /\b(?:GoogleWorkspaceConnector|HubSpotConnector|SlackOAuthService|StripeConnector|ZendeskConnector|TeamsService)\b/,
    "native provider runtime leaked into public export",
  ],
  [
    /ACTIONPROXY_(?:GOOGLE|HUBSPOT|MAILGUN|MANAGED_EMAIL|MODEL_PROVIDER|RESEND|SLACK_(?:CONNECTOR|OAUTH)|STRIPE|TEAMS|ZENDESK)_[A-Z0-9_]+|OPENAI_API_KEY/,
    "platform or managed-provider credential variable leaked into public export",
  ],
  [
    /VITE_ACTIONPROXY_LEAD_CAPTURE_URL|supabase\/functions\/early-access|functions\/v1\/early-access|marketing_leads/i,
    "hosted lead-capture surface leaked into public export",
  ],
  [
    /(?:^|[\s'"`])(?:\.\.\/|\.\/|@actionproxy\/)[^\s'"`]*(?:platform|hosted|native-provider|agent-runtime|workflow-builder)[^\s'"`]*/im,
    "Community code imports a private platform module",
  ],
  [
    /(?:hosted private beta|private hosted beta|managed SaaS beta|private SMB SaaS|hosted paid workspace|public self-serve SaaS available|preview-only)/i,
    "hosted or preview release copy leaked into public export",
  ],
  [
    /(?:^|\n)\s{2}(?:actionproxy\.agent\.[a-z0-9_*.-]+|e2e_detector\.[a-z0-9_*.-]+|google\.(?:calendar|gmail)\.[a-z0-9_*.-]+|hubspot\.[a-z0-9_*.-]+|zendesk\.[a-z0-9_*.-]+|stripe\.(?:create_refund_request|delete_customer|execute_refund|read_(?:invoice|payment|subscription)|search_customers|update_subscription)):\s*(?:\r?\n|$)/i,
    "provider-heavy platform default-policy content leaked into public export",
  ],
  [/actiongate\.dev/i, "old product domain leaked into public export"],
];

// These are exact, single-occurrence assertions or scrub guards that prove
// removed Community interfaces and managed credentials stay unavailable.
// Replacing only the known text keeps a second occurrence in the same file
// visible to the strict rules.
const negativeHarnessAllowances = new Map([
  [
    "scripts/first-run.mjs",
    new Map([
      [
        "platform or managed-provider credential variable leaked into public export",
        [
          "    /(?:ACTIONPROXY_CONTROL_PLANE_KEY_FILE|ACTIONPROXY_LEGACY_RUNTIME_KEY_FD|CONTROL_PLANE_API_KEY|OPENAI_API_KEY)\\s*:/u.test(",
          "    /(?:ACTIONPROXY_CONTROL_PLANE_KEY_FILE|ACTIONPROXY_LEGACY_RUNTIME_KEY_FD|CONTROL_PLANE_API_KEY|OPENAI_API_KEY)=/u.test(",
          "  delete sanitizedEnvironment.OPENAI_API_KEY;",
          "  delete safe.OPENAI_API_KEY;",
          "    delete process.env.OPENAI_API_KEY;",
        ],
      ],
    ]),
  ],
  [
    "scripts/first-run.test.mjs",
    new Map([
      [
        "platform or managed-provider credential variable leaked into public export",
        [
          "        /CONTROL_PLANE_API_KEY|OPENAI_API_KEY/u,",
          "        (call) => call.env.CONTROL_PLANE_API_KEY || call.env.OPENAI_API_KEY,",
          "          call.env.OPENAI_API_KEY ||",
        ],
      ],
    ]),
  ],
  [
    "scripts/generate-openapi.test.mjs",
    new Map([
      [
        "connected-app catalog or business-action API leaked into public export",
        [
          '    "/v1/integrations/connected-apps",',
          '    "/v1/integrations/business-actions",',
        ],
      ],
      [
        "removed Community capability route leaked into public export",
        ['    "/v1/system/capabilities",'],
      ],
      [
        "legacy ChatGPT Work compatibility surface leaked into public export",
        ['    "/mcp/chatgpt-work",'],
      ],
    ]),
  ],
  [
    "apps/server/src/routes/tool-calls.test.ts",
    new Map([
      [
        "task-contract surface leaked into public export",
        [
          "        taskContractId: 'removed_contract_interface',",
          "    expect(response.json().details.formErrors.join(' ')).toContain('taskContractId');",
        ],
      ],
    ]),
  ],
  [
    "apps/server/src/routes/integrations.test.ts",
    new Map([
      [
        "connected-app catalog or business-action API leaked into public export",
        [
          "      app.inject({ method: 'GET', url: '/v1/integrations/connected-apps' }),",
          "      app.inject({ method: 'POST', url: '/v1/integrations/business-actions/custom.write/dry-run' }),",
        ],
      ],
    ]),
  ],
  [
    "apps/web/tests/e2e/community.spec.ts",
    new Map([
      [
        "removed Community capability route leaked into public export",
        [
          '  await expectCommunityRouteMissing(page, "/v1/system/capabilities");',
        ],
      ],
    ]),
  ],
  [
    "scripts/dev.test.mjs",
    new Map([
      [
        "runtime edition selection leaked into fixed Community export",
        ["  assert.equal(specs[0].env.ACTIONPROXY_EDITION, undefined);"],
      ],
    ]),
  ],
  [
    "scripts/smoke-community-docker.mjs",
    new Map([
      [
        "task-contract surface leaked into public export",
        [
          "    '/v1/task-contracts',",
          "      taskContractId: 'removed-interface',",
          "  assert(legacySubmission.status === 400, 'taskContractId should fail strict request validation');",
        ],
      ],
      [
        "connected-app catalog or business-action API leaked into public export",
        [
          "    '/v1/integrations/connected-apps',",
          "    '/v1/integrations/business-actions/example/dry-run',",
        ],
      ],
      [
        "removed Community capability route leaked into public export",
        ["    '/v1/system/capabilities',"],
      ],
    ]),
  ],
]);

const narrativeRules = [
  [/\bworking(?:\s+(?:open-source|project))?\s+name\b/i, "working-name copy"],
  [
    /\b(?:TODO|TBD|FIXME)\b|\bcoming\s+soon\b|\bplaceholder\s+copy\b/i,
    "placeholder copy",
  ],
  [
    /\/mcp\/chatgpt-work\b|\bACTIONPROXY_CHATGPT_WORK(?:_[A-Z0-9_]+)?\b/i,
    "legacy ChatGPT onboarding copy",
  ],
  [
    /\bNode(?:\.js)?(?:\s+|:\s*)v?20(?:\.\d+)*\b/i,
    "unsupported Node 20 guidance",
  ],
];

if (!(await exists(destination))) {
  fail(`Public export directory does not exist: ${destination}`);
}
if (checkoutMode) {
  await initializeCheckoutVerification();
} else if (await exists(path.join(destination, ".git"))) {
  fail(
    "Artifact verification requires a clean generated directory without .git; run scripts/attest-public-checkout.mjs and then verify with --checkout for a Git checkout.",
  );
}

for (const relativePath of requiredPaths) {
  if (!(await verificationPathExists(relativePath))) {
    failures.push(`Required public path missing: ${relativePath}`);
  }
}

try {
  const distribution = JSON.parse(
    await fs.readFile(
      path.join(
        destination,
        "examples/chatgpt-tunnel/tunnel-client-distribution.json",
      ),
      "utf8",
    ),
  );
  const expectedAssets = {
    "darwin-amd64": {
      archiveSha256:
        "1a48616e584484f8bef4c1128d515ac96cf44d0d9609c1462abccc1793f4b847",
      archiveSize: 7672583,
      assetId: 464595694,
      binarySha256:
        "addc6fadb1ea504219e30a6ccad6dd832bf3fa1f3a4fddb6c9a39dc9b59d676a",
      binarySize: 20542944,
    },
    "darwin-arm64": {
      archiveSha256:
        "288accc7fd20cfee1d495adb933773af9e19ebc0cdef3173f7fb544afa5065b2",
      archiveSize: 7100022,
      assetId: 464595695,
      binarySha256:
        "5870da52ada51e96b32375a04fa112f3c0de7238cd76e8d1ed19b06fed6acbf2",
      binarySize: 19192114,
    },
  };
  const assetKeys = Object.keys(distribution.assets ?? {}).sort();
  if (
    distribution.schemaVersion !==
      "actionproxy.tunnel-client-distribution.v1" ||
    distribution.repository !== "openai/tunnel-client" ||
    distribution.releaseId !== 348221172 ||
    distribution.releaseTag !== "v0.0.10" ||
    distribution.releaseCommit !== "105e17a79a36e4e5c897fd698ed2b8dbf935b144" ||
    distribution.expectedVersion !==
      "0.0.10+105e17a79a36e4e5c897fd698ed2b8dbf935b144" ||
    distribution.archiveEntry !== "tunnel-client" ||
    JSON.stringify(assetKeys) !==
      JSON.stringify(["darwin-amd64", "darwin-arm64"]) ||
    assetKeys.some((platformKey) => {
      const asset = distribution.assets[platformKey];
      const expected = expectedAssets[platformKey];
      const name = `tunnel-client-v0.0.10-${platformKey}.zip`;
      return (
        asset.assetId !== expected.assetId ||
        asset.name !== name ||
        asset.url !==
          `https://github.com/openai/tunnel-client/releases/download/v0.0.10/${name}` ||
        asset.archiveSize !== expected.archiveSize ||
        asset.archiveSha256 !== expected.archiveSha256 ||
        asset.binarySize !== expected.binarySize ||
        asset.binarySha256 !== expected.binarySha256
      );
    })
  ) {
    failures.push(
      "tunnel-client-distribution.json does not match the reviewed v0.0.10 release pins",
    );
  }
} catch (error) {
  failures.push(
    `tunnel-client-distribution.json is unreadable: ${error instanceof Error ? error.message : String(error)}`,
  );
}
for (const relativePath of forbiddenPaths) {
  if (await verificationPathExists(relativePath)) {
    failures.push(`Forbidden path present: ${relativePath}`);
  }
}

await verifyManifestArtifact();
await verifyCommunityMigrationSequence();
await verifyPackagesAndCommands();
await verifyCommunityTypeVocabulary();
await verifyRepositoryMetadata();
await verifyAgentInstructions();
await verifyDockerAndWorkflow();
await verifyDocumentation();
if (strict) {
  await verifyStrictBoundary();
  await verifySecrets();
}

if (failures.length > 0) {
  if (jsonOutput) writeVerificationReport(false, failures);
  else {
    console.error("Public export verification failed:");
    for (const failure of failures) console.error(`- ${failure}`);
  }
  process.exit(1);
}

if (jsonOutput) writeVerificationReport(true, []);
else
  console.log(
    `Public ${checkoutMode ? "checkout boundary" : "export artifact"} verification passed${strict ? " in strict mode" : ""}: ${destination}`,
  );

async function verifyManifestArtifact() {
  const manifestPath = path.join(destination, "PUBLIC_MANIFEST.json");
  let manifest;
  let manifestBody;
  try {
    const manifestStat = await fs.lstat(manifestPath);
    if (!manifestStat.isFile() || manifestStat.isSymbolicLink()) {
      failures.push("PUBLIC_MANIFEST.json must be a regular file");
      return;
    }
    if (gitModeFromStat(manifestStat) !== "100644") {
      failures.push("PUBLIC_MANIFEST.json must have Git mode 100644");
    }
    manifestBody = await fs.readFile(manifestPath, "utf8");
    manifest = JSON.parse(manifestBody);
  } catch (error) {
    failures.push(
      `PUBLIC_MANIFEST.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
    return;
  }

  if (
    !hasExactKeys(manifest, [
      "files",
      "releaseTag",
      "repository",
      "schemaVersion",
    ])
  ) {
    failures.push(
      "PUBLIC_MANIFEST.json must contain only the canonical top-level fields",
    );
  }

  if (manifest?.schemaVersion !== PUBLIC_MANIFEST_SCHEMA_VERSION) {
    failures.push("PUBLIC_MANIFEST.json has an unexpected schemaVersion");
  }
  const canonicalRepository = canonicalGitHubRepositoryUrl(
    manifest?.repository,
  );
  if (!canonicalRepository || canonicalRepository !== manifest.repository) {
    failures.push(
      "PUBLIC_MANIFEST.json repository must be a canonical HTTPS github.com/<owner>/<repository> URL",
    );
  } else if (manifest.repository !== approvedRepository) {
    failures.push(
      `PUBLIC_MANIFEST.json repository must be the approved destination: ${approvedRepository}`,
    );
  }
  if (!isSemverTag(manifest?.releaseTag)) {
    failures.push(
      "PUBLIC_MANIFEST.json releaseTag must be a strict v-prefixed semantic version",
    );
  } else if (manifest.releaseTag !== approvedReleaseTag) {
    failures.push(
      `PUBLIC_MANIFEST.json releaseTag must be the approved release: ${approvedReleaseTag}`,
    );
  }
  const configuredRepository =
    process.env.ACTIONPROXY_PUBLIC_REPOSITORY_URL?.trim();
  if (
    configuredRepository &&
    canonicalGitHubRepositoryUrl(configuredRepository) !== manifest?.repository
  ) {
    failures.push(
      "PUBLIC_MANIFEST.json repository does not match ACTIONPROXY_PUBLIC_REPOSITORY_URL",
    );
  }
  const configuredTag = process.env.ACTIONPROXY_PUBLIC_RELEASE_TAG?.trim();
  if (configuredTag && configuredTag !== manifest?.releaseTag) {
    failures.push(
      "PUBLIC_MANIFEST.json releaseTag does not match ACTIONPROXY_PUBLIC_RELEASE_TAG",
    );
  }
  if (!Array.isArray(manifest?.files)) {
    failures.push("PUBLIC_MANIFEST.json files must be an array");
    return;
  }

  const declared = new Map();
  const declaredOrder = [];
  for (const [index, entry] of manifest.files.entries()) {
    if (!hasExactKeys(entry, ["mode", "path", "sha256"])) {
      failures.push(
        `PUBLIC_MANIFEST.json contains non-canonical fields at files[${index}]`,
      );
    }
    if (
      !isSafeRelativePath(entry?.path) ||
      entry.path === "PUBLIC_MANIFEST.json"
    ) {
      failures.push(
        `PUBLIC_MANIFEST.json contains an unsafe or reserved path at files[${index}]: ${String(entry?.path)}`,
      );
      continue;
    }
    if (!/^[a-f0-9]{64}$/u.test(entry?.sha256 ?? "")) {
      failures.push(
        `PUBLIC_MANIFEST.json contains an invalid SHA-256 for ${entry.path}`,
      );
    }
    if (!isRegularGitMode(entry?.mode)) {
      failures.push(
        `PUBLIC_MANIFEST.json contains an invalid Git mode for ${entry.path}`,
      );
    }
    if (declared.has(entry.path)) {
      failures.push(
        `PUBLIC_MANIFEST.json contains duplicate path: ${entry.path}`,
      );
      continue;
    }
    declared.set(entry.path, entry);
    declaredOrder.push(entry.path);
  }
  const sortedDeclared = [...declaredOrder].sort(comparePaths);
  if (declaredOrder.some((entry, index) => entry !== sortedDeclared[index])) {
    failures.push("PUBLIC_MANIFEST.json file entries are not sorted by path");
  }
  const canonicalBody = `${JSON.stringify(
    {
      files: manifest.files,
      releaseTag: manifest.releaseTag,
      repository: manifest.repository,
      schemaVersion: manifest.schemaVersion,
    },
    null,
    2,
  )}\n`;
  if (manifestBody !== canonicalBody) {
    failures.push(
      "PUBLIC_MANIFEST.json is not in canonical deterministic form",
    );
  }

  const actualPaths = [];
  for (const relativePath of await getVerificationFiles()) {
    if (relativePath !== "PUBLIC_MANIFEST.json") actualPaths.push(relativePath);
  }
  actualPaths.sort(comparePaths);
  const actualSet = new Set(actualPaths);
  for (const [relativePath, entry] of declared) {
    if (!actualSet.has(relativePath)) {
      failures.push(
        `PUBLIC_MANIFEST.json references missing file: ${relativePath}`,
      );
      continue;
    }
    try {
      const absolutePath = path.join(destination, relativePath);
      const stat = await fs.lstat(absolutePath);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        failures.push(
          `PUBLIC_MANIFEST.json path is not a regular file: ${relativePath}`,
        );
        continue;
      }
      const actualMode = gitModeFromStat(stat);
      if (actualMode !== entry.mode) {
        failures.push(
          `PUBLIC_MANIFEST.json Git mode mismatch: ${relativePath} (manifest ${entry.mode}, artifact ${actualMode})`,
        );
      }
      if (
        checkoutMode &&
        verificationGitModes?.get(relativePath) !== entry.mode
      ) {
        failures.push(
          `PUBLIC_MANIFEST.json index mode mismatch: ${relativePath} (manifest ${entry.mode}, index ${verificationGitModes?.get(relativePath) ?? "missing"})`,
        );
      }
      const contents = await fs.readFile(absolutePath);
      const actualDigest = createHash("sha256").update(contents).digest("hex");
      if (actualDigest !== entry.sha256) {
        failures.push(`PUBLIC_MANIFEST.json SHA-256 mismatch: ${relativePath}`);
      }
    } catch (error) {
      failures.push(
        `Cannot read manifest file ${relativePath}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  for (const relativePath of actualPaths) {
    if (!declared.has(relativePath)) {
      failures.push(
        `Unexpected file absent from PUBLIC_MANIFEST.json: ${relativePath}`,
      );
    }
  }
  if (declared.get("actionproxy")?.mode !== "100755") {
    failures.push(
      "PUBLIC_MANIFEST.json must record the root actionproxy shim with Git mode 100755",
    );
  }
  verifiedManifest = manifest;
}

async function verifyCommunityMigrationSequence() {
  const expected = [
    "apps/server/src/storage/migrations/0001_initial.sql",
    "apps/server/src/storage/migrations/0002_legacy_schema_reconciliation.sql",
    "apps/server/src/storage/migrations/0003_approver_principal_identity.sql",
  ];
  const actual = (await getVerificationFiles()).filter(
    (relativePath) =>
      relativePath.startsWith("apps/server/src/storage/migrations/") &&
      relativePath.endsWith(".sql"),
  );
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    failures.push(
      `Community migration sequence must be frozen exactly as ${expected.join(", ")}; found ${actual.join(", ") || "(none)"}`,
    );
  }
}

async function verifyPackagesAndCommands() {
  const packageFiles = [];
  for (const relativePath of await getVerificationFiles()) {
    if (
      relativePath === "package.json" ||
      relativePath.endsWith("/package.json")
    ) {
      packageFiles.push(relativePath);
    }
  }
  const packages = [];
  for (const relativePath of packageFiles) {
    try {
      packages.push({
        directory: path.dirname(relativePath),
        manifest: JSON.parse(
          await fs.readFile(path.join(destination, relativePath), "utf8"),
        ),
        relativePath,
      });
    } catch (error) {
      failures.push(
        `${relativePath} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  const rootPackage = packages.find(
    ({ relativePath }) => relativePath === "package.json",
  )?.manifest;
  if (!rootPackage) return;
  const actualScripts = Object.keys(rootPackage.scripts ?? {}).sort(
    comparePaths,
  );
  const expectedScripts = [...requiredRootScripts].sort(comparePaths);
  if (
    actualScripts.length !== expectedScripts.length ||
    actualScripts.some((name, index) => name !== expectedScripts[index])
  ) {
    failures.push(
      `Root package scripts must match the public allowlist exactly: ${expectedScripts.join(", ")}`,
    );
  }
  if (rootPackage.engines?.node !== ">=22 <25") {
    failures.push("package.json engines.node must support exactly Node 22–24");
  }
  if (!/^pnpm@11\.\d+\.\d+$/u.test(rootPackage.packageManager ?? "")) {
    failures.push(
      "package.json packageManager must pin an exact pnpm 11 release",
    );
  }
  for (const [dependency, version] of [
    ["@readme/openapi-parser", "6.3.0"],
    ["ajv", "8.20.0"],
  ]) {
    if (rootPackage.devDependencies?.[dependency] !== version) {
      failures.push(
        `package.json must pin ${dependency} exactly to ${version}`,
      );
    }
  }
  for (const versionFile of [".node-version", ".nvmrc"]) {
    const version = (await readTextIfPresent(versionFile))?.trim();
    if (version !== "24") failures.push(`${versionFile} must pin Node 24`);
  }

  const workspaceNames = new Set(
    packages.map(({ manifest }) => manifest?.name).filter(Boolean),
  );
  for (const expected of [
    {
      directory: "packages/sdk-js",
      keywords: [
        "ai-agents",
        "approval-gateway",
        "audit",
        "human-in-the-loop",
        "tool-calls",
      ],
      name: "@actionproxy/sdk-js",
    },
    {
      directory: "packages/mcp-wrapper",
      keywords: [
        "ai-agents",
        "approval-gateway",
        "audit",
        "human-in-the-loop",
        "mcp",
        "model-context-protocol",
      ],
      name: "@actionproxy/mcp-wrapper",
    },
  ]) {
    const candidate = packages.find(
      ({ directory }) => directory === expected.directory,
    )?.manifest;
    if (!candidate) continue;
    if (
      candidate.name !== expected.name ||
      candidate.version !== rootPackage.version ||
      candidate.private !== undefined ||
      JSON.stringify(candidate.files) !== JSON.stringify(["dist"]) ||
      candidate.publishConfig?.access !== "public" ||
      candidate.publishConfig?.registry !== "https://registry.npmjs.org/" ||
      candidate.engines?.node !== ">=22 <25" ||
      candidate.repository?.url !==
        "git+https://github.com/ActionProxy/actionproxy.git" ||
      candidate.repository?.directory !== expected.directory ||
      candidate.homepage !==
        "https://github.com/ActionProxy/actionproxy#readme" ||
      candidate.bugs?.url !==
        "https://github.com/ActionProxy/actionproxy/issues" ||
      JSON.stringify(candidate.keywords) !== JSON.stringify(expected.keywords)
    ) {
      failures.push(
        `${expected.directory}/package.json must remain the reviewed public, version-aligned, dist-only npm candidate`,
      );
    }
  }
  for (const { directory, manifest, relativePath } of packages) {
    if (manifest.license !== "Apache-2.0") {
      failures.push(`${relativePath} must declare license Apache-2.0`);
    }
    for (const [scriptName, command] of Object.entries(
      manifest.scripts ?? {},
    )) {
      if (typeof command !== "string" || command.trim() === "") {
        failures.push(
          `${relativePath} has an empty or non-string script: ${scriptName}`,
        );
        continue;
      }
      if (
        /(?:^|:)site(?::|$)|publish|ghcr\.io|ACTIONPROXY_EDITION|VITE_ACTIONPROXY_EDITION|marketing-prerender/.test(
          `${scriptName} ${command}`,
        )
      ) {
        failures.push(
          `${relativePath} contains a release-excluded command in script ${scriptName}`,
        );
      }
      for (const match of command.matchAll(/--filter(?:=|\s+)([^\s;&|]+)/gu)) {
        if (!workspaceNames.has(match[1])) {
          failures.push(
            `${relativePath} script ${scriptName} targets missing workspace package: ${match[1]}`,
          );
        }
      }
      for (const match of command.matchAll(
        /\b(?:bash|node)\s+(?!-)([^\s;&|]+)/gu,
      )) {
        const commandPath = match[1].replace(/^['"]|['"]$/gu, "");
        if (commandPath.includes("$") || commandPath.startsWith("node:"))
          continue;
        const resolved = path.resolve(
          destination,
          directory === "." ? "" : directory,
          commandPath,
        );
        const resolvedRelative = normalizePath(
          path.relative(destination, resolved),
        );
        if (
          !commandPath.startsWith("dist/") &&
          (!resolved.startsWith(`${destination}${path.sep}`) ||
            !(await verificationPathExists(resolvedRelative)))
        ) {
          failures.push(
            `${relativePath} script ${scriptName} references missing command path: ${commandPath}`,
          );
        }
      }
    }
  }
}

async function verifyRepositoryMetadata() {
  const license = await readTextIfPresent("LICENSE");
  if (
    license &&
    !/^\s*Apache License\n\s+Version 2\.0, January 2004\n/u.test(license)
  ) {
    failures.push("LICENSE must contain the official Apache License 2.0 text");
  }
  for (const packageLicensePath of [
    "packages/mcp-wrapper/LICENSE",
    "packages/sdk-js/LICENSE",
  ]) {
    const packageLicense = await readTextIfPresent(packageLicensePath);
    if (license && packageLicense && packageLicense !== license) {
      failures.push(`${packageLicensePath} must be byte-identical to LICENSE`);
    }
  }
  const gitAttributes = await readTextIfPresent(".gitattributes");
  if (gitAttributes !== "* text=auto eol=lf\n*.png binary\n") {
    failures.push(
      ".gitattributes must exactly match the reviewed manifest-stability policy; custom filters and attributes are forbidden",
    );
  }
  const dependabot = await readTextIfPresent(".github/dependabot.yml");
  if (
    dependabot &&
    (!/^version:\s*2\s*$/mu.test(dependabot) ||
      !/^\s*- package-ecosystem:\s*npm\s*$/mu.test(dependabot) ||
      !/^\s*directory:\s*\/\s*$/mu.test(dependabot) ||
      !/^\s*interval:\s*monthly\s*$/mu.test(dependabot))
  ) {
    failures.push(
      "Dependabot must use the minimal monthly npm workspace configuration",
    );
  }
  const contributing = await readTextIfPresent("CONTRIBUTING.md");
  if (
    contributing &&
    !/licensed under[\s\S]{0,120}Apache License 2\.0/iu.test(contributing)
  ) {
    failures.push(
      "CONTRIBUTING.md must state the Apache-2.0 contribution license",
    );
  }
  const rootPackage = await readJsonIfPresent("package.json");
  if (!rootPackage || !verifiedManifest) return;
  if (rootPackage.version !== verifiedManifest.releaseTag?.slice(1)) {
    failures.push(
      "package.json version does not match PUBLIC_MANIFEST.json releaseTag",
    );
  }
  if (rootPackage.repository?.url !== `${verifiedManifest.repository}.git`) {
    failures.push(
      "package.json repository does not match PUBLIC_MANIFEST.json repository",
    );
  }
  if (rootPackage.homepage !== `${verifiedManifest.repository}#readme`) {
    failures.push(
      "package.json homepage does not match PUBLIC_MANIFEST.json repository",
    );
  }
  if (rootPackage.bugs?.url !== `${verifiedManifest.repository}/issues`) {
    failures.push(
      "package.json bugs URL does not match PUBLIC_MANIFEST.json repository",
    );
  }
}

async function verifyAgentInstructions() {
  const instructions = await readTextIfPresent("AGENTS.md");
  if (instructions === undefined) return;

  if (
    !instructions.includes("<!-- actionproxy-public-agent-instructions:v1 -->")
  ) {
    failures.push(
      "AGENTS.md is missing the public coding-agent instruction schema marker",
    );
  }

  const headings = new Set(
    instructions
      .split(/\r?\n/gu)
      .filter((line) => /^#{1,6}\s+/u.test(line))
      .map((line) => line.replace(/^#{1,6}\s+/u, "").trim()),
  );
  for (const heading of [
    "Product boundary",
    "Read before editing",
    "Adopting from another repository",
    "Repository map",
    "Architecture invariants",
    "Validation by change area",
    "Safety and contribution discipline",
    "Public manifest and handoff",
  ]) {
    if (!headings.has(heading)) {
      failures.push(`AGENTS.md is missing required heading: ${heading}`);
    }
  }

  for (const reference of [
    "docs/ADOPTING.md",
    "docs/ARCHITECTURE.md",
    "docs/API_SPEC.md",
    "docs/POLICY_SPEC.md",
    "docs/SECURITY_MODEL.md",
    "docs/DECISIONS.md",
    "apps/server/src/services/action-gate.ts",
    "apps/server/src/policy/",
    "apps/server/src/storage/",
    "apps/web/src/",
    "packages/sdk-js/",
    "packages/mcp-wrapper/",
  ]) {
    if (!instructions.includes(reference)) {
      failures.push(
        `AGENTS.md is missing required public reference: ${reference}`,
      );
    }
  }

  for (const invariant of [
    "ActionProxyService",
    "ToolRegistry",
    "Audit events are append-only",
    "Unknown tools require approval by default",
    "PUBLIC_MANIFEST.json",
  ]) {
    if (!instructions.includes(invariant)) {
      failures.push(`AGENTS.md is missing required invariant: ${invariant}`);
    }
  }

  for (const command of [
    "./actionproxy doctor --json",
    "./actionproxy local --no-open",
    "./actionproxy status --json",
    "corepack pnpm --filter @actionproxy/server test",
    "corepack pnpm --filter @actionproxy/server lint",
    "corepack pnpm --filter @actionproxy/web test",
    "corepack pnpm --filter @actionproxy/web lint",
    "corepack pnpm --filter @actionproxy/sdk-js test",
    "corepack pnpm --filter @actionproxy/sdk-js lint",
    "corepack pnpm --filter @actionproxy/mcp-wrapper test",
    "corepack pnpm --filter @actionproxy/mcp-wrapper lint",
    "corepack pnpm test:first-run",
    "corepack pnpm test:e2e:community",
    "corepack pnpm test",
    "corepack pnpm lint",
    "corepack pnpm build",
    "corepack pnpm manifest:refresh",
    "corepack pnpm verify:tracked-checkout",
    "corepack pnpm verify:oss-boundary",
    "node scripts/verify-public-export.mjs . --checkout --strict --json",
    "node scripts/verify-public-export.mjs . --strict --json",
  ]) {
    if (!instructions.includes(command)) {
      failures.push(
        `AGENTS.md is missing required validation command: ${command}`,
      );
    }
  }

  for (const privateReference of [
    "PROGRESS.md",
    "START_HERE_FOR_CODEX.md",
    "codex/",
    "planning/",
    "apps/server/src/platform-modules.ts",
  ]) {
    if (instructions.includes(privateReference)) {
      failures.push(
        `AGENTS.md references private-only source guidance: ${privateReference}`,
      );
    }
  }
}

async function verifyCommunityTypeVocabulary() {
  const serverPackage = await readJsonIfPresent("apps/server/package.json");
  if (
    serverPackage &&
    serverPackage.scripts?.test !==
      "vitest run --config vitest.config.ts --no-file-parallelism"
  ) {
    failures.push(
      "Community server test script must explicitly load vitest.config.ts",
    );
  }
  const serverTsconfig = await readJsonIfPresent("apps/server/tsconfig.json");
  if (serverTsconfig && Object.hasOwn(serverTsconfig, "exclude")) {
    failures.push(
      "Community server tsconfig must not describe private-source exclusions",
    );
  }
  const sdkContracts = await readTextIfPresent(
    "packages/sdk-js/src/contracts.ts",
  );
  if (sdkContracts) {
    for (const staleValue of [
      "| 'appId'",
      "| 'workflowId'",
      "'hosted' | 'local' | 'self_hosted'",
      "| 'business_action_default'",
    ]) {
      if (sdkContracts.includes(staleValue)) {
        failures.push(
          `Community SDK contracts contain private platform vocabulary: ${staleValue}`,
        );
      }
    }
  }
  const serverModels = await readTextIfPresent("apps/server/src/models.ts");
  const sdkTypes = await readTextIfPresent("packages/sdk-js/src/types.ts");
  if (serverModels && sdkTypes) {
    const serverAuditTypes = interfaceUnionValues(serverModels, "AuditEvent");
    const sdkAuditTypes = interfaceUnionValues(sdkTypes, "AuditEvent");
    if (
      serverAuditTypes.length === 0 ||
      JSON.stringify(serverAuditTypes) !== JSON.stringify(sdkAuditTypes)
    ) {
      failures.push(
        "Community SDK AuditEvent variants do not match the server AuditEvent contract",
      );
    }
    for (const auditField of [
      "auth?",
      "eventHash?",
      "inputHash?",
      "policyVersionHash?",
      "policyVersionId?",
      "previousEventHash?",
    ]) {
      if (!sdkTypes.includes(`${auditField}:`)) {
        failures.push(
          `Community SDK AuditEvent omits server evidence field ${auditField}`,
        );
      }
    }
  }
  const webEnvironment = await readTextIfPresent("apps/web/src/vite-env.d.ts");
  if (
    webEnvironment &&
    /VITE_ACTIONPROXY_(?:PUBLIC_RELEASE_TAG|PUBLIC_REPOSITORY_URL|PUBLIC_SITE_URL|SITE_MODE)/u.test(
      webEnvironment,
    )
  ) {
    failures.push(
      "Community web environment declarations contain private landing-build settings",
    );
  }
  const decisionContract = await readTextIfPresent(
    "apps/server/src/contracts/decision.ts",
  );
  if (decisionContract?.includes("business_action_default")) {
    failures.push(
      "Community decision validator contains the private business-action fallback type",
    );
  }
  for (const runtimeIdentityPath of [
    "apps/server/src/integrations/mcp-discovery.ts",
    "apps/server/src/routes/mcp.ts",
    "examples/google-workspace-mcp-demo/run-gmail-draft-test.mjs",
    "examples/mcp-demo/run-smoke-test.mjs",
    "examples/mcp-demo/server.mjs",
    "packages/mcp-wrapper/src/wrap-server.ts",
  ]) {
    const runtimeIdentity = await readTextIfPresent(runtimeIdentityPath);
    if (/\bversion:\s*['"]0\.0\.0['"]/u.test(runtimeIdentity ?? "")) {
      failures.push(
        `Public MCP runtime advertises a placeholder version: ${runtimeIdentityPath}`,
      );
    }
  }
}

function interfaceUnionValues(source, interfaceName) {
  const body =
    new RegExp(
      `export interface ${interfaceName}\\s*\\{([\\s\\S]*?)\\n\\}`,
      "u",
    ).exec(source)?.[1] ?? "";
  return [...body.matchAll(/^\s*\|\s*'([^']+)'/gmu)]
    .map((match) => match[1])
    .sort(comparePaths);
}

async function verifyDockerAndWorkflow() {
  const dockerIgnore = await readTextIfPresent(".dockerignore");
  if (dockerIgnore) {
    const dockerIgnoreLines = new Set(
      dockerIgnore
        .split(/\r?\n/gu)
        .map((line) => line.trim())
        .filter(Boolean),
    );
    for (const requiredPattern of [
      ".env",
      ".env.*",
      "*.env",
      "*.env.*",
      "**/.env",
      "**/.env.*",
      "**/*.env",
      "**/*.env.*",
      "!.env.example",
      "!*.env.example",
      "!**/.env.example",
      "!**/*.env.example",
    ]) {
      if (!dockerIgnoreLines.has(requiredPattern)) {
        failures.push(
          `.dockerignore does not protect the Docker build context with ${requiredPattern}`,
        );
      }
    }
  }
  const dockerfile = await readTextIfPresent("Dockerfile");
  if (dockerfile) {
    const flattened = dockerfile.replace(/\\\n\s*/gu, " ");
    if (!/apt-get install[^\n]*sqlite3/u.test(flattened)) {
      failures.push("Dockerfile runtime image does not install sqlite3");
    }
    if (!dockerfile.includes("apps/server/src/storage/migrations")) {
      failures.push("Dockerfile does not package Community migrations");
    }
    if (!dockerfile.includes("examples/chatgpt-tunnel")) {
      failures.push(
        "Dockerfile does not package the ChatGPT tunnel configuration",
      );
    }
  }
  const workflow = await readTextIfPresent(".github/workflows/security.yml");
  if (workflow) {
    const codeqlJob = /\n  codeql:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u.exec(
      workflow,
    )?.[0];
    const secretScanJob =
      /\n  secret-scan:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u.exec(
        workflow,
      )?.[0];
    const attestationIndex = workflow.indexOf(
      "corepack pnpm verify:tracked-checkout",
    );
    const boundaryIndex = workflow.indexOf("corepack pnpm verify:oss-boundary");
    if (!/^\s{2}workflow_dispatch:\s*$/mu.test(workflow)) {
      failures.push(
        "Public workflow does not expose the owner-controlled post-visibility dispatch trigger",
      );
    }
    if (attestationIndex === -1) {
      failures.push("Public workflow does not attest the tracked checkout");
    }
    if (boundaryIndex === -1) {
      failures.push(
        "Public workflow does not scan the tracked checkout boundary",
      );
    } else if (attestationIndex === -1 || boundaryIndex < attestationIndex) {
      failures.push(
        "Public workflow must attest before scanning the tracked checkout boundary",
      );
    }
    if (!workflow.includes("corepack pnpm release:versions:check")) {
      failures.push(
        "Public workflow does not enforce release-version consistency",
      );
    }
    if (!workflow.includes("corepack pnpm contracts:validate")) {
      failures.push(
        "Public workflow does not run offline standards-level contract validation",
      );
    }
    if (!workflow.includes("corepack pnpm test:e2e:community")) {
      failures.push(
        "Public workflow does not run generated-tree Community Playwright",
      );
    }
    if (!workflow.includes("corepack pnpm test:postgres:no-skip")) {
      failures.push(
        "Public workflow does not enforce the zero-skip Postgres release suite",
      );
    }
    if (/\bpull_request_target\s*:/u.test(workflow)) {
      failures.push(
        "Public workflow must not run fork contributions through pull_request_target",
      );
    }
    if (
      !/node-version:\s*\$\{\{ matrix\.node-version \}\}/u.test(workflow) ||
      !workflow.includes("['22', '24']")
    ) {
      failures.push("Public workflow does not test Node 22 and 24");
    }
    if (!codeqlJob) {
      failures.push("Public workflow does not define the CodeQL job");
    } else {
      if (
        !codeqlJob.includes(
          "if: ${{ github.event.repository.visibility == 'public' }}",
        )
      ) {
        failures.push(
          "Public CodeQL job must stay public-only while private staging has no paid Code Security license",
        );
      }
      if (!codeqlJob.includes("actions: read")) {
        failures.push("Public CodeQL job does not grant actions: read");
      }
      if (!codeqlJob.includes("security-events: write")) {
        failures.push(
          "Public CodeQL job does not grant security-events: write",
        );
      }
    }
    if (!secretScanJob) {
      failures.push("Public workflow does not define the secret-scan job");
    } else {
      const secretAttestationIndex = secretScanJob.indexOf(
        "node scripts/attest-public-checkout.mjs .",
      );
      const gitleaksIndex = secretScanJob.indexOf(
        "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
      );
      if (!secretScanJob.includes("fetch-depth: 0")) {
        failures.push("Public secret scan does not fetch complete Git history");
      }
      if (gitleaksIndex === -1) {
        failures.push(
          "Public secret scan does not use the approved digest-pinned Gitleaks CLI image",
        );
      } else if (
        secretAttestationIndex === -1 ||
        gitleaksIndex < secretAttestationIndex
      ) {
        failures.push(
          "Public secret scan must attest the checkout before running Gitleaks",
        );
      }
      if (
        !/\n\s+git\n\s+--no-banner\n\s+--no-color\n\s+--redact\n\s+\./u.test(
          secretScanJob,
        )
      ) {
        failures.push(
          "Public secret scan does not run the redacted full-history Gitleaks git command",
        );
      }
    }
    if (
      workflow.includes("gitleaks/gitleaks-action") ||
      workflow.includes("GITLEAKS_LICENSE")
    ) {
      failures.push(
        "Public secret scan depends on the organization-license-gated Gitleaks Action",
      );
    }
  }
}

async function verifyDocumentation() {
  const rootPackage = await readJsonIfPresent("package.json");
  const readme = await readTextIfPresent("README.md");
  const adoptionGuide = await readTextIfPresent("docs/ADOPTING.md");
  if (readme && !readme.includes("](docs/ADOPTING.md)")) {
    failures.push(
      "README.md must link the third-party adoption guide at docs/ADOPTING.md",
    );
  }
  if (adoptionGuide) {
    for (const requirement of [
      "does not yet publish an npm package or a registry container image",
      "corepack pnpm --filter @actionproxy/sdk-js pack --out",
      "runExternalAction",
      "MCP consumer path",
      "HTTP consumer path",
      "unknown_outcome",
      "Do not automatically",
      "GET /v1/audit/verify",
      "OpenAI runtime key",
      "Prompt for a coding agent",
    ]) {
      if (!adoptionGuide.includes(requirement)) {
        failures.push(
          `docs/ADOPTING.md is missing required third-party adoption guidance: ${requirement}`,
        );
      }
    }
  }
  for (const relativePath of await getVerificationFiles()) {
    if (path.extname(relativePath) !== ".md") continue;
    const body = await fs.readFile(
      path.join(destination, relativePath),
      "utf8",
    );
    if (rootPackage) {
      for (const match of body.matchAll(/corepack pnpm ([a-z][a-z0-9:-]*)/gu)) {
        if (
          !["add", "audit", "dlx", "exec", "install"].includes(match[1]) &&
          typeof rootPackage.scripts?.[match[1]] !== "string"
        ) {
          failures.push(
            `${relativePath} documents missing package script: ${match[1]}`,
          );
        }
      }
    }
    for (const match of body.matchAll(/\]\(([^)]+)\)/gu)) {
      let linkTarget = match[1].trim();
      if (linkTarget.startsWith("<") && linkTarget.endsWith(">")) {
        linkTarget = linkTarget.slice(1, -1);
      }
      if (
        linkTarget.startsWith("/") ||
        /^[a-z][a-z0-9+.-]*:/iu.test(linkTarget) ||
        /[{}*]/u.test(linkTarget)
      )
        continue;
      const hashIndex = linkTarget.indexOf("#");
      let fragment = hashIndex === -1 ? "" : linkTarget.slice(hashIndex + 1);
      let target = (
        hashIndex === -1 ? linkTarget : linkTarget.slice(0, hashIndex)
      ).split("?", 1)[0];
      try {
        target = decodeURIComponent(target);
        fragment = decodeURIComponent(fragment);
      } catch {
        failures.push(
          `Invalid encoded Markdown link in ${relativePath}: ${match[1]}`,
        );
        continue;
      }
      const resolved = target
        ? path.resolve(destination, path.dirname(relativePath), target)
        : path.join(destination, relativePath);
      const resolvedRelative = normalizePath(
        path.relative(destination, resolved),
      );
      if (
        (resolved !== destination &&
          !resolved.startsWith(`${destination}${path.sep}`)) ||
        !(await verificationPathExists(resolvedRelative))
      ) {
        failures.push(
          `Dangling relative Markdown link in ${relativePath}: ${match[1]}`,
        );
      } else if (
        fragment &&
        path.extname(resolvedRelative).toLowerCase() === ".md" &&
        !(await markdownHasAnchor(resolvedRelative, fragment))
      ) {
        failures.push(
          `Dangling Markdown heading link in ${relativePath}: ${match[1]}`,
        );
      }
    }
  }
}

async function markdownHasAnchor(relativePath, fragment) {
  let anchors = markdownAnchorCache.get(relativePath);
  if (!anchors) {
    anchors = new Set();
    const duplicates = new Map();
    const body = await fs.readFile(
      path.join(destination, relativePath),
      "utf8",
    );
    for (const line of body.split(/\r?\n/gu)) {
      const heading = /^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$/u.exec(line)?.[1];
      if (!heading) continue;
      const baseSlug = heading
        .replace(/<[^>]*>/gu, "")
        .replace(/[`*_~]/gu, "")
        .toLowerCase()
        .trim()
        .replace(/[^\p{L}\p{N}\s_-]/gu, "")
        .replace(/\s+/gu, "-");
      const duplicate = duplicates.get(baseSlug) ?? 0;
      duplicates.set(baseSlug, duplicate + 1);
      anchors.add(duplicate === 0 ? baseSlug : `${baseSlug}-${duplicate}`);
    }
    markdownAnchorCache.set(relativePath, anchors);
  }
  return anchors.has(fragment.toLowerCase());
}

async function verifyStrictBoundary() {
  for (const relativePath of await getVerificationFiles()) {
    if (relativePath === "scripts/verify-public-export.mjs") continue;
    const extension = path.extname(relativePath);
    if (
      ![
        ".css",
        ".json",
        ".md",
        ".mjs",
        ".sh",
        ".ts",
        ".tsx",
        ".yaml",
        ".yml",
      ].includes(extension) &&
      !relativePath.endsWith(".env.example")
    )
      continue;
    const body = await fs.readFile(
      path.join(destination, relativePath),
      "utf8",
    );
    for (const [pattern, reason] of forbiddenContentRules) {
      const boundaryBody = stripExactNegativeHarnessAssertions(
        relativePath,
        reason,
        body,
      );
      pattern.lastIndex = 0;
      if (pattern.test(boundaryBody))
        failures.push(`Forbidden content in ${relativePath}: ${reason}`);
    }
    if (
      relativePath.startsWith("apps/server/") &&
      /globalThis\.fetch\s*=/u.test(body)
    ) {
      failures.push(
        `Forbidden content in ${relativePath}: server code replaces globalThis.fetch`,
      );
    }
    if (extension === ".md" || relativePath.endsWith(".env.example")) {
      for (const [pattern, reason] of narrativeRules) {
        pattern.lastIndex = 0;
        if (pattern.test(body))
          failures.push(`Public narrative copy in ${relativePath}: ${reason}`);
      }
      const positiveClaims = body.replace(
        /\bnot\s+(?:currently\s+)?(?:published|available)\s+(?:to|on|from|via)\s+(?:the\s+)?npm(?:\s+registry)?\b/giu,
        "",
      );
      if (
        /\b(?:available|published|installable)\s+(?:on|from|via|to)\s+(?:the\s+)?npm(?:\s+registry)?\b/iu.test(
          positiveClaims,
        )
      ) {
        failures.push(
          `Public narrative copy in ${relativePath}: unpublished npm distribution claim`,
        );
      }
      if (
        /\b(?:ghcr\.io|docker\.io|quay\.io)\/[^\s`'"]*actionproxy\b/iu.test(
          body,
        )
      ) {
        failures.push(
          `Public narrative copy in ${relativePath}: unpublished registry-image claim`,
        );
      }
    }
  }
}

function stripExactNegativeHarnessAssertions(relativePath, reason, body) {
  const assertions = negativeHarnessAllowances.get(relativePath)?.get(reason);
  if (!assertions) return body;
  let sanitized = body;
  for (const assertion of assertions) {
    const index = sanitized.indexOf(assertion);
    if (index === -1) continue;
    sanitized = `${sanitized.slice(0, index)}${" ".repeat(assertion.length)}${sanitized.slice(index + assertion.length)}`;
  }
  return sanitized;
}

async function verifySecrets() {
  const scannerPath = path.join(destination, "scripts/scan-public-secrets.mjs");
  if (!(await verificationPathExists("scripts/scan-public-secrets.mjs")))
    return;
  const result = spawnSync(process.execPath, [scannerPath, destination], {
    cwd: destination,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail =
      result.error?.message ||
      result.stderr.trim() ||
      result.stdout.trim() ||
      `exit ${String(result.status)}`;
    failures.push(`Secret scan failed: ${detail}`);
  }
}

async function initializeCheckoutVerification() {
  const topLevel = runGit(["rev-parse", "--show-toplevel"]).trim();
  let canonicalDestination;
  let canonicalTopLevel;
  try {
    canonicalDestination = await fs.realpath(destination);
    canonicalTopLevel = await fs.realpath(topLevel);
  } catch (error) {
    fail(
      `Cannot resolve Git checkout root: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (canonicalDestination !== canonicalTopLevel) {
    fail(
      `Checkout verification must run at the Git worktree root: ${canonicalTopLevel}`,
    );
  }

  let trackedRecords;
  try {
    trackedRecords = parseGitStageRecords(
      runGit(["ls-files", "--stage", "-z", "--cached"]),
    );
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
  verificationGitModes = new Map();
  for (const record of trackedRecords) {
    if (record.stage !== 0) {
      failures.push(
        `Tracked checkout has an unmerged index entry: ${record.path}`,
      );
      continue;
    }
    if (!isRegularGitMode(record.mode)) {
      failures.push(
        `Tracked public path has forbidden Git mode ${record.mode}: ${record.path}`,
      );
      continue;
    }
    if (verificationGitModes.has(record.path)) {
      failures.push(
        `Tracked checkout contains a duplicate path: ${record.path}`,
      );
      continue;
    }
    verificationGitModes.set(record.path, record.mode);
  }
  const trackedPaths = [...verificationGitModes.keys()].sort(comparePaths);
  if (
    verificationGitModes.has("PUBLIC_MANIFEST.json") &&
    verificationGitModes.get("PUBLIC_MANIFEST.json") !== "100644"
  ) {
    failures.push("Tracked PUBLIC_MANIFEST.json must have Git mode 100644");
  }
  for (const relativePath of trackedPaths) {
    try {
      const stat = await fs.lstat(path.join(destination, relativePath));
      if (stat.isSymbolicLink() || !stat.isFile()) {
        failures.push(
          `Tracked public path is not a regular file: ${relativePath}`,
        );
      }
    } catch (error) {
      failures.push(
        `Cannot read tracked public path ${relativePath}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  verificationFiles = trackedPaths;
}

async function getVerificationFiles() {
  if (verificationFiles) return verificationFiles;
  const files = [];
  for await (const relativePath of walkAllFiles(destination))
    files.push(relativePath);
  verificationFiles = files.sort(comparePaths);
  return verificationFiles;
}

async function verificationPathExists(relativePath) {
  if (!checkoutMode) return exists(path.join(destination, relativePath));
  const trackedPaths = await getVerificationFiles();
  return trackedPaths.some(
    (trackedPath) =>
      trackedPath === relativePath ||
      trackedPath.startsWith(`${relativePath}/`),
  );
}

async function* walkAllFiles(directory, base = directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => comparePaths(left.name, right.name));
  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);
    const relativePath = normalizePath(path.relative(base, absolutePath));
    if (entry.isSymbolicLink()) {
      failures.push(
        `Symbolic link is not allowed in public artifact: ${relativePath}`,
      );
    } else if (entry.isDirectory()) {
      yield* walkAllFiles(absolutePath, base);
    } else if (entry.isFile()) {
      yield relativePath;
    } else {
      failures.push(`Non-regular public artifact path: ${relativePath}`);
    }
  }
}

function runGit(args) {
  const result = spawnSync("git", ["-C", destination, ...args], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    fail(
      `git ${args.join(" ")} failed: ${result.error?.message || result.stderr.trim() || `exit ${String(result.status)}`}`,
    );
  }
  return result.stdout;
}

async function readTextIfPresent(relativePath) {
  const absolutePath = path.join(destination, relativePath);
  return (await exists(absolutePath))
    ? fs.readFile(absolutePath, "utf8")
    : undefined;
}

async function readJsonIfPresent(relativePath) {
  const body = await readTextIfPresent(relativePath);
  if (body === undefined) return undefined;
  try {
    return JSON.parse(body);
  } catch (error) {
    failures.push(
      `${relativePath} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
    return undefined;
  }
}

function canonicalGitHubRepositoryUrl(value) {
  if (typeof value !== "string" || value === "") return undefined;
  try {
    const parsed = new URL(value);
    const segments = parsed.pathname.split("/").filter(Boolean);
    if (
      parsed.protocol !== "https:" ||
      parsed.hostname.toLowerCase() !== "github.com" ||
      parsed.port ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      segments.length !== 2 ||
      segments[1].endsWith(".git") ||
      segments.some((segment) => !/^[A-Za-z0-9_.-]+$/u.test(segment))
    )
      return undefined;
    return `https://github.com/${segments[0]}/${segments[1]}`;
  } catch {
    return undefined;
  }
}

function isSemverTag(value) {
  if (typeof value !== "string") return false;
  const match =
    /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/u.exec(
      value,
    );
  return (
    Boolean(match) &&
    !match?.[1]
      ?.split(".")
      .some(
        (part) =>
          /^\d+$/u.test(part) && part.length > 1 && part.startsWith("0"),
      )
  );
}

function hasExactKeys(value, expectedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actualKeys = Object.keys(value).sort(comparePaths);
  const sortedExpectedKeys = [...expectedKeys].sort(comparePaths);
  return (
    actualKeys.length === sortedExpectedKeys.length &&
    actualKeys.every((key, index) => key === sortedExpectedKeys[index])
  );
}

function normalizePath(value) {
  return value.split(path.sep).join("/");
}

function writeVerificationReport(ok, reportFailures) {
  writeFileSync(
    1,
    `${JSON.stringify(
      {
        schemaVersion: verificationReportSchemaVersion,
        ok,
        mode: checkoutMode ? "checkout" : "artifact",
        strict,
        failureCount: reportFailures.length,
        failures: [...reportFailures],
      },
      null,
      2,
    )}\n`,
  );
}

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function fail(message) {
  if (jsonOutput) writeVerificationReport(false, [message]);
  else console.error(message);
  process.exit(1);
}
