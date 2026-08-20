#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
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
const bootstrapMode = process.argv.includes("--bootstrap");
const approvedRepository = "https://github.com/ActionProxy/actionproxy";
const approvedReleaseTag = "v0.1.1";
const verificationReportSchemaVersion = "actionproxy.public-verification.v2";
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
  "apps/server/src/storage/migrations/0004_unique_approver_principal.sql",
  "apps/server/src/storage/migrations/0005_unique_approver_effective_identity.sql",
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
  "packages/mcp-wrapper/src/npm-release-artifacts.mjs",
  "packages/mcp-wrapper/src/npm-release-artifacts.test.mjs",
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

const reviewedNpmPackageSurfaceFields = [
  "type",
  "files",
  "sideEffects",
  "main",
  "module",
  "types",
  "exports",
  "bin",
  "scripts",
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "peerDependenciesMeta",
  "optionalDependencies",
  "bundledDependencies",
  "bundleDependencies",
  "publishConfig",
  "engines",
];

const reviewedNpmPackageSurfaces = {
  "packages/sdk-js": {
    type: "module",
    files: ["dist"],
    sideEffects: false,
    main: "dist/index.js",
    types: "dist/index.d.ts",
    exports: {
      ".": {
        types: "./dist/index.d.ts",
        import: "./dist/index.js",
      },
    },
    scripts: {
      build: "tsup src/index.ts --format esm --dts --out-dir dist",
      prepack: "npm run build",
      test: "vitest run",
      lint: "tsc --noEmit",
    },
    devDependencies: {
      "@types/node": "^22.7.4",
      tsup: "^8.3.0",
      typescript: "^5.6.3",
      vitest: "^3.2.6",
    },
    publishConfig: {
      access: "public",
      registry: "https://registry.npmjs.org/",
    },
    engines: {
      node: ">=22 <25",
    },
  },
  "packages/mcp-wrapper": {
    type: "module",
    files: ["dist"],
    bin: {
      "actionproxy-mcp": "dist/index.js",
    },
    main: "dist/index.js",
    types: "dist/index.d.ts",
    exports: {
      ".": {
        types: "./dist/index.d.ts",
        import: "./dist/index.js",
      },
    },
    scripts: {
      build: "tsup src/index.ts --format esm --dts --out-dir dist",
      prepack: "npm run build",
      test: "vitest run",
      lint: "tsc --noEmit",
    },
    dependencies: {
      yaml: "^2.5.1",
    },
    devDependencies: {
      "@types/node": "^22.7.4",
      tsup: "^8.3.0",
      typescript: "^5.6.3",
      vitest: "^3.2.6",
    },
    publishConfig: {
      access: "public",
      registry: "https://registry.npmjs.org/",
    },
    engines: {
      node: ">=22 <25",
    },
  },
};

const reviewedRootVerificationToolchain = {
  "@readme/openapi-parser": "6.3.0",
  ajv: "8.20.0",
  typescript: "5.9.3",
};

const forbiddenInstallLifecycleScripts = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
];

const forbiddenPaths = [
  ".git",
  ".npmrc",
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
    /\b(?:AgentRun|AgentRunService|AgentFlowBuilderService|AgentRunRecord|CompanyAgentRecord|CustomAgentFlowRecord|UserConnectedAccountRecord)\b|\b(?:agent_runs|company_agents|custom_agent_flows|user_connected_accounts)\b/,
    "platform agent or connected-account model leaked into public export",
  ],
  [
    /\b(?:GoogleWorkspaceConnector|HubSpotConnector|SlackOAuthService|StripeConnector|ZendeskConnector|TeamsService)\b/,
    "native provider runtime leaked into public export",
  ],
  [
    /--platform\b|\/v1\/system\/mcp-status\b|\bactionproxy\.(?:agents\.list|connections\.status|email\.propose_exact|runs\.(?:get|start)|approvals\.get)\b/,
    "private platform MCP preflight or catalog surface leaked into public export",
  ],
  [
    /\b(?:agent:(?:read|write|run)|user_connection:(?:read|write))\b/,
    "private platform authorization scope leaked into public export",
  ],
  [
    /\b(?:agent_run_continue|nativeAction)\b/,
    "private authorized-action projection leaked into public export",
  ],
  [
    /\bactionproxy\.(?:exact-email|native\.[a-z0-9_.-]+)\b|\bgoogle\.gmail\.send_email\b/i,
    "private provider prepared-action fixture leaked into public export",
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

const approvedPublishedNpmPackages = [
  "@actionproxy/sdk-js",
  "@actionproxy/mcp-wrapper",
];

// Registry/package/container prose is intentionally fail-closed. Each digest
// binds one normalized Markdown logical unit to its reviewed public path and
// exact occurrence count. New wording must update this inventory in the same
// reviewed change; the verifier does not try to infer whether a new natural-
// language claim is true.
const reviewedRegistryNarrativeInventory = [
  [
    "AGENTS.md",
    "0080f58a860cbc326bf46c939ba4ed0992ae2bd19fb660d7f68546f6bf97d1f8",
    1,
  ],
  [
    "AGENTS.md",
    "80c3386d88ba92518a19215d292a413c6de45ed769ecb23de782ff46efdb6e3e",
    1,
  ],
  [
    "README.md",
    "039404ad4b3eab148ee6f086f1352eba25746f53be5d2cbb9b693b543ec11d9a",
    1,
  ],
  [
    "README.md",
    "cfab7f673beea1e8bf89df4773e7c9240296618d76c15adcc1471da066c57302",
    1,
  ],
  [
    "README.md",
    "fcf6bb2112b0f2ca20f8a391bf60728bb95b992f4746c4216258ffff39ebb135",
    1,
  ],
  [
    "README.md",
    "ef2c70060651114603a2793e3a603ecd867088d77e4ff0ef394cf7bc0f1c143b",
    1,
  ],
  [
    "README.md",
    "b3ff502d4fe0601372de05b7ab251ec0fb50a4422f6eab19ecb2a48329c6d72a",
    1,
  ],
  [
    "README.md",
    "e3c9634ed1393f66d32a665c3b630ad5e2c0597c3a905f841f890ebb98473658",
    1,
  ],
  [
    "docs/ADOPTING.md",
    "3317ff7a147ac3eb537afd7a952e96e985eeb1d84c29bb77a46c02204778ec76",
    1,
  ],
  [
    "docs/ADOPTING.md",
    "c37c79c05b56409c1556d1e9bee77e102806c6480fd4944057f78838a75d8f57",
    1,
  ],
  [
    "docs/ADOPTING.md",
    "b8ae5fbb5801e819b64f096b706eb37f6e335044ba6b2e3920334a8f02333473",
    1,
  ],
  [
    "docs/ADOPTING.md",
    "80b205d3ccd3c1f1cb05bdf8778329a663668fc1fbf019d2a93ea19906deac20",
    1,
  ],
  [
    "docs/ADOPTING.md",
    "45f99590a3e7f28cf5fd5f86da56ac670212ed0a2c65b49b088daed9ab2a77b3",
    1,
  ],
  [
    "docs/COMMUNITY_CAPABILITIES.md",
    "43e1d6b0569f1bdc85f78d00ee6b444ca5f26d8e55dbd3c1ec9d75365933c370",
    1,
  ],
  [
    "docs/COMMUNITY_CAPABILITIES.md",
    "1d672a37539f7b12f01116e30f40d7c5ad8ab3b07e17066dcbbd5a6f7f3cadfa",
    1,
  ],
  [
    "docs/EXTERNAL_RUNNERS_MCP.md",
    "b928cca5f81769622fbcdeb3c7bdc3dedf1892eabec5ab4900fee7604ad5bd6c",
    1,
  ],
  [
    "docs/OSS_TEST_STATUS.md",
    "f26e69a80c092a272da135a2d1155cd2dd591bacff8f08d6698361e4e276b9a9",
    1,
  ],
  [
    "docs/OSS_TEST_STATUS.md",
    "9d2c1920e1a90545b1c32c7a13117055eb03eb149b09b27d8f6ebebd70162eaf",
    1,
  ],
  [
    "docs/OSS_TEST_STATUS.md",
    "97e339dc896189b67a4d8de1574d4abae90383596c4d33923b159da67c039bc7",
    1,
  ],
  [
    "docs/OSS_TEST_STATUS.md",
    "56555fc131625854f06d75e17524652919e1fc69d563f0cf705627f2d68773dc",
    1,
  ],
  [
    "docs/OSS_TEST_STATUS.md",
    "771c8d79c7d550faaf27bb6cb417a0060b59ba11f7d60841eabdc70acee7f167",
    1,
  ],
  [
    "CHANGELOG.md",
    "8c91220676bb21e252f7ce3434f94947ffa2814200bf1addaedcb0006e0fd72f",
    1,
  ],
  [
    "CHANGELOG.md",
    "e0417abf49f32eeffd31cc6363a7b5108e414bbc2146c09cdd489754ec8c3cf3",
    1,
  ],
  [
    "CHANGELOG.md",
    "c1a2855f5d7fee3020534c4107a12155b0c4a966ede0b92ec51bc49ea3ea8b18",
    1,
  ],
  [
    "CHANGELOG.md",
    "11f56d800e768b85aa04eac05c71cfdb0dc9536280615ed71927fdfba0c38caa",
    1,
  ],
  [
    "packages/sdk-js/README.md",
    "71bbde949e333d09e1cdca6d028dec586287c60f235d115c04a2d2c317b3f34e",
    1,
  ],
  [
    "packages/mcp-wrapper/README.md",
    "71bbde949e333d09e1cdca6d028dec586287c60f235d115c04a2d2c317b3f34e",
    1,
  ],
  [
    "packages/mcp-wrapper/README.md",
    "4041f018ec60af8c6419e5e10db147b95b8ce5a8ffe3dc44a381afea098804ec",
    1,
  ],
];

// Dynamic shell examples are also fail-closed. The Community export contains
// only these two reviewed operational commands; new variable/substitution
// syntax must be reviewed and digest-bound instead of relying on partial shell
// interpretation. A single source-bound local .tgz install remains a
// structural fallback allowance below.
const reviewedDynamicShellUnitInventory = [
  [
    "docs/CHATGPT_MCP.md",
    "1654e898e50cdf981e5caa8cee192e6792dfe7f9be5c40d7222075f414469622",
    1,
  ],
  [
    "docs/CHATGPT_MCP.md",
    "a118d2de757f394cfd2786e41917b435b629d0840bee59d8faeb674276556c7a",
    1,
  ],
];

const dynamicShellTokenPattern =
  /\$\{[^}\r\n]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?$!-]|\$\(|`/gu;

const historicalChangelogNpmNarrativeExemptions = new Map([
  [
    "- Prepared `@actionproxy/sdk-js` and `@actionproxy/mcp-wrapper` for their first public npm release with exact-install guidance, focused registry metadata, protected publication gates, and anonymous consumer verification.",
    { release: "0.1.1", subsection: "Added" },
  ],
  [
    "- Versioned JavaScript SDK and MCP-wrapper source-package candidates, an OpenAPI 3.1 contract, policy and MCP-wrapper JSON Schemas, and an isolated packed-consumer conformance suite.",
    { release: "0.1.0", subsection: "Added" },
  ],
  [
    "- `@actionproxy/sdk-js@0.1.0` and `@actionproxy/mcp-wrapper@0.1.0` are packable source-package candidates. The packages are not currently published to npm.",
    { release: "0.1.0", subsection: "Distribution" },
  ],
]);

const scopedActionProxyPackagePattern =
  /(?<![A-Za-z0-9._/@-])(@actionproxy\/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)(?:@([^\s`'"<>\[\](){},;]+))?/giu;
const lookalikeScopedActionProxyPackagePattern =
  /(?<![A-Za-z0-9._/@-])(@(?:action[._-]+proxy[a-z0-9._-]*|actionproxy[a-z0-9._-]+)\/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)(?:@([^\s`'"<>\[\](){},;]+))?/giu;
const unofficialScopedActionProxyPackagePattern =
  /(?<![A-Za-z0-9._/@-])(@[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\/action[._-]*proxy(?:[._-][a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)*)(?:@([^\s`'"<>\[\](){},;]+))?/giu;
const unscopedActionProxyPackagePattern =
  /(?<![A-Za-z0-9._/@-])(action[._-]*proxy(?:[._-][a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)*)(?:@([^\s`'"<>\[\](){},;]+))?/gu;

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
if (!bootstrapMode) await verifyRelativeImportClosure();
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
    `Public ${checkoutMode ? "checkout boundary" : "export artifact"} verification passed${strict ? " in strict mode" : ""}${bootstrapMode ? " (bootstrap checks; source closure deferred)" : ""}: ${destination}`,
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

async function verifyRelativeImportClosure() {
  let ts;
  let typeScriptModuleUrl;
  try {
    typeScriptModuleUrl = import.meta.resolve("typescript");
    ts = await import(typeScriptModuleUrl);
  } catch {
    failures.push(
      "Full source-closure verification requires the frozen TypeScript dependency; run --bootstrap only before dependency installation, then rerun full verification",
    );
    return;
  }
  if (checkoutMode) {
    const candidateNodeModules = path.join(destination, "node_modules");
    const resolvedTypeScriptPath = fileURLToPath(typeScriptModuleUrl);
    const relativeTypeScriptPath = path.relative(
      candidateNodeModules,
      resolvedTypeScriptPath,
    );
    if (
      relativeTypeScriptPath === "" ||
      relativeTypeScriptPath === ".." ||
      relativeTypeScriptPath.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativeTypeScriptPath)
    ) {
      failures.push(
        "Full tracked-checkout source closure must resolve TypeScript from the candidate root node_modules",
      );
    }
  }
  const sourceExtensions = new Set([
    ".cjs",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".mts",
    ".ts",
    ".tsx",
  ]);
  const resolvableExtensions = [
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".json",
  ];
  const files = await getVerificationFiles();
  const fileSet = new Set(files);
  const declaredBuildOutputs = await collectDeclaredPackageBuildOutputs(files);
  for (const relativePath of files) {
    if (!sourceExtensions.has(path.extname(relativePath))) continue;
    let body;
    try {
      body = await fs.readFile(path.join(destination, relativePath), "utf8");
    } catch (error) {
      failures.push(
        `Cannot inspect imports in ${relativePath}: ${error instanceof Error ? error.message : String(error)}`,
      );
      continue;
    }
    let sourceReferences;
    try {
      sourceReferences = collectSourceReferences(ts, relativePath, body);
    } catch {
      failures.push(
        `Cannot analyze source closure in ${relativePath} (TypeScript traversal failed)`,
      );
      continue;
    }
    for (const reference of sourceReferences) {
      const specifier = reference.specifier;
      if (!specifier.startsWith(".")) continue;
      const cleanSpecifier = specifier.replace(/[?#].*$/u, "");
      const base = normalizePath(
        path.posix.normalize(
          path.posix.join(path.posix.dirname(relativePath), cleanSpecifier),
        ),
      );
      if (
        base === ".." ||
        base.startsWith("../") ||
        path.posix.isAbsolute(base) ||
        !relativeImportResolves(
          base,
          fileSet,
          resolvableExtensions,
          declaredBuildOutputs,
        )
      ) {
        failures.push(
          `Unresolved relative ${reference.kind} in ${relativePath}: ${specifier}`,
        );
      }
    }
  }
}

function collectSourceReferences(ts, relativePath, source) {
  const scriptKind = scriptKindForPath(ts, relativePath);
  const parserSource = source.startsWith("\ufeff#!") ? source.slice(1) : source;
  const sourceFile = ts.createSourceFile(
    relativePath,
    parserSource,
    ts.ScriptTarget.Latest,
    true,
    scriptKind,
  );
  if (sourceFile.parseDiagnostics.length > 0) {
    for (const diagnostic of sourceFile.parseDiagnostics) {
      const position = sourceFile.getLineAndCharacterOfPosition(
        diagnostic.start ?? 0,
      );
      failures.push(
        `Cannot parse source closure in ${relativePath}:${String(position.line + 1)}:${String(position.character + 1)} (TypeScript diagnostic ${String(diagnostic.code)})`,
      );
    }
    return [];
  }

  const references = sourceFile.referencedFiles.map((reference) => ({
    kind: "triple-slash path reference",
    specifier: reference.fileName,
  }));
  for (const reference of sourceFile.typeReferenceDirectives) {
    references.push({
      kind: "triple-slash types reference",
      specifier: reference.fileName,
    });
  }
  for (const reference of sourceFile.libReferenceDirectives) {
    references.push({
      kind: "triple-slash lib reference",
      specifier: reference.fileName,
    });
  }
  for (const dependency of sourceFile.amdDependencies) {
    references.push({
      kind: "AMD dependency",
      specifier: dependency.path,
    });
  }

  const addLiteral = (kind, literal) => {
    if (literal && ts.isStringLiteralLike(literal)) {
      references.push({ kind, specifier: literal.text });
      return true;
    }
    return false;
  };
  const nodes = [sourceFile];
  while (nodes.length > 0) {
    const node = nodes.pop();
    if (!node) continue;
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      addLiteral("import", node.moduleSpecifier);
    } else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference)
    ) {
      addLiteral("import", node.moduleReference.expression);
    } else if (ts.isModuleDeclaration(node)) {
      addLiteral("module declaration", node.name);
    } else if (ts.isImportTypeNode(node)) {
      if (ts.isLiteralTypeNode(node.argument)) {
        addLiteral("import type", node.argument.literal);
      }
    } else if (ts.isCallExpression(node)) {
      const expression = node.expression;
      const firstArgument = node.arguments[0];
      if (expression.kind === ts.SyntaxKind.ImportKeyword) {
        addLiteral("import", firstArgument);
      } else if (isDependencyRequireExpression(ts, expression)) {
        addLiteral("import", firstArgument);
      } else if (isImportMetaResolveExpression(ts, expression)) {
        addLiteral("import.meta.resolve", firstArgument);
      }
    }
    // Recursively calling back through TypeScript's binary-expression walker
    // can overflow the JavaScript stack on generated-but-valid, left-deep
    // chains. Keep our traversal iterative, visit binary operands directly,
    // and use `forEachChild` only for bounded immediate-child walks.
    if (ts.isBinaryExpression(node)) {
      nodes.push(node.right, node.left);
    } else {
      ts.forEachChild(node, (child) => {
        nodes.push(child);
      });
    }
  }
  return references;
}

function scriptKindForPath(ts, relativePath) {
  const extension = path.extname(relativePath).toLowerCase();
  if (extension === ".jsx") return ts.ScriptKind.JSX;
  if (extension === ".tsx") return ts.ScriptKind.TSX;
  if ([".ts", ".mts", ".cts"].includes(extension)) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function isDependencyRequireExpression(ts, expression) {
  expression = unwrapDependencyExpression(ts, expression);
  if (ts.isIdentifier(expression)) return expression.text === "require";
  if (ts.isPropertyAccessExpression(expression)) {
    return isApprovedRequireMember(
      ts,
      expression.expression,
      expression.name.text,
    );
  }
  if (
    ts.isElementAccessExpression(expression) &&
    expression.argumentExpression &&
    ts.isStringLiteralLike(expression.argumentExpression)
  ) {
    return isApprovedRequireMember(
      ts,
      expression.expression,
      expression.argumentExpression.text,
    );
  }
  return false;
}

function isImportMetaResolveExpression(ts, expression) {
  expression = unwrapDependencyExpression(ts, expression);
  if (ts.isPropertyAccessExpression(expression)) {
    return (
      expression.name.text === "resolve" &&
      isImportMetaExpression(ts, expression.expression)
    );
  }
  if (
    ts.isElementAccessExpression(expression) &&
    expression.argumentExpression &&
    ts.isStringLiteralLike(expression.argumentExpression)
  ) {
    return (
      expression.argumentExpression.text === "resolve" &&
      isImportMetaExpression(ts, expression.expression)
    );
  }
  return false;
}

function isImportMetaExpression(ts, expression) {
  expression = unwrapDependencyExpression(ts, expression);
  return (
    ts.isMetaProperty(expression) &&
    expression.keywordToken === ts.SyntaxKind.ImportKeyword &&
    expression.name.text === "meta"
  );
}

function isApprovedRequireMember(ts, owner, member) {
  owner = unwrapDependencyExpression(ts, owner);
  return (
    ts.isIdentifier(owner) &&
    ((owner.text === "require" && member === "resolve") ||
      (owner.text === "module" && member === "require"))
  );
}

function unwrapDependencyExpression(ts, expression) {
  while (
    ts.isParenthesizedExpression(expression) ||
    ts.isNonNullExpression(expression) ||
    ts.isAsExpression(expression) ||
    ts.isTypeAssertionExpression(expression) ||
    ts.isSatisfiesExpression(expression)
  ) {
    expression = expression.expression;
  }
  return expression;
}

function relativeImportResolves(
  base,
  fileSet,
  extensions,
  declaredBuildOutputs,
) {
  const candidates = [base];
  const extension = path.posix.extname(base);
  if (extension === "") {
    for (const candidateExtension of extensions) {
      candidates.push(`${base}${candidateExtension}`);
      candidates.push(`${base}/index${candidateExtension}`);
    }
  } else {
    const sourceExtensionMappings = {
      ".cjs": [".cts"],
      ".js": [".ts", ".tsx"],
      ".jsx": [".tsx"],
      ".mjs": [".mts"],
    };
    for (const mappedExtension of sourceExtensionMappings[extension] ?? []) {
      candidates.push(`${base.slice(0, -extension.length)}${mappedExtension}`);
    }
  }
  return candidates.some(
    (candidate) =>
      fileSet.has(candidate) || declaredBuildOutputs.has(candidate),
  );
}

async function collectDeclaredPackageBuildOutputs(files) {
  const outputs = new Set();
  for (const relativePath of files) {
    if (!relativePath.endsWith("/package.json")) continue;
    let manifest;
    try {
      manifest = JSON.parse(
        await fs.readFile(path.join(destination, relativePath), "utf8"),
      );
    } catch {
      continue;
    }
    const directory = path.posix.dirname(relativePath);
    const collect = (value) => {
      if (typeof value === "string") {
        const normalized = value.replace(/^\.\//u, "");
        if (normalized.startsWith("dist/") && !normalized.includes("..")) {
          outputs.add(path.posix.join(directory, normalized));
        }
        return;
      }
      if (Array.isArray(value)) {
        for (const item of value) collect(item);
        return;
      }
      if (value && typeof value === "object") {
        for (const item of Object.values(value)) collect(item);
      }
    };
    for (const field of ["main", "module", "types", "exports", "bin"]) {
      collect(manifest[field]);
    }
  }
  return outputs;
}

async function verifyCommunityMigrationSequence() {
  const expected = [
    "apps/server/src/storage/migrations/0001_initial.sql",
    "apps/server/src/storage/migrations/0002_legacy_schema_reconciliation.sql",
    "apps/server/src/storage/migrations/0003_approver_principal_identity.sql",
    "apps/server/src/storage/migrations/0004_unique_approver_principal.sql",
    "apps/server/src/storage/migrations/0005_unique_approver_effective_identity.sql",
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
  if (
    rootPackage.scripts?.["verify:oss-boundary"] !==
    "node scripts/verify-public-export.mjs . --checkout --strict"
  ) {
    failures.push(
      "package.json verify:oss-boundary must run the full strict checkout verifier without bootstrap deferral",
    );
  }
  if (
    rootPackage.scripts?.["verify:tracked-checkout"] !==
    "node scripts/attest-public-checkout.mjs ."
  ) {
    failures.push(
      "package.json verify:tracked-checkout must run the reviewed tracked-checkout attestor",
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
  if (
    !isDeepStrictEqual(
      rootPackage.devDependencies,
      reviewedRootVerificationToolchain,
    )
  ) {
    failures.push(
      `package.json devDependencies must match the reviewed root verification toolchain exactly: ${Object.entries(
        reviewedRootVerificationToolchain,
      )
        .map(([dependency, version]) => `${dependency}@${version}`)
        .join(", ")}`,
    );
  }
  await verifyRootVerificationToolchainLock();
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
      homepage: "https://actionproxy.com/quickstart/",
      keywords: [
        "actionproxy",
        "ai-agents",
        "agent-security",
        "ai-governance",
        "approval-gateway",
        "audit",
        "human-in-the-loop",
        "tool-calling",
        "tool-governance",
      ],
      name: "@actionproxy/sdk-js",
    },
    {
      directory: "packages/mcp-wrapper",
      homepage: "https://actionproxy.com/quickstart/",
      keywords: [
        "actionproxy",
        "ai-agents",
        "agent-security",
        "ai-governance",
        "approval-gateway",
        "audit",
        "human-in-the-loop",
        "mcp",
        "mcp-proxy",
        "mcp-server",
        "model-context-protocol",
        "tool-calling",
        "tool-governance",
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
      candidate.homepage !== expected.homepage ||
      candidate.bugs?.url !==
        "https://github.com/ActionProxy/actionproxy/issues" ||
      JSON.stringify(candidate.keywords) !== JSON.stringify(expected.keywords)
    ) {
      failures.push(
        `${expected.directory}/package.json must remain the reviewed public, version-aligned, dist-only npm candidate`,
      );
    }
    const reviewedSurface = reviewedNpmPackageSurfaces[expected.directory];
    for (const field of reviewedNpmPackageSurfaceFields) {
      const actualHasField = Object.hasOwn(candidate, field);
      const expectedHasField = Object.hasOwn(reviewedSurface, field);
      if (
        actualHasField !== expectedHasField ||
        (actualHasField &&
          !isDeepStrictEqual(candidate[field], reviewedSurface[field]))
      ) {
        failures.push(
          `${expected.directory}/package.json ${field} must match the reviewed npm package surface exactly`,
        );
      }
    }
    for (const scriptName of forbiddenInstallLifecycleScripts) {
      if (Object.hasOwn(candidate.scripts ?? {}, scriptName)) {
        failures.push(
          `${expected.directory}/package.json must not define install lifecycle script ${scriptName}`,
        );
      }
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

async function verifyRootVerificationToolchainLock() {
  const lockfile = await readTextIfPresent("pnpm-lock.yaml");
  if (lockfile === undefined) return;
  const importerMarker = "\n  .:\n";
  const importerStart = lockfile.indexOf(importerMarker);
  let rootImporter;
  if (importerStart !== -1) {
    const importerBodyStart = importerStart + importerMarker.length;
    const remainder = lockfile.slice(importerBodyStart);
    const nextImporter = /^  [^\s].*:\s*$/mu.exec(remainder);
    rootImporter = remainder.slice(0, nextImporter?.index ?? remainder.length);
  }
  const typeScriptEntries = rootImporter
    ? [
        ...rootImporter.matchAll(
          /^      typescript:\n        specifier: ([^\n]+)\n        version: ([^\n]+)$/gmu,
        ),
      ]
    : [];
  if (
    typeScriptEntries.length !== 1 ||
    typeScriptEntries[0]?.[1] !==
      reviewedRootVerificationToolchain.typescript ||
    typeScriptEntries[0]?.[2] !== reviewedRootVerificationToolchain.typescript
  ) {
    failures.push(
      `pnpm-lock.yaml root importer must pin typescript exactly to specifier/version ${reviewedRootVerificationToolchain.typescript}`,
    );
  }
  const version = reviewedRootVerificationToolchain.typescript;
  if (
    !lockfile.includes(
      `\n  typescript@${version}:\n    resolution: {integrity: `,
    ) ||
    !lockfile.includes(`\n  typescript@${version}: {}\n`)
  ) {
    failures.push(
      `pnpm-lock.yaml must contain the frozen typescript@${version} package resolution and snapshot`,
    );
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
    const npmPrepareJob =
      /\n  npm-release-prepare:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u.exec(
        workflow,
      )?.[0];
    const npmReleaseJob =
      /\n  npm-release:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u.exec(
        workflow,
      )?.[0];
    const npmVerifyJob =
      /\n  npm-release-verify:\n[\s\S]*?(?=\n  [a-z][a-z0-9-]*:\n|$)/u.exec(
        workflow,
      )?.[0];
    const npmReleaseHelper = await readTextIfPresent(
      "packages/mcp-wrapper/src/npm-release-artifacts.mjs",
    );
    const attestationIndex = workflow.indexOf(
      "corepack pnpm verify:tracked-checkout",
    );
    const bootstrapBoundaryIndex = workflow.indexOf(
      "node scripts/verify-public-export.mjs . --checkout --strict --bootstrap",
    );
    const installIndex = workflow.indexOf(
      "corepack pnpm install --frozen-lockfile",
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
    if (bootstrapBoundaryIndex === -1) {
      failures.push(
        "Public workflow does not bootstrap-verify the tracked checkout before dependency installation",
      );
    } else if (
      attestationIndex === -1 ||
      bootstrapBoundaryIndex < attestationIndex
    ) {
      failures.push(
        "Public workflow must attest before bootstrap-verifying the tracked checkout boundary",
      );
    }
    if (boundaryIndex === -1) {
      failures.push(
        "Public workflow does not fully verify the tracked checkout boundary",
      );
    } else if (
      installIndex === -1 ||
      bootstrapBoundaryIndex === -1 ||
      !(bootstrapBoundaryIndex < installIndex && installIndex < boundaryIndex)
    ) {
      failures.push(
        "Public workflow must bootstrap-verify before install and fully verify source closure after install",
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
    if (!npmPrepareJob) {
      failures.push(
        "Public workflow does not define the owner-only npm release preparation job",
      );
    } else {
      for (const requirement of [
        "github.event_name == 'workflow_dispatch'",
        "inputs.npm_operation != 'none'",
        "needs['first-run-macos'].result == 'success'",
        "needs.verify.result == 'success'",
        "needs['postgres-atomicity'].result == 'success'",
        "needs['docker-community'].result == 'success'",
        "needs.codeql.result == 'success'",
        "needs['secret-scan'].result == 'success'",
        "needs['workflow-lint'].result == 'success'",
        "timeout-minutes: 45",
        "fetch-depth: 0",
        "persist-credentials: false",
        "corepack pnpm verify:tracked-checkout",
        "node scripts/verify-public-export.mjs . --checkout --strict --bootstrap",
        "corepack pnpm verify:oss-boundary",
        "corepack pnpm release:versions:check",
        "corepack pnpm install --frozen-lockfile",
        "corepack pnpm test:consumer-conformance",
        "npm-release-artifacts.mjs prepare npm-release-bundle",
        "node-version: 22",
        "node-version: 24",
        "npm-release-artifacts.mjs consume npm-release-bundle",
        "npm-release-artifacts.mjs verify npm-release-bundle",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "path: npm-release-bundle",
      ]) {
        if (!npmPrepareJob.includes(requirement)) {
          failures.push(
            `Public npm release preparation is missing: ${requirement}`,
          );
        }
      }
      if (
        npmPrepareJob.includes("id-token: write") ||
        npmPrepareJob.includes("NODE_AUTH_TOKEN")
      ) {
        failures.push(
          "Public npm release preparation must not receive an OIDC or registry credential",
        );
      }
    }
    if (!npmVerifyJob) {
      failures.push(
        "Public workflow does not define the credential-free npm artifact verification job",
      );
    } else {
      for (const requirement of [
        "needs['npm-release-prepare'].result == 'success'",
        "timeout-minutes: 20",
        "fetch-depth: 0",
        "persist-credentials: false",
        "node-version: 24.11.0",
        "corepack pnpm install --frozen-lockfile",
        "corepack pnpm --filter @actionproxy/sdk-js build",
        "corepack pnpm --filter @actionproxy/mcp-wrapper build",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "path: npm-release-bundle",
        "npm-release-artifacts.mjs verify npm-release-bundle",
      ]) {
        if (!npmVerifyJob.includes(requirement)) {
          failures.push(
            `Public npm artifact verification is missing: ${requirement}`,
          );
        }
      }
      if (
        npmVerifyJob.includes("id-token: write") ||
        npmVerifyJob.includes("NODE_AUTH_TOKEN")
      ) {
        failures.push(
          "Public npm artifact verification must not receive an OIDC or registry credential",
        );
      }
    }
    if (!npmReleaseJob) {
      failures.push(
        "Public workflow does not define the environment-protected npm registry job",
      );
    } else {
      for (const requirement of [
        "needs['npm-release-prepare'].result == 'success'",
        "needs['npm-release-verify'].result == 'success'",
        "timeout-minutes: 20",
        "environment: npm-production",
        "group: actionproxy-npm-production",
        "cancel-in-progress: false",
        "contents: read",
        "id-token: write",
        "fetch-depth: 0",
        "persist-credentials: false",
        "node-version: 24.11.0",
        'test "$(npm --version)" = 11.6.1',
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "npm-release-artifacts.mjs write npm-release-bundle",
        "inputs.npm_operation == 'publish-latest'",
        "ACTIONPROXY_NPM_OPERATION: publish-latest",
        "ACTIONPROXY_NPM_TARGET_TAG: latest",
        "npm-release-artifacts.mjs registry-verify npm-release-bundle",
        "path: npm-release-bundle",
      ]) {
        if (!npmReleaseJob.includes(requirement)) {
          failures.push(`Public npm registry job is missing: ${requirement}`);
        }
      }
      if (
        npmReleaseJob.includes("NODE_AUTH_TOKEN") ||
        npmReleaseJob.includes("NPM_BOOTSTRAP_TOKEN")
      ) {
        failures.push(
          "Public npm registry job must use trusted-publisher OIDC without an npm token",
        );
      }
      if (npmReleaseJob.includes("registry-url:")) {
        failures.push(
          "Public npm registry job must not inherit setup-node's placeholder registry credential",
        );
      }
      if (npmReleaseJob.includes("dist-tag")) {
        failures.push(
          "Public npm registry job must publish directly and must not mutate npm dist-tags",
        );
      }
      if (
        npmReleaseJob.includes("corepack pnpm install") ||
        npmReleaseJob.includes("corepack pnpm --filter") ||
        npmReleaseJob.includes("npm install --global")
      ) {
        failures.push(
          "Public npm registry job must not execute repository dependencies or install a new npm CLI",
        );
      }
    }
    const npmOperationInput =
      /^ {6}npm_operation:\s*\n(?<body>[\s\S]*?)^ {6}npm_confirmation:/mu.exec(
        workflow,
      )?.groups?.body;
    const npmOperationOptions = npmOperationInput
      ? /^ {8}options:\s*\n(?<choices>(?: {10}- [^\n]+\n)+)/mu
          .exec(npmOperationInput)
          ?.groups?.choices.trim()
          .split("\n")
          .map((line) => line.trim().slice(2))
      : undefined;
    if (
      JSON.stringify(npmOperationOptions) !==
      JSON.stringify(["none", "publish-latest"])
    ) {
      failures.push(
        "Public workflow must expose only the direct trusted-publisher publish-latest operation",
      );
    }
    if (workflow.includes("NPM_BOOTSTRAP_TOKEN")) {
      failures.push(
        "Public workflow must not retain the retired npm bootstrap credential",
      );
    }
    if (!npmReleaseHelper) {
      failures.push("Public npm release artifact helper is missing");
    } else {
      for (const requirement of [
        "@actionproxy/sdk-js",
        "@actionproxy/mcp-wrapper",
        "SUPPORTED_NPM_RELEASE_COMMANDS",
        '"registry-verify"',
        "assertOperationTarget",
        "planPublishLatestRegistryState",
        "assertTrustedPublishingRuntime",
        '"--provenance"',
        '"--access"',
        '"public"',
        '"--tag"',
        '"latest"',
        "hasExactRegistryAttestations",
        "hasExactRegistryManifestMetadata",
        "hasExpectedTagState",
        "dist.signatures",
        "dist.attestations",
        '"cat-file"',
        '"rev-parse"',
        '"merge-base"',
        '"refs/remotes/origin/main"',
        "sanitizeChildEnvironment",
        "createSensitiveNpmContext",
        'path.join(os.tmpdir(), "actionproxy-npm-config-")',
        "NPM_CONFIG_USERCONFIG",
        "NPM_CONFIG_GLOBALCONFIG",
        'path.join(npmConfigRoot, ".npmrc")',
        "cwd: context.cwd",
        "/^npm_config_/",
        '["BASH_ENV", "ENV", "NODE_OPTIONS"]',
        "packaged manifest differs from the reviewed workspace manifest",
        "Publish-latest found an existing target outside the exact latest state",
        "Publish-latest refuses to replace or downgrade the current latest release",
        '"dist/index.d.ts"',
        '"dist/index.js"',
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "{ includeGitHubOidc: true }",
        "installPackageTarball",
        "The frozen workspace yaml dependency is outside node_modules",
        "data after its terminator",
        "unsupported permission bits",
        "nonzero entry padding",
      ]) {
        if (!npmReleaseHelper.includes(requirement)) {
          failures.push(`Public npm release helper is missing: ${requirement}`);
        }
      }
      for (const forbidden of [
        "bootstrap-next",
        "resume-bootstrap-next",
        "promote-latest",
        "includeNpmToken",
        '"dist-tag"',
        "_authToken=",
      ]) {
        if (npmReleaseHelper.includes(forbidden)) {
          failures.push(
            `Public npm release helper retains forbidden token or promotion flow: ${forbidden}`,
          );
        }
      }
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
      "published to npm with verified provenance",
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
    if (
      !/does not publish a\s+registry container image/iu.test(adoptionGuide)
    ) {
      failures.push(
        "docs/ADOPTING.md must state that ActionProxy does not publish a registry container image",
      );
    }
  }
  await verifyPublishedNpmNarratives({ adoptionGuide, readme });
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

async function verifyPublishedNpmNarratives({ adoptionGuide, readme }) {
  if (!verifiedManifest) return;
  const exactVersion = verifiedManifest.releaseTag.slice(1);
  const exactSpecs = new Map(
    approvedPublishedNpmPackages.map((packageName) => [
      packageName,
      `${packageName}@${exactVersion}`,
    ]),
  );
  const canonicalCommands = [
    `npm view ${exactSpecs.get("@actionproxy/sdk-js")} version dist.integrity repository.url dist.attestations`,
    `npm view ${exactSpecs.get("@actionproxy/mcp-wrapper")} version dist.integrity repository.url dist.attestations`,
    `npm install --save-exact ${exactSpecs.get("@actionproxy/sdk-js")}`,
    `npm install --save-exact ${exactSpecs.get("@actionproxy/mcp-wrapper")}`,
  ];

  for (const [relativePath, body] of [
    ["README.md", readme],
    ["docs/ADOPTING.md", adoptionGuide],
  ]) {
    if (!body) continue;
    for (const command of canonicalCommands) {
      if (!body.includes(command)) {
        failures.push(
          `${relativePath} is missing exact npm adoption guidance: ${command}`,
        );
      }
    }
  }

  const approvedNames = new Set(approvedPublishedNpmPackages);
  const reviewedNarrativeByPathAndDigest = new Map(
    reviewedRegistryNarrativeInventory.map(
      ([relativePath, digest, expectedCount]) => [
        `${relativePath}\0${digest}`,
        { digest, expectedCount, relativePath },
      ],
    ),
  );
  const reviewedNarrativeCounts = new Map(
    [...reviewedNarrativeByPathAndDigest.keys()].map((key) => [key, 0]),
  );
  const reviewedDynamicShellByPathAndDigest = new Map(
    reviewedDynamicShellUnitInventory.map(
      ([relativePath, digest, expectedCount]) => [
        `${relativePath}\0${digest}`,
        { digest, expectedCount, relativePath },
      ],
    ),
  );
  const reviewedDynamicShellCounts = new Map(
    [...reviewedDynamicShellByPathAndDigest.keys()].map((key) => [key, 0]),
  );
  for (const relativePath of await getVerificationFiles()) {
    if (path.extname(relativePath).toLowerCase() !== ".md") continue;
    const body = await readTextIfPresent(relativePath);
    if (!body) continue;
    let changelogSection;
    let changelogSubsection;
    let npmMarkdownContext;
    const historicalExemptionCounts = new Map(
      [...historicalChangelogNpmNarrativeExemptions.keys()].map((text) => [
        text,
        0,
      ]),
    );
    for (const unit of markdownLogicalUnits(body)) {
      if (relativePath === "CHANGELOG.md") {
        const releaseHeading = /^##\s+(.+)$/u.exec(unit.text);
        if (releaseHeading) {
          changelogSection = releaseHeading[1];
          changelogSubsection = undefined;
        }
        const subsectionHeading = /^###\s+(.+)$/u.exec(unit.text);
        if (subsectionHeading) changelogSubsection = subsectionHeading[1];
      }
      const narrativeText = normalizeMarkdownNarrative(unit.text);
      const digest = createHash("sha256").update(narrativeText).digest("hex");
      const inventoryKey = `${relativePath}\0${digest}`;
      if (reviewedNarrativeByPathAndDigest.has(inventoryKey)) {
        reviewedNarrativeCounts.set(
          inventoryKey,
          (reviewedNarrativeCounts.get(inventoryKey) ?? 0) + 1,
        );
      } else if (isRegistryOrContainerNarrative(unit, narrativeText)) {
        failures.push(
          `Public narrative copy in ${relativePath}:${unit.line}: unreviewed registry/container claim; stale pre-publication npm wording and unpublished registry-image claims require reviewed inventory`,
        );
      }
      const expectedHistoricalLocation =
        historicalChangelogNpmNarrativeExemptions.get(unit.text);
      if (
        relativePath === "CHANGELOG.md" &&
        expectedHistoricalLocation !== undefined &&
        expectedHistoricalLocation.release === changelogSection &&
        expectedHistoricalLocation.subsection === changelogSubsection
      ) {
        historicalExemptionCounts.set(
          unit.text,
          (historicalExemptionCounts.get(unit.text) ?? 0) + 1,
        );
        npmMarkdownContext = undefined;
        continue;
      }
      const shellCommandScanText =
        unit.kind === "shell"
          ? normalizeShellQuoteConcatenation(unit.text)
              .replace(/\s+/gu, " ")
              .trim()
          : normalizeShellQuoteConcatenation(unit.text);
      const packageScanText = normalizeMarkdownNarrative(shellCommandScanText);
      let reviewedDynamicShellUnit = false;
      const sourceBoundDynamicTarball =
        isSourceBoundDynamicTarballCommand(shellCommandScanText);
      if (unit.kind === "shell" && hasDynamicShellToken(unit.text)) {
        const dynamicShellDigest = createHash("sha256")
          .update(unit.text.replace(/\s+/gu, " ").trim())
          .digest("hex");
        const dynamicShellKey = `${relativePath}\0${dynamicShellDigest}`;
        if (reviewedDynamicShellByPathAndDigest.has(dynamicShellKey)) {
          reviewedDynamicShellUnit = true;
          reviewedDynamicShellCounts.set(
            dynamicShellKey,
            (reviewedDynamicShellCounts.get(dynamicShellKey) ?? 0) + 1,
          );
        } else if (!sourceBoundDynamicTarball) {
          failures.push(
            `Public shell guidance in ${relativePath}:${unit.line} uses unreviewed variable or substitution syntax with digest ${dynamicShellDigest}`,
          );
        }
      }
      const shellExpansionText = shellCommandScanText.replace(
        /\[::1\](?::\d+)?(?=\/)/giu,
        "ipv6-loopback",
      );
      if (
        (unit.kind === "shell" &&
          !reviewedDynamicShellUnit &&
          !sourceBoundDynamicTarball &&
          /\\[^\s]|[{}*?\[]/u.test(shellExpansionText)) ||
        (unit.kind === "code" &&
          /\\[^\s]/u.test(shellExpansionText) &&
          (findActionProxyPackageSpecs(packageScanText).length > 0 ||
            findActionProxyImageReferences(shellCommandScanText).length > 0))
      ) {
        failures.push(
          `Public distribution guidance in ${relativePath}:${unit.line} must not use unreviewed shell expansion syntax`,
        );
      }
      if (
        (unit.kind === "shell" || unit.kind === "code") &&
        hasUnapprovedDynamicShellExecutable(shellCommandScanText)
      ) {
        failures.push(
          `Public distribution guidance in ${relativePath}:${unit.line} must use a literal package or container command executable`,
        );
      }
      if (
        (unit.kind === "shell" || unit.kind === "code") &&
        hasUnapprovedShellExecutableExpansion(shellCommandScanText)
      ) {
        failures.push(
          `Public distribution guidance in ${relativePath}:${unit.line} must not use shell expansion in a command executable`,
        );
      }
      const packageManagerCommand =
        isPackageManagerCommandShaped(shellCommandScanText);
      const imageCommand = isImageCommandShaped(shellCommandScanText);
      if (
        (packageManagerCommand || imageCommand) &&
        hasUnapprovedDistributionWordExpansion(shellCommandScanText)
      ) {
        failures.push(
          `Public distribution guidance in ${relativePath}:${unit.line} must not use shell expansion in package or container command words`,
        );
      }
      if (
        (unit.kind === "shell" || imageCommand) &&
        hasUnapprovedRemoteActionProxyImageCommand(shellCommandScanText)
      ) {
        failures.push(
          `Public narrative copy in ${relativePath}:${unit.line}: unpublished registry-image claim; remote ActionProxy image commands are not published`,
        );
      }
      const inheritedNpmPackageContext = inheritsNpmMarkdownContext(
        npmMarkdownContext,
        unit,
      );
      const npmCommand =
        /\b(?:npm|pnpm|yarn|bun)\b.{0,160}\b(?:add|i|in|ins|inst|insta|instal|install|isnt|isnta|isntal|isntall|update|up|upgrade|view|info|show)\b/iu.test(
          packageScanText,
        );
      const npmInstallProse = /\b(?:install|add|fetch|download)\b/iu.test(
        packageScanText,
      );
      const npmRegistryClaim =
        /\b(?:npm|package\s+registry|registry\s+(?:package|record|release|download|install)|published|available|installable|dist-tag|provenance|attestations?|integrity)\b/iu.test(
          packageScanText,
        );
      if (
        (unit.kind === "shell" || packageManagerCommand) &&
        hasDynamicRegistryPackageSpecifier(shellCommandScanText)
      ) {
        failures.push(
          `Public npm guidance in ${relativePath}:${unit.line} must use a literal or same-fence exact ActionProxy package spec`,
        );
      }
      const packageSpecs = findActionProxyPackageSpecs(packageScanText).filter(
        (packageSpec) => {
          if (
            unit.kind !== "shell" &&
            unit.kind !== "code" &&
            isStructuralPostInstallImportNarrative(narrativeText)
          ) {
            return false;
          }
          if (isWorkspaceFilterSpecifier(packageScanText, packageSpec)) {
            return false;
          }
          if (
            (unit.kind === "shell" &&
              isShellPackageDistributionGuidance(
                packageScanText,
                packageSpec,
              )) ||
            (unit.kind === "shell" && packageSpec.kind !== "unscoped") ||
            inheritedNpmPackageContext ||
            isRegistryExecutionGuidance(packageScanText, packageSpec)
          ) {
            return true;
          }
          if (!(npmCommand || npmInstallProse || npmRegistryClaim)) {
            return false;
          }
          return (
            packageSpec.kind !== "unscoped" ||
            isUnscopedRegistryPackageGuidance(packageScanText, packageSpec)
          );
        },
      );
      if (packageSpecs.length > 0) {
        for (const { packageName, version } of packageSpecs) {
          if (!approvedNames.has(packageName)) {
            failures.push(
              `Public npm guidance in ${relativePath}:${unit.line} references unapproved package ${packageName}`,
            );
            continue;
          }
          if (version !== exactVersion) {
            failures.push(
              `Public npm guidance in ${relativePath}:${unit.line} must pin ${packageName}@${exactVersion}`,
            );
          }
        }
      }

      npmMarkdownContext = nextNpmMarkdownContext({
        context: npmMarkdownContext,
        inherited: inheritedNpmPackageContext,
        text: narrativeText,
        unit,
      });
    }
    if (relativePath === "CHANGELOG.md") {
      for (const [
        text,
        expectedLocation,
      ] of historicalChangelogNpmNarrativeExemptions) {
        const count = historicalExemptionCounts.get(text) ?? 0;
        if (count !== 1) {
          failures.push(
            `CHANGELOG.md must preserve exactly one reviewed historical npm narrative in ${expectedLocation.release}/${expectedLocation.subsection}`,
          );
        }
      }
    }
  }
  for (const [inventoryKey, inventory] of reviewedNarrativeByPathAndDigest) {
    const actualCount = reviewedNarrativeCounts.get(inventoryKey) ?? 0;
    if (actualCount !== inventory.expectedCount) {
      failures.push(
        `${inventory.relativePath} must preserve exactly ${inventory.expectedCount} reviewed registry/container narrative unit with digest ${inventory.digest}; found ${actualCount}`,
      );
    }
  }
  for (const [inventoryKey, inventory] of reviewedDynamicShellByPathAndDigest) {
    const actualCount = reviewedDynamicShellCounts.get(inventoryKey) ?? 0;
    if (actualCount !== inventory.expectedCount) {
      failures.push(
        `${inventory.relativePath} must preserve exactly ${inventory.expectedCount} reviewed dynamic shell unit with digest ${inventory.digest}; found ${actualCount}`,
      );
    }
  }
}

function normalizeMarkdownNarrative(text) {
  return text
    .replace(/<[^>]*>/gu, " ")
    .replace(/(?<![\p{L}\p{N}])[*_~`]+|[*_~`]+(?![\p{L}\p{N}])/gu, "")
    .replace(/\\([\\`*_{}\[\]()#+.!>|-])/gu, "$1")
    .replace(/\s+/gu, " ")
    .trim();
}

function isRegistryOrContainerNarrative(unit, text) {
  if (unit.kind === "shell" || unit.kind === "code" || !text) return false;
  if (isStructuralPostInstallImportNarrative(text)) return false;

  const hasNpmClaim =
    /\bnpm\b/iu.test(text) &&
    (/^\s*(?:on\s+)?npm\s*:?\s*$/iu.test(text) ||
      /\b(?:attestations?|available|availability|candidates?|dist-tag|download|exact|exists?|fetch|find|found|404|install(?:ation|able|ed|ing)?|integrity|launch|list|lookup|missing|packages?|provenance|publish(?:ed|es|ing)?|publication|records?|registry|release[ds]?|rollout|signatures?|source-bound|tarball|unavailable|unpublished|unreleased|versions?)\b/iu.test(
        text,
      ));
  const hasPackageRegistryClaim =
    /\b(?:package\s+registry|registry\s+(?:availability|download|install(?:ation)?|lookup|metadata|package|publication|publish(?:ing)?|records?|release|rollout))\b/iu.test(
      text,
    );
  const hasDistributionMetadataClaim =
    /\b(?:dist-tag|registry\s+integrity|registry\s+metadata|registry\s+record|SLSA\s+provenance)\b/iu.test(
      text,
    );
  const hasPackageIdentityNarrative =
    !isSourceBoundPackageReferenceOnly(text) &&
    !isWorkspaceSelectionNarrative(text) &&
    ((hasScopedActionProxyLikePackageIdentity(text) &&
      /\b(?:add|available|candidate|dependency|dist-tag|download|fetch|install(?:ation|able|ed|ing)?|package|provenance|publish(?:ed|es|ing)?|publication|registry|release[ds]?)\b/iu.test(
        text,
      )) ||
      hasUnscopedActionProxyPackageNarrative(text));
  const hasRegistryImageNarrative =
    /\bregistry\s+(?:container|docker|oci)?\s*image\b/iu.test(text) ||
    hasActionProxyRegistryImageNarrative(text);

  return (
    hasNpmClaim ||
    hasPackageRegistryClaim ||
    hasDistributionMetadataClaim ||
    hasPackageIdentityNarrative ||
    hasRegistryImageNarrative
  );
}

function isStructuralPostInstallImportNarrative(text) {
  return (
    /\bafter\s+npm\s+installation\b/iu.test(text) &&
    /\bimport\b.{0,160}\bfrom\s+@actionproxy\/(?:sdk-js|mcp-wrapper)\b/iu.test(
      text,
    ) &&
    !/\b(?:available|dist-tag|provenance|publish(?:ed|es|ing)?|publication|registry|release[ds]?)\b/iu.test(
      text,
    )
  );
}

function isSourceBoundPackageReferenceOnly(text) {
  return (
    /\b(?:file\s+dependency|local[-\s]+(?:package[-\s]+)?tarball|source[-\s]+bound|vendor\/)\b/iu.test(
      text,
    ) &&
    !/\b(?:available|dist-tag|provenance|publish(?:ed|es|ing)?|publication|registry\s+(?:availability|record|release)|release[ds]?)\b/iu.test(
      text,
    )
  );
}

function isWorkspaceSelectionNarrative(text) {
  return /\b(?:corepack\s+)?pnpm\s+--filter\b/iu.test(text);
}

function hasScopedActionProxyLikePackageIdentity(text) {
  return /(?<![A-Za-z0-9._/@-])@(?:action[._-]*proxy|action[._-]*proxy[a-z0-9._-]*)\/[a-z0-9][a-z0-9._-]*/iu.test(
    text,
  );
}

function hasUnscopedActionProxyPackageNarrative(text) {
  const packageIdentity =
    "action[._-]*proxy(?:[._-]+(?:agent|client|mcp|package|sdk|server|wrapper))(?:[._-]+[a-z0-9][a-z0-9._-]*)*";
  return (
    new RegExp(
      `\\b(?:npm|registry|packages?)\\b.{0,48}\\b${packageIdentity}\\b|\\b${packageIdentity}\\b.{0,48}\\b(?:npm|registry|packages?)\\b`,
      "iu",
    ).test(text) ||
    new RegExp(
      `\\b(?:add|download|fetch|install)\\b.{0,80}\\b${packageIdentity}\\b`,
      "iu",
    ).test(text)
  );
}

function hasActionProxyRegistryImageNarrative(text) {
  if (
    /\b(?:localhost|127\.0\.0\.1|::1)(?::\d+)?\/[^\s`'"]*action[._-]*proxy\b/iu.test(
      text,
    ) ||
    /\baction[._-]*proxy(?:\/action[._-]*proxy)?\s*:\s*local\b/iu.test(text)
  ) {
    return false;
  }
  const actionProxyReference =
    /\baction[._-]*proxy\b/iu.test(text) ||
    /\baction[._-]*proxy(?:\/action[._-]*proxy)?\s*:\s*[a-z0-9][a-z0-9._-]*\b/iu.test(
      text,
    );
  if (!actionProxyReference) return false;
  const actionProxyImageReference =
    /\baction[._-]*proxy\b.{0,60}\b(?:container|docker|oci)?\s*image\b|\b(?:container|docker|oci)?\s*image\b.{0,60}\baction[._-]*proxy\b/iu.test(
      text,
    );
  return (
    (actionProxyImageReference &&
      /\b(?:available|download|fetch|host(?:ed|s)?|provide[ds]?|publish(?:ed|es)?|pull|release[ds]?|registry)\b/iu.test(
        text,
      )) ||
    (/\b(?:container|docker|oci)\s+image\b/iu.test(text) &&
      /\b(?:available|download|fetch|host(?:ed|s)?|provide[ds]?|publish(?:ed|es)?|pull|release[ds]?|registry)\b/iu.test(
        text,
      )) ||
    /\bregistry\s+container\s+image\b/iu.test(text) ||
    /\b(?:Docker\s*Hub|GHCR|GitHub\s+Container\s+Registry|Quay(?:\.io)?|Harbor\s+registry|Amazon\s+ECR|public\s+ECR|container\s+registry|OCI\s+registry)\b/iu.test(
      text,
    ) ||
    (/\bOCI\s+artifact\b/iu.test(text) &&
      /\b(?:available|download|fetch|host(?:ed|s)?|provide[ds]?|publish(?:ed|es)?|pull|release[ds]?)\b/iu.test(
        text,
      )) ||
    /\b(?:ghcr\.io|docker\.io|quay\.io|public\.ecr\.aws|registry\.[a-z0-9.-]+|icr\.io|[a-z0-9-]+\.azurecr\.io|\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com|[a-z0-9-]+-docker\.pkg\.dev)\//iu.test(
      text,
    ) ||
    (hasRemoteImageCommand(text) &&
      /\baction[._-]*proxy(?:\/action[._-]*proxy)?\s*:\s*(?!local\b)[a-z0-9][a-z0-9._-]*\b/iu.test(
        text,
      )) ||
    (/\bskopeo\s+copy\b/iu.test(text) &&
      /\baction[._-]*proxy(?:\/action[._-]*proxy)?\b/iu.test(text))
  );
}

function normalizeShellQuoteConcatenation(text) {
  return text
    .replace(/\$'([^'\r\n]*)'/gu, "$1")
    .replace(/(?<=[A-Za-z0-9@/._-])["']+(?=[A-Za-z0-9@/._-])/gu, "");
}

function findDynamicShellTokens(text) {
  return [...text.matchAll(dynamicShellTokenPattern)];
}

function hasDynamicShellToken(text) {
  return findDynamicShellTokens(text).length > 0;
}

function hasDynamicRegistryPackageSpecifier(text) {
  const dynamicTokens = findDynamicShellTokens(text);
  if (dynamicTokens.length === 0) return false;
  if (isSourceBoundDynamicTarballCommand(text)) return false;
  return [
    ...text.matchAll(
      /\b(?:npm|pnpm|yarn|bun|npx|pnpx|bunx)\b[^;&|]{0,280}/giu,
    ),
  ].some((command) =>
    dynamicTokens.some(
      (token) =>
        token.index >= command.index &&
        token.index < command.index + command[0].length,
    ),
  );
}

function isSourceBoundDynamicTarballCommand(text) {
  const dynamicTokens = findDynamicShellTokens(text);
  if (dynamicTokens.length !== 1) return false;
  return /^(?:\$\s+)?(?:corepack\s+)?(?:npm|pnpm|yarn|bun)\s+(?:add|i|install)(?:\s+--?[A-Za-z0-9][A-Za-z0-9-]*(?:=[A-Za-z0-9._/:,@%+-]+)?)*\s+["']?(?:file:)?\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)\/[A-Za-z0-9._/-]+\.tgz["']?$/u.test(
    text,
  );
}

function hasUnapprovedDynamicShellExecutable(text) {
  for (const executable of shellCommandExecutables(text)) {
    if (!hasDynamicShellToken(executable)) continue;
    const normalized = stripShellWordQuotes(executable);
    if (
      /^\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)\/actionproxy$/u.test(
        normalized,
      )
    ) {
      continue;
    }
    return true;
  }
  return false;
}

function hasUnapprovedShellExecutableExpansion(text) {
  const distributionExecutables = [
    "bun",
    "bunx",
    "crane",
    "crictl",
    "ctr",
    "docker",
    "nerdctl",
    "npm",
    "npx",
    "oras",
    "pnpm",
    "pnpx",
    "podman",
    "skopeo",
    "yarn",
  ];
  return shellCommandExecutables(text).some((executable) => {
    if (!/\\[^\s]|[{}*?\[]/u.test(executable)) return false;
    const normalized = stripShellWordQuotes(executable)
      .replace(/\\(.)/gu, "$1")
      .split("/")
      .at(-1);
    if (!normalized) return false;
    return expandSimpleShellBraces(normalized).some((candidate) => {
      const globPattern = shellGlobPattern(candidate);
      return distributionExecutables.some((name) => globPattern.test(name));
    });
  });
}

function expandSimpleShellBraces(word) {
  const brace = /\{([^{}]*)\}/u.exec(word);
  if (!brace) return [word];
  const [whole, body] = brace;
  let alternatives;
  const sequence = /^(.)\.\.(.)$/u.exec(body);
  if (sequence) {
    const start = sequence[1].codePointAt(0);
    const end = sequence[2].codePointAt(0);
    const distance = Math.abs(end - start);
    alternatives =
      distance <= 32
        ? Array.from({ length: distance + 1 }, (_, index) =>
            String.fromCodePoint(start + Math.sign(end - start) * index),
          )
        : [body];
  } else {
    alternatives = body.split(",");
  }
  return alternatives.flatMap((alternative) =>
    expandSimpleShellBraces(
      `${word.slice(0, brace.index)}${alternative}${word.slice(
        brace.index + whole.length,
      )}`,
    ),
  );
}

function shellGlobPattern(word) {
  let pattern = "^";
  for (let index = 0; index < word.length; index += 1) {
    const character = word[index];
    if (character === "*") {
      pattern += ".*";
    } else if (character === "?") {
      pattern += ".";
    } else if (character === "[") {
      const end = word.indexOf("]", index + 1);
      if (end === -1) {
        pattern += "\\[";
      } else {
        const body = word.slice(index + 1, end).replace(/[\\\]^-]/gu, "\\$&");
        pattern += `[${body}]`;
        index = end;
      }
    } else {
      pattern += character.replace(/[\\^$.*+?()[\]{}|]/gu, "\\$&");
    }
  }
  return new RegExp(`${pattern}$`, "u");
}

function hasUnapprovedDistributionWordExpansion(text) {
  const withoutIpv6Loopback = text.replace(
    /\[::1\](?::\d+)?(?=\/)/giu,
    "ipv6-loopback",
  );
  return /\\[^\s]|[{}*?\[]/u.test(withoutIpv6Loopback);
}

function shellCommandExecutables(text) {
  const executables = [];
  for (const segment of shellCommandSegments(text)) {
    const words = shellWords(segment);
    if (words[0] === "$") words.shift();
    let unwrap = true;
    while (unwrap && words.length > 0) {
      while (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(words[0] ?? "")) {
        words.shift();
      }
      if (words.length === 0) break;
      unwrap = false;
      const wrapper =
        stripShellWordQuotes(words[0]).toLowerCase().split("/").at(-1) ?? "";
      if (wrapper === "command" || wrapper === "exec") {
        words.shift();
        while ((words[0] ?? "").startsWith("-")) words.shift();
        unwrap = true;
      } else if (wrapper === "env") {
        words.shift();
        while (words.length > 0) {
          const option = stripShellWordQuotes(words[0]);
          if (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(option)) {
            words.shift();
          } else if (/^-(?:u|C|S)$/u.test(option)) {
            words.splice(0, Math.min(2, words.length));
          } else if (option.startsWith("-")) {
            words.shift();
          } else {
            break;
          }
        }
        unwrap = true;
      } else if (wrapper === "sudo") {
        words.shift();
        while (words.length > 0) {
          const option = stripShellWordQuotes(words[0]);
          if (/^-(?:C|D|g|h|p|R|r|t|T|u)$/u.test(option)) {
            words.splice(0, Math.min(2, words.length));
          } else if (option.startsWith("-")) {
            words.shift();
          } else {
            break;
          }
        }
        unwrap = true;
      } else if (wrapper === "time") {
        words.shift();
        while ((words[0] ?? "").startsWith("-")) {
          const option = stripShellWordQuotes(words[0]);
          if (/^(?:-f|-o|--format|--output)$/u.test(option)) {
            words.splice(0, Math.min(2, words.length));
          } else {
            words.shift();
          }
        }
        unwrap = true;
      } else if (wrapper === "nohup") {
        words.shift();
        while ((words[0] ?? "").startsWith("-")) words.shift();
        unwrap = true;
      } else if (wrapper === "nice") {
        words.shift();
        if (/^-n$/u.test(words[0] ?? "")) words.splice(0, 2);
        while ((words[0] ?? "").startsWith("-")) words.shift();
        unwrap = true;
      } else if (wrapper === "timeout") {
        words.shift();
        while ((words[0] ?? "").startsWith("-")) {
          const option = stripShellWordQuotes(words[0]);
          if (/^(?:-k|-s|--kill-after|--signal)$/u.test(option)) {
            words.splice(0, Math.min(2, words.length));
          } else {
            words.shift();
          }
        }
        if (words[0]) words.shift();
        unwrap = true;
      }
    }
    if (words[0]) executables.push(words[0]);
  }
  return executables;
}

function shellCommandSegments(text) {
  const segments = [];
  let start = 0;
  let quote;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "#" && (index === 0 || /\s/u.test(text[index - 1]))) {
      segments.push(text.slice(start, index));
      return segments;
    }
    if (character === ";" || character === "&" || character === "|") {
      segments.push(text.slice(start, index));
      if (text[index + 1] === character) index += 1;
      start = index + 1;
    }
  }
  segments.push(text.slice(start));
  return segments;
}

function shellWords(segment) {
  return segment.match(/(?:"(?:\\.|[^"\\])*"|'[^']*'|`[^`]*`|\S+)/gu) ?? [];
}

function stripShellWordQuotes(word) {
  return word.replace(/["']/gu, "");
}

function isPackageManagerCommandShaped(text) {
  return shellCommandExecutables(text).some((word) =>
    /^(?:npm|pnpm|yarn|bun|npx|pnpx|bunx)$/iu.test(
      stripShellWordQuotes(word).split("/").at(-1) ?? "",
    ),
  );
}

function isImageCommandShaped(text) {
  return shellCommandExecutables(text).some((word) =>
    /^(?:crane|crictl|oras|ctr|docker|nerdctl|podman|skopeo)$/iu.test(
      stripShellWordQuotes(word).split("/").at(-1) ?? "",
    ),
  );
}

function hasUnapprovedRemoteActionProxyImageCommand(text) {
  if (isImageCommandShaped(text) && hasDynamicShellToken(text)) {
    return true;
  }
  const command = hasRemoteImageCommand(text);
  const references = findActionProxyImageReferences(text);
  if (!command) {
    return (
      hasDynamicShellToken(text) &&
      references.some(isTaggedActionProxyImageReference)
    );
  }

  const commandVerb = /\b(?:create|pull|push|run|copy)\b/iu.exec(text);
  if (!commandVerb) return false;
  if (
    references.some((reference) => !isLocalActionProxyImageReference(reference))
  ) {
    return true;
  }
  if (
    /^(?:pull|push|copy)$/iu.test(commandVerb[0]) &&
    references.some((reference) => !isLoopbackImageReference(reference))
  ) {
    return true;
  }
  const commandArguments = text.slice(
    commandVerb.index + commandVerb[0].length,
  );
  return hasDynamicShellToken(commandArguments);
}

function findActionProxyImageReferences(text) {
  return (
    text.match(
      /(?:(?:[a-z0-9.-]+(?::\d+)?|\[::1\](?::\d+)?)\/)*action[._-]*proxy(?:\/action[._-]*proxy)?(?::[a-z0-9][a-z0-9._-]*)?/giu,
    ) ?? []
  );
}

function isLocalActionProxyImageReference(reference) {
  const normalized = reference.toLowerCase();
  return (
    isLoopbackImageReference(normalized) ||
    /^action[._-]*proxy(?:\/action[._-]*proxy)?:local$/u.test(normalized)
  );
}

function isTaggedActionProxyImageReference(reference) {
  return /:[a-z0-9][a-z0-9._-]*$/iu.test(reference);
}

function isLoopbackImageReference(reference) {
  return /^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?\//iu.test(reference);
}

function hasRemoteImageCommand(text) {
  return /\b(?:crane|crictl|oras)\b[^;&|]{0,160}\b(?:pull|push)\b|\bctr\b[^;&|]{0,160}\bimages?\s+(?:pull|push)\b|\b(?:docker|nerdctl|podman)\b[^;&|]{0,160}\b(?:create|pull|push|run)\b|\bskopeo\b[^;&|]{0,160}\bcopy\b/iu.test(
    text,
  );
}

function findActionProxyPackageSpecs(text) {
  const matches = [];
  for (const [kind, pattern] of [
    ["approved-scope", scopedActionProxyPackagePattern],
    ["lookalike-scope", lookalikeScopedActionProxyPackagePattern],
    ["unofficial-scope", unofficialScopedActionProxyPackagePattern],
    ["unscoped", unscopedActionProxyPackagePattern],
  ]) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      const packageName = match[1];
      if (packageName.toLowerCase().endsWith(".tgz")) continue;
      matches.push({
        index: match.index,
        kind,
        packageName,
        version: normalizePackageSpecVersion(match[2]),
      });
    }
  }
  return matches
    .sort((left, right) => left.index - right.index)
    .filter(
      (candidate, index, all) =>
        index === 0 ||
        candidate.index !== all[index - 1].index ||
        candidate.packageName !== all[index - 1].packageName,
    );
}

function isUnscopedRegistryPackageGuidance(text, packageSpec) {
  const beforePackage = text.slice(
    Math.max(0, packageSpec.index - 240),
    packageSpec.index,
  );
  if (
    /\b(?:npm|pnpm|yarn|bun)\b.{0,160}\b(?:view|info|show|install|i|add)\b[^;&|]{0,100}$/iu.test(
      beforePackage,
    )
  ) {
    return true;
  }
  // The package scanner has already identified the exact package token. Check
  // only the bounded suffix instead of matching the package name again with
  // nested separator quantifiers, which can backtrack exponentially.
  const claimSuffix = text.slice(
    packageSpec.index + packageSpec.packageName.length,
    packageSpec.index + packageSpec.packageName.length + 160,
  );
  return (
    /^(?:@[^\s`'"]+)?\s+(?:npm\s+)?package\b.{0,100}\b(?:npm|registry|published|available|installable)\b/iu.test(
      claimSuffix,
    ) ||
    /^(?:@[^\s`'"]+)?\b.{0,40}\b(?:is|are)\s+(?:published|available|installable)\b.{0,80}\b(?:npm|registry)\b/iu.test(
      claimSuffix,
    )
  );
}

function isRegistryExecutionGuidance(text, packageSpec) {
  const beforePackage = text.slice(
    Math.max(0, packageSpec.index - 240),
    packageSpec.index,
  );
  if (isWorkspaceFilterSpecifier(text, packageSpec)) return false;
  if (
    /\b(?:npx|pnpx|bunx)\b[^;&|]{0,180}$/iu.test(beforePackage) ||
    /\b(?:npm|bun)\b[^;&|]{0,120}\bx\b[^;&|]{0,120}$/iu.test(beforePackage) ||
    /\b(?:pnpm|yarn|bun)\b[^;&|]{0,160}\bdlx\b[^;&|]{0,120}$/iu.test(
      beforePackage,
    )
  ) {
    return true;
  }
  if (
    !/\b(?:npm|pnpm|yarn|bun)\b[^;&|]{0,160}\bexec\b[^;&|]{0,120}$/iu.test(
      beforePackage,
    )
  ) {
    return false;
  }
  return (
    packageSpec.kind !== "unscoped" ||
    packageSpec.version !== undefined ||
    /--package(?:=|\s+)\s*$/iu.test(beforePackage)
  );
}

function isShellPackageDistributionGuidance(text, packageSpec) {
  if (isWorkspaceFilterSpecifier(text, packageSpec)) return false;
  const beforePackage = text.slice(
    Math.max(0, packageSpec.index - 280),
    packageSpec.index,
  );
  return (
    /\bnpm\b[^;&|]{0,180}\b(?:add|i|in|ins|inst|insta|instal|install|isnt|isnta|isntal|isntall|update|up|upgrade|view|info|show)\b[^;&|]{0,120}$/iu.test(
      beforePackage,
    ) ||
    /\bpnpm\b[^;&|]{0,180}\b(?:add|i|install|update|up|upgrade|view|info|show)\b[^;&|]{0,120}$/iu.test(
      beforePackage,
    ) ||
    /\byarn\b[^;&|]{0,180}\b(?:add|install|update|up|upgrade|info)\b[^;&|]{0,120}$/iu.test(
      beforePackage,
    ) ||
    /\bbun\b[^;&|]{0,180}\b(?:add|i|install|update|view)\b[^;&|]{0,120}$/iu.test(
      beforePackage,
    ) ||
    isRegistryExecutionGuidance(text, packageSpec)
  );
}

function isWorkspaceFilterSpecifier(text, packageSpec) {
  const beforePackage = text.slice(
    Math.max(0, packageSpec.index - 80),
    packageSpec.index,
  );
  return /(?:^|\s)(?:--filter|-F|--workspace|-w)(?:=|\s+)\s*["']?(?:!|\.\.\.)?$/u.test(
    beforePackage,
  );
}

function isNpmPackageListLeadIn(text) {
  const label = text.replace(/^(?:#{1,6}\s+|[-*+]|\d+[.)])\s*/u, "").trim();
  if (
    /^(?:(?:available\s+)?on\s+)?npm(?:\s+(?:registry\s+)?packages?|\s+installation)?\s*:?$/iu.test(
      label,
    ) ||
    /^(?:package\s+)?registry(?:\s+packages?)?\s*:?$/iu.test(label)
  ) {
    return true;
  }
  if (!/\b(?:npm|package\s+registry|registry)\b/iu.test(label)) return false;
  if (
    !/\b(?:install(?:ation)?|add|fetch|download|published|available)\b/iu.test(
      label,
    )
  ) {
    return false;
  }
  return (
    /:\s*$/u.test(label) || /\b(?:packages?|dependencies)\.?\s*$/iu.test(label)
  );
}

function isNpmPackageTableLeadIn(text) {
  return (
    /\b(?:npm|package\s+registry|registry)\b/iu.test(text) &&
    /\b(?:packages?|install(?:ation)?|availability|source|registry|npm)\b/iu.test(
      text,
    )
  );
}

function inheritsNpmMarkdownContext(context, unit) {
  if (!context || unit.kind === "shell" || unit.kind === "code") return false;
  if (unit.kind === "heading") return false;
  if (context.kind === "adjacent") return true;
  if (context.kind === "list-block") return unit.kind === "list";
  if (context.kind === "nested-list") {
    return unit.kind === "list" && unit.listIndent > context.listIndent;
  }
  if (context.kind === "table-block") return unit.kind === "table";
  if (context.kind === "definition-block") return unit.kind === "definition";
  return false;
}

function nextNpmMarkdownContext({ context, inherited, text, unit }) {
  if (unit.kind !== "shell" && unit.kind !== "code") {
    const isLeadIn =
      isNpmPackageListLeadIn(text) ||
      (unit.kind === "table" && isNpmPackageTableLeadIn(text));
    if (isLeadIn) {
      if (unit.kind === "list") {
        return { kind: "nested-list", listIndent: unit.listIndent };
      }
      if (unit.kind === "table") return { kind: "table-block" };
      if (unit.kind === "definition") return { kind: "definition-block" };
      return { kind: "adjacent" };
    }
  }
  if (!inherited) return undefined;
  if (context.kind !== "adjacent") return context;
  if (unit.kind === "list") return { kind: "list-block" };
  if (unit.kind === "table") return { kind: "table-block" };
  if (unit.kind === "definition") return { kind: "definition-block" };
  return undefined;
}

function normalizePackageSpecVersion(version) {
  return version?.replace(/\.$/u, "");
}

function markdownLogicalUnits(body) {
  const units = [];
  const lines = body.split(/\r?\n/gu);
  let inFence = false;
  let shellFence = false;
  let currentFenceId;
  let nextFenceId = 1;
  let buffered = [];
  let bufferedLine = 1;
  let bufferedMetadata;

  const flush = () => {
    if (buffered.length === 0) return;
    const text = buffered
      .join("\n")
      .replace(/\\\s*\n\s*/gu, " ")
      .replace(/\s+/gu, " ")
      .trim();
    if (text) units.push({ line: bufferedLine, text, ...bufferedMetadata });
    buffered = [];
    bufferedMetadata = undefined;
  };
  const start = (line, lineNumber) => {
    if (buffered.length === 0) {
      bufferedLine = lineNumber;
      bufferedMetadata = inFence
        ? {
            kind: shellFence ? "shell" : "code",
            shellFenceId: shellFence ? currentFenceId : undefined,
          }
        : markdownUnitMetadata(line);
    }
    buffered.push(line);
  };

  for (const [index, line] of lines.entries()) {
    const lineNumber = index + 1;
    const fence = /^\s*```\s*([A-Za-z0-9_-]*)\s*$/u.exec(line);
    if (fence) {
      flush();
      if (inFence) {
        inFence = false;
        shellFence = false;
        currentFenceId = undefined;
      } else {
        inFence = true;
        shellFence = /^(?:ba|z)?sh$|^shell$|^console$/iu.test(fence[1]);
        currentFenceId = nextFenceId;
        nextFenceId += 1;
      }
      continue;
    }

    if (!line.trim()) {
      flush();
      continue;
    }

    if (inFence && shellFence) {
      const continuesPrevious =
        buffered.length > 0 &&
        (/\\\s*$/u.test(buffered.at(-1)) || /^\s+/u.test(line));
      if (buffered.length > 0 && !continuesPrevious) flush();
      start(line, lineNumber);
      continue;
    }

    const startsMarkdownBlock =
      !inFence &&
      /^\s*(?:#{1,6}\s+|[-*+]\s+|\d+[.)]\s+|:\s+|\|.*\|\s*$)/u.test(line);
    if (startsMarkdownBlock && buffered.length > 0) flush();
    start(line, lineNumber);
  }
  flush();
  return units;
}

function markdownUnitMetadata(line) {
  const list = /^(\s*)(?:[-*+]|\d+[.)])\s+/u.exec(line);
  if (list) {
    const listIndent = [...list[1]].reduce(
      (width, character) => width + (character === "\t" ? 4 : 1),
      0,
    );
    return { kind: "list", listIndent };
  }
  if (/^\s*#{1,6}\s+/u.test(line)) return { kind: "heading" };
  if (/^\s*\|.*\|\s*$/u.test(line)) return { kind: "table" };
  if (/^\s*:\s+/u.test(line)) return { kind: "definition" };
  return { kind: "prose" };
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
        sourceClosure: bootstrapMode ? "deferred" : "verified",
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
