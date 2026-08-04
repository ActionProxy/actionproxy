#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import readline from "node:readline";
import { ReadStream as TtyReadStream } from "node:tty";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";

export const FIRST_RUN_VERSION = "0.1.0";
export const STATE_VERSION = "actionproxy.first-run-state.v1";
export const PROFILE_MARKER_VERSION = "actionproxy.chatgpt-tunnel-profile.v3";
export const STATUS_SCHEMA_VERSION = "actionproxy.quickstart.v1";
export const DOCTOR_SCHEMA_VERSION = "actionproxy.first-run-doctor.v1";
export const INTEGRATION_STARTER_SCHEMA_VERSION =
  "actionproxy.integration-starter.v1";
export const TUNNEL_CLIENT_DISTRIBUTION_SCHEMA_VERSION =
  "actionproxy.tunnel-client-distribution.v1";
export const TUNNEL_CLIENT_RECEIPT_SCHEMA_VERSION =
  "actionproxy.tunnel-client-install.v1";
export const APPROVAL_TIMEOUT_MS = 300_000;
export const INTEGRATION_MODES = ["sdk", "mcp", "http"];
export const EXPECTED_DEMO_TOOLS = [
  "docs.search",
  "gmail.send_email",
  "dangerous.delete_customer",
];

export const CHECK_IDS = [
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
];

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultRepoRoot = path.resolve(scriptDirectory, "..");
const tunnelIdPattern = /^tunnel_[0-9a-f]{32}$/u;
const profilePattern = /^[A-Za-z0-9._-]{1,64}$/u;
const integrationOutputPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const projectPattern = /^actionproxy-first-run-[0-9a-f]{10}$/u;
const setupVersionPattern =
  /^v?(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){1,3}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const sessionPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const gitCommitPattern = /^[0-9a-f]{40}$/u;
const TUNNEL_CLIENT_ARCHIVE_MAX_BYTES = 16 * 1024 * 1024;
const TUNNEL_CLIENT_BINARY_MAX_BYTES = 32 * 1024 * 1024;
const TUNNEL_CLIENT_DOWNLOAD_TIMEOUT_MS = 30_000;
const TUNNEL_CLIENT_REDIRECT_LIMIT = 5;
const TUNNEL_CLIENT_REDIRECT_HOSTS = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
]);
const remediationCodes = new Set([
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
]);
const CHATGPT_ADMIN_ACCESS_REQUEST =
  "I’m testing ActionProxy locally with OpenAI Secure MCP Tunnel. Please allow developer mode in the target ChatGPT workspace, grant my Platform account Tunnels Read + Use, and associate the test tunnel with that workspace. The demonstration exposes only three simulated tools and connects no production systems.";
const OFFICIAL_OPENAI_URLS = Object.freeze({
  chatgptAppSettings: "https://chatgpt.com/plugins",
  developerMode:
    "https://help.openai.com/en/articles/12584461-developer-mode-apps-and-full-mcp-connectors-in-chatgpt-beta",
  runtimeApiKeys: "https://platform.openai.com/settings/organization/api-keys", // public-secret-scan: allow — canonical settings URL, not a credential
  secureMcpTunnel:
    "https://developers.openai.com/api/docs/guides/secure-mcp-tunnels",
  tunnelClientConfiguration:
    "https://github.com/openai/tunnel-client/blob/master/docs/configuration.md",
  tunnelClientReleases:
    "https://github.com/openai/tunnel-client/releases/latest",
  tunnelSettings: "https://platform.openai.com/settings/organization/tunnels",
});

export class FirstRunError extends Error {
  constructor(code, message, { remedy, retry, exitCode = 1 } = {}) {
    super(message);
    this.name = "FirstRunError";
    this.code = code;
    this.remedy = remedy;
    this.retry = retry;
    this.exitCode = exitCode;
  }
}

export function usage() {
  return [
    "ActionProxy First Run Concierge",
    "",
    "Usage:",
    "  ./actionproxy",
    "  ./actionproxy local [--port auto|N] [--no-open] [--verbose]",
    "  ./actionproxy chatgpt [--tunnel-id tunnel_...] [--profile NAME]",
    "                         [--port auto|N] [--no-open] [--verbose]",
    "  ./actionproxy doctor [--chatgpt] [--json]",
    "  ./actionproxy status [--json]",
    "  ./actionproxy integrate --mode sdk|mcp|http [--output NAME] [--json]",
    "  ./actionproxy tunnel-client install [--json]",
    "  ./actionproxy tunnel-client status [--json]",
    "  ./actionproxy tunnel-client remove [--json]",
    "  ./actionproxy stop",
    "  ./actionproxy reset",
    "  ./actionproxy --help",
    "  ./actionproxy --version",
    "",
    "Omit --tunnel-id in an interactive terminal for guided ChatGPT setup.",
    "The guided journeys use Docker. Source development remains available with `corepack pnpm dev`.",
    "",
  ].join("\n");
}

export function parseArguments(args) {
  if (args.length > 1 && args[1] === "--") {
    args = [args[0], ...args.slice(2)];
  }
  if (args.length === 0) return { command: undefined };
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h"))
    return { command: "help" };
  if (args.length === 1 && args[0] === "--version")
    return { command: "version" };

  const command = args[0];
  if (
    ![
      "local",
      "chatgpt",
      "doctor",
      "status",
      "integrate",
      "tunnel-client",
      "stop",
      "reset",
    ].includes(command)
  ) {
    throw usageError(`Unknown command: ${command ?? "(missing)"}`);
  }

  const parsed = {
    chatgpt: false,
    command,
    json: false,
    mode: undefined,
    noOpen: false,
    output: undefined,
    port: "auto",
    profile: undefined,
    tunnelId: undefined,
    tunnelClientAction: undefined,
    verbose: false,
  };
  let optionStart = 1;
  if (command === "tunnel-client") {
    const action = args[1];
    if (action === "--help" || action === "-h") return { command: "help" };
    if (!["install", "status", "remove"].includes(action)) {
      throw usageError(
        "tunnel-client requires one action: install, status, or remove.",
      );
    }
    parsed.tunnelClientAction = action;
    optionStart = 2;
  }
  const seen = new Set();
  for (let index = optionStart; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help" || argument === "-h") return { command: "help" };
    if (["--chatgpt", "--json", "--no-open", "--verbose"].includes(argument)) {
      if (seen.has(argument)) throw usageError(`Duplicate option: ${argument}`);
      seen.add(argument);
      const property = {
        "--chatgpt": "chatgpt",
        "--json": "json",
        "--no-open": "noOpen",
        "--verbose": "verbose",
      }[argument];
      parsed[property] = true;
      continue;
    }
    if (
      ["--mode", "--output", "--port", "--profile", "--tunnel-id"].includes(
        argument,
      )
    ) {
      if (
        seen.has(argument) ||
        index + 1 >= args.length ||
        args[index + 1].startsWith("--")
      ) {
        throw usageError(`Duplicate or incomplete option: ${argument}`);
      }
      seen.add(argument);
      const value = args[index + 1];
      index += 1;
      if (argument === "--port") parsed.port = parsePort(value);
      if (argument === "--profile") parsed.profile = validateProfile(value);
      if (argument === "--tunnel-id") parsed.tunnelId = validateTunnelId(value);
      if (argument === "--mode") parsed.mode = validateIntegrationMode(value);
      if (argument === "--output")
        parsed.output = validateIntegrationOutput(value);
      continue;
    }
    throw usageError(`Unknown option for ${command}: ${argument}`);
  }

  const allowed = {
    chatgpt: new Set([
      "--tunnel-id",
      "--profile",
      "--port",
      "--no-open",
      "--verbose",
    ]),
    doctor: new Set(["--chatgpt", "--json"]),
    integrate: new Set(["--mode", "--output", "--json"]),
    local: new Set(["--port", "--no-open", "--verbose"]),
    reset: new Set(),
    status: new Set(["--json"]),
    stop: new Set(),
    "tunnel-client": new Set(["--json"]),
  }[command];
  for (const option of seen) {
    if (!allowed.has(option))
      throw usageError(`${option} is not valid for ${command}.`);
  }
  return parsed;
}

export function parsePort(value) {
  if (value === undefined || value === "" || value === "auto") return "auto";
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    throw usageError("--port must be `auto` or an integer from 1024 to 65535.");
  }
  return port;
}

export function validateTunnelId(value) {
  if (!tunnelIdPattern.test(value ?? "")) {
    throw usageError(
      "--tunnel-id must be `tunnel_` followed by 32 lowercase hexadecimal characters.",
    );
  }
  return value;
}

export function validateProfile(value) {
  if (!profilePattern.test(value ?? "")) {
    throw usageError(
      "--profile must contain 1-64 letters, numbers, dots, underscores, or hyphens.",
    );
  }
  return value;
}

export function validateIntegrationMode(value) {
  if (!INTEGRATION_MODES.includes(value)) {
    throw usageError("--mode must be one of: sdk, mcp, or http.");
  }
  return value;
}

export function validateIntegrationOutput(value) {
  if (
    !integrationOutputPattern.test(value ?? "") ||
    value === "." ||
    value === ".."
  ) {
    throw usageError(
      "--output must be a new single-directory name using letters, numbers, dots, underscores, or hyphens.",
    );
  }
  return value;
}

export function createIntegrationStarter(
  mode,
  { actionProxySource = ".." } = {},
) {
  validateIntegrationMode(mode);
  const packageVersion = FIRST_RUN_VERSION;
  const normalizedActionProxySource = normalizeIntegrationSource(actionProxySource);
  const proofChecklist = integrationProofChecklist(mode);
  const packageSource = integrationPackageSource(mode, packageVersion);
  const files = integrationFiles(
    mode,
    packageVersion,
    proofChecklist,
    packageSource,
    normalizedActionProxySource,
  );
  const descriptor = {
    mode,
    packageSource,
    packageVersion,
    policyArtifact: {
      enforcement: "sample_only_not_loaded_by_first_run",
      path: "actionproxy.policy.sample.yaml",
    },
    proofChecklist,
    schemaArtifacts: {
      mcpWrapper: "schemas/actionproxy.mcp-wrapper.v1.schema.json",
      policy: "schemas/actionproxy.policy.v1.schema.json",
    },
    sourceBinding: {
      containsCredential: false,
      localOnly: true,
      path: "actionproxy-source.json",
      purpose: "locate_the_reviewed_local_source_checkout",
    },
    safeguards: [
      "Targets a loopback ActionProxy gateway by default.",
      "Uses only deterministic mock operations; no SaaS system is contacted.",
      "Never contains, reads, prints, or persists a credential.",
      "Never approves an action or bypasses ActionProxy policy.",
      "Uses a fresh idempotency key for each logical proof run.",
    ],
    schemaVersion: INTEGRATION_STARTER_SCHEMA_VERSION,
  };
  const descriptorFile = {
    content: `${JSON.stringify(descriptor, null, 2)}\n`,
    path: "actionproxy-integration.json",
  };
  return {
    ...descriptor,
    files: [...files, descriptorFile]
      .sort((left, right) => left.path.localeCompare(right.path))
      .map((file) => ({
        ...file,
        sha256: createHash("sha256").update(file.content).digest("hex"),
      })),
  };
}

export function writeIntegrationStarter(
  starter,
  outputName,
  { currentWorkingDirectory = process.cwd(), fileSystem = fs } = {},
) {
  validateIntegrationOutput(outputName);
  const parent = fileSystem.realpathSync(currentWorkingDirectory);
  const parentStats = fileSystem.lstatSync(parent);
  if (parentStats.isSymbolicLink?.() || !parentStats.isDirectory?.()) {
    throw operationalError(
      "INTEGRATION_OUTPUT_UNSAFE",
      "The current working directory is not a safe real directory.",
      "Change to the consumer project directory and retry.",
      `./actionproxy integrate --mode ${starter.mode} --output ${outputName}`,
    );
  }
  const target = path.join(parent, outputName);
  if (fileSystem.existsSync(target)) {
    throw operationalError(
      "INTEGRATION_OUTPUT_EXISTS",
      `Refusing to overwrite the existing ${outputName} entry.`,
      "Choose a new --output name; generated integrations never overwrite files.",
      `./actionproxy integrate --mode ${starter.mode} --output ${outputName}-new`,
    );
  }

  try {
    fileSystem.mkdirSync(target, { mode: 0o755 });
    for (const file of starter.files) {
      const segments = file.path.split("/");
      if (
        segments.length === 0 ||
        segments.some(
          (segment) =>
            !segment ||
            segment === "." ||
            segment === ".." ||
            segment.includes("\\"),
        )
      ) {
        throw new Error(`unsafe generated path: ${file.path}`);
      }
      const destination = path.join(target, ...segments);
      const relative = path.relative(target, destination);
      if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
        throw new Error(`unsafe generated path: ${file.path}`);
      }
      fileSystem.mkdirSync(path.dirname(destination), {
        mode: 0o755,
        recursive: true,
      });
      fileSystem.writeFileSync(destination, file.content, {
        flag: "wx",
        mode: file.mode ?? 0o644,
      });
    }
  } catch (error) {
    void error;
    throw operationalError(
      "INTEGRATION_WRITE_FAILED",
      `Could not finish the starter in ${outputName}.`,
      `Inspect the newly created ${outputName} directory, then rename or remove only that directory before retrying.`,
      `./actionproxy integrate --mode ${starter.mode} --output ${outputName}-new`,
    );
  }
  return outputName;
}

function integrationProofChecklist(mode) {
  const common = [
    {
      expectation: "The gateway health endpoint returns {ok:true} on loopback.",
      id: "gateway_health",
      verification: "automatic",
    },
  ];
  if (mode === "http") {
    return [
      ...common,
      {
        expectation: "A read-only mock call is allowed with exactly one execution attempt.",
        id: "allowed_once",
        verification: "automatic",
      },
      {
        expectation:
          "The mock email remains pending with zero execution attempts; this starter does not approve it.",
        id: "approval_holds_execution",
        verification: "automatic",
      },
      {
        expectation:
          "The destructive mock is denied with zero execution attempts.",
        id: "denied_without_dispatch",
        verification: "automatic",
      },
      {
        expectation: "GET /v1/audit/verify reports a valid local hash chain.",
        id: "audit_chain_valid",
        verification: "automatic",
      },
    ];
  }
  if (mode === "sdk") {
    return [
      ...common,
      {
        expectation:
          "The SDK waits for a human decision before its simulated callback can run.",
        id: "approval_holds_execution",
        verification: "manual_then_automatic",
      },
      {
        expectation:
          "After approval, the simulated callback runs once and one execution attempt is recorded.",
        id: "approved_once",
        verification: "automatic_after_approval",
      },
      {
        expectation: "GET /v1/audit/verify reports a valid local hash chain.",
        id: "audit_chain_valid",
        verification: "automatic_after_approval",
      },
    ];
  }
  return [
    {
      expectation:
        "MCP doctor discovers exactly docs.search, gmail.send_email, and dangerous.delete_customer from the bundled downstream mock.",
      id: "exact_tool_discovery",
      verification: "automatic",
    },
    {
      expectation:
        "Doctor does not prove policy, approval, execution, or audit; invoke the wrapper from an MCP host and complete those checks before replacing the mock.",
      id: "lifecycle_requires_host_call",
      verification: "manual_required",
    },
  ];
}

function integrationPackageSource(mode, packageVersion) {
  if (mode === "http") return null;
  const packageName =
    mode === "sdk" ? "@actionproxy/sdk-js" : "@actionproxy/mcp-wrapper";
  const archiveName =
    mode === "sdk"
      ? `actionproxy-sdk-js-${packageVersion}.tgz`
      : `actionproxy-mcp-wrapper-${packageVersion}.tgz`;
  return {
    archive: `vendor/${archiveName}`,
    availability: "local_source_tarball_required",
    kind: "local_tarball",
    packageName,
    registryInstallAvailable: false,
    version: packageVersion,
  };
}

function normalizeIntegrationSource(actionProxySource) {
  if (
    typeof actionProxySource !== "string" ||
    !actionProxySource ||
    /[\u0000-\u001f\u007f]/u.test(actionProxySource)
  ) {
    throw usageError(
      "The generated ActionProxy source binding must identify the reviewed checkout without control characters.",
    );
  }
  return actionProxySource;
}

function localPackagePreparerSource(packageSource) {
  return lines([
    "import { spawnSync } from 'node:child_process';",
    "import fs from 'node:fs';",
    "import path from 'node:path';",
    "import { fileURLToPath } from 'node:url';",
    "",
    `const expectedName = ${JSON.stringify(packageSource.packageName)};`,
    `const expectedVersion = ${JSON.stringify(packageSource.version)};`,
    `const archiveRelative = ${JSON.stringify(packageSource.archive)};`,
    "const starterRoot = path.dirname(fileURLToPath(import.meta.url));",
    "const binding = readJson(path.join(starterRoot, 'actionproxy-source.json'));",
    "if (binding?.schemaVersion !== 'actionproxy.integration-source.v1' || typeof binding?.sourcePath !== 'string' || !binding.sourcePath || /[\\u0000-\\u001f\\u007f]/u.test(binding.sourcePath)) {",
    "  fail('actionproxy-source.json is not a valid local source binding. Regenerate this starter from the reviewed checkout.');",
    "}",
    "const sourceRoot = fs.realpathSync(path.resolve(starterRoot, binding.sourcePath));",
    "const rootManifest = readJson(path.join(sourceRoot, 'package.json'));",
    "if (rootManifest.name !== 'actionproxy-monorepo' || rootManifest.version !== expectedVersion) {",
    "  fail(`Expected the reviewed ActionProxy ${expectedVersion} source checkout.`);",
    "}",
    "const packageDirectory = expectedName.endsWith('/sdk-js') ? 'sdk-js' : 'mcp-wrapper';",
    "const packageManifest = readJson(path.join(sourceRoot, 'packages', packageDirectory, 'package.json'));",
    "if (packageManifest.name !== expectedName || packageManifest.version !== expectedVersion || packageManifest.license !== 'Apache-2.0') {",
    "  fail(`Unexpected ${expectedName} package identity.`);",
    "}",
    "const vendorRoot = path.join(starterRoot, 'vendor');",
    "fs.mkdirSync(vendorRoot, { mode: 0o755, recursive: true });",
    "const archivePath = path.join(starterRoot, ...archiveRelative.split('/'));",
    "const temporaryPath = `${archivePath}.partial-${process.pid}`;",
    "try {",
    "  run('corepack', ['pnpm', 'install', '--frozen-lockfile'], sourceRoot);",
    "  run('corepack', ['pnpm', '--filter', expectedName, 'pack', '--out', temporaryPath, '--json'], sourceRoot);",
    "  const stats = fs.lstatSync(temporaryPath);",
    "  if (!stats.isFile() || stats.isSymbolicLink() || stats.size === 0) fail('Package output was not a nonempty regular file.');",
    "  fs.renameSync(temporaryPath, archivePath);",
    "} finally {",
    "  fs.rmSync(temporaryPath, { force: true });",
    "}",
    "process.stdout.write(`${JSON.stringify({ archive: archiveRelative, name: expectedName, ok: true, version: expectedVersion })}\\n`);",
    "",
    "function readJson(filePath) {",
    "  return JSON.parse(fs.readFileSync(filePath, 'utf8'));",
    "}",
    "function run(command, commandArgs, cwd) {",
    "  const executable = process.platform === 'win32' ? `${command}.cmd` : command;",
    "  const result = spawnSync(executable, commandArgs, { cwd, encoding: 'utf8', env: { ...process.env, npm_config_audit: 'false', npm_config_fund: 'false' }, stdio: ['ignore', 'inherit', 'inherit'] });",
    "  if (result.error || result.status !== 0) fail(`${command} failed with exit ${String(result.status)}.`);",
    "}",
    "function fail(message) {",
    "  process.stderr.write(`${message}\\n`);",
    "  process.exit(1);",
    "}",
  ]);
}

function liveGatewayRunnerSource() {
  return lines([
    "import { spawnSync } from 'node:child_process';",
    "import fs from 'node:fs';",
    "import path from 'node:path';",
    "import { fileURLToPath } from 'node:url';",
    "",
    "const commandArgs = process.argv.slice(2);",
    "const starterRoot = path.dirname(fileURLToPath(import.meta.url));",
    "const binding = readJson(path.join(starterRoot, 'actionproxy-source.json'));",
    "if (binding?.schemaVersion !== 'actionproxy.integration-source.v1' || typeof binding?.sourcePath !== 'string' || !binding.sourcePath || /[\\u0000-\\u001f\\u007f]/u.test(binding.sourcePath)) {",
    "  fail('actionproxy-source.json is not a valid local source binding. Regenerate this starter from the reviewed checkout.');",
    "}",
    "const sourceRoot = fs.realpathSync(path.resolve(starterRoot, binding.sourcePath));",
    "const actionProxy = fs.realpathSync(path.join(sourceRoot, 'actionproxy'));",
    "if (commandArgs.length === 1 && commandArgs[0] === '--start') {",
    "  const start = spawnSync(actionProxy, ['local', '--no-open'], { env: process.env, stdio: 'inherit' });",
    "  process.exit(start.error ? 1 : (start.status ?? 1));",
    "}",
    "if (commandArgs.length === 0) fail('Usage: node run-with-live-gateway.mjs --start | <command> [arguments...]');",
    "const status = spawnSync(actionProxy, ['status', '--json'], { encoding: 'utf8', env: process.env, stdio: ['ignore', 'pipe', 'inherit'] });",
    "if (status.error || status.status !== 0) fail('Could not read live ActionProxy status. Run the generated start command, then retry.');",
    "let report;",
    "try { report = JSON.parse(status.stdout); } catch { fail('ActionProxy status did not return its stable JSON contract.'); }",
    "const port = report?.gateway?.port;",
    "if (report?.schemaVersion !== 'actionproxy.first-run-status.v1' || report?.projectRunning !== true || report?.gateway?.healthy !== true || report?.gateway?.loopbackOnly !== true || !Number.isInteger(port) || port < 1024 || port > 65535) {",
    "  fail('The remembered ActionProxy gateway is not live and loopback-only. Start it from the reviewed checkout, then retry.');",
    "}",
    "const command = commandArgs[0];",
    "const executable = process.platform === 'win32' && ['npm', 'npx', 'corepack'].includes(command) ? `${command}.cmd` : command;",
    "const child = spawnSync(executable, commandArgs.slice(1), { encoding: 'utf8', env: { ...process.env, ACTIONPROXY_BASE_URL: `http://127.0.0.1:${port}` }, stdio: 'inherit' });",
    "if (child.error || child.status !== 0) process.exit(child.status ?? 1);",
    "",
    "function readJson(filePath) {",
    "  return JSON.parse(fs.readFileSync(filePath, 'utf8'));",
    "}",
    "",
    "function fail(message) {",
    "  process.stderr.write(`${message}\\n`);",
    "  process.exit(1);",
    "}",
  ]);
}

function integrationFiles(
  mode,
  packageVersion,
  proofChecklist,
  packageSource,
  actionProxySource,
) {
  const policy = integrationPolicy();
  const readme = integrationReadme(mode, proofChecklist, packageSource);
  const sourceBinding = {
    content: jsonFile({
      schemaVersion: "actionproxy.integration-source.v1",
      sourcePath: actionProxySource,
    }),
    mode: 0o600,
    path: "actionproxy-source.json",
  };
  const localArtifactsIgnore = {
    content: lines([
      "actionproxy-source.json",
      "node_modules/",
      "vendor/*.tgz",
    ]),
    path: ".gitignore",
  };
  if (mode === "sdk") {
    return [
      localArtifactsIgnore,
      { content: policy, path: "actionproxy.policy.sample.yaml" },
      {
        content: liveGatewayRunnerSource(),
        path: "run-with-live-gateway.mjs",
      },
      {
        content: localPackagePreparerSource(packageSource),
        path: "prepare-local-package.mjs",
      },
      {
        content: jsonFile({
          dependencies: {
            "@actionproxy/sdk-js": `file:${packageSource.archive}`,
          },
          engines: { node: ">=22 <25" },
          name: "actionproxy-sdk-starter",
          private: true,
          scripts: { proof: "node src/governed-operation.mjs" },
          type: "module",
          version: "0.0.0",
        }),
        path: "package.json",
      },
      { content: readme, path: "README.md" },
      sourceBinding,
      { content: sdkStarterSource(), path: "src/governed-operation.mjs" },
    ];
  }
  if (mode === "mcp") {
    return [
      localArtifactsIgnore,
      { content: mcpStarterConfig(), path: "actionproxy.mcp.yaml" },
      { content: policy, path: "actionproxy.policy.sample.yaml" },
      { content: mcpDemoServerSource(), path: "demo-mcp-server.mjs" },
      {
        content: liveGatewayRunnerSource(),
        path: "run-with-live-gateway.mjs",
      },
      {
        content: localPackagePreparerSource(packageSource),
        path: "prepare-local-package.mjs",
      },
      {
        content: jsonFile({
          dependencies: {
            "@actionproxy/mcp-wrapper": `file:${packageSource.archive}`,
          },
          engines: { node: ">=22 <25" },
          name: "actionproxy-mcp-starter",
          private: true,
          scripts: {
            doctor:
              "actionproxy-mcp doctor --config actionproxy.mcp.yaml --discover --json",
            wrap: "actionproxy-mcp wrap --config actionproxy.mcp.yaml",
          },
          type: "module",
          version: "0.0.0",
        }),
        path: "package.json",
      },
      { content: readme, path: "README.md" },
      sourceBinding,
    ];
  }
  return [
    localArtifactsIgnore,
    { content: policy, path: "actionproxy.policy.sample.yaml" },
    {
      content: liveGatewayRunnerSource(),
      path: "run-with-live-gateway.mjs",
    },
    {
      content: jsonFile({
        engines: { node: ">=22 <25" },
        name: "actionproxy-http-starter",
        private: true,
        scripts: { proof: "node proof.mjs" },
        type: "module",
        version: "0.0.0",
      }),
      path: "package.json",
    },
    { content: httpStarterSource(), path: "proof.mjs" },
    { content: readme, path: "README.md" },
    sourceBinding,
  ];
}

function integrationPolicy() {
  return lines([
    "# Schema: schemas/actionproxy.policy.v1.schema.json in the ActionProxy release.",
    "version: 1",
    "default:",
    "  approval: required",
    "  risk: unknown",
    "  reason: Unknown tools require human approval by default.",
    "tools:",
    "  docs.search:",
    "    approval: never",
    "    risk: read_only",
    "    resultSource:",
    "      integrity: organization_managed",
    "      sourceId: starter-docs",
    "    reason: This deterministic local read is safe to run automatically.",
    "  gmail.send_email:",
    "    approval: required",
    "    risk: external_communication",
    "    resultSource: none",
    "    reason: External communication requires a human decision.",
    "  dangerous.delete_customer:",
    "    approval: deny",
    "    risk: destructive",
    "    resultSource: none",
    "    reason: Destructive customer deletion is blocked.",
  ]);
}

function integrationReadme(mode, proofChecklist, packageSource) {
  const packagePreparation = packageSource
    ? [
        `Build the unpublished \`${packageSource.packageName}@${packageSource.version}\` candidate from the reviewed ActionProxy source checkout:`,
        "",
        "```bash",
        "node prepare-local-package.mjs",
        "npm install",
        "```",
        "",
        `This creates only \`${packageSource.archive}\` in this starter before npm installs it. It does not claim or probe npm registry availability.`,
      ]
    : ["This HTTP starter has no runtime package dependency."];
  const modeInstructions = {
    http: [
      "This starter uses Node's built-in `fetch`; it adds no runtime dependency.",
      "Run `node run-with-live-gateway.mjs npm run proof` to submit the allow, approval, and deny fixtures against the verified live port.",
      "The script never approves the pending email and never calls a real downstream system.",
    ],
    mcp: [
      "Run `node run-with-live-gateway.mjs npm run doctor` to verify exact downstream discovery.",
      "Use `node run-with-live-gateway.mjs npm run wrap` as the stdio MCP command in an MCP-capable agent host.",
      "The included downstream server exposes only three deterministic mocks and performs no real effects. Doctor alone does not prove a governed call.",
    ],
    sdk: [
      "Run `node run-with-live-gateway.mjs npm run proof`.",
      "Approve the pending mock email in ActionProxy; only then does the simulated callback run.",
      "Replace the simulated callback only after the full proof checklist passes.",
    ],
  }[mode];
  return lines([
    `# ActionProxy ${mode.toUpperCase()} integration starter`,
    "",
    "Generated by `./actionproxy integrate`. It is deliberately local-only and credential-free.",
    "",
    "## Before running",
    "",
    "1. `actionproxy-source.json` is a private local binding to the reviewed checkout. It contains a filesystem path and no credential. The machine-readable result lists only its filename and digest, not its contents or source path. `.gitignore` excludes the binding, local tarballs, and installed dependencies; do not commit them.",
    "2. Run `node run-with-live-gateway.mjs --start` if the local gateway is not already running.",
    "3. The runner reads live `./actionproxy status --json`, requires a healthy loopback-only gateway, and supplies its Docker-assigned port only to the child process.",
    "4. `actionproxy.policy.sample.yaml` is a sample only. `./actionproxy local` continues to enforce and verify its bundled deterministic demo policy; it does not load this generated file.",
    `5. In this directory, follow the ${mode.toUpperCase()} steps below.`,
    "",
    "## Package source",
    "",
    ...packagePreparation,
    "",
    "## Mode steps",
    "",
    ...modeInstructions.map((entry, index) => `${index + 1}. ${entry}`),
    "",
    "The starter accepts only `http://127.0.0.1` or `http://localhost` as its gateway. Production authentication and deployment are intentionally out of scope for this proof.",
    "",
    "## Proof checklist",
    "",
    ...proofChecklist.map((item) =>
      `- [ ] **${item.id}** (${item.verification}) — ${item.expectation}`,
    ),
    "",
    "Inspect the console and `GET /v1/audit`; do not infer execution from an approval record alone. A failed or unknown downstream outcome must be reconciled before retrying.",
  ]);
}

function sdkStarterSource() {
  return lines([
    "import { randomUUID } from 'node:crypto';",
    "import { ActionProxyClient, runExternalAction } from '@actionproxy/sdk-js';",
    "",
    "const baseUrl = localGatewayUrl(process.env.ACTIONPROXY_BASE_URL ?? 'http://127.0.0.1:8787');",
    "const client = new ActionProxyClient({ baseUrl });",
    "const health = await getJson('/health');",
    "if (health.ok !== true) throw new Error('ActionProxy health check did not return {ok:true}.');",
    "let callbackCalls = 0;",
    "",
    "console.log('Submitting one simulated external email. Approve it in ActionProxy to continue.');",
    "const result = await runExternalAction({",
    "  action: {",
    "    executionMode: 'external_grant',",
    "    operation: { kind: 'external_send', name: 'starter.fake_mailer.send' },",
    "    protocol: 'custom',",
    "    source: { name: 'actionproxy-sdk-starter', type: 'custom' },",
    "  },",
    "  agentId: 'actionproxy-sdk-starter',",
    "  client,",
    "  execute: async (input, context) => {",
    "    callbackCalls += 1;",
    "    if (callbackCalls !== 1) throw new Error('The simulated callback was invoked more than once.');",
    "    return {",
    "      delivered: false,",
    "      grantId: context.consumed.grant.id,",
    "      note: 'Simulation only. No email was sent.',",
    "      proposedRecipient: input.to,",
    "    };",
    "  },",
    "  idempotencyKey: `sdk-starter-${randomUUID()}` ,",
    "  input: {",
    "    body: 'Your request is ready.',",
    "    subject: 'Refund update',",
    "    to: 'customer@example.com',",
    "  },",
    "  reason: 'Prove that ActionProxy holds an external action for approval.',",
    "  requestedBy: 'sdk-starter@example.local',",
    "  toolName: 'gmail.send_email',",
    "  wait: { intervalMs: 1000, timeoutMs: 300000 },",
    "});",
    "",
    "const attempts = await client.listExecutionAttempts(result.toolCall.id);",
    "const auditVerification = await getJson('/v1/audit/verify');",
    "if (callbackCalls !== 1 || attempts.length !== 1) throw new Error(`Expected one callback and one execution attempt; received ${callbackCalls} and ${attempts.length}.`);",
    "if (result.toolCall.status !== 'executed') throw new Error(`Expected executed status; received ${result.toolCall.status}.`);",
    "if (auditVerification.valid !== true) throw new Error('The local audit hash chain did not verify.');",
    "",
    "console.log(JSON.stringify({",
    "  auditChainValid: true,",
    "  callbackCalls,",
    "  delivered: result.result.delivered,",
    "  executionAttempts: attempts.length,",
    "  status: result.toolCall.status,",
    "  toolCallId: result.toolCall.id,",
    "}, null, 2));",
    "",
    "function localGatewayUrl(value) {",
    "  const url = new URL(value);",
    "  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname)) {",
    "    throw new Error('This starter accepts only a loopback HTTP ActionProxy URL.');",
    "  }",
    "  return url.toString().replace(/\\/$/u, '');",
    "}",
    "",
    "async function getJson(pathname) {",
    "  const response = await fetch(`${baseUrl}${pathname}`);",
    "  if (!response.ok) throw new Error(`${pathname} returned HTTP ${response.status}.`);",
    "  return response.json();",
    "}",
  ]);
}

function mcpStarterConfig() {
  return lines([
    "# Schema: schemas/actionproxy.mcp-wrapper.v1.schema.json in the ActionProxy release.",
    "actionproxy:",
    "  baseUrl: http://127.0.0.1:8787",
    "  requestedBy: mcp-starter@example.local",
    "  agentId: actionproxy-mcp-starter",
    "  approvalPollIntervalMs: 1000",
    "  approvalTimeoutMs: 300000",
    "  cancelPendingOnAbort: true",
    "servers:",
    "  starter-demo:",
    "    command: node",
    '    args: ["./demo-mcp-server.mjs"]',
    "    stdioFraming: newline",
    "policies:",
    "  docs.search:",
    "    approval: never",
    "  gmail.send_email:",
    "    approval: required",
    "  dangerous.delete_customer:",
    "    approval: deny",
  ]);
}

function mcpDemoServerSource() {
  return lines([
    "#!/usr/bin/env node",
    "import readline from 'node:readline';",
    "",
    "const tools = [",
    "  { name: 'docs.search', description: 'Search deterministic demo docs.', inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] } },",
    "  { name: 'gmail.send_email', description: 'Propose a simulated email.', inputSchema: { type: 'object', properties: { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' } }, required: ['to', 'subject', 'body'] } },",
    "  { name: 'dangerous.delete_customer', description: 'A destructive policy-denial fixture.', inputSchema: { type: 'object', properties: { customerId: { type: 'string' } }, required: ['customerId'] } },",
    "];",
    "",
    "const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });",
    "for await (const line of input) {",
    "  if (!line.trim()) continue;",
    "  const request = JSON.parse(line);",
    "  if (request.method?.startsWith('notifications/')) continue;",
    "  if (request.method === 'initialize') {",
    "    send({ id: request.id, jsonrpc: '2.0', result: { capabilities: { tools: {} }, protocolVersion: '2025-06-18', serverInfo: { name: 'actionproxy-safe-starter', version: '0.1.0' } } });",
    "  } else if (request.method === 'tools/list') {",
    "    send({ id: request.id, jsonrpc: '2.0', result: { tools } });",
    "  } else if (request.method === 'tools/call') {",
    "    send({ id: request.id, jsonrpc: '2.0', result: { content: [{ type: 'text', text: JSON.stringify({ arguments: request.params?.arguments ?? {}, note: 'Simulation only. No external system was changed.', tool: request.params?.name ?? null }) }] } });",
    "  } else {",
    "    send({ error: { code: -32601, message: 'Unsupported method' }, id: request.id, jsonrpc: '2.0' });",
    "  }",
    "}",
    "",
    "function send(message) {",
    "  process.stdout.write(`${JSON.stringify(message)}\\n`);",
    "}",
  ]);
}

function httpStarterSource() {
  return lines([
    "import { randomUUID } from 'node:crypto';",
    "",
    "const baseUrl = localGatewayUrl(process.env.ACTIONPROXY_BASE_URL ?? 'http://127.0.0.1:8787');",
    "const health = await getJson('/health');",
    "if (health.ok !== true) throw new Error('ActionProxy health check did not return {ok:true}.');",
    "const proposals = [",
    "  { toolName: 'docs.search', input: { query: 'refund policy' }, expected: 'executed' },",
    "  { toolName: 'gmail.send_email', input: { to: 'customer@example.com', subject: 'Refund update', body: 'Your request is ready.' }, expected: 'pending_approval' },",
    "  { toolName: 'dangerous.delete_customer', input: { customerId: 'cus_123' }, expected: 'blocked' },",
    "];",
    "",
    "const results = [];",
    "for (const proposal of proposals) {",
    "  const response = await fetch(`${baseUrl}/v1/tool-calls`, {",
    "    body: JSON.stringify({",
    "      agentId: 'actionproxy-http-starter',",
    "      input: proposal.input,",
    "      reason: 'Deterministic local integration proof.',",
    "      requestedBy: 'http-starter@example.local',",
    "      toolName: proposal.toolName,",
    "    }),",
    "    headers: { 'content-type': 'application/json', 'idempotency-key': `http-starter-${randomUUID()}` },",
    "    method: 'POST',",
    "  });",
    "  const body = await response.json();",
    "  if (!response.ok) throw new Error(`ActionProxy returned HTTP ${response.status}.`);",
    "  if (body.status !== proposal.expected) throw new Error(`${proposal.toolName}: expected ${proposal.expected}, received ${body.status}.`);",
    "  results.push({ approvalId: body.approval?.id, status: body.status, toolCallId: body.id, toolName: proposal.toolName });",
    "}",
    "",
    "for (const result of results) {",
    "  const { attempts } = await getJson(`/v1/tool-calls/${encodeURIComponent(result.toolCallId)}/execution-attempts`);",
    "  const expectedAttempts = result.toolName === 'docs.search' ? 1 : 0;",
    "  if (!Array.isArray(attempts) || attempts.length !== expectedAttempts) {",
    "    throw new Error(`${result.toolName}: expected ${expectedAttempts} execution attempts, received ${Array.isArray(attempts) ? attempts.length : 'an invalid response'}.`);",
    "  }",
    "  result.executionAttempts = attempts.length;",
    "}",
    "const auditVerification = await getJson('/v1/audit/verify');",
    "if (auditVerification.valid !== true) throw new Error('The local audit hash chain did not verify.');",
    "",
    "console.log(JSON.stringify({",
    "  auditChainValid: true,",
    "  note: 'The email is still pending; this script never approves it.',",
    "  results,",
    "  schemaVersion: 'actionproxy.http-starter-proof.v1',",
    "}, null, 2));",
    "",
    "function localGatewayUrl(value) {",
    "  const url = new URL(value);",
    "  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname)) {",
    "    throw new Error('This starter accepts only a loopback HTTP ActionProxy URL.');",
    "  }",
    "  return url.toString().replace(/\\/$/u, '');",
    "}",
    "",
    "async function getJson(pathname) {",
    "  const response = await fetch(`${baseUrl}${pathname}`);",
    "  if (!response.ok) throw new Error(`${pathname} returned HTTP ${response.status}.`);",
    "  return response.json();",
    "}",
  ]);
}

function jsonFile(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function shellQuotePosix(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

function lines(values) {
  return `${values.join("\n")}\n`;
}

export function checkoutIdentity(repoRoot, fileSystem = fs) {
  const realRoot = fileSystem.realpathSync(repoRoot);
  const checkoutId = createHash("sha256")
    .update(realRoot)
    .digest("hex")
    .slice(0, 10);
  return {
    checkoutId,
    projectName: `actionproxy-first-run-${checkoutId}`,
    realRoot,
  };
}

export function tunnelClientAsset(platform, architecture) {
  const normalizedArchitecture =
    architecture === "x64" ? "amd64" : architecture;
  if (
    !["darwin", "linux", "windows"].includes(platform) ||
    !["amd64", "arm64"].includes(normalizedArchitecture)
  ) {
    return undefined;
  }
  return `tunnel-client-v<VERSION>-${platform}-${normalizedArchitecture}.zip`;
}

function tunnelClientPlatformKey(platform, architecture) {
  const normalizedArchitecture =
    architecture === "x64" ? "amd64" : architecture;
  return `${platform}-${normalizedArchitecture}`;
}

export function validateTunnelClientDistribution(value) {
  const topLevelKeys = [
    "archiveEntry",
    "assets",
    "expectedVersion",
    "licenseUrl",
    "releaseCommit",
    "releaseId",
    "releaseTag",
    "releaseUrl",
    "repository",
    "reviewedAt",
    "schemaVersion",
  ];
  const actualTopLevelKeys = Object.keys(value ?? {}).sort();
  const reviewedDate = new Date(`${value?.reviewedAt}T00:00:00.000Z`);
  if (
    actualTopLevelKeys.length !== topLevelKeys.length ||
    actualTopLevelKeys.some(
      (key, index) => key !== [...topLevelKeys].sort()[index],
    ) ||
    value.schemaVersion !== TUNNEL_CLIENT_DISTRIBUTION_SCHEMA_VERSION ||
    value.repository !== "openai/tunnel-client" ||
    !/^v(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}$/u.test(
      value.releaseTag ?? "",
    ) ||
    !gitCommitPattern.test(value.releaseCommit ?? "") ||
    !Number.isSafeInteger(value.releaseId) ||
    value.releaseId <= 0 ||
    value.releaseUrl !==
      `https://github.com/openai/tunnel-client/releases/tag/${value.releaseTag}` ||
    value.licenseUrl !==
      `https://github.com/openai/tunnel-client/blob/${value.releaseTag}/LICENSE` ||
    value.expectedVersion !==
      `${value.releaseTag.slice(1)}+${value.releaseCommit}` ||
    value.archiveEntry !== "tunnel-client" ||
    !/^\d{4}-\d{2}-\d{2}$/u.test(value.reviewedAt ?? "") ||
    Number.isNaN(reviewedDate.getTime()) ||
    reviewedDate.toISOString().slice(0, 10) !== value.reviewedAt
  ) {
    throw operationalError(
      "TUNNEL_CLIENT_DISTRIBUTION_INVALID",
      "The bundled tunnel-client distribution record is invalid.",
      "Restore examples/chatgpt-tunnel/tunnel-client-distribution.json from this ActionProxy release.",
      "./actionproxy tunnel-client status",
    );
  }

  const expectedAssetKeys = ["darwin-amd64", "darwin-arm64"];
  const actualAssetKeys = Object.keys(value.assets ?? {}).sort();
  if (
    actualAssetKeys.length !== expectedAssetKeys.length ||
    actualAssetKeys.some((key, index) => key !== expectedAssetKeys[index])
  ) {
    throw operationalError(
      "TUNNEL_CLIENT_DISTRIBUTION_INVALID",
      "The bundled tunnel-client distribution asset list is invalid.",
      "Restore the reviewed distribution record from this ActionProxy release.",
      "./actionproxy tunnel-client status",
    );
  }
  const assetKeys = [
    "archiveSha256",
    "archiveSize",
    "assetId",
    "binarySha256",
    "binarySize",
    "name",
    "url",
  ];
  for (const platformKey of expectedAssetKeys) {
    const asset = value.assets[platformKey];
    const expectedName = `tunnel-client-${value.releaseTag}-${platformKey}.zip`;
    const expectedUrl =
      `https://github.com/openai/tunnel-client/releases/download/` +
      `${value.releaseTag}/${expectedName}`;
    const keys = Object.keys(asset ?? {}).sort();
    if (
      keys.length !== assetKeys.length ||
      keys.some((key, index) => key !== [...assetKeys].sort()[index]) ||
      !Number.isSafeInteger(asset.assetId) ||
      asset.assetId <= 0 ||
      asset.name !== expectedName ||
      asset.url !== expectedUrl ||
      !Number.isSafeInteger(asset.archiveSize) ||
      asset.archiveSize < 1 ||
      asset.archiveSize > TUNNEL_CLIENT_ARCHIVE_MAX_BYTES ||
      !sha256Pattern.test(asset.archiveSha256 ?? "") ||
      !Number.isSafeInteger(asset.binarySize) ||
      asset.binarySize < 1 ||
      asset.binarySize > TUNNEL_CLIENT_BINARY_MAX_BYTES ||
      !sha256Pattern.test(asset.binarySha256 ?? "")
    ) {
      throw operationalError(
        "TUNNEL_CLIENT_DISTRIBUTION_INVALID",
        `The bundled ${platformKey} tunnel-client asset record is invalid.`,
        "Restore the reviewed distribution record from this ActionProxy release.",
        "./actionproxy tunnel-client status",
      );
    }
  }
  return value;
}

export function readTunnelClientDistribution(fileSystem, repoRoot) {
  const filename = path.join(
    repoRoot,
    "examples",
    "chatgpt-tunnel",
    "tunnel-client-distribution.json",
  );
  try {
    return validateTunnelClientDistribution(
      JSON.parse(fileSystem.readFileSync(filename, "utf8")),
    );
  } catch (error) {
    if (
      error instanceof FirstRunError &&
      error.code === "TUNNEL_CLIENT_DISTRIBUTION_INVALID"
    ) {
      throw error;
    }
    throw operationalError(
      "TUNNEL_CLIENT_DISTRIBUTION_INVALID",
      "The bundled tunnel-client distribution record is missing or unreadable.",
      "Restore examples/chatgpt-tunnel/tunnel-client-distribution.json from this ActionProxy release.",
      "./actionproxy tunnel-client status",
    );
  }
}

export function firstRunPaths(repoRoot) {
  const root = path.join(repoRoot, ".actionproxy", "first-run");
  return {
    lockDirectory: path.join(root, "active.lock"),
    lockOwner: path.join(root, "active.lock", "owner.json"),
    root,
    state: path.join(root, "state.json"),
  };
}

export function tunnelClientInstallPaths(repoRoot) {
  const directory = path.join(repoRoot, ".actionproxy", "bin");
  return {
    binary: path.join(directory, "tunnel-client"),
    directory,
    receipt: path.join(directory, "tunnel-client.actionproxy.json"),
  };
}

export function profileMarkerPath(repoRoot, profile) {
  return path.join(
    repoRoot,
    ".actionproxy",
    "chatgpt-tunnel",
    `${profile}.json`,
  );
}

export function validateDoctorReport(raw) {
  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    throw operationalError(
      "TOOL_DISCOVERY_INVALID",
      "ActionProxy MCP discovery returned invalid JSON.",
      "Rebuild the bundled Docker image.",
      "./actionproxy local",
    );
  }
  const server = report.servers?.[0];
  const tools =
    server?.discovery?.status === "verified"
      ? [...(server.discovery.tools ?? [])].sort()
      : [];
  const expectedTools = [...EXPECTED_DEMO_TOOLS].sort();
  if (
    report.version !== "actionproxy.tool-plane-report.v1" ||
    report.coverage !== "configured_mcp_wrapper" ||
    report.mode !== "discover" ||
    report.ok !== true ||
    report.servers?.length !== 1 ||
    server?.name !== "chatgpt-tunnel-demo" ||
    server?.discovery?.toolCount !== EXPECTED_DEMO_TOOLS.length ||
    JSON.stringify(tools) !== JSON.stringify(expectedTools)
  ) {
    throw operationalError(
      "TOOL_DISCOVERY_MISMATCH",
      `MCP discovery must expose exactly: ${EXPECTED_DEMO_TOOLS.join(", ")}.`,
      "Rebuild the bundled image and do not continue with an unexpected tool set.",
      "./actionproxy local",
    );
  }
  return report;
}

export function validRuntimeKey(value) {
  if (
    !value ||
    value.trim() !== value ||
    value.length > 8192 ||
    /\p{Cc}/u.test(value)
  ) {
    throw operationalError(
      "RUNTIME_KEY_INVALID",
      "The runtime API key must be nonempty, unpadded, at most 8192 characters, and contain no control characters.",
      "Create or copy a runtime API key from OpenAI Platform and try again.",
      "./actionproxy chatgpt",
    );
  }
  return value;
}

function consumeLegacyRuntimeKeyFd(fileSystem, rawDescriptor) {
  if (rawDescriptor === undefined) return undefined;
  const descriptor = Number(rawDescriptor);
  if (String(rawDescriptor) !== "9" || descriptor !== 9) {
    throw operationalError(
      "LEGACY_RUNTIME_KEY_HANDOFF_INVALID",
      "The private legacy runtime-key handoff is invalid.",
      "Remove ACTIONPROXY_LEGACY_RUNTIME_KEY_FD and rerun through ./actionproxy.",
      "./actionproxy chatgpt",
    );
  }

  try {
    const stats = fileSystem.fstatSync(descriptor);
    const expectedUid = process.getuid?.();
    if (
      !stats.isFile?.() ||
      (expectedUid !== undefined && stats.uid !== expectedUid) ||
      (stats.mode & 0o777) !== 0o600 ||
      stats.size > 8192
    ) {
      throw new Error("unsafe private handoff descriptor");
    }
    return fileSystem.readFileSync(descriptor, "utf8");
  } catch {
    throw operationalError(
      "LEGACY_RUNTIME_KEY_HANDOFF_INVALID",
      "The private legacy runtime-key handoff failed ownership, mode, or size validation.",
      "Remove ACTIONPROXY_LEGACY_RUNTIME_KEY_FD and rerun through ./actionproxy.",
      "./actionproxy chatgpt",
    );
  } finally {
    try {
      fileSystem.closeSync(descriptor);
    } catch {
      /* the descriptor may already have been closed by a failed read */
    }
  }
}

function readCallerRuntimeKeyFile(fileSystem, rawFilename) {
  const filename = String(rawFilename);
  let stats;
  try {
    if (
      filename !== filename.trim() ||
      !path.isAbsolute(filename) ||
      /[\r\n\u0000]/u.test(filename)
    ) {
      throw new Error("invalid path");
    }
    stats = fileSystem.lstatSync(filename);
    const expectedUid = process.getuid?.();
    if (
      stats.isSymbolicLink?.() ||
      !stats.isFile?.() ||
      (stats.mode & 0o777) !== 0o600 ||
      (expectedUid !== undefined && stats.uid !== expectedUid) ||
      stats.size < 1 ||
      stats.size > 8192 ||
      fileSystem.realpathSync(filename) !== path.resolve(filename)
    ) {
      throw new Error("unsafe key file");
    }
    return fileSystem.readFileSync(filename, "utf8");
  } catch {
    throw operationalError(
      "RUNTIME_KEY_FILE_INVALID",
      "The automation runtime-key file must be an absolute, caller-owned, non-symlinked regular file with mode 0600 and at most 8192 bytes.",
      "Fix the file ownership and permissions, then set ACTIONPROXY_CONTROL_PLANE_KEY_FILE to its absolute path.",
      "./actionproxy chatgpt",
    );
  }
}

function createPrivateRuntimeDirectory(fileSystem, sessionId) {
  const temporaryRoot = fileSystem.realpathSync(os.tmpdir());
  const directory = fileSystem.mkdtempSync(
    path.join(temporaryRoot, `actionproxy-first-run-${sessionId}-`),
  );
  fileSystem.chmodSync?.(directory, 0o700);
  const stats = fileSystem.lstatSync(directory);
  const relative = path.relative(
    temporaryRoot,
    fileSystem.realpathSync(directory),
  );
  if (
    stats.isSymbolicLink?.() ||
    !stats.isDirectory?.() ||
    (stats.mode & 0o777) !== 0o700 ||
    !relative ||
    relative.startsWith("..") ||
    path.isAbsolute(relative)
  ) {
    throw operationalError(
      "RUNTIME_SESSION_UNSAFE",
      "Could not create a private OS-temporary runtime-key session.",
      "Check TMPDIR ownership and permissions, then retry.",
      "./actionproxy chatgpt",
    );
  }
  return directory;
}

export function redact(value, secrets) {
  const list = (Array.isArray(secrets) ? secrets : [secrets]).filter(Boolean);
  return list.reduce(
    (result, secret) => result.split(secret).join("[REDACTED]"),
    String(value),
  );
}

export function parseComposePort(raw) {
  const lines = String(raw).trim().split(/\r?\n/u).filter(Boolean);
  if (lines.length !== 1) throw new Error("expected one published port");
  const match = /^127\.0\.0\.1:(\d{1,5})$/u.exec(lines[0]);
  const port = match ? Number(match[1]) : NaN;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("expected a single 127.0.0.1 port binding");
  }
  return port;
}

export function validateTunnelHealthUrl(raw) {
  if (String(raw).length > 2048) throw new Error("health URL is too long");
  const url = new URL(String(raw).trim());
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "[::1]"].includes(url.hostname) ||
    !url.port ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !["", "/"].includes(url.pathname)
  ) {
    throw new Error("health URL must be loopback HTTP with an explicit port");
  }
  return url.origin;
}

export function createStatusSnapshot({
  sessionId,
  journey,
  setupStage,
  checks,
  setupDetails,
  tunnelUiUrl,
}) {
  const byId = new Map((checks ?? []).map((check) => [check.id, check]));
  const normalizedChecks = CHECK_IDS.map((id) => {
    const check = byId.get(id) ?? { id, state: "pending" };
    if (
      !["pending", "running", "pass", "action_required", "fail"].includes(
        check.state,
      )
    ) {
      throw new Error(`invalid check state for ${id}`);
    }
    if (check.remediationCode && !remediationCodes.has(check.remediationCode)) {
      throw new Error(`invalid remediation code for ${id}`);
    }
    return check.remediationCode
      ? { id, remediationCode: check.remediationCode, state: check.state }
      : { id, state: check.state };
  });
  const snapshot = {
    approvalTimeoutMs: APPROVAL_TIMEOUT_MS,
    checks: normalizedChecks,
    journey,
    schemaVersion: STATUS_SCHEMA_VERSION,
    sessionId,
    setupStage,
  };
  if (setupDetails) {
    const details = {
      composeVersion: validateSetupVersion(
        setupDetails.composeVersion,
        "Compose",
      ),
      dockerVersion: validateSetupVersion(
        setupDetails.dockerVersion,
        "Docker engine",
      ),
      nodeVersion: validateSetupVersion(setupDetails.nodeVersion, "Node"),
      port: setupDetails.port,
      projectName: setupDetails.projectName,
    };
    if (
      setupDetails.runtimeKeyExcludedFromDocker !== undefined &&
      typeof setupDetails.runtimeKeyExcludedFromDocker !== "boolean"
    ) {
      throw new Error("invalid runtime-key Docker check for Quickstart status");
    }
    if (!projectPattern.test(details.projectName)) {
      throw new Error("invalid Quickstart setup project name");
    }
    if (
      !Number.isInteger(details.port) ||
      details.port < 1024 ||
      details.port > 65535
    ) {
      throw new Error("invalid Quickstart setup port");
    }
    snapshot.setupDetails =
      setupDetails.runtimeKeyExcludedFromDocker === undefined
        ? details
        : {
            ...details,
            runtimeKeyExcludedFromDocker:
              setupDetails.runtimeKeyExcludedFromDocker,
          };
  }
  if (tunnelUiUrl) snapshot.tunnelUiUrl = tunnelUiUrl;
  return snapshot;
}

function validateSetupVersion(value, name) {
  const version = String(value ?? "").trim();
  if (version.length > 64 || !setupVersionPattern.test(version)) {
    throw new Error(`invalid ${name} version for Quickstart status`);
  }
  return version;
}

export function mcpCommand(projectName) {
  if (!projectPattern.test(projectName))
    throw new Error("invalid Compose project name");
  return [
    "docker",
    "compose",
    "--project-name",
    projectName,
    "-f",
    "docker-compose.yml",
    "exec",
    "-T",
    "actionproxy",
    "node",
    "packages/mcp-wrapper/dist/index.js",
    "wrap",
    "--config",
    "examples/chatgpt-tunnel/actionproxy.mcp.yaml",
  ].join(" ");
}

export function profileMarker({ tunnelId, projectName }) {
  const command = mcpCommand(projectName);
  return {
    commandHash: createHash("sha256").update(command).digest("hex"),
    composeProject: projectName,
    tunnelId,
    version: PROFILE_MARKER_VERSION,
  };
}

export function tunnelProfilePaths(repoRoot, profile) {
  validateProfile(profile);
  const root = path.join(repoRoot, ".actionproxy", "chatgpt-tunnel");
  const profileDirectory = path.join(root, "profiles");
  return {
    file: path.join(profileDirectory, `${profile}.yaml`),
    profileDirectory,
    root,
  };
}

export async function runFirstRun(
  {
    args = process.argv.slice(2),
    env = process.env,
    legacyRuntimeKey,
    repoRoot = defaultRepoRoot,
  } = {},
  dependencies = {},
) {
  const fileSystem = dependencies.fileSystem ?? fs;
  const sanitizedEnvironment = { ...env };
  const bootstrapRuntimeKey = consumeLegacyRuntimeKeyFd(
    fileSystem,
    sanitizedEnvironment.ACTIONPROXY_LEGACY_RUNTIME_KEY_FD,
  );
  const rawEnvironmentRuntimeKey = sanitizedEnvironment.CONTROL_PLANE_API_KEY;
  const capturedLegacyRuntimeKey = legacyRuntimeKey ?? bootstrapRuntimeKey;
  const runtimeKeyFile =
    sanitizedEnvironment.ACTIONPROXY_CONTROL_PLANE_KEY_FILE?.trim();
  if (capturedLegacyRuntimeKey !== undefined && runtimeKeyFile) {
    throw usageError(
      "Choose only one runtime-key source: hidden input, ACTIONPROXY_CONTROL_PLANE_KEY_FILE, or legacy CONTROL_PLANE_API_KEY.",
    );
  }
  delete sanitizedEnvironment.ACTIONPROXY_CONTROL_PLANE_KEY_FILE;
  delete sanitizedEnvironment.ACTIONPROXY_LEGACY_RUNTIME_KEY_FD;
  delete sanitizedEnvironment.CONTROL_PLANE_API_KEY;
  delete sanitizedEnvironment.OPENAI_API_KEY;
  if (env === process.env) {
    delete process.env.ACTIONPROXY_CONTROL_PLANE_KEY_FILE;
    delete process.env.ACTIONPROXY_LEGACY_RUNTIME_KEY_FD;
    delete process.env.CONTROL_PLANE_API_KEY;
    delete process.env.OPENAI_API_KEY;
  }
  if (rawEnvironmentRuntimeKey !== undefined) {
    throw usageError(
      "Raw CONTROL_PLANE_API_KEY input is accepted only by ./actionproxy, which scrubs it before the long-lived Node launcher starts. Run ./actionproxy chatgpt directly or use ACTIONPROXY_CONTROL_PLANE_KEY_FILE for strict automation.",
    );
  }
  const runtime = createRuntime(
    {
      env: sanitizedEnvironment,
      legacyRuntimeKey: capturedLegacyRuntimeKey,
      legacyRuntimeKeySource:
        capturedLegacyRuntimeKey === undefined
          ? undefined
          : bootstrapRuntimeKey !== undefined
            ? "bootstrap"
            : "direct_environment",
      repoRoot,
      runtimeKeyFile,
    },
    dependencies,
  );
  let parsed = parseArguments(args);
  if (parsed.command === "help") {
    runtime.stdout.write(usage());
    return 0;
  }
  if (parsed.command === "version") {
    runtime.stdout.write(`${FIRST_RUN_VERSION}\n`);
    return 0;
  }
  if (!parsed.command) {
    if (!runtime.isTTY)
      throw usageError(
        "Choose `local` or `chatgpt` when input is not interactive.",
      );
    const answer = await runtime.promptLine(
      [
        "What do you want to prove?",
        "",
        "  1. Run the local approval lifecycle",
        "  2. Connect ActionProxy to ChatGPT",
        "",
        "Choose 1 or 2: ",
      ].join("\n"),
    );
    if (answer.trim() === "1") parsed = parseArguments(["local"]);
    else if (answer.trim() === "2") parsed = parseArguments(["chatgpt"]);
    else throw usageError("Choose 1 or 2.");
  }

  if (parsed.command === "doctor") return doctorCommand(parsed, runtime);
  if (parsed.command === "status") return statusCommand(parsed, runtime);
  if (parsed.command === "integrate") return integrateCommand(parsed, runtime);
  if (parsed.command === "tunnel-client")
    return tunnelClientCommand(parsed, runtime);
  if (parsed.command === "stop") return stopCommand(runtime);
  if (parsed.command === "reset") return resetCommand(runtime);
  if (parsed.command === "local" || parsed.command === "chatgpt") {
    return startJourney(parsed, runtime);
  }
  throw usageError(`Unsupported command: ${parsed.command}`);
}

function createRuntime(
  { env, legacyRuntimeKey, legacyRuntimeKeySource, repoRoot, runtimeKeyFile },
  dependencies,
) {
  return {
    command: dependencies.runCommand ?? runCommand,
    currentWorkingDirectory:
      dependencies.currentWorkingDirectory ?? process.cwd(),
    architecture: dependencies.architecture ?? os.arch(),
    env: { ...env },
    fetchFn: dependencies.fetchFn ?? fetch,
    fileSystem: dependencies.fileSystem ?? fs,
    foreground: dependencies.runForeground ?? runForeground,
    isTTY:
      dependencies.isTTY ??
      Boolean(process.stdin.isTTY && process.stdout.isTTY),
    legacyRuntimeKey,
    legacyRuntimeKeySource,
    now: dependencies.now ?? (() => Date.now()),
    openUrl: dependencies.openUrl ?? defaultOpenUrl,
    platform: dependencies.platform ?? process.platform,
    processId: dependencies.processId ?? process.pid,
    processKill: dependencies.processKill ?? process.kill.bind(process),
    signalEmitter: dependencies.signalEmitter ?? process,
    promptConfirm: dependencies.promptConfirm ?? defaultPromptConfirm,
    promptLine: dependencies.promptLine ?? readTerminalLine,
    readSecret: dependencies.readSecret ?? readHiddenSecret,
    repoRoot: (dependencies.fileSystem ?? fs).realpathSync(repoRoot),
    runtimeKeyFile,
    sleep:
      dependencies.sleep ??
      ((milliseconds) =>
        new Promise((resolve) => setTimeout(resolve, milliseconds))),
    stderr: dependencies.stderr ?? process.stderr,
    stdout: dependencies.stdout ?? process.stdout,
    uuid: dependencies.uuid ?? randomUUID,
  };
}

async function integrateCommand(parsed, runtime) {
  if (!parsed.mode) {
    throw usageError(
      "integrate requires --mode sdk, --mode mcp, or --mode http.",
    );
  }
  const outputName = parsed.output ?? `actionproxy-${parsed.mode}-integration`;
  const starter = createIntegrationStarter(parsed.mode, {
    actionProxySource: runtime.repoRoot,
  });
  const gatewayBaseUrl = await integrationGatewayHint(runtime);
  try {
    writeIntegrationStarter(starter, outputName, {
      currentWorkingDirectory: runtime.currentWorkingDirectory,
      fileSystem: runtime.fileSystem,
    });
  } catch (error) {
    if (!parsed.json || !(error instanceof FirstRunError)) throw error;
    runtime.stdout.write(
      `${JSON.stringify({
        error: {
          code: error.code,
          message: error.message,
          remedy: error.remedy,
          retry: error.retry,
        },
        ok: false,
        schemaVersion: INTEGRATION_STARTER_SCHEMA_VERSION,
      })}\n`,
    );
    return error.exitCode;
  }

  const result = {
    files: starter.files.map(({ path: filename, sha256 }) => ({
      path: filename,
      sha256,
    })),
    mode: starter.mode,
    gatewayBaseUrl,
    nextCommands: integrationNextCommands(
      starter.mode,
      outputName,
      gatewayBaseUrl,
      starter.packageSource,
    ),
    ok: true,
    outputDirectory: outputName,
    packageVersion: starter.packageVersion,
    packageSource: starter.packageSource,
    proofChecklist: starter.proofChecklist,
    safeguards: starter.safeguards,
    schemaVersion: starter.schemaVersion,
    written: true,
  };
  if (parsed.json) {
    runtime.stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  }

  runtime.stdout.write(
    lines([
      `✓ Generated the ${starter.mode.toUpperCase()} starter in ./${outputName}`,
      `✓ ${starter.files.length} deterministic, credential-free files`,
      "✓ Existing files were not changed",
      "",
      "Next:",
      ...result.nextCommands.map((command) => `  ${command}`),
      "",
      "Proof before replacing any mock:",
      ...starter.proofChecklist.map(
        (item) => `  ○ ${item.id}: ${item.expectation}`,
      ),
    ]),
  );
  return 0;
}

function integrationNextCommands(
  mode,
  outputName,
  gatewayBaseUrl,
  packageSource,
) {
  const commands = [`cd ${shellQuotePosix(outputName)}`];
  if (!gatewayBaseUrl) {
    commands.push("node run-with-live-gateway.mjs --start");
  }
  if (packageSource) {
    commands.push("node prepare-local-package.mjs", "npm install");
  }
  if (mode === "mcp") {
    return [
      ...commands,
      "node run-with-live-gateway.mjs npm run doctor",
      "node run-with-live-gateway.mjs npm run wrap",
    ];
  }
  if (mode === "sdk") {
    return [
      ...commands,
      "node run-with-live-gateway.mjs npm run proof",
    ];
  }
  return [...commands, "node run-with-live-gateway.mjs npm run proof"];
}

async function integrationGatewayHint(runtime) {
  try {
    const state = readState(
      runtime.fileSystem,
      runtime.repoRoot,
      firstRunPaths(runtime.repoRoot).state,
      { optional: true },
    );
    const gateway = await inspectExistingGateway(runtime, state ?? {});
    if (
      gateway.healthy &&
      gateway.loopbackOnly &&
      gateway.port === state?.port &&
      state?.baseUrl === `http://127.0.0.1:${state.port}`
    ) {
      return state.baseUrl;
    }
  } catch {
    // A stale or malformed First Run state must not block an integration
    // scaffold. The generated README explains how to resolve the live port.
  }
  return null;
}

async function startJourney(parsed, runtime) {
  const signalGuard = installJourneySignalGuard(runtime.signalEmitter);
  const fetchFn = runtime.fetchFn;
  const sleep = runtime.sleep;
  runtime.fetchAfterInterrupt = fetchFn;
  runtime.fetchFn = (...args) => signalGuard.race(fetchFn(...args));
  runtime.sleep = (...args) => signalGuard.race(sleep(...args));
  runtime.throwIfInterrupted = signalGuard.throwIfInterrupted;
  try {
    return await runJourney(parsed, runtime);
  } finally {
    runtime.fetchFn = fetchFn;
    runtime.sleep = sleep;
    delete runtime.fetchAfterInterrupt;
    delete runtime.throwIfInterrupted;
    signalGuard.dispose();
  }
}

async function runJourney(parsed, runtime) {
  const journey = parsed.command;
  const identity = checkoutIdentity(runtime.repoRoot, runtime.fileSystem);
  const oldState = readState(
    runtime.fileSystem,
    runtime.repoRoot,
    firstRunPaths(runtime.repoRoot).state,
    { optional: true },
  );
  const projectName =
    oldState?.projectName && projectPattern.test(oldState.projectName)
      ? oldState.projectName
      : identity.projectName;
  const sessionId = runtime.uuid();
  if (!sessionPattern.test(sessionId))
    throw new Error("session generator returned a non-v4 UUID");
  const updateToken = randomBytes(32).toString("hex");
  let originToken;
  do {
    originToken = randomBytes(32).toString("hex");
  } while (originToken === updateToken);
  const retry = `./actionproxy ${journey}`;
  const requestedPort = parsed.port;

  let tunnelClient;
  let tunnelId = parsed.tunnelId;
  let profile = parsed.profile;
  let openAiLinks;
  if (journey === "chatgpt" && !tunnelId && !runtime.isTTY) {
    throw usageError("Provide --tunnel-id when input is not interactive.");
  }
  runtime.stdout.write(`ActionProxy First Run ${FIRST_RUN_VERSION}\n`);
  await ensurePlatform(runtime, retry);
  await ensureNode(runtime, retry);
  const dockerPrerequisites = await ensureDocker(runtime, retry);
  if (journey === "chatgpt") {
    openAiLinks = readOpenAiLinks(runtime.fileSystem, runtime.repoRoot);
    tunnelId = await prepareChatGptTunnelId(runtime, {
      links: openAiLinks,
      noOpen: parsed.noOpen,
      tunnelId,
    });
    if (!tunnelId) return 0;
    tunnelClient = await requireTunnelClient(runtime, retry, {
      links: openAiLinks,
      noOpen: parsed.noOpen,
    });
    if (!tunnelClient) return 0;
    profile ??= `actionproxy-local-${projectName.slice("actionproxy-first-run-".length)}`;
    validateProfile(profile);
    runtime.stdout.write(
      "\n[ChatGPT preparation complete] Tunnel configuration and control-plane access will be checked after the local gateway is ready. Confirm developer mode and app visibility in ChatGPT.\n",
    );
  }

  const releaseLock = acquireLock(runtime, { journey, sessionId });
  let state;
  let keyFile;
  let healthUrlFile;
  let sessionDirectory;
  let sessionSignalGuard;
  let heartbeat;
  let tunnelAbortController;
  let dockerEnvironment;
  let setupDetails;
  let statusChecks;
  let tunnelStarted = false;
  let dockerStarted = false;
  let gatewayHandedOff = false;
  let provisionalProfile;
  try {
    statusChecks = basePassedChecks(journey === "chatgpt");
    state = {
      baseUrl: undefined,
      checkoutId: identity.checkoutId,
      journey,
      port: undefined,
      profile,
      projectName,
      schemaVersion: STATE_VERSION,
      sessionId,
      startedAt: new Date(runtime.now()).toISOString(),
    };
    writeState(
      runtime.fileSystem,
      runtime.repoRoot,
      firstRunPaths(runtime.repoRoot).state,
      state,
    );

    dockerEnvironment = dockerEnv(runtime.env, {
      journey,
      originToken,
      port: requestedPort,
      sessionId,
      updateToken,
    });
    const compose = composeArgs(projectName);
    runtime.stdout.write(
      [
        "",
        "[1/4] Prerequisites verified",
        `[2/4] Build and start Community image (${requestedPort === "auto" ? "automatic loopback port" : `port ${requestedPort}`})…`,
        "",
      ].join("\n"),
    );
    const startedAt = runtime.now();
    const progress = parsed.verbose
      ? undefined
      : setInterval(() => {
          runtime.stdout.write(
            `  [build/start] still running (${formatDuration(runtime.now() - startedAt)})…\n`,
          );
        }, 15_000);
    progress?.unref?.();
    const reportDockerStage = parsed.verbose
      ? undefined
      : dockerProgressReporter(runtime, startedAt);
    // Compose may create resources before its process reports success. Treat
    // the project as mutation-started so interruption/failure uses only the
    // scoped, label-verified cleanup path.
    dockerStarted = true;
    try {
      await checked(runtime, {
        args: [...compose, "up", "-d", "--build", "actionproxy"],
        code: "DOCKER_START_FAILED",
        env: dockerEnvironment,
        executable: "docker",
        message: "Docker could not build and start ActionProxy.",
        remedy:
          "Review the bounded error output, ensure Docker has enough disk space, and retry.",
        retry,
        onOutput: reportDockerStage,
        stream: parsed.verbose,
      });
    } catch (error) {
      if (
        typeof requestedPort === "number" &&
        error?.code === "DOCKER_START_FAILED" &&
        /(?:address already in use|bind.*failed|port is already allocated)/iu.test(
          error.message,
        )
      ) {
        throw operationalError(
          "PORT_OCCUPIED",
          `Port ${requestedPort} is already in use.`,
          "Let Docker choose a race-free loopback port.",
          `./actionproxy ${journey} --port auto`,
        );
      }
      throw error;
    } finally {
      if (progress) clearInterval(progress);
    }
    runtime.stdout.write(
      `✓ Docker build/start completed in ${formatDuration(runtime.now() - startedAt)}\n`,
    );
    const portResult = await checked(runtime, {
      args: [...compose, "port", "actionproxy", "8787"],
      code: "LOOPBACK_PORT_INVALID",
      env: dockerEnvironment,
      executable: "docker",
      message: "Docker did not publish exactly one loopback gateway port.",
      remedy: "Stop the concierge project, then retry with --port auto.",
      retry: "./actionproxy stop",
    });
    let port;
    try {
      port = parseComposePort(portResult.stdout);
    } catch (error) {
      throw operationalError(
        "LOOPBACK_PORT_INVALID",
        `Docker published an unsafe or ambiguous port (${error.message}).`,
        "Run ./actionproxy stop, then retry with --port auto.",
        retry,
      );
    }
    if (typeof requestedPort === "number" && port !== requestedPort) {
      throw operationalError(
        "PORT_MISMATCH",
        `Docker published port ${port}, but port ${requestedPort} was requested.`,
        "Stop the existing concierge and retry with --port auto.",
        "./actionproxy stop",
      );
    }
    const baseUrl = `http://127.0.0.1:${port}`;
    setupDetails = {
      composeVersion: dockerPrerequisites.composeVersion,
      dockerVersion: dockerPrerequisites.dockerVersion,
      nodeVersion: process.versions.node,
      port,
      projectName,
    };
    state = { ...state, baseUrl, port };
    writeState(
      runtime.fileSystem,
      runtime.repoRoot,
      firstRunPaths(runtime.repoRoot).state,
      state,
    );
    runtime.stdout.write(
      "[3/4] Verify local gateway and governed tool boundary…\n",
    );
    await waitForGateway(runtime, `${baseUrl}/health`, retry);
    await verifyContainer(runtime, { compose, dockerEnvironment, port, retry });
    await discoverTools(runtime, { compose, dockerEnvironment, retry });
    statusChecks.set("gateway", { id: "gateway", state: "pass" });
    statusChecks.set("storage", { id: "storage", state: "pass" });
    statusChecks.set("loopback", { id: "loopback", state: "pass" });
    statusChecks.set("tool_discovery", { id: "tool_discovery", state: "pass" });
    // Once the complete local boundary is verified, later ChatGPT setup errors
    // must not remove the gateway or its audit evidence. Only failures during
    // build or gateway verification are eligible for automatic cleanup.
    gatewayHandedOff = true;

    if (journey === "local") {
      const snapshot = createStatusSnapshot({
        checks: [...statusChecks.values()],
        journey,
        sessionId,
        setupDetails,
        setupStage: "gateway_ready",
      });
      await publishStatus(runtime, baseUrl, updateToken, snapshot);
      const quickstartUrl = `${baseUrl}/app#/demo?journey=local&session=${encodeURIComponent(sessionId)}`;
      await maybeOpen(runtime, quickstartUrl, parsed.noOpen);
      runtime.stdout.write(
        [
          "",
          "[4/4] Quickstart ready",
          "✓ Local gateway ready",
          `  Quickstart: ${quickstartUrl}`,
          `  Storage: SQLite in Docker volume ${projectName}_actionproxy_data`,
          `  Stop safely: ./actionproxy stop`,
          `  Delete local audit: ./actionproxy reset`,
          "",
        ].join("\n"),
      );
      return 0;
    }

    statusChecks.set("tunnel_client", { id: "tunnel_client", state: "pass" });
    await publishStatus(
      runtime,
      baseUrl,
      updateToken,
      createStatusSnapshot({
        checks: [...statusChecks.values()],
        journey,
        sessionId,
        setupDetails,
        setupStage: "tunnel_checking",
      }),
    );
    const quickstartUrl = `${baseUrl}/app#/demo?journey=chatgpt&session=${encodeURIComponent(sessionId)}`;
    await maybeOpen(runtime, quickstartUrl, parsed.noOpen);
    runtime.stdout.write(
      [
        "",
        "✓ Local gateway ready; Quickstart is following secure-tunnel setup",
        `  Quickstart: ${quickstartUrl}`,
        "  Continue in this terminal for the private runtime-key step.",
        "",
      ].join("\n"),
    );

    if (runtime.legacyRuntimeKeySource) {
      runtime.stderr.write(
        "! CONTROL_PLANE_API_KEY compatibility input was scrubbed before the long-lived launcher started. Use ACTIONPROXY_CONTROL_PLANE_KEY_FILE for strict automation.\n",
      );
    }
    const configuredRuntimeKeyFile = runtime.runtimeKeyFile;
    runtime.runtimeKeyFile = undefined;
    if (
      runtime.legacyRuntimeKey === undefined &&
      !configuredRuntimeKeyFile &&
      !(await prepareInteractiveRuntimeKey(runtime, {
        links: openAiLinks,
        noOpen: parsed.noOpen,
      }))
    ) {
      await publishStatus(
        runtime,
        baseUrl,
        updateToken,
        createStatusSnapshot({
          checks: [...statusChecks.values()],
          journey,
          sessionId,
          setupDetails,
          setupStage: "gateway_ready",
        }),
        { bestEffort: true },
      );
      runtime.stdout.write(
        [
          "Setup paused before a runtime key was requested.",
          "The verified local gateway and SQLite audit remain available.",
          "Resume: ./actionproxy chatgpt",
          "",
        ].join("\n"),
      );
      return 0;
    }
    const runtimeKey =
      runtime.legacyRuntimeKey !== undefined
        ? validRuntimeKey(runtime.legacyRuntimeKey)
        : configuredRuntimeKeyFile
          ? validRuntimeKey(
              readCallerRuntimeKeyFile(
                runtime.fileSystem,
                configuredRuntimeKeyFile,
              ),
            )
          : await readValidInteractiveRuntimeKey(runtime);
    runtime.legacyRuntimeKey = undefined;
    runtime.legacyRuntimeKeySource = undefined;
    sessionDirectory = createPrivateRuntimeDirectory(
      runtime.fileSystem,
      sessionId,
    );
    keyFile = path.join(sessionDirectory, "runtime-key");
    runtime.fileSystem.writeFileSync(keyFile, runtimeKey, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    runtime.fileSystem.chmodSync?.(keyFile, 0o600);
    healthUrlFile = path.join(sessionDirectory, "tunnel-health-url");
    sessionSignalGuard = installSessionSignalGuard(
      runtime.signalEmitter,
      runtime.fileSystem,
      {
        healthUrlFile,
        keyFile,
        sessionDirectory,
      },
    );
    const secretRef = `file:${keyFile}`;
    const safeTunnelEnvironment = secretFreeEnv(runtime.env, runtimeKey);
    await verifyDockerHasNoRuntimeKey(runtime, {
      compose,
      dockerEnvironment,
      runtimeKey,
      retry,
    });
    setupDetails = { ...setupDetails, runtimeKeyExcludedFromDocker: true };
    sessionSignalGuard.throwIfInterrupted();

    const binding = profileMarker({ projectName, tunnelId });
    const markerFile = profileMarkerPath(runtime.repoRoot, profile);
    const profilePaths = tunnelProfilePaths(runtime.repoRoot, profile);
    let pendingProfileMarker;
    ensurePrivateDirectoryWithin(
      runtime.fileSystem,
      runtime.repoRoot,
      profilePaths.profileDirectory,
    );
    const existingMarker = readProfileMarker(
      runtime.fileSystem,
      runtime.repoRoot,
      markerFile,
    );
    if (
      existingMarker &&
      (existingMarker.commandHash !== binding.commandHash ||
        existingMarker.composeProject !== binding.composeProject ||
        existingMarker.tunnelId !== binding.tunnelId)
    ) {
      throw operationalError(
        "TUNNEL_PROFILE_CONFLICT",
        `Tunnel profile ${profile} belongs to a different tunnel, Compose project, or MCP command.`,
        "Choose a new --profile name; the concierge will not overwrite an unrelated profile.",
        retry,
      );
    }
    if (existingMarker) {
      const actualProfileHash = hashOwnedProfileFile(
        runtime.fileSystem,
        profilePaths.file,
      );
      if (actualProfileHash !== existingMarker.profileHash) {
        throw operationalError(
          "TUNNEL_PROFILE_CONTENT_CHANGED",
          `Tunnel profile ${profile} no longer matches the profile initialized by this checkout.`,
          "Choose a new --profile name or restore the original profile; the concierge will not run modified profile commands.",
          retry,
        );
      }
      runtime.stdout.write(`Reusing verified tunnel profile ${profile}.\n`);
    } else {
      if (runtime.fileSystem.existsSync(profilePaths.file)) {
        throw operationalError(
          "TUNNEL_PROFILE_UNOWNED",
          `Tunnel profile ${profile} already exists without an ActionProxy ownership marker.`,
          "Choose a new --profile name; the concierge will not inspect, overwrite, or run an unowned profile.",
          retry,
        );
      }
      runtime.stdout.write(`Initializing tunnel profile ${profile}…\n`);
      // The exact target was verified absent while this launcher owns the
      // checkout lock. Track it before init so a client that writes and then
      // exits nonzero cannot leave a retry-blocking unowned profile behind.
      provisionalProfile = { filename: profilePaths.file };
      await checked(runtime, {
        args: [
          "init",
          "--sample",
          "sample_mcp_stdio_local",
          "--profile",
          profile,
          "--profile-dir",
          profilePaths.profileDirectory,
          "--tunnel-id",
          tunnelId,
          "--mcp-command",
          mcpCommand(projectName),
        ],
        code: "TUNNEL_PROFILE_INIT_FAILED",
        env: safeTunnelEnvironment,
        executable: tunnelClient,
        message: "OpenAI tunnel profile initialization failed.",
        remedy: "Review tunnel-client help and retry with a new profile name.",
        retry,
        secrets: [runtimeKey],
      });
      sessionSignalGuard.throwIfInterrupted();
      const profileHash = hashOwnedProfileFile(
        runtime.fileSystem,
        profilePaths.file,
      );
      pendingProfileMarker = {
        ...binding,
        profileHash,
      };
      provisionalProfile = { filename: profilePaths.file, profileHash };
    }

    await checked(runtime, {
      args: [
        "doctor",
        "--profile",
        profile,
        "--profile-dir",
        profilePaths.profileDirectory,
        "--explain",
        `--control-plane.api-key=${secretRef}`,
      ],
      code: "TUNNEL_ACCESS_FAILED",
      env: safeTunnelEnvironment,
      executable: tunnelClient,
      message: "OpenAI tunnel doctor could not verify this setup.",
      remedy: `Check the runtime key, Tunnels Read + Use, and workspace association at ${openAiLinks.links.tunnelSettings.url}. Official link reviewed ${openAiLinks.reviewedAt}.`,
      retry,
      secrets: [runtimeKey],
    });
    sessionSignalGuard.throwIfInterrupted();
    if (pendingProfileMarker) {
      writeJsonPrivate(
        runtime.fileSystem,
        runtime.repoRoot,
        markerFile,
        pendingProfileMarker,
      );
      provisionalProfile = undefined;
    }
    runtime.stdout.write("✓ Tunnel configuration check passed\n");
    statusChecks.set("tunnel_doctor", { id: "tunnel_doctor", state: "pass" });
    await publishStatus(
      runtime,
      baseUrl,
      updateToken,
      createStatusSnapshot({
        checks: [...statusChecks.values()],
        journey,
        sessionId,
        setupDetails,
        setupStage: "tunnel_checking",
      }),
    );
    sessionSignalGuard.throwIfInterrupted();

    tunnelAbortController = new AbortController();
    const tunnelPromise = runtime.foreground(
      tunnelClient,
      [
        "run",
        "--profile",
        profile,
        "--profile-dir",
        profilePaths.profileDirectory,
        `--control-plane.api-key=${secretRef}`,
        "--health.listen-addr",
        "127.0.0.1:0",
        "--health.url-file",
        healthUrlFile,
      ],
      {
        cwd: runtime.repoRoot,
        env: safeTunnelEnvironment,
        secrets: [runtimeKey],
        signal: tunnelAbortController.signal,
        stderr: runtime.stderr,
        stdout: runtime.stdout,
      },
    );
    tunnelStarted = true;
    const tunnelUiOrigin = await waitForTunnelReadiness(
      runtime,
      healthUrlFile,
      tunnelPromise,
      retry,
    );
    statusChecks.set("tunnel_readiness", {
      id: "tunnel_readiness",
      state: "pass",
    });
    const readySnapshot = createStatusSnapshot({
      checks: [...statusChecks.values()],
      journey,
      sessionId,
      setupDetails,
      setupStage: "tunnel_ready",
      tunnelUiUrl: `${tunnelUiOrigin}/ui`,
    });
    await publishStatus(runtime, baseUrl, updateToken, readySnapshot);
    heartbeat = setInterval(() => {
      void publishStatus(runtime, baseUrl, updateToken, readySnapshot, {
        bestEffort: true,
      });
    }, 5_000);
    heartbeat.unref?.();

    runtime.stdout.write(
      [
        "",
        "[4/4] ChatGPT Quickstart ready",
        "✓ Secure tunnel ready",
        `  Quickstart: ${quickstartUrl}`,
        `  Tunnel status: ${tunnelUiOrigin}/ui`,
        `  Open ChatGPT app settings: ${openAiLinks.links.chatgptAppSettings.url}`,
        `  Official OpenAI links reviewed ${openAiLinks.reviewedAt}.`,
        "  Keep this terminal open while testing. Press Ctrl+C to stop only the tunnel.",
        "",
      ].join("\n"),
    );

    const tunnelResult = await tunnelPromise;
    clearInterval(heartbeat);
    heartbeat = undefined;
    statusChecks.set(
      "tunnel_readiness",
      tunnelResult.interrupted
        ? {
            id: "tunnel_readiness",
            remediationCode: "tunnel_disconnected",
            state: "action_required",
          }
        : {
            id: "tunnel_readiness",
            remediationCode: "tunnel_disconnected",
            state: "fail",
          },
    );
    await publishStatus(
      runtime,
      baseUrl,
      updateToken,
      createStatusSnapshot({
        checks: [...statusChecks.values()],
        journey,
        sessionId,
        setupDetails,
        setupStage: "tunnel_stopped",
      }),
      {
        afterInterrupt: tunnelResult.interrupted,
        bestEffort: true,
      },
    );
    if (tunnelResult.code !== 0 && !tunnelResult.interrupted) {
      throw operationalError(
        "TUNNEL_DISCONNECTED",
        `OpenAI tunnel disconnected with exit code ${tunnelResult.code ?? "unknown"}.`,
        `Open ${tunnelUiOrigin}/ui for diagnostics, then retry.`,
        retry,
      );
    }
    runtime.stdout.write(
      "\nTunnel stopped. ActionProxy and its local audit remain available; run ./actionproxy stop when finished.\n",
    );
    return 0;
  } catch (error) {
    if (provisionalProfile) {
      removeProvisionalTunnelProfile(runtime, provisionalProfile);
      provisionalProfile = undefined;
    }
    const interrupted = error instanceof FirstRunError && error.exitCode === 0;
    if (state?.baseUrl) {
      const failureSetupDetails =
        error?.code === "RUNTIME_KEY_IN_DOCKER" && setupDetails
          ? { ...setupDetails, runtimeKeyExcludedFromDocker: false }
          : setupDetails;
      const failed = createStatusSnapshot({
        checks: failureChecks(error, journey, statusChecks),
        journey,
        sessionId,
        setupDetails: failureSetupDetails,
        setupStage: interrupted
          ? journey === "chatgpt" && tunnelStarted
            ? "tunnel_stopped"
            : gatewayHandedOff
              ? "gateway_ready"
              : "failed"
          : "failed",
      });
      await publishStatus(runtime, state.baseUrl, updateToken, failed, {
        afterInterrupt: interrupted,
        bestEffort: true,
      });
    }
    if (dockerStarted && !gatewayHandedOff && dockerEnvironment) {
      const cleanup = await removeConciergeRuntime(runtime, {
        bestEffort: true,
        dockerEnvironment,
        projectName,
        removeVolume: false,
      });
      if (!cleanup.ok) {
        throw operationalError(
          "SAFETY_CLEANUP_INCOMPLETE",
          `Gateway verification failed and ActionProxy could not confirm removal of the concierge container for ${projectName}.`,
          "Run the exact scoped cleanup command ./actionproxy stop before continuing; it will target only the recorded project.",
          "./actionproxy stop",
        );
      }
    }
    throw error;
  } finally {
    let runtimeKeyCleanupError;
    runtime.legacyRuntimeKey = undefined;
    runtime.legacyRuntimeKeySource = undefined;
    runtime.runtimeKeyFile = undefined;
    if (heartbeat) clearInterval(heartbeat);
    tunnelAbortController?.abort();
    sessionSignalGuard?.dispose();
    try {
      removeRequiredRuntimeKey(runtime, keyFile);
    } catch (error) {
      runtimeKeyCleanupError = error;
    }
    removeEphemeralFile(runtime, healthUrlFile, "tunnel health URL");
    if (sessionDirectory) {
      try {
        runtime.fileSystem.rmdirSync(sessionDirectory);
      } catch (error) {
        if (error?.code !== "ENOENT" && error?.code !== "ENOTEMPTY") {
          runtime.stderr.write(
            "Warning: could not remove the empty First Run session directory.\n",
          );
        }
      }
    }
    releaseLock();
    if (runtimeKeyCleanupError) throw runtimeKeyCleanupError;
  }
}

async function doctorCommand(parsed, runtime) {
  const report = await collectDoctor(runtime, {
    includeChatgpt: parsed.chatgpt,
  });
  if (parsed.json) runtime.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else {
    const links = parsed.chatgpt
      ? readOpenAiLinks(runtime.fileSystem, runtime.repoRoot)
      : undefined;
    printDoctor(runtime.stdout, report, parsed.chatgpt, links);
  }
  return report.ok ? 0 : 1;
}

async function collectDoctor(runtime, { includeChatgpt }) {
  const checks = [];
  const nodeMajor = Number(process.versions.node.split(".")[0]);
  checks.push(
    nodeMajor >= 22 && nodeMajor <= 24
      ? { id: "node", state: "pass" }
      : { id: "node", remediationCode: "unsupported_node", state: "fail" },
  );
  const supportedArchitecture = ["arm64", "x64"].includes(runtime.architecture);
  checks.push(
    runtime.platform === "darwin" && supportedArchitecture
      ? { id: "operating_system", state: "pass" }
      : runtime.platform === "linux" && supportedArchitecture
        ? {
            id: "operating_system",
            remediationCode: "unsupported_os",
            state: "action_required",
          }
        : {
            id: "operating_system",
            remediationCode: "unsupported_os",
            state: "fail",
          },
  );

  const dockerCli = await probe(runtime, "docker", ["--version"]);
  checks.push(
    dockerCli.ok
      ? { id: "docker_cli", state: "pass" }
      : { id: "docker_cli", remediationCode: "docker_missing", state: "fail" },
  );
  let dockerDaemon = { ok: false, version: undefined };
  let compose = { ok: false, version: undefined };
  if (dockerCli.ok) {
    dockerDaemon = await probe(runtime, "docker", [
      "info",
      "--format",
      "{{.ServerVersion}}",
    ]);
    compose = await probe(runtime, "docker", ["compose", "version", "--short"]);
  }
  checks.push(
    !dockerCli.ok
      ? { id: "docker_daemon", state: "pending" }
      : dockerDaemon.ok
        ? { id: "docker_daemon", state: "pass" }
        : {
            id: "docker_daemon",
            remediationCode: "docker_not_running",
            state: "fail",
          },
  );
  checks.push(
    !dockerCli.ok
      ? { id: "compose", state: "pending" }
      : compose.ok
        ? { id: "compose", state: "pass" }
        : { id: "compose", remediationCode: "compose_missing", state: "fail" },
  );

  let tunnelClientVersion;
  if (includeChatgpt) {
    const tunnel = await inspectTunnelClient(runtime);
    checks.push(
      tunnel.ok
        ? { id: "tunnel_client", state: "pass" }
        : {
            id: "tunnel_client",
            remediationCode: tunnel.missing
              ? "tunnel_client_missing"
              : "tunnel_client_incompatible",
            state: "fail",
          },
    );
    tunnelClientVersion = tunnel.version;
  }

  const state = readState(
    runtime.fileSystem,
    runtime.repoRoot,
    firstRunPaths(runtime.repoRoot).state,
    { optional: true },
  );
  let gateway = {
    healthy: false,
    loopbackOnly: false,
    port: null,
    storageMode: null,
    toolNames: [],
  };
  if (state?.baseUrl && state?.port && state?.projectName) {
    gateway = await inspectExistingGateway(runtime, state);
  }
  if (!state) {
    checks.push(
      { id: "gateway", state: "pending" },
      { id: "storage", state: "pending" },
      { id: "loopback", state: "pending" },
      { id: "tool_discovery", state: "pending" },
    );
  } else {
    checks.push(
      gateway.healthy
        ? { id: "gateway", state: "pass" }
        : {
            id: "gateway",
            remediationCode: "gateway_unhealthy",
            state: "fail",
          },
      gateway.storageMode === "sqlite"
        ? { id: "storage", state: "pass" }
        : {
            id: "storage",
            remediationCode: "storage_not_sqlite",
            state: "fail",
          },
      gateway.loopbackOnly
        ? { id: "loopback", state: "pass" }
        : {
            id: "loopback",
            remediationCode: "non_loopback_binding",
            state: "fail",
          },
      JSON.stringify(gateway.toolNames) === JSON.stringify(EXPECTED_DEMO_TOOLS)
        ? { id: "tool_discovery", state: "pass" }
        : {
            id: "tool_discovery",
            remediationCode: "tool_discovery_mismatch",
            state: "fail",
          },
    );
  }
  const ok = checks.every((check) => check.state !== "fail");
  return {
    architecture: runtime.architecture,
    checks,
    composeVersion: extractSemanticVersion(compose.version),
    dockerVersion: extractSemanticVersion(dockerCli.version),
    gateway,
    nodeVersion: process.versions.node,
    ok,
    operatingSystem: runtime.platform,
    schemaVersion: DOCTOR_SCHEMA_VERSION,
    supportedNodeRange: "22-24",
    tunnelClientVersion: extractSemanticVersion(tunnelClientVersion),
  };
}

async function statusCommand(parsed, runtime) {
  const state = readState(
    runtime.fileSystem,
    runtime.repoRoot,
    firstRunPaths(runtime.repoRoot).state,
    { optional: true },
  );
  if (!state) {
    const empty = {
      gateway: {
        healthy: false,
        loopbackOnly: false,
        port: null,
        storageMode: null,
        toolNames: [],
      },
      journey: null,
      projectRunning: false,
      schemaVersion: "actionproxy.first-run-status.v1",
      sessionId: null,
      tunnel: { ready: false, state: "not_started", uiUrl: null },
    };
    if (parsed.json)
      runtime.stdout.write(`${JSON.stringify(empty, null, 2)}\n`);
    else
      runtime.stdout.write(
        "ActionProxy First Run has not been started in this checkout.\n  Start: ./actionproxy\n",
      );
    return 0;
  }
  const gateway = await inspectExistingGateway(runtime, state);
  let quickstart;
  if (gateway.healthy) {
    try {
      const response = await runtime.fetchFn(
        `${state.baseUrl}/v1/demo/quickstart/status/${state.sessionId}`,
        {
          signal: AbortSignal.timeout(2_000),
        },
      );
      if (response.ok) quickstart = await response.json();
    } catch {
      /* reported as unavailable below */
    }
  }
  const tunnelReady =
    quickstart?.setupStage === "tunnel_ready" &&
    Date.parse(quickstart.updatedAt ?? 0) >= runtime.now() - 15_000;
  let tunnelResponding = false;
  if (tunnelReady && isLoopbackUiUrl(quickstart?.tunnelUiUrl)) {
    try {
      const tunnelOrigin = new URL(quickstart.tunnelUiUrl).origin;
      const response = await runtime.fetchFn(`${tunnelOrigin}/readyz`, {
        signal: AbortSignal.timeout(2_000),
      });
      tunnelResponding = response.ok;
    } catch {
      /* a heartbeat alone is not live readiness */
    }
  }
  const liveTunnelReady = tunnelReady && tunnelResponding;
  const report = {
    gateway,
    journey: state.journey,
    projectRunning: gateway.healthy,
    schemaVersion: "actionproxy.first-run-status.v1",
    sessionId: state.sessionId,
    tunnel: {
      ready: liveTunnelReady,
      state: liveTunnelReady
        ? "ready"
        : quickstart?.setupStage === "tunnel_ready"
          ? "tunnel_stopped"
          : (quickstart?.setupStage ?? "not_started"),
      uiUrl: isLoopbackUiUrl(quickstart?.tunnelUiUrl)
        ? quickstart.tunnelUiUrl
        : null,
    },
  };
  if (parsed.json) runtime.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else {
    runtime.stdout.write(
      [
        `ActionProxy First Run (${state.journey})`,
        `  Gateway: ${gateway.healthy ? `healthy at ${state.baseUrl}` : "not running"}`,
        `  Storage: ${gateway.storageMode ?? "unavailable"}`,
        `  Tunnel: ${report.tunnel.state}`,
        gateway.healthy
          ? `  Quickstart: ${state.baseUrl}/app#/demo?journey=${state.journey}&session=${state.sessionId}`
          : `  Restart: ./actionproxy ${state.journey}`,
        gateway.healthy ? "  Stop safely: ./actionproxy stop" : undefined,
        state.journey === "chatgpt" && report.tunnel.state !== "ready"
          ? "  Reconnect tunnel: ./actionproxy chatgpt"
          : undefined,
        "",
      ]
        .filter(Boolean)
        .join("\n") + "\n",
    );
  }
  return gateway.healthy ? 0 : 1;
}

async function stopCommand(runtime) {
  const state = requireState(
    runtime,
    "Nothing to stop; this checkout has no First Run state.",
  );
  ensureNoLiveLock(runtime);
  const environment = dockerEnv(runtime.env, {
    journey: state.journey,
    port: state.port ?? "auto",
    sessionId: state.sessionId,
    updateToken: "actionproxy-stop-placeholder",
    originToken: "actionproxy-stop-origin-placeholder",
  });
  await removeConciergeRuntime(runtime, {
    dockerEnvironment: environment,
    projectName: state.projectName,
    removeVolume: false,
  });
  writeState(
    runtime.fileSystem,
    runtime.repoRoot,
    firstRunPaths(runtime.repoRoot).state,
    {
      ...state,
      stoppedAt: new Date(runtime.now()).toISOString(),
    },
  );
  runtime.stdout.write(
    `Stopped ${state.projectName}. Its SQLite audit volume was retained.\n`,
  );
  return 0;
}

async function tunnelClientCommand(parsed, runtime) {
  const action = parsed.tunnelClientAction;
  if (action === "status") {
    const distribution = readTunnelClientDistribution(
      runtime.fileSystem,
      runtime.repoRoot,
    );
    const result = await inspectTunnelClient(runtime, { distribution });
    const report = tunnelClientPublicReport(result, distribution, "status");
    if (parsed.json)
      runtime.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    else printTunnelClientStatus(runtime, report);
    return result.ok ? 0 : 1;
  }

  if (action === "install") {
    return withStandaloneSignalGuard(runtime, async () => {
      const distribution = readTunnelClientDistribution(
        runtime.fileSystem,
        runtime.repoRoot,
      );
      const result = await installCheckoutTunnelClient(runtime, distribution, {
        quiet: parsed.json,
        retry: "./actionproxy tunnel-client install",
      });
      const report = tunnelClientPublicReport(result, distribution, "install");
      if (parsed.json)
        runtime.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
      else {
        runtime.stdout.write(
          `${result.reused ? "Reused" : "Installed"} ActionProxy-reviewed pinned copy of OpenAI tunnel-client ${report.version} at .actionproxy/bin/tunnel-client.\n`,
        );
        runtime.stdout.write(
          "It is private to this checkout and removable with ./actionproxy tunnel-client remove.\n",
        );
      }
      return 0;
    });
  }

  if (action === "remove") {
    const result = removeCheckoutTunnelClient(runtime);
    const report = {
      action: "remove",
      removed: result.removed,
      schemaVersion: TUNNEL_CLIENT_RECEIPT_SCHEMA_VERSION,
    };
    if (parsed.json)
      runtime.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    else {
      runtime.stdout.write(
        result.removed
          ? "Removed the ActionProxy-installed checkout-local tunnel-client.\n"
          : "No ActionProxy-installed checkout-local tunnel-client was present.\n",
      );
    }
    return 0;
  }
  throw usageError("tunnel-client requires install, status, or remove.");
}

async function withStandaloneSignalGuard(runtime, operation) {
  if (typeof runtime.throwIfInterrupted === "function") return operation();
  const guard = installJourneySignalGuard(runtime.signalEmitter);
  runtime.throwIfInterrupted = guard.throwIfInterrupted;
  try {
    return await operation();
  } finally {
    delete runtime.throwIfInterrupted;
    guard.dispose();
  }
}

function tunnelClientPublicReport(result, distribution, action) {
  return {
    action,
    architecture: result.platformKey?.split("-").slice(1).join("-") ?? null,
    compatible: result.ok === true,
    installedByActionProxy: result.managed === true,
    platform: result.platformKey?.split("-")[0] ?? null,
    releaseTag: result.managed === true ? distribution.releaseTag : null,
    schemaVersion: TUNNEL_CLIENT_RECEIPT_SCHEMA_VERSION,
    selectedSource: result.source ?? "none",
    version: result.version ?? null,
  };
}

function printTunnelClientStatus(runtime, report) {
  if (report.compatible) {
    runtime.stdout.write(
      [
        `Compatible tunnel-client ${report.version ?? "(version unavailable)"}`,
        `  Source: ${report.selectedSource}`,
        `  Managed by ActionProxy: ${report.installedByActionProxy ? "yes" : "no"}`,
        report.installedByActionProxy
          ? "  Remove: ./actionproxy tunnel-client remove"
          : undefined,
        "",
      ]
        .filter(Boolean)
        .join("\n"),
    );
  } else {
    runtime.stdout.write(
      [
        "No compatible tunnel-client is currently selected.",
        `  Source checked: ${report.selectedSource}`,
        "  Install the reviewed checkout-local copy: ./actionproxy tunnel-client install",
        "",
      ].join("\n"),
    );
  }
}

async function resetCommand(runtime) {
  const state = requireState(
    runtime,
    "Nothing to reset; this checkout has no First Run state.",
  );
  ensureNoLiveLock(runtime);
  if (!runtime.isTTY) {
    throw usageError(
      "Reset requires an interactive terminal and exact confirmation.",
    );
  }
  const answer = await runtime.promptLine(
    "Type DELETE LOCAL AUDIT to remove the concierge SQLite volume: ",
  );
  if (answer !== "DELETE LOCAL AUDIT") {
    runtime.stdout.write("Reset cancelled. No local data was removed.\n");
    return 0;
  }
  const paths = firstRunPaths(runtime.repoRoot);
  assertSafeRemovalTree(runtime.fileSystem, runtime.repoRoot, paths.root);
  const environment = dockerEnv(runtime.env, {
    journey: state.journey,
    port: state.port ?? "auto",
    sessionId: state.sessionId,
    updateToken: "actionproxy-reset-placeholder",
    originToken: "actionproxy-reset-origin-placeholder",
  });
  await removeConciergeRuntime(runtime, {
    dockerEnvironment: environment,
    projectName: state.projectName,
    removeVolume: true,
  });
  runtime.fileSystem.rmSync(paths.root, { force: true, recursive: true });
  runtime.stdout.write(
    `Removed ${state.projectName} and its local SQLite audit volume. This cannot be recovered. Tunnel profiles and any checkout-local tunnel-client were retained.\n`,
  );
  return 0;
}

async function ensureNode(runtime, retry) {
  const major = Number(process.versions.node.split(".")[0]);
  runtime.stdout.write(
    `${major >= 22 && major <= 24 ? "✓" : "!"} Node ${process.versions.node}${major === 24 ? "" : " (Node 24 recommended)"}\n`,
  );
  if (major < 22 || major > 24) {
    throw operationalError(
      "NODE_UNSUPPORTED",
      `Node ${process.versions.node} is unsupported.`,
      "Use Node 22-24; Node 24 is recommended.",
      retry,
    );
  }
}

async function ensurePlatform(runtime, retry) {
  const architecture =
    runtime.architecture === "x64" ? "amd64" : runtime.architecture;
  if (!["amd64", "arm64"].includes(architecture)) {
    throw operationalError(
      "PLATFORM_UNSUPPORTED",
      `Unsupported CPU architecture: ${runtime.architecture}.`,
      "Use a Mac or Linux machine with arm64 or amd64.",
      retry,
    );
  }
  if (runtime.platform === "darwin") {
    runtime.stdout.write(`✓ macOS ${architecture}\n`);
    return;
  }
  if (runtime.platform === "linux") {
    runtime.stdout.write(
      `! Linux ${architecture} — best-effort; release-quality First Run support targets macOS\n`,
    );
    return;
  }
  throw operationalError(
    "PLATFORM_UNSUPPORTED",
    `Unsupported operating system: ${runtime.platform}.`,
    "Run First Run on macOS; Linux arm64/amd64 is available on a best-effort basis.",
    retry,
  );
}

async function ensureDocker(runtime, retry) {
  let result = await probe(runtime, "docker", ["--version"]);
  if (!result.ok) {
    throw operationalError(
      "DOCKER_MISSING",
      "Docker CLI was not found.",
      "Install Docker Desktop for Mac, then retry.",
      retry,
    );
  }
  runtime.stdout.write("✓ Docker installed\n");
  result = await probe(runtime, "docker", [
    "info",
    "--format",
    "{{.ServerVersion}}",
  ]);
  if (!result.ok && runtime.platform === "darwin" && runtime.isTTY) {
    runtime.stdout.write("! Docker Desktop is not running\n");
    if (
      await runtime.promptConfirm("Open Docker Desktop and wait for it? [Y/n] ")
    ) {
      let opened;
      try {
        opened = await runtime.command("open", ["-a", "Docker"], {
          capture: true,
          cwd: runtime.repoRoot,
          env: secretFreeEnv(runtime.env),
        });
      } catch (error) {
        if (error instanceof FirstRunError) throw error;
        runtime.throwIfInterrupted?.();
        opened = { code: 1 };
      }
      if (opened.interrupted) {
        throw new FirstRunError(
          "INTERRUPTED",
          "First Run cancelled by the user.",
          { exitCode: 0 },
        );
      }
      runtime.throwIfInterrupted?.();
      if (opened.code === 0) {
        const deadline = runtime.now() + 120_000;
        while (runtime.now() < deadline) {
          await runtime.sleep(1_000);
          result = await probe(runtime, "docker", [
            "info",
            "--format",
            "{{.ServerVersion}}",
          ]);
          if (result.ok) break;
        }
      }
    }
  }
  if (!result.ok) {
    throw operationalError(
      "DOCKER_NOT_RUNNING",
      "Docker Desktop is installed but its engine is not available.",
      "Open Docker Desktop and wait until it reports that the engine is running.",
      retry,
    );
  }
  const dockerVersion = validateSetupVersion(result.version, "Docker engine");
  runtime.stdout.write("✓ Docker engine running\n");
  result = await probe(runtime, "docker", ["compose", "version", "--short"]);
  if (!result.ok) {
    throw operationalError(
      "COMPOSE_MISSING",
      "Docker Compose v2 is not available.",
      "Update Docker Desktop so `docker compose version` succeeds.",
      retry,
    );
  }
  const composeVersion = validateSetupVersion(result.version, "Compose");
  runtime.stdout.write("✓ Docker Compose available\n");
  return { composeVersion, dockerVersion };
}

async function openGuidanceLink(runtime, link, noOpen) {
  runtime.throwIfInterrupted?.();
  if (noOpen) {
    runtime.stdout.write(`${link.label}: ${link.url}\n`);
    return false;
  }
  let opened = false;
  try {
    opened = await runtime.openUrl(link.url);
    runtime.throwIfInterrupted?.();
  } catch (error) {
    if (error instanceof FirstRunError) throw error;
    runtime.throwIfInterrupted?.();
    opened = false;
  }
  if (!opened) runtime.stdout.write(`${link.label}: ${link.url}\n`);
  return opened;
}

function writeChatGptPreparationPaused(runtime) {
  runtime.stdout.write(
    [
      "Setup paused before any runtime credential was requested.",
      "No new checkout-local software was installed by this paused step.",
      "Resume: ./actionproxy chatgpt",
      "The tunnel ID was not stored; paste it again when prompted.",
      "",
    ].join("\n"),
  );
}

async function prepareChatGptTunnelId(runtime, { links, noOpen, tunnelId }) {
  runtime.stdout.write(
    [
      "",
      "[ChatGPT preparation 1/2] OpenAI access",
      "Platform tunnel access and ChatGPT developer mode are separate:",
      "  • Run or select a tunnel: Tunnels Read + Use",
      "  • Create or edit a tunnel: Tunnels Read + Manage",
      "  • ChatGPT: developer mode enabled in the target workspace",
      "  • Association: the tunnel includes that ChatGPT workspace",
      `  Official OpenAI links reviewed ${links.reviewedAt}.`,
      "",
    ].join("\n"),
  );

  if (tunnelId) {
    runtime.stdout.write(
      "✓ Tunnel ID format accepted; tunnel configuration and control-plane access will be checked later. Confirm developer mode and app visibility in ChatGPT.\n",
    );
    return tunnelId;
  }
  if (!runtime.isTTY) {
    throw usageError("Provide --tunnel-id when input is not interactive.");
  }

  runtime.stdout.write(
    [
      "Paste an existing workspace-associated tunnel ID, or choose an action:",
      "  O  Open tunnel settings and show create/association steps",
      "  D  Open ChatGPT developer-mode guidance",
      "  A  Print an administrator access request",
      "  Q  Pause and resume later",
      "",
    ].join("\n"),
  );
  for (;;) {
    const answer = (
      await runtime.promptLine("Tunnel ID or action [O/D/A/Q]: ")
    ).trim();
    const action = answer.toLowerCase();
    if (action === "q") {
      writeChatGptPreparationPaused(runtime);
      return undefined;
    }
    if (action === "o") {
      runtime.stdout.write(
        [
          "In OpenAI Platform:",
          "  1. Select the intended Platform organization.",
          "  2. Choose an existing tunnel, or create one if you have Read + Manage.",
          "  3. Associate both the owning Platform organization and target ChatGPT workspace.",
          "  4. Copy the tunnel ID; it starts with tunnel_.",
        ].join("\n") + "\n",
      );
      await openGuidanceLink(runtime, links.links.tunnelSettings, noOpen);
      continue;
    }
    if (action === "d") {
      await openGuidanceLink(runtime, links.links.developerMode, noOpen);
      continue;
    }
    if (action === "a") {
      runtime.stdout.write(
        `\nAdministrator access request:\n${CHATGPT_ADMIN_ACCESS_REQUEST}\n\n`,
      );
      continue;
    }
    if (!answer) {
      runtime.stdout.write(
        "! No tunnel ID entered. Choose O for guided setup, A for admin help, or Q to pause.\n",
      );
      continue;
    }
    try {
      const validated = validateTunnelId(answer);
      runtime.stdout.write(
        "✓ Tunnel ID format accepted; tunnel configuration and control-plane access will be checked later. Confirm developer mode and app visibility in ChatGPT.\n",
      );
      return validated;
    } catch {
      runtime.stdout.write(
        "! Invalid tunnel ID. Expected `tunnel_` followed by 32 lowercase hexadecimal characters.\n",
      );
    }
  }
}

function tunnelClientFailure(runtime, result, links, retry, distribution) {
  const architecture =
    runtime.platform === "darwin"
      ? `darwin-${runtime.architecture === "x64" ? "amd64" : runtime.architecture}`
      : `${runtime.platform}-${runtime.architecture === "x64" ? "amd64" : runtime.architecture}`;
  const platformKey = tunnelClientPlatformKey(
    runtime.platform,
    runtime.architecture,
  );
  const reviewedAsset = distribution?.assets?.[platformKey];
  const asset =
    reviewedAsset?.name ??
    tunnelClientAsset(runtime.platform, runtime.architecture);
  const code = result.missing
    ? "TUNNEL_CLIENT_MISSING"
    : "TUNNEL_CLIENT_INCOMPATIBLE";
  const message = result.localNonExecutable
    ? "The checkout-local tunnel-client exists but is not executable."
    : result.managedInvalid
      ? "The ActionProxy-installed tunnel-client no longer matches its private ownership receipt."
      : result.missing
        ? `OpenAI tunnel-client was not found for ${architecture}.`
        : "The installed tunnel-client does not advertise required profile, file-secret, and health URL capabilities.";
  const reviewedPin = reviewedAsset
    ? ` ActionProxy's reviewed ${distribution.releaseTag} archive SHA-256 is ${reviewedAsset.archiveSha256}.`
    : "";
  const remedy = `Run \`./actionproxy tunnel-client install\` for the explicit checkout-local installer, or from ${links.links.tunnelClientReleases.url}, download ${asset ?? `the ${architecture} asset`} and SHA256SUMS.txt from the same release. Run \`shasum -a 256 ${asset ?? "<downloaded-asset>"}\` and compare all 64 hexadecimal characters with that asset's SHA256SUMS.txt line before extracting it.${reviewedPin} Then make tunnel-client executable and place it at .actionproxy/bin/tunnel-client or set TUNNEL_CLIENT_BIN. Keep quarantine metadata intact; ActionProxy does not run Gatekeeper override commands. Official link reviewed ${links.reviewedAt}.`;
  return operationalError(code, message, remedy, retry);
}

async function requireTunnelClient(
  runtime,
  retry,
  { links, noOpen = false } = {},
) {
  const officialLinks =
    links ?? readOpenAiLinks(runtime.fileSystem, runtime.repoRoot);
  const distribution = readTunnelClientDistribution(
    runtime.fileSystem,
    runtime.repoRoot,
  );
  runtime.stdout.write(
    [
      "",
      "[ChatGPT preparation 2/2] OpenAI tunnel-client",
      "○ Checking TUNNEL_CLIENT_BIN, .actionproxy/bin/tunnel-client, then PATH…",
    ].join("\n") + "\n",
  );
  let guidanceShown = false;
  for (;;) {
    const result = await inspectTunnelClient(runtime);
    if (result.ok) {
      runtime.stdout.write(
        result.managed
          ? `✓ ActionProxy-reviewed pinned tunnel-client ${result.version ?? ""} verified\n`
          : `✓ Capability-compatible unmanaged tunnel-client found (${result.source})\n`,
      );
      return result.executable;
    }
    const failure = tunnelClientFailure(
      runtime,
      result,
      officialLinks,
      retry,
      distribution,
    );
    if (!runtime.isTTY) throw failure;

    if (!guidanceShown) {
      const selectedSourceHelp =
        result.source === "environment"
          ? "TUNNEL_CLIENT_BIN is active. Enter rechecks that same path; press Q, change or unset the variable, and rerun to select another path."
          : result.localNonExecutable
            ? "The .actionproxy/bin/tunnel-client file must be executable before this launcher can use it. ActionProxy will not remove quarantine attributes or invoke Gatekeeper override commands."
            : "In-place recheck uses .actionproxy/bin/tunnel-client or a directory already present on this launcher's PATH.";
      const platformKey = tunnelClientPlatformKey(
        runtime.platform,
        runtime.architecture,
      );
      const reviewedAsset = distribution.assets[platformKey];
      const installPaths = tunnelClientInstallPaths(runtime.repoRoot);
      const installEligible = Boolean(
        reviewedAsset &&
        result.source !== "environment" &&
        result.source !== "checkout" &&
        !fileSystemEntryExists(runtime.fileSystem, installPaths.binary) &&
        !fileSystemEntryExists(runtime.fileSystem, installPaths.receipt),
      );
      runtime.stdout.write(
        [
          `! ${failure.message}`,
          selectedSourceHelp,
          reviewedAsset
            ? `ActionProxy can install its reviewed, pinned copy of OpenAI ${distribution.releaseTag} only in this checkout.`
            : undefined,
          reviewedAsset
            ? `  Download: ${formatBinarySize(reviewedAsset.archiveSize)}; installed: ${formatBinarySize(reviewedAsset.binarySize)}`
            : undefined,
          reviewedAsset
            ? "  Writes: .actionproxy/bin/tunnel-client plus a private ownership receipt"
            : undefined,
          reviewedAsset
            ? "  Remove: ./actionproxy tunnel-client remove"
            : undefined,
          installEligible
            ? "  I  Install locally now (recommended)"
            : undefined,
          "  M  Show manual setup",
          "  D  Show verification and signing details",
          "  O  Open the official release",
          "  C  Open configuration help",
          "  R  Recheck after a manual install (Enter also works)",
          "  Q  Pause",
          "Nothing downloads unless you choose I or explicitly run ./actionproxy tunnel-client install.",
          "",
        ].join("\n"),
      );
      guidanceShown = true;
    } else {
      runtime.stdout.write(`! ${failure.message}\n`);
    }

    let recheck = false;
    while (!recheck) {
      const installPaths = tunnelClientInstallPaths(runtime.repoRoot);
      const platformKey = tunnelClientPlatformKey(
        runtime.platform,
        runtime.architecture,
      );
      const reviewedAsset = distribution.assets[platformKey];
      const installEligible = Boolean(
        reviewedAsset &&
        result.source !== "environment" &&
        result.source !== "checkout" &&
        !fileSystemEntryExists(runtime.fileSystem, installPaths.binary) &&
        !fileSystemEntryExists(runtime.fileSystem, installPaths.receipt),
      );
      const action = (
        await runtime.promptLine(
          installEligible
            ? "Choose I, M, D, O, C, R/Enter, or Q: "
            : "Choose M, D, O, C, R/Enter, or Q: ",
        )
      )
        .trim()
        .toLowerCase();
      if (action === "q") {
        writeChatGptPreparationPaused(runtime);
        return undefined;
      }
      if (action === "o") {
        await openGuidanceLink(
          runtime,
          officialLinks.links.tunnelClientReleases,
          noOpen,
        );
        continue;
      }
      if (action === "c") {
        await openGuidanceLink(
          runtime,
          officialLinks.links.tunnelClientConfiguration,
          noOpen,
        );
        continue;
      }
      if (action === "m") {
        runtime.stdout.write(
          [
            "Manual setup:",
            `  1. Open ${officialLinks.links.tunnelClientReleases.url}`,
            `  2. Download ${reviewedAsset?.name ?? tunnelClientAsset(runtime.platform, runtime.architecture) ?? "the asset for this machine"} and SHA256SUMS.txt from the same release.`,
            `  3. Run \`shasum -a 256 ${reviewedAsset?.name ?? tunnelClientAsset(runtime.platform, runtime.architecture) ?? "<downloaded-asset>"}\` and compare all 64 hexadecimal characters.`,
            "  4. Extract it while keeping any macOS quarantine metadata intact.",
            "  5. Put the executable at .actionproxy/bin/tunnel-client, on the current PATH, or set TUNNEL_CLIENT_BIN before rerunning.",
            `  Configuration: ${officialLinks.links.tunnelClientConfiguration.url}`,
            "",
          ].join("\n"),
        );
        continue;
      }
      if (action === "d") {
        runtime.stdout.write(
          [
            "Verification details:",
            reviewedAsset
              ? `  Asset: ${reviewedAsset.name}`
              : "  No ActionProxy-reviewed asset is available for this platform.",
            reviewedAsset
              ? `  Archive SHA-256: ${reviewedAsset.archiveSha256}`
              : undefined,
            "  Checks: exact archive and binary hashes, Mach-O architecture, embedded signature integrity, version, and required capabilities",
            "  Scope: this is an artifact-integrity review, not a source-code security audit",
            "  macOS signing: the upstream binary is ad-hoc signed, not Developer ID-signed or notarized",
            "  ActionProxy does not invoke sudo, change PATH, remove quarantine attributes, or run Gatekeeper override commands.",
            "",
          ]
            .filter(Boolean)
            .join("\n") + "\n",
        );
        continue;
      }
      if (action === "i" && installEligible) {
        await installCheckoutTunnelClient(runtime, distribution, { retry });
        runtime.stdout.write(
          `✓ ActionProxy-reviewed pinned copy of OpenAI tunnel-client ${distribution.releaseTag} installed only in this checkout\n`,
        );
        recheck = true;
        continue;
      }
      if (action && action !== "r") {
        runtime.stdout.write(
          installEligible
            ? "! Choose I, M, D, O, C, R, Enter, or Q.\n"
            : "! Choose M, D, O, C, R, Enter, or Q.\n",
        );
        continue;
      }
      if (!action || action === "r") recheck = true;
    }
    runtime.stdout.write("○ Rechecking tunnel-client…\n");
  }
}

async function installCheckoutTunnelClient(
  runtime,
  distribution,
  { quiet = false, retry = "./actionproxy chatgpt" } = {},
) {
  runtime.throwIfInterrupted?.();
  const platformKey = tunnelClientPlatformKey(
    runtime.platform,
    runtime.architecture,
  );
  const asset = distribution.assets[platformKey];
  if (!asset) {
    throw operationalError(
      "TUNNEL_CLIENT_INSTALL_UNSUPPORTED",
      `The reviewed checkout-local installer does not support ${platformKey}.`,
      "Install tunnel-client manually from the official OpenAI release and set TUNNEL_CLIENT_BIN.",
      retry,
    );
  }

  const sessionId = runtime.uuid();
  if (!sessionPattern.test(sessionId)) {
    throw operationalError(
      "TUNNEL_CLIENT_INSTALL_FAILED",
      "The installer could not create a safe local session identifier.",
      "Retry from the unchanged checkout.",
      retry,
    );
  }
  const releaseLock = acquireLock(runtime, {
    journey: "tunnel-client-install",
    sessionId,
  });
  const installPaths = tunnelClientInstallPaths(runtime.repoRoot);
  let stageDirectory;
  let promoted = false;
  let promotedIdentity;
  try {
    const binaryExists = fileSystemEntryExists(
      runtime.fileSystem,
      installPaths.binary,
    );
    const receiptExists = fileSystemEntryExists(
      runtime.fileSystem,
      installPaths.receipt,
    );
    if (binaryExists) {
      const managedState = inspectManagedTunnelClient(runtime, distribution);
      if (managedState.managed && !managedState.invalid) {
        const existing = await inspectTunnelClientExecutable(
          runtime,
          installPaths.binary,
          "checkout",
        );
        if (existing.ok) {
          return {
            ...existing,
            managed: true,
            platformKey,
            reused: true,
          };
        }
      }
      throw operationalError(
        "TUNNEL_CLIENT_INSTALL_CONFLICT",
        "A checkout-local tunnel-client already exists and ActionProxy will not overwrite it.",
        managedState.managed
          ? "Inspect .actionproxy/bin/tunnel-client and its receipt; remove the modified managed copy explicitly before retrying."
          : "Keep the manually installed file, or move it yourself before running the reviewed installer.",
        retry,
      );
    }
    if (receiptExists) {
      throw operationalError(
        "TUNNEL_CLIENT_INSTALL_CONFLICT",
        "A tunnel-client ownership receipt exists without its managed binary.",
        "Run ./actionproxy tunnel-client remove to clear only the stale ActionProxy receipt, then retry.",
        retry,
      );
    }

    ensurePrivateDirectoryWithin(
      runtime.fileSystem,
      runtime.repoRoot,
      installPaths.directory,
    );
    stageDirectory = path.join(
      installPaths.directory,
      `.install-${randomBytes(12).toString("hex")}`,
    );
    ensurePrivateDirectoryWithin(
      runtime.fileSystem,
      runtime.repoRoot,
      stageDirectory,
    );
    const archivePath = path.join(stageDirectory, "download.zip");
    const candidatePath = path.join(stageDirectory, "tunnel-client");
    if (!quiet) {
      runtime.stdout.write(
        [
          `○ Installing ActionProxy-reviewed pinned copy of OpenAI tunnel-client ${distribution.releaseTag} in this checkout…`,
          `  Asset: ${asset.name}`,
          `  Official release: ${distribution.releaseUrl}`,
          "  Destination: .actionproxy/bin/tunnel-client",
          "  Scope: no sudo, no global PATH change, no quarantine removal, no Gatekeeper override, and no runtime key passed to verification processes",
          "  Trust: ActionProxy-reviewed pinned hashes; the upstream Mac binary is ad-hoc signed, not Developer ID/notarized",
          "",
        ].join("\n"),
      );
    }
    const archiveSha256 = await downloadPinnedTunnelClientArchive(
      runtime,
      asset,
      archivePath,
      retry,
    );
    runtime.throwIfInterrupted?.();
    if (archiveSha256 !== asset.archiveSha256) {
      throw operationalError(
        "TUNNEL_CLIENT_CHECKSUM_MISMATCH",
        "The downloaded tunnel-client archive did not match the reviewed SHA-256 pin.",
        "Do not run the download. Retry on a trusted network or use the documented manual checksum procedure.",
        retry,
      );
    }
    const archive = runtime.fileSystem.readFileSync(archivePath);
    const binary = extractSingleZipEntry(
      archive,
      distribution.archiveEntry,
      asset.binarySize,
    );
    const binarySha256 = createHash("sha256").update(binary).digest("hex");
    if (binarySha256 !== asset.binarySha256) {
      throw operationalError(
        "TUNNEL_CLIENT_CHECKSUM_MISMATCH",
        "The extracted tunnel-client did not match the reviewed binary SHA-256 pin.",
        "Do not run the file. Restore the distribution record and retry.",
        retry,
      );
    }
    runtime.throwIfInterrupted?.();
    assertMachOArchitecture(binary, platformKey, retry);
    runtime.fileSystem.writeFileSync(candidatePath, binary, {
      flag: "wx",
      mode: 0o700,
    });
    runtime.fileSystem.chmodSync?.(candidatePath, 0o700);
    assertSafeExecutableFile(
      runtime.fileSystem,
      runtime.repoRoot,
      candidatePath,
      asset.binarySize,
    );

    const signature = await probe(
      runtime,
      "/usr/bin/codesign",
      ["--verify", "--strict", candidatePath],
      tunnelClientProbeEnv(runtime.env),
    );
    runtime.throwIfInterrupted?.();
    if (!signature.ok) {
      throw operationalError(
        "TUNNEL_CLIENT_SIGNATURE_INVALID",
        "The reviewed tunnel-client failed its embedded code-signature integrity check.",
        "ActionProxy will not run a Gatekeeper override. Use the official manual installation path and report the release mismatch.",
        retry,
      );
    }
    const staged = await inspectTunnelClientExecutable(
      runtime,
      candidatePath,
      "checkout",
    );
    const rawVersion = await probe(runtime, candidatePath, ["--version"]);
    runtime.throwIfInterrupted?.();
    if (
      !staged.ok ||
      !rawVersion.ok ||
      !firstLine(rawVersion.version).includes(distribution.expectedVersion)
    ) {
      throw operationalError(
        "TUNNEL_CLIENT_INSTALL_INCOMPATIBLE",
        "The reviewed tunnel-client did not pass the required capability and version probes.",
        "Keep the existing checkout unchanged and review the official tunnel-client release notes.",
        retry,
      );
    }

    runtime.throwIfInterrupted?.();
    try {
      runtime.fileSystem.linkSync(candidatePath, installPaths.binary);
    } catch (error) {
      if (error?.code === "EEXIST") {
        throw operationalError(
          "TUNNEL_CLIENT_INSTALL_CONFLICT",
          "Another file appeared at the checkout-local tunnel-client destination.",
          "ActionProxy did not overwrite it. Inspect .actionproxy/bin/tunnel-client before retrying.",
          retry,
        );
      }
      throw error;
    }
    promoted = true;
    const promotedStats = runtime.fileSystem.lstatSync(candidatePath);
    promotedIdentity = {
      dev: promotedStats.dev,
      ino: promotedStats.ino,
    };
    runtime.fileSystem.chmodSync?.(installPaths.binary, 0o700);
    const receipt = {
      archiveSha256: asset.archiveSha256,
      assetName: asset.name,
      binarySha256: asset.binarySha256,
      binarySize: asset.binarySize,
      codeSignatureIntegrityVerified: true,
      installedAt: new Date(runtime.now()).toISOString(),
      platformKey,
      releaseTag: distribution.releaseTag,
      schemaVersion: TUNNEL_CLIENT_RECEIPT_SCHEMA_VERSION,
      source: "actionproxy-reviewed-release",
      version: distribution.expectedVersion,
    };
    try {
      runtime.throwIfInterrupted?.();
      writeJsonPrivateExclusive(
        runtime.fileSystem,
        runtime.repoRoot,
        installPaths.receipt,
        receipt,
      );
    } catch {
      throw operationalError(
        "TUNNEL_CLIENT_INSTALL_FAILED",
        "The tunnel-client passed verification, but its private ownership receipt could not be committed.",
        "ActionProxy will remove its newly linked binary. Inspect .actionproxy/bin only if cleanup is reported incomplete.",
        retry,
      );
    }
    // The binary plus exclusive receipt are the install commit point. The
    // staging hard link is removed by the contained finally cleanup.
    promoted = false;
    return {
      executable: installPaths.binary,
      managed: true,
      missing: false,
      ok: true,
      platformKey,
      reused: false,
      source: "checkout",
      version: staged.version,
    };
  } catch (error) {
    if (promoted) {
      try {
        const targetStats = runtime.fileSystem.lstatSync(installPaths.binary);
        if (
          targetStats.dev === promotedIdentity?.dev &&
          targetStats.ino === promotedIdentity?.ino
        ) {
          runtime.fileSystem.unlinkSync(installPaths.binary);
        }
      } catch (cleanupError) {
        if (cleanupError?.code !== "ENOENT") {
          throw operationalError(
            "TUNNEL_CLIENT_INSTALL_CLEANUP_FAILED",
            "Installation failed and ActionProxy could not confirm cleanup of its newly linked binary.",
            "Do not run .actionproxy/bin/tunnel-client; inspect the checkout-local file before retrying.",
            retry,
          );
        }
      }
    }
    if (error instanceof FirstRunError) throw error;
    throw operationalError(
      "TUNNEL_CLIENT_INSTALL_FAILED",
      "The checkout-local tunnel-client installation could not be completed safely.",
      "The existing checkout was not overwritten. Retry or use the documented manual installation path.",
      retry,
    );
  } finally {
    let cleanupFailed = false;
    if (stageDirectory && runtime.fileSystem.existsSync(stageDirectory)) {
      try {
        assertSafeRemovalTree(
          runtime.fileSystem,
          runtime.repoRoot,
          stageDirectory,
        );
        runtime.fileSystem.rmSync(stageDirectory, {
          force: true,
          recursive: true,
        });
      } catch {
        cleanupFailed = true;
      }
    }
    releaseLock();
    removeDirectoryIfEmptyWithin(
      runtime.fileSystem,
      runtime.repoRoot,
      firstRunPaths(runtime.repoRoot).root,
    );
    removeDirectoryIfEmptyWithin(
      runtime.fileSystem,
      runtime.repoRoot,
      installPaths.directory,
    );
    removeDirectoryIfEmptyWithin(
      runtime.fileSystem,
      runtime.repoRoot,
      path.join(runtime.repoRoot, ".actionproxy"),
    );
    if (cleanupFailed) {
      throw operationalError(
        "TUNNEL_CLIENT_INSTALL_CLEANUP_FAILED",
        "ActionProxy could not confirm removal of its temporary tunnel-client installer files.",
        "Inspect only .actionproxy/bin/.install-* before continuing.",
        retry,
      );
    }
  }
}

function removeCheckoutTunnelClient(runtime) {
  ensureNoLiveLock(runtime);
  const installPaths = tunnelClientInstallPaths(runtime.repoRoot);
  const binaryExists = fileSystemEntryExists(
    runtime.fileSystem,
    installPaths.binary,
  );
  const receiptExists = fileSystemEntryExists(
    runtime.fileSystem,
    installPaths.receipt,
  );
  if (!binaryExists && !receiptExists) return { removed: false };
  if (!receiptExists) {
    throw operationalError(
      "TUNNEL_CLIENT_REMOVE_UNOWNED",
      "The checkout-local tunnel-client has no ActionProxy ownership receipt.",
      "It may have been installed manually. ActionProxy will not remove it; inspect it yourself.",
      "./actionproxy tunnel-client status",
    );
  }
  let receipt;
  try {
    assertSafePrivateFile(
      runtime.fileSystem,
      runtime.repoRoot,
      installPaths.receipt,
    );
    receipt = validateTunnelClientReceiptShape(
      JSON.parse(runtime.fileSystem.readFileSync(installPaths.receipt, "utf8")),
    );
  } catch {
    throw operationalError(
      "TUNNEL_CLIENT_REMOVE_UNOWNED",
      "The tunnel-client ownership receipt is invalid, so removal was refused.",
      "Inspect .actionproxy/bin manually; ActionProxy will not delete an unverified file.",
      "./actionproxy tunnel-client status",
    );
  }
  if (binaryExists) {
    let verifiedIdentity;
    try {
      assertSafeExecutableFile(
        runtime.fileSystem,
        runtime.repoRoot,
        installPaths.binary,
        receipt.binarySize,
      );
      const beforeHash = runtime.fileSystem.lstatSync(installPaths.binary);
      if (
        sha256File(runtime.fileSystem, installPaths.binary) !==
        receipt.binarySha256
      ) {
        throw new Error("digest changed");
      }
      const afterHash = runtime.fileSystem.lstatSync(installPaths.binary);
      if (
        beforeHash.dev !== afterHash.dev ||
        beforeHash.ino !== afterHash.ino ||
        afterHash.size !== receipt.binarySize
      ) {
        throw new Error("file identity changed during verification");
      }
      verifiedIdentity = { dev: afterHash.dev, ino: afterHash.ino };
    } catch {
      throw operationalError(
        "TUNNEL_CLIENT_REMOVE_MODIFIED",
        "The managed tunnel-client no longer matches its ownership receipt.",
        "ActionProxy will not remove a changed file. Inspect .actionproxy/bin manually.",
        "./actionproxy tunnel-client status",
      );
    }
    let changedBeforeUnlink = false;
    try {
      const beforeUnlink = runtime.fileSystem.lstatSync(installPaths.binary);
      changedBeforeUnlink =
        beforeUnlink.dev !== verifiedIdentity.dev ||
        beforeUnlink.ino !== verifiedIdentity.ino;
    } catch {
      changedBeforeUnlink = true;
    }
    if (changedBeforeUnlink) {
      throw operationalError(
        "TUNNEL_CLIENT_REMOVE_MODIFIED",
        "The managed tunnel-client changed after verification, so removal was refused.",
        "Inspect .actionproxy/bin manually; ActionProxy did not delete the replacement.",
        "./actionproxy tunnel-client status",
      );
    }
    runtime.fileSystem.unlinkSync(installPaths.binary);
  }
  try {
    runtime.fileSystem.unlinkSync(installPaths.receipt);
    if (runtime.fileSystem.readdirSync(installPaths.directory).length === 0) {
      runtime.fileSystem.rmdirSync(installPaths.directory);
    }
    removeDirectoryIfEmptyWithin(
      runtime.fileSystem,
      runtime.repoRoot,
      path.join(runtime.repoRoot, ".actionproxy"),
    );
  } catch {
    throw operationalError(
      "TUNNEL_CLIENT_REMOVE_CLEANUP_FAILED",
      "The managed binary was removed, but its checkout-local receipt could not be fully cleaned up.",
      "Inspect .actionproxy/bin/tunnel-client.actionproxy.json before retrying.",
      "./actionproxy tunnel-client remove",
    );
  }
  return { removed: true };
}

async function downloadPinnedTunnelClientArchive(
  runtime,
  asset,
  destination,
  retry,
) {
  let interrupted = false;
  let timedOut = false;
  const controller = new AbortController();
  const interrupt = () => {
    interrupted = true;
    controller.abort();
  };
  runtime.signalEmitter.once("SIGINT", interrupt);
  runtime.signalEmitter.once("SIGTERM", interrupt);
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, TUNNEL_CLIENT_DOWNLOAD_TIMEOUT_MS);
  timeout.unref?.();
  let descriptor;
  try {
    let currentUrl = asset.url;
    let response;
    for (let redirectCount = 0; ; redirectCount += 1) {
      assertTrustedTunnelClientDownloadUrl(currentUrl, asset, redirectCount);
      response = await runtime.fetchFn(currentUrl, {
        headers: {
          accept: "application/octet-stream",
          "user-agent": `ActionProxy-First-Run/${FIRST_RUN_VERSION}`,
        },
        redirect: "manual",
        signal: controller.signal,
      });
      runtime.throwIfInterrupted?.();
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        if (redirectCount >= TUNNEL_CLIENT_REDIRECT_LIMIT) {
          throw operationalError(
            "TUNNEL_CLIENT_DOWNLOAD_UNTRUSTED",
            "The tunnel-client download exceeded the redirect limit.",
            "Use the official release page and manual checksum procedure.",
            retry,
          );
        }
        const location = response.headers?.get?.("location");
        if (!location) {
          throw operationalError(
            "TUNNEL_CLIENT_DOWNLOAD_FAILED",
            "The official download returned a redirect without a destination.",
            "Retry or use the official manual installation path.",
            retry,
          );
        }
        currentUrl = new URL(location, currentUrl).toString();
        continue;
      }
      break;
    }
    if (response.status !== 200) {
      throw operationalError(
        "TUNNEL_CLIENT_DOWNLOAD_FAILED",
        `The official tunnel-client download returned HTTP ${response.status}.`,
        "Check network access to GitHub Releases, then retry or use the manual path.",
        retry,
      );
    }
    const contentLength = response.headers?.get?.("content-length");
    if (
      contentLength !== null &&
      contentLength !== undefined &&
      (!/^\d+$/u.test(contentLength) ||
        Number(contentLength) !== asset.archiveSize)
    ) {
      throw operationalError(
        "TUNNEL_CLIENT_DOWNLOAD_SIZE_MISMATCH",
        "The official tunnel-client download reported an unexpected size.",
        "Do not use the response. Retry or follow the manual checksum procedure.",
        retry,
      );
    }
    descriptor = runtime.fileSystem.openSync(destination, "wx", 0o600);
    runtime.fileSystem.chmodSync?.(destination, 0o600);
    const digest = createHash("sha256");
    let total = 0;
    for await (const chunk of responseBodyChunks(response)) {
      runtime.throwIfInterrupted?.();
      const bytes = Buffer.from(chunk);
      total += bytes.length;
      if (
        total > asset.archiveSize ||
        total > TUNNEL_CLIENT_ARCHIVE_MAX_BYTES
      ) {
        throw operationalError(
          "TUNNEL_CLIENT_DOWNLOAD_SIZE_MISMATCH",
          "The tunnel-client download exceeded its reviewed size.",
          "Do not use the response. Retry or follow the manual checksum procedure.",
          retry,
        );
      }
      runtime.fileSystem.writeSync(descriptor, bytes);
      digest.update(bytes);
    }
    if (total !== asset.archiveSize) {
      throw operationalError(
        "TUNNEL_CLIENT_DOWNLOAD_SIZE_MISMATCH",
        "The tunnel-client download ended at an unexpected size.",
        "Retry or follow the manual checksum procedure.",
        retry,
      );
    }
    return digest.digest("hex");
  } catch (error) {
    if (interrupted) {
      throw new FirstRunError(
        "INTERRUPTED",
        "Tunnel-client installation cancelled by the user.",
        { exitCode: 0 },
      );
    }
    if (timedOut) {
      throw operationalError(
        "TUNNEL_CLIENT_DOWNLOAD_TIMEOUT",
        "The tunnel-client download did not finish within 30 seconds.",
        "Check the network, then retry or use the official manual installation path.",
        retry,
      );
    }
    if (error instanceof FirstRunError) throw error;
    throw operationalError(
      "TUNNEL_CLIENT_DOWNLOAD_FAILED",
      "ActionProxy could not download the reviewed tunnel-client asset.",
      "Check network access to GitHub Releases, then retry or use the manual installation path.",
      retry,
    );
  } finally {
    clearTimeout(timeout);
    runtime.signalEmitter.removeListener("SIGINT", interrupt);
    runtime.signalEmitter.removeListener("SIGTERM", interrupt);
    if (descriptor !== undefined) runtime.fileSystem.closeSync(descriptor);
  }
}

async function* responseBodyChunks(response) {
  if (response.body?.[Symbol.asyncIterator]) {
    yield* response.body;
    return;
  }
  if (typeof response.arrayBuffer === "function") {
    yield Buffer.from(await response.arrayBuffer());
    return;
  }
  throw new Error("download response has no readable body");
}

function assertTrustedTunnelClientDownloadUrl(value, asset, redirectCount) {
  let url;
  try {
    url = new URL(value);
  } catch {
    url = undefined;
  }
  const isInitial = redirectCount === 0;
  if (
    !url ||
    url.protocol !== "https:" ||
    (url.port !== "" && url.port !== "443") ||
    url.username ||
    url.password ||
    !TUNNEL_CLIENT_REDIRECT_HOSTS.has(url.hostname) ||
    (isInitial && url.toString() !== asset.url) ||
    (!isInitial &&
      url.hostname === "github.com" &&
      url.toString() !== asset.url)
  ) {
    throw operationalError(
      "TUNNEL_CLIENT_DOWNLOAD_UNTRUSTED",
      "The tunnel-client download attempted an untrusted URL or redirect.",
      "Use the official release page and manual checksum procedure.",
      "./actionproxy tunnel-client install",
    );
  }
}

export function extractSingleZipEntry(archive, expectedEntry, expectedSize) {
  const bytes = Buffer.from(archive);
  const invalid = () =>
    operationalError(
      "TUNNEL_CLIENT_ARCHIVE_INVALID",
      "The reviewed tunnel-client archive structure is invalid.",
      "Do not run it. Retry or use the official manual checksum procedure.",
      "./actionproxy tunnel-client install",
    );
  if (bytes.length < 22 || expectedEntry !== "tunnel-client") throw invalid();
  const end = bytes.length - 22;
  if (
    bytes.readUInt32LE(end) !== 0x06054b50 ||
    bytes.readUInt16LE(end + 4) !== 0 ||
    bytes.readUInt16LE(end + 6) !== 0 ||
    bytes.readUInt16LE(end + 8) !== 1 ||
    bytes.readUInt16LE(end + 10) !== 1 ||
    bytes.readUInt16LE(end + 20) !== 0
  ) {
    throw invalid();
  }
  const centralSize = bytes.readUInt32LE(end + 12);
  const centralOffset = bytes.readUInt32LE(end + 16);
  if (
    centralOffset + centralSize !== end ||
    centralOffset + 46 > end ||
    bytes.readUInt32LE(centralOffset) !== 0x02014b50
  ) {
    throw invalid();
  }
  const flags = bytes.readUInt16LE(centralOffset + 8);
  const compression = bytes.readUInt16LE(centralOffset + 10);
  const compressedSize = bytes.readUInt32LE(centralOffset + 20);
  const uncompressedSize = bytes.readUInt32LE(centralOffset + 24);
  const nameLength = bytes.readUInt16LE(centralOffset + 28);
  const extraLength = bytes.readUInt16LE(centralOffset + 30);
  const commentLength = bytes.readUInt16LE(centralOffset + 32);
  const diskStart = bytes.readUInt16LE(centralOffset + 34);
  const externalAttributes = bytes.readUInt32LE(centralOffset + 38);
  const localOffset = bytes.readUInt32LE(centralOffset + 42);
  const centralEnd =
    centralOffset + 46 + nameLength + extraLength + commentLength;
  const entryName = bytes
    .subarray(centralOffset + 46, centralOffset + 46 + nameLength)
    .toString("utf8");
  const unixMode = externalAttributes >>> 16;
  if (
    centralEnd !== end ||
    entryName !== expectedEntry ||
    diskStart !== 0 ||
    (flags & 0x0009) !== 0 ||
    ![0, 8].includes(compression) ||
    uncompressedSize !== expectedSize ||
    expectedSize < 1 ||
    expectedSize > TUNNEL_CLIENT_BINARY_MAX_BYTES ||
    (unixMode & 0o170000) !== 0o100000 ||
    localOffset + 30 > centralOffset ||
    bytes.readUInt32LE(localOffset) !== 0x04034b50
  ) {
    throw invalid();
  }
  const localFlags = bytes.readUInt16LE(localOffset + 6);
  const localCompression = bytes.readUInt16LE(localOffset + 8);
  const localCompressedSize = bytes.readUInt32LE(localOffset + 18);
  const localUncompressedSize = bytes.readUInt32LE(localOffset + 22);
  const localNameLength = bytes.readUInt16LE(localOffset + 26);
  const localExtraLength = bytes.readUInt16LE(localOffset + 28);
  const localName = bytes
    .subarray(localOffset + 30, localOffset + 30 + localNameLength)
    .toString("utf8");
  const dataStart = localOffset + 30 + localNameLength + localExtraLength;
  const dataEnd = dataStart + compressedSize;
  if (
    localFlags !== flags ||
    localCompression !== compression ||
    localCompressedSize !== compressedSize ||
    localUncompressedSize !== uncompressedSize ||
    localName !== expectedEntry ||
    dataEnd !== centralOffset
  ) {
    throw invalid();
  }
  try {
    const compressed = bytes.subarray(dataStart, dataEnd);
    const result =
      compression === 0
        ? Buffer.from(compressed)
        : inflateRawSync(compressed, { maxOutputLength: expectedSize });
    if (result.length !== expectedSize) throw invalid();
    return result;
  } catch (error) {
    if (error instanceof FirstRunError) throw error;
    throw invalid();
  }
}

function assertMachOArchitecture(binary, platformKey, retry) {
  const expectedCpuType = {
    "darwin-amd64": 0x01000007,
    "darwin-arm64": 0x0100000c,
  }[platformKey];
  if (
    !expectedCpuType ||
    binary.length < 8 ||
    binary.readUInt32LE(0) !== 0xfeedfacf ||
    binary.readUInt32LE(4) !== expectedCpuType
  ) {
    throw operationalError(
      "TUNNEL_CLIENT_ARCHITECTURE_MISMATCH",
      "The extracted tunnel-client is not the reviewed Mach-O architecture for this Mac.",
      "Do not run it. Restore the distribution record and retry.",
      retry,
    );
  }
}

async function inspectTunnelClient(runtime, { distribution } = {}) {
  const installPaths = tunnelClientInstallPaths(runtime.repoRoot);
  const local = installPaths.binary;
  let executable = runtime.env.TUNNEL_CLIENT_BIN?.trim();
  let localNonExecutable = false;
  let source = executable ? "environment" : undefined;
  let managed = false;
  let managedInvalid = false;
  if (
    !executable &&
    fileSystemEntryExists(runtime.fileSystem, installPaths.receipt) &&
    !fileSystemEntryExists(runtime.fileSystem, local)
  ) {
    return {
      executable: local,
      managed: true,
      managedInvalid: true,
      missing: false,
      ok: false,
      platformKey: tunnelClientPlatformKey(
        runtime.platform,
        runtime.architecture,
      ),
      source: "checkout",
    };
  }
  if (!executable && fileSystemEntryExists(runtime.fileSystem, local)) {
    const managedState = inspectManagedTunnelClient(
      runtime,
      distribution ??
        readTunnelClientDistribution(runtime.fileSystem, runtime.repoRoot),
    );
    managed = managedState.managed;
    managedInvalid = managedState.invalid;
    if (managedInvalid) {
      return {
        executable: local,
        managed,
        managedInvalid: true,
        missing: false,
        ok: false,
        platformKey: managedState.platformKey,
        source: "checkout",
      };
    }
    try {
      runtime.fileSystem.accessSync(
        local,
        runtime.fileSystem.constants?.X_OK ?? fs.constants.X_OK,
      );
      executable = local;
      source = "checkout";
    } catch {
      executable = local;
      localNonExecutable = true;
      source = "checkout";
    }
  }
  if (!executable) {
    executable = "tunnel-client";
    source = "path";
  }
  if (localNonExecutable) {
    return {
      executable,
      localNonExecutable: true,
      managed,
      missing: false,
      ok: false,
      platformKey: tunnelClientPlatformKey(
        runtime.platform,
        runtime.architecture,
      ),
      source,
    };
  }
  const result = await inspectTunnelClientExecutable(
    runtime,
    executable,
    source,
  );
  return {
    ...result,
    managed,
    platformKey: tunnelClientPlatformKey(
      runtime.platform,
      runtime.architecture,
    ),
  };
}

async function inspectTunnelClientExecutable(runtime, executable, source) {
  const environment = tunnelClientProbeEnv(runtime.env);
  const quickstart = await probe(
    runtime,
    executable,
    ["help", "quickstart"],
    environment,
  );
  if (!quickstart.ok)
    return {
      executable,
      missing: quickstart.missing,
      ok: false,
      source,
    };
  const runHelp = await probe(
    runtime,
    executable,
    ["run", "--help"],
    environment,
  );
  let version = await probe(runtime, executable, ["--version"], environment);
  let parsedVersion = version.ok
    ? extractSemanticVersion(version.version)
    : null;
  if (!parsedVersion) {
    version = await probe(runtime, executable, ["version"], environment);
    parsedVersion = version.ok ? extractSemanticVersion(version.version) : null;
  }
  const help = `${quickstart.version}\n${runHelp.version}`;
  const capabilities = [
    /--profile/u,
    /--profile-dir/u,
    /--control-plane\.api-key/u,
    /file:/u,
    /--health\.listen-addr/u,
    /--health\.url-file/u,
  ];
  return {
    executable,
    missing: false,
    ok: runHelp.ok && capabilities.every((pattern) => pattern.test(help)),
    source,
    version: parsedVersion,
  };
}

function inspectManagedTunnelClient(runtime, distribution) {
  const installPaths = tunnelClientInstallPaths(runtime.repoRoot);
  const receiptPresent = fileSystemEntryExists(
    runtime.fileSystem,
    installPaths.receipt,
  );
  if (!receiptPresent) {
    return {
      invalid: false,
      managed: false,
      platformKey: tunnelClientPlatformKey(
        runtime.platform,
        runtime.architecture,
      ),
    };
  }
  try {
    assertSafePrivateFile(
      runtime.fileSystem,
      runtime.repoRoot,
      installPaths.receipt,
    );
    const receipt = JSON.parse(
      runtime.fileSystem.readFileSync(installPaths.receipt, "utf8"),
    );
    validateTunnelClientReceipt(receipt, distribution);
    if (
      receipt.platformKey !==
      tunnelClientPlatformKey(runtime.platform, runtime.architecture)
    ) {
      throw new Error("managed binary platform does not match this process");
    }
    if (!fileSystemEntryExists(runtime.fileSystem, installPaths.binary)) {
      throw new Error("managed binary is missing");
    }
    assertSafeExecutableFile(
      runtime.fileSystem,
      runtime.repoRoot,
      installPaths.binary,
      distribution.assets[receipt.platformKey].binarySize,
    );
    const binarySha256 = sha256File(runtime.fileSystem, installPaths.binary);
    if (binarySha256 !== receipt.binarySha256) {
      throw new Error("managed binary digest changed");
    }
    return {
      invalid: false,
      managed: true,
      platformKey: receipt.platformKey,
      receipt,
    };
  } catch {
    return {
      invalid: true,
      managed: true,
      platformKey: tunnelClientPlatformKey(
        runtime.platform,
        runtime.architecture,
      ),
    };
  }
}

function validateTunnelClientReceiptShape(receipt) {
  const keys = [
    "archiveSha256",
    "assetName",
    "binarySha256",
    "binarySize",
    "codeSignatureIntegrityVerified",
    "installedAt",
    "platformKey",
    "releaseTag",
    "schemaVersion",
    "source",
    "version",
  ];
  const actualKeys = Object.keys(receipt ?? {}).sort();
  const installedAt = new Date(receipt?.installedAt ?? "");
  if (
    actualKeys.length !== keys.length ||
    actualKeys.some((key, index) => key !== [...keys].sort()[index]) ||
    receipt.schemaVersion !== TUNNEL_CLIENT_RECEIPT_SCHEMA_VERSION ||
    receipt.source !== "actionproxy-reviewed-release" ||
    !/^v(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}$/u.test(
      receipt.releaseTag ?? "",
    ) ||
    !/^darwin-(?:amd64|arm64)$/u.test(receipt.platformKey ?? "") ||
    receipt.assetName !==
      `tunnel-client-${receipt.releaseTag}-${receipt.platformKey}.zip` ||
    !new RegExp(
      `^${receipt.releaseTag.slice(1).replaceAll(".", "\\.")}\\+[0-9a-f]{40}$`,
      "u",
    ).test(receipt.version ?? "") ||
    !sha256Pattern.test(receipt.archiveSha256 ?? "") ||
    !sha256Pattern.test(receipt.binarySha256 ?? "") ||
    !Number.isSafeInteger(receipt.binarySize) ||
    receipt.binarySize < 1 ||
    receipt.binarySize > TUNNEL_CLIENT_BINARY_MAX_BYTES ||
    receipt.codeSignatureIntegrityVerified !== true ||
    Number.isNaN(installedAt.getTime()) ||
    installedAt.toISOString() !== receipt.installedAt
  ) {
    throw new Error("invalid tunnel-client install receipt");
  }
  return receipt;
}

function validateTunnelClientReceipt(receipt, distribution) {
  validateTunnelClientReceiptShape(receipt);
  const asset = distribution.assets?.[receipt.platformKey];
  if (
    !asset ||
    receipt.releaseTag !== distribution.releaseTag ||
    receipt.version !== distribution.expectedVersion ||
    receipt.assetName !== asset.name ||
    receipt.archiveSha256 !== asset.archiveSha256 ||
    receipt.binarySha256 !== asset.binarySha256 ||
    receipt.binarySize !== asset.binarySize
  ) {
    throw new Error("tunnel-client receipt does not match this distribution");
  }
  return receipt;
}

async function discoverTools(runtime, { compose, dockerEnvironment, retry }) {
  const doctor = await checked(runtime, {
    args: [
      ...compose,
      "exec",
      "-T",
      "actionproxy",
      "node",
      "packages/mcp-wrapper/dist/index.js",
      "doctor",
      "--config",
      "examples/chatgpt-tunnel/actionproxy.mcp.yaml",
      "--discover",
      "--json",
    ],
    code: "TOOL_DISCOVERY_FAILED",
    env: dockerEnvironment,
    executable: "docker",
    message: "ActionProxy MCP wrapper discovery failed.",
    remedy:
      "Rebuild the Community image and inspect the MCP wrapper diagnostics.",
    retry,
  });
  validateDoctorReport(doctor.stdout);
  runtime.stdout.write(
    `✓ Exactly ${EXPECTED_DEMO_TOOLS.length} mock tools discovered\n`,
  );
}

async function verifyContainer(
  runtime,
  { compose, dockerEnvironment, port, retry },
) {
  const environment = await checked(runtime, {
    args: [
      ...compose,
      "exec",
      "-T",
      "actionproxy",
      "node",
      "-e",
      "process.stdout.write(JSON.stringify({storage:process.env.ACTIONPROXY_STORAGE,quickstart:process.env.ACTIONPROXY_QUICKSTART_MODE}))",
    ],
    code: "CONTAINER_CONFIG_INVALID",
    env: dockerEnvironment,
    executable: "docker",
    message: "Could not verify the ActionProxy container configuration.",
    remedy: "Rebuild the Community image.",
    retry,
  });
  let config;
  try {
    config = JSON.parse(environment.stdout);
  } catch {
    config = {};
  }
  if (config.storage !== "sqlite") {
    throw operationalError(
      "STORAGE_NOT_SQLITE",
      "The guided container is not using SQLite.",
      "Use the current bundled docker-compose.yml and rebuild.",
      retry,
    );
  }
  if (config.quickstart !== "true") {
    throw operationalError(
      "QUICKSTART_MODE_DISABLED",
      "The bundled container did not enable local Quickstart mode.",
      "Use the current bundled docker-compose.yml and rebuild.",
      retry,
    );
  }
  const container = await checked(runtime, {
    args: [...compose, "ps", "-q", "actionproxy"],
    code: "CONTAINER_NOT_FOUND",
    env: dockerEnvironment,
    executable: "docker",
    message: "Could not resolve the concierge-owned ActionProxy container.",
    remedy: "Run ./actionproxy stop, then retry.",
    retry,
  });
  const containerId = container.stdout.trim();
  if (!/^[a-f0-9]{12,64}$/u.test(containerId)) {
    throw operationalError(
      "CONTAINER_NOT_FOUND",
      "Docker returned an invalid ActionProxy container identifier.",
      "Run ./actionproxy stop, then retry.",
      retry,
    );
  }
  const bindings = await checked(runtime, {
    args: [
      "inspect",
      "--format",
      "{{json .HostConfig.PortBindings}}",
      containerId,
    ],
    code: "LOOPBACK_BINDING_INVALID",
    env: dockerEnvironment,
    executable: "docker",
    message: "Could not verify the gateway host binding.",
    remedy:
      "Do not continue unless Docker publishes ActionProxy only on 127.0.0.1.",
    retry,
  });
  let published;
  try {
    published = JSON.parse(bindings.stdout)?.["8787/tcp"];
  } catch {
    published = undefined;
  }
  // Docker retains the requested HostPort "0" in HostConfig after assigning a
  // real ephemeral port. The preceding `docker compose port` result proves the
  // live port; HostConfig independently proves that publication was requested
  // only on loopback. Explicit ports retain their numeric value here.
  if (
    !Array.isArray(published) ||
    published.length !== 1 ||
    published[0]?.HostIp !== "127.0.0.1" ||
    !["0", String(port)].includes(String(published[0]?.HostPort))
  ) {
    throw operationalError(
      "LOOPBACK_BINDING_INVALID",
      "ActionProxy is not published on exactly one 127.0.0.1 port.",
      "Stop the container and restore the bundled loopback-only Compose configuration.",
      retry,
    );
  }
  runtime.stdout.write(
    "✓ Gateway healthy, loopback-only, with SQLite audit storage\n",
  );
}

async function verifyDockerHasNoRuntimeKey(
  runtime,
  { compose, dockerEnvironment, runtimeKey, retry },
) {
  const rendered = await checked(runtime, {
    args: [...compose, "config"],
    code: "CONTAINER_CONFIG_INVALID",
    env: dockerEnvironment,
    executable: "docker",
    message: "Could not render the sanitized Docker Compose configuration.",
    remedy:
      "Do not continue until `docker compose config` succeeds without runtime credentials.",
    retry,
    secrets: [runtimeKey],
  });
  if (
    rendered.stdout.includes(runtimeKey) ||
    /(?:ACTIONPROXY_CONTROL_PLANE_KEY_FILE|ACTIONPROXY_LEGACY_RUNTIME_KEY_FD|CONTROL_PLANE_API_KEY|OPENAI_API_KEY)\s*:/u.test(
      rendered.stdout,
    )
  ) {
    throw operationalError(
      "RUNTIME_KEY_IN_DOCKER",
      "The OpenAI runtime key or a key-bearing variable reached the rendered Docker Compose configuration.",
      "Stop the concierge project and remove the affected container before retrying.",
      "./actionproxy stop",
    );
  }
  const container = await checked(runtime, {
    args: [...compose, "ps", "-q", "actionproxy"],
    code: "CONTAINER_NOT_FOUND",
    env: dockerEnvironment,
    executable: "docker",
    message:
      "Could not resolve the ActionProxy container for the runtime-key boundary check.",
    remedy: "Stop and restart the guided journey.",
    retry,
    secrets: [runtimeKey],
  });
  const inspected = await checked(runtime, {
    args: [
      "inspect",
      "--format",
      "{{json .Config.Env}}",
      container.stdout.trim(),
    ],
    code: "CONTAINER_CONFIG_INVALID",
    env: dockerEnvironment,
    executable: "docker",
    message: "Could not verify the Docker credential boundary.",
    remedy: "Do not continue until Docker inspection succeeds.",
    retry,
    secrets: [runtimeKey],
  });
  if (
    inspected.stdout.includes(runtimeKey) ||
    /(?:ACTIONPROXY_CONTROL_PLANE_KEY_FILE|ACTIONPROXY_LEGACY_RUNTIME_KEY_FD|CONTROL_PLANE_API_KEY|OPENAI_API_KEY)=/u.test(
      inspected.stdout,
    )
  ) {
    throw operationalError(
      "RUNTIME_KEY_IN_DOCKER",
      "The OpenAI runtime key or a key-bearing variable reached Docker.",
      "Stop the concierge project and remove the affected container before retrying.",
      "./actionproxy stop",
    );
  }
  runtime.stdout.write("✓ Runtime key excluded from Docker\n");
}

async function waitForGateway(runtime, url, retry) {
  const deadline = runtime.now() + 120_000;
  let last = "no response";
  while (runtime.now() < deadline) {
    try {
      const response = await runtime.fetchFn(url, {
        signal: AbortSignal.timeout(2_000),
      });
      const body = response.ok ? await response.json() : undefined;
      runtime.throwIfInterrupted?.();
      if (response.ok && body?.ok === true) return;
      last = `HTTP ${response.status}`;
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    await runtime.sleep(500);
  }
  throw operationalError(
    "GATEWAY_UNHEALTHY",
    `ActionProxy did not become healthy (${sanitizeDetail(last)}).`,
    "Open Docker Desktop logs for the concierge-owned container.",
    retry,
  );
}

async function waitForTunnelReadiness(runtime, urlFile, tunnelPromise, retry) {
  const deadline = runtime.now() + 60_000;
  let last = "health URL not published";
  let settled;
  void tunnelPromise.then(
    (result) => {
      settled = result;
    },
    (error) => {
      settled = { error };
    },
  );
  while (runtime.now() < deadline) {
    if (settled) {
      if (settled.error) throw settled.error;
      if (settled.interrupted) {
        throw new FirstRunError(
          "INTERRUPTED",
          "First Run cancelled by the user.",
          { exitCode: 0 },
        );
      }
      throw operationalError(
        "TUNNEL_NOT_READY",
        `tunnel-client exited before readiness (exit ${settled.code ?? "unknown"}).`,
        "Run tunnel-client doctor --explain and inspect its local UI.",
        retry,
      );
    }
    try {
      if (runtime.fileSystem.existsSync(urlFile)) {
        const origin = validateTunnelHealthUrl(
          runtime.fileSystem.readFileSync(urlFile, "utf8"),
        );
        const response = await runtime.fetchFn(`${origin}/readyz`, {
          signal: AbortSignal.timeout(2_000),
        });
        runtime.throwIfInterrupted?.();
        if (response.ok) return origin;
        last = `HTTP ${response.status}`;
      }
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    await runtime.sleep(250);
  }
  throw operationalError(
    "TUNNEL_NOT_READY",
    `Secure tunnel did not become ready (${sanitizeDetail(last)}).`,
    "Run tunnel-client doctor --explain and inspect the tunnel-client output.",
    retry,
  );
}

async function publishStatus(
  runtime,
  baseUrl,
  token,
  snapshot,
  { afterInterrupt = false, bestEffort = false } = {},
) {
  try {
    const fetchStatus =
      afterInterrupt && runtime.fetchAfterInterrupt
        ? runtime.fetchAfterInterrupt
        : runtime.fetchFn;
    const response = await fetchStatus(
      `${baseUrl}/v1/demo/quickstart/status/${snapshot.sessionId}`,
      {
        body: JSON.stringify(snapshot),
        headers: {
          "content-type": "application/json",
          "x-actionproxy-quickstart-token": token,
        },
        method: "PUT",
        signal: AbortSignal.timeout(2_000),
      },
    );
    if (!afterInterrupt) runtime.throwIfInterrupted?.();
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
  } catch (error) {
    if (!afterInterrupt) runtime.throwIfInterrupted?.();
    if (bestEffort) return;
    throw operationalError(
      "QUICKSTART_STATUS_FAILED",
      `The local Quickstart status channel rejected an update (${sanitizeDetail(error.message)}).`,
      "Rebuild the current Community image so the CLI and local console match.",
      `./actionproxy ${snapshot.journey}`,
    );
  }
}

async function inspectExistingGateway(runtime, state) {
  const fallback = {
    healthy: false,
    loopbackOnly: false,
    port: state.port ?? null,
    storageMode: null,
    toolNames: [],
  };
  if (!projectPattern.test(state.projectName) || !Number.isInteger(state.port))
    return fallback;
  const environment = dockerEnv(runtime.env, {
    journey: state.journey,
    port: state.port,
    sessionId: state.sessionId,
    updateToken: "actionproxy-status-placeholder",
    originToken: "actionproxy-status-origin-placeholder",
  });
  const compose = composeArgs(state.projectName);
  const running = await probe(
    runtime,
    "docker",
    [...compose, "ps", "--status", "running", "-q", "actionproxy"],
    environment,
  );
  if (!running.ok || !/^[a-f0-9]{12,64}$/u.test(running.version.trim()))
    return fallback;
  const containerId = running.version.trim();
  try {
    const response = await runtime.fetchFn(`${state.baseUrl}/health`, {
      signal: AbortSignal.timeout(2_000),
    });
    if (!response.ok || (await response.json()).ok !== true) return fallback;
  } catch {
    return fallback;
  }
  const published = await probe(
    runtime,
    "docker",
    [...compose, "port", "actionproxy", "8787"],
    environment,
  );
  let loopbackOnly = false;
  try {
    loopbackOnly =
      published.ok && parseComposePort(published.version) === state.port;
  } catch {
    /* false */
  }
  const binding = await probe(
    runtime,
    "docker",
    ["inspect", "--format", "{{json .HostConfig.PortBindings}}", containerId],
    environment,
  );
  if (binding.ok) {
    try {
      const host = JSON.parse(binding.version)?.["8787/tcp"];
      // See verifyContainer: automatic publication remains "0" in HostConfig.
      loopbackOnly =
        loopbackOnly &&
        Array.isArray(host) &&
        host.length === 1 &&
        host[0]?.HostIp === "127.0.0.1" &&
        ["0", String(state.port)].includes(String(host[0]?.HostPort));
    } catch {
      loopbackOnly = false;
    }
  } else {
    loopbackOnly = false;
  }
  let storageMode = null;
  const config = await probe(
    runtime,
    "docker",
    [
      ...compose,
      "exec",
      "-T",
      "actionproxy",
      "node",
      "-e",
      'process.stdout.write(process.env.ACTIONPROXY_STORAGE||"")',
    ],
    environment,
  );
  if (
    config.ok &&
    ["memory", "sqlite", "postgres"].includes(config.version.trim())
  )
    storageMode = config.version.trim();
  let toolNames = [];
  const discovery = await probe(
    runtime,
    "docker",
    [
      ...compose,
      "exec",
      "-T",
      "actionproxy",
      "node",
      "packages/mcp-wrapper/dist/index.js",
      "doctor",
      "--config",
      "examples/chatgpt-tunnel/actionproxy.mcp.yaml",
      "--discover",
      "--json",
    ],
    environment,
  );
  if (discovery.ok) {
    try {
      validateDoctorReport(discovery.version);
      toolNames = [...EXPECTED_DEMO_TOOLS];
    } catch {
      /* retain empty allowlisted value */
    }
  }
  return {
    healthy: true,
    loopbackOnly,
    port: state.port,
    storageMode,
    toolNames,
  };
}

function acquireLock(runtime, owner) {
  const paths = firstRunPaths(runtime.repoRoot);
  ensurePrivateDirectoryWithin(
    runtime.fileSystem,
    runtime.repoRoot,
    paths.root,
  );
  try {
    runtime.fileSystem.mkdirSync(paths.lockDirectory, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    assertSafeDirectory(
      runtime.fileSystem,
      runtime.repoRoot,
      paths.lockDirectory,
    );
    const existing = readLockOwner(runtime.fileSystem, paths.lockOwner);
    if (!existing) {
      throw operationalError(
        "FIRST_RUN_LOCK_UNOWNED",
        "The First Run lock exists without a valid process owner.",
        "Do not clear a newly created lock. If no launcher is active, inspect .actionproxy/first-run/active.lock and remove it manually.",
        "./actionproxy status",
      );
    }
    if (existing && processIsAlive(runtime, existing.pid)) {
      throw operationalError(
        "FIRST_RUN_BUSY",
        `Another First Run launcher is active (PID ${existing.pid}).`,
        "Return to that terminal or stop its tunnel before starting another journey.",
        "./actionproxy status",
      );
    }
    removeOwnedLockDirectory(runtime.fileSystem, runtime.repoRoot, paths);
    runtime.fileSystem.mkdirSync(paths.lockDirectory, { mode: 0o700 });
  }
  runtime.fileSystem.chmodSync?.(paths.lockDirectory, 0o700);
  writeJsonPrivate(runtime.fileSystem, runtime.repoRoot, paths.lockOwner, {
    journey: owner.journey,
    pid: runtime.processId,
    sessionId: owner.sessionId,
    startedAt: new Date(runtime.now()).toISOString(),
  });
  let released = false;
  return () => {
    if (released) return;
    released = true;
    try {
      const current = readLockOwner(runtime.fileSystem, paths.lockOwner);
      if (
        current?.pid === runtime.processId &&
        current?.sessionId === owner.sessionId
      ) {
        removeOwnedLockDirectory(runtime.fileSystem, runtime.repoRoot, paths);
      }
    } catch {
      /* stale lock is safe for the next launcher to clear */
    }
  };
}

function ensureNoLiveLock(runtime) {
  const paths = firstRunPaths(runtime.repoRoot);
  if (!runtime.fileSystem.existsSync(paths.lockDirectory)) return;
  assertSafeDirectory(
    runtime.fileSystem,
    runtime.repoRoot,
    paths.lockDirectory,
  );
  const owner = readLockOwner(runtime.fileSystem, paths.lockOwner);
  if (!owner) {
    throw operationalError(
      "FIRST_RUN_LOCK_UNOWNED",
      "The First Run lock exists without a valid process owner.",
      "Inspect .actionproxy/first-run/active.lock manually; ActionProxy will not delete an unowned lock.",
      "./actionproxy status",
    );
  }
  if (owner && processIsAlive(runtime, owner.pid)) {
    throw operationalError(
      "FIRST_RUN_BUSY",
      `The ChatGPT tunnel launcher is active (PID ${owner.pid}).`,
      "Press Ctrl+C in its terminal before stopping or resetting Docker.",
      "./actionproxy status",
    );
  }
  removeOwnedLockDirectory(runtime.fileSystem, runtime.repoRoot, paths);
}

function removeOwnedLockDirectory(fileSystem, repoRoot, paths) {
  assertSafeDirectory(fileSystem, repoRoot, paths.lockDirectory);
  const entries = fileSystem.readdirSync(paths.lockDirectory);
  if (entries.length !== 1 || entries[0] !== path.basename(paths.lockOwner)) {
    throw operationalError(
      "FIRST_RUN_LOCK_UNOWNED",
      "The First Run lock contains unknown entries and was not removed.",
      "Inspect .actionproxy/first-run/active.lock manually.",
      "./actionproxy status",
    );
  }
  const ownerStats = fileSystem.lstatSync(paths.lockOwner);
  if (ownerStats.isSymbolicLink?.() || !ownerStats.isFile?.()) {
    throw operationalError(
      "FIRST_RUN_LOCK_UNOWNED",
      "The First Run lock owner is not a regular file and was not removed.",
      "Inspect .actionproxy/first-run/active.lock manually.",
      "./actionproxy status",
    );
  }
  fileSystem.unlinkSync(paths.lockOwner);
  fileSystem.rmdirSync(paths.lockDirectory);
}

function processIsAlive(runtime, pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    runtime.processKill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function readLockOwner(fileSystem, filename) {
  try {
    const stats = fileSystem.lstatSync(filename);
    if (
      stats.isSymbolicLink?.() ||
      !stats.isFile?.() ||
      (stats.mode & 0o777) !== 0o600 ||
      stats.size < 1 ||
      stats.size > 4096
    ) {
      return undefined;
    }
    const value = JSON.parse(fileSystem.readFileSync(filename, "utf8"));
    return Number.isSafeInteger(value?.pid) &&
      sessionPattern.test(value?.sessionId ?? "")
      ? value
      : undefined;
  } catch {
    return undefined;
  }
}

function readState(fileSystem, repoRoot, filename, { optional }) {
  if (!fileSystem.existsSync(filename)) {
    if (optional) return undefined;
    throw new Error("missing state");
  }
  let state;
  try {
    assertSafePrivateFile(fileSystem, repoRoot, filename);
    state = JSON.parse(fileSystem.readFileSync(filename, "utf8"));
  } catch {
    throw operationalError(
      "STATE_INVALID",
      "First Run state is unreadable.",
      "Move .actionproxy/first-run/state.json aside and start a new guided journey.",
      "./actionproxy local",
    );
  }
  if (
    state?.schemaVersion !== STATE_VERSION ||
    !projectPattern.test(state.projectName ?? "") ||
    !sessionPattern.test(state.sessionId ?? "") ||
    !["local", "chatgpt"].includes(state.journey) ||
    (state.checkoutId !== undefined &&
      !/^[0-9a-f]{10}$/u.test(state.checkoutId)) ||
    (state.profile !== undefined &&
      state.profile !== null &&
      !profilePattern.test(state.profile)) ||
    (state.port !== undefined &&
      (!Number.isSafeInteger(state.port) ||
        state.port < 1 ||
        state.port > 65535)) ||
    (state.baseUrl !== undefined &&
      state.baseUrl !== `http://127.0.0.1:${state.port}`)
  ) {
    throw operationalError(
      "STATE_INVALID",
      "First Run state failed strict validation.",
      "Move .actionproxy/first-run/state.json aside and start a new guided journey.",
      "./actionproxy local",
    );
  }
  return state;
}

function requireState(runtime, message) {
  const state = readState(
    runtime.fileSystem,
    runtime.repoRoot,
    firstRunPaths(runtime.repoRoot).state,
    { optional: true },
  );
  if (!state)
    throw operationalError(
      "STATE_MISSING",
      message,
      "Start a guided journey first.",
      "./actionproxy local",
    );
  return state;
}

function writeState(fileSystem, repoRoot, filename, state) {
  writeJsonPrivate(fileSystem, repoRoot, filename, state);
}

function writeJsonPrivate(fileSystem, repoRoot, filename, value) {
  ensurePrivateDirectoryWithin(fileSystem, repoRoot, path.dirname(filename));
  const temporary = `${filename}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  fileSystem.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  fileSystem.chmodSync?.(temporary, 0o600);
  fileSystem.renameSync(temporary, filename);
  fileSystem.chmodSync?.(filename, 0o600);
}

function writeJsonPrivateExclusive(fileSystem, repoRoot, filename, value) {
  ensurePrivateDirectoryWithin(fileSystem, repoRoot, path.dirname(filename));
  const temporary = `${filename}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  let linked = false;
  try {
    fileSystem.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    fileSystem.chmodSync?.(temporary, 0o600);
    fileSystem.linkSync(temporary, filename);
    linked = true;
    fileSystem.chmodSync?.(filename, 0o600);
  } finally {
    try {
      fileSystem.unlinkSync(temporary);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        if (linked) {
          try {
            const temporaryStats = fileSystem.lstatSync(temporary);
            const finalStats = fileSystem.lstatSync(filename);
            if (
              temporaryStats.dev === finalStats.dev &&
              temporaryStats.ino === finalStats.ino
            ) {
              fileSystem.unlinkSync(filename);
            }
          } catch {
            /* caller reports a fail-closed install error */
          }
        }
        throw error;
      }
    }
  }
}

function ensurePrivateDirectoryWithin(fileSystem, repoRoot, directory) {
  const realRoot = fileSystem.realpathSync(repoRoot);
  const target = path.resolve(directory);
  const relative = path.relative(realRoot, target);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw operationalError(
      "LOCAL_STATE_PATH_UNSAFE",
      "A local First Run state path escaped the checkout.",
      "Inspect .actionproxy for symlinks or moved state before retrying.",
      "./actionproxy status",
    );
  }
  let current = realRoot;
  for (const component of relative.split(path.sep)) {
    current = path.join(current, component);
    if (!fileSystem.existsSync(current)) {
      try {
        fileSystem.mkdirSync(current, { mode: 0o700 });
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
      }
    }
    const stats = fileSystem.lstatSync(current);
    if (stats.isSymbolicLink?.() || !stats.isDirectory?.()) {
      throw operationalError(
        "LOCAL_STATE_PATH_UNSAFE",
        "A local First Run state directory is symlinked or is not a directory.",
        "Inspect .actionproxy manually; ActionProxy refused to follow it.",
        "./actionproxy status",
      );
    }
    fileSystem.chmodSync?.(current, 0o700);
  }
  const finalRelative = path.relative(
    realRoot,
    fileSystem.realpathSync(target),
  );
  if (
    !finalRelative ||
    finalRelative.startsWith("..") ||
    path.isAbsolute(finalRelative)
  ) {
    throw operationalError(
      "LOCAL_STATE_PATH_UNSAFE",
      "A local First Run state directory resolved outside the checkout.",
      "Inspect .actionproxy manually; ActionProxy refused to write through it.",
      "./actionproxy status",
    );
  }
}

function readProfileMarker(fileSystem, repoRoot, filename) {
  if (!fileSystem.existsSync(filename)) return undefined;
  try {
    assertSafePrivateFile(fileSystem, repoRoot, filename);
    const marker = JSON.parse(fileSystem.readFileSync(filename, "utf8"));
    if (
      marker?.version !== PROFILE_MARKER_VERSION ||
      !tunnelIdPattern.test(marker.tunnelId ?? "") ||
      !projectPattern.test(marker.composeProject ?? "") ||
      !/^[0-9a-f]{64}$/u.test(marker.commandHash ?? "") ||
      !/^[0-9a-f]{64}$/u.test(marker.profileHash ?? "")
    )
      throw new Error("invalid marker");
    return marker;
  } catch {
    throw operationalError(
      "TUNNEL_PROFILE_MARKER_INVALID",
      `Tunnel profile marker is invalid: ${filename}.`,
      "Move the invalid marker aside or select a new --profile; it will not be overwritten.",
      "./actionproxy chatgpt",
    );
  }
}

function hashOwnedProfileFile(fileSystem, filename) {
  let stats;
  try {
    stats = fileSystem.lstatSync(filename);
  } catch {
    throw operationalError(
      "TUNNEL_PROFILE_MISSING",
      "The tunnel client did not produce the expected checkout-owned profile file.",
      "Retry with a new --profile name and a tunnel-client that supports --profile-dir.",
      "./actionproxy chatgpt",
    );
  }
  if (
    stats.isSymbolicLink?.() ||
    !stats.isFile?.() ||
    stats.size < 1 ||
    stats.size > 1024 * 1024
  ) {
    throw operationalError(
      "TUNNEL_PROFILE_INVALID",
      "The checkout-owned tunnel profile is not a regular profile file of an acceptable size.",
      "Choose a new --profile name; symlinked, empty, or oversized profiles are never run.",
      "./actionproxy chatgpt",
    );
  }
  fileSystem.chmodSync?.(filename, 0o600);
  return createHash("sha256")
    .update(fileSystem.readFileSync(filename))
    .digest("hex");
}

function composeArgs(projectName) {
  if (!projectPattern.test(projectName))
    throw new Error("invalid Compose project name");
  return ["compose", "--project-name", projectName, "-f", "docker-compose.yml"];
}

async function removeConciergeRuntime(
  runtime,
  { bestEffort = false, dockerEnvironment, projectName, removeVolume },
) {
  const execute = async () => {
    const containerId = await resolveOwnedConciergeContainer(runtime, {
      dockerEnvironment,
      projectName,
    });
    if (containerId) {
      try {
        await checked(runtime, {
          args: [
            ...composeArgs(projectName),
            "rm",
            "--stop",
            "--force",
            "actionproxy",
          ],
          code: removeVolume ? "DOCKER_RESET_FAILED" : "DOCKER_STOP_FAILED",
          env: dockerEnvironment,
          executable: "docker",
          message:
            "Docker could not remove the concierge-owned ActionProxy container.",
          remedy:
            "Inspect the recorded concierge project. No unrelated Docker service will be removed automatically.",
          retry: removeVolume ? "./actionproxy reset" : "./actionproxy stop",
        });
      } catch {
        await checked(runtime, {
          args: ["container", "rm", "--force", containerId],
          code: "SAFETY_CLEANUP_INCOMPLETE",
          env: dockerEnvironment,
          executable: "docker",
          message:
            "Compose cleanup failed and Docker could not remove the label-verified concierge container directly.",
          remedy:
            "Run ./actionproxy stop; it targets only the recorded concierge project.",
          retry: "./actionproxy stop",
        });
      }
      const remains = await runtime.command(
        "docker",
        ["container", "inspect", containerId],
        {
          capture: true,
          cwd: runtime.repoRoot,
          env: dockerEnvironment,
          secrets: [],
        },
      );
      if (remains.code === 0) {
        throw operationalError(
          "SAFETY_CLEANUP_INCOMPLETE",
          "Docker still reports the label-verified concierge container after removal.",
          "Run ./actionproxy stop before continuing.",
          "./actionproxy stop",
        );
      }
    }
    await removeLabeledDockerResource(runtime, {
      dockerEnvironment,
      kind: "network",
      labels: {
        "com.docker.compose.network": "default",
        "com.docker.compose.project": projectName,
      },
      name: `${projectName}_default`,
    });
    if (removeVolume) {
      await removeLabeledDockerResource(runtime, {
        dockerEnvironment,
        kind: "volume",
        labels: {
          "com.docker.compose.project": projectName,
          "com.docker.compose.volume": "actionproxy_data",
        },
        name: `${projectName}_actionproxy_data`,
      });
    }
    return { ok: true };
  };
  if (!bestEffort) return execute();
  try {
    return await execute();
  } catch (error) {
    runtime.stderr.write(
      "Warning: automatic safety cleanup was incomplete. Run ./actionproxy stop before continuing.\n",
    );
    return { error, ok: false };
  }
}

async function resolveOwnedConciergeContainer(
  runtime,
  { dockerEnvironment, projectName },
) {
  const resolved = await runtime.command(
    "docker",
    [...composeArgs(projectName), "ps", "-a", "-q", "actionproxy"],
    {
      capture: true,
      cwd: runtime.repoRoot,
      env: dockerEnvironment,
      secrets: [],
    },
  );
  if (resolved.code !== 0) {
    throw operationalError(
      "DOCKER_RESOURCE_OWNERSHIP_INVALID",
      "Docker could not resolve the recorded concierge container.",
      "Inspect the recorded project manually; ActionProxy refused broad cleanup.",
      "./actionproxy status",
    );
  }
  const identifiers = resolved.stdout.trim().split(/\r?\n/u).filter(Boolean);
  if (identifiers.length === 0) return undefined;
  if (identifiers.length !== 1 || !/^[a-f0-9]{12,64}$/u.test(identifiers[0])) {
    throw operationalError(
      "DOCKER_RESOURCE_OWNERSHIP_INVALID",
      "Docker returned an ambiguous concierge container identity.",
      "Inspect the recorded project manually; ActionProxy refused broad cleanup.",
      "./actionproxy status",
    );
  }
  const containerId = identifiers[0];
  const inspected = await runtime.command(
    "docker",
    ["inspect", "--format", "{{json .Config.Labels}}", containerId],
    {
      capture: true,
      cwd: runtime.repoRoot,
      env: dockerEnvironment,
      secrets: [],
    },
  );
  let labels;
  try {
    labels = inspected.code === 0 ? JSON.parse(inspected.stdout) : undefined;
  } catch {
    labels = undefined;
  }
  if (
    labels?.["com.docker.compose.project"] !== projectName ||
    labels?.["com.docker.compose.service"] !== "actionproxy"
  ) {
    throw operationalError(
      "DOCKER_RESOURCE_OWNERSHIP_MISMATCH",
      "The resolved container is not label-owned by the recorded concierge project and service.",
      "Inspect the resource manually; ActionProxy refused to remove it.",
      "./actionproxy status",
    );
  }
  return containerId;
}

async function removeLabeledDockerResource(
  runtime,
  { dockerEnvironment, kind, labels, name },
) {
  const inspected = await runtime.command(
    "docker",
    [kind, "inspect", "--format", "{{json .Labels}}", name],
    {
      capture: true,
      cwd: runtime.repoRoot,
      env: dockerEnvironment,
      secrets: [],
    },
  );
  if (inspected.code !== 0) return;
  let actualLabels;
  try {
    actualLabels = JSON.parse(inspected.stdout);
  } catch {
    throw operationalError(
      "DOCKER_RESOURCE_OWNERSHIP_INVALID",
      `Docker returned invalid ownership labels for ${kind} ${name}.`,
      "Inspect this resource manually; ActionProxy refused to remove it.",
      "./actionproxy status",
    );
  }
  if (
    !actualLabels ||
    Object.entries(labels).some(([key, value]) => actualLabels[key] !== value)
  ) {
    throw operationalError(
      "DOCKER_RESOURCE_OWNERSHIP_MISMATCH",
      `Docker ${kind} ${name} is not owned by the recorded concierge project.`,
      "Inspect this resource manually; ActionProxy refused to remove it.",
      "./actionproxy status",
    );
  }
  await checked(runtime, {
    args: [kind, "rm", name],
    code: kind === "volume" ? "DOCKER_RESET_FAILED" : "DOCKER_STOP_FAILED",
    env: dockerEnvironment,
    executable: "docker",
    message: `Docker could not remove concierge ${kind} ${name}.`,
    remedy:
      "Confirm no other container is attached; unrelated containers will not be removed automatically.",
    retry: kind === "volume" ? "./actionproxy reset" : "./actionproxy stop",
  });
}

function dockerEnv(
  env,
  { journey, originToken, port, sessionId, updateToken },
) {
  return {
    ...secretFreeEnv(env),
    ACTIONPROXY_DOCKER_PORT: String(port === "auto" ? 0 : port),
    ACTIONPROXY_QUICKSTART_LOOPBACK_PUBLISHED: "true",
    ACTIONPROXY_QUICKSTART_JOURNEY: journey,
    ACTIONPROXY_QUICKSTART_MODE: "true",
    ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN: originToken,
    ACTIONPROXY_QUICKSTART_SESSION_ID: sessionId,
    ACTIONPROXY_QUICKSTART_UPDATE_TOKEN: updateToken,
    BUILDKIT_PROGRESS: "plain",
    COMPOSE_PROGRESS: "plain",
  };
}

function secretFreeEnv(env, secret) {
  const safe = { ...env };
  delete safe.ACTIONPROXY_CONTROL_PLANE_KEY_FILE;
  delete safe.ACTIONPROXY_LEGACY_RUNTIME_KEY_FD;
  delete safe.CONTROL_PLANE_API_KEY;
  delete safe.OPENAI_API_KEY;
  delete safe.ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN;
  delete safe.ACTIONPROXY_QUICKSTART_UPDATE_TOKEN;
  if (secret) {
    for (const [name, value] of Object.entries(safe)) {
      if (String(value).includes(secret)) delete safe[name];
    }
  }
  return safe;
}

function tunnelClientProbeEnv(env) {
  const safe = {};
  for (const name of ["LANG", "LC_ALL", "LC_CTYPE", "PATH", "TMPDIR"]) {
    if (typeof env?.[name] === "string" && env[name]) safe[name] = env[name];
  }
  return safe;
}

function basePassedChecks(includeTunnel) {
  const checks = new Map(CHECK_IDS.map((id) => [id, { id, state: "pending" }]));
  checks.set("node", { id: "node", state: "pass" });
  checks.set("docker_cli", { id: "docker_cli", state: "pass" });
  checks.set("docker_daemon", { id: "docker_daemon", state: "pass" });
  checks.set("compose", { id: "compose", state: "pass" });
  if (!includeTunnel)
    checks.set("tunnel_client", { id: "tunnel_client", state: "pending" });
  return checks;
}

function failureChecks(error, journey, currentChecks) {
  const checks = currentChecks
    ? new Map(
        [...currentChecks.entries()].map(([id, check]) => [id, { ...check }]),
      )
    : basePassedChecks(journey === "chatgpt");
  const mapping = {
    GATEWAY_UNHEALTHY: ["gateway", "gateway_unhealthy"],
    LOOPBACK_BINDING_INVALID: ["loopback", "non_loopback_binding"],
    STORAGE_NOT_SQLITE: ["storage", "storage_not_sqlite"],
    TOOL_DISCOVERY_FAILED: ["tool_discovery", "tool_discovery_mismatch"],
    TOOL_DISCOVERY_MISMATCH: ["tool_discovery", "tool_discovery_mismatch"],
    TUNNEL_ACCESS_FAILED: ["tunnel_doctor", "tunnel_access_failed"],
    TUNNEL_DISCONNECTED: ["tunnel_readiness", "tunnel_disconnected"],
    TUNNEL_NOT_READY: ["tunnel_readiness", "tunnel_not_ready"],
  };
  const entry = mapping[error?.code];
  if (entry)
    checks.set(entry[0], {
      id: entry[0],
      remediationCode: entry[1],
      state: "fail",
    });
  return [...checks.values()];
}

async function probe(
  runtime,
  executable,
  args,
  env = secretFreeEnv(runtime.env),
) {
  try {
    const result = await runtime.command(executable, args, {
      capture: true,
      cwd: runtime.repoRoot,
      env,
    });
    if (result.interrupted) {
      throw new FirstRunError(
        "INTERRUPTED",
        "First Run cancelled by the user.",
        {
          exitCode: 0,
        },
      );
    }
    return {
      missing: false,
      ok: result.code === 0,
      version: String(result.stdout || result.stderr || "").trim(),
    };
  } catch (error) {
    if (error instanceof FirstRunError) throw error;
    return { missing: error?.code === "ENOENT", ok: false, version: "" };
  }
}

async function checked(
  runtime,
  {
    executable,
    args,
    env,
    code,
    message,
    remedy,
    retry,
    secrets = [],
    stream = false,
    onOutput,
  },
) {
  let result;
  try {
    result = await runtime.command(executable, args, {
      capture: !stream,
      cwd: runtime.repoRoot,
      env,
      onOutput,
      secrets,
      stderr: runtime.stderr,
      stdout: runtime.stdout,
    });
  } catch (error) {
    throw operationalError(
      code,
      `${message} ${redact(error instanceof Error ? error.message : error, secrets)}`.trim(),
      remedy,
      retry,
    );
  }
  if (result.interrupted) {
    throw new FirstRunError("INTERRUPTED", "First Run cancelled by the user.", {
      exitCode: 0,
    });
  }
  if (result.code !== 0) {
    const detail = sanitizeDetail(
      redact(result.stderr || result.stdout || "", secrets),
    );
    throw operationalError(
      code,
      `${message}${detail ? ` ${detail}` : ""}`,
      remedy,
      retry,
    );
  }
  return result;
}

function runCommand(executable, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const output = options.capture
      ? undefined
      : redactingWriter(options.secrets, (value) =>
          options.stdout.write(value),
        );
    const errors = options.capture
      ? undefined
      : redactingWriter(options.secrets, (value) =>
          options.stderr.write(value),
        );
    let interrupted = false;
    const forward = (signal) => {
      interrupted = true;
      child.kill(signal);
    };
    const onSigint = () => forward("SIGINT");
    const onSigterm = () => forward("SIGTERM");
    process.once("SIGINT", onSigint);
    process.once("SIGTERM", onSigterm);
    const onAbort = () => forward("SIGTERM");
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const cleanupSignals = () => {
      process.removeListener("SIGINT", onSigint);
      process.removeListener("SIGTERM", onSigterm);
      options.signal?.removeEventListener("abort", onAbort);
    };
    child.once("error", (error) => {
      cleanupSignals();
      reject(error);
    });
    child.stdout.on("data", (chunk) => {
      stdout = appendTail(stdout, chunk);
      output?.push(chunk);
      options.onOutput?.(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = appendTail(stderr, chunk);
      errors?.push(chunk);
      options.onOutput?.(chunk);
    });
    child.once("close", (code) => {
      cleanupSignals();
      output?.end();
      errors?.end();
      resolve({ code, interrupted, stderr, stdout });
    });
  });
}

function runForeground(executable, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ["inherit", "pipe", "pipe"],
    });
    const output = redactingWriter(options.secrets, (value) =>
      options.stdout.write(value),
    );
    const errors = redactingWriter(options.secrets, (value) =>
      options.stderr.write(value),
    );
    let interrupted = false;
    const forward = (signal) => {
      interrupted = true;
      child.kill(signal);
    };
    const onSigint = () => forward("SIGINT");
    const onSigterm = () => forward("SIGTERM");
    process.once("SIGINT", onSigint);
    process.once("SIGTERM", onSigterm);
    const onAbort = () => forward("SIGTERM");
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const cleanupSignals = () => {
      process.removeListener("SIGINT", onSigint);
      process.removeListener("SIGTERM", onSigterm);
      options.signal?.removeEventListener("abort", onAbort);
    };
    child.once("error", (error) => {
      cleanupSignals();
      reject(error);
    });
    child.stdout.on("data", (chunk) => output.push(chunk));
    child.stderr.on("data", (chunk) => errors.push(chunk));
    child.once("close", (code) => {
      cleanupSignals();
      output.end();
      errors.end();
      resolve({ code, interrupted });
    });
  });
}

function redactingWriter(secrets, write) {
  let buffer = "";
  const reserve = Math.max(
    0,
    ...(Array.isArray(secrets) ? secrets : [secrets])
      .filter(Boolean)
      .map((secret) => secret.length - 1),
  );
  return {
    push(chunk) {
      buffer += String(chunk);
      for (;;) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) break;
        write(redact(buffer.slice(0, newline + 1), secrets));
        buffer = buffer.slice(newline + 1);
      }
      if (buffer.length > 65_536 + reserve) {
        const flushLength = buffer.length - reserve;
        write(redact(buffer.slice(0, flushLength), secrets));
        buffer = buffer.slice(flushLength);
      }
    },
    end() {
      if (buffer) write(redact(buffer, secrets));
      buffer = "";
    },
  };
}

export function appendTail(existing, chunk, maximum = 65_536) {
  const combined = `${existing}${String(chunk)}`;
  return combined.length <= maximum ? combined : combined.slice(-maximum);
}

export function dockerProgressStage(line) {
  const value = String(line)
    .replace(/\x1b\[[0-9;]*m/gu, "")
    .trim();
  const build = /(?:#\d+|=>)\s+\[([^\]]{1,120})\]/u.exec(value);
  if (build) return `build ${build[1].replace(/\s+/gu, " ")}`;
  const runtime =
    /Container\s+\S+\s+(Creating|Created|Starting|Started|Waiting|Healthy|Stopping|Stopped)/iu.exec(
      value,
    );
  if (runtime) return `runtime ${runtime[1].toLowerCase()}`;
  const compose =
    /\b(Building|Built|Creating|Created|Starting|Started|Waiting|Healthy)\b/iu.exec(
      value,
    );
  return compose ? `runtime ${compose[1].toLowerCase()}` : undefined;
}

function dockerProgressReporter(runtime, startedAt) {
  let buffer = "";
  let lastStage;
  return (chunk) => {
    buffer = appendTail(buffer, chunk, 8_192);
    for (;;) {
      const newline = buffer.indexOf("\n");
      if (newline < 0) break;
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      const stage = dockerProgressStage(line);
      if (!stage || stage === lastStage) continue;
      lastStage = stage;
      runtime.stdout.write(
        `  [${stage}] ${formatDuration(runtime.now() - startedAt)}\n`,
      );
    }
  };
}

function installJourneySignalGuard(signalEmitter) {
  const waiters = new Set();
  const handlers = new Map();
  let interrupted = false;
  const interruptError = () =>
    new FirstRunError("INTERRUPTED", "First Run cancelled by the user.", {
      exitCode: 0,
    });
  for (const signal of ["SIGINT", "SIGTERM"]) {
    const handler = () => {
      interrupted = true;
      const error = interruptError();
      for (const reject of waiters) reject(error);
      waiters.clear();
    };
    handlers.set(signal, handler);
    signalEmitter.on(signal, handler);
  }
  return {
    dispose() {
      for (const [signal, handler] of handlers)
        signalEmitter.removeListener(signal, handler);
      waiters.clear();
    },
    race(promise) {
      if (interrupted) return Promise.reject(interruptError());
      return new Promise((resolve, reject) => {
        waiters.add(reject);
        Promise.resolve(promise).then(
          (value) => {
            waiters.delete(reject);
            resolve(value);
          },
          (error) => {
            waiters.delete(reject);
            reject(error);
          },
        );
      });
    },
    throwIfInterrupted() {
      if (interrupted) throw interruptError();
    },
  };
}

function installSessionSignalGuard(
  signalEmitter,
  fileSystem,
  { healthUrlFile, keyFile, sessionDirectory },
) {
  const handlers = new Map();
  let interrupted = false;
  for (const signal of ["SIGINT", "SIGTERM"]) {
    const handler = () => {
      interrupted = true;
      try {
        fileSystem.unlinkSync(keyFile);
      } catch {
        /* best effort before normal signal handling */
      }
      try {
        fileSystem.unlinkSync(healthUrlFile);
      } catch {
        /* best effort before normal signal handling */
      }
      try {
        fileSystem.rmdirSync(sessionDirectory);
      } catch {
        /* best effort before normal signal handling */
      }
    };
    handlers.set(signal, handler);
    signalEmitter.once(signal, handler);
  }
  return {
    dispose() {
      for (const [signal, handler] of handlers)
        signalEmitter.removeListener(signal, handler);
    },
    throwIfInterrupted() {
      if (interrupted) {
        throw new FirstRunError(
          "INTERRUPTED",
          "First Run cancelled by the user.",
          { exitCode: 0 },
        );
      }
    },
  };
}

function removeEphemeralFile(runtime, filename, label) {
  if (!filename) return;
  try {
    runtime.fileSystem.unlinkSync(filename);
  } catch (error) {
    if (error?.code !== "ENOENT")
      runtime.stderr.write(
        `Warning: could not remove the temporary ${label} file. Remove it before continuing.\n`,
      );
  }
}

function removeRequiredRuntimeKey(runtime, filename) {
  if (!filename) return;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      runtime.fileSystem.unlinkSync(filename);
      if (!runtime.fileSystem.existsSync(filename)) return;
    } catch (error) {
      if (error?.code === "ENOENT") return;
    }
  }
  throw operationalError(
    "RUNTIME_KEY_CLEANUP_FAILED",
    "ActionProxy could not confirm deletion of the private temporary runtime-key file.",
    `Delete the remaining file without opening it: ${filename}`,
    "./actionproxy chatgpt",
  );
}

function removeProvisionalTunnelProfile(runtime, { filename, profileHash }) {
  try {
    if (profileHash) {
      assertSafePrivateFile(runtime.fileSystem, runtime.repoRoot, filename);
      const actualHash = createHash("sha256")
        .update(runtime.fileSystem.readFileSync(filename))
        .digest("hex");
      if (actualHash !== profileHash)
        throw new Error("the provisional profile changed after initialization");
    } else {
      assertSafeDirectory(
        runtime.fileSystem,
        runtime.repoRoot,
        path.dirname(filename),
      );
      const stats = runtime.fileSystem.lstatSync(filename);
      if (
        stats.isSymbolicLink?.() ||
        !stats.isFile?.() ||
        stats.size > 1024 * 1024
      ) {
        throw new Error("the failed initializer left an unsafe profile entry");
      }
    }
    runtime.fileSystem.unlinkSync(filename);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      runtime.stderr.write(
        "Warning: could not safely remove the unverified tunnel profile. Choose a new --profile name before retrying.\n",
      );
    }
  }
}

async function prepareInteractiveRuntimeKey(runtime, { links, noOpen }) {
  if (!runtime.isTTY) return true;
  runtime.stdout.write(
    [
      "",
      "OpenAI tunnel runtime key",
      "The key is requested only after the local gateway and three mock tools are verified.",
      "ActionProxy reads it with terminal echo disabled, passes tunnel-client only a private temporary file reference, and deletes that file on exit.",
      "It is not sent to Docker or the browser and is not stored in launcher state, tunnel profiles, or the audit trail.",
      "",
      "  Enter  Continue to hidden key input",
      "  O      Open OpenAI Platform runtime API keys",
      "  Q      Pause; keep the verified local gateway running",
      "",
    ].join("\n"),
  );
  for (;;) {
    const action = (
      await runtime.promptLine("Runtime key action [Enter/O/Q]: ")
    )
      .trim()
      .toLowerCase();
    if (!action) return true;
    if (action === "q") return false;
    if (action === "o") {
      await openGuidanceLink(runtime, links.links.runtimeApiKeys, noOpen);
      continue;
    }
    runtime.stdout.write("! Choose Enter, O, or Q.\n");
  }
}

async function requireInteractiveSecret(runtime) {
  if (!runtime.isTTY) {
    throw operationalError(
      "RUNTIME_KEY_MISSING",
      "A runtime API key is required when using a noninteractive terminal.",
      "Set ACTIONPROXY_CONTROL_PLANE_KEY_FILE to a caller-owned mode-0600 file, or rerun in an interactive terminal for hidden input. Legacy CONTROL_PLANE_API_KEY is accepted only through a direct ./actionproxy invocation and is deprecated for strict automation.",
      "./actionproxy chatgpt",
    );
  }
  return runtime.readSecret("OpenAI runtime API key (hidden): ");
}

async function readValidInteractiveRuntimeKey(runtime) {
  for (;;) {
    const candidate = await requireInteractiveSecret(runtime);
    try {
      return validRuntimeKey(candidate);
    } catch (error) {
      if (
        !(error instanceof FirstRunError) ||
        error.code !== "RUNTIME_KEY_INVALID"
      )
        throw error;
      runtime.stderr.write(
        "! That runtime key could not be accepted. Nothing was retained; enter a nonempty key without surrounding whitespace or control characters.\n",
      );
    }
  }
}

export async function readHiddenSecret(prompt, dependencies = {}) {
  const fileSystem = dependencies.fileSystem ?? fs;
  const processObject = dependencies.processObject ?? process;
  const spawnSyncFn = dependencies.spawnSyncFn ?? spawnSync;
  const createTtyReadStream =
    dependencies.createTtyReadStream ??
    ((descriptor) => new TtyReadStream(descriptor));
  const descriptor = fileSystem.openSync("/dev/tty", "r+");
  let input;
  let lineReader;
  let restoreRequired = false;
  let restored = false;
  const restore = () => {
    if (restored || !restoreRequired) return;
    restored = true;
    spawnSyncFn("stty", ["echo"], { stdio: [descriptor, "ignore", "ignore"] });
  };
  const handlers = new Map();
  let interruptedError;
  let rejectRead;
  try {
    for (const signal of ["SIGINT", "SIGTERM"]) {
      const handler = () => {
        interruptedError ??= new FirstRunError(
          "INTERRUPTED",
          "First Run cancelled by the user.",
          { exitCode: 0 },
        );
        rejectRead?.(interruptedError);
      };
      handlers.set(signal, handler);
      // Install the guard before disabling echo or making the prompt visible.
      // Otherwise an immediate Ctrl+C can take the process's default signal
      // path and leave the caller's controlling terminal with echo disabled.
      processObject.once(signal, handler);
    }
    // Restore even when stty is signalled or reports failure: it may have
    // applied -echo before terminating without a successful status.
    restoreRequired = true;
    const disabled = spawnSyncFn("stty", ["-echo"], {
      stdio: [descriptor, "ignore", "ignore"],
    });
    if (disabled.status !== 0)
      throw new Error("could not disable terminal echo");
    if (interruptedError) throw interruptedError;
    fileSystem.writeSync(descriptor, prompt);
    if (interruptedError) throw interruptedError;
    // A generic fs.ReadStream performs character-device reads in a libuv
    // worker. On macOS, closing its descriptor after readline has accepted a
    // line can block until the terminal receives an additional character.
    // tty.ReadStream uses libuv's cancellable TTY handle instead, so one Enter
    // completes the prompt and signal cleanup can stop the pending read.
    input = createTtyReadStream(descriptor);
    if (interruptedError) throw interruptedError;
    lineReader = readline.createInterface({
      crlfDelay: Infinity,
      input,
      terminal: false,
    });
    if (interruptedError) throw interruptedError;
    const value = await new Promise((resolve, reject) => {
      let settled = false;
      const settle = (callback, result) => {
        if (settled) return;
        settled = true;
        callback(result);
      };
      rejectRead = (error) => settle(reject, error);
      if (interruptedError) {
        rejectRead(interruptedError);
        return;
      }
      lineReader.once("line", (line) => settle(resolve, line));
      lineReader.once("error", (error) => settle(reject, error));
      lineReader.once("close", () =>
        settle(
          reject,
          new Error("terminal input closed before a runtime key was entered"),
        ),
      );
    });
    if (interruptedError) throw interruptedError;
    fileSystem.writeSync(descriptor, "\n");
    return value;
  } finally {
    restore();
    for (const [signal, handler] of handlers)
      processObject.removeListener(signal, handler);
    lineReader?.close();
    input?.destroy();
    fileSystem.closeSync(descriptor);
  }
}

export async function readTerminalLine(prompt, dependencies = {}) {
  const fileSystem = dependencies.fileSystem ?? fs;
  const processObject = dependencies.processObject ?? process;
  const createTtyReadStream =
    dependencies.createTtyReadStream ??
    ((descriptor) => new TtyReadStream(descriptor));
  const descriptor = fileSystem.openSync("/dev/tty", "r+");
  let input;
  let lineReader;
  const handlers = new Map();
  let interruptedError;
  let rejectRead;
  try {
    for (const signal of ["SIGINT", "SIGTERM"]) {
      const handler = () => {
        interruptedError ??= new FirstRunError(
          "INTERRUPTED",
          "First Run cancelled by the user.",
          { exitCode: 0 },
        );
        rejectRead?.(interruptedError);
      };
      handlers.set(signal, handler);
      // Guard the prompt-visible window just as strictly as hidden input.
      processObject.once(signal, handler);
    }
    fileSystem.writeSync(descriptor, prompt);
    if (interruptedError) throw interruptedError;
    input = createTtyReadStream(descriptor);
    if (interruptedError) throw interruptedError;
    lineReader = readline.createInterface({
      crlfDelay: Infinity,
      input,
      terminal: false,
    });
    if (interruptedError) throw interruptedError;
    return await new Promise((resolve, reject) => {
      let settled = false;
      const settle = (callback, result) => {
        if (settled) return;
        settled = true;
        callback(result);
      };
      rejectRead = (error) => settle(reject, error);
      if (interruptedError) {
        rejectRead(interruptedError);
        return;
      }
      lineReader.once("line", (line) => settle(resolve, line));
      lineReader.once("error", (error) => settle(reject, error));
      lineReader.once("close", () =>
        settle(
          reject,
          new Error("terminal input closed before a response was entered"),
        ),
      );
    });
  } finally {
    for (const [signal, handler] of handlers)
      processObject.removeListener(signal, handler);
    lineReader?.close();
    input?.destroy();
    fileSystem.closeSync(descriptor);
  }
}

async function defaultPromptConfirm(prompt) {
  const answer = (await readTerminalLine(prompt)).trim().toLowerCase();
  return answer === "" || answer === "y" || answer === "yes";
}

function defaultOpenUrl(url) {
  if (process.platform !== "darwin") return Promise.resolve(false);
  return runCommand("open", [url], {
    capture: true,
    cwd: defaultRepoRoot,
    env: secretFreeEnv(process.env),
  }).then((result) => {
    if (result.interrupted) {
      throw new FirstRunError(
        "INTERRUPTED",
        "First Run cancelled by the user.",
        { exitCode: 0 },
      );
    }
    return result.code === 0;
  });
}

async function maybeOpen(runtime, url, noOpen) {
  runtime.throwIfInterrupted?.();
  if (noOpen) return;
  try {
    const opened = await runtime.openUrl(url);
    runtime.throwIfInterrupted?.();
    if (!opened)
      runtime.stdout.write(`Open this URL in your browser: ${url}\n`);
  } catch (error) {
    if (error instanceof FirstRunError) throw error;
    runtime.throwIfInterrupted?.();
    runtime.stdout.write(`Open this URL in your browser: ${url}\n`);
  }
}

function readOpenAiLinks(fileSystem, repoRoot) {
  const filename = path.join(
    repoRoot,
    "examples",
    "chatgpt-tunnel",
    "openai-links.json",
  );
  try {
    const value = JSON.parse(fileSystem.readFileSync(filename, "utf8"));
    const expectedKeys = Object.keys(OFFICIAL_OPENAI_URLS).sort();
    const actualKeys = Object.keys(value?.links ?? {}).sort();
    const reviewedAt = value?.reviewedAt;
    const reviewedDate = new Date(`${reviewedAt}T00:00:00.000Z`);
    if (
      value?.schemaVersion !== "actionproxy.openai-links.v1" ||
      !/^\d{4}-\d{2}-\d{2}$/u.test(reviewedAt ?? "") ||
      Number.isNaN(reviewedDate.getTime()) ||
      reviewedDate.toISOString().slice(0, 10) !== reviewedAt ||
      actualKeys.length !== expectedKeys.length ||
      actualKeys.some((key, index) => key !== expectedKeys[index]) ||
      expectedKeys.some((key) => {
        const link = value.links[key];
        return (
          typeof link?.label !== "string" ||
          link.label.length < 1 ||
          link.label.length > 120 ||
          /[\u0000-\u001f\u007f]/u.test(link.label) ||
          link.url !== OFFICIAL_OPENAI_URLS[key]
        );
      })
    )
      throw new Error("unsupported links schema");
    return value;
  } catch {
    throw operationalError(
      "OPENAI_LINKS_INVALID",
      "The bundled OpenAI link registry is missing or invalid.",
      "Restore examples/chatgpt-tunnel/openai-links.json from this release.",
      "./actionproxy chatgpt",
    );
  }
}

function printDoctor(stdout, report, includeChatgpt, links) {
  stdout.write(
    `ActionProxy First Run doctor (${report.operatingSystem}/${report.architecture})\n`,
  );
  stdout.write("  Supported Node versions: 22-24 (Node 24 recommended)\n");
  const retry = `./actionproxy doctor${includeChatgpt ? " --chatgpt" : ""}`;
  for (const check of report.checks) {
    const icon =
      check.state === "pass"
        ? "✓"
        : check.state === "action_required"
          ? "!"
          : check.state === "pending"
            ? "○"
            : "✗";
    const remediation = check.remediationCode
      ? doctorRemedy(check.remediationCode, links)
      : undefined;
    stdout.write(
      `  ${icon} ${check.id}${remediation ? ` — ${remediation.cause}` : ""}\n`,
    );
    if (remediation) {
      stdout.write(`    Fix: ${remediation.fix}\n`);
      stdout.write(`    Retry: ${retry}\n`);
    }
  }
  if (report.gateway.healthy)
    stdout.write(
      `  ✓ gateway — 127.0.0.1:${report.gateway.port}, ${report.gateway.storageMode}\n`,
    );
}

function doctorRemedy(code, links) {
  return (
    {
      compose_missing: {
        cause: "Docker Compose v2 is unavailable.",
        fix: "Update Docker Desktop until `docker compose version` succeeds.",
      },
      docker_missing: {
        cause: "Docker CLI is missing.",
        fix: "Install Docker Desktop for Mac.",
      },
      docker_not_running: {
        cause: "Docker Desktop engine is not running.",
        fix: "Open Docker Desktop and wait for the engine to become ready.",
      },
      gateway_unhealthy: {
        cause: "The recorded local gateway is not healthy.",
        fix: "Run `./actionproxy stop`, then start a new local journey.",
      },
      non_loopback_binding: {
        cause: "The recorded gateway binding is not verified as loopback-only.",
        fix: "Stop it and restore the bundled Compose configuration before restarting.",
      },
      runtime_key_in_docker: {
        cause: "A runtime-key variable reached the guided Docker boundary.",
        fix: "Run `./actionproxy stop`, remove the affected container, and restore the bundled Compose configuration before retrying.",
      },
      storage_not_sqlite: {
        cause: "The recorded guided gateway is not using SQLite.",
        fix: "Stop it and rebuild with the bundled Compose configuration.",
      },
      tool_discovery_mismatch: {
        cause:
          "The recorded gateway does not expose exactly the three demo tools.",
        fix: "Stop it, restore the bundled MCP configuration, and rebuild.",
      },
      tunnel_client_incompatible: {
        cause:
          "tunnel-client lacks required file-secret or health capabilities.",
        fix: links
          ? `Run \`./actionproxy tunnel-client install\` for the explicit reviewed local copy, or install manually from ${links.links.tunnelClientReleases.url}. Official link reviewed ${links.reviewedAt}.`
          : "Run `./actionproxy tunnel-client install`, or install the supported release manually.",
      },
      tunnel_client_missing: {
        cause: "tunnel-client is missing.",
        fix: links
          ? `Run \`./actionproxy tunnel-client install\` for explicit checkout-local installation, or install manually from ${links.links.tunnelClientReleases.url}. Official link reviewed ${links.reviewedAt}.`
          : "Run `./actionproxy tunnel-client install`, or install manually and put it on PATH or set TUNNEL_CLIENT_BIN.",
      },
      unsupported_node: {
        cause: "The active Node version is unsupported.",
        fix: "Use Node 22, 23, or 24; Node 24 is recommended.",
      },
      unsupported_os: {
        cause: "This operating system is outside release-quality Mac support.",
        fix: "Use macOS, or continue on Linux knowing support is best-effort.",
      },
    }[code] ?? {
      cause: code,
      fix: "Apply the documented remediation for this check.",
    }
  );
}

function readJsonSafe(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function isLoopbackUiUrl(value) {
  if (!value) return false;
  try {
    const url = new URL(value);
    return (
      url.protocol === "http:" &&
      ["127.0.0.1", "[::1]"].includes(url.hostname) &&
      url.pathname === "/ui" &&
      Boolean(url.port)
    );
  } catch {
    return false;
  }
}

function extractSemanticVersion(value) {
  const match = firstLine(value).match(
    /v?(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){1,3}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?/u,
  );
  return match && setupVersionPattern.test(match[0]) ? match[0] : null;
}

function firstLine(value) {
  return String(value ?? "")
    .split(/\r?\n/u)[0]
    .trim();
}
function formatDuration(milliseconds) {
  return `${Math.max(0, Math.round(milliseconds / 100) / 10).toFixed(1)}s`;
}
function formatBinarySize(bytes) {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}
function sanitizeDetail(value) {
  return String(value ?? "")
    .replace(/[\r\n\t]+/gu, " ")
    .trim()
    .slice(-2_000);
}

function assertSafeDirectory(fileSystem, repoRoot, target) {
  const lexicalRoot = path.resolve(repoRoot);
  const lexicalTarget = path.resolve(target);
  const relative = path.relative(lexicalRoot, lexicalTarget);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw operationalError(
      "LOCAL_STATE_PATH_UNSAFE",
      "Refusing a destructive operation outside the scoped First Run directory.",
      "Inspect .actionproxy manually; no broad deletion was attempted.",
      "./actionproxy status",
    );
  }
  let current = lexicalRoot;
  for (const component of relative.split(path.sep)) {
    current = path.join(current, component);
    const stats = fileSystem.lstatSync(current);
    if (stats.isSymbolicLink?.() || !stats.isDirectory?.()) {
      throw operationalError(
        "LOCAL_STATE_PATH_UNSAFE",
        "Refusing a destructive operation through a symlink or non-directory.",
        "Inspect .actionproxy manually; no broad deletion was attempted.",
        "./actionproxy status",
      );
    }
  }
  const realRoot = fileSystem.realpathSync(lexicalRoot);
  const realTarget = fileSystem.realpathSync(lexicalTarget);
  const realRelative = path.relative(realRoot, realTarget);
  if (
    !realRelative ||
    realRelative.startsWith("..") ||
    path.isAbsolute(realRelative)
  ) {
    throw operationalError(
      "LOCAL_STATE_PATH_UNSAFE",
      "Refusing a destructive operation outside the real checkout root.",
      "Inspect .actionproxy manually; no broad deletion was attempted.",
      "./actionproxy status",
    );
  }
}

function assertSafePrivateFile(fileSystem, repoRoot, filename) {
  assertSafeDirectory(fileSystem, repoRoot, path.dirname(filename));
  const stats = fileSystem.lstatSync(filename);
  if (
    stats.isSymbolicLink?.() ||
    !stats.isFile?.() ||
    (stats.mode & 0o777) !== 0o600 ||
    stats.size < 1 ||
    stats.size > 1024 * 1024
  ) {
    throw new Error(
      "refusing to read a symlinked, non-private, or non-regular local state file",
    );
  }
  const realRoot = fileSystem.realpathSync(repoRoot);
  const realFile = fileSystem.realpathSync(filename);
  const relative = path.relative(realRoot, realFile);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("refusing to read local state outside the checkout");
  }
}

function assertSafeExecutableFile(fileSystem, repoRoot, filename, exactSize) {
  assertSafeDirectory(fileSystem, repoRoot, path.dirname(filename));
  const stats = fileSystem.lstatSync(filename);
  if (
    stats.isSymbolicLink?.() ||
    !stats.isFile?.() ||
    (stats.mode & 0o777) !== 0o700 ||
    stats.size !== exactSize ||
    stats.size < 1 ||
    stats.size > TUNNEL_CLIENT_BINARY_MAX_BYTES
  ) {
    throw new Error(
      "refusing a symlinked, modified, non-executable, or non-regular tunnel-client",
    );
  }
  const realRoot = fileSystem.realpathSync(repoRoot);
  const realFile = fileSystem.realpathSync(filename);
  const relative = path.relative(realRoot, realFile);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("refusing a tunnel-client outside the checkout");
  }
}

function sha256File(fileSystem, filename) {
  return createHash("sha256")
    .update(fileSystem.readFileSync(filename))
    .digest("hex");
}

function assertSafeRemovalTree(fileSystem, repoRoot, target) {
  assertSafeDirectory(fileSystem, repoRoot, target);
  const visit = (directory) => {
    for (const entry of fileSystem.readdirSync(directory)) {
      const child = path.join(directory, entry);
      const stats = fileSystem.lstatSync(child);
      if (stats.isSymbolicLink?.()) {
        throw operationalError(
          "LOCAL_STATE_PATH_UNSAFE",
          "Refusing to remove a tree containing a symlink.",
          "Inspect .actionproxy/first-run manually; no local state was deleted.",
          "./actionproxy status",
        );
      }
      if (stats.isDirectory?.()) visit(child);
      else if (!stats.isFile?.()) {
        throw operationalError(
          "LOCAL_STATE_PATH_UNSAFE",
          "Refusing to remove a tree containing a non-regular entry.",
          "Inspect .actionproxy/first-run manually; no local state was deleted.",
          "./actionproxy status",
        );
      }
    }
  };
  visit(path.resolve(target));
}

function removeDirectoryIfEmptyWithin(fileSystem, repoRoot, target) {
  if (!fileSystem.existsSync(target)) return;
  assertSafeDirectory(fileSystem, repoRoot, target);
  if (fileSystem.readdirSync(target).length === 0) {
    fileSystem.rmdirSync(target);
  }
}

function fileSystemEntryExists(fileSystem, target) {
  try {
    fileSystem.lstatSync(target);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function operationalError(code, message, remedy, retry) {
  return new FirstRunError(code, message, { remedy, retry });
}

function usageError(message) {
  return new FirstRunError("USAGE", message, {
    exitCode: 2,
    remedy: "Run ./actionproxy --help.",
  });
}

export function formatFirstRunError(error) {
  const normalized =
    error instanceof FirstRunError
      ? error
      : new FirstRunError(
          "UNEXPECTED",
          error instanceof Error ? error.message : String(error),
        );
  return [
    `[${normalized.code}] ${normalized.message}`,
    normalized.remedy ? `Fix: ${normalized.remedy}` : undefined,
    normalized.retry ? `Retry: ${normalized.retry}` : undefined,
  ]
    .filter(Boolean)
    .join("\n");
}

async function main() {
  try {
    process.exitCode = await runFirstRun();
  } catch (error) {
    const exitCode = error instanceof FirstRunError ? error.exitCode : 1;
    if (exitCode === 0)
      process.stdout.write(
        "First Run cancelled. No runtime key was retained.\n",
      );
    else process.stderr.write(`${formatFirstRunError(error)}\n`);
    process.exitCode = exitCode;
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}
