import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { deflateRawSync } from "node:zlib";
import {
  APPROVAL_TIMEOUT_MS,
  CHECK_IDS,
  EXPECTED_DEMO_TOOLS,
  INTEGRATION_MODES,
  INTEGRATION_STARTER_SCHEMA_VERSION,
  appendTail,
  checkoutIdentity,
  createIntegrationStarter,
  createStatusSnapshot,
  dockerProgressStage,
  firstRunPaths,
  extractSingleZipEntry,
  mcpCommand,
  parseArguments,
  parseComposePort,
  profileMarker,
  profileMarkerPath,
  redact,
  readHiddenSecret,
  readTerminalLine,
  runFirstRun,
  tunnelClientAsset,
  tunnelClientInstallPaths,
  tunnelProfilePaths,
  validRuntimeKey,
  validateDoctorReport,
  validateTunnelHealthUrl,
  validateTunnelClientDistribution,
} from "./first-run.mjs";

const containerId = "a".repeat(64);
const sessionIds = [
  "01234567-89ab-4cde-8fab-0123456789ab",
  "11234567-89ab-4cde-8fab-0123456789ab",
  "21234567-89ab-4cde-8fab-0123456789ab",
];
const doctorReport = JSON.stringify({
  coverage: "configured_mcp_wrapper",
  mode: "discover",
  ok: true,
  servers: [
    {
      discovery: {
        status: "verified",
        toolCount: 3,
        tools: EXPECTED_DEMO_TOOLS,
      },
      name: "chatgpt-tunnel-demo",
    },
  ],
  version: "actionproxy.tool-plane-report.v1",
});

function syntheticMachO(platformKey = "darwin-arm64") {
  const binary = Buffer.alloc(96, 0);
  binary.writeUInt32LE(0xfeedfacf, 0);
  binary.writeUInt32LE(
    platformKey === "darwin-amd64" ? 0x01000007 : 0x0100000c,
    4,
  );
  binary.write("ActionProxy deterministic tunnel-client fixture", 16, "utf8");
  return binary;
}

function singleEntryZip(entryName, contents, { mode = 0o100755 } = {}) {
  const name = Buffer.from(entryName, "utf8");
  const compressed = deflateRawSync(contents);
  const local = Buffer.alloc(30 + name.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(8, 8);
  local.writeUInt32LE(0, 14);
  local.writeUInt32LE(compressed.length, 18);
  local.writeUInt32LE(contents.length, 22);
  local.writeUInt16LE(name.length, 26);
  local.writeUInt16LE(0, 28);
  name.copy(local, 30);

  const central = Buffer.alloc(46 + name.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE((3 << 8) | 30, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 8);
  central.writeUInt16LE(8, 10);
  central.writeUInt32LE(0, 16);
  central.writeUInt32LE(compressed.length, 20);
  central.writeUInt32LE(contents.length, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt32LE((mode << 16) >>> 0, 38);
  central.writeUInt32LE(0, 42);
  name.copy(central, 46);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(local.length + compressed.length, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([local, compressed, central, end]);
}

function configureSyntheticTunnelClient(fixture, platformKey = "darwin-arm64") {
  const binary = syntheticMachO(platformKey);
  const archive = singleEntryZip("tunnel-client", binary);
  const filename = path.join(
    fixture.repoRoot,
    "examples",
    "chatgpt-tunnel",
    "tunnel-client-distribution.json",
  );
  const distribution = JSON.parse(fs.readFileSync(filename, "utf8"));
  const asset = distribution.assets[platformKey];
  asset.archiveSize = archive.length;
  asset.archiveSha256 = createHash("sha256").update(archive).digest("hex");
  asset.binarySize = binary.length;
  asset.binarySha256 = createHash("sha256").update(binary).digest("hex");
  fs.writeFileSync(filename, `${JSON.stringify(distribution, null, 2)}\n`);
  validateTunnelClientDistribution(distribution);
  return { archive, asset, binary, distribution };
}

function binaryResponse(bytes, { headers = {}, status = 200 } = {}) {
  const normalizedHeaders = new Map(
    Object.entries(headers).map(([key, value]) => [
      key.toLowerCase(),
      String(value),
    ]),
  );
  return {
    body: {
      async *[Symbol.asyncIterator]() {
        const midpoint = Math.max(1, Math.floor(bytes.length / 2));
        yield bytes.subarray(0, midpoint);
        yield bytes.subarray(midpoint);
      },
    },
    headers: {
      get: (name) => normalizedHeaders.get(String(name).toLowerCase()) ?? null,
    },
    ok: status >= 200 && status < 300,
    status,
  };
}

function syntheticTunnelCommand(base, distribution) {
  return async (executable, args, options) => {
    if (executable === "/usr/bin/codesign") {
      return base.runCommand(executable, args, options);
    }
    if (
      path.basename(executable) === "tunnel-client" &&
      executable !== "tunnel-client"
    ) {
      if (args[0] === "--version" || args[0] === "version") {
        return {
          code: 0,
          stderr: "",
          stdout: `${distribution.expectedVersion} (git sha: ${distribution.releaseCommit})`,
        };
      }
      return base.runCommand("tunnel-client", args, options);
    }
    return base.runCommand(executable, args, options);
  };
}

test("parses the public command surface and rejects ambiguous input", () => {
  assert.deepEqual(parseArguments([]), { command: undefined });
  assert.deepEqual(parseArguments(["local", "--port", "auto", "--no-open"]), {
    chatgpt: false,
    command: "local",
    json: false,
    mode: undefined,
    noOpen: true,
    output: undefined,
    port: "auto",
    profile: undefined,
    tunnelId: undefined,
    tunnelClientAction: undefined,
    verbose: false,
  });
  assert.equal(
    parseArguments([
      "chatgpt",
      "--port",
      "18787",
      "--tunnel-id",
      "tunnel_0123456789abcdef0123456789abcdef",
    ]).port,
    18787,
  );
  assert.equal(
    parseArguments([
      "chatgpt",
      "--",
      "--tunnel-id",
      "tunnel_0123456789abcdef0123456789abcdef",
    ]).tunnelId,
    "tunnel_0123456789abcdef0123456789abcdef",
  );
  assert.throws(
    () => parseArguments(["chatgpt", "--tunnel-id", "tunnel_0123456789abcdef"]),
    /32 lowercase/u,
  );
  assert.throws(() => parseArguments(["local", "--json"]), /not valid/u);
  assert.throws(() => parseArguments(["stop", "--verbose"]), /not valid/u);
  assert.throws(() => parseArguments(["local", "--port", "80"]), /1024/u);
  assert.throws(() => parseArguments(["local", "--port"]), /incomplete/u);
  assert.equal(
    parseArguments(["integrate", "--mode", "sdk", "--json"]).mode,
    "sdk",
  );
  assert.equal(
    parseArguments([
      "integrate",
      "--mode",
      "mcp",
      "--output",
      "my-safe-starter",
    ]).output,
    "my-safe-starter",
  );
  assert.throws(
    () => parseArguments(["integrate", "--mode", "python"]),
    /sdk, mcp, or http/u,
  );
  assert.throws(
    () =>
      parseArguments(["integrate", "--mode", "http", "--output", "../outside"]),
    /single-directory/u,
  );
  assert.equal(
    parseArguments(["tunnel-client", "install", "--json"]).tunnelClientAction,
    "install",
  );
  assert.equal(
    parseArguments(["tunnel-client", "status"]).tunnelClientAction,
    "status",
  );
  assert.throws(
    () => parseArguments(["tunnel-client", "upgrade"]),
    /install, status, or remove/u,
  );
});

test("integration starters are deterministic, local-only, and machine-readable", () => {
  assert.deepEqual(INTEGRATION_MODES, ["sdk", "mcp", "http"]);
  for (const mode of INTEGRATION_MODES) {
    const first = createIntegrationStarter(mode);
    const second = createIntegrationStarter(mode);
    assert.deepEqual(first, second);
    assert.equal(first.schemaVersion, INTEGRATION_STARTER_SCHEMA_VERSION);
    assert.equal(first.mode, mode);
    assert.ok(first.proofChecklist.length >= 2);
    assert.ok(
      first.proofChecklist.every((item) =>
        [
          "automatic",
          "automatic_after_approval",
          "manual_required",
          "manual_then_automatic",
        ].includes(item.verification),
      ),
    );
    assert.ok(first.files.length >= 4);
    for (const file of first.files) {
      assert.match(file.path, /^(?!\/)(?!.*\.\.)[A-Za-z0-9./_-]+$/u);
      assert.match(file.sha256, /^[0-9a-f]{64}$/u);
      assert.equal(
        createHash("sha256").update(file.content).digest("hex"),
        file.sha256,
        `${mode}:${file.path}`,
      );
      assert.doesNotMatch(
        file.content,
        /CONTROL_PLANE_API_KEY|OPENAI_API_KEY/u,
      );
    }
    const descriptor = JSON.parse(
      first.files.find((file) => file.path === "actionproxy-integration.json")
        .content,
    );
    assert.equal(descriptor.schemaVersion, INTEGRATION_STARTER_SCHEMA_VERSION);
    assert.equal(descriptor.mode, mode);
    assert.equal(Object.hasOwn(descriptor, "actionProxySource"), false);
    assert.deepEqual(descriptor.sourceBinding, {
      containsCredential: false,
      localOnly: true,
      path: "actionproxy-source.json",
      purpose: "locate_the_reviewed_local_source_checkout",
    });
    assert.equal(
      descriptor.policyArtifact.enforcement,
      "sample_only_not_loaded_by_first_run",
    );
    assert.ok(
      first.files.some(
        (file) => file.path === "actionproxy.policy.sample.yaml",
      ),
    );
    assert.match(
      first.files.find((file) => file.path === ".gitignore").content,
      /^actionproxy-source\.json\nnode_modules\/\nvendor\/\*\.tgz\n$/u,
    );
  }
  const sdkPackage = JSON.parse(
    createIntegrationStarter("sdk").files.find(
      (file) => file.path === "package.json",
    ).content,
  );
  assert.equal(
    sdkPackage.dependencies["@actionproxy/sdk-js"],
    "file:vendor/actionproxy-sdk-js-0.1.1.tgz",
  );
  const sdkStarter = createIntegrationStarter("sdk");
  assert.deepEqual(sdkStarter.packageSource, {
    archive: "vendor/actionproxy-sdk-js-0.1.1.tgz",
    availability: "local_source_tarball_selected",
    kind: "local_tarball",
    packageName: "@actionproxy/sdk-js",
    registryInstallAvailable: true,
    version: "0.1.1",
  });
  assert.match(
    sdkStarter.files.find((file) => file.path === "README.md").content,
    /exact package is also available from npm/u,
  );
  assert.match(
    sdkStarter.files.find((file) => file.path === "README.md").content,
    /generated starter stays bound to the reviewed source checkout and does not probe the registry/u,
  );
  const mcpConfig = createIntegrationStarter("mcp").files.find(
    (file) => file.path === "actionproxy.mcp.yaml",
  ).content;
  assert.match(
    mcpConfig,
    /schemas\/actionproxy\.mcp-wrapper\.v1\.schema\.json/u,
  );
  assert.doesNotMatch(mcpConfig, /#.*https:\/\/actionproxy\.com\/schemas/u);
  assert.match(mcpConfig, /cancelPendingOnAbort: true/u);
  const httpProof = createIntegrationStarter("http").files.find(
    (file) => file.path === "proof.mjs",
  ).content;
  assert.doesNotMatch(httpProof, /\/approve|authorization/u);
  assert.match(httpProof, /pending_approval/u);
  assert.match(httpProof, /execution-attempts/u);
  assert.match(httpProof, /\/v1\/audit\/verify/u);
});

test("integrate writes a new isolated starter and never overwrites it", async () => {
  const fixture = createFixture();
  const consumerRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "actionproxy-consumer-integration-"),
  );
  try {
    const dependencies = fixture.dependencies({
      currentWorkingDirectory: consumerRoot,
    });
    const code = await runFirstRun(
      {
        args: [
          "integrate",
          "--mode",
          "http",
          "--output",
          "safe-http-starter",
          "--json",
        ],
        repoRoot: fixture.repoRoot,
      },
      dependencies,
    );
    assert.equal(code, 0);
    const report = JSON.parse(fixture.output.trim());
    assert.equal(report.ok, true);
    assert.equal(report.outputDirectory, "safe-http-starter");
    assert.equal(report.schemaVersion, INTEGRATION_STARTER_SCHEMA_VERSION);
    const outputRoot = path.join(consumerRoot, "safe-http-starter");
    assert.ok(fs.statSync(outputRoot).isDirectory());
    assert.equal(fs.statSync(outputRoot).mode & 0o022, 0);
    assert.ok(fs.existsSync(path.join(outputRoot, "proof.mjs")));
    const sourceBindingPath = path.join(outputRoot, "actionproxy-source.json");
    assert.equal(fs.statSync(sourceBindingPath).mode & 0o077, 0);
    assert.deepEqual(JSON.parse(fs.readFileSync(sourceBindingPath, "utf8")), {
      schemaVersion: "actionproxy.integration-source.v1",
      sourcePath: fixture.repoRoot,
    });
    assert.equal(JSON.stringify(report).includes(fixture.repoRoot), false);
    assert.equal(JSON.stringify(report).includes(consumerRoot), false);
    assert.ok(
      report.nextCommands.includes("node run-with-live-gateway.mjs --start"),
    );
    assert.equal(
      report.nextCommands.some((command) =>
        command.includes("npm install @actionproxy"),
      ),
      false,
    );
    assert.deepEqual(fixture.calls, []);

    const secondFixture = createFixture();
    try {
      const secondCode = await runFirstRun(
        {
          args: [
            "integrate",
            "--mode",
            "http",
            "--output",
            "safe-http-starter",
            "--json",
          ],
          repoRoot: secondFixture.repoRoot,
        },
        secondFixture.dependencies({
          currentWorkingDirectory: consumerRoot,
        }),
      );
      assert.equal(secondCode, 1);
      const failure = JSON.parse(secondFixture.output.trim());
      assert.equal(failure.ok, false);
      assert.equal(failure.error.code, "INTEGRATION_OUTPUT_EXISTS");
      assert.doesNotMatch(
        JSON.stringify(failure),
        new RegExp(consumerRoot, "u"),
      );
    } finally {
      secondFixture.cleanup();
    }
  } finally {
    fixture.cleanup();
    fs.rmSync(consumerRoot, { force: true, recursive: true });
  }
});

test("derives scoped project names and validates loopback-only endpoints", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "actionproxy path's space "),
  );
  try {
    const identity = checkoutIdentity(root);
    assert.match(identity.checkoutId, /^[0-9a-f]{10}$/u);
    assert.equal(
      identity.projectName,
      `actionproxy-first-run-${identity.checkoutId}`,
    );
    assert.equal(parseComposePort("127.0.0.1:18787\n"), 18787);
    assert.throws(() => parseComposePort("0.0.0.0:18787"), /127\.0\.0\.1/u);
    assert.throws(
      () => parseComposePort("127.0.0.1:18787\n127.0.0.1:18788"),
      /one published/u,
    );
    assert.equal(
      validateTunnelHealthUrl("http://127.0.0.1:49152\n"),
      "http://127.0.0.1:49152",
    );
    assert.throws(
      () => validateTunnelHealthUrl("https://example.com"),
      /loopback/u,
    );
    assert.match(
      mcpCommand(identity.projectName),
      new RegExp(`--project-name ${identity.projectName}`, "u"),
    );
    assert.equal(
      tunnelClientAsset("darwin", "x64"),
      "tunnel-client-v<VERSION>-darwin-amd64.zip",
    );
    assert.equal(
      tunnelClientAsset("darwin", "arm64"),
      "tunnel-client-v<VERSION>-darwin-arm64.zip",
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("strictly validates discovery, status snapshots, profiles, and runtime keys", () => {
  assert.equal(validateDoctorReport(doctorReport).ok, true);
  assert.throws(
    () =>
      validateDoctorReport(
        JSON.stringify({ ...JSON.parse(doctorReport), servers: [] }),
      ),
    /exactly/u,
  );
  assert.equal(validRuntimeKey("runtime-test-key"), "runtime-test-key");
  assert.throws(() => validRuntimeKey(" padded "), /unpadded/u);
  assert.throws(() => validRuntimeKey("bad\nkey"), /control/u);
  assert.equal(
    redact("split runtime-test-key output", ["runtime-test-key"]),
    "split [REDACTED] output",
  );
  assert.equal(appendTail("", `discard-${"x".repeat(80)}`, 32), "x".repeat(32));
  assert.equal(
    dockerProgressStage(
      "#12 [actionproxy builder 4/8] RUN corepack pnpm build",
    ),
    "build actionproxy builder 4/8",
  );
  assert.equal(
    dockerProgressStage("Container actionproxy-first-run Starting"),
    "runtime starting",
  );

  const snapshot = createStatusSnapshot({
    checks: [{ id: "gateway", state: "pass" }],
    journey: "local",
    sessionId: sessionIds[0],
    setupDetails: {
      composeVersion: "v2.35.1-desktop.1",
      dockerVersion: "28.1.1",
      nodeVersion: "24.11.0",
      port: 18787,
      projectName: "actionproxy-first-run-0123456789",
    },
    setupStage: "gateway_ready",
  });
  assert.equal(snapshot.approvalTimeoutMs, APPROVAL_TIMEOUT_MS);
  assert.deepEqual(
    snapshot.checks.map((check) => check.id),
    CHECK_IDS,
  );
  assert.equal(
    snapshot.checks.find((check) => check.id === "gateway").state,
    "pass",
  );
  assert.deepEqual(snapshot.setupDetails, {
    composeVersion: "v2.35.1-desktop.1",
    dockerVersion: "28.1.1",
    nodeVersion: "24.11.0",
    port: 18787,
    projectName: "actionproxy-first-run-0123456789",
  });
  assert.throws(
    () =>
      createStatusSnapshot({
        checks: [
          { id: "gateway", remediationCode: "arbitrary", state: "fail" },
        ],
        journey: "local",
        sessionId: sessionIds[0],
        setupStage: "failed",
      }),
    /remediation/u,
  );
  for (const setupDetails of [
    {
      composeVersion: "2.35.1",
      dockerVersion: "Docker version 28.1.1",
      nodeVersion: "24.11.0",
      port: 18787,
      projectName: "actionproxy-first-run-0123456789",
    },
    {
      composeVersion: "2.35.1",
      dockerVersion: "28.1.1",
      nodeVersion: "24.11.0",
      port: 80,
      projectName: "actionproxy-first-run-0123456789",
    },
    {
      composeVersion: "2.35.1",
      dockerVersion: "28.1.1",
      nodeVersion: "24.11.0",
      port: 18787,
      projectName: "actionproxy-first-run-unsafe",
    },
  ]) {
    assert.throws(
      () =>
        createStatusSnapshot({
          checks: [],
          journey: "local",
          sessionId: sessionIds[0],
          setupDetails,
          setupStage: "gateway_ready",
        }),
      /invalid/u,
    );
  }

  const marker = profileMarker({
    projectName: "actionproxy-first-run-0123456789",
    tunnelId: "tunnel_0123456789abcdef0123456789abcdef",
  });
  assert.equal(marker.composeProject, "actionproxy-first-run-0123456789");
  assert.match(marker.commandHash, /^[0-9a-f]{64}$/u);
});

test("the pinned tunnel-client ZIP parser accepts one regular entry and rejects unsafe inventory", () => {
  const binary = syntheticMachO();
  const archive = singleEntryZip("tunnel-client", binary);
  assert.deepEqual(
    extractSingleZipEntry(archive, "tunnel-client", binary.length),
    binary,
  );
  assert.throws(
    () =>
      extractSingleZipEntry(
        singleEntryZip("../tunnel-client", binary),
        "tunnel-client",
        binary.length,
      ),
    /archive structure is invalid/u,
  );
  assert.throws(
    () =>
      extractSingleZipEntry(
        singleEntryZip("tunnel-client", binary, { mode: 0o120777 }),
        "tunnel-client",
        binary.length,
      ),
    /archive structure is invalid/u,
  );
  const distribution = JSON.parse(
    fs.readFileSync(
      new URL(
        "../examples/chatgpt-tunnel/tunnel-client-distribution.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  distribution.assets["darwin-arm64"].url =
    "https://example.com/tunnel-client.zip";
  assert.throws(
    () => validateTunnelClientDistribution(distribution),
    (error) => error.code === "TUNNEL_CLIENT_DISTRIBUTION_INVALID",
  );
});

test("local journey uses an automatic loopback port, exact discovery, private state, and status update", async () => {
  const fixture = createFixture();
  try {
    const result = await runFirstRun(
      {
        args: ["local", "--no-open"],
        env: { ACTIONPROXY_DOCKER_PORT: "19999", PATH: process.env.PATH },
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies(),
    );
    assert.equal(result, 0);
    const up = fixture.calls.find(
      (call) => call.executable === "docker" && call.args.includes("up"),
    );
    assert.ok(up);
    assert.equal(up.env.ACTIONPROXY_DOCKER_PORT, "0");
    assert.match(up.env.ACTIONPROXY_QUICKSTART_UPDATE_TOKEN, /^[0-9a-f]{64}$/u);
    assert.match(up.env.ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN, /^[0-9a-f]{64}$/u);
    assert.notEqual(
      up.env.ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN,
      up.env.ACTIONPROXY_QUICKSTART_UPDATE_TOKEN,
    );
    assert.match(
      up.args.join(" "),
      /compose --project-name actionproxy-first-run-[0-9a-f]{10} -f docker-compose\.yml up -d --build actionproxy/u,
    );
    assert.ok(
      fixture.calls.some(
        (call) => call.args.includes("port") && call.args.includes("8787"),
      ),
    );
    assert.ok(
      fixture.calls.some(
        (call) =>
          call.args.includes("--json") && call.args.includes("--discover"),
      ),
    );
    assert.match(fixture.output, /Local gateway ready/u);
    assert.match(fixture.output, /macOS arm64/u);
    assert.match(fixture.output, /127\.0\.0\.1:18787/u);

    const stateFile = firstRunPaths(fixture.repoRoot).state;
    const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    assert.equal(state.port, 18787);
    assert.equal(state.journey, "local");
    assert.equal(Object.hasOwn(state, "quickstartUpdateToken"), false);
    assert.equal(fs.statSync(stateFile).mode & 0o777, 0o600);
    assert.equal(
      fs.existsSync(firstRunPaths(fixture.repoRoot).lockDirectory),
      false,
    );
    assert.equal(fixture.statuses.at(-1).setupStage, "gateway_ready");
    assert.deepEqual(fixture.statuses.at(-1).setupDetails, {
      composeVersion: "2.35.1",
      dockerVersion: "28.1.1",
      nodeVersion: process.versions.node,
      port: 18787,
      projectName: checkoutIdentity(fixture.repoRoot).projectName,
    });
    assert.equal(
      fixture.statuses.at(-1).checks.find((check) => check.id === "storage")
        .state,
      "pass",
    );
  } finally {
    fixture.cleanup();
  }
});

test("ChatGPT journey keeps the runtime key out of argv, Docker, output, state, and profile", async () => {
  const fixture = createFixture();
  const runtimeKey = "runtime-key-canary-do-not-leak";
  try {
    const result = await runFirstRun(
      {
        args: [
          "chatgpt",
          "--no-open",
          "--tunnel-id",
          "tunnel_0123456789abcdef0123456789abcdef",
        ],
        env: {
          ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN: "ambient-origin-canary", // public-secret-scan: allow
          ACTIONPROXY_QUICKSTART_UPDATE_TOKEN: "ambient-update-canary", // public-secret-scan: allow
          PATH: process.env.PATH,
        },
        legacyRuntimeKey: runtimeKey,
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies({ tunnelInterrupted: true }),
    );
    assert.equal(result, 0);

    const dockerCalls = fixture.calls.filter(
      (call) => call.executable === "docker",
    );
    assert.equal(
      dockerCalls.some((call) => JSON.stringify(call).includes(runtimeKey)),
      false,
    );
    assert.equal(
      dockerCalls.some(
        (call) => call.env.CONTROL_PLANE_API_KEY || call.env.OPENAI_API_KEY,
      ),
      false,
    );
    assert.ok(
      dockerCalls.every(
        (call) =>
          call.env.ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN !==
            "ambient-origin-canary" &&
          call.env.ACTIONPROXY_QUICKSTART_UPDATE_TOKEN !==
            "ambient-update-canary",
      ),
    );
    assert.ok(dockerCalls.some((call) => call.args.includes("config")));
    const tunnelCalls = fixture.calls.filter(
      (call) => call.executable === "tunnel-client",
    );
    assert.ok(tunnelCalls.some((call) => call.args[0] === "init"));
    assert.ok(tunnelCalls.some((call) => call.args[0] === "doctor"));
    assert.ok(tunnelCalls.some((call) => call.args[0] === "run"));
    assert.equal(JSON.stringify(tunnelCalls).includes(runtimeKey), false);
    assert.equal(
      tunnelCalls.some(
        (call) =>
          call.env.CONTROL_PLANE_API_KEY ||
          call.env.OPENAI_API_KEY ||
          call.env.ACTIONPROXY_QUICKSTART_ORIGIN_TOKEN ||
          call.env.ACTIONPROXY_QUICKSTART_UPDATE_TOKEN,
      ),
      false,
    );
    assert.ok(
      tunnelCalls
        .filter(
          (call) =>
            call.args[0] === "doctor" ||
            (call.args[0] === "run" && call.args[1] !== "--help"),
        )
        .every((call) =>
          call.args.some((argument) =>
            argument.startsWith("--control-plane.api-key=file:"),
          ),
        ),
    );
    const doctorKeyReference = tunnelCalls
      .find((call) => call.args[0] === "doctor")
      .args.find((argument) =>
        argument.startsWith("--control-plane.api-key=file:"),
      );
    const temporaryKeyPath = doctorKeyReference.slice(
      "--control-plane.api-key=file:".length,
    );
    assert.equal(
      path.relative(fixture.repoRoot, temporaryKeyPath).startsWith(".."),
      true,
    );
    assert.equal(fs.existsSync(temporaryKeyPath), false);

    const state = fs.readFileSync(
      firstRunPaths(fixture.repoRoot).state,
      "utf8",
    );
    assert.equal(state.includes(runtimeKey), false);
    const identity = checkoutIdentity(fixture.repoRoot);
    const markerFile = profileMarkerPath(
      fixture.repoRoot,
      `actionproxy-local-${identity.checkoutId}`,
    );
    const marker = fs.readFileSync(markerFile, "utf8");
    assert.equal(marker.includes(runtimeKey), false);
    assert.equal(fs.statSync(markerFile).mode & 0o777, 0o600);
    assert.equal(fixture.output.includes(runtimeKey), false);
    assert.match(fixture.output, /Official OpenAI links reviewed 2026-08-03/u);
    assert.equal(
      fs.existsSync(
        path.join(firstRunPaths(fixture.repoRoot).root, sessionIds[0]),
      ),
      false,
    );
    assert.ok(
      fixture.statuses.some((status) => status.setupStage === "tunnel_ready"),
    );
    assert.ok(
      fixture.statuses.every(
        (status) =>
          status.setupDetails?.composeVersion === "2.35.1" &&
          status.setupDetails?.dockerVersion === "28.1.1" &&
          status.setupDetails?.nodeVersion === process.versions.node &&
          status.setupDetails?.port === 18787 &&
          status.setupDetails?.projectName ===
            checkoutIdentity(fixture.repoRoot).projectName,
      ),
    );
    assert.equal(fixture.statuses.at(-1).setupStage, "tunnel_stopped");
  } finally {
    fixture.cleanup();
  }
});

test("strict automation reads a private caller-owned key file and leaves it owned by the caller", async () => {
  const fixture = createFixture();
  const secretDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "actionproxy-caller-secret-"),
  );
  const secretFile = path.join(secretDirectory, "runtime-key");
  const runtimeKey = "strict-file-runtime-key-canary";
  fs.writeFileSync(secretFile, runtimeKey, { mode: 0o600 });
  fs.chmodSync(secretFile, 0o600);
  try {
    const result = await runFirstRun(
      {
        args: [
          "chatgpt",
          "--no-open",
          "--tunnel-id",
          "tunnel_0123456789abcdef0123456789abcdef",
        ],
        env: {
          ACTIONPROXY_CONTROL_PLANE_KEY_FILE: fs.realpathSync(secretFile),
          PATH: process.env.PATH,
        },
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies({ tunnelInterrupted: true }),
    );
    assert.equal(result, 0);
    assert.equal(fs.readFileSync(secretFile, "utf8"), runtimeKey);
    assert.equal(JSON.stringify(fixture.calls).includes(runtimeKey), false);
    assert.equal(fixture.output.includes(runtimeKey), false);
    assert.equal(
      fixture.calls.some(
        (call) =>
          call.env.ACTIONPROXY_CONTROL_PLANE_KEY_FILE ||
          call.env.CONTROL_PLANE_API_KEY,
      ),
      false,
    );
  } finally {
    fixture.cleanup();
    fs.rmSync(secretDirectory, { force: true, recursive: true });
  }
});

test("a surviving runtime-key file is an authoritative failure on normal and signal exits", async () => {
  for (const signal of [undefined, "SIGINT", "SIGTERM"]) {
    const fixture = createFixture();
    const signalEmitter = new EventEmitter();
    let keyPath;
    const guardedFileSystem = Object.create(fs);
    guardedFileSystem.writeFileSync = (filename, ...args) => {
      if (path.basename(String(filename)) === "runtime-key") {
        keyPath = String(filename);
      }
      return fs.writeFileSync(filename, ...args);
    };
    guardedFileSystem.unlinkSync = (filename) => {
      if (keyPath && String(filename) === keyPath) {
        const error = new Error("simulated runtime-key deletion denial");
        error.code = "EACCES";
        throw error;
      }
      return fs.unlinkSync(filename);
    };
    try {
      const base = fixture.dependencies({
        fileSystem: guardedFileSystem,
        signalEmitter,
      });
      await assert.rejects(
        runFirstRun(
          {
            args: [
              "chatgpt",
              "--no-open",
              "--tunnel-id",
              "tunnel_0123456789abcdef0123456789abcdef",
            ],
            legacyRuntimeKey: `cleanup-failure-key-${signal ?? "normal"}`,
            repoRoot: fixture.repoRoot,
          },
          {
            ...base,
            runForeground: signal
              ? async (...args) => {
                  const running = base.runForeground(...args);
                  signalEmitter.emit(signal);
                  const result = await running;
                  return { ...result, interrupted: true };
                }
              : base.runForeground,
          },
        ),
        (error) => {
          assert.equal(error.code, "RUNTIME_KEY_CLEANUP_FAILED");
          assert.equal(error.exitCode, 1);
          assert.match(error.remedy, /Delete the remaining file/u);
          return true;
        },
        signal ?? "normal exit",
      );
      assert.ok(keyPath);
      assert.equal(fs.existsSync(keyPath), true);
      assert.equal(
        fs.existsSync(firstRunPaths(fixture.repoRoot).lockDirectory),
        false,
      );
      assert.equal(
        fixture.output.includes(`cleanup-failure-key-${signal ?? "normal"}`),
        false,
      );
    } finally {
      if (keyPath) {
        try {
          fs.unlinkSync(keyPath);
        } catch {
          /* test cleanup */
        }
        fs.rmSync(path.dirname(keyPath), { force: true, recursive: true });
      }
      fixture.cleanup();
    }
  }
});

test("the long-lived JavaScript entry point rejects raw environment credentials", async () => {
  const fixture = createFixture();
  try {
    await assert.rejects(
      runFirstRun(
        {
          args: [
            "chatgpt",
            "--no-open",
            "--tunnel-id",
            "tunnel_0123456789abcdef0123456789abcdef",
          ],
          env: {
            CONTROL_PLANE_API_KEY: "raw-environment-rejection-canary", // public-secret-scan: allow
            PATH: process.env.PATH,
          },
          repoRoot: fixture.repoRoot,
        },
        fixture.dependencies(),
      ),
      (error) => {
        assert.equal(error.code, "USAGE");
        assert.match(error.message, /accepted only by \.\/actionproxy/u);
        return true;
      },
    );
    assert.deepEqual(fixture.calls, []);
  } finally {
    fixture.cleanup();
  }
});

test("explicit tunnel-client install is pinned, private, reusable offline, and exactly removable", async () => {
  const fixture = createFixture();
  const setup = configureSyntheticTunnelClient(fixture);
  const base = fixture.dependencies();
  const installPaths = tunnelClientInstallPaths(fixture.repoRoot);
  let downloads = 0;
  const dependencies = {
    ...base,
    fetchFn: async (url, options) => {
      if (String(url) === setup.asset.url) {
        downloads += 1;
        assert.equal(options.redirect, "manual");
        assert.equal(options.headers.accept, "application/octet-stream");
        assert.equal(options.headers.authorization, undefined);
        return binaryResponse(setup.archive, {
          headers: { "content-length": setup.archive.length },
        });
      }
      return base.fetchFn(url, options);
    },
    runCommand: syntheticTunnelCommand(base, setup.distribution),
  };
  try {
    const installed = await runFirstRun(
      {
        args: ["tunnel-client", "install", "--json"],
        env: {
          ...process.env,
          ACTIONPROXY_PROBE_ENV_CANARY: "ambient-probe-canary",
        },
        repoRoot: fixture.repoRoot,
      },
      dependencies,
    );
    assert.equal(installed, 0);
    assert.equal(downloads, 1);
    const report = JSON.parse(fixture.output);
    assert.equal(report.action, "install");
    assert.equal(report.compatible, true);
    assert.equal(report.installedByActionProxy, true);
    assert.equal(report.releaseTag, "v0.0.10");
    assert.equal(fs.statSync(installPaths.directory).mode & 0o777, 0o700);
    assert.equal(fs.statSync(installPaths.binary).mode & 0o777, 0o700);
    assert.equal(fs.statSync(installPaths.receipt).mode & 0o777, 0o600);
    assert.equal(
      createHash("sha256")
        .update(fs.readFileSync(installPaths.binary))
        .digest("hex"),
      setup.asset.binarySha256,
    );
    const receiptText = fs.readFileSync(installPaths.receipt, "utf8");
    const receipt = JSON.parse(receiptText);
    assert.equal(receipt.binarySha256, setup.asset.binarySha256);
    assert.equal(receipt.source, "actionproxy-reviewed-release");
    assert.doesNotMatch(receiptText, new RegExp(fixture.repoRoot, "u"));
    assert.doesNotMatch(
      receiptText,
      /tunnel_[0-9a-f]+|explicit-install-runtime-key-canary/u,
    );
    assert.deepEqual(fs.readdirSync(installPaths.directory).sort(), [
      "tunnel-client",
      "tunnel-client.actionproxy.json",
    ]);
    assert.equal(
      fixture.calls.some((call) =>
        Object.values(call.env).includes("ambient-probe-canary"),
      ),
      false,
    );

    await runFirstRun(
      {
        args: ["tunnel-client", "install"],
        env: {
          PATH: process.env.PATH,
          TUNNEL_CLIENT_BIN: "/unexpected/environment/tunnel-client",
        },
        repoRoot: fixture.repoRoot,
      },
      {
        ...dependencies,
        fetchFn: async () => {
          assert.fail("a verified local install must be reusable offline");
        },
      },
    );
    assert.equal(downloads, 1);
    assert.equal(
      fixture.calls.some(
        (call) => call.executable === "/unexpected/environment/tunnel-client",
      ),
      false,
    );

    fs.appendFileSync(installPaths.binary, "changed");
    await assert.rejects(
      runFirstRun(
        { args: ["tunnel-client", "remove"], repoRoot: fixture.repoRoot },
        dependencies,
      ),
      (error) => error.code === "TUNNEL_CLIENT_REMOVE_MODIFIED",
    );
    assert.equal(fs.existsSync(installPaths.binary), true);
    fs.writeFileSync(installPaths.binary, setup.binary, { mode: 0o700 });
    fs.chmodSync(installPaths.binary, 0o700);
    fs.writeFileSync(
      path.join(
        fixture.repoRoot,
        "examples",
        "chatgpt-tunnel",
        "tunnel-client-distribution.json",
      ),
      '{"futureRelease":true}\n',
    );

    const removed = await runFirstRun(
      {
        args: ["tunnel-client", "remove", "--json"],
        repoRoot: fixture.repoRoot,
      },
      dependencies,
    );
    assert.equal(removed, 0);
    assert.equal(fs.existsSync(installPaths.binary), false);
    assert.equal(fs.existsSync(installPaths.receipt), false);
    assert.equal(
      fs.existsSync(path.join(fixture.repoRoot, ".actionproxy")),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("the ChatGPT concierge installs only after explicit I consent and continues in place", async () => {
  const fixture = createFixture();
  const setup = configureSyntheticTunnelClient(fixture);
  const base = fixture.dependencies();
  let downloads = 0;
  try {
    const result = await runFirstRun(
      {
        args: [
          "chatgpt",
          "--no-open",
          "--tunnel-id",
          "tunnel_0123456789abcdef0123456789abcdef",
        ],
        legacyRuntimeKey: "explicit-install-runtime-key-canary",
        repoRoot: fixture.repoRoot,
      },
      {
        ...base,
        fetchFn: async (url, options) => {
          if (String(url) === setup.asset.url) {
            downloads += 1;
            return binaryResponse(setup.archive, {
              headers: { "content-length": setup.archive.length },
            });
          }
          return base.fetchFn(url, options);
        },
        isTTY: true,
        promptLine: async () => "i",
        runCommand: async (executable, args, options) => {
          if (executable === "tunnel-client") {
            const error = new Error("not found");
            error.code = "ENOENT";
            throw error;
          }
          return syntheticTunnelCommand(base, setup.distribution)(
            executable,
            args,
            options,
          );
        },
        tunnelInterrupted: true,
      },
    );
    assert.equal(result, 0);
    assert.equal(downloads, 1);
    assert.match(fixture.output, /I  Install locally now \(recommended\)/u);
    assert.match(fixture.output, /installed only in this checkout/u);
    assert.match(fixture.output, /Secure tunnel ready/u);
    assert.equal(
      fs.existsSync(tunnelClientInstallPaths(fixture.repoRoot).binary),
      true,
    );
    assert.doesNotMatch(fixture.output, /explicit-install-runtime-key-canary/u);
  } finally {
    fixture.cleanup();
  }
});

test("checksum failure and unowned files leave no managed tunnel-client", async () => {
  const fixture = createFixture();
  const setup = configureSyntheticTunnelClient(fixture);
  const base = fixture.dependencies();
  const installPaths = tunnelClientInstallPaths(fixture.repoRoot);
  const corrupted = Buffer.from(setup.archive);
  corrupted[Math.floor(corrupted.length / 2)] ^= 0xff;
  try {
    await assert.rejects(
      runFirstRun(
        {
          args: ["tunnel-client", "install"],
          repoRoot: fixture.repoRoot,
        },
        {
          ...base,
          fetchFn: async () =>
            binaryResponse(corrupted, {
              headers: { "content-length": corrupted.length },
            }),
          runCommand: syntheticTunnelCommand(base, setup.distribution),
        },
      ),
      (error) => error.code === "TUNNEL_CLIENT_CHECKSUM_MISMATCH",
    );
    assert.equal(fs.existsSync(installPaths.binary), false);
    assert.equal(fs.existsSync(installPaths.receipt), false);
    assert.equal(
      fs.existsSync(installPaths.directory)
        ? fs
            .readdirSync(installPaths.directory)
            .some((entry) => entry.startsWith(".install-"))
        : false,
      false,
    );

    fs.mkdirSync(installPaths.directory, { mode: 0o700, recursive: true });
    fs.writeFileSync(installPaths.binary, "manual", { mode: 0o700 });
    await assert.rejects(
      runFirstRun(
        { args: ["tunnel-client", "install"], repoRoot: fixture.repoRoot },
        {
          ...base,
          fetchFn: async () => {
            assert.fail("an existing manual file must block before download");
          },
          runCommand: async (executable, args, options) => {
            if (String(executable) === installPaths.binary) {
              assert.fail("an unowned destination must not be executed");
            }
            return base.runCommand(executable, args, options);
          },
        },
      ),
      (error) => error.code === "TUNNEL_CLIENT_INSTALL_CONFLICT",
    );
    await assert.rejects(
      runFirstRun(
        { args: ["tunnel-client", "remove"], repoRoot: fixture.repoRoot },
        base,
      ),
      (error) => error.code === "TUNNEL_CLIENT_REMOVE_UNOWNED",
    );
    assert.equal(fs.readFileSync(installPaths.binary, "utf8"), "manual");
  } finally {
    fixture.cleanup();
  }
});

test("tunnel-client removal refuses a dangling replacement symlink", async () => {
  const fixture = createFixture();
  const setup = configureSyntheticTunnelClient(fixture);
  const base = fixture.dependencies();
  const installPaths = tunnelClientInstallPaths(fixture.repoRoot);
  try {
    await runFirstRun(
      { args: ["tunnel-client", "install"], repoRoot: fixture.repoRoot },
      {
        ...base,
        fetchFn: async () =>
          binaryResponse(setup.archive, {
            headers: { "content-length": setup.archive.length },
          }),
        runCommand: syntheticTunnelCommand(base, setup.distribution),
      },
    );
    fs.unlinkSync(installPaths.binary);
    fs.symlinkSync("missing-replacement", installPaths.binary);

    await assert.rejects(
      runFirstRun(
        { args: ["tunnel-client", "remove"], repoRoot: fixture.repoRoot },
        base,
      ),
      (error) => error.code === "TUNNEL_CLIENT_REMOVE_MODIFIED",
    );
    assert.equal(fs.lstatSync(installPaths.binary).isSymbolicLink(), true);
    assert.equal(fs.existsSync(installPaths.receipt), true);
  } finally {
    fixture.cleanup();
  }
});

test("tunnel-client removal refuses a file identity change after hashing", async () => {
  const fixture = createFixture();
  const setup = configureSyntheticTunnelClient(fixture);
  const base = fixture.dependencies();
  const installPaths = tunnelClientInstallPaths(fixture.repoRoot);
  try {
    await runFirstRun(
      { args: ["tunnel-client", "install"], repoRoot: fixture.repoRoot },
      {
        ...base,
        fetchFn: async () =>
          binaryResponse(setup.archive, {
            headers: { "content-length": setup.archive.length },
          }),
        runCommand: syntheticTunnelCommand(base, setup.distribution),
      },
    );

    let binaryHashed = false;
    let postHashStats = 0;
    const guardedFileSystem = Object.create(fs);
    guardedFileSystem.readFileSync = (filename, ...args) => {
      const result = fs.readFileSync(filename, ...args);
      if (String(filename) === installPaths.binary) binaryHashed = true;
      return result;
    };
    guardedFileSystem.lstatSync = (filename, ...args) => {
      const stats = fs.lstatSync(filename, ...args);
      if (String(filename) !== installPaths.binary || !binaryHashed) {
        return stats;
      }
      postHashStats += 1;
      return postHashStats === 2
        ? { ...stats, dev: stats.dev, ino: stats.ino + 1 }
        : stats;
    };

    await assert.rejects(
      runFirstRun(
        { args: ["tunnel-client", "remove"], repoRoot: fixture.repoRoot },
        fixture.dependencies({ fileSystem: guardedFileSystem }),
      ),
      (error) => error.code === "TUNNEL_CLIENT_REMOVE_MODIFIED",
    );
    assert.equal(fs.existsSync(installPaths.binary), true);
    assert.equal(fs.existsSync(installPaths.receipt), true);
  } finally {
    fixture.cleanup();
  }
});

test("an interrupted tunnel-client download leaves no installer state", async () => {
  const fixture = createFixture();
  const setup = configureSyntheticTunnelClient(fixture);
  const signalEmitter = new EventEmitter();
  const base = fixture.dependencies({ signalEmitter });
  try {
    await assert.rejects(
      runFirstRun(
        {
          args: ["tunnel-client", "install"],
          repoRoot: fixture.repoRoot,
        },
        {
          ...base,
          fetchFn: async () => ({
            body: {
              async *[Symbol.asyncIterator]() {
                yield setup.archive.subarray(
                  0,
                  Math.floor(setup.archive.length / 2),
                );
                signalEmitter.emit("SIGINT");
                throw new Error("simulated aborted response body");
              },
            },
            headers: {
              get: (name) =>
                String(name).toLowerCase() === "content-length"
                  ? String(setup.archive.length)
                  : null,
            },
            ok: true,
            status: 200,
          }),
          runCommand: syntheticTunnelCommand(base, setup.distribution),
        },
      ),
      (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
    );
    assert.equal(
      fs.existsSync(path.join(fixture.repoRoot, ".actionproxy")),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("a signal during tunnel-client verification leaves no installer state", async () => {
  const fixture = createFixture();
  const setup = configureSyntheticTunnelClient(fixture);
  const signalEmitter = new EventEmitter();
  const base = fixture.dependencies({ signalEmitter });
  try {
    await assert.rejects(
      runFirstRun(
        {
          args: ["tunnel-client", "install"],
          repoRoot: fixture.repoRoot,
        },
        {
          ...base,
          fetchFn: async () =>
            binaryResponse(setup.archive, {
              headers: { "content-length": setup.archive.length },
            }),
          runCommand: async (executable, args, options) => {
            const result = await syntheticTunnelCommand(
              base,
              setup.distribution,
            )(executable, args, options);
            if (executable === "/usr/bin/codesign") {
              signalEmitter.emit("SIGTERM");
            }
            return result;
          },
        },
      ),
      (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
    );
    assert.equal(
      fs.existsSync(path.join(fixture.repoRoot, ".actionproxy")),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("tunnel-client removal refuses a live First Run launcher", async () => {
  const fixture = createFixture();
  const setup = configureSyntheticTunnelClient(fixture);
  const base = fixture.dependencies();
  const installPaths = tunnelClientInstallPaths(fixture.repoRoot);
  try {
    await runFirstRun(
      { args: ["tunnel-client", "install"], repoRoot: fixture.repoRoot },
      {
        ...base,
        fetchFn: async () =>
          binaryResponse(setup.archive, {
            headers: { "content-length": setup.archive.length },
          }),
        runCommand: syntheticTunnelCommand(base, setup.distribution),
      },
    );
    const paths = firstRunPaths(fixture.repoRoot);
    fs.mkdirSync(paths.lockDirectory, { mode: 0o700, recursive: true });
    fs.writeFileSync(
      paths.lockOwner,
      `${JSON.stringify({
        journey: "chatgpt",
        pid: 4242,
        sessionId: sessionIds[0],
        startedAt: "2026-08-03T00:00:00.000Z",
      })}\n`,
      { mode: 0o600 },
    );
    fs.chmodSync(paths.lockOwner, 0o600);

    await assert.rejects(
      runFirstRun(
        { args: ["tunnel-client", "remove"], repoRoot: fixture.repoRoot },
        fixture.dependencies({ processKill: () => {} }),
      ),
      (error) => error.code === "FIRST_RUN_BUSY",
    );
    assert.equal(fs.existsSync(installPaths.binary), true);
    assert.equal(fs.existsSync(installPaths.receipt), true);
    assert.equal(fs.existsSync(paths.lockDirectory), true);
  } finally {
    fixture.cleanup();
  }
});

test("tunnel-client download follows only bounded HTTPS release redirects", async () => {
  const trustedFixture = createFixture();
  const trustedSetup = configureSyntheticTunnelClient(trustedFixture);
  const trustedBase = trustedFixture.dependencies();
  const redirectedUrl =
    "https://release-assets.githubusercontent.com/actionproxy-test-object";
  const seen = [];
  try {
    const code = await runFirstRun(
      {
        args: ["tunnel-client", "install"],
        repoRoot: trustedFixture.repoRoot,
      },
      {
        ...trustedBase,
        fetchFn: async (url) => {
          seen.push(String(url));
          if (String(url) === trustedSetup.asset.url) {
            return binaryResponse(Buffer.alloc(0), {
              headers: { location: redirectedUrl },
              status: 302,
            });
          }
          assert.equal(String(url), redirectedUrl);
          return binaryResponse(trustedSetup.archive, {
            headers: { "content-length": trustedSetup.archive.length },
          });
        },
        runCommand: syntheticTunnelCommand(
          trustedBase,
          trustedSetup.distribution,
        ),
      },
    );
    assert.equal(code, 0);
    assert.deepEqual(seen, [trustedSetup.asset.url, redirectedUrl]);
  } finally {
    trustedFixture.cleanup();
  }

  const rejectedFixture = createFixture();
  const rejectedSetup = configureSyntheticTunnelClient(rejectedFixture);
  const rejectedBase = rejectedFixture.dependencies();
  try {
    await assert.rejects(
      runFirstRun(
        {
          args: ["tunnel-client", "install"],
          repoRoot: rejectedFixture.repoRoot,
        },
        {
          ...rejectedBase,
          fetchFn: async () =>
            binaryResponse(Buffer.alloc(0), {
              headers: {
                location: "https://example.com/untrusted-tunnel-client.zip",
              },
              status: 302,
            }),
          runCommand: syntheticTunnelCommand(
            rejectedBase,
            rejectedSetup.distribution,
          ),
        },
      ),
      (error) => error.code === "TUNNEL_CLIENT_DOWNLOAD_UNTRUSTED",
    );
    assert.equal(
      fs.existsSync(tunnelClientInstallPaths(rejectedFixture.repoRoot).binary),
      false,
    );
  } finally {
    rejectedFixture.cleanup();
  }
});

test("an explicitly occupied Docker port produces a direct auto-port remedy", async () => {
  const fixture = createFixture();
  try {
    const base = fixture.dependencies();
    const original = base.runCommand;
    await assert.rejects(
      runFirstRun(
        {
          args: ["local", "--no-open", "--port", "18787"],
          repoRoot: fixture.repoRoot,
        },
        {
          ...base,
          runCommand: async (executable, args, options) => {
            if (executable === "docker" && args.includes("up")) {
              return {
                code: 1,
                stderr:
                  "Bind for 127.0.0.1:18787 failed: port is already allocated",
                stdout: "",
              };
            }
            return original(executable, args, options);
          },
        },
      ),
      (error) => {
        assert.equal(error.code, "PORT_OCCUPIED");
        assert.match(error.retry, /--port auto/u);
        return true;
      },
    );
  } finally {
    fixture.cleanup();
  }
});

test("missing tunnel-client remedy names the Mac asset and exact SHA-256 comparison", async () => {
  const fixture = createFixture();
  try {
    const base = fixture.dependencies({ architecture: "x64" });
    await assert.rejects(
      runFirstRun(
        {
          args: [
            "chatgpt",
            "--no-open",
            "--tunnel-id",
            "tunnel_0123456789abcdef0123456789abcdef",
          ],
          repoRoot: fixture.repoRoot,
        },
        {
          ...base,
          runCommand: async (executable, args, options) => {
            if (executable === "tunnel-client") {
              const error = new Error("not found");
              error.code = "ENOENT";
              throw error;
            }
            return base.runCommand(executable, args, options);
          },
        },
      ),
      (error) => {
        assert.match(
          error.remedy,
          /tunnel-client-v0\.0\.10-darwin-amd64\.zip/u,
        );
        assert.match(error.remedy, /SHA256SUMS\.txt/u);
        assert.match(error.remedy, /shasum -a 256/u);
        assert.match(error.remedy, /1a48616e584484f8/u);
        assert.match(error.remedy, /tunnel-client install/u);
        return true;
      },
    );
  } finally {
    fixture.cleanup();
  }
});

test("interactive ChatGPT preparation guides access actions and retries tunnel IDs inline", async () => {
  const fixture = createFixture();
  const answers = [
    "",
    "o",
    "d",
    "a",
    "not-a-tunnel",
    "tunnel_0123456789abcdef0123456789abcdef",
  ];
  let answerIndex = 0;
  try {
    const result = await runFirstRun(
      {
        args: ["chatgpt", "--no-open"],
        legacyRuntimeKey: "interactive-access-runtime-key",
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies({
        isTTY: true,
        openUrl: async () => {
          assert.fail("--no-open must suppress every browser open");
        },
        promptLine: async () => answers[answerIndex++],
        tunnelInterrupted: true,
      }),
    );
    assert.equal(result, 0);
    assert.equal(answerIndex, answers.length);
    assert.ok(
      fixture.output.indexOf("✓ Docker Compose available") <
        fixture.output.indexOf("[ChatGPT preparation 1/2]"),
    );
    assert.match(fixture.output, /No tunnel ID entered/u);
    assert.match(fixture.output, /Select the intended Platform organization/u);
    assert.match(
      fixture.output,
      /platform\.openai\.com\/settings\/organization\/tunnels/u,
    );
    assert.match(fixture.output, /developer-mode guidance/u);
    assert.match(fixture.output, /Administrator access request/u);
    assert.match(
      fixture.output,
      /grant my Platform account Tunnels Read \+ Use/u,
    );
    assert.match(fixture.output, /Invalid tunnel ID/u);
    assert.match(fixture.output, /Tunnel ID format accepted/u);
  } finally {
    fixture.cleanup();
  }
});

test("interactive ChatGPT access can pause before launcher state or Docker mutation", async () => {
  const fixture = createFixture();
  try {
    const result = await runFirstRun(
      { args: ["chatgpt", "--no-open"], repoRoot: fixture.repoRoot },
      fixture.dependencies({
        isTTY: true,
        promptLine: async () => "q",
      }),
    );
    assert.equal(result, 0);
    assert.match(fixture.output, /Setup paused/u);
    assert.match(fixture.output, /Resume: \.\/actionproxy chatgpt/u);
    assert.equal(
      fixture.calls.some(
        (call) => call.executable === "docker" && call.args.includes("up"),
      ),
      false,
    );
    assert.equal(fs.existsSync(firstRunPaths(fixture.repoRoot).root), false);
  } finally {
    fixture.cleanup();
  }
});

test("Ctrl+C while opening ChatGPT setup guidance exits as a clean interruption", async () => {
  const fixture = createFixture();
  const signalEmitter = new EventEmitter();
  try {
    await assert.rejects(
      runFirstRun(
        { args: ["chatgpt"], repoRoot: fixture.repoRoot },
        fixture.dependencies({
          isTTY: true,
          openUrl: async () => {
            signalEmitter.emit("SIGINT");
            return false;
          },
          promptLine: async () => "o",
          signalEmitter,
        }),
      ),
      (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
    );
    assert.equal(
      fixture.calls.some(
        (call) => call.executable === "docker" && call.args.includes("up"),
      ),
      false,
    );
    assert.equal(fs.existsSync(firstRunPaths(fixture.repoRoot).root), false);
  } finally {
    fixture.cleanup();
  }
});

test("Ctrl+C while opening Quickstart retains a truthful verified gateway", async () => {
  const fixture = createFixture();
  const signalEmitter = new EventEmitter();
  try {
    await assert.rejects(
      runFirstRun(
        { args: ["local"], repoRoot: fixture.repoRoot },
        fixture.dependencies({
          openUrl: async () => {
            signalEmitter.emit("SIGTERM");
            return false;
          },
          signalEmitter,
        }),
      ),
      (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
    );
    assert.equal(fixture.statuses.at(-1).setupStage, "gateway_ready");
    assert.equal(
      fixture.calls.some(
        (call) =>
          call.executable === "docker" &&
          (call.args.includes("down") || call.args.includes("rm")),
      ),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("Ctrl+C while Docker Desktop opens is not misreported as a daemon failure", async () => {
  const fixture = createFixture();
  const signalEmitter = new EventEmitter();
  const base = fixture.dependencies({ isTTY: true, signalEmitter });
  try {
    await assert.rejects(
      runFirstRun(
        { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
        {
          ...base,
          runCommand: async (executable, args, options) => {
            if (executable === "docker" && args[0] === "info") {
              return { code: 1, stderr: "daemon stopped", stdout: "" };
            }
            if (executable === "open" && args[0] === "-a") {
              signalEmitter.emit("SIGINT");
              return { code: null, interrupted: true, stderr: "", stdout: "" };
            }
            return base.runCommand(executable, args, options);
          },
        },
      ),
      (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
    );
    assert.equal(fs.existsSync(firstRunPaths(fixture.repoRoot).root), false);
  } finally {
    fixture.cleanup();
  }
});

test("noninteractive ChatGPT rejects a missing tunnel ID before external checks", async () => {
  const fixture = createFixture();
  try {
    await assert.rejects(
      runFirstRun(
        { args: ["chatgpt", "--no-open"], repoRoot: fixture.repoRoot },
        {
          ...fixture.dependencies({ isTTY: false }),
          runCommand: async () => {
            assert.fail(
              "invalid noninteractive usage must not probe the machine",
            );
          },
        },
      ),
      (error) => {
        assert.equal(error.code, "USAGE");
        assert.equal(error.exitCode, 2);
        assert.match(error.message, /Provide --tunnel-id/u);
        return true;
      },
    );
    assert.deepEqual(fixture.calls, []);
    assert.equal(fs.existsSync(firstRunPaths(fixture.repoRoot).root), false);
  } finally {
    fixture.cleanup();
  }
});

test("ChatGPT setup rejects a noncanonical external-link registry before opening it", async () => {
  const fixture = createFixture();
  const registry = path.join(
    fixture.repoRoot,
    "examples",
    "chatgpt-tunnel",
    "openai-links.json",
  );
  const value = JSON.parse(fs.readFileSync(registry, "utf8"));
  value.links.tunnelSettings.url = "file:///tmp/not-an-official-link";
  fs.writeFileSync(registry, `${JSON.stringify(value, null, 2)}\n`);
  try {
    await assert.rejects(
      runFirstRun(
        {
          args: [
            "chatgpt",
            "--tunnel-id",
            "tunnel_0123456789abcdef0123456789abcdef",
          ],
          repoRoot: fixture.repoRoot,
        },
        fixture.dependencies({
          openUrl: async () => {
            assert.fail("an invalid registry must never be opened");
          },
        }),
      ),
      (error) => error.code === "OPENAI_LINKS_INVALID",
    );
    assert.equal(
      fixture.calls.some(
        (call) => call.executable === "docker" && call.args.includes("up"),
      ),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("interactive missing tunnel-client reveals optional help and rechecks in place", async () => {
  const fixture = createFixture();
  const base = fixture.dependencies();
  const actions = ["m", "d", "o", "c", "r"];
  const opened = [];
  let actionIndex = 0;
  let missingChecks = 0;
  try {
    const result = await runFirstRun(
      {
        args: [
          "chatgpt",
          "--tunnel-id",
          "tunnel_0123456789abcdef0123456789abcdef",
        ],
        legacyRuntimeKey: "interactive-client-runtime-key",
        repoRoot: fixture.repoRoot,
      },
      {
        ...base,
        isTTY: true,
        openUrl: async (url) => {
          opened.push(String(url));
          return true;
        },
        promptLine: async () => actions[actionIndex++],
        runCommand: async (executable, args, options) => {
          if (
            executable === "tunnel-client" &&
            args[0] === "help" &&
            missingChecks < 1
          ) {
            missingChecks += 1;
            const error = new Error("not found");
            error.code = "ENOENT";
            throw error;
          }
          return base.runCommand(executable, args, options);
        },
        tunnelInterrupted: true,
      },
    );
    assert.equal(result, 0);
    assert.equal(actionIndex, actions.length);
    assert.match(
      fixture.output,
      /Nothing downloads unless you choose I or explicitly run/u,
    );
    assert.match(
      fixture.output,
      /ad-hoc signed, not Developer ID-signed or notarized/u,
    );
    assert.match(fixture.output, /darwin-arm64\.zip/u);
    assert.match(fixture.output, /compare all 64 hexadecimal characters/u);
    assert.match(fixture.output, /set TUNNEL_CLIENT_BIN before rerunning/u);
    assert.match(fixture.output, /Rechecking tunnel-client/u);
    assert.match(
      fixture.output,
      /Capability-compatible unmanaged tunnel-client found/u,
    );
    assert.ok(
      opened.includes(
        "https://github.com/openai/tunnel-client/releases/latest",
      ),
    );
    assert.ok(
      opened.includes(
        "https://github.com/openai/tunnel-client/blob/master/docs/configuration.md",
      ),
    );
  } finally {
    fixture.cleanup();
  }
});

test("--no-open prints tunnel-client help links and can pause without a Docker build", async () => {
  const fixture = createFixture();
  const base = fixture.dependencies();
  const actions = ["o", "q"];
  let actionIndex = 0;
  try {
    const result = await runFirstRun(
      {
        args: [
          "chatgpt",
          "--no-open",
          "--tunnel-id",
          "tunnel_0123456789abcdef0123456789abcdef",
        ],
        repoRoot: fixture.repoRoot,
      },
      {
        ...base,
        isTTY: true,
        openUrl: async () => {
          assert.fail("--no-open must suppress the release-page open");
        },
        promptLine: async () => actions[actionIndex++],
        runCommand: async (executable, args, options) => {
          if (executable === "tunnel-client") {
            const error = new Error("not found");
            error.code = "ENOENT";
            throw error;
          }
          return base.runCommand(executable, args, options);
        },
      },
    );
    assert.equal(result, 0);
    assert.equal(actionIndex, actions.length);
    assert.match(
      fixture.output,
      /github\.com\/openai\/tunnel-client\/releases\/latest/u,
    );
    assert.equal(
      fixture.calls.some(
        (call) => call.executable === "docker" && call.args.includes("up"),
      ),
      false,
    );
    assert.equal(fs.existsSync(firstRunPaths(fixture.repoRoot).root), false);
  } finally {
    fixture.cleanup();
  }
});

test("tunnel-client recovery explains an active environment override", async () => {
  const fixture = createFixture();
  try {
    const result = await runFirstRun(
      {
        args: [
          "chatgpt",
          "--no-open",
          "--tunnel-id",
          "tunnel_0123456789abcdef0123456789abcdef",
        ],
        env: {
          PATH: process.env.PATH,
          TUNNEL_CLIENT_BIN: "/missing/selected-tunnel-client",
        },
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies({ isTTY: true, promptLine: async () => "q" }),
    );
    assert.equal(result, 0);
    assert.match(fixture.output, /TUNNEL_CLIENT_BIN is active/u);
    assert.match(fixture.output, /change or unset the variable/u);
  } finally {
    fixture.cleanup();
  }
});

test("a nonexecutable checkout-local tunnel-client is never hidden by PATH fallback", async () => {
  const fixture = createFixture();
  const localClient = path.join(
    fixture.repoRoot,
    ".actionproxy",
    "bin",
    "tunnel-client",
  );
  fs.mkdirSync(path.dirname(localClient), { recursive: true, mode: 0o700 });
  fs.writeFileSync(localClient, "not executable", { mode: 0o600 });
  try {
    const result = await runFirstRun(
      {
        args: [
          "chatgpt",
          "--no-open",
          "--tunnel-id",
          "tunnel_0123456789abcdef0123456789abcdef",
        ],
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies({ isTTY: true, promptLine: async () => "q" }),
    );
    assert.equal(result, 0);
    assert.match(fixture.output, /exists but is not executable/u);
    assert.equal(
      fixture.calls.some((call) => call.executable === "tunnel-client"),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("interactive runtime-key guidance opens after Quickstart and before hidden input", async () => {
  const fixture = createFixture();
  const actions = ["o", ""];
  const events = [];
  let actionIndex = 0;
  let secretAttempts = 0;
  const invalidRuntimeKey = " invalid-guided-runtime-key ";
  const runtimeKey = "guided-runtime-key-canary";
  try {
    const result = await runFirstRun(
      {
        args: [
          "chatgpt",
          "--tunnel-id",
          "tunnel_0123456789abcdef0123456789abcdef",
        ],
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies({
        isTTY: true,
        openUrl: async (url) => {
          events.push(`open:${String(url)}`);
          return true;
        },
        promptLine: async () => actions[actionIndex++],
        readSecret: async () => {
          events.push("read-secret");
          secretAttempts += 1;
          return secretAttempts === 1 ? invalidRuntimeKey : runtimeKey;
        },
        tunnelInterrupted: true,
      }),
    );
    assert.equal(result, 0);
    assert.equal(actionIndex, actions.length);
    const quickstartIndex = events.findIndex((event) =>
      event.includes("/app#/demo?journey=chatgpt"),
    );
    const keyPageIndex = events.indexOf(
      "open:https://platform.openai.com/settings/organization/api-keys",
    );
    const secretIndex = events.indexOf("read-secret");
    assert.ok(quickstartIndex >= 0 && quickstartIndex < keyPageIndex);
    assert.ok(keyPageIndex < secretIndex);
    assert.equal(secretAttempts, 2);
    assert.match(fixture.output, /OpenAI tunnel runtime key/u);
    assert.match(fixture.output, /terminal echo disabled/u);
    assert.match(fixture.output, /not sent to Docker or the browser/u);
    assert.match(fixture.output, /Nothing was retained/u);
    assert.equal(fixture.output.includes(runtimeKey), false);
    assert.equal(fixture.output.includes(invalidRuntimeKey), false);
    assert.equal(JSON.stringify(fixture.calls).includes(runtimeKey), false);
    assert.equal(
      JSON.stringify(fixture.calls).includes(invalidRuntimeKey),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("pausing before runtime-key input leaves a truthful gateway-ready session", async () => {
  const fixture = createFixture();
  try {
    const result = await runFirstRun(
      {
        args: [
          "chatgpt",
          "--no-open",
          "--tunnel-id",
          "tunnel_0123456789abcdef0123456789abcdef",
        ],
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies({
        isTTY: true,
        promptLine: async () => "q",
        readSecret: async () => {
          assert.fail("pausing must happen before hidden key input");
        },
      }),
    );

    assert.equal(result, 0);
    assert.equal(fixture.statuses.at(-1).setupStage, "gateway_ready");
    assert.ok(
      fixture.statuses.some(
        (status) => status.setupStage === "tunnel_checking",
      ),
    );
    assert.equal(
      fixture.calls.some(
        (call) =>
          call.executable === "tunnel-client" &&
          (call.args[0] === "init" ||
            call.args[0] === "doctor" ||
            (call.args[0] === "run" && call.args[1] !== "--help")),
      ),
      false,
    );
    assert.ok(
      fixture.calls.some(
        (call) => call.executable === "docker" && call.args.includes("up"),
      ),
    );
    assert.equal(
      fs.existsSync(firstRunPaths(fixture.repoRoot).lockDirectory),
      false,
    );
    assert.match(
      fixture.output,
      /verified local gateway and SQLite audit remain/u,
    );
  } finally {
    fixture.cleanup();
  }
});

test("SIGTERM during tunnel doctor retains the verified gateway and removes the private session", async () => {
  const fixture = createFixture();
  const bootstrapDirectoriesBefore = new Set(
    fs
      .readdirSync(os.tmpdir())
      .filter((entry) => entry.startsWith("actionproxy-first-run-key.")),
  );
  const readyFile = path.join(fixture.repoRoot, "doctor-started");
  const dockerLogFile = path.join(fixture.repoRoot, "docker-commands.log");
  const scriptsDirectory = path.join(fixture.repoRoot, "scripts");
  const binaryDirectory = path.join(fixture.repoRoot, "fake-bin");
  fs.mkdirSync(scriptsDirectory, { recursive: true });
  fs.mkdirSync(binaryDirectory, { recursive: true });
  fs.copyFileSync(
    new URL("./first-run.mjs", import.meta.url),
    path.join(scriptsDirectory, "first-run.mjs"),
  );
  const shim = path.join(fixture.repoRoot, "actionproxy");
  fs.copyFileSync(new URL("../actionproxy", import.meta.url), shim);
  fs.chmodSync(shim, 0o755);
  const fetchHook = path.join(fixture.repoRoot, "fetch-hook.mjs");
  fs.writeFileSync(
    fetchHook,
    `
globalThis.fetch = async () => ({ json: async () => ({ ok: true }), ok: true, status: 200 });
`,
  );
  const fakeBinary = (name, source) => {
    const filename = path.join(binaryDirectory, name);
    fs.writeFileSync(filename, `#!${process.execPath}\n${source}\n`, {
      mode: 0o755,
    });
    fs.chmodSync(filename, 0o755);
  };
  fakeBinary(
    "docker",
    `
import fs from 'node:fs';
const args = process.argv.slice(2);
if (process.env.DOCKER_COMMAND_LOG) fs.appendFileSync(process.env.DOCKER_COMMAND_LOG, JSON.stringify(args) + '\\n');
if (args[0] === '--version') process.stdout.write('Docker version 28.1.1');
else if (args[0] === 'info') process.stdout.write('28.1.1');
else if (args.includes('version')) process.stdout.write('2.35.1');
else if (args.includes('port')) process.stdout.write('127.0.0.1:18787\\n');
else if (args[0] === 'inspect' && args.includes('{{json .Config.Env}}')) process.stdout.write('[]');
else if (args[0] === 'inspect' && args.includes('{{json .Config.Labels}}')) process.stdout.write(JSON.stringify({ 'com.docker.compose.project': process.env.FAKE_PROJECT_NAME, 'com.docker.compose.service': 'actionproxy' }));
else if (args[0] === 'inspect') process.stdout.write(JSON.stringify({ '8787/tcp': [{ HostIp: '127.0.0.1', HostPort: '0' }] }));
else if (args[0] === 'container' && args[1] === 'inspect') process.exitCode = 1;
else if (args[0] === 'network' && args[1] === 'inspect') process.stdout.write(JSON.stringify({ 'com.docker.compose.network': 'default', 'com.docker.compose.project': process.env.FAKE_PROJECT_NAME }));
else if (args.includes('ps') && args.includes('-q')) process.stdout.write(${JSON.stringify(containerId)});
else if (args.includes('--discover')) process.stdout.write(process.env.FAKE_DOCTOR_REPORT);
else if (args.includes('-e')) process.stdout.write(JSON.stringify({ quickstart: 'true', storage: 'sqlite' }));
`,
  );
  fakeBinary(
    "tunnel-client",
    `
import fs from 'node:fs';
const args = process.argv.slice(2);
if (args[0] === 'help' || (args[0] === 'run' && args[1] === '--help')) {
  process.stdout.write('--profile --profile-dir --control-plane.api-key=file: --health.listen-addr --health.url-file');
} else if (args[0] === 'init') {
  const profile = args[args.indexOf('--profile') + 1];
  const profileDirectory = args[args.indexOf('--profile-dir') + 1];
  fs.mkdirSync(profileDirectory, { recursive: true });
  fs.writeFileSync(profileDirectory + '/' + profile + '.yaml', 'config_version: 1\\n');
} else if (args[0] === 'doctor') {
  fs.writeFileSync(process.env.SIGNAL_READY_FILE, 'ready');
  setInterval(() => {}, 1000);
}
`,
  );
  const child = spawn(
    shim,
    [
      "chatgpt",
      "--no-open",
      "--tunnel-id",
      "tunnel_0123456789abcdef0123456789abcdef",
    ],
    {
      cwd: fixture.repoRoot,
      env: {
        ...process.env,
        CONTROL_PLANE_API_KEY: "test-signal-runtime-key",
        DOCKER_COMMAND_LOG: dockerLogFile,
        FAKE_PROJECT_NAME: checkoutIdentity(fixture.repoRoot).projectName,
        FAKE_DOCTOR_REPORT: doctorReport,
        // The POSIX shim resolves `node` through PATH. Keep this child on the
        // same supported Node release as the test runner even when the parent
        // login shell still defaults to an older Node installation.
        PATH: `${binaryDirectory}${path.delimiter}${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH ?? ""}`,
        NODE_OPTIONS: `--import=${fetchHook}`,
        SIGNAL_READY_FILE: readyFile,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const completed = collectChild(child);
  try {
    await waitForFile(readyFile, 5_000);
    const bootstrapDirectoriesDuringRun = fs
      .readdirSync(os.tmpdir())
      .filter(
        (entry) =>
          entry.startsWith("actionproxy-first-run-key.") &&
          !bootstrapDirectoriesBefore.has(entry),
      );
    assert.deepEqual(bootstrapDirectoriesDuringRun, []);
    const processListing = spawnSync("ps", ["eww", "-p", String(child.pid)], {
      encoding: "utf8",
    });
    assert.equal(processListing.status, 0, processListing.stderr);
    assert.equal(
      `${processListing.stdout}${processListing.stderr}`.includes(
        "test-signal-runtime-key",
      ),
      false,
    );
    child.kill("SIGTERM");
    const result = await withTimeout(
      completed,
      5_000,
      "launcher did not exit after SIGTERM",
    );
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.signal, null);
    assert.equal(result.stdout.includes("test-signal-runtime-key"), false);
    assert.equal(result.stderr.includes("test-signal-runtime-key"), false);
    const dockerCalls = fs
      .readFileSync(dockerLogFile, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    assert.equal(
      dockerCalls.some(
        (args) =>
          args.includes("down") ||
          (args[0] === "container" && args[1] === "rm") ||
          (args[0] === "network" && args[1] === "rm"),
      ),
      false,
    );
    const firstRunRoot = firstRunPaths(fixture.repoRoot).root;
    const directories = fs
      .readdirSync(firstRunRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory());
    assert.deepEqual(directories, []);
  } finally {
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGKILL");
    fixture.cleanup();
  }
});

test("readiness failure aborts the foreground tunnel instead of leaving a child running", async () => {
  const fixture = createFixture();
  let aborted = false;
  let clock = 0;
  try {
    const base = fixture.dependencies();
    await assert.rejects(
      runFirstRun(
        {
          args: [
            "chatgpt",
            "--no-open",
            "--tunnel-id",
            "tunnel_0123456789abcdef0123456789abcdef",
          ],
          env: { PATH: process.env.PATH },
          legacyRuntimeKey: "test-readiness-failure-key",
          repoRoot: fixture.repoRoot,
        },
        {
          ...base,
          now: () => {
            clock += 30_000;
            return clock;
          },
          runForeground: async (_executable, _args, options) =>
            new Promise((resolve) => {
              options.signal.addEventListener(
                "abort",
                () => {
                  aborted = true;
                  resolve({ code: null, interrupted: true });
                },
                { once: true },
              );
            }),
        },
      ),
      /did not become ready/u,
    );
    assert.equal(aborted, true);
    const firstRunRoot = firstRunPaths(fixture.repoRoot).root;
    assert.equal(
      fs
        .readdirSync(firstRunRoot, { withFileTypes: true })
        .some((entry) => entry.isDirectory()),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("an interrupt before tunnel readiness leaves the verified gateway running", async () => {
  const fixture = createFixture();
  try {
    const base = fixture.dependencies();
    await assert.rejects(
      runFirstRun(
        {
          args: [
            "chatgpt",
            "--no-open",
            "--tunnel-id",
            "tunnel_0123456789abcdef0123456789abcdef",
          ],
          env: { PATH: process.env.PATH },
          legacyRuntimeKey: "test-pre-readiness-interrupt-key",
          repoRoot: fixture.repoRoot,
        },
        {
          ...base,
          runForeground: async () => ({
            code: null,
            interrupted: true,
            stderr: "",
            stdout: "",
          }),
        },
      ),
      (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
    );
    assert.equal(fixture.statuses.at(-1).setupStage, "tunnel_stopped");
    const dockerCalls = fixture.calls
      .filter((call) => call.executable === "docker")
      .map((call) => call.args);
    assert.equal(
      dockerCalls.some(
        (args) =>
          args.includes("down") ||
          (args[0] === "container" && args[1] === "rm") ||
          (args[0] === "network" && args[1] === "rm"),
      ),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("a signal between tunnel doctor and run exits cleanly without starting the tunnel", async () => {
  const fixture = createFixture();
  const signalEmitter = new EventEmitter();
  try {
    const base = fixture.dependencies({ signalEmitter });
    let emitted = false;
    await assert.rejects(
      runFirstRun(
        {
          args: [
            "chatgpt",
            "--no-open",
            "--tunnel-id",
            "tunnel_0123456789abcdef0123456789abcdef",
          ],
          env: { PATH: process.env.PATH },
          legacyRuntimeKey: "test-status-gap-interrupt-key",
          repoRoot: fixture.repoRoot,
        },
        {
          ...base,
          fetchFn: async (url, options = {}) => {
            const response = await base.fetchFn(url, options);
            if (options.method === "PUT") {
              const snapshot = JSON.parse(options.body);
              if (
                !emitted &&
                snapshot.checks.some(
                  (check) =>
                    check.id === "tunnel_doctor" && check.state === "pass",
                )
              ) {
                emitted = true;
                signalEmitter.emit("SIGTERM");
              }
            }
            return response;
          },
        },
      ),
      (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
    );
    assert.equal(emitted, true);
    assert.equal(fixture.statuses.at(-1).setupStage, "gateway_ready");
    assert.equal(
      fixture.calls.some(
        (call) =>
          call.executable === "tunnel-client" &&
          call.args[0] === "run" &&
          call.args[1] !== "--help",
      ),
      false,
    );
    assert.equal(
      fixture.calls.some(
        (call) =>
          call.executable === "docker" &&
          (call.args.includes("down") ||
            (call.args[0] === "container" && call.args[1] === "rm") ||
            (call.args[0] === "network" && call.args[1] === "rm")),
      ),
      false,
    );
    const firstRunRoot = firstRunPaths(fixture.repoRoot).root;
    assert.equal(
      fs
        .readdirSync(firstRunRoot, { withFileTypes: true })
        .some((entry) => entry.isDirectory()),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("an interrupt during gateway polling exits cleanly and removes only the unverified runtime", async () => {
  const fixture = createFixture();
  const signalEmitter = new EventEmitter();
  try {
    const base = fixture.dependencies({ signalEmitter });
    let emitted = false;
    await assert.rejects(
      runFirstRun(
        { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
        {
          ...base,
          fetchFn: async (url, options = {}) => {
            if (!emitted && String(url).endsWith("/health")) {
              emitted = true;
              signalEmitter.emit("SIGINT");
            }
            return base.fetchFn(url, options);
          },
        },
      ),
      (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
    );
    assert.equal(emitted, true);
    assert.equal(
      fixture.calls.some(
        (call) => call.executable === "docker" && call.args.includes("rm"),
      ),
      true,
    );
    assert.equal(
      fs.existsSync(firstRunPaths(fixture.repoRoot).lockDirectory),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("ChatGPT journey refuses missing secrets and conflicting profile markers without overwriting", async () => {
  const fixture = createFixture();
  try {
    await assert.rejects(
      runFirstRun(
        {
          args: [
            "chatgpt",
            "--no-open",
            "--tunnel-id",
            "tunnel_0123456789abcdef0123456789abcdef",
          ],
          env: { PATH: process.env.PATH },
          repoRoot: fixture.repoRoot,
        },
        fixture.dependencies(),
      ),
      /runtime API key is required/u,
    );

    const identity = checkoutIdentity(fixture.repoRoot);
    const markerFile = profileMarkerPath(
      fixture.repoRoot,
      `actionproxy-local-${identity.checkoutId}`,
    );
    fs.mkdirSync(path.dirname(markerFile), { recursive: true });
    fs.writeFileSync(
      markerFile,
      JSON.stringify({
        ...profileMarker({
          projectName: identity.projectName,
          tunnelId: "tunnel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }),
        profileHash: "0".repeat(64),
      }),
      { mode: 0o600 },
    );
    await assert.rejects(
      runFirstRun(
        {
          args: [
            "chatgpt",
            "--no-open",
            "--tunnel-id",
            "tunnel_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          ],
          env: { PATH: process.env.PATH },
          legacyRuntimeKey: "test-different-runtime-key",
          repoRoot: fixture.repoRoot,
        },
        fixture.dependencies({ uuid: () => sessionIds[1] }),
      ),
      /different tunnel/u,
    );
    assert.match(fs.readFileSync(markerFile, "utf8"), /tunnel_aaaaaaaa/u);
  } finally {
    fixture.cleanup();
  }
});

test("a failed tunnel doctor removes only its provisional default profile so retry can recover", async () => {
  const fixture = createFixture();
  const firstTunnelId = "tunnel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const correctedTunnelId = "tunnel_0123456789abcdef0123456789abcdef";
  const identity = checkoutIdentity(fixture.repoRoot);
  const profile = `actionproxy-local-${identity.checkoutId}`;
  const profileFile = tunnelProfilePaths(fixture.repoRoot, profile).file;
  const markerFile = profileMarkerPath(fixture.repoRoot, profile);
  const base = fixture.dependencies({ tunnelInterrupted: true });
  let rejectDoctor = true;
  const runCommand = async (executable, args, options) => {
    if (
      executable === "tunnel-client" &&
      args[0] === "doctor" &&
      rejectDoctor
    ) {
      assert.equal(fs.existsSync(profileFile), true);
      assert.equal(fs.existsSync(markerFile), false);
      return {
        code: 1,
        stderr: "simulated access or association failure",
        stdout: "",
      };
    }
    return base.runCommand(executable, args, options);
  };
  try {
    await assert.rejects(
      runFirstRun(
        {
          args: ["chatgpt", "--no-open", "--tunnel-id", firstTunnelId],
          legacyRuntimeKey: "failed-doctor-runtime-key",
          repoRoot: fixture.repoRoot,
        },
        { ...base, runCommand },
      ),
      (error) => error.code === "TUNNEL_ACCESS_FAILED",
    );
    assert.equal(fs.existsSync(profileFile), false);
    assert.equal(fs.existsSync(markerFile), false);
    const failedStatus = fixture.statuses.at(-1);
    assert.equal(failedStatus.setupStage, "failed");
    for (const id of [
      "gateway",
      "storage",
      "loopback",
      "tool_discovery",
      "tunnel_client",
    ]) {
      assert.equal(
        failedStatus.checks.find((check) => check.id === id).state,
        "pass",
      );
    }
    assert.equal(
      failedStatus.checks.find((check) => check.id === "tunnel_doctor").state,
      "fail",
    );

    rejectDoctor = false;
    const result = await runFirstRun(
      {
        args: ["chatgpt", "--no-open", "--tunnel-id", correctedTunnelId],
        legacyRuntimeKey: "corrected-doctor-runtime-key",
        repoRoot: fixture.repoRoot,
      },
      { ...base, runCommand },
    );
    assert.equal(result, 0);
    assert.equal(fs.existsSync(profileFile), true);
    assert.equal(fs.existsSync(markerFile), true);
    assert.match(fs.readFileSync(markerFile, "utf8"), /0123456789abcdef/u);
  } finally {
    fixture.cleanup();
  }
});

test("a tunnel init that writes then fails cannot poison the next profile retry", async () => {
  const fixture = createFixture();
  const identity = checkoutIdentity(fixture.repoRoot);
  const profile = `actionproxy-local-${identity.checkoutId}`;
  const profileFile = tunnelProfilePaths(fixture.repoRoot, profile).file;
  const markerFile = profileMarkerPath(fixture.repoRoot, profile);
  const base = fixture.dependencies();
  try {
    await assert.rejects(
      runFirstRun(
        {
          args: [
            "chatgpt",
            "--no-open",
            "--tunnel-id",
            "tunnel_0123456789abcdef0123456789abcdef",
          ],
          legacyRuntimeKey: "failed-init-runtime-key",
          repoRoot: fixture.repoRoot,
        },
        {
          ...base,
          runCommand: async (executable, args, options) => {
            const result = await base.runCommand(executable, args, options);
            if (executable === "tunnel-client" && args[0] === "init") {
              assert.equal(fs.existsSync(profileFile), true);
              return {
                code: 1,
                stderr: "simulated failure after profile write",
                stdout: "",
              };
            }
            return result;
          },
        },
      ),
      (error) => error.code === "TUNNEL_PROFILE_INIT_FAILED",
    );
    assert.equal(fs.existsSync(profileFile), false);
    assert.equal(fs.existsSync(markerFile), false);
  } finally {
    fixture.cleanup();
  }
});

test("ChatGPT journey refuses a modified checkout-owned tunnel profile", async () => {
  const fixture = createFixture();
  const tunnelId = "tunnel_0123456789abcdef0123456789abcdef";
  try {
    await runFirstRun(
      {
        args: ["chatgpt", "--no-open", "--tunnel-id", tunnelId],
        env: { PATH: process.env.PATH },
        legacyRuntimeKey: "test-profile-baseline-key",
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies({ tunnelInterrupted: true }),
    );

    const identity = checkoutIdentity(fixture.repoRoot);
    const profile = `actionproxy-local-${identity.checkoutId}`;
    const profileFile = tunnelProfilePaths(fixture.repoRoot, profile).file;
    fs.appendFileSync(profileFile, "tampered: true\n");

    await assert.rejects(
      runFirstRun(
        {
          args: ["chatgpt", "--no-open", "--tunnel-id", tunnelId],
          env: { PATH: process.env.PATH },
          legacyRuntimeKey: "test-profile-reuse-key",
          repoRoot: fixture.repoRoot,
        },
        fixture.dependencies({ uuid: () => sessionIds[1] }),
      ),
      (error) => {
        assert.equal(error.code, "TUNNEL_PROFILE_CONTENT_CHANGED");
        assert.match(error.message, /no longer matches/u);
        return true;
      },
    );
    assert.match(fs.readFileSync(profileFile, "utf8"), /tampered: true/u);
  } finally {
    fixture.cleanup();
  }
});

test("a failed post-start verification removes only the concierge service and network", async () => {
  const fixture = createFixture();
  try {
    const base = fixture.dependencies();
    await assert.rejects(
      runFirstRun(
        { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
        {
          ...base,
          runCommand: async (executable, args, options) => {
            if (args.includes("--discover") && args.includes("--json")) {
              return {
                code: 0,
                stderr: "",
                stdout: JSON.stringify({
                  ...JSON.parse(doctorReport),
                  servers: [],
                }),
              };
            }
            return base.runCommand(executable, args, options);
          },
        },
      ),
      /MCP discovery must expose exactly/u,
    );

    assert.ok(
      fixture.calls.some(
        (call) =>
          call.executable === "docker" &&
          call.args.includes("rm") &&
          call.args.includes("--stop") &&
          call.args.includes("--force") &&
          call.args.at(-1) === "actionproxy",
      ),
    );
    assert.ok(
      fixture.calls.some(
        (call) =>
          call.executable === "docker" &&
          call.args[0] === "network" &&
          call.args[1] === "rm" &&
          call.args[2].endsWith("_default"),
      ),
    );
    assert.equal(
      fixture.calls.some(
        (call) => call.args[0] === "volume" && call.args[1] === "rm",
      ),
      false,
    );
    assert.equal(
      fixture.calls.some((call) => call.args.includes("postgres")),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("an unconfirmed failed safety cleanup surfaces a distinct operational failure", async () => {
  const fixture = createFixture();
  try {
    const base = fixture.dependencies();
    await assert.rejects(
      runFirstRun(
        { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
        {
          ...base,
          runCommand: async (executable, args, options) => {
            if (args.includes("--discover") && args.includes("--json")) {
              return {
                code: 0,
                stderr: "",
                stdout: JSON.stringify({
                  ...JSON.parse(doctorReport),
                  servers: [],
                }),
              };
            }
            if (
              (args.includes("rm") && args.includes("--stop")) ||
              (args[0] === "container" && args[1] === "rm")
            ) {
              return {
                code: 1,
                stderr: "simulated scoped removal failure",
                stdout: "",
              };
            }
            return base.runCommand(executable, args, options);
          },
        },
      ),
      (error) => {
        assert.equal(error.code, "SAFETY_CLEANUP_INCOMPLETE");
        assert.equal(error.retry, "./actionproxy stop");
        assert.match(error.message, /could not confirm removal/u);
        return true;
      },
    );
  } finally {
    fixture.cleanup();
  }
});

test("an empty or malformed active lock fails closed and is never cleared", async () => {
  for (const owner of [undefined, "not-json\n"]) {
    const fixture = createFixture();
    try {
      const paths = firstRunPaths(fixture.repoRoot);
      fs.mkdirSync(paths.lockDirectory, { mode: 0o700, recursive: true });
      if (owner !== undefined) fs.writeFileSync(paths.lockOwner, owner);

      await assert.rejects(
        runFirstRun(
          { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
          fixture.dependencies(),
        ),
        (error) => {
          assert.equal(error.code, "FIRST_RUN_LOCK_UNOWNED");
          return true;
        },
      );
      assert.equal(fs.existsSync(paths.lockDirectory), true);
      if (owner !== undefined) {
        assert.equal(fs.readFileSync(paths.lockOwner, "utf8"), owner);
      }
      assert.equal(
        fixture.calls.some((call) => call.args.includes("up")),
        false,
      );
    } finally {
      fixture.cleanup();
    }
  }
});

test("reset refuses to traverse a symlink in First Run state", async () => {
  const fixture = createFixture();
  const outside = fs.mkdtempSync(
    path.join(os.tmpdir(), "actionproxy-first-run-outside-"),
  );
  const outsideFile = path.join(outside, "keep.txt");
  fs.writeFileSync(outsideFile, "keep");
  try {
    await runFirstRun(
      { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
      fixture.dependencies(),
    );
    const link = path.join(firstRunPaths(fixture.repoRoot).root, "unsafe-link");
    fs.symlinkSync(outside, link, "dir");

    await assert.rejects(
      runFirstRun(
        { args: ["reset"], repoRoot: fixture.repoRoot },
        fixture.dependencies({
          isTTY: true,
          promptLine: async () => "DELETE LOCAL AUDIT",
        }),
      ),
      (error) => {
        assert.equal(error.code, "LOCAL_STATE_PATH_UNSAFE");
        assert.match(
          error.message,
          /Refusing to remove a tree containing a symlink/u,
        );
        return true;
      },
    );
    assert.equal(fs.readFileSync(outsideFile, "utf8"), "keep");
    assert.equal(fs.lstatSync(link).isSymbolicLink(), true);
    assert.equal(
      fixture.calls.some(
        (call) =>
          (call.args.includes("rm") && call.args.includes("actionproxy")) ||
          (call.args[0] === "network" && call.args[1] === "rm") ||
          (call.args[0] === "volume" && call.args[1] === "rm"),
      ),
      false,
    );
  } finally {
    fixture.cleanup();
    fs.rmSync(outside, { force: true, recursive: true });
  }
});

test("First Run refuses to create state through a symlinked checkout ancestor", async () => {
  const fixture = createFixture();
  const outside = fs.mkdtempSync(
    path.join(os.tmpdir(), "actionproxy-first-run-write-outside-"),
  );
  try {
    fs.symlinkSync(outside, path.join(fixture.repoRoot, ".actionproxy"), "dir");
    await assert.rejects(
      runFirstRun(
        { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
        fixture.dependencies(),
      ),
      (error) => {
        assert.equal(error.code, "LOCAL_STATE_PATH_UNSAFE");
        return true;
      },
    );
    assert.deepEqual(fs.readdirSync(outside), []);
    assert.equal(
      fixture.calls.some((call) => call.args.includes("up")),
      false,
    );
  } finally {
    fixture.cleanup();
    fs.rmSync(outside, { force: true, recursive: true });
  }
});

test("doctor is read-only and emits an allowlisted JSON report", async () => {
  const fixture = createFixture();
  try {
    const code = await runFirstRun(
      {
        args: ["doctor", "--chatgpt", "--json"],
        env: { PATH: process.env.PATH },
        legacyRuntimeKey: "test-must-not-appear",
        repoRoot: fixture.repoRoot,
      },
      fixture.dependencies(),
    );
    assert.equal(code, 0);
    const report = JSON.parse(fixture.output);
    assert.equal(report.schemaVersion, "actionproxy.first-run-doctor.v1");
    assert.equal(report.ok, true);
    assert.equal(report.supportedNodeRange, "22-24");
    assert.equal(report.dockerVersion, "28.1.1");
    assert.equal(report.composeVersion, "2.35.1");
    assert.equal(report.tunnelClientVersion, "v1.2.3");
    assert.equal(fixture.output.includes("arbitrary-output-marker"), false);
    assert.equal(
      report.checks.find((check) => check.id === "gateway").state,
      "pending",
    );
    assert.equal(fixture.output.includes("test-must-not-appear"), false);
    assert.equal(
      fixture.calls.some(
        (call) => call.args.includes("up") || call.args.includes("init"),
      ),
      false,
    );
    assert.equal(
      fs.existsSync(path.join(fixture.repoRoot, ".actionproxy")),
      false,
    );
  } finally {
    fixture.cleanup();
  }
});

test("doctor fails a recorded gateway whose live binding is not loopback-only", async () => {
  const fixture = createFixture();
  try {
    await runFirstRun(
      { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
      fixture.dependencies(),
    );
    const base = fixture.dependencies();
    let output = "";
    const code = await runFirstRun(
      { args: ["doctor", "--json"], repoRoot: fixture.repoRoot },
      {
        ...base,
        runCommand: async (executable, args, options) => {
          if (executable === "docker" && args[0] === "inspect") {
            return {
              code: 0,
              stderr: "",
              stdout: JSON.stringify({
                "8787/tcp": [{ HostIp: "0.0.0.0", HostPort: "18787" }],
              }),
            };
          }
          return base.runCommand(executable, args, options);
        },
        stdout: {
          write: (value) => {
            output += String(value);
            return true;
          },
        },
      },
    );
    assert.equal(code, 1);
    const report = JSON.parse(output);
    assert.deepEqual(
      report.checks.find((check) => check.id === "loopback"),
      {
        id: "loopback",
        remediationCode: "non_loopback_binding",
        state: "fail",
      },
    );
  } finally {
    fixture.cleanup();
  }
});

test("human doctor output gives a cause, corrective action, and exact rerun", async () => {
  const fixture = createFixture();
  try {
    const base = fixture.dependencies();
    const code = await runFirstRun(
      { args: ["doctor"], repoRoot: fixture.repoRoot },
      {
        ...base,
        runCommand: async (executable, args, options) => {
          if (executable === "docker" && args[0] === "info") {
            return { code: 1, stderr: "daemon unavailable", stdout: "" };
          }
          return base.runCommand(executable, args, options);
        },
      },
    );
    assert.equal(code, 1);
    assert.match(fixture.output, /Docker Desktop engine is not running/u);
    assert.match(fixture.output, /Fix: Open Docker Desktop/u);
    assert.match(fixture.output, /Retry: \.\/actionproxy doctor/u);
  } finally {
    fixture.cleanup();
  }
});

test("doctor reports blocked Docker dependents as pending instead of duplicate failures", async () => {
  const fixture = createFixture();
  const base = fixture.dependencies();
  let output = "";
  try {
    const code = await runFirstRun(
      { args: ["doctor", "--json"], repoRoot: fixture.repoRoot },
      {
        ...base,
        runCommand: async (executable, args, options) => {
          if (executable === "docker") {
            assert.deepEqual(args, ["--version"]);
            const error = new Error("not found");
            error.code = "ENOENT";
            throw error;
          }
          return base.runCommand(executable, args, options);
        },
        stdout: {
          write: (value) => {
            output += String(value);
            return true;
          },
        },
      },
    );
    assert.equal(code, 1);
    const report = JSON.parse(output);
    assert.deepEqual(
      report.checks.filter((check) =>
        ["docker_cli", "docker_daemon", "compose"].includes(check.id),
      ),
      [
        {
          id: "docker_cli",
          remediationCode: "docker_missing",
          state: "fail",
        },
        { id: "docker_daemon", state: "pending" },
        { id: "compose", state: "pending" },
      ],
    );
  } finally {
    fixture.cleanup();
  }
});

test("status requires a fresh live /readyz response, not only a server heartbeat", async () => {
  const fixture = createFixture();
  try {
    await runFirstRun(
      { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
      fixture.dependencies(),
    );
    let output = "";
    const updatedAt = new Date().toISOString();
    const base = fixture.dependencies();
    const code = await runFirstRun(
      { args: ["status", "--json"], repoRoot: fixture.repoRoot },
      {
        ...base,
        fetchFn: async (url) => {
          if (String(url).endsWith("/health"))
            return { json: async () => ({ ok: true }), ok: true, status: 200 };
          if (String(url).includes("/v1/demo/quickstart/status/")) {
            return {
              json: async () => ({
                setupStage: "tunnel_ready",
                tunnelUiUrl: "http://127.0.0.1:49152/ui",
                updatedAt,
              }),
              ok: true,
              status: 200,
            };
          }
          if (String(url) === "http://127.0.0.1:49152/readyz")
            return { ok: false, status: 503 };
          throw new Error(`unexpected URL: ${url}`);
        },
        stdout: {
          write: (value) => {
            output += String(value);
            return true;
          },
        },
      },
    );
    assert.equal(code, 0);
    const report = JSON.parse(output);
    assert.equal(report.tunnel.ready, false);
    assert.equal(report.tunnel.state, "tunnel_stopped");
  } finally {
    fixture.cleanup();
  }
});

test("hidden runtime-key input restores terminal echo and exits cleanly on interruption", async () => {
  const terminal = new PassThrough();
  const signals = new EventEmitter();
  const stty = [];
  let closed = false;
  const promise = readHiddenSecret("Runtime key: ", {
    fileSystem: {
      closeSync: () => {
        closed = true;
      },
      openSync: () => 42,
      writeSync: () => {},
    },
    createTtyReadStream: () => terminal,
    processObject: signals,
    spawnSyncFn: (_command, args) => {
      stty.push([...args]);
      return { status: 0 };
    },
  });
  signals.emit("SIGINT");
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, "INTERRUPTED");
    assert.equal(error.exitCode, 0);
    return true;
  });
  assert.deepEqual(stty, [["-echo"], ["echo"]]);
  assert.equal(closed, true);
  assert.equal(signals.listenerCount("SIGINT"), 0);
  assert.equal(signals.listenerCount("SIGTERM"), 0);
});

test("hidden input guards an interruption as soon as its prompt is visible", async () => {
  const terminal = new PassThrough();
  const signals = new EventEmitter();
  const stty = [];
  let closed = false;
  const promise = readHiddenSecret("Runtime key: ", {
    createTtyReadStream: () => terminal,
    fileSystem: {
      closeSync: () => {
        closed = true;
      },
      openSync: () => 42,
      writeSync: () => {
        signals.emit("SIGINT");
      },
    },
    processObject: signals,
    spawnSyncFn: (_command, args) => {
      stty.push([...args]);
      return { status: 0 };
    },
  });
  await assert.rejects(
    promise,
    (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
  );
  assert.deepEqual(stty, [["-echo"], ["echo"]]);
  assert.equal(closed, true);
  assert.equal(signals.listenerCount("SIGINT"), 0);
  assert.equal(signals.listenerCount("SIGTERM"), 0);
});

test("hidden input restores echo when disabling echo reports failure", async () => {
  const signals = new EventEmitter();
  const stty = [];
  let closed = false;
  await assert.rejects(
    readHiddenSecret("Runtime key: ", {
      fileSystem: {
        closeSync: () => {
          closed = true;
        },
        openSync: () => 42,
        writeSync: () => {
          assert.fail("the prompt must not be written after stty fails");
        },
      },
      processObject: signals,
      spawnSyncFn: (_command, args) => {
        stty.push([...args]);
        return { status: args[0] === "-echo" ? 1 : 0 };
      },
    }),
    /could not disable terminal echo/u,
  );
  assert.deepEqual(stty, [["-echo"], ["echo"]]);
  assert.equal(closed, true);
  assert.equal(signals.listenerCount("SIGINT"), 0);
  assert.equal(signals.listenerCount("SIGTERM"), 0);
});

test("hidden runtime-key input completes after one submitted line", async () => {
  const terminal = new PassThrough();
  const signals = new EventEmitter();
  const stty = [];
  let closed = false;
  const promise = readHiddenSecret("Runtime key: ", {
    createTtyReadStream: () => terminal,
    fileSystem: {
      closeSync: () => {
        closed = true;
      },
      openSync: () => 42,
      writeSync: () => {},
    },
    processObject: signals,
    spawnSyncFn: (_command, args) => {
      stty.push([...args]);
      return { status: 0 };
    },
  });
  terminal.write("runtime-key-canary\n");
  assert.equal(await promise, "runtime-key-canary");
  assert.deepEqual(stty, [["-echo"], ["echo"]]);
  assert.equal(closed, true);
});

test("ordinary TTY input exits cleanly on interruption", async () => {
  const terminal = new PassThrough();
  const signals = new EventEmitter();
  let closed = false;
  const promise = readTerminalLine("Choose: ", {
    fileSystem: {
      closeSync: () => {
        closed = true;
      },
      openSync: () => 42,
      writeSync: () => {},
    },
    createTtyReadStream: () => terminal,
    processObject: signals,
  });
  signals.emit("SIGINT");
  await assert.rejects(
    promise,
    (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
  );
  assert.equal(closed, true);
  assert.equal(signals.listenerCount("SIGINT"), 0);
  assert.equal(signals.listenerCount("SIGTERM"), 0);
});

test("ordinary input guards an interruption as soon as its prompt is visible", async () => {
  const terminal = new PassThrough();
  const signals = new EventEmitter();
  let closed = false;
  const promise = readTerminalLine("Choose: ", {
    createTtyReadStream: () => terminal,
    fileSystem: {
      closeSync: () => {
        closed = true;
      },
      openSync: () => 42,
      writeSync: () => {
        signals.emit("SIGINT");
      },
    },
    processObject: signals,
  });
  await assert.rejects(
    promise,
    (error) => error.code === "INTERRUPTED" && error.exitCode === 0,
  );
  assert.equal(closed, true);
  assert.equal(signals.listenerCount("SIGINT"), 0);
  assert.equal(signals.listenerCount("SIGTERM"), 0);
});

test("ordinary TTY input completes after one submitted line", async () => {
  const terminal = new PassThrough();
  const signals = new EventEmitter();
  let closed = false;
  const promise = readTerminalLine("Choose: ", {
    createTtyReadStream: () => terminal,
    fileSystem: {
      closeSync: () => {
        closed = true;
      },
      openSync: () => 42,
      writeSync: () => {},
    },
    processObject: signals,
  });
  terminal.write("1\n");
  assert.equal(await promise, "1");
  assert.equal(closed, true);
});

const realMacTtyTest =
  process.platform === "darwin" && process.env.ACTIONPROXY_TEST_REAL_TTY === "1"
    ? test
    : test.skip;

realMacTtyTest(
  "macOS controlling-TTY prompts complete with one Enter and hide the runtime key",
  () => {
    const moduleUrl = new URL("./first-run.mjs", import.meta.url).href;
    const canary = "tty-key-canary-42";
    const code = [
      `import { readHiddenSecret, readTerminalLine } from ${JSON.stringify(moduleUrl)};`,
      'const choice = await readTerminalLine("Choice: ");',
      'const secret = await readHiddenSecret("Runtime key (hidden): ");',
      'process.stdout.write("RESULT:" + choice + ":" + secret.length + "\\n");',
    ].join("\n");
    const expectScript = [
      "set timeout 8",
      "spawn $env(ACTIONPROXY_TTY_NODE) --input-type=module --eval $env(ACTIONPROXY_TTY_CODE)",
      "expect {",
      '  -exact "Choice: " {}',
      "  timeout { exit 120 }",
      "  eof { exit 121 }",
      "}",
      'send "1\\r"',
      "expect {",
      '  -exact "Runtime key (hidden): " {}',
      "  timeout { exit 122 }",
      "  eof { exit 123 }",
      "}",
      `send ${JSON.stringify(`${canary}\r`)}`,
      "expect {",
      `  -exact "RESULT:1:${canary.length}" {}`,
      "  timeout { exit 124 }",
      "  eof { exit 125 }",
      "}",
      "exit 0",
    ].join("\n");
    const result = spawnSync("/usr/bin/expect", ["-c", expectScript], {
      encoding: "utf8",
      env: {
        ...process.env,
        ACTIONPROXY_TTY_CODE: code,
        ACTIONPROXY_TTY_NODE: process.execPath,
      },
      timeout: 15_000,
    });
    const diagnostic = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    assert.equal(result.status, 0, diagnostic);
    assert.doesNotMatch(diagnostic, new RegExp(canary, "u"));
    assert.match(diagnostic, new RegExp(`RESULT:1:${canary.length}`, "u"));
  },
);

realMacTtyTest(
  "macOS hidden prompt catches immediate Ctrl+C and restores terminal settings",
  () => {
    const moduleUrl = new URL("./first-run.mjs", import.meta.url).href;
    const code = [
      'import fs from "node:fs";',
      'import { spawnSync } from "node:child_process";',
      `import { readHiddenSecret } from ${JSON.stringify(moduleUrl)};`,
      "const terminalState = () => {",
      '  const descriptor = fs.openSync("/dev/tty", "r+");',
      "  try {",
      '    return spawnSync("stty", ["-g"], { encoding: "utf8", stdio: [descriptor, "pipe", "pipe"] }).stdout.trim();',
      "  } finally {",
      "    fs.closeSync(descriptor);",
      "  }",
      "};",
      "const before = terminalState();",
      "try {",
      '  await readHiddenSecret("Runtime key (hidden): ");',
      '  process.stdout.write("RESULT:UNEXPECTED\\n");',
      "} catch (error) {",
      "  const after = terminalState();",
      '  process.stdout.write("RESULT:" + error.code + ":" + String(before === after) + "\\n");',
      "}",
    ].join("\n");
    const expectScript = [
      "set timeout 8",
      "spawn $env(ACTIONPROXY_TTY_NODE) --input-type=module --eval $env(ACTIONPROXY_TTY_CODE)",
      "expect {",
      '  -exact "Runtime key (hidden): " {}',
      "  timeout { exit 130 }",
      "  eof { exit 131 }",
      "}",
      'send "\\003"',
      "expect {",
      '  -exact "RESULT:INTERRUPTED:true" {}',
      "  timeout { exit 132 }",
      "  eof { exit 133 }",
      "}",
      "exit 0",
    ].join("\n");
    const result = spawnSync("/usr/bin/expect", ["-c", expectScript], {
      encoding: "utf8",
      env: {
        ...process.env,
        ACTIONPROXY_TTY_CODE: code,
        ACTIONPROXY_TTY_NODE: process.execPath,
      },
      timeout: 15_000,
    });
    const diagnostic = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    assert.equal(result.status, 0, diagnostic);
    assert.match(diagnostic, /RESULT:INTERRUPTED:true/u);
  },
);

realMacTtyTest(
  "macOS chooser catches immediate Ctrl+C as a clean user interruption",
  () => {
    const executable = fileURLToPath(
      new URL("../actionproxy", import.meta.url),
    );
    const expectScript = [
      "set timeout 8",
      "spawn $env(ACTIONPROXY_TTY_EXECUTABLE)",
      "expect {",
      '  -exact "Choose 1 or 2: " {}',
      "  timeout { exit 140 }",
      "  eof { exit 141 }",
      "}",
      'send "\\003"',
      "expect {",
      '  -exact "First Run cancelled. No runtime key was retained." {}',
      "  timeout { exit 142 }",
      "  eof { exit 143 }",
      "}",
      "expect eof",
      "exit 0",
    ].join("\n");
    const result = spawnSync("/usr/bin/expect", ["-c", expectScript], {
      encoding: "utf8",
      env: {
        ...process.env,
        ACTIONPROXY_TTY_EXECUTABLE: executable,
      },
      timeout: 15_000,
    });
    const diagnostic = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    assert.equal(result.status, 0, diagnostic);
    assert.match(
      diagnostic,
      /First Run cancelled\. No runtime key was retained\./u,
    );
  },
);

test("stop retains the volume while reset requires the exact phrase and removes only first-run state", async () => {
  const fixture = createFixture();
  try {
    await runFirstRun(
      { args: ["local", "--no-open"], repoRoot: fixture.repoRoot },
      fixture.dependencies(),
    );
    fixture.calls.length = 0;
    await runFirstRun(
      { args: ["stop"], repoRoot: fixture.repoRoot },
      fixture.dependencies(),
    );
    const serviceRemoval = fixture.calls.find(
      (call) => call.args.includes("rm") && call.args.includes("actionproxy"),
    );
    assert.ok(serviceRemoval);
    assert.equal(
      fixture.calls.some(
        (call) => call.args[0] === "volume" && call.args[1] === "rm",
      ),
      false,
    );

    const markerDirectory = path.join(
      fixture.repoRoot,
      ".actionproxy",
      "chatgpt-tunnel",
    );
    fs.mkdirSync(markerDirectory, { recursive: true });
    fs.writeFileSync(path.join(markerDirectory, "keep.json"), "{}");
    fixture.calls.length = 0;
    await runFirstRun(
      { args: ["reset"], repoRoot: fixture.repoRoot },
      fixture.dependencies({
        isTTY: true,
        promptLine: async () => "not the phrase",
      }),
    );
    assert.equal(
      fixture.calls.some(
        (call) => call.args[0] === "volume" && call.args[1] === "rm",
      ),
      false,
    );
    assert.equal(fs.existsSync(firstRunPaths(fixture.repoRoot).state), true);

    await runFirstRun(
      { args: ["reset"], repoRoot: fixture.repoRoot },
      fixture.dependencies({
        isTTY: true,
        promptLine: async () => "DELETE LOCAL AUDIT",
      }),
    );
    assert.ok(
      fixture.calls.some(
        (call) =>
          call.args[0] === "volume" &&
          call.args[1] === "rm" &&
          call.args[2].endsWith("_actionproxy_data"),
      ),
    );
    assert.equal(
      fixture.calls.some((call) =>
        call.args.some((argument) => argument.includes("postgres")),
      ),
      false,
    );
    assert.equal(fs.existsSync(firstRunPaths(fixture.repoRoot).root), false);
    assert.equal(fs.existsSync(path.join(markerDirectory, "keep.json")), true);
  } finally {
    fixture.cleanup();
  }
});

test("the POSIX shim is executable, reports version under Node 24, and rejects no-command pipes", () => {
  const shim = fileURLToPath(new URL("../actionproxy", import.meta.url));
  assert.equal(fs.statSync(shim).mode & 0o111, 0o111);
  const env = {
    ...process.env,
    PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH ?? ""}`,
  };
  const version = spawnSync(shim, ["--version"], { encoding: "utf8", env });
  assert.equal(version.status, 0, version.stderr);
  assert.match(version.stdout, /^0\.1\.1/u);
  const noCommand = spawnSync(shim, [], { encoding: "utf8", env, input: "" });
  assert.equal(noCommand.status, 2);
  assert.match(noCommand.stderr, /input is not interactive/u);
  const pnpmRawEnvironment = spawnSync(shim, ["--version"], {
    encoding: "utf8",
    env: {
      ...env,
      ACTIONPROXY_PNPM_ENTRY: "1",
      CONTROL_PLANE_API_KEY: "pnpm-parent-process-canary", // public-secret-scan: allow
    },
  });
  assert.equal(pnpmRawEnvironment.status, 2);
  assert.match(pnpmRawEnvironment.stderr, /parent process would retain it/u);
  assert.doesNotMatch(
    `${pnpmRawEnvironment.stdout}${pnpmRawEnvironment.stderr}`,
    /pnpm-parent-process-canary/u,
  );
});

function createFixture() {
  const repoRoot = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "actionproxy-first-run-test-")),
  );
  const linksDirectory = path.join(repoRoot, "examples", "chatgpt-tunnel");
  fs.mkdirSync(linksDirectory, { recursive: true });
  fs.copyFileSync(
    new URL("../examples/chatgpt-tunnel/openai-links.json", import.meta.url),
    path.join(linksDirectory, "openai-links.json"),
  );
  fs.copyFileSync(
    new URL(
      "../examples/chatgpt-tunnel/tunnel-client-distribution.json",
      import.meta.url,
    ),
    path.join(linksDirectory, "tunnel-client-distribution.json"),
  );
  const calls = [];
  const statuses = [];
  let output = "";
  let uuidIndex = 0;

  function dependencies(overrides = {}) {
    const runCommand = async (executable, args, options) => {
      calls.push({ args: [...args], env: { ...options.env }, executable });
      if (executable === "tunnel-client") {
        if (args[0] === "--version") {
          return {
            code: 0,
            stderr: "",
            stdout: "tunnel-client v1.2.3 arbitrary-output-marker",
          };
        }
        if (args[0] === "help") {
          return {
            code: 0,
            stderr: "",
            stdout:
              "tunnel-client quickstart --profile --profile-dir --control-plane.api-key=file: --health.listen-addr --health.url-file",
          };
        }
        if (args[0] === "run" && args[1] === "--help") {
          return {
            code: 0,
            stderr: "",
            stdout:
              "--profile --profile-dir --control-plane.api-key=file: --health.listen-addr --health.url-file",
          };
        }
        if (args[0] === "init") {
          const profile = args[args.indexOf("--profile") + 1];
          const profileDirectory = args[args.indexOf("--profile-dir") + 1];
          fs.mkdirSync(profileDirectory, { recursive: true });
          fs.writeFileSync(
            path.join(profileDirectory, `${profile}.yaml`),
            [
              "config_version: 1",
              `tunnel_id: ${args[args.indexOf("--tunnel-id") + 1]}`,
              `mcp_command: ${args[args.indexOf("--mcp-command") + 1]}`,
              "",
            ].join("\n"),
            { mode: 0o600 },
          );
        }
        return { code: 0, stderr: "", stdout: "" };
      }
      if (executable !== "docker") return { code: 0, stderr: "", stdout: "" };
      if (args[0] === "network" && args[1] === "inspect") {
        const projectName = args.at(-1).replace(/_default$/u, "");
        return {
          code: 0,
          stderr: "",
          stdout: JSON.stringify({
            "com.docker.compose.network": "default",
            "com.docker.compose.project": projectName,
          }),
        };
      }
      if (args[0] === "container" && args[1] === "inspect") {
        return { code: 1, stderr: "not found", stdout: "" };
      }
      if (args[0] === "volume" && args[1] === "inspect") {
        const projectName = args.at(-1).replace(/_actionproxy_data$/u, "");
        return {
          code: 0,
          stderr: "",
          stdout: JSON.stringify({
            "com.docker.compose.project": projectName,
            "com.docker.compose.volume": "actionproxy_data",
          }),
        };
      }
      if (args[0] === "--version")
        return { code: 0, stderr: "", stdout: "Docker version 28.1.1" };
      if (args[0] === "info") return { code: 0, stderr: "", stdout: "28.1.1" };
      if (args.includes("version"))
        return { code: 0, stderr: "", stdout: "2.35.1" };
      if (args.includes("port"))
        return { code: 0, stderr: "", stdout: "127.0.0.1:18787\n" };
      if (args[0] === "inspect" && args.includes("{{json .Config.Env}}"))
        return { code: 0, stderr: "", stdout: "[]\n" };
      if (args[0] === "inspect" && args.includes("{{json .Config.Labels}}")) {
        const projectIndex = args.indexOf("--project-name");
        const projectName =
          projectIndex >= 0
            ? args[projectIndex + 1]
            : checkoutIdentity(repoRoot).projectName;
        return {
          code: 0,
          stderr: "",
          stdout: JSON.stringify({
            "com.docker.compose.project": projectName,
            "com.docker.compose.service": "actionproxy",
          }),
        };
      }
      if (args[0] === "inspect") {
        return {
          code: 0,
          stderr: "",
          stdout: JSON.stringify({
            "8787/tcp": [{ HostIp: "127.0.0.1", HostPort: "0" }],
          }),
        };
      }
      if (args.includes("ps") && args.includes("-q"))
        return { code: 0, stderr: "", stdout: `${containerId}\n` };
      if (args.includes("--discover") && args.includes("--json"))
        return { code: 0, stderr: "", stdout: doctorReport };
      if (args.includes("-e") && args.join(" ").includes("JSON.stringify")) {
        return {
          code: 0,
          stderr: "",
          stdout: JSON.stringify({ quickstart: "true", storage: "sqlite" }),
        };
      }
      if (args.includes("-e") && args.join(" ").includes("ACTIONPROXY_STORAGE"))
        return { code: 0, stderr: "", stdout: "sqlite" };
      return { code: 0, stderr: "", stdout: "" };
    };
    return {
      architecture: "arm64",
      fetchFn: async (url, options = {}) => {
        if (options.method === "PUT") {
          statuses.push(JSON.parse(options.body));
          return { json: async () => ({}), ok: true, status: 200 };
        }
        if (String(url).endsWith("/readyz"))
          return { json: async () => ({}), ok: true, status: 200 };
        return { json: async () => ({ ok: true }), ok: true, status: 200 };
      },
      isTTY: false,
      openUrl: async () => true,
      platform: "darwin",
      processKill: () => {
        const error = new Error("not running");
        error.code = "ESRCH";
        throw error;
      },
      promptConfirm: async () => true,
      promptLine: async () => "",
      readSecret: async () => {
        throw new Error("unexpected hidden prompt");
      },
      runCommand,
      runForeground: async (executable, args, options) => {
        calls.push({ args: [...args], env: { ...options.env }, executable });
        const index = args.indexOf("--health.url-file");
        fs.writeFileSync(args[index + 1], "http://127.0.0.1:49152\n");
        await new Promise((resolve) => setImmediate(resolve));
        return { code: 0, interrupted: overrides.tunnelInterrupted ?? false };
      },
      sleep: async () => {},
      stderr: {
        write: (value) => {
          output += String(value);
          return true;
        },
      },
      stdout: {
        write: (value) => {
          output += String(value);
          return true;
        },
      },
      uuid: () => overrides.uuid ?? sessionIds[uuidIndex++ % sessionIds.length],
      ...overrides,
    };
  }

  return {
    calls,
    cleanup: () => fs.rmSync(repoRoot, { force: true, recursive: true }),
    dependencies,
    get output() {
      return output;
    },
    repoRoot,
    statuses,
  };
}

async function waitForFile(filename, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(filename)) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`Timed out waiting for ${filename}`);
}

function collectChild(child) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.once("error", reject);
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.once("close", (code, signal) =>
      resolve({ code, signal, stderr, stdout }),
    );
  });
}

function withTimeout(promise, timeoutMs, message) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
      timer.unref?.();
    }),
  ]);
}
