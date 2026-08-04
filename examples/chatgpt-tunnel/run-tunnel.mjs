#!/usr/bin/env node
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  EXPECTED_DEMO_TOOLS,
  FirstRunError,
  formatFirstRunError,
  profileMarker,
  profileMarkerPath,
  redact,
  runFirstRun,
  validateDoctorReport,
  validateProfile,
  validateTunnelId,
} from "../../scripts/first-run.mjs";

export { EXPECTED_DEMO_TOOLS, profileMarker, redact, validateDoctorReport };

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const defaultRepoRoot = path.resolve(scriptDirectory, "..", "..");

/**
 * Compatibility adapter for the pre-concierge command. New users should run
 * `./actionproxy chatgpt`; this keeps the documented pnpm alias working while
 * sharing every safety check and state transition with the public entry point.
 */
export async function runTunnelDemo(
  {
    args = process.argv.slice(2),
    env = process.env,
    repoRoot = defaultRepoRoot,
  } = {},
  dependencies = {},
) {
  const forwarded = [...args];
  if (!forwarded.includes("--port") && env.ACTIONPROXY_DOCKER_PORT) {
    forwarded.push(
      "--port",
      env.ACTIONPROXY_DOCKER_PORT === "0"
        ? "auto"
        : env.ACTIONPROXY_DOCKER_PORT,
    );
  }
  return runFirstRun(
    { args: ["chatgpt", ...forwarded], env, repoRoot },
    dependencies,
  );
}

export function parseArguments(args) {
  let tunnelId;
  let profile;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help" || argument === "-h") return { help: true };
    if (
      argument === "--tunnel-id" &&
      tunnelId === undefined &&
      args[index + 1]
    ) {
      tunnelId = validateTunnelId(args[index + 1]);
      index += 1;
      continue;
    }
    if (argument === "--profile" && profile === undefined && args[index + 1]) {
      profile = validateProfile(args[index + 1]);
      index += 1;
      continue;
    }
    throw new FirstRunError(
      "USAGE",
      `Unknown or incomplete argument: ${argument ?? "(missing)"}`,
      { exitCode: 2 },
    );
  }
  if (!tunnelId) validateTunnelId(tunnelId);
  return { help: false, profile, tunnelId };
}

export function markerPath(repoRoot, profile) {
  return profileMarkerPath(repoRoot, profile);
}

export function usage() {
  return [
    "Usage:",
    "  corepack pnpm demo:chatgpt:tunnel -- --tunnel-id tunnel_<32 lowercase hex> [--profile NAME]",
    "",
    "This compatibility command delegates to `./actionproxy chatgpt`.",
    "In a terminal, the OpenAI runtime key is requested with hidden input.",
    "For strict automation, set ACTIONPROXY_CONTROL_PLANE_KEY_FILE to an absolute mode-0600 file.",
    "Legacy CONTROL_PLANE_API_KEY is accepted only by a direct ./actionproxy invocation; do not place it in front of pnpm or this Node adapter.",
    "",
  ].join("\n");
}

async function main() {
  if (
    process.argv
      .slice(2)
      .some((argument) => argument === "--help" || argument === "-h")
  ) {
    process.stdout.write(usage());
    return;
  }
  try {
    process.exitCode = await runTunnelDemo();
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
