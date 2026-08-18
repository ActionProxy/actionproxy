#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { gunzipSync } from "node:zlib";
import { fileURLToPath, pathToFileURL } from "node:url";

export const NPM_RELEASE_SCHEMA_VERSION = "actionproxy.npm-release.v1";
export const NPM_RELEASE_REGISTRY = "https://registry.npmjs.org/";
export const SUPPORTED_NPM_RELEASE_COMMANDS = Object.freeze([
  "consume",
  "prepare",
  "registry-verify",
  "verify",
  "write",
]);
export const SUPPORTED_NPM_RELEASE_OPERATIONS = Object.freeze([
  "bootstrap-next",
  "promote-latest",
  "resume-bootstrap-next",
]);

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const packageSpecifications = Object.freeze([
  Object.freeze({
    directory: "packages/sdk-js",
    filenamePrefix: "actionproxy-sdk-js",
    name: "@actionproxy/sdk-js",
  }),
  Object.freeze({
    directory: "packages/mcp-wrapper",
    executable: "dist/index.js",
    filenamePrefix: "actionproxy-mcp-wrapper",
    name: "@actionproxy/mcp-wrapper",
  }),
]);
const expectedPackageFiles = Object.freeze([
  "LICENSE",
  "README.md",
  "dist/index.d.ts",
  "dist/index.js",
  "package.json",
]);
const registryFetchTimeoutMs = 10_000;
const registryMetadataLimitBytes = 8 * 1024 * 1024;
const exactRegistryManifestFields = Object.freeze([
  "acceptDependencies",
  "author",
  "bin",
  "browser",
  "browserslist",
  "bundleDependencies",
  "bundledDependencies",
  "bugs",
  "config",
  "contributors",
  "cpu",
  "dependencies",
  "deprecated",
  "description",
  "devDependencies",
  "directories",
  "engines",
  "exports",
  "files",
  "funding",
  "homepage",
  "imports",
  "keywords",
  "libc",
  "license",
  "main",
  "man",
  "module",
  "name",
  "optionalDependencies",
  "os",
  "peerDependencies",
  "peerDependenciesMeta",
  "preferGlobal",
  "repository",
  "scripts",
  "sideEffects",
  "type",
  "types",
  "typings",
  "version",
  "workspaces",
]);
const secretNamePattern =
  /(?:^|_)(?:AUTH|CREDENTIAL|KEY|PASSWORD|SECRET|TOKEN)(?:_|$)|_authToken$/iu;

export function expectedConfirmation(operation, version, targetTag) {
  const effectiveTargetTag =
    targetTag ?? (operation === "promote-latest" ? "latest" : "next");
  assertOperationTarget(operation, effectiveTargetTag);
  assertSemanticVersion(version);
  if (operation === "bootstrap-next") {
    return `PUBLISH @actionproxy ${version} TO NEXT`;
  }
  if (operation === "resume-bootstrap-next") {
    return `RESUME @actionproxy ${version} TO NEXT`;
  }
  if (operation === "promote-latest") {
    return `PROMOTE @actionproxy ${version} TO LATEST`;
  }
  throw new Error("Unsupported npm release operation.");
}

export function assertOperationTarget(operation, targetTag) {
  assertOperation(operation);
  if (!["latest", "next"].includes(targetTag)) {
    throw new Error("npm target tag must be exactly next or latest.");
  }
  if (
    ["bootstrap-next", "resume-bootstrap-next"].includes(operation) &&
    targetTag !== "next"
  ) {
    throw new Error(`${operation} requires the next npm target tag.`);
  }
  if (operation === "promote-latest" && targetTag !== "latest") {
    throw new Error("promote-latest requires the latest npm target tag.");
  }
  return true;
}

export function sanitizeChildEnvironment(
  environment = process.env,
  { includeGitHubOidc = false, includeNpmToken = false } = {},
) {
  const sanitized = {};
  for (const [name, value] of Object.entries(environment)) {
    if (value === undefined) continue;
    if (/^npm_config_/iu.test(name)) {
      continue;
    }
    if (["BASH_ENV", "ENV", "NODE_OPTIONS"].includes(name)) continue;
    if (secretNamePattern.test(name)) {
      if (includeNpmToken && name === "NODE_AUTH_TOKEN") {
        sanitized[name] = value;
      } else if (
        includeGitHubOidc &&
        (name === "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ||
          name === "ACTIONS_ID_TOKEN_REQUEST_URL")
      ) {
        sanitized[name] = value;
      }
      continue;
    }
    if (name === "ACTIONS_ID_TOKEN_REQUEST_URL" && !includeGitHubOidc) {
      continue;
    }
    sanitized[name] = value;
  }
  sanitized.NODE_PATH = undefined;
  sanitized.npm_config_audit = "false";
  sanitized.npm_config_fund = "false";
  return sanitized;
}

export function createSensitiveNpmContext(
  environment = process.env,
  credentialScope = {},
) {
  const npmConfigRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "actionproxy-npm-config-"),
  );
  fs.chmodSync(npmConfigRoot, 0o700);
  try {
    const npmConfigPath = path.join(npmConfigRoot, "user-npmrc");
    const npmGlobalConfigPath = path.join(npmConfigRoot, "global-npmrc");
    const npmProjectConfigPath = path.join(npmConfigRoot, ".npmrc");
    writeFileExclusive(
      npmConfigPath,
      credentialScope.includeNpmToken
        ? "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\n"
        : "",
    );
    writeFileExclusive(npmGlobalConfigPath, "");
    writeFileExclusive(npmProjectConfigPath, "");
    const childEnvironment = sanitizeChildEnvironment(
      environment,
      credentialScope,
    );
    childEnvironment.NPM_CONFIG_USERCONFIG = npmConfigPath;
    childEnvironment.NPM_CONFIG_GLOBALCONFIG = npmGlobalConfigPath;
    childEnvironment.npm_config_cache = path.join(npmConfigRoot, "cache");
    return Object.freeze({
      cleanup() {
        fs.rmSync(npmConfigRoot, { force: true, recursive: true });
      },
      cwd: npmConfigRoot,
      environment: childEnvironment,
    });
  } catch (error) {
    fs.rmSync(npmConfigRoot, { force: true, recursive: true });
    throw error;
  }
}

export function compareSemanticVersions(left, right) {
  const leftVersion = parseSemanticVersion(left);
  const rightVersion = parseSemanticVersion(right);
  for (const field of ["major", "minor", "patch"]) {
    if (leftVersion[field] !== rightVersion[field]) {
      return leftVersion[field] < rightVersion[field] ? -1 : 1;
    }
  }
  if (leftVersion.prerelease.length === 0) {
    return rightVersion.prerelease.length === 0 ? 0 : 1;
  }
  if (rightVersion.prerelease.length === 0) return -1;
  const maximumLength = Math.max(
    leftVersion.prerelease.length,
    rightVersion.prerelease.length,
  );
  for (let index = 0; index < maximumLength; index += 1) {
    const leftPart = leftVersion.prerelease[index];
    const rightPart = rightVersion.prerelease[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;
    const leftNumeric = /^\d+$/u.test(leftPart);
    const rightNumeric = /^\d+$/u.test(rightPart);
    if (leftNumeric && rightNumeric) {
      if (leftPart.length !== rightPart.length) {
        return leftPart.length < rightPart.length ? -1 : 1;
      }
      return compareText(leftPart, rightPart);
    }
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return compareText(leftPart, rightPart);
  }
  return 0;
}

export function hasExactRegistryManifestMetadata(metadata, expectedManifest) {
  if (!isPlainObject(metadata) || !isPlainObject(expectedManifest)) {
    return false;
  }
  if (metadata.hasInstallScript === true || metadata._hasShrinkwrap === true) {
    return false;
  }
  for (const field of exactRegistryManifestFields) {
    const actualHasField = Object.hasOwn(metadata, field);
    const expectedHasField = Object.hasOwn(expectedManifest, field);
    if (
      actualHasField !== expectedHasField ||
      (actualHasField &&
        canonicalJson(metadata[field]) !==
          canonicalJson(expectedManifest[field]))
    ) {
      return false;
    }
  }
  return true;
}

export function assertBootstrapRegistryState(operation, states, version) {
  if (
    !["bootstrap-next", "resume-bootstrap-next"].includes(operation) ||
    !Array.isArray(states) ||
    states.length !== packageSpecifications.length
  ) {
    throw new Error("Bootstrap registry state is malformed.");
  }
  assertSemanticVersion(version);
  if (operation === "bootstrap-next") {
    if (states.some(({ packageExists }) => packageExists)) {
      throw new Error(
        "Bootstrap requires both package namespaces to be absent.",
      );
    }
    return true;
  }
  if (states.every(({ packageExists }) => !packageExists)) {
    throw new Error(
      "Resume requires at least one exact package from a partial bootstrap.",
    );
  }
  if (
    states.some(
      (state) =>
        (state.exists && !state.exact) ||
        (state.packageExists && !state.exists) ||
        (state.exists && !hasExpectedTagState(state, version, "next")),
    )
  ) {
    throw new Error(
      "Resume found a package namespace, version, or tag outside the exact partial bootstrap.",
    );
  }
  return true;
}

export function parseNpmTarball(bytes) {
  const archive = gunzipSync(bytes, { maxOutputLength: 32 * 1024 * 1024 });
  const entries = [];
  const seen = new Set();
  let offset = 0;
  let terminated = false;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (!archive.subarray(offset).every((byte) => byte === 0)) {
        throw new Error("npm tarball contains data after its terminator.");
      }
      terminated = true;
      break;
    }
    verifyTarChecksum(header);
    const name = readTarText(header, 0, 100);
    const prefix = readTarText(header, 345, 155);
    const archivePath = prefix ? `${prefix}/${name}` : name;
    const type = String.fromCharCode(header[156] ?? 0).replace("\0", "");
    const size = readTarOctal(header, 124, 12, "size");
    const mode = readTarOctal(header, 100, 8, "mode");
    if ((mode & ~0o777) !== 0) {
      throw new Error("npm tarball contains unsupported permission bits.");
    }
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    const paddedDataEnd = dataStart + Math.ceil(size / 512) * 512;
    if (dataEnd > archive.length || paddedDataEnd > archive.length) {
      throw new Error("npm tarball contains a truncated entry.");
    }
    if (!archive.subarray(dataEnd, paddedDataEnd).every((byte) => byte === 0)) {
      throw new Error("npm tarball contains nonzero entry padding.");
    }
    if (type !== "" && type !== "0") {
      throw new Error(`npm tarball contains unsupported entry type ${type}.`);
    }
    if (!archivePath.startsWith("package/")) {
      throw new Error("npm tarball entry is outside the package directory.");
    }
    const relativePath = archivePath.slice("package/".length);
    assertSafePackagePath(relativePath);
    if (seen.has(relativePath)) {
      throw new Error(`npm tarball contains duplicate entry ${relativePath}.`);
    }
    seen.add(relativePath);
    const contents = archive.subarray(dataStart, dataEnd);
    entries.push({
      contents,
      mode,
      path: relativePath,
      sha256: sha256(contents),
      size,
    });
    offset = paddedDataEnd;
  }
  if (!terminated) {
    throw new Error("npm tarball has no zero-block terminator.");
  }
  return entries.sort((left, right) => compareText(left.path, right.path));
}

export function verifyReleaseBundle(
  inputDirectory,
  { expectedTag, root = repositoryRoot, verifyBuildOutputs = true } = {},
) {
  const directory = path.resolve(inputDirectory);
  const manifestPath = path.join(directory, "manifest.json");
  const manifest = readJson(manifestPath);
  requireExactKeys(
    manifest,
    ["packages", "repository", "schemaVersion", "tag", "version"],
    "npm release manifest",
  );
  if (manifest.schemaVersion !== NPM_RELEASE_SCHEMA_VERSION) {
    throw new Error("npm release manifest has an unsupported schemaVersion.");
  }
  if (manifest.repository !== "https://github.com/ActionProxy/actionproxy") {
    throw new Error("npm release manifest has an unexpected repository.");
  }
  assertSemanticVersion(manifest.version);
  if (manifest.tag !== `v${manifest.version}`) {
    throw new Error("npm release manifest tag does not match its version.");
  }
  if (expectedTag !== undefined && manifest.tag !== expectedTag) {
    throw new Error("npm release manifest does not match the selected tag.");
  }
  if (!Array.isArray(manifest.packages) || manifest.packages.length !== 2) {
    throw new Error("npm release manifest must describe exactly two packages.");
  }
  const expectedRootVersion = readJson(path.join(root, "package.json")).version;
  if (manifest.version !== expectedRootVersion) {
    throw new Error(
      "npm release manifest version does not match the repository.",
    );
  }
  const verifiedPackages = manifest.packages.map((record, index) =>
    verifyPackageRecord(
      record,
      packageSpecifications[index],
      directory,
      root,
      verifyBuildOutputs,
    ),
  );
  return Object.freeze({
    ...manifest,
    packages: Object.freeze(verifiedPackages),
  });
}

export function prepareReleaseBundle(
  outputDirectory,
  { expectedTag, root = repositoryRoot } = {},
) {
  const rootManifest = readJson(path.join(root, "package.json"));
  assertSemanticVersion(rootManifest.version);
  const tag = expectedTag ?? `v${rootManifest.version}`;
  if (tag !== `v${rootManifest.version}`) {
    throw new Error(
      "Selected release tag does not match the repository version.",
    );
  }
  const output = path.resolve(outputDirectory);
  if (fs.existsSync(output)) {
    throw new Error("npm release output directory already exists.");
  }
  fs.mkdirSync(output, { mode: 0o700 });
  const packageRecords = [];
  for (const specification of packageSpecifications) {
    const workspaceManifest = readJson(
      path.join(root, specification.directory, "package.json"),
    );
    if (
      workspaceManifest.name !== specification.name ||
      workspaceManifest.version !== rootManifest.version ||
      workspaceManifest.private !== undefined
    ) {
      throw new Error(
        `${specification.name} has inconsistent release metadata.`,
      );
    }
    const filename = `${specification.filenamePrefix}-${rootManifest.version}.tgz`;
    const tarballPath = path.join(output, filename);
    runNonSecret(
      corepackExecutable(),
      [
        "pnpm",
        "--filter",
        specification.name,
        "pack",
        "--out",
        tarballPath,
        "--json",
      ],
      root,
      `pack ${specification.name}`,
    );
    const tarball = fs.readFileSync(tarballPath);
    const entries = parseNpmTarball(tarball);
    assertPackageEntries(entries, specification);
    const packagedManifest = JSON.parse(
      entries
        .find((entry) => entry.path === "package.json")
        .contents.toString("utf8"),
    );
    assertPackagedWorkspaceFiles(
      entries,
      specification,
      workspaceManifest,
      root,
      true,
    );
    if (
      packagedManifest.name !== specification.name ||
      packagedManifest.version !== rootManifest.version
    ) {
      throw new Error(
        `${specification.name} tarball metadata is inconsistent.`,
      );
    }
    packageRecords.push(
      packageRecord(
        specification,
        filename,
        tarball,
        entries,
        rootManifest.version,
      ),
    );
  }
  const manifest = {
    packages: packageRecords,
    repository: "https://github.com/ActionProxy/actionproxy",
    schemaVersion: NPM_RELEASE_SCHEMA_VERSION,
    tag,
    version: rootManifest.version,
  };
  writeFileExclusive(
    path.join(output, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  return verifyReleaseBundle(output, { expectedTag: tag, root });
}

export function assertReleaseRef(
  { eventName, ref, refName, refType },
  version,
) {
  if (
    eventName !== "workflow_dispatch" ||
    refType !== "tag" ||
    ref !== `refs/tags/v${version}` ||
    refName !== `v${version}`
  ) {
    throw new Error(
      "npm release requires workflow_dispatch on the exact version tag.",
    );
  }
  return true;
}

function assertAnnotatedReleaseTag({ ref, sha }, root = repositoryRoot) {
  if (!/^refs\/tags\/v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(ref ?? "")) {
    throw new Error("npm release ref is not an exact version tag.");
  }
  if (!/^[a-f0-9]{40}$/u.test(sha ?? "")) {
    throw new Error("npm release commit SHA is malformed.");
  }
  const objectType = runNonSecret(
    "git",
    ["cat-file", "-t", ref],
    root,
    "inspect npm release tag object",
  ).stdout.trim();
  if (objectType !== "tag") {
    throw new Error("npm release requires an annotated tag object.");
  }
  const peeledCommit = runNonSecret(
    "git",
    ["rev-parse", `${ref}^{commit}`],
    root,
    "peel npm release tag",
  ).stdout.trim();
  const headCommit = runNonSecret(
    "git",
    ["rev-parse", "HEAD"],
    root,
    "resolve npm release checkout",
  ).stdout.trim();
  if (peeledCommit !== sha || headCommit !== sha) {
    throw new Error(
      "npm release tag, GitHub SHA, and checked-out HEAD do not match.",
    );
  }
  runNonSecret(
    "git",
    ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
    root,
    "resolve protected origin/main",
  );
  runNonSecret(
    "git",
    ["merge-base", "--is-ancestor", sha, "refs/remotes/origin/main"],
    root,
    "verify npm release ancestry through protected main",
  );
}

async function main() {
  const [command, directory] = process.argv.slice(2);
  if (!SUPPORTED_NPM_RELEASE_COMMANDS.includes(command ?? "")) {
    throw new UsageError(
      "Usage: npm-release-artifacts.mjs <prepare|verify|consume|write|registry-verify> <directory>",
    );
  }
  if (!directory || process.argv.length !== 4) {
    throw new UsageError(
      "Usage: npm-release-artifacts.mjs <prepare|verify|consume|write|registry-verify> <directory>",
    );
  }
  if (command === "prepare") {
    const version = readJson(path.join(repositoryRoot, "package.json")).version;
    assertReleaseRef(
      {
        eventName: process.env.GITHUB_EVENT_NAME,
        ref: process.env.GITHUB_REF,
        refName: process.env.GITHUB_REF_NAME,
        refType: process.env.GITHUB_REF_TYPE,
      },
      version,
    );
    assertAnnotatedReleaseTag({
      ref: process.env.GITHUB_REF,
      sha: process.env.GITHUB_SHA,
    });
    const result = prepareReleaseBundle(directory, {
      expectedTag: process.env.GITHUB_REF_NAME,
    });
    process.stdout.write(
      `${JSON.stringify({ ok: true, packages: result.packages.map(({ name }) => name), tag: result.tag })}\n`,
    );
    return;
  }
  const bundle = verifyReleaseBundle(directory, {
    expectedTag: process.env.GITHUB_REF_NAME,
    verifyBuildOutputs: !["registry-verify", "write"].includes(command),
  });
  assertReleaseRef(
    {
      eventName: process.env.GITHUB_EVENT_NAME,
      ref: process.env.GITHUB_REF,
      refName: process.env.GITHUB_REF_NAME,
      refType: process.env.GITHUB_REF_TYPE,
    },
    bundle.version,
  );
  assertAnnotatedReleaseTag({
    ref: process.env.GITHUB_REF,
    sha: process.env.GITHUB_SHA,
  });
  if (command === "verify") {
    process.stdout.write(
      `${JSON.stringify({ ok: true, packages: bundle.packages.map(({ name }) => name), tag: bundle.tag })}\n`,
    );
    return;
  }
  if (command === "consume") {
    consumeReleaseBundle(bundle, path.resolve(directory));
    process.stdout.write(
      `${JSON.stringify({ node: process.versions.node, ok: true, version: bundle.version })}\n`,
    );
    return;
  }
  if (command === "registry-verify") {
    if (process.env.NODE_AUTH_TOKEN) {
      throw new Error(
        "Anonymous registry verification refuses NODE_AUTH_TOKEN.",
      );
    }
    await verifyRegistryRelease(bundle, path.resolve(directory));
    return;
  }
  await writeRegistry(bundle, path.resolve(directory));
}

async function verifyRegistryRelease(bundle, directory) {
  const operation = process.env.ACTIONPROXY_NPM_OPERATION ?? "";
  const impliedTargetTag = operation === "promote-latest" ? "latest" : "next";
  const targetTag = process.env.ACTIONPROXY_NPM_TARGET_TAG ?? impliedTargetTag;
  assertOperationTarget(operation, targetTag);
  let states;
  for (let attempt = 0; attempt < 15; attempt += 1) {
    try {
      states = await Promise.all(
        bundle.packages.map((record) =>
          registryPackageState(record, directory),
        ),
      );
    } catch (error) {
      if (attempt === 14) throw error;
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      continue;
    }
    const exact = states.every((state) => state.exact);
    const tagged = states.every((state) =>
      hasExpectedTagState(state, bundle.version, targetTag),
    );
    if (exact && tagged) break;
    if (attempt < 14)
      await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  if (
    !states?.every((state) => state.exact) ||
    !states.every((state) =>
      hasExpectedTagState(state, bundle.version, targetTag),
    )
  ) {
    throw new Error(
      "Anonymous npm registry verification did not reach the exact expected state.",
    );
  }
  verifyRegistrySignatures(bundle);
  process.stdout.write(
    `${JSON.stringify({ anonymous: true, ok: true, operation, packages: bundle.packages.map(({ name }) => name), version: bundle.version })}\n`,
  );
}

async function writeRegistry(bundle, directory) {
  const operation = process.env.ACTIONPROXY_NPM_OPERATION ?? "";
  const targetTag = process.env.ACTIONPROXY_NPM_TARGET_TAG ?? "next";
  assertOperationTarget(operation, targetTag);
  const expected = expectedConfirmation(operation, bundle.version, targetTag);
  if (process.env.ACTIONPROXY_NPM_CONFIRMATION !== expected) {
    throw new Error(`Confirmation mismatch. Required: ${expected}`);
  }
  assertRuntimeToken(process.env.NODE_AUTH_TOKEN);
  const states = await Promise.all(
    bundle.packages.map((record) => registryPackageState(record, directory)),
  );
  if (["bootstrap-next", "resume-bootstrap-next"].includes(operation)) {
    assertBootstrapRegistryState(operation, states, bundle.version);
  }
  if (operation === "promote-latest") {
    for (const [index, state] of states.entries()) {
      if (!state.exact || state.tags.next !== bundle.version) {
        throw new Error(
          `${bundle.packages[index].name} is not an exact verified next release.`,
        );
      }
      if (
        state.tags.latest &&
        state.tags.latest !== bundle.version &&
        compareSemanticVersions(state.tags.latest, bundle.version) >= 0
      ) {
        throw new Error(
          `${bundle.packages[index].name} already has a latest release that is not older.`,
        );
      }
    }
    for (const [index, record] of bundle.packages.entries()) {
      if (states[index].tags.latest === bundle.version) continue;
      runSensitive(
        npmExecutable(),
        [
          "dist-tag",
          "add",
          `${record.name}@${bundle.version}`,
          "latest",
          "--registry",
          NPM_RELEASE_REGISTRY,
        ],
        `promote ${record.name}`,
        { includeNpmToken: true },
      );
    }
    process.stdout.write(
      `${JSON.stringify({ ok: true, operation, promoted: bundle.packages.map(({ name }) => name) })}\n`,
    );
    return;
  }
  for (const [index, record] of bundle.packages.entries()) {
    if (states[index].exists) continue;
    runSensitive(
      npmExecutable(),
      [
        "publish",
        path.join(directory, record.filename),
        "--provenance",
        "--access",
        "public",
        "--tag",
        "next",
        "--registry",
        NPM_RELEASE_REGISTRY,
      ],
      `publish ${record.name}`,
      { includeGitHubOidc: true, includeNpmToken: true },
    );
  }
  process.stdout.write(
    `${JSON.stringify({ ok: true, operation, published: bundle.packages.map(({ name }) => name), tag: "next" })}\n`,
  );
}

async function registryPackageState(record, directory) {
  const packageUrl = new URL(
    `${encodeURIComponent(record.name)}/${encodeURIComponent(record.version)}`,
    NPM_RELEASE_REGISTRY,
  );
  const response = await fetchRegistry(packageUrl);
  const tagsResponse = await fetchRegistry(
    new URL(encodeURIComponent(record.name), NPM_RELEASE_REGISTRY),
    {
      headers: { accept: "application/vnd.npm.install-v1+json" },
    },
  );
  let tags = {};
  let packageExists = false;
  if (tagsResponse.status === 200) {
    packageExists = true;
    const packument = await readRegistryJson(tagsResponse, "package metadata");
    tags = isPlainObject(packument["dist-tags"]) ? packument["dist-tags"] : {};
  } else if (tagsResponse.status !== 404) {
    throw new Error(
      `Registry package lookup failed with HTTP ${tagsResponse.status}.`,
    );
  }
  if (response.status === 404)
    return { exact: false, exists: false, packageExists, tags };
  if (response.status !== 200) {
    throw new Error(
      `Registry version lookup failed with HTTP ${response.status}.`,
    );
  }
  const metadata = await readRegistryJson(response, "version metadata");
  const expectedBytes = fs.readFileSync(path.join(directory, record.filename));
  const expectedManifest = JSON.parse(
    parseNpmTarball(expectedBytes)
      .find((entry) => entry.path === "package.json")
      .contents.toString("utf8"),
  );
  const dist = isPlainObject(metadata.dist) ? metadata.dist : {};
  const tarballUrl = safeRegistryTarballUrl(dist.tarball);
  const tarballResponse = await fetchRegistry(tarballUrl);
  if (tarballResponse.status !== 200) {
    throw new Error(
      `Registry tarball lookup failed with HTTP ${tarballResponse.status}.`,
    );
  }
  const registryBytes = await readBoundedResponse(
    tarballResponse,
    expectedBytes.length,
    "registry tarball",
  );
  const exact =
    hasExactRegistryManifestMetadata(metadata, expectedManifest) &&
    dist.integrity === record.integrity &&
    dist.shasum === record.sha1 &&
    hasExactRegistryAttestations(dist) &&
    registryBytes.equals(expectedBytes);
  return { exact, exists: true, packageExists: true, tags };
}

function hasExpectedTagState(state, version, targetTag) {
  if (targetTag === "latest") {
    return state.tags.latest === version && state.tags.next === version;
  }
  return state.tags.next === version && state.tags.latest !== version;
}

function fetchRegistry(url, options = {}) {
  return fetch(url, {
    ...options,
    redirect: "error",
    signal: AbortSignal.timeout(registryFetchTimeoutMs),
  });
}

async function readRegistryJson(response, label) {
  const bytes = await readBoundedResponse(
    response,
    registryMetadataLimitBytes,
    label,
  );
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(`Registry returned invalid ${label} JSON.`);
  }
}

async function readBoundedResponse(response, maximumBytes, label) {
  const contentLength = response.headers.get("content-length");
  if (
    contentLength !== null &&
    (!/^\d+$/u.test(contentLength) || Number(contentLength) > maximumBytes)
  ) {
    throw new Error(`Registry ${label} exceeds the allowed size.`);
  }
  if (!response.body) {
    throw new Error(`Registry ${label} has no response body.`);
  }
  const chunks = [];
  let totalBytes = 0;
  const reader = response.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > maximumBytes) {
      await reader.cancel();
      throw new Error(`Registry ${label} exceeds the allowed size.`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, totalBytes);
}

function verifyRegistrySignatures(bundle) {
  const temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "actionproxy-npm-registry-verify-"),
  );
  const npmContext = createSensitiveNpmContext(process.env);
  try {
    writeFileExclusive(
      path.join(temporaryRoot, "package.json"),
      `${JSON.stringify(
        {
          dependencies: Object.fromEntries(
            bundle.packages.map(({ name, version }) => [name, version]),
          ),
          name: "actionproxy-registry-verifier",
          private: true,
          version: "1.0.0",
        },
        null,
        2,
      )}\n`,
    );
    runNonSecret(
      npmExecutable(),
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--package-lock=true",
        "--registry",
        NPM_RELEASE_REGISTRY,
      ],
      temporaryRoot,
      "install exact anonymous registry versions",
      npmContext.environment,
    );
    runNonSecret(
      npmExecutable(),
      ["audit", "signatures", "--json", "--registry", NPM_RELEASE_REGISTRY],
      temporaryRoot,
      "verify npm registry signatures and provenance attestations",
      npmContext.environment,
    );
  } finally {
    npmContext.cleanup();
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
  }
}

function hasExactRegistryAttestations(dist) {
  const signatures = Array.isArray(dist.signatures) ? dist.signatures : [];
  const attestations = isPlainObject(dist.attestations)
    ? dist.attestations
    : {};
  const provenance = isPlainObject(attestations.provenance)
    ? attestations.provenance
    : {};
  if (
    signatures.length < 1 ||
    signatures.some(
      (signature) =>
        !isPlainObject(signature) ||
        typeof signature.keyid !== "string" ||
        signature.keyid.length < 1 ||
        typeof signature.sig !== "string" ||
        signature.sig.length < 1,
    ) ||
    provenance.predicateType !== "https://slsa.dev/provenance/v1"
  ) {
    return false;
  }
  try {
    safeRegistryUrl(attestations.url, "attestation");
  } catch {
    return false;
  }
  return true;
}

export function consumeReleaseBundle(bundle, directory) {
  const temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "actionproxy-npm-consumer-"),
  );
  try {
    fs.chmodSync(temporaryRoot, 0o700);
    const consumerNodeModules = path.join(temporaryRoot, "node_modules");
    fs.mkdirSync(consumerNodeModules, { mode: 0o700 });
    for (const record of bundle.packages) {
      installPackageTarball(
        fs.readFileSync(path.join(directory, record.filename)),
        path.join(consumerNodeModules, ...record.name.split("/")),
      );
    }
    const workspaceYaml = resolveWorkspaceYamlDependency(repositoryRoot);
    fs.cpSync(workspaceYaml, path.join(consumerNodeModules, "yaml"), {
      dereference: true,
      errorOnExist: true,
      force: false,
      recursive: true,
    });
    writeFileExclusive(
      path.join(temporaryRoot, "actionproxy.mcp.yaml"),
      [
        "actionproxy:",
        "  baseUrl: http://127.0.0.1:8787",
        "  requestedBy: npm-consumer@example.com",
        "  agentId: npm-consumer",
        "servers:",
        "  fixture:",
        `    command: ${JSON.stringify(process.execPath)}`,
        "",
      ].join("\n"),
    );
    writeFileExclusive(
      path.join(temporaryRoot, "consumer.mjs"),
      [
        "import assert from 'node:assert/strict';",
        "import { ActionProxyClient, runExternalAction } from '@actionproxy/sdk-js';",
        "import { TOOL_PLANE_REPORT_VERSION } from '@actionproxy/mcp-wrapper';",
        "assert.equal(typeof ActionProxyClient, 'function');",
        "assert.equal(typeof runExternalAction, 'function');",
        "assert.equal(TOOL_PLANE_REPORT_VERSION, 'actionproxy.tool-plane-report.v1');",
        "",
      ].join("\n"),
    );
    runNonSecret(
      process.execPath,
      ["consumer.mjs"],
      temporaryRoot,
      "import exact npm release tarballs",
    );
    const binary = path.join(
      consumerNodeModules,
      "@actionproxy",
      "mcp-wrapper",
      "dist",
      "index.js",
    );
    runNonSecret(
      binary,
      ["doctor", "--config", "actionproxy.mcp.yaml", "--json"],
      temporaryRoot,
      "run installed MCP doctor",
    );
  } finally {
    fs.rmSync(temporaryRoot, { force: true, recursive: true });
  }
}

export function resolveWorkspaceYamlDependency(root = repositoryRoot) {
  const repositoryNodeModules = fs.realpathSync(
    path.join(root, "node_modules"),
  );
  const workspaceYaml = fs.realpathSync(
    path.join(root, "packages", "mcp-wrapper", "node_modules", "yaml"),
  );
  if (!workspaceYaml.startsWith(`${repositoryNodeModules}${path.sep}`)) {
    throw new Error(
      "The frozen workspace yaml dependency is outside node_modules.",
    );
  }
  return workspaceYaml;
}

function installPackageTarball(tarball, destination) {
  fs.mkdirSync(destination, { mode: 0o700, recursive: true });
  const canonicalDestination = fs.realpathSync(destination);
  for (const entry of parseNpmTarball(tarball)) {
    const target = path.join(canonicalDestination, entry.path);
    if (
      target !== canonicalDestination &&
      !target.startsWith(`${canonicalDestination}${path.sep}`)
    ) {
      throw new Error("npm package extraction target escaped its destination.");
    }
    fs.mkdirSync(path.dirname(target), { mode: 0o700, recursive: true });
    writeFileExclusive(target, entry.contents);
    fs.chmodSync(target, entry.mode);
  }
}

function verifyPackageRecord(
  record,
  specification,
  directory,
  root,
  verifyBuildOutputs,
) {
  requireExactKeys(
    record,
    [
      "entryCount",
      "filename",
      "files",
      "integrity",
      "name",
      "sha1",
      "sha256",
      "size",
      "version",
    ],
    "npm package release record",
  );
  if (!specification || record.name !== specification.name) {
    throw new Error("npm release package order or name is unexpected.");
  }
  const workspaceManifest = readJson(
    path.join(root, specification.directory, "package.json"),
  );
  const expectedFilename = `${specification.filenamePrefix}-${workspaceManifest.version}.tgz`;
  if (
    record.version !== workspaceManifest.version ||
    record.filename !== expectedFilename ||
    !Number.isSafeInteger(record.size) ||
    record.size < 1 ||
    !/^[a-f0-9]{40}$/u.test(record.sha1) ||
    !/^[a-f0-9]{64}$/u.test(record.sha256) ||
    !/^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(record.integrity)
  ) {
    throw new Error(`${record.name} release record is malformed.`);
  }
  const tarballPath = path.join(directory, record.filename);
  if (
    path.dirname(tarballPath) !== directory ||
    !fs.statSync(tarballPath).isFile()
  ) {
    throw new Error(`${record.name} release tarball is missing.`);
  }
  const tarball = fs.readFileSync(tarballPath);
  if (
    tarball.length !== record.size ||
    sha1(tarball) !== record.sha1 ||
    sha256(tarball) !== record.sha256 ||
    integrity(tarball) !== record.integrity
  ) {
    throw new Error(`${record.name} release tarball digest mismatch.`);
  }
  const entries = parseNpmTarball(tarball);
  assertPackageEntries(entries, specification);
  assertPackagedWorkspaceFiles(
    entries,
    specification,
    workspaceManifest,
    root,
    verifyBuildOutputs,
  );
  const expectedFiles = entries.map(publicFileRecord);
  if (
    record.entryCount !== expectedFiles.length ||
    JSON.stringify(record.files) !== JSON.stringify(expectedFiles)
  ) {
    throw new Error(`${record.name} release inventory mismatch.`);
  }
  return Object.freeze({
    ...record,
    files: Object.freeze(record.files.map(Object.freeze)),
  });
}

function packageRecord(specification, filename, tarball, entries, version) {
  return {
    entryCount: entries.length,
    filename,
    files: entries.map(publicFileRecord),
    integrity: integrity(tarball),
    name: specification.name,
    sha1: sha1(tarball),
    sha256: sha256(tarball),
    size: tarball.length,
    version,
  };
}

function publicFileRecord(entry) {
  return {
    mode: entry.mode,
    path: entry.path,
    sha256: entry.sha256,
    size: entry.size,
  };
}

function assertPackageEntries(entries, specification) {
  const actual = entries.map(({ path: entryPath }) => entryPath);
  if (JSON.stringify(actual) !== JSON.stringify(expectedPackageFiles)) {
    throw new Error(
      `${specification.name} does not have the exact five-file inventory.`,
    );
  }
  for (const entry of entries) {
    const expectedMode =
      entry.path === specification.executable ? 0o755 : 0o644;
    if (entry.mode !== expectedMode) {
      throw new Error(
        `${specification.name} has an unexpected mode for ${entry.path}.`,
      );
    }
  }
}

function assertPackagedWorkspaceFiles(
  entries,
  specification,
  workspaceManifest,
  root,
  verifyBuildOutputs,
) {
  const entryByPath = new Map(entries.map((entry) => [entry.path, entry]));
  const reviewedFiles = ["LICENSE", "README.md"];
  if (verifyBuildOutputs) {
    reviewedFiles.push("dist/index.d.ts", "dist/index.js");
  }
  for (const filename of reviewedFiles) {
    const expected = fs.readFileSync(
      path.join(root, specification.directory, filename),
    );
    if (!entryByPath.get(filename)?.contents.equals(expected)) {
      throw new Error(
        `${specification.name} packaged ${filename} differs from the reviewed workspace file.`,
      );
    }
  }
  const packagedManifest = JSON.parse(
    entryByPath.get("package.json").contents.toString("utf8"),
  );
  const expectedManifest = JSON.parse(JSON.stringify(workspaceManifest));
  if (isPlainObject(expectedManifest.scripts)) {
    delete expectedManifest.scripts.prepack;
  }
  if (canonicalJson(packagedManifest) !== canonicalJson(expectedManifest)) {
    throw new Error(
      `${specification.name} packaged manifest differs from the reviewed workspace manifest.`,
    );
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function requireExactKeys(value, keys, label) {
  if (
    !isPlainObject(value) ||
    JSON.stringify(Object.keys(value).sort()) !==
      JSON.stringify([...keys].sort())
  ) {
    throw new Error(`${label} has unexpected fields.`);
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertOperation(operation) {
  if (!SUPPORTED_NPM_RELEASE_OPERATIONS.includes(operation)) {
    throw new Error("Unsupported npm release operation.");
  }
}

function assertSemanticVersion(version) {
  parseSemanticVersion(version);
}

function parseSemanticVersion(version) {
  const match =
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/u.exec(
      version ?? "",
    );
  if (!match) {
    throw new Error("npm release version is not a supported semantic version.");
  }
  const numericParts = match.slice(1, 4).map(Number);
  const prerelease = match[4]?.split(".") ?? [];
  if (
    numericParts.some((part) => !Number.isSafeInteger(part)) ||
    prerelease.some(
      (part) => /^\d+$/u.test(part) && part.length > 1 && part.startsWith("0"),
    )
  ) {
    throw new Error("npm release version is not a supported semantic version.");
  }
  return {
    major: numericParts[0],
    minor: numericParts[1],
    patch: numericParts[2],
    prerelease,
  };
}

function assertRuntimeToken(value) {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length < 1 ||
    value.length > 8192 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error("Bootstrap npm credential is missing or malformed.");
  }
}

function safeRegistryTarballUrl(value) {
  return safeRegistryUrl(value, "tarball");
}

function safeRegistryUrl(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Registry returned an invalid ${label} URL.`);
  }
  if (
    url.protocol !== "https:" ||
    url.hostname !== "registry.npmjs.org" ||
    url.username ||
    url.password ||
    url.hash
  ) {
    throw new Error(
      `Registry returned a ${label} URL outside registry.npmjs.org.`,
    );
  }
  return url;
}

function assertSafePackagePath(value) {
  if (
    !value ||
    value.includes("\\") ||
    value.startsWith("/") ||
    value.endsWith("/") ||
    value
      .split("/")
      .some((part) => part === "" || part === "." || part === "..") ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error("npm tarball contains an unsafe path.");
  }
}

function readTarText(header, start, length) {
  const end = header.indexOf(0, start);
  return header
    .subarray(start, end === -1 || end > start + length ? start + length : end)
    .toString("utf8");
}

function readTarOctal(header, start, length, label) {
  const text = readTarText(header, start, length).trim();
  if (!/^[0-7]+$/u.test(text))
    throw new Error(`npm tarball has an invalid ${label}.`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error(`npm tarball has an invalid ${label}.`);
  return value;
}

function verifyTarChecksum(header) {
  const expected = readTarOctal(header, 148, 8, "checksum");
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 32 : header[index];
  }
  if (actual !== expected)
    throw new Error("npm tarball header checksum mismatch.");
}

function runNonSecret(
  command,
  args,
  cwd,
  label,
  environment = sanitizeChildEnvironment(),
) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env: environment,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const tail = `${result.stderr ?? ""}\n${result.stdout ?? ""}`.slice(-4000);
    throw new Error(
      `${label} failed (exit ${String(result.status)}).\n${tail}`,
    );
  }
  return result;
}

function runSensitive(command, args, label, credentialScope) {
  const context = createSensitiveNpmContext(process.env, credentialScope);
  try {
    const result = spawnSync(command, args, {
      cwd: context.cwd,
      encoding: "utf8",
      env: context.environment,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (result.error || result.status !== 0) {
      throw new Error(
        `${label} failed (exit ${String(result.status)}); inspect the npm registry state before retrying.`,
      );
    }
  } finally {
    context.cleanup();
  }
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeFileExclusive(filePath, body) {
  const descriptor = fs.openSync(filePath, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, body, "utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

function corepackExecutable() {
  return process.platform === "win32" ? "corepack.cmd" : "corepack";
}

function npmExecutable() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

function sha1(bytes) {
  return createHash("sha1").update(bytes).digest("hex");
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function integrity(bytes) {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

class UsageError extends Error {}

const isMain =
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;

if (isMain) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = error instanceof UsageError ? 2 : 1;
  });
}
