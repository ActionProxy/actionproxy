#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const checkout = path.resolve(process.argv[2] ?? '.');
const approvedRepository = 'https://github.com/ActionProxy/actionproxy';
const approvedReleaseTag = 'v0.1.0';
const failures = [];

await attestTrackedCheckout();

if (failures.length > 0) {
  console.error('Public checkout attestation failed:');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Public tracked checkout matches PUBLIC_MANIFEST.json: ${checkout}`);

async function attestTrackedCheckout() {
  const manifestPath = path.join(checkout, 'PUBLIC_MANIFEST.json');
  let manifest;
  let manifestBody;
  try {
    manifestBody = await fs.readFile(manifestPath, 'utf8');
    manifest = JSON.parse(manifestBody);
  } catch (error) {
    failures.push(
      `Cannot read PUBLIC_MANIFEST.json: ${error instanceof Error ? error.message : String(error)}`,
    );
    return;
  }

  if (
    manifest?.schemaVersion !== 'actionproxy.public-manifest.v1' ||
    !Array.isArray(manifest.files)
  ) {
    failures.push('PUBLIC_MANIFEST.json has an unexpected schema');
    return;
  }
  if (
    !hasExactKeys(manifest, [
      'files',
      'releaseTag',
      'repository',
      'schemaVersion',
    ])
  ) {
    failures.push('PUBLIC_MANIFEST.json must contain only the canonical top-level fields');
  }
  if (
    canonicalGitHubRepositoryUrl(manifest.repository) !== manifest.repository
  ) {
    failures.push('PUBLIC_MANIFEST.json has a non-canonical GitHub repository URL');
  } else if (manifest.repository !== approvedRepository) {
    failures.push(
      `PUBLIC_MANIFEST.json repository must be the approved destination: ${approvedRepository}`,
    );
  }
  if (!isSemverTag(manifest.releaseTag)) {
    failures.push('PUBLIC_MANIFEST.json has an invalid release tag');
  } else if (manifest.releaseTag !== approvedReleaseTag) {
    failures.push(
      `PUBLIC_MANIFEST.json releaseTag must be the approved release: ${approvedReleaseTag}`,
    );
  }

  try {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(checkout, 'package.json'), 'utf8'),
    );
    if (packageJson.version !== manifest.releaseTag?.slice(1)) {
      failures.push('package.json version does not match the public manifest');
    }
    if (packageJson.repository?.url !== `${manifest.repository}.git`) {
      failures.push('package.json repository does not match the public manifest');
    }
  } catch (error) {
    failures.push(
      `Cannot validate package.json metadata: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const topLevel = runGit(['rev-parse', '--show-toplevel']);
  if (!topLevel.ok) return;
  let canonicalCheckout;
  let canonicalTopLevel;
  try {
    canonicalCheckout = await fs.realpath(checkout);
    canonicalTopLevel = await fs.realpath(topLevel.stdout.trim());
  } catch (error) {
    failures.push(
      `Cannot resolve checkout root: ${error instanceof Error ? error.message : String(error)}`,
    );
    return;
  }
  if (canonicalCheckout !== canonicalTopLevel) {
    failures.push(
      `Attestation directory must be the Git worktree root: ${canonicalTopLevel}`,
    );
    return;
  }

  const listed = runGit(['ls-files', '-z', '--cached']);
  if (!listed.ok) return;
  const trackedPaths = listed.stdout
    .split('\0')
    .filter(Boolean)
    .sort(comparePaths);

  const declared = new Map();
  for (const [index, entry] of manifest.files.entries()) {
    if (!hasExactKeys(entry, ['path', 'sha256'])) {
      failures.push(`Manifest contains non-canonical fields at files[${index}]`);
    }
    if (
      !isSafeRelativePath(entry?.path) ||
      entry.path === 'PUBLIC_MANIFEST.json'
    ) {
      failures.push(
        `Manifest contains an unsafe or reserved path at files[${index}]: ${String(entry?.path)}`,
      );
      continue;
    }
    if (!/^[a-f0-9]{64}$/u.test(entry?.sha256 ?? '')) {
      failures.push(`Manifest contains an invalid SHA-256 for ${entry.path}`);
      continue;
    }
    if (declared.has(entry.path)) {
      failures.push(`Manifest contains a duplicate path: ${entry.path}`);
      continue;
    }
    declared.set(entry.path, entry.sha256);
  }

  const manifestPaths = [...declared.keys()];
  const sortedManifestPaths = [...manifestPaths].sort(comparePaths);
  if (
    manifestPaths.some(
      (relativePath, index) => relativePath !== sortedManifestPaths[index],
    )
  ) {
    failures.push('Manifest file entries are not sorted by path');
  }
  const canonicalManifestBody = `${JSON.stringify(
    {
      files: manifest.files,
      releaseTag: manifest.releaseTag,
      repository: manifest.repository,
      schemaVersion: manifest.schemaVersion,
    },
    null,
    2,
  )}\n`;
  if (manifestBody !== canonicalManifestBody) {
    failures.push('PUBLIC_MANIFEST.json is not in canonical deterministic form');
  }

  const expectedTrackedPaths = [
    ...sortedManifestPaths,
    'PUBLIC_MANIFEST.json',
  ].sort(comparePaths);
  const trackedSet = new Set(trackedPaths);
  const expectedSet = new Set(expectedTrackedPaths);

  for (const relativePath of expectedTrackedPaths) {
    if (!trackedSet.has(relativePath)) {
      failures.push(`Manifest path is not tracked by Git: ${relativePath}`);
    }
  }
  for (const relativePath of trackedPaths) {
    if (!expectedSet.has(relativePath)) {
      failures.push(`Unexpected tracked file absent from manifest: ${relativePath}`);
    }
  }

  for (const [relativePath, expectedDigest] of declared) {
    if (!trackedSet.has(relativePath)) continue;
    const absolutePath = path.join(checkout, relativePath);
    try {
      const stat = await fs.lstat(absolutePath);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        failures.push(`Manifest path is not a regular file: ${relativePath}`);
        continue;
      }
      const contents = await fs.readFile(absolutePath);
      const actualDigest = createHash('sha256').update(contents).digest('hex');
      if (actualDigest !== expectedDigest) {
        failures.push(`Manifest SHA-256 mismatch: ${relativePath}`);
      }
    } catch (error) {
      failures.push(
        `Cannot read tracked manifest path ${relativePath}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}

function runGit(args) {
  const result = spawnSync('git', ['-C', checkout, ...args], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail =
      result.error?.message || result.stderr.trim() || `exit ${String(result.status)}`;
    failures.push(
      `Git command failed (git ${args.join(' ')}): ${detail}`,
    );
    return { ok: false, stdout: '' };
  }
  return { ok: true, stdout: result.stdout };
}

function isSafeRelativePath(value) {
  if (typeof value !== 'string' || value === '' || value.includes('\\')) {
    return false;
  }
  const normalized = path.posix.normalize(value);
  return (
    normalized === value &&
    !path.posix.isAbsolute(normalized) &&
    normalized !== '..' &&
    !normalized.startsWith('../')
  );
}

function hasExactKeys(value, expectedKeys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actualKeys = Object.keys(value).sort(comparePaths);
  const sortedExpectedKeys = [...expectedKeys].sort(comparePaths);
  return (
    actualKeys.length === sortedExpectedKeys.length &&
    actualKeys.every((key, index) => key === sortedExpectedKeys[index])
  );
}

function comparePaths(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalGitHubRepositoryUrl(value) {
  if (typeof value !== 'string' || value === '') return undefined;
  try {
    const parsed = new URL(value);
    const segments = parsed.pathname.split('/').filter(Boolean);
    if (
      parsed.protocol !== 'https:' ||
      parsed.hostname.toLowerCase() !== 'github.com' ||
      parsed.port ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      segments.length !== 2 ||
      segments[1].endsWith('.git') ||
      segments.some((segment) => !/^[A-Za-z0-9_.-]+$/u.test(segment))
    ) return undefined;
    return `https://github.com/${segments[0]}/${segments[1]}`;
  } catch {
    return undefined;
  }
}

function isSemverTag(value) {
  return typeof value === 'string' &&
    /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u.test(value);
}
