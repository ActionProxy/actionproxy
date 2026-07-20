#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(process.argv[2] ?? '.');
const manifestPath = path.join(root, 'PUBLIC_MANIFEST.json');
const approvedRepository = 'https://github.com/ActionProxy/actionproxy';
const approvedReleaseTag = 'v0.1.0';

const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
if (
  !hasExactKeys(manifest, [
    'files',
    'releaseTag',
    'repository',
    'schemaVersion',
  ]) ||
  manifest?.schemaVersion !== 'actionproxy.public-manifest.v1' ||
  manifest.repository !== approvedRepository ||
  manifest.releaseTag !== approvedReleaseTag
) {
  fail('PUBLIC_MANIFEST.json has unexpected schema or release metadata.');
}

const topLevel = runGit(['rev-parse', '--show-toplevel']).trim();
if ((await fs.realpath(root)) !== (await fs.realpath(topLevel))) {
  fail(`Manifest refresh must run at the Git worktree root: ${topLevel}`);
}

const paths = runGit([
  'ls-files',
  '-z',
  '--cached',
  '--others',
  '--exclude-standard',
])
  .split('\0')
  .filter((relativePath) => relativePath && relativePath !== 'PUBLIC_MANIFEST.json')
  .sort(comparePaths);

const files = [];
for (const relativePath of paths) {
  if (!isSafeRelativePath(relativePath)) {
    fail(`Git reported an unsafe public path: ${relativePath}`);
  }
  const absolutePath = path.join(root, relativePath);
  let stat;
  try {
    stat = await fs.lstat(absolutePath);
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') continue;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`Public manifest paths must be regular files: ${relativePath}`);
  }
  const contents = await fs.readFile(absolutePath);
  files.push({
    path: relativePath,
    sha256: createHash('sha256').update(contents).digest('hex'),
  });
}

await fs.writeFile(
  manifestPath,
  `${JSON.stringify(
    {
      files,
      releaseTag: manifest.releaseTag,
      repository: manifest.repository,
      schemaVersion: manifest.schemaVersion,
    },
    null,
    2,
  )}\n`,
  'utf8',
);
console.log(`Refreshed PUBLIC_MANIFEST.json with ${files.length} files.`);

function runGit(args) {
  const result = spawnSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    fail(
      `git ${args.join(' ')} failed: ${result.error?.message || result.stderr.trim() || `exit ${String(result.status)}`}`,
    );
  }
  return result.stdout;
}

function isSafeRelativePath(value) {
  if (typeof value !== 'string' || value === '' || value.includes('\\')) return false;
  const normalized = path.posix.normalize(value);
  return normalized === value && !path.posix.isAbsolute(normalized) && normalized !== '..' && !normalized.startsWith('../');
}

function comparePaths(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
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

function fail(message) {
  console.error(message);
  process.exit(1);
}
