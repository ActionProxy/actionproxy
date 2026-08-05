import { existsSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const allowedRuntimeLicenses = new Set([
  '0BSD',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'CC0-1.0',
  'ISC',
  'MIT',
]);
export const runtimePackageScope = [
  '@actionproxy/server',
  '@actionproxy/mcp-wrapper',
];
export const runtimePackageLocations = {
  '@actionproxy/mcp-wrapper': 'packages/mcp-wrapper',
  '@actionproxy/server': 'apps/server',
};

export function validateRuntimeLicenses(report) {
  if (!report || Array.isArray(report) || typeof report !== 'object') {
    throw new Error('pnpm returned an invalid runtime license report.');
  }

  const disallowed = Object.keys(report).filter((license) => !allowedRuntimeLicenses.has(license));
  if (disallowed.length > 0) {
    throw new Error(`Unreviewed runtime licenses: ${disallowed.sort().join(', ')}`);
  }

  const inventory = Object.entries(report)
    .flatMap(([license, packages]) => {
      if (!Array.isArray(packages)) {
        throw new Error(`pnpm returned an invalid package list for ${license}.`);
      }
      return packages.flatMap((entry) => {
        if (!entry || typeof entry.name !== 'string' || !Array.isArray(entry.versions)) {
          throw new Error(`pnpm returned an invalid package entry for ${license}.`);
        }
        return entry.versions.map((version) => ({
          license,
          name: entry.name,
          version,
          ...(typeof entry.homepage === 'string' ? { homepage: entry.homepage } : {}),
        }));
      });
    })
    .sort((left, right) => `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`));

  if (inventory.length === 0) {
    throw new Error('Runtime license inventory is empty.');
  }
  return inventory;
}

function readPackageManifest(manifestPath, expectedName) {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    throw new Error(`Unable to read the installed package manifest for ${expectedName}.`);
  }
  if (!manifest || Array.isArray(manifest) || typeof manifest !== 'object') {
    throw new Error(`Installed package ${expectedName} has an invalid package manifest.`);
  }
  return manifest;
}

function dependencyManifestCandidates(parentManifestPath, parentPackageName, dependencyName) {
  const dependencyParts = dependencyName.split('/');
  const packageDirectory = dirname(parentManifestPath);
  const siblingNodeModules = parentPackageName.startsWith('@')
    ? dirname(dirname(packageDirectory))
    : dirname(packageDirectory);
  return [
    join(packageDirectory, 'node_modules', ...dependencyParts, 'package.json'),
    join(siblingNodeModules, ...dependencyParts, 'package.json'),
  ];
}

function installedDependencyManifest(parentManifestPath, parentPackageName, dependencyName) {
  return dependencyManifestCandidates(parentManifestPath, parentPackageName, dependencyName).find(
    (candidate) => existsSync(candidate),
  );
}

function packageDependencies(manifest) {
  const dependencies = new Map();
  for (const dependencyName of Object.keys(manifest.dependencies ?? {})) {
    dependencies.set(dependencyName, { optional: false });
  }
  for (const dependencyName of Object.keys(manifest.optionalDependencies ?? {})) {
    dependencies.set(dependencyName, { optional: true });
  }
  for (const dependencyName of Object.keys(manifest.peerDependencies ?? {})) {
    if (!dependencies.has(dependencyName)) {
      dependencies.set(dependencyName, {
        optional: manifest.peerDependenciesMeta?.[dependencyName]?.optional === true,
      });
    }
  }
  return [...dependencies.entries()].sort(([left], [right]) => left.localeCompare(right));
}

export function buildRuntimeLicenseReport(repoRoot = process.cwd()) {
  const packages = new Map();
  const visitedManifestPaths = new Set();
  const pending = [];

  for (const packageName of runtimePackageScope) {
    const packageLocation = runtimePackageLocations[packageName];
    const manifestPath = resolve(repoRoot, packageLocation, 'package.json');
    const manifest = readPackageManifest(manifestPath, packageName);
    if (manifest.name !== packageName) {
      throw new Error(`Runtime package location for ${packageName} contains a different package.`);
    }
    for (const [dependencyName, metadata] of packageDependencies(manifest)) {
      const dependencyManifestPath = join(
        dirname(manifestPath),
        'node_modules',
        ...dependencyName.split('/'),
        'package.json',
      );
      pending.push({
        dependencyName,
        manifestPath: dependencyManifestPath,
        optional: metadata.optional,
        parentPackageName: packageName,
      });
    }
  }

  while (pending.length > 0) {
    const next = pending.pop();
    if (!next.manifestPath || !existsSync(next.manifestPath)) {
      if (next.optional) continue;
      throw new Error(
        `Runtime dependency ${next.dependencyName} required by ${next.parentPackageName} is not installed. Run corepack pnpm install --frozen-lockfile, then retry.`,
      );
    }

    const manifestPath = realpathSync(next.manifestPath);
    if (visitedManifestPaths.has(manifestPath)) continue;
    visitedManifestPaths.add(manifestPath);

    const manifest = readPackageManifest(manifestPath, next.dependencyName);
    if (
      typeof manifest.name !== 'string' ||
      manifest.name.length === 0 ||
      typeof manifest.version !== 'string' ||
      manifest.version.length === 0 ||
      typeof manifest.license !== 'string' ||
      manifest.license.length === 0
    ) {
      throw new Error(`Installed runtime dependency ${next.dependencyName} lacks name, version, or license metadata.`);
    }

    const packageKey = `${manifest.name}\u0000${manifest.version}`;
    const existingPackage = packages.get(packageKey);
    if (existingPackage && existingPackage.license !== manifest.license) {
      throw new Error(`Installed runtime dependency ${manifest.name}@${manifest.version} has conflicting license metadata.`);
    }
    packages.set(packageKey, {
      license: manifest.license,
      name: manifest.name,
      version: manifest.version,
      ...(typeof manifest.homepage === 'string' ? { homepage: manifest.homepage } : {}),
    });

    for (const [dependencyName, metadata] of packageDependencies(manifest)) {
      const dependencyManifestPath = installedDependencyManifest(
        manifestPath,
        manifest.name,
        dependencyName,
      );
      pending.push({
        dependencyName,
        manifestPath: dependencyManifestPath ?? '',
        optional: metadata.optional,
        parentPackageName: manifest.name,
      });
    }
  }

  const report = {};
  for (const entry of [...packages.values()].sort((left, right) =>
    `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`),
  )) {
    report[entry.license] ??= [];
    report[entry.license].push({
      name: entry.name,
      versions: [entry.version],
      ...(entry.homepage ? { homepage: entry.homepage } : {}),
    });
  }
  return report;
}

function main() {
  const inventory = validateRuntimeLicenses(buildRuntimeLicenseReport());
  const outputPath = process.argv[2] ?? 'runtime-licenses.json';
  writeFileSync(
    outputPath,
    `${JSON.stringify(
      {
        packages: inventory,
        scope: {
          packages: runtimePackageScope,
          productionOnly: true,
        },
      },
      null,
      2,
    )}\n`,
  );
  console.log(`Validated ${inventory.length} runtime package licenses; wrote ${outputPath}.`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
