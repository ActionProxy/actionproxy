import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
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

function main() {
  const filters = runtimePackageScope.flatMap((packageName) => [
    '--filter',
    packageName,
  ]);
  const result = spawnSync('corepack', ['pnpm', ...filters, 'licenses', 'list', '--prod', '--json'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    shell: process.platform === 'win32',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `pnpm licenses exited with status ${result.status}.`);
  }

  const inventory = validateRuntimeLicenses(JSON.parse(result.stdout));
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
