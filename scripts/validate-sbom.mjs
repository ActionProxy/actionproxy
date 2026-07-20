import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const forbiddenRuntimeComponents = new Set([
  '@playwright/test',
  'jsdom',
  'playwright',
  'playwright-core',
  'tsx',
  'tsup',
  'typescript',
  'vitest',
]);
const requiredRuntimeComponents = new Set(['fastify', 'pg', 'yaml', 'zod']);

export function validateSbom(sbom, options = {}) {
  if (!sbom || typeof sbom !== 'object' || Array.isArray(sbom)) {
    throw new Error('SBOM must be a JSON object.');
  }
  if (sbom.bomFormat !== 'CycloneDX') {
    throw new Error(`Expected CycloneDX SBOM, received ${String(sbom.bomFormat)}.`);
  }
  if (typeof sbom.specVersion !== 'string' || !/^1\.[4-9]$/.test(sbom.specVersion)) {
    throw new Error(`Unsupported CycloneDX spec version ${String(sbom.specVersion)}.`);
  }
  if (!Array.isArray(sbom.components) || sbom.components.length === 0) {
    throw new Error('SBOM component inventory is empty.');
  }

  for (const component of sbom.components) {
    if (!component || typeof component.name !== 'string' || component.name.length === 0) {
      throw new Error('SBOM contains a component without a name.');
    }
    if (typeof component.version !== 'string' || component.version.length === 0) {
      throw new Error(`SBOM component ${component.name} has no version.`);
    }
  }
  if (options.runtime === true) {
    if (sbom.specVersion !== '1.7') {
      throw new Error(`Runtime SBOM must use CycloneDX 1.7, received ${String(sbom.specVersion)}.`);
    }
    const names = new Set(sbom.components.map((component) => component.name));
    const forbidden = [...names].filter((name) => forbiddenRuntimeComponents.has(name));
    if (forbidden.length > 0) {
      throw new Error(`Runtime SBOM contains development-only components: ${forbidden.sort().join(', ')}.`);
    }
    const missing = [...requiredRuntimeComponents].filter((name) => !names.has(name));
    if (missing.length > 0) {
      throw new Error(`Runtime SBOM is missing required production components: ${missing.sort().join(', ')}.`);
    }
  }
  return sbom.components.length;
}

function main() {
  const inputPath = process.argv[2] ?? 'bom.json';
  const sbom = JSON.parse(readFileSync(inputPath, 'utf8'));
  const count = validateSbom(sbom, { runtime: true });
  console.log(`Validated CycloneDX ${sbom.specVersion} SBOM with ${count} components.`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
