import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

import { validateDependencyAudit } from './check-dependency-audit.mjs';
import { validateRuntimeLicenses } from './check-runtime-licenses.mjs';
import { findMutableActionReferences } from './check-workflow-actions.mjs';
import { validateSbom } from './validate-sbom.mjs';

test('dependency audit blocks high findings and unreviewed moderate findings', () => {
  assert.throws(
    () => validateDependencyAudit({ advisories: { 1: { id: 1, severity: 'high' } } }, { reviews: [] }, '2026-07-16'),
    /Blocked dependency advisories: 1/,
  );
  assert.throws(
    () =>
      validateDependencyAudit(
        { advisories: { 2: { id: 2, github_advisory_id: 'GHSA-abcd-1234-efgh', severity: 'moderate' } } },
        { reviews: [] },
        '2026-07-16',
      ),
    /Moderate advisories without written review/,
  );
});

test('dependency audit accepts a current written moderate review', () => {
  const result = validateDependencyAudit(
    { advisories: { 2: { id: 2, github_advisory_id: 'GHSA-abcd-1234-efgh', severity: 'moderate' } } },
    {
      reviews: [
        {
          advisoryId: 'GHSA-abcd-1234-efgh',
          expiresOn: '2026-08-01',
          rationale: 'Development-only dependency is isolated from shipped runtime paths.',
          reviewedBy: 'release-owner',
          reviewedOn: '2026-07-15',
        },
      ],
    },
    '2026-07-16',
  );
  assert.deepEqual(result, { advisories: 1, moderateReviewed: 1 });
});

test('workflow action validation requires full commit revisions', () => {
  assert.deepEqual(findMutableActionReferences('steps:\n  - uses: actions/checkout@v6\n'), [
    'workflow.yml:2: actions/checkout@v6',
  ]);
  assert.deepEqual(
    findMutableActionReferences('steps:\n  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6\n'),
    [],
  );
});

test('runtime license validation creates a deterministic inventory', () => {
  const inventory = validateRuntimeLicenses({
    MIT: [{ name: 'z-package', versions: ['2.0.0'] }],
    'Apache-2.0': [{ name: 'a-package', versions: ['1.0.0'], homepage: 'https://example.test/a' }],
  });
  assert.deepEqual(inventory, [
    { homepage: 'https://example.test/a', license: 'Apache-2.0', name: 'a-package', version: '1.0.0' },
    { license: 'MIT', name: 'z-package', version: '2.0.0' },
  ]);
});

test('runtime license validation rejects unreviewed and empty reports', () => {
  assert.throws(
    () => validateRuntimeLicenses({ GPL: [{ name: 'copyleft', versions: ['1.0.0'] }] }),
    /Unreviewed runtime licenses: GPL/,
  );
  assert.throws(() => validateRuntimeLicenses({}), /inventory is empty/);
});

test('SBOM validation accepts a populated CycloneDX document', () => {
  assert.equal(
    validateSbom({
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      components: [{ name: 'fastify', version: '5.0.0' }],
    }),
    1,
  );
});

test('SBOM validation rejects malformed and empty inventories', () => {
  assert.throws(
    () => validateSbom({ bomFormat: 'SPDX', specVersion: '2.3', components: [] }),
    /Expected CycloneDX/,
  );
  assert.throws(
    () => validateSbom({ bomFormat: 'CycloneDX', specVersion: '1.7', components: [] }),
    /inventory is empty/,
  );
});

test('runtime SBOM validation rejects development tools and requires shipped closures', () => {
  const production = ['fastify', 'pg', 'yaml', 'zod'].map((name) => ({
    name,
    version: '1.0.0',
  }));
  assert.equal(
    validateSbom(
      {
        bomFormat: 'CycloneDX',
        components: production,
        specVersion: '1.7',
      },
      { runtime: true },
    ),
    4,
  );
  assert.throws(
    () =>
      validateSbom(
        {
          bomFormat: 'CycloneDX',
          components: [...production, { name: 'vitest', version: '3.0.0' }],
          specVersion: '1.7',
        },
        { runtime: true },
      ),
    /development-only components: vitest/u,
  );
  assert.throws(
    () =>
      validateSbom(
        {
          bomFormat: 'CycloneDX',
          components: production.filter((component) => component.name !== 'pg'),
          specVersion: '1.7',
        },
        { runtime: true },
      ),
    /missing required production components: pg/u,
  );
});

test('Community runtime images are non-root, production-only, and tunnel-complete', () => {
  const dockerfiles = ['Dockerfile', 'scripts/public-repo/Dockerfile'].filter((file) =>
    existsSync(file),
  );
  assert.ok(dockerfiles.includes('Dockerfile'), 'the canonical Community Dockerfile must exist');

  for (const file of dockerfiles) {
    const dockerfile = readFileSync(file, 'utf8');
    assert.match(dockerfile, /deploy --prod --legacy \/prod\/server/u);
    assert.match(dockerfile, /deploy --prod --legacy \/prod\/mcp-wrapper/u);
    assert.match(dockerfile, /COPY --from=build \/prod\/server\/node_modules/u);
    assert.match(dockerfile, /COPY --from=build \/prod\/mcp-wrapper\/node_modules/u);
    assert.match(dockerfile, /examples\/chatgpt-tunnel\/actionproxy\.mcp\.yaml/u);
    assert.match(dockerfile, /examples\/mcp-demo\/server\.mjs/u);
    assert.match(dockerfile, /\nUSER node\n/u);
    assert.doesNotMatch(dockerfile, /COPY --from=build \/app\/node_modules/u);
  }

  const smoke = readFileSync('scripts/smoke-community-docker.mjs', 'utf8');
  assert.match(smoke, /packages\/mcp-wrapper\/dist\/index\.js/u);
  assert.match(smoke, /'dangerous\.delete_customer', 'docs\.search', 'gmail\.send_email'/u);
});
