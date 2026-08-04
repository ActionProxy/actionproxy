import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  buildEditorAssociations,
  buildMcpWrapperSchema,
  buildPolicySchema,
  checkConfigSchemas,
  CONFIG_SCHEMA_OUTPUTS,
  renderedConfigSchemas,
  writeConfigSchemas,
} from './generate-config-schemas.mjs';

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
);

test('checked-in configuration schemas exactly match deterministic output', () => {
  assert.deepEqual(checkConfigSchemas(repoRoot), []);

  for (const [relativePath, expected] of renderedConfigSchemas()) {
    assert.equal(
      fs.readFileSync(path.join(repoRoot, relativePath), 'utf8'),
      expected,
    );
  }
});

test('schema checker reports missing and changed artifacts without rewriting them', () => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), 'actionproxy-config-schema-test-'),
  );
  writeConfigSchemas(temporaryRoot);
  assert.deepEqual(checkConfigSchemas(temporaryRoot), []);

  fs.writeFileSync(
    path.join(temporaryRoot, CONFIG_SCHEMA_OUTPUTS.policy),
    '{"changed":true}\n',
    'utf8',
  );
  fs.rmSync(path.join(temporaryRoot, CONFIG_SCHEMA_OUTPUTS.editorAssociations));

  assert.deepEqual(checkConfigSchemas(temporaryRoot), [
    'schemas/actionproxy.policy.v1.schema.json: differs from deterministic generator output',
    'schemas/editor-associations.json: missing',
  ]);
});

test('schemas use draft 2020-12, stable IDs, and runtime-compatible unknown-field boundaries', () => {
  const policy = buildPolicySchema();
  const mcp = buildMcpWrapperSchema();

  assert.equal(policy.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(
    policy.$id,
    'https://actionproxy.com/schemas/actionproxy.policy.v1.schema.json',
  );
  assert.equal(policy.additionalProperties, true);
  assert.equal(policy.$defs.policyRule.additionalProperties, true);
  assert.equal(policy.$defs.approvers.additionalProperties, true);
  assert.equal(policy.$defs.externalExecution.additionalProperties, true);
  assert.equal(policy.$defs.notification.additionalProperties, true);
  assert.equal(policy.$defs.redaction.additionalProperties, true);
  assert.equal(policy.$defs.resultSourceDescriptor.additionalProperties, false);
  assert.equal(policy.$defs.influence.additionalProperties, false);

  assert.equal(mcp.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(
    mcp.$id,
    'https://actionproxy.com/schemas/actionproxy.mcp-wrapper.v1.schema.json',
  );
  assert.equal(mcp.additionalProperties, true);
  assert.equal(mcp.$defs.actionproxy.additionalProperties, true);
  assert.equal(mcp.$defs.server.additionalProperties, true);
  assert.equal(mcp.$defs.policyIntent.additionalProperties, true);
  assert.equal(mcp.$defs.actionproxy.properties.apiKey, false);
  assert.equal(mcp.$defs.actionproxy.properties.bearerToken, false);
  assert.equal(mcp.$defs.actionproxy.properties.token, false);
  assert.equal(mcp.$defs.actionproxy.properties.quickstartOriginToken, false);
});

test('editor associations cover conventional policy and MCP-wrapper YAML names', () => {
  assert.deepEqual(buildEditorAssociations(), {
    'yaml.schemas': {
      './schemas/actionproxy.policy.v1.schema.json': [
        '**/actionproxy.policy.yaml',
        '**/actionproxy.policy.yml',
        '**/*.policy.yaml',
        '**/*.policy.yml',
      ],
      './schemas/actionproxy.mcp-wrapper.v1.schema.json': [
        '**/actionproxy.mcp.yaml',
        '**/actionproxy.mcp.yml',
      ],
    },
  });
});

test('check CLI is read-only and rejects unsupported arguments with usage exit code 2', () => {
  const success = spawnSync(
    process.execPath,
    ['scripts/generate-config-schemas.mjs', '--check'],
    {
      cwd: repoRoot,
      encoding: 'utf8',
    },
  );
  assert.equal(success.status, 0, success.stderr);
  assert.match(success.stdout, /schemas are current/u);

  const invalid = spawnSync(
    process.execPath,
    ['scripts/generate-config-schemas.mjs', '--unknown'],
    {
      cwd: repoRoot,
      encoding: 'utf8',
    },
  );
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /Usage:/u);
});
