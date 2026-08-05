#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCHEMA_DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const POLICY_SCHEMA_ID =
  'https://actionproxy.com/schemas/actionproxy.policy.v1.schema.json';
const MCP_WRAPPER_SCHEMA_ID =
  'https://actionproxy.com/schemas/actionproxy.mcp-wrapper.v1.schema.json';

const approvalModes = ['never', 'required', 'deny'];
const contentIntegrityValues = [
  'organization_managed',
  'verified_publisher',
  'authenticated_external',
  'public_untrusted',
  'unknown',
];
const influenceSourceValues = ['none', ...contentIntegrityValues];

export const CONFIG_SCHEMA_OUTPUTS = Object.freeze({
  editorAssociations: 'schemas/editor-associations.json',
  mcpWrapper: 'schemas/actionproxy.mcp-wrapper.v1.schema.json',
  policy: 'schemas/actionproxy.policy.v1.schema.json',
});

export function buildPolicySchema() {
  const nonEmptyString = { minLength: 1, type: 'string' };

  return {
    $schema: SCHEMA_DIALECT,
    $id: POLICY_SCHEMA_ID,
    title: 'ActionProxy policy v1',
    description:
      'Deterministic policy for ActionProxy tool-call allow, approval, and denial decisions. YAML files are validated against the equivalent JSON data model.',
    type: 'object',
    required: ['version', 'default'],
    properties: {
      version: {
        description:
          'Operator-managed policy version included in authorization evidence.',
        type: 'number',
        examples: [1],
      },
      default: { $ref: '#/$defs/policyRule' },
      tools: {
        description:
          'Exact tool names or terminal namespace wildcards such as payments.*.',
        type: 'object',
        default: {},
        additionalProperties: { $ref: '#/$defs/policyRule' },
      },
    },
    additionalProperties: true,
    $comment:
      'The v1 runtime strips unknown top-level and policy-rule fields for legacy compatibility. resultSource and influence are intentionally strict.',
    $defs: {
      approvalMode: {
        type: 'string',
        enum: approvalModes,
        description:
          'never allows, required queues approval, and deny blocks before dispatch.',
      },
      approvers: {
        type: 'object',
        properties: {
          groups: { type: 'array', items: nonEmptyString },
          users: { type: 'array', items: nonEmptyString },
          requiredApprovals: { type: 'integer', minimum: 1, maximum: 10 },
          separationOfDuties: { type: 'boolean' },
        },
        additionalProperties: true,
      },
      externalExecution: {
        type: 'object',
        properties: {
          grantTtlSeconds: { type: 'integer', minimum: 1, maximum: 86400 },
          requireGrantConsumption: { type: 'boolean' },
        },
        additionalProperties: true,
      },
      influence: {
        type: 'object',
        required: ['allowFrom', 'otherwise'],
        properties: {
          allowFrom: {
            type: 'array',
            minItems: 1,
            maxItems: influenceSourceValues.length,
            uniqueItems: true,
            items: { type: 'string', enum: influenceSourceValues },
          },
          otherwise: { type: 'string', enum: ['required', 'deny'] },
        },
        additionalProperties: false,
      },
      notification: {
        type: 'object',
        properties: {
          channels: { type: 'array', items: nonEmptyString },
        },
        additionalProperties: true,
      },
      redaction: {
        type: 'object',
        properties: {
          fields: { type: 'array', items: nonEmptyString },
          replacement: { type: 'string' },
        },
        additionalProperties: true,
      },
      resultSource: {
        oneOf: [
          {
            const: 'none',
            description:
              'The reviewed tool result cannot release external content to the model.',
          },
          { $ref: '#/$defs/resultSourceDescriptor' },
        ],
      },
      resultSourceDescriptor: {
        type: 'object',
        required: ['integrity'],
        properties: {
          integrity: { type: 'string', enum: contentIntegrityValues },
          sourceId: {
            type: 'string',
            pattern: '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$',
          },
        },
        additionalProperties: false,
      },
      policyRule: {
        type: 'object',
        required: ['approval'],
        properties: {
          approval: { $ref: '#/$defs/approvalMode' },
          approvers: { $ref: '#/$defs/approvers' },
          conditions: {
            type: 'object',
            description:
              'Typed condition values evaluated against trusted adapter-derived context.',
            additionalProperties: true,
          },
          externalExecution: { $ref: '#/$defs/externalExecution' },
          influence: { $ref: '#/$defs/influence' },
          notify: { $ref: '#/$defs/notification' },
          redaction: { $ref: '#/$defs/redaction' },
          resultSource: { $ref: '#/$defs/resultSource' },
          risk: { type: 'string' },
          reason: { type: 'string' },
        },
        additionalProperties: true,
        allOf: [
          {
            if: {
              required: ['risk'],
              properties: { risk: { const: 'open_world_read' } },
            },
            then: {
              required: ['resultSource'],
              properties: {
                resultSource: {
                  type: 'object',
                  required: ['integrity'],
                  properties: { integrity: { const: 'public_untrusted' } },
                },
              },
            },
          },
        ],
      },
    },
    examples: [
      {
        version: 1,
        default: {
          approval: 'required',
          risk: 'unknown',
          reason: 'Unknown tools require approval by default.',
        },
        tools: {
          'docs.search': {
            approval: 'never',
            risk: 'read_only',
            reason: 'Search is read-only.',
          },
          'gmail.send_email': {
            approval: 'required',
            risk: 'external_communication',
            reason: 'External email requires approval.',
          },
          'dangerous.delete_customer': {
            approval: 'deny',
            risk: 'destructive',
            reason: 'Customer deletion is blocked.',
          },
        },
      },
    ],
  };
}

export function buildMcpWrapperSchema() {
  const environmentName = { $ref: '#/$defs/environmentVariableName' };

  return {
    $schema: SCHEMA_DIALECT,
    $id: MCP_WRAPPER_SCHEMA_ID,
    title: 'ActionProxy MCP wrapper configuration v1',
    description:
      'Configuration for wrapping one or more downstream stdio MCP servers with the ActionProxy governance lifecycle.',
    type: 'object',
    required: ['actionproxy', 'servers'],
    properties: {
      actionproxy: { $ref: '#/$defs/actionproxy' },
      servers: {
        type: 'object',
        minProperties: 1,
        additionalProperties: { $ref: '#/$defs/server' },
      },
      policies: {
        type: 'object',
        description:
          'Documented wrapper intent only. The ActionProxy server policy remains the enforcement source of truth.',
        additionalProperties: { $ref: '#/$defs/policyIntent' },
      },
    },
    additionalProperties: true,
    $comment:
      'The v1 parser strips unknown fields for compatibility. It also performs case-insensitive credential isolation and inline-versus-passthrough checks that JSON Schema cannot express.',
    $defs: {
      actionproxy: {
        type: 'object',
        required: ['baseUrl'],
        properties: {
          baseUrl: {
            type: 'string',
            pattern: '\\S',
            description:
              'ActionProxy gateway base URL. ACTIONPROXY_BASE_URL may override it at runtime.',
            examples: ['http://127.0.0.1:8787'],
          },
          agentId: { type: 'string' },
          requestedBy: { type: 'string' },
          approvalPollIntervalMs: { type: 'number' },
          approvalTimeoutMs: { type: 'number' },
          cancelPendingOnAbort: { type: 'boolean', default: false },
          bearerTokenEnv: environmentName,
          quickstartOriginTokenEnv: environmentName,
          requestTimeoutMs: {
            type: 'integer',
            minimum: 1,
            maximum: Number.MAX_SAFE_INTEGER,
          },
          apiKey: false,
          bearerToken: false,
          token: false,
          quickstartOriginToken: false,
        },
        additionalProperties: true,
        $comment:
          'Credentials must be referenced by environment-variable name. Literal apiKey, bearerToken, token, and quickstartOriginToken properties are rejected by the runtime.',
      },
      environmentVariableName: {
        type: 'string',
        pattern: '^[A-Za-z_][A-Za-z0-9_]*$',
      },
      policyIntent: {
        type: 'object',
        required: ['approval'],
        properties: {
          approval: { type: 'string', enum: approvalModes },
        },
        additionalProperties: true,
      },
      server: {
        type: 'object',
        required: ['command'],
        properties: {
          command: { type: 'string', pattern: '\\S' },
          args: { type: 'array', items: { type: 'string' } },
          cwd: { type: 'string' },
          env: {
            type: 'object',
            additionalProperties: { type: 'string' },
          },
          envPassthrough: {
            type: 'array',
            items: environmentName,
            uniqueItems: true,
          },
          requestTimeoutMs: {
            type: 'integer',
            minimum: 1,
            maximum: Number.MAX_SAFE_INTEGER,
          },
          stdioFraming: { type: 'string', enum: ['content-length', 'newline'] },
        },
        additionalProperties: true,
        $comment:
          'At runtime envPassthrough names are unique case-insensitively, cannot duplicate inline env names, and cannot expose either configured ActionProxy credential variable.',
      },
    },
    examples: [
      {
        actionproxy: {
          baseUrl: 'http://127.0.0.1:8787',
          bearerTokenEnv: 'ACTIONPROXY_MCP_BEARER_TOKEN',
          approvalPollIntervalMs: 1000,
          approvalTimeoutMs: 300000,
          cancelPendingOnAbort: true,
        },
        servers: {
          demo: {
            command: 'node',
            args: ['./server.mjs'],
            envPassthrough: ['DOWNSTREAM_CREDENTIAL_REFERENCE'],
          },
        },
        policies: {
          'docs.search': { approval: 'never' },
          'gmail.send_email': { approval: 'required' },
          'dangerous.delete_customer': { approval: 'deny' },
        },
      },
    ],
  };
}

export function buildEditorAssociations() {
  return {
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
  };
}

export function renderedConfigSchemas() {
  return new Map([
    [CONFIG_SCHEMA_OUTPUTS.policy, renderJson(buildPolicySchema())],
    [CONFIG_SCHEMA_OUTPUTS.mcpWrapper, renderJson(buildMcpWrapperSchema())],
    [
      CONFIG_SCHEMA_OUTPUTS.editorAssociations,
      renderJson(buildEditorAssociations()),
    ],
  ]);
}

export function checkConfigSchemas(repoRoot) {
  const failures = [];
  for (const [relativePath, expected] of renderedConfigSchemas()) {
    const outputPath = path.join(repoRoot, relativePath);
    if (!fs.existsSync(outputPath)) {
      failures.push(`${relativePath}: missing`);
      continue;
    }
    if (fs.readFileSync(outputPath, 'utf8') !== expected) {
      failures.push(
        `${relativePath}: differs from deterministic generator output`,
      );
    }
  }
  return failures;
}

export function writeConfigSchemas(repoRoot) {
  for (const [relativePath, contents] of renderedConfigSchemas()) {
    const outputPath = path.join(repoRoot, relativePath);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, contents, 'utf8');
  }
}

function renderJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function isDirectExecution() {
  return (
    process.argv[1] &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  );
}

if (isDirectExecution()) {
  const args = process.argv.slice(2);
  const unknown = args.filter((argument) => argument !== '--check');
  if (unknown.length > 0) {
    process.stderr.write(
      `Unknown argument: ${unknown[0]}\nUsage: node scripts/generate-config-schemas.mjs [--check]\n`,
    );
    process.exitCode = 2;
  } else {
    const repoRoot = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '..',
    );
    if (args.includes('--check')) {
      const failures = checkConfigSchemas(repoRoot);
      if (failures.length > 0) {
        process.stderr.write(
          `${failures.join('\n')}\nRun: node scripts/generate-config-schemas.mjs\n`,
        );
        process.exitCode = 1;
      } else {
        process.stdout.write(
          'ActionProxy configuration schemas are current.\n',
        );
      }
    } else {
      writeConfigSchemas(repoRoot);
      process.stdout.write('Generated ActionProxy configuration schemas.\n');
    }
  }
}
