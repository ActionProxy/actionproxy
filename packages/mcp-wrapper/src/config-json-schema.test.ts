import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import YAML from 'yaml';
import { describe, expect, it } from 'vitest';
import { loadMcpWrapperConfig } from './config';

type JsonSchema = {
  $schema: string;
  $id: string;
  additionalProperties: boolean;
  examples: unknown[];
  $defs: Record<string, any>;
};

const schema = JSON.parse(
  fs.readFileSync(
    new URL(
      '../../../schemas/actionproxy.mcp-wrapper.v1.schema.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as JsonSchema;

function loadObject(value: unknown) {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'actionproxy-mcp-schema-test-'),
  );
  const configPath = path.join(directory, 'actionproxy.mcp.yaml');
  fs.writeFileSync(configPath, YAML.stringify(value), 'utf8');
  return loadMcpWrapperConfig(configPath, {});
}

function minimalConfig() {
  return {
    actionproxy: { baseUrl: 'http://127.0.0.1:8787' },
    servers: { demo: { command: 'node' } },
  };
}

describe('ActionProxy MCP-wrapper JSON Schema parity', () => {
  it('keeps runtime enums and validation constraints aligned with the public schema', () => {
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema.$id).toBe(
      'https://actionproxy.com/schemas/actionproxy.mcp-wrapper.v1.schema.json',
    );
    expect(schema.$defs.policyIntent.properties.approval.enum).toEqual([
      'never',
      'required',
      'deny',
    ]);
    expect(schema.$defs.server.properties.stdioFraming.enum).toEqual([
      'content-length',
      'newline',
    ]);
    expect(schema.$defs.environmentVariableName.pattern).toBe(
      '^[A-Za-z_][A-Za-z0-9_]*$',
    );
    expect(schema.$defs.actionproxy.properties.requestTimeoutMs).toMatchObject({
      maximum: Number.MAX_SAFE_INTEGER,
      minimum: 1,
      type: 'integer',
    });
    expect(schema.$defs.server.properties.requestTimeoutMs).toMatchObject({
      maximum: Number.MAX_SAFE_INTEGER,
      minimum: 1,
      type: 'integer',
    });

    for (const approval of schema.$defs.policyIntent.properties.approval
      .enum as string[]) {
      const config = minimalConfig();
      const loaded = loadObject({
        ...config,
        policies: { 'test.tool': { approval } },
      });
      expect(loaded.policies?.['test.tool']?.approval).toBe(approval);
    }
    for (const stdioFraming of schema.$defs.server.properties.stdioFraming
      .enum as string[]) {
      expect(
        loadObject({
          actionproxy: { baseUrl: 'http://127.0.0.1:8787' },
          servers: { demo: { command: 'node', stdioFraming } },
        }).servers.demo?.stdioFraming,
      ).toBe(stdioFraming);
    }
  });

  it('keeps unknown-field compatibility while rejecting literal credentials', () => {
    expect(schema.additionalProperties).toBe(true);
    expect(schema.$defs.actionproxy.additionalProperties).toBe(true);
    expect(schema.$defs.server.additionalProperties).toBe(true);
    expect(schema.$defs.policyIntent.additionalProperties).toBe(true);
    for (const forbidden of [
      'apiKey',
      'bearerToken',
      'token',
      'quickstartOriginToken',
    ]) {
      expect(schema.$defs.actionproxy.properties[forbidden]).toBe(false);
    }

    const loaded = loadObject({
      actionproxy: {
        baseUrl: 'http://127.0.0.1:8787',
        legacyActionProxyHint: true,
      },
      legacyTopLevelHint: true,
      policies: {
        'docs.search': { approval: 'never', legacyPolicyHint: true },
      },
      servers: {
        demo: { command: 'node', legacyServerHint: true },
      },
    });
    expect(loaded).toMatchObject({
      actionproxy: { baseUrl: 'http://127.0.0.1:8787' },
      policies: { 'docs.search': { approval: 'never' } },
      servers: { demo: { command: 'node' } },
    });
    expect(loaded.actionproxy).not.toHaveProperty('legacyActionProxyHint');
    expect(loaded.servers.demo).not.toHaveProperty('legacyServerHint');
    expect(loaded.policies?.['docs.search']).not.toHaveProperty(
      'legacyPolicyHint',
    );

    for (const forbidden of [
      'apiKey',
      'bearerToken',
      'token',
      'quickstartOriginToken',
    ]) {
      const config = minimalConfig();
      expect(() =>
        loadObject({
          ...config,
          actionproxy: {
            ...config.actionproxy,
            [forbidden]: 'must-not-be-inline',
          },
        }),
      ).toThrow(/must reference/u);
    }
  });

  it('rejects malformed recognized fields instead of silently normalizing them', () => {
    const invalidConfigs: Array<[string, unknown]> = [
      [
        'actionproxy.agentId',
        {
          ...minimalConfig(),
          actionproxy: { baseUrl: 'http://127.0.0.1:8787', agentId: 7 },
        },
      ],
      [
        'actionproxy.requestedBy',
        {
          ...minimalConfig(),
          actionproxy: { baseUrl: 'http://127.0.0.1:8787', requestedBy: false },
        },
      ],
      [
        'actionproxy.approvalPollIntervalMs',
        {
          ...minimalConfig(),
          actionproxy: {
            baseUrl: 'http://127.0.0.1:8787',
            approvalPollIntervalMs: '1000',
          },
        },
      ],
      [
        'actionproxy.approvalTimeoutMs',
        {
          ...minimalConfig(),
          actionproxy: {
            baseUrl: 'http://127.0.0.1:8787',
            approvalTimeoutMs: '300000',
          },
        },
      ],
      [
        'actionproxy.requestTimeoutMs',
        {
          ...minimalConfig(),
          actionproxy: {
            baseUrl: 'http://127.0.0.1:8787',
            requestTimeoutMs: Number.MAX_SAFE_INTEGER + 1,
          },
        },
      ],
      [
        'servers.demo.args',
        {
          actionproxy: { baseUrl: 'http://127.0.0.1:8787' },
          servers: { demo: { command: 'node', args: ['./server.mjs', 7] } },
        },
      ],
      [
        'servers.demo.cwd',
        {
          actionproxy: { baseUrl: 'http://127.0.0.1:8787' },
          servers: { demo: { command: 'node', cwd: false } },
        },
      ],
      [
        'servers.demo.env',
        {
          actionproxy: { baseUrl: 'http://127.0.0.1:8787' },
          servers: { demo: { command: 'node', env: { CHILD_VALUE: 7 } } },
        },
      ],
      [
        'servers.demo.requestTimeoutMs',
        {
          actionproxy: { baseUrl: 'http://127.0.0.1:8787' },
          servers: {
            demo: {
              command: 'node',
              requestTimeoutMs: Number.MAX_SAFE_INTEGER + 1,
            },
          },
        },
      ],
      [
        'policies.test.tool.approval',
        {
          ...minimalConfig(),
          policies: { 'test.tool': { approval: 'sometimes' } },
        },
      ],
    ];

    for (const [expectedPath, invalidConfig] of invalidConfigs) {
      expect(() => loadObject(invalidConfig), expectedPath).toThrow(
        expectedPath,
      );
    }
  });

  it('loads every checked-in schema example through the configuration parser', () => {
    expect(schema.examples.length).toBeGreaterThan(0);
    for (const example of schema.examples) {
      const loaded = loadObject(example);
      expect(loaded.actionproxy.baseUrl).toBe('http://127.0.0.1:8787');
      expect(Object.keys(loaded.servers)).toEqual(['demo']);
      expect(loaded.policies).toEqual({
        'dangerous.delete_customer': { approval: 'deny' },
        'docs.search': { approval: 'never' },
        'gmail.send_email': { approval: 'required' },
      });
    }
  });
});
