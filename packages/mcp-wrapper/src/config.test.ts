import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadMcpWrapperConfig } from './config';

describe('loadMcpWrapperConfig', () => {
  it('loads ActionProxy and downstream server settings', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-config-test-'));
    const configPath = path.join(dir, 'actionproxy.mcp.yaml');
    fs.writeFileSync(
      configPath,
      `
actionproxy:
  baseUrl: http://localhost:8787
  bearerTokenEnv: ACTIONPROXY_MCP_BEARER_TOKEN
  requestedBy: dev@example.com
  requestTimeoutMs: 15000
servers:
  demo:
    command: node
    args: ["./server.mjs"]
    envPassthrough: [HOME]
    requestTimeoutMs: 20000
    stdioFraming: newline
policies:
  gmail.send_email:
    approval: required
`,
      'utf8',
    );

    const config = loadMcpWrapperConfig(configPath);

    expect(config.actionproxy.baseUrl).toBe('http://localhost:8787');
    expect(config.actionproxy).toMatchObject({
      bearerTokenEnv: 'ACTIONPROXY_MCP_BEARER_TOKEN',
      requestTimeoutMs: 15000,
    });
    expect(config.servers.demo).toMatchObject({
      args: ['./server.mjs'],
      command: 'node',
      cwd: dir,
      envPassthrough: ['HOME'],
      requestTimeoutMs: 20000,
      stdioFraming: 'newline',
    });
    expect(config.policies?.['gmail.send_email']).toEqual({ approval: 'required' });
  });

  it('requires canonical ActionProxy top-level settings', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-config-test-'));
    const configPath = path.join(dir, 'missing-actionproxy.mcp.yaml');
    fs.writeFileSync(
      configPath,
      `
proxy:
  baseUrl: http://invalid.local:8787
servers:
  demo:
    command: node
`,
      'utf8',
    );

    expect(() => loadMcpWrapperConfig(configPath)).toThrow(/requires actionproxy settings/i);
  });

  it('lets the standard base URL environment override a checked-in demo config', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-config-test-'));
    const configPath = path.join(dir, 'overridden.mcp.yaml');
    fs.writeFileSync(
      configPath,
      `
actionproxy:
  baseUrl: http://localhost:8787
servers:
  demo:
    command: node
`,
      'utf8',
    );

    const config = loadMcpWrapperConfig(configPath, {
      ACTIONPROXY_BASE_URL: 'http://127.0.0.1:18789/',
    });

    expect(config.actionproxy.baseUrl).toBe('http://127.0.0.1:18789/');
  });

  it('rejects inline ActionProxy credentials in favor of an environment reference', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-config-test-'));
    const configPath = path.join(dir, 'inline-token.mcp.yaml');
    fs.writeFileSync(
      configPath,
      `
actionproxy:
  baseUrl: http://localhost:8787
  bearerToken: do-not-store-this
servers:
  demo:
    command: node
`,
      'utf8',
    );

    expect(() => loadMcpWrapperConfig(configPath)).toThrow('bearerTokenEnv');
  });

  it('rejects invalid bearer references and forwarding the bearer variable to a child', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-config-test-'));
    const invalidNamePath = path.join(dir, 'invalid-name.mcp.yaml');
    fs.writeFileSync(
      invalidNamePath,
      `
actionproxy:
  baseUrl: http://localhost:8787
  bearerTokenEnv: NOT-A-VARIABLE
servers:
  demo:
    command: node
`,
      'utf8',
    );
    expect(() => loadMcpWrapperConfig(invalidNamePath)).toThrow('environment variable name');

    const forwardedPath = path.join(dir, 'forwarded-token.mcp.yaml');
    fs.writeFileSync(
      forwardedPath,
      `
actionproxy:
  baseUrl: http://localhost:8787
  bearerTokenEnv: ACTIONPROXY_MCP_BEARER_TOKEN
servers:
  demo:
    command: node
    env:
      ACTIONPROXY_MCP_BEARER_TOKEN: forbidden
`,
      'utf8',
    );
    expect(() => loadMcpWrapperConfig(forwardedPath)).toThrow('must not receive');

    const passedThroughPath = path.join(dir, 'passed-through-token.mcp.yaml');
    fs.writeFileSync(
      passedThroughPath,
      `
actionproxy:
  baseUrl: http://localhost:8787
  bearerTokenEnv: ACTIONPROXY_MCP_BEARER_TOKEN
servers:
  demo:
    command: node
    envPassthrough: [actionproxy_mcp_bearer_token]
`,
      'utf8',
    );
    expect(() => loadMcpWrapperConfig(passedThroughPath)).toThrow('must not pass through');
  });

  it('rejects non-positive request timeouts', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-config-test-'));
    const configPath = path.join(dir, 'timeout.mcp.yaml');
    fs.writeFileSync(
      configPath,
      `
actionproxy:
  baseUrl: http://localhost:8787
  requestTimeoutMs: 0
servers:
  demo:
    command: node
`,
      'utf8',
    );

    expect(() => loadMcpWrapperConfig(configPath)).toThrow('positive integer');
  });

  it('validates passthrough names and rejects inline/passthrough ambiguity', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-config-test-'));
    const invalidPath = path.join(dir, 'invalid-passthrough.mcp.yaml');
    fs.writeFileSync(
      invalidPath,
      `
actionproxy:
  baseUrl: http://localhost:8787
servers:
  demo:
    command: node
    envPassthrough: [VALID_NAME, NOT-A-NAME]
`,
      'utf8',
    );
    expect(() => loadMcpWrapperConfig(invalidPath)).toThrow('only environment variable names');

    const duplicatePath = path.join(dir, 'duplicate-passthrough.mcp.yaml');
    fs.writeFileSync(
      duplicatePath,
      `
actionproxy:
  baseUrl: http://localhost:8787
servers:
  demo:
    command: node
    env:
      CHILD_VALUE: inline
    envPassthrough: [child_value]
`,
      'utf8',
    );
    expect(() => loadMcpWrapperConfig(duplicatePath)).toThrow('cannot be both inline and passed through');
  });
});
