import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { inspectConfiguredMcpWrapper } from './doctor';
import { runMcpWrapperCli } from './index';
import type { DownstreamMcpClient, McpTool } from './wrap-server';

describe('actionproxy-mcp doctor', () => {
  it('produces a static v1 configured-wrapper report without starting a child or resolving credentials', async () => {
    const configPath = writeConfig();
    const startClient = vi.fn();

    const report = await inspectConfiguredMcpWrapper(configPath, {
      env: { ACTIONPROXY_BASE_URL: 'http://127.0.0.1:9999' },
      startClient,
    });

    expect(startClient).not.toHaveBeenCalled();
    expect(report).toMatchObject({
      actionproxy: {
        baseUrl: 'http://127.0.0.1:9999',
        bearerTokenEnv: 'ACTIONPROXY_MCP_BEARER_TOKEN',
      },
      coverage: 'configured_mcp_wrapper',
      mode: 'static',
      ok: true,
      version: 'actionproxy.tool-plane-report.v1',
    });
    expect(report.servers).toEqual([
      expect.objectContaining({
        discovery: { status: 'unverified' },
        environment: { explicit: ['SAFE_CHILD_SETTING'], passthrough: ['NAMED_CHILD_SECRET'] },
        name: 'demo',
        transport: 'stdio',
      }),
    ]);
    expect(report.unverified.map(({ code }) => code)).toEqual([
      'agent_host_configuration',
      'host_native_provider_tools',
      'direct_network_shell_access',
      'unmediated_credentials',
      'conversation_identity',
      'server_policy',
      'prompt_injection_resistance',
      'downstream_discovery_not_run',
    ]);
    expect(JSON.stringify(report)).not.toContain('inline-safe-value');
  });

  it('discovers initialize plus one tools/list per server and always closes the client', async () => {
    const configPath = writeConfig();
    const client: DownstreamMcpClient = {
      callTool: vi.fn(),
      close: vi.fn(async () => undefined),
      listTools: vi.fn(async () => [{ name: 'docs.search' }, { name: 'gmail.send_email' }]),
    };
    const startClient = vi.fn(async () => client);

    const report = await inspectConfiguredMcpWrapper(configPath, {
      discover: true,
      env: {
        ACTIONPROXY_MCP_BEARER_TOKEN: 'test-must-not-be-forwarded',
        NAMED_CHILD_SECRET: 'child-only',
        PATH: process.env.PATH,
      },
      startClient,
    });

    expect(startClient).toHaveBeenCalledTimes(1);
    expect(startClient).toHaveBeenCalledWith(expect.any(Object), {
      forbiddenEnvironmentVariables: ['ACTIONPROXY_MCP_BEARER_TOKEN'],
      parentEnvironment: expect.any(Object),
    });
    expect(client.listTools).toHaveBeenCalledTimes(1);
    expect(client.callTool).not.toHaveBeenCalled();
    expect(client.close).toHaveBeenCalledTimes(1);
    expect(report.ok).toBe(true);
    expect(report.servers[0]?.discovery).toEqual({
      status: 'verified',
      toolCount: 2,
      tools: ['docs.search', 'gmail.send_email'],
    });
    expect(report.unverified.map(({ code }) => code)).toEqual([
      'agent_host_configuration',
      'host_native_provider_tools',
      'direct_network_shell_access',
      'unmediated_credentials',
      'conversation_identity',
      'server_policy',
      'prompt_injection_resistance',
    ]);
  });

  it('rejects duplicate and bounded-invalid discovered tool names without calling tools', async () => {
    for (const tools of [
      [{ name: 'docs.search' }, { name: 'docs.search' }],
      [{ name: `tool.${'x'.repeat(260)}` }],
      [{ inputSchema: 'not-an-object', name: 'docs.search' }],
      [{ inputSchema: { description: 'x'.repeat(300_000), type: 'object' }, name: 'docs.search' }],
      Array.from({ length: 5 }, (_, index) => ({ description: 'x'.repeat(220_000), name: `tool.${index}` })),
      Array.from({ length: 1001 }, (_, index) => ({ name: `tool.${index}` })),
    ]) {
      const client: DownstreamMcpClient = {
        callTool: vi.fn(),
        close: vi.fn(async () => undefined),
        listTools: vi.fn(async () => tools as unknown as McpTool[]),
      };
      const report = await inspectConfiguredMcpWrapper(writeConfig(), {
        discover: true,
        startClient: vi.fn(async () => client),
      });

      expect(report.ok).toBe(false);
      expect(client.callTool).not.toHaveBeenCalled();
      expect(client.close).toHaveBeenCalledTimes(1);
    }
  });

  it('keeps discovery failures static and marks the report incomplete', async () => {
    const report = await inspectConfiguredMcpWrapper(writeConfig(), {
      discover: true,
      startClient: vi.fn(async () => {
        throw new Error('attacker-controlled child diagnostic');
      }),
    });

    expect(report.ok).toBe(false);
    expect(report.servers[0]?.discovery).toEqual({ status: 'failed' });
    expect(report.unverified).toContainEqual(expect.objectContaining({
      code: 'downstream_discovery_failed',
      server: 'demo',
    }));
    expect(JSON.stringify(report)).not.toContain('attacker-controlled');
  });

  it('supports the documented static JSON CLI form', async () => {
    let stdout = '';
    let stderr = '';
    const exitCode = await runMcpWrapperCli(
      ['doctor', '--config', writeConfig(), '--json'],
      {
        stderr: { write: (chunk: string) => { stderr += chunk; return true; } },
        stdout: { write: (chunk: string) => { stdout += chunk; return true; } },
      },
    );

    expect(exitCode).toBe(0);
    expect(stderr).toBe('');
    expect(JSON.parse(stdout)).toMatchObject({
      coverage: 'configured_mcp_wrapper',
      mode: 'static',
      version: 'actionproxy.tool-plane-report.v1',
    });
  });

  it('discovers real child processes with initialize and tools/list but never tools/call', async () => {
    const fixture = writeRealProcessFixture();
    let stdout = '';
    let stderr = '';

    const exitCode = await runMcpWrapperCli(
      ['doctor', '--config', fixture.configPath, '--discover', '--json'],
      {
        stderr: { write: (chunk: string) => { stderr += chunk; return true; } },
        stdout: { write: (chunk: string) => { stdout += chunk; return true; } },
      },
    );

    expect(exitCode).toBe(0);
    expect(stderr).toBe('');
    const report = JSON.parse(stdout);
    expect(report).toMatchObject({ mode: 'discover', ok: true });
    expect(report.servers).toEqual([
      expect.objectContaining({
        discovery: { status: 'verified', toolCount: 1, tools: ['first.docs.search'] },
        name: 'first',
      }),
      expect.objectContaining({
        discovery: { status: 'verified', toolCount: 1, tools: ['second.docs.search'] },
        name: 'second',
      }),
    ]);
    for (const tracePath of fixture.tracePaths) {
      const trace = fs.readFileSync(tracePath, 'utf8').trim().split('\n');
      expect(trace).toEqual(['initialize', 'tools/list', 'close']);
      expect(trace).not.toContain('tools/call');
    }
  });
});

function writeConfig(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-doctor-'));
  const configPath = path.join(directory, 'actionproxy.mcp.yaml');
  fs.writeFileSync(configPath, `
actionproxy:
  baseUrl: http://127.0.0.1:8787
  bearerTokenEnv: ACTIONPROXY_MCP_BEARER_TOKEN
servers:
  demo:
    command: node
    args: [server.mjs]
    env:
      SAFE_CHILD_SETTING: inline-safe-value
    envPassthrough: [NAMED_CHILD_SECRET]
`, 'utf8');
  return configPath;
}

function writeRealProcessFixture(): { configPath: string; tracePaths: string[] } {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'actionproxy-mcp-doctor-process-'));
  const serverPath = path.join(directory, 'server.mjs');
  const tracePaths = [path.join(directory, 'first.trace'), path.join(directory, 'second.trace')];
  fs.writeFileSync(serverPath, `
import fs from 'node:fs';

let buffer = '';
const trace = (event) => fs.appendFileSync(process.env.TRACE_PATH, event + '\\n', 'utf8');
const send = (message) => process.stdout.write(JSON.stringify(message) + '\\n');

process.stdin.on('data', (chunk) => {
  buffer += chunk.toString('utf8');
  for (;;) {
    const lineEnd = buffer.indexOf('\\n');
    if (lineEnd === -1) return;
    const line = buffer.slice(0, lineEnd).trim();
    buffer = buffer.slice(lineEnd + 1);
    if (!line) continue;
    const message = JSON.parse(line);
    if (message.method === 'initialize') {
      trace('initialize');
      send({
        id: message.id,
        jsonrpc: '2.0',
        result: {
          capabilities: { tools: {} },
          protocolVersion: '2025-06-18',
          serverInfo: { name: process.env.TOOL_NAME, version: '0.0.0' },
        },
      });
    } else if (message.method === 'tools/list') {
      trace('tools/list');
      send({
        id: message.id,
        jsonrpc: '2.0',
        result: { tools: [{ name: process.env.TOOL_NAME }] },
      });
    } else if (message.method === 'tools/call') {
      trace('tools/call');
      send({ id: message.id, jsonrpc: '2.0', result: { content: [] } });
    }
  }
});

process.once('SIGTERM', () => {
  trace('close');
  process.exit(0);
});
`, 'utf8');

  const configPath = path.join(directory, 'actionproxy.mcp.yaml');
  fs.writeFileSync(configPath, `
actionproxy:
  baseUrl: http://127.0.0.1:8787
servers:
  first:
    command: ${JSON.stringify(process.execPath)}
    args: [${JSON.stringify(serverPath)}]
    stdioFraming: newline
    env:
      TOOL_NAME: first.docs.search
      TRACE_PATH: ${JSON.stringify(tracePaths[0])}
  second:
    command: ${JSON.stringify(process.execPath)}
    args: [${JSON.stringify(serverPath)}]
    stdioFraming: newline
    env:
      TOOL_NAME: second.docs.search
      TRACE_PATH: ${JSON.stringify(tracePaths[1])}
`, 'utf8');
  return { configPath, tracePaths };
}
