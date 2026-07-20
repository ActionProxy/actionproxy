import path from 'node:path';
import { loadMcpWrapperConfig, type McpServerConfig, type McpWrapperConfig } from './config';
import {
  MAX_MCP_TOOLS,
  StdioMcpClient,
  assertWrappedMcpToolListWithinLimit,
  validateDiscoveredMcpTools,
  type DownstreamMcpClient,
  type McpTool,
} from './wrap-server';

export const TOOL_PLANE_REPORT_VERSION = 'actionproxy.tool-plane-report.v1' as const;

export interface McpDoctorUnverifiedEntry {
  code:
    | 'agent_host_configuration'
    | 'conversation_identity'
    | 'direct_network_shell_access'
    | 'downstream_discovery_failed'
    | 'downstream_discovery_not_run'
    | 'host_native_provider_tools'
    | 'prompt_injection_resistance'
    | 'server_policy'
    | 'unmediated_credentials';
  message: string;
  server?: string;
}

export interface McpDoctorServerReport {
  argumentCount: number;
  command: string;
  cwd?: string;
  discovery:
    | { status: 'failed' }
    | { status: 'unverified' }
    | { status: 'verified'; toolCount: number; tools: string[] };
  environment: {
    explicit: string[];
    passthrough: string[];
  };
  name: string;
  stdioFraming: 'content-length' | 'newline';
  transport: 'stdio';
}

export interface ConfiguredMcpWrapperReportV1 {
  actionproxy: {
    baseUrl: string;
    bearerTokenEnv?: string;
  };
  configPath: string;
  coverage: 'configured_mcp_wrapper';
  mode: 'discover' | 'static';
  ok: boolean;
  servers: McpDoctorServerReport[];
  unverified: McpDoctorUnverifiedEntry[];
  version: typeof TOOL_PLANE_REPORT_VERSION;
}

export interface McpDoctorOptions {
  discover?: boolean;
  env?: Record<string, string | undefined>;
  startClient?: (
    config: McpServerConfig,
    options: {
      forbiddenEnvironmentVariables?: string[];
      parentEnvironment?: Record<string, string | undefined>;
    },
  ) => Promise<DownstreamMcpClient>;
}

export async function inspectConfiguredMcpWrapper(
  configPath: string,
  options: McpDoctorOptions = {},
): Promise<ConfiguredMcpWrapperReportV1> {
  const environment = options.env ?? process.env;
  const config = loadMcpWrapperConfig(configPath, environment);
  const resolvedConfigPath = path.resolve(configPath);
  const discover = options.discover ?? false;
  const unverified: McpDoctorUnverifiedEntry[] = [
    {
      code: 'agent_host_configuration',
      message: 'The agent-host configuration was not inspected; confirm the host has exactly one MCP entry: this wrapper.',
    },
    {
      code: 'host_native_provider_tools',
      message: 'Host-native and provider-hosted tools are outside configured MCP-wrapper coverage.',
    },
    {
      code: 'direct_network_shell_access',
      message: 'Direct network and shell access are outside configured MCP-wrapper coverage.',
    },
    {
      code: 'unmediated_credentials',
      message: 'Credentials available outside the wrapper were not inspected.',
    },
    {
      code: 'conversation_identity',
      message: 'A wrapper process or MCP transport session is not proof of conversation identity.',
    },
    {
      code: 'server_policy',
      message: 'ActionProxy reachability, authentication, active policy, approvals, execution, and audit were not verified.',
    },
    {
      code: 'prompt_injection_resistance',
      message: 'The doctor does not detect or prove resistance to prompt injection.',
    },
  ];
  const servers = configuredServerReports(config);

  if (!discover) {
    for (const server of servers) {
      unverified.push({
        code: 'downstream_discovery_not_run',
        message: 'Static mode did not start the downstream process or inspect its tools.',
        server: server.name,
      });
    }
  } else {
    const startClient = options.startClient ?? ((serverConfig, clientOptions) =>
      StdioMcpClient.start(serverConfig, clientOptions));
    const discoveredToolOwners = new Map<string, string>();
    const discoveredTools: McpTool[] = [];
    let discoveredToolCount = 0;
    for (const server of servers) {
      const configured = config.servers[server.name];
      if (!configured) continue;
      let client: DownstreamMcpClient | undefined;
      try {
        client = await startClient(configured, {
          forbiddenEnvironmentVariables: config.actionproxy.bearerTokenEnv
            ? [config.actionproxy.bearerTokenEnv]
            : [],
          parentEnvironment: environment,
        });
        const tools = validateDiscoveredMcpTools(await client.listTools());
        const toolNames = validatedToolNames(tools);
        discoveredToolCount += toolNames.length;
        if (discoveredToolCount > MAX_MCP_TOOLS) {
          throw new Error(`Configured servers exposed more than ${MAX_MCP_TOOLS} tools.`);
        }
        for (const toolName of toolNames) {
          const owner = discoveredToolOwners.get(toolName);
          if (owner) throw new Error(`Duplicate MCP tool name across ${owner} and ${server.name}.`);
          discoveredToolOwners.set(toolName, server.name);
        }
        assertWrappedMcpToolListWithinLimit([...discoveredTools, ...tools]);
        discoveredTools.push(...tools);
        server.discovery = {
          status: 'verified',
          toolCount: toolNames.length,
          tools: toolNames,
        };
      } catch {
        server.discovery = { status: 'failed' };
        unverified.push({
          code: 'downstream_discovery_failed',
          message: 'Downstream initialize or tools/list did not complete successfully.',
          server: server.name,
        });
      } finally {
        if (client) {
          try {
            await client.close();
          } catch {
            server.discovery = { status: 'failed' };
            if (!unverified.some((entry) =>
              entry.code === 'downstream_discovery_failed' && entry.server === server.name)) {
              unverified.push({
                code: 'downstream_discovery_failed',
                message: 'Downstream discovery completed, but the child process did not close cleanly.',
                server: server.name,
              });
            }
          }
        }
      }
    }
  }

  return {
    actionproxy: {
      baseUrl: config.actionproxy.baseUrl,
      bearerTokenEnv: config.actionproxy.bearerTokenEnv,
    },
    configPath: resolvedConfigPath,
    coverage: 'configured_mcp_wrapper',
    mode: discover ? 'discover' : 'static',
    ok: !servers.some((server) => server.discovery.status === 'failed'),
    servers,
    unverified,
    version: TOOL_PLANE_REPORT_VERSION,
  };
}

export function formatMcpDoctorReport(report: ConfiguredMcpWrapperReportV1): string {
  const lines = [
    'ActionProxy MCP tool-plane doctor',
    `Version: ${report.version}`,
    `Coverage: ${report.coverage}`,
    `Mode: ${report.mode}`,
    `Status: ${report.ok ? 'ok' : 'failed'}`,
    `Config: ${displayValue(report.configPath)}`,
    `ActionProxy: ${displayValue(report.actionproxy.baseUrl)}`,
    `Authentication: ${report.actionproxy.bearerTokenEnv
      ? `environment reference ${displayValue(report.actionproxy.bearerTokenEnv)}`
      : 'not configured'}`,
    'Servers:',
  ];

  for (const server of report.servers) {
    const discovery = server.discovery.status === 'verified'
      ? `verified (${server.discovery.toolCount} tools: ${server.discovery.tools.map(displayValue).join(', ') || 'none'})`
      : server.discovery.status;
    lines.push(`- ${displayValue(server.name)}: stdio/${server.stdioFraming}, discovery ${discovery}`);
  }

  lines.push('Unverified:');
  for (const entry of report.unverified) {
    lines.push(`- [${entry.code}]${entry.server ? ` ${displayValue(entry.server)}:` : ''} ${entry.message}`);
  }
  return `${lines.join('\n')}\n`;
}

function configuredServerReports(config: McpWrapperConfig): McpDoctorServerReport[] {
  return Object.entries(config.servers).map(([name, server]) => ({
    argumentCount: server.args?.length ?? 0,
    command: server.command,
    cwd: server.cwd,
    discovery: { status: 'unverified' },
    environment: {
      explicit: Object.keys(server.env ?? {}).sort(),
      passthrough: [...(server.envPassthrough ?? [])].sort(),
    },
    name,
    stdioFraming: server.stdioFraming ?? 'content-length',
    transport: 'stdio',
  }));
}

function validatedToolNames(tools: readonly McpTool[]): string[] {
  const names = new Set<string>();
  return tools.map((tool) => {
    if (names.has(tool.name)) throw new Error('Downstream tools/list contained a duplicate tool name.');
    names.add(tool.name);
    return tool.name;
  });
}

function displayValue(value: string): string {
  return JSON.stringify(value).slice(1, -1);
}
