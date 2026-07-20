#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadMcpWrapperConfig } from './config';
import { formatMcpDoctorReport, inspectConfiguredMcpWrapper } from './doctor';
import { createWrapperFromConfig, runStdioServer } from './wrap-server';

export { loadMcpWrapperConfig } from './config';
export type { McpServerConfig, McpWrapperConfig } from './config';
export {
  TOOL_PLANE_REPORT_VERSION,
  formatMcpDoctorReport,
  inspectConfiguredMcpWrapper,
} from './doctor';
export type {
  ConfiguredMcpWrapperReportV1,
  McpDoctorOptions,
  McpDoctorServerReport,
  McpDoctorUnverifiedEntry,
} from './doctor';
export {
  ActionProxyMcpWrapper,
  MAX_MCP_TOOLS,
  HttpActionProxyGateway,
  JsonRpcFramer,
  McpJsonRpcServer,
  NewlineJsonRpcFramer,
  StdioMcpClient,
  assertWrappedMcpToolListWithinLimit,
  createWrapperFromConfig,
  encodeLineDelimitedJsonRpcMessage,
  encodeJsonRpcMessage,
  resultDeliveryForMcpResult,
  runStdioServer,
  validateDiscoveredMcpTools,
} from './wrap-server';
export type {
  ActionProxyGateway,
  ActionProxyGatewayRequestOptions,
  ActionProxyResultDelivery,
  ActionProxySubmitResponse,
  ActionProxyToolCall,
  DownstreamMcpClient,
  JsonObject,
  JsonRpcId,
  JsonRpcMessage,
  HttpActionProxyGatewayOptions,
  McpCallResult,
  McpTool,
} from './wrap-server';

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = await runMcpWrapperCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`actionproxy-mcp: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

export async function runMcpWrapperCli(
  args: string[],
  options: {
    env?: Record<string, string | undefined>;
    stderr?: Pick<NodeJS.WriteStream, 'write'>;
    stdout?: Pick<NodeJS.WriteStream, 'write'>;
  } = {},
): Promise<number> {
  const [command, ...rest] = args;
  const stderr = options.stderr ?? process.stderr;
  const stdout = options.stdout ?? process.stdout;
  const parsed = parseCommandArguments(rest, command === 'doctor');
  if ((command !== 'wrap' && command !== 'doctor') || !parsed) {
    stderr.write(usage());
    return 1;
  }

  if (command === 'doctor') {
    const report = await inspectConfiguredMcpWrapper(parsed.configPath, {
      discover: parsed.discover,
      env: options.env,
    });
    stdout.write(parsed.json ? `${JSON.stringify(report, null, 2)}\n` : formatMcpDoctorReport(report));
    return report.ok ? 0 : 1;
  }

  if (parsed.discover || parsed.json) {
    stderr.write(usage());
    return 1;
  }
  const environment = options.env ?? process.env;
  const config = loadMcpWrapperConfig(parsed.configPath, environment);
  const wrapper = await createWrapperFromConfig(config, { env: environment });
  await runStdioServer(wrapper);
  return 0;
}

function parseCommandArguments(
  args: string[],
  allowDoctorFlags: boolean,
): { configPath: string; discover: boolean; json: boolean } | undefined {
  let configPath: string | undefined;
  let discover = false;
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--config' && configPath === undefined) {
      const value = args[index + 1];
      if (!value || value.startsWith('--')) return undefined;
      configPath = value;
      index += 1;
      continue;
    }
    if (allowDoctorFlags && argument === '--discover' && !discover) {
      discover = true;
      continue;
    }
    if (allowDoctorFlags && argument === '--json' && !json) {
      json = true;
      continue;
    }
    return undefined;
  }
  return configPath ? { configPath, discover, json } : undefined;
}

function usage(): string {
  return [
    'Usage:',
    '  actionproxy-mcp wrap --config <path>',
    '  actionproxy-mcp doctor --config <path> [--discover] [--json]',
    '',
  ].join('\n');
}
