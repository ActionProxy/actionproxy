import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';

export type McpServerStdioFraming = 'content-length' | 'newline';

export interface McpServerConfig {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  envPassthrough?: string[];
  requestTimeoutMs?: number;
  stdioFraming?: McpServerStdioFraming;
}

export interface McpWrapperConfig {
  actionproxy: {
    baseUrl: string;
    agentId?: string;
    requestedBy?: string;
    approvalPollIntervalMs?: number;
    approvalTimeoutMs?: number;
    cancelPendingOnAbort?: boolean;
    bearerTokenEnv?: string;
    quickstartOriginTokenEnv?: string;
    requestTimeoutMs?: number;
  };
  servers: Record<string, McpServerConfig>;
  policies?: Record<string, { approval: 'never' | 'required' | 'deny' }>;
}

export function loadMcpWrapperConfig(
  configPath: string,
  env: Record<string, string | undefined> = process.env,
): McpWrapperConfig {
  const resolvedPath = path.resolve(configPath);
  const parsed = YAML.parse(fs.readFileSync(resolvedPath, 'utf8')) as unknown;
  const config = validateConfig(parsed);
  const baseUrl = env.ACTIONPROXY_BASE_URL ?? config.actionproxy.baseUrl;

  return {
    ...config,
    actionproxy: {
      ...config.actionproxy,
      baseUrl,
    },
    servers: Object.fromEntries(
      Object.entries(config.servers).map(([name, server]) => [
        name,
        {
          ...server,
          cwd: server.cwd ? path.resolve(path.dirname(resolvedPath), server.cwd) : path.dirname(resolvedPath),
        },
      ]),
    ),
  };
}

function validateConfig(value: unknown): McpWrapperConfig {
  if (!isRecord(value)) throw new Error('MCP wrapper config must be an object.');
  const actionProxy = isRecord(value.actionproxy) ? value.actionproxy : undefined;
  if (!actionProxy) throw new Error('MCP wrapper config requires actionproxy settings.');
  if (typeof actionProxy.baseUrl !== 'string' || !actionProxy.baseUrl.trim()) {
    throw new Error('MCP wrapper config requires actionproxy.baseUrl.');
  }
  for (const forbidden of ['apiKey', 'bearerToken', 'token']) {
    if (actionProxy[forbidden] !== undefined) {
      throw new Error(`MCP wrapper config must reference credentials with actionproxy.bearerTokenEnv, not actionproxy.${forbidden}.`);
    }
  }
  if (actionProxy.quickstartOriginToken !== undefined) {
    throw new Error(
      'MCP wrapper config must reference Quickstart provenance with actionproxy.quickstartOriginTokenEnv, not actionproxy.quickstartOriginToken.',
    );
  }
  const bearerTokenEnv = optionalEnvironmentVariableName(actionProxy.bearerTokenEnv, 'actionproxy.bearerTokenEnv');
  const quickstartOriginTokenEnv = optionalEnvironmentVariableName(actionProxy.quickstartOriginTokenEnv, 'actionproxy.quickstartOriginTokenEnv');
  if (!isRecord(value.servers) || Object.keys(value.servers).length === 0) {
    throw new Error('MCP wrapper config requires at least one downstream server.');
  }

  const servers: Record<string, McpServerConfig> = {};
  for (const [name, server] of Object.entries(value.servers)) {
    if (!isRecord(server) || typeof server.command !== 'string' || !server.command.trim()) {
      throw new Error(`MCP server "${name}" requires a command.`);
    }

    const serverEnvironment = optionalStringRecord(server.env, `servers.${name}.env`);
    const environmentPassthrough = environmentVariableNamesOrUndefined(server.envPassthrough, `servers.${name}.envPassthrough`);
    servers[name] = {
      args: optionalStringArray(server.args, `servers.${name}.args`),
      command: server.command,
      cwd: optionalString(server.cwd, `servers.${name}.cwd`),
      env: serverEnvironment,
      envPassthrough: environmentPassthrough,
      requestTimeoutMs: positiveIntegerOrUndefined(server.requestTimeoutMs, `servers.${name}.requestTimeoutMs`),
      stdioFraming: parseStdioFraming(name, server.stdioFraming),
    };
    if (bearerTokenEnv && Object.keys(serverEnvironment ?? {}).some((key) => sameEnvironmentName(key, bearerTokenEnv))) {
      throw new Error(`MCP server "${name}" must not receive the ActionProxy bearer environment variable ${bearerTokenEnv}.`);
    }
    if (bearerTokenEnv && environmentPassthrough?.some((key) => sameEnvironmentName(key, bearerTokenEnv))) {
      throw new Error(`MCP server "${name}" must not pass through the ActionProxy bearer environment variable ${bearerTokenEnv}.`);
    }
    if (
      quickstartOriginTokenEnv &&
      (Object.keys(serverEnvironment ?? {}).some((key) => sameEnvironmentName(key, quickstartOriginTokenEnv)) ||
        environmentPassthrough?.some((key) => sameEnvironmentName(key, quickstartOriginTokenEnv)))
    ) {
      throw new Error(`MCP server "${name}" must not receive the Quickstart origin environment variable ${quickstartOriginTokenEnv}.`);
    }
    const explicitNames = new Set(Object.keys(serverEnvironment ?? {}).map((key) => key.toLowerCase()));
    const duplicateName = environmentPassthrough?.find((key) => explicitNames.has(key.toLowerCase()));
    if (duplicateName) {
      throw new Error(`MCP server "${name}" environment variable ${duplicateName} cannot be both inline and passed through.`);
    }
  }

  return {
    actionproxy: {
      agentId: optionalString(actionProxy.agentId, 'actionproxy.agentId'),
      approvalPollIntervalMs: numberOrUndefined(actionProxy.approvalPollIntervalMs, 'actionproxy.approvalPollIntervalMs'),
      approvalTimeoutMs: numberOrUndefined(actionProxy.approvalTimeoutMs, 'actionproxy.approvalTimeoutMs'),
      baseUrl: actionProxy.baseUrl,
      bearerTokenEnv,
      cancelPendingOnAbort: optionalBoolean(actionProxy.cancelPendingOnAbort, 'actionproxy.cancelPendingOnAbort'),
      quickstartOriginTokenEnv,
      requestedBy: optionalString(actionProxy.requestedBy, 'actionproxy.requestedBy'),
      requestTimeoutMs: positiveIntegerOrUndefined(actionProxy.requestTimeoutMs, 'actionproxy.requestTimeoutMs'),
    },
    policies: optionalPolicies(value.policies),
    servers,
  };
}

function optionalPolicies(value: unknown): McpWrapperConfig['policies'] {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new Error('policies must be an object.');

  return Object.fromEntries(
    Object.entries(value).map(([toolName, policy]) => {
      if (!isRecord(policy) || (policy.approval !== 'never' && policy.approval !== 'required' && policy.approval !== 'deny')) {
        throw new Error(`policies.${toolName}.approval must be "never", "required", or "deny".`);
      }
      return [toolName, { approval: policy.approval }];
    }),
  );
}

function numberOrUndefined(value: unknown, path: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${path} must be a finite number.`);
  }
  return value;
}

function optionalString(value: unknown, path: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new Error(`${path} must be a string.`);
  return value;
}

function optionalStringArray(value: unknown, path: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`${path} must contain only strings.`);
  }
  return value;
}

function optionalStringRecord(value: unknown, path: string): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  if (!isStringRecord(value)) throw new Error(`${path} must contain only string values.`);
  return value;
}

function positiveIntegerOrUndefined(value: unknown, path: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${path} must be a positive integer.`);
  }
  return value;
}

function optionalBoolean(value: unknown, path: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new Error(`${path} must be a boolean.`);
  return value;
}

function optionalEnvironmentVariableName(value: unknown, path = 'actionproxy.bearerTokenEnv'): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(value)) {
    throw new Error(`${path} must be an environment variable name.`);
  }
  return value;
}

function environmentVariableNamesOrUndefined(value: unknown, path: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(entry))) {
    throw new Error(`${path} must contain only environment variable names.`);
  }
  const names = value as string[];
  const unique = new Map(names.map((name) => [name.toLowerCase(), name]));
  if (unique.size !== names.length) throw new Error(`${path} must not contain duplicate names.`);
  return [...unique.values()];
}

function sameEnvironmentName(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function parseStdioFraming(name: string, value: unknown): McpServerStdioFraming | undefined {
  if (value === undefined) return undefined;
  if (value === 'content-length' || value === 'newline') return value;
  throw new Error(`MCP server "${name}" stdioFraming must be "content-length" or "newline".`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return isRecord(value) && Object.values(value).every((entry) => typeof entry === 'string');
}
