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
    bearerTokenEnv?: string;
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
  const bearerTokenEnv = optionalEnvironmentVariableName(actionProxy.bearerTokenEnv);
  if (!isRecord(value.servers) || Object.keys(value.servers).length === 0) {
    throw new Error('MCP wrapper config requires at least one downstream server.');
  }

  const servers: Record<string, McpServerConfig> = {};
  for (const [name, server] of Object.entries(value.servers)) {
    if (!isRecord(server) || typeof server.command !== 'string' || !server.command.trim()) {
      throw new Error(`MCP server "${name}" requires a command.`);
    }

    const serverEnvironment = isStringRecord(server.env) ? server.env : undefined;
    const environmentPassthrough = environmentVariableNamesOrUndefined(
      server.envPassthrough,
      `servers.${name}.envPassthrough`,
    );
    servers[name] = {
      args: Array.isArray(server.args) ? server.args.map(String) : undefined,
      command: server.command,
      cwd: typeof server.cwd === 'string' ? server.cwd : undefined,
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
    const explicitNames = new Set(Object.keys(serverEnvironment ?? {}).map((key) => key.toLowerCase()));
    const duplicateName = environmentPassthrough?.find((key) => explicitNames.has(key.toLowerCase()));
    if (duplicateName) {
      throw new Error(`MCP server "${name}" environment variable ${duplicateName} cannot be both inline and passed through.`);
    }
  }

  return {
    actionproxy: {
      agentId: typeof actionProxy.agentId === 'string' ? actionProxy.agentId : undefined,
      approvalPollIntervalMs: numberOrUndefined(actionProxy.approvalPollIntervalMs),
      approvalTimeoutMs: numberOrUndefined(actionProxy.approvalTimeoutMs),
      baseUrl: actionProxy.baseUrl,
      bearerTokenEnv,
      requestedBy: typeof actionProxy.requestedBy === 'string' ? actionProxy.requestedBy : undefined,
      requestTimeoutMs: positiveIntegerOrUndefined(actionProxy.requestTimeoutMs, 'actionproxy.requestTimeoutMs'),
    },
    policies: isRecord(value.policies) ? parsePolicies(value.policies) : undefined,
    servers,
  };
}

function parsePolicies(value: Record<string, unknown>): McpWrapperConfig['policies'] {
  return Object.fromEntries(
    Object.entries(value)
      .filter((entry): entry is [string, { approval: 'never' | 'required' | 'deny' }] => {
        const policy = entry[1];
        return (
          isRecord(policy) &&
          (policy.approval === 'never' || policy.approval === 'required' || policy.approval === 'deny')
        );
      })
      .map(([toolName, policy]) => [toolName, { approval: policy.approval }]),
  );
}

function numberOrUndefined(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function positiveIntegerOrUndefined(value: unknown, path: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${path} must be a positive integer.`);
  }
  return value;
}

function optionalEnvironmentVariableName(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(value)) {
    throw new Error('actionproxy.bearerTokenEnv must be an environment variable name.');
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
