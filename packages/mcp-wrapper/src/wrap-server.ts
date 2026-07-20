import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import type { Readable, Writable } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
import type { McpServerConfig, McpServerStdioFraming, McpWrapperConfig } from './config';

const DEFAULT_ACTIONPROXY_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_DOWNSTREAM_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_FRAME_BYTES = 1024 * 1024;
const DEFAULT_MAX_FRAME_HEADER_BYTES = 8 * 1024;
const DEFAULT_MAX_HTTP_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_MAX_MCP_RESULT_BYTES = 1024 * 1024;
const DEFAULT_MAX_MCP_SCHEMA_BYTES = 256 * 1024;
const DEFAULT_MAX_MCP_TOOL_LIST_BYTES = 1024 * 1024;
export const MAX_MCP_TOOLS = 1000;
const DEFAULT_CHILD_SHUTDOWN_TIMEOUT_MS = 1000;

export type JsonObject = Record<string, unknown>;
export type JsonRpcId = string | number;

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: JsonObject;
}

export interface McpCallResult {
  content: Array<{ type: 'text'; text: string } | JsonObject>;
  isError?: boolean;
  [key: string]: unknown;
}

export interface ActionProxyResultDelivery {
  byteCount: number;
  canonicalResultHash: string;
  modelVisible: true;
  version: 'actionproxy.result-delivery.v1';
}

export interface DownstreamMcpClient {
  close(): Promise<void>;
  callTool(name: string, args: JsonObject, options?: { signal?: AbortSignal }): Promise<McpCallResult>;
  listTools(): Promise<McpTool[]>;
}

export interface ActionProxyGatewayRequestOptions {
  idempotencyKey?: string;
  signal?: AbortSignal;
}

export interface HttpActionProxyGatewayOptions {
  bearerToken?: string;
  maxResponseBytes?: number;
  requestTimeoutMs?: number;
  sessionId?: string;
}

export interface ActionProxySubmitResponse {
  id: string;
  status: 'submitted' | 'authorized' | 'executed' | 'pending_approval' | 'blocked' | 'rejected' | 'failed';
  decision?: 'allow' | 'require_approval' | 'deny';
  reason?: string;
  risk?: string;
  result?: unknown;
  error?: string;
  approval?: {
    id: string;
    status: 'pending' | 'approved' | 'rejected';
  };
  toolCall: ActionProxyToolCall;
}

export interface ActionProxyToolCall {
  id: string;
  status: ActionProxySubmitResponse['status'];
  decision?: ActionProxySubmitResponse['decision'];
  input?: JsonObject;
  policyVersionHash?: string;
  result?: unknown;
  error?: string;
}

export interface ActionProxyGateway {
  consumeExecutionGrant(
    grantId: string,
    input: {
      input: JsonObject;
      policyVersionHash?: string;
      toolCallId: string;
      toolName: string;
    },
    options?: ActionProxyGatewayRequestOptions,
  ): Promise<unknown>;
  reportExecutionGrantOutcome(
    grantId: string,
    input:
      | {
          error?: string;
          result?: JsonObject;
          resultDelivery?: ActionProxyResultDelivery;
          status: 'cancelled' | 'failed' | 'timed_out' | 'unknown_outcome';
        }
      | {
          result?: JsonObject;
          resultDelivery?: ActionProxyResultDelivery;
          status: 'succeeded';
        },
    options?: ActionProxyGatewayRequestOptions,
  ): Promise<unknown>;
  submitToolCall(input: {
    action?: JsonObject;
    agentId: string;
    input: JsonObject;
    metadata?: JsonObject;
    reason: string;
    requestedBy: string;
    toolName: string;
  }, options?: ActionProxyGatewayRequestOptions): Promise<ActionProxySubmitResponse>;
  waitForToolCall(
    id: string,
    options: { intervalMs: number; signal?: AbortSignal; timeoutMs: number },
  ): Promise<ActionProxyToolCall>;
}

interface ToolRoute {
  downstream: DownstreamMcpClient;
  serverName: string;
  tool: McpTool;
}

export class HttpActionProxyGateway implements ActionProxyGateway {
  private readonly baseUrl: string;
  private readonly sessionId: string;

  constructor(
    baseUrl: string,
    private readonly fetchFn = fetch,
    private readonly options: HttpActionProxyGatewayOptions = {},
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.sessionId = options.sessionId ?? randomUUID();
    if (!isUuid(this.sessionId)) {
      throw new Error('ActionProxy MCP session id must be a UUID.');
    }
  }

  async submitToolCall(
    input: Parameters<ActionProxyGateway['submitToolCall']>[0],
    options: ActionProxyGatewayRequestOptions = {},
  ): Promise<ActionProxySubmitResponse> {
    return this.request('/v1/mcp/tool-calls', {
      body: input,
      idempotencyKey: options.idempotencyKey,
      method: 'POST',
      signal: options.signal,
    });
  }

  async consumeExecutionGrant(
    grantId: string,
    input: Parameters<ActionProxyGateway['consumeExecutionGrant']>[1],
    options: ActionProxyGatewayRequestOptions = {},
  ): Promise<unknown> {
    return this.request(`/v1/execution-grants/${encodeURIComponent(grantId)}/consume`, {
      body: input,
      method: 'POST',
      signal: options.signal,
    });
  }

  async reportExecutionGrantOutcome(
    grantId: string,
    input: Parameters<ActionProxyGateway['reportExecutionGrantOutcome']>[1],
    options: ActionProxyGatewayRequestOptions = {},
  ): Promise<unknown> {
    return this.request(`/v1/execution-grants/${encodeURIComponent(grantId)}/outcome`, {
      body: input,
      method: 'POST',
      signal: options.signal,
    });
  }

  async waitForToolCall(
    id: string,
    options: { intervalMs: number; signal?: AbortSignal; timeoutMs: number },
  ): Promise<ActionProxyToolCall> {
    const startedAt = Date.now();

    while (true) {
      throwIfAborted(options.signal);
      const toolCall = await this.request<ActionProxyToolCall>(`/v1/mcp/tool-calls/${encodeURIComponent(id)}`, {
        signal: options.signal,
      });
      if (toolCall.status !== 'pending_approval' && toolCall.status !== 'submitted') return toolCall;

      if (Date.now() - startedAt >= options.timeoutMs) {
        throw new Error(`Timed out waiting for ActionProxy approval for tool call ${id}.`);
      }

      await delay(options.intervalMs, options.signal);
    }
  }

  private async request<T>(
    path: string,
    init: {
      body?: unknown;
      idempotencyKey?: string;
      method?: 'GET' | 'POST';
      signal?: AbortSignal;
    } = {},
  ): Promise<T> {
    const timeoutMs = this.options.requestTimeoutMs ?? DEFAULT_ACTIONPROXY_REQUEST_TIMEOUT_MS;
    const controller = new AbortController();
    let timedOut = false;
    const abortFromCaller = () => controller.abort(init.signal?.reason);
    if (init.signal?.aborted) abortFromCaller();
    else init.signal?.addEventListener('abort', abortFromCaller, { once: true });
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);

    let response: Response;
    try {
      response = await this.fetchFn(`${this.baseUrl}${path}`, {
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
        headers: {
          'content-type': 'application/json',
          ...(this.options.bearerToken ? { authorization: `Bearer ${this.options.bearerToken}` } : {}),
          ...(init.idempotencyKey ? { 'idempotency-key': init.idempotencyKey } : {}),
          'X-ActionProxy-MCP-Session-Id': this.sessionId,
        },
        method: init.method ?? 'GET',
        signal: controller.signal,
      });
    } catch (error) {
      clearTimeout(timeout);
      init.signal?.removeEventListener('abort', abortFromCaller);
      if (timedOut) throw new ActionProxyRequestTimeoutError(`ActionProxy request timed out after ${timeoutMs}ms.`);
      if (init.signal?.aborted) throw new McpRequestCancelledError('MCP request was cancelled.');
      throw error;
    }

    let text: string;
    try {
      text = await readResponseTextBounded(
        response,
        this.options.maxResponseBytes ?? DEFAULT_MAX_HTTP_RESPONSE_BYTES,
      );
    } catch (error) {
      if (timedOut) throw new ActionProxyRequestTimeoutError(`ActionProxy request timed out after ${timeoutMs}ms.`);
      if (init.signal?.aborted) throw new McpRequestCancelledError('MCP request was cancelled.');
      throw error;
    } finally {
      clearTimeout(timeout);
      init.signal?.removeEventListener('abort', abortFromCaller);
    }
    let body: unknown;
    try {
      body = text ? JSON.parse(text) : undefined;
    } catch {
      throw new Error(`ActionProxy returned invalid JSON with HTTP ${response.status}.`);
    }

    if (!response.ok) {
      throw new Error(`ActionProxy request failed: ${response.status} ${text}`);
    }

    return body as T;
  }
}

export class ActionProxyMcpWrapper {
  private directCallId = 0;
  private readonly directSessionNonce = randomUUID();
  private readonly routes = new Map<string, ToolRoute>();

  constructor(
    private readonly config: McpWrapperConfig,
    private readonly downstreams: Record<string, DownstreamMcpClient>,
    private readonly actionProxy: ActionProxyGateway,
  ) {}

  async initialize(): Promise<void> {
    let toolCount = 0;
    for (const [serverName, downstream] of Object.entries(this.downstreams)) {
      const tools = validateDiscoveredMcpTools(await downstream.listTools());
      toolCount += tools.length;
      if (toolCount > MAX_MCP_TOOLS) {
        throw new McpOutputLimitError(`Downstream MCP servers exposed more than ${MAX_MCP_TOOLS} tools.`);
      }
      for (const tool of tools) {
        if (this.routes.has(tool.name)) {
          throw new Error(`Duplicate MCP tool name "${tool.name}". Rename or split downstream servers.`);
        }
        this.routes.set(tool.name, { downstream, serverName, tool });
      }
    }
    assertWrappedMcpToolListWithinLimit([...this.routes.values()].map((route) => route.tool));
  }

  listTools(): McpTool[] {
    return [...this.routes.values()].map((route) => ({
      ...route.tool,
      description: route.tool.description
        ? `${route.tool.description}\n\nWrapped by ActionProxy.`
        : 'Wrapped by ActionProxy.',
    }));
  }

  async callTool(
    name: string,
    args: JsonObject,
    options: ActionProxyGatewayRequestOptions = {},
  ): Promise<McpCallResult> {
    const route = this.routes.get(name);
    if (!route) return errorResult(`Unknown MCP tool: ${name}`);
    throwIfAborted(options.signal);
    assertJsonWithinLimit(args, DEFAULT_MAX_FRAME_BYTES, 'MCP tool arguments');
    const idempotencyKey = options.idempotencyKey ?? mcpIdempotencyKey(
      this.directSessionNonce,
      `direct-${this.directCallId++}`,
    );
    const submitted = await this.actionProxy.submitToolCall(
      {
        action: {
          executionMode: 'external_grant',
          operation: { name, kind: operationKindFromToolName(name) },
          protocol: 'mcp',
          resources: [{ name, type: 'mcp.tool' }],
          source: { name: route.serverName, type: 'mcp_server' },
        },
        agentId: this.config.actionproxy.agentId ?? 'actionproxy-mcp-wrapper',
        input: args,
        metadata: {
          actionproxyExecution: 'external',
          source: 'mcp-wrapper',
          mcpServer: route.serverName,
          mcpTool: name,
        },
        reason: `MCP tool call ${name} from server ${route.serverName}`,
        requestedBy: this.config.actionproxy.requestedBy ?? 'mcp-host',
        toolName: name,
      },
      { idempotencyKey, signal: options.signal },
    );
    const finalToolCall =
      submitted.status === 'pending_approval'
        ? await this.actionProxy.waitForToolCall(submitted.id, {
            intervalMs: this.config.actionproxy.approvalPollIntervalMs ?? 1000,
            signal: options.signal,
            timeoutMs: this.config.actionproxy.approvalTimeoutMs ?? 120_000,
          })
        : submitted.toolCall;

    if (finalToolCall.status !== 'authorized' && finalToolCall.status !== 'executed') {
      return errorResult(formatDeniedResult(finalToolCall));
    }

    const executionInput = finalToolCall.input ?? args;
    const grant = executionGrantFromResult(finalToolCall.result);
    if (!grant) {
      return errorResult('ActionProxy authorized external execution without an execution grant; downstream call was not forwarded.');
    }

    try {
      const consumeInput = {
        input: executionInput,
        policyVersionHash: finalToolCall.policyVersionHash ?? grant.policyVersionHash,
        toolCallId: finalToolCall.id,
        toolName: name,
      };
      if (options.signal) {
        await this.actionProxy.consumeExecutionGrant(grant.id, consumeInput, { signal: options.signal });
      } else {
        await this.actionProxy.consumeExecutionGrant(grant.id, consumeInput);
      }
    } catch (error) {
      const message = errorMessage(error);
      if (error instanceof ActionProxyRequestTimeoutError || error instanceof McpRequestCancelledError) {
        try {
          await this.actionProxy.reportExecutionGrantOutcome(grant.id, {
            error: message,
            status: error instanceof ActionProxyRequestTimeoutError ? 'timed_out' : 'unknown_outcome',
          });
        } catch {
          // The grant may not have reached the dispatched state. Never retry consumption or downstream dispatch.
        }
      }
      return errorResult(`ActionProxy execution grant could not be consumed: ${message}`);
    }

    if (options.signal?.aborted) {
      try {
        await this.actionProxy.reportExecutionGrantOutcome(grant.id, {
          error: 'MCP request was cancelled before downstream dispatch.',
          status: 'cancelled',
        });
      } catch (error) {
        return errorResult(`MCP request was cancelled and ActionProxy outcome reporting failed: ${errorMessage(error)}`);
      }
      return errorResult('MCP request was cancelled before downstream dispatch.');
    }

    let downstreamResult: McpCallResult;
    try {
      downstreamResult = options.signal
        ? await route.downstream.callTool(name, executionInput, { signal: options.signal })
        : await route.downstream.callTool(name, executionInput);
      validateMcpCallResult(downstreamResult);
      downstreamResult = normalizeMcpCallResult(downstreamResult);
    } catch (error) {
      const status = error instanceof McpRequestTimeoutError ? 'timed_out' : 'unknown_outcome';
      const recordedError = status === 'timed_out'
        ? 'Downstream MCP transport timed out after dispatch.'
        : 'Downstream MCP transport failed after dispatch.';
      try {
        await this.actionProxy.reportExecutionGrantOutcome(grant.id, { error: recordedError, status });
      } catch {
        return errorResult(DOWNSTREAM_OUTCOME_REPORTING_FAILURE_MESSAGE);
      }
      return errorResult(
        status === 'timed_out' ? DOWNSTREAM_TIMEOUT_MESSAGE : DOWNSTREAM_UNKNOWN_OUTCOME_MESSAGE,
      );
    }

    const resultDelivery = resultDeliveryForMcpResult(downstreamResult);
    try {
      if (downstreamResult.isError) {
        await this.actionProxy.reportExecutionGrantOutcome(grant.id, {
          error: textFromMcpResult(downstreamResult) ?? 'Downstream MCP tool returned an error result.',
          result: downstreamResult,
          resultDelivery,
          status: 'failed',
        });
      } else {
        await this.actionProxy.reportExecutionGrantOutcome(grant.id, {
          result: downstreamResult,
          resultDelivery,
          status: 'succeeded',
        });
      }
    } catch {
      return errorResult(DOWNSTREAM_OUTCOME_REPORTING_FAILURE_MESSAGE);
    }

    return downstreamResult;
  }

  async close(): Promise<void> {
    await Promise.all(Object.values(this.downstreams).map((downstream) => downstream.close()));
  }
}

export async function createWrapperFromConfig(
  config: McpWrapperConfig,
  options: { env?: Record<string, string | undefined>; fetchFn?: typeof fetch } = {},
): Promise<ActionProxyMcpWrapper> {
  const environment = options.env ?? process.env;
  const bearerToken = resolveBearerToken(config.actionproxy.bearerTokenEnv, environment);
  const downstreams: Record<string, DownstreamMcpClient> = {};
  try {
    for (const [name, serverConfig] of Object.entries(config.servers)) {
      downstreams[name] = await StdioMcpClient.start(serverConfig, {
        forbiddenEnvironmentVariables: config.actionproxy.bearerTokenEnv ? [config.actionproxy.bearerTokenEnv] : [],
        parentEnvironment: environment,
      });
    }
  } catch (error) {
    await Promise.allSettled(Object.values(downstreams).map((downstream) => downstream.close()));
    throw error;
  }
  const wrapper = new ActionProxyMcpWrapper(
    config,
    downstreams,
    new HttpActionProxyGateway(config.actionproxy.baseUrl, options.fetchFn ?? fetch, {
      bearerToken,
      requestTimeoutMs: config.actionproxy.requestTimeoutMs,
    }),
  );
  try {
    await wrapper.initialize();
  } catch (error) {
    await wrapper.close();
    throw error;
  }
  return wrapper;
}

export class StdioMcpClient implements DownstreamMcpClient {
  private constructor(
    private readonly process: ChildProcessWithoutNullStreams,
    private readonly peer: JsonRpcPeer,
    private readonly requestTimeoutMs: number,
  ) {}

  static async start(
    config: McpServerConfig,
    options: {
      forbiddenEnvironmentVariables?: string[];
      parentEnvironment?: Record<string, string | undefined>;
    } = {},
  ): Promise<StdioMcpClient> {
    const child = spawn(config.command, config.args ?? [], {
      cwd: config.cwd,
      env: leastPrivilegeChildEnvironment(
        options.parentEnvironment ?? process.env,
        config.env,
        config.envPassthrough,
        options.forbiddenEnvironmentVariables ?? [],
      ),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    // Drain without forwarding untrusted child output or credentials to ordinary logs.
    child.stderr.resume();

    const peer = new JsonRpcPeer(
      child.stdout,
      child.stdin,
      config.stdioFraming ?? 'content-length',
      () => child.kill('SIGTERM'),
    );
    child.once('error', (error) => peer.fail(new McpTransportError(`Downstream MCP process failed: ${error.message}`)));
    child.once('exit', (code, signal) => {
      peer.fail(new McpTransportError(`Downstream MCP process exited before completing pending requests (${formatExit(code, signal)}).`));
    });
    peer.start();
    try {
      await peer.request('initialize', {
        capabilities: {},
        clientInfo: { name: 'actionproxy-mcp-wrapper', version: '0.1.0' },
        protocolVersion: '2025-06-18',
      }, { timeoutMs: config.requestTimeoutMs ?? DEFAULT_DOWNSTREAM_REQUEST_TIMEOUT_MS });
      peer.notify('notifications/initialized', {});
    } catch (error) {
      peer.fail(new McpTransportError('Downstream MCP initialization failed.'));
      child.kill('SIGTERM');
      await waitForChildExit(child, DEFAULT_CHILD_SHUTDOWN_TIMEOUT_MS);
      throw error;
    }

    return new StdioMcpClient(child, peer, config.requestTimeoutMs ?? DEFAULT_DOWNSTREAM_REQUEST_TIMEOUT_MS);
  }

  async listTools(): Promise<McpTool[]> {
    const response = await this.peer.request<{ tools?: McpTool[] }>(
      'tools/list',
      {},
      { timeoutMs: this.requestTimeoutMs },
    );
    if (!isRecord(response)) {
      throw new McpOutputLimitError('Downstream MCP server returned an invalid tools response.');
    }
    if (response.tools !== undefined && !Array.isArray(response.tools)) {
      throw new McpOutputLimitError('Downstream MCP server returned an invalid tools list.');
    }
    return (response.tools as McpTool[] | undefined) ?? [];
  }

  async callTool(name: string, args: JsonObject, options: { signal?: AbortSignal } = {}): Promise<McpCallResult> {
    const result = await this.peer.request<McpCallResult>(
      'tools/call',
      { arguments: args, name },
      { signal: options.signal, timeoutMs: this.requestTimeoutMs },
    );
    validateMcpCallResult(result);
    return result;
  }

  async close(): Promise<void> {
    this.peer.fail(new McpTransportError('Downstream MCP client closed.'));
    if (this.process.exitCode !== null || this.process.signalCode !== null) return;
    this.process.kill('SIGTERM');
    const exited = await waitForChildExit(this.process, DEFAULT_CHILD_SHUTDOWN_TIMEOUT_MS);
    if (exited || this.process.exitCode !== null || this.process.signalCode !== null) return;
    this.process.kill('SIGKILL');
    await waitForChildExit(this.process, DEFAULT_CHILD_SHUTDOWN_TIMEOUT_MS);
  }
}

export class McpJsonRpcServer {
  private readonly activeCalls = new Map<string, AbortController>();

  constructor(
    private readonly wrapper: ActionProxyMcpWrapper,
    private readonly sessionNonce: string = randomUUID(),
  ) {}

  async handle(message: JsonRpcMessage): Promise<JsonRpcMessage | undefined> {
    if (!isRequest(message)) return undefined;
    if (message.method === 'notifications/cancelled') {
      const params = isRecord(message.params) ? message.params : {};
      const requestId = jsonRpcId(params.requestId);
      if (requestId !== undefined) this.activeCalls.get(typedJsonRpcId(requestId))?.abort();
      return undefined;
    }
    if (message.method.startsWith('notifications/')) return undefined;

    try {
      if (message.method === 'initialize') {
        return response(message.id, {
          capabilities: { tools: {} },
          protocolVersion: '2025-06-18',
          serverInfo: { name: 'actionproxy-mcp-wrapper', version: '0.1.0' },
        });
      }

      if (message.method === 'ping') {
        return response(message.id, {});
      }

      if (message.method === 'tools/list') {
        return response(message.id, { tools: this.wrapper.listTools() });
      }

      if (message.method === 'tools/call') {
        if (message.id === undefined || message.id === null) return undefined;
        const params = isRecord(message.params) ? message.params : {};
        const name = typeof params.name === 'string' ? params.name : '';
        const args = isRecord(params.arguments) ? params.arguments : {};
        const callKey = typedJsonRpcId(message.id);
        const controller = new AbortController();
        const previous = this.activeCalls.get(callKey);
        if (previous) {
          return rpcError(message.id, -32600, 'A request with this JSON-RPC id is already in flight.');
        }
        this.activeCalls.set(callKey, controller);
        try {
          return response(message.id, await this.wrapper.callTool(name, args, {
            idempotencyKey: mcpIdempotencyKey(this.sessionNonce, message.id),
            signal: controller.signal,
          }));
        } finally {
          this.activeCalls.delete(callKey);
        }
      }

      return rpcError(message.id, -32601, `Method not found: ${message.method}`);
    } catch (error) {
      return rpcError(message.id, -32000, error instanceof Error ? error.message : String(error));
    }
  }
}

export async function runStdioServer(wrapper: ActionProxyMcpWrapper): Promise<void> {
  const server = new McpJsonRpcServer(wrapper);
  const framer = new JsonRpcFramer();
  let failed = false;

  process.stdin.on('data', (chunk) => {
    if (failed) return;
    let messages: JsonRpcMessage[];
    try {
      messages = framer.push(Buffer.from(chunk));
    } catch {
      failed = true;
      process.stdin.pause();
      process.stdout.write(encodeJsonRpcMessage(rpcError(null, -32700, 'Invalid or oversized JSON-RPC frame.')));
      return;
    }
    for (const message of messages) {
      void server.handle(message).then((result) => {
        if (result) process.stdout.write(encodeJsonRpcMessage(result));
      }).catch(() => {
        process.stdout.write(encodeJsonRpcMessage(rpcError(message.id, -32000, 'MCP request failed.')));
      });
    }
  });

  const shutdown = async () => {
    await wrapper.close();
    process.exit(0);
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

export interface JsonRpcMessage {
  error?: unknown;
  id?: JsonRpcId | null;
  jsonrpc: '2.0';
  method?: string;
  params?: unknown;
  result?: unknown;
}

export class JsonRpcFramer {
  private buffer = Buffer.alloc(0);

  constructor(
    private readonly maxFrameBytes = DEFAULT_MAX_FRAME_BYTES,
    private readonly maxHeaderBytes = DEFAULT_MAX_FRAME_HEADER_BYTES,
  ) {}

  push(chunk: Buffer): JsonRpcMessage[] {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const messages: JsonRpcMessage[] = [];

    while (true) {
      const headerEnd = this.buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (this.buffer.byteLength > this.maxHeaderBytes) {
          throw new McpFrameLimitError(`MCP frame header exceeds ${this.maxHeaderBytes} bytes.`);
        }
        return messages;
      }
      if (headerEnd > this.maxHeaderBytes) {
        throw new McpFrameLimitError(`MCP frame header exceeds ${this.maxHeaderBytes} bytes.`);
      }

      const header = this.buffer.subarray(0, headerEnd).toString('utf8');
      const matches = [...header.matchAll(/^content-length:\s*(\d+)\s*$/gimu)];
      if (matches.length !== 1) throw new Error('Invalid JSON-RPC frame: exactly one Content-Length is required.');

      const length = Number(matches[0]?.[1]);
      if (!Number.isSafeInteger(length) || length < 0) throw new Error('Invalid JSON-RPC frame: invalid Content-Length.');
      if (length > this.maxFrameBytes) {
        throw new McpFrameLimitError(`MCP frame exceeds ${this.maxFrameBytes} bytes.`);
      }
      const bodyStart = headerEnd + 4;
      const bodyEnd = bodyStart + length;
      if (this.buffer.length < bodyEnd) return messages;

      const body = this.buffer.subarray(bodyStart, bodyEnd).toString('utf8');
      messages.push(JSON.parse(body) as JsonRpcMessage);
      this.buffer = this.buffer.subarray(bodyEnd);
    }
  }
}

export function encodeJsonRpcMessage(message: JsonRpcMessage): string {
  const body = JSON.stringify(message);
  return `Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`;
}

export class NewlineJsonRpcFramer {
  private buffer = '';
  private readonly decoder = new StringDecoder('utf8');

  constructor(private readonly maxFrameBytes = DEFAULT_MAX_FRAME_BYTES) {}

  push(chunk: Buffer): JsonRpcMessage[] {
    this.buffer += this.decoder.write(chunk);
    const messages: JsonRpcMessage[] = [];

    while (true) {
      const lineEnd = this.buffer.indexOf('\n');
      if (lineEnd === -1) {
        if (Buffer.byteLength(this.buffer, 'utf8') > this.maxFrameBytes) {
          throw new McpFrameLimitError(`MCP newline frame exceeds ${this.maxFrameBytes} bytes.`);
        }
        return messages;
      }

      const line = this.buffer.slice(0, lineEnd).trim();
      this.buffer = this.buffer.slice(lineEnd + 1);
      if (!line) continue;
      if (Buffer.byteLength(line, 'utf8') > this.maxFrameBytes) {
        throw new McpFrameLimitError(`MCP newline frame exceeds ${this.maxFrameBytes} bytes.`);
      }

      messages.push(JSON.parse(line) as JsonRpcMessage);
    }
  }
}

export function encodeLineDelimitedJsonRpcMessage(message: JsonRpcMessage): string {
  return `${JSON.stringify(message)}\n`;
}

class JsonRpcPeer {
  private readonly framer: JsonRpcFramer | NewlineJsonRpcFramer;
  private nextId = 1;
  private readonly pending = new Map<JsonRpcId, {
    abort?: () => void;
    reject(error: Error): void;
    resolve(value: unknown): void;
    signal?: AbortSignal;
    timeout: ReturnType<typeof setTimeout>;
  }>();

  constructor(
    private readonly input: Readable,
    private readonly output: Writable,
    private readonly framing: McpServerStdioFraming = 'content-length',
    private readonly onFatal?: (error: Error) => void,
  ) {
    this.framer = framing === 'newline' ? new NewlineJsonRpcFramer() : new JsonRpcFramer();
  }

  start(): void {
    this.input.on('data', (chunk) => {
      try {
        for (const message of this.framer.push(Buffer.from(chunk))) {
          if (message.id !== undefined && message.id !== null && !message.method) {
            const pending = this.takePending(message.id);
            if (!pending) continue;
            if (message.error) pending.reject(new Error(JSON.stringify(message.error)));
            else pending.resolve(message.result);
          }
        }
      } catch (error) {
        this.fail(new McpTransportError(`Invalid downstream MCP framing: ${errorMessage(error)}`), true);
      }
    });
    this.input.once('error', (error) => this.fail(new McpTransportError(`Downstream MCP stream failed: ${error.message}`)));
    this.input.once('end', () => this.fail(new McpTransportError('Downstream MCP stream ended.')));
    this.output.once('error', (error) => this.fail(new McpTransportError(`Downstream MCP input failed: ${error.message}`), true));
  }

  notify(method: string, params: unknown): void {
    this.output.write(this.encode({ jsonrpc: '2.0', method, params }));
  }

  request<T>(
    method: string,
    params: unknown,
    options: { signal?: AbortSignal; timeoutMs?: number } = {},
  ): Promise<T> {
    const id = this.nextId++;
    const timeoutMs = options.timeoutMs ?? DEFAULT_DOWNSTREAM_REQUEST_TIMEOUT_MS;

    return new Promise<T>((resolve, reject) => {
      const abort = () => {
        const pending = this.takePending(id);
        if (!pending) return;
        this.tryNotifyCancellation(id, 'MCP host cancelled the request.');
        pending.reject(new McpRequestCancelledError(`MCP request ${method} was cancelled.`));
      };
      const timeout = setTimeout(() => {
        const pending = this.takePending(id);
        if (!pending) return;
        this.tryNotifyCancellation(id, `Request exceeded ${timeoutMs}ms.`);
        pending.reject(new McpRequestTimeoutError(`Timed out waiting for downstream MCP response to ${method}.`));
      }, timeoutMs);
      this.pending.set(id, {
        abort,
        reject,
        resolve: (value) => resolve(value as T),
        signal: options.signal,
        timeout,
      });
      if (options.signal?.aborted) {
        abort();
        return;
      }
      options.signal?.addEventListener('abort', abort, { once: true });
      try {
        this.output.write(this.encode({ id, jsonrpc: '2.0', method, params }));
      } catch (error) {
        const pending = this.takePending(id);
        pending?.reject(new McpTransportError(`Could not write downstream MCP request: ${errorMessage(error)}`));
      }
    });
  }

  fail(error: Error, fatal = false): void {
    for (const id of [...this.pending.keys()]) {
      this.takePending(id)?.reject(error);
    }
    if (fatal) this.onFatal?.(error);
  }

  private takePending(id: JsonRpcId) {
    const pending = this.pending.get(id);
    if (!pending) return undefined;
    this.pending.delete(id);
    clearTimeout(pending.timeout);
    if (pending.abort) pending.signal?.removeEventListener('abort', pending.abort);
    return pending;
  }

  private tryNotifyCancellation(requestId: JsonRpcId, reason: string): void {
    try {
      this.notify('notifications/cancelled', { reason, requestId });
    } catch {
      // The transport may already be gone; the caller still receives the terminal error.
    }
  }

  private encode(message: JsonRpcMessage): string {
    return this.framing === 'newline' ? encodeLineDelimitedJsonRpcMessage(message) : encodeJsonRpcMessage(message);
  }
}

function formatDeniedResult(toolCall: ActionProxyToolCall): string {
  if (toolCall.status === 'blocked') return 'ActionProxy blocked this MCP tool call.';
  if (toolCall.status === 'rejected') return 'ActionProxy approval was rejected.';
  if (toolCall.status === 'failed') return toolCall.error ?? 'ActionProxy failed this MCP tool call.';
  return `ActionProxy did not authorize execution. Status: ${toolCall.status}`;
}

function operationKindFromToolName(name: string): string {
  const normalized = name.toLowerCase();
  if (normalized.includes('delete') || normalized.includes('remove')) return 'delete';
  if (normalized.includes('send') || normalized.includes('email') || normalized.includes('slack')) return 'external_send';
  if (normalized.includes('search') || normalized.includes('list') || normalized.includes('get')) return 'read';
  if (normalized.includes('pay') || normalized.includes('invoice') || normalized.includes('refund')) return 'financial';
  if (normalized.includes('create') || normalized.includes('update') || normalized.includes('write')) return 'write';
  return 'custom';
}

function errorResult(text: string): McpCallResult {
  return { content: [{ text, type: 'text' }], isError: true };
}

const DOWNSTREAM_TIMEOUT_MESSAGE =
  'Downstream MCP execution timed out after dispatch. ActionProxy recorded the uncertain outcome; do not retry automatically.';
const DOWNSTREAM_UNKNOWN_OUTCOME_MESSAGE =
  'Downstream MCP execution ended without a trusted result. ActionProxy recorded the uncertain outcome; do not retry automatically.';
const DOWNSTREAM_OUTCOME_REPORTING_FAILURE_MESSAGE =
  'Downstream MCP execution ended without a trusted result, and ActionProxy outcome reporting failed. Do not retry automatically.';

export function resultDeliveryForMcpResult(result: McpCallResult): ActionProxyResultDelivery {
  const canonicalResult = canonicalJsonStringify(result);
  return {
    byteCount: Buffer.byteLength(canonicalResult, 'utf8'),
    canonicalResultHash: createHash('sha256').update(canonicalResult).digest('hex'),
    modelVisible: true,
    version: 'actionproxy.result-delivery.v1',
  };
}

function normalizeMcpCallResult(result: McpCallResult): McpCallResult {
  const serialized = JSON.stringify(result);
  const normalized = JSON.parse(serialized) as McpCallResult;
  validateMcpCallResult(normalized);
  return normalized;
}

function textFromMcpResult(result: McpCallResult): string | undefined {
  const textParts = result.content
    .filter((item): item is { text: string; type: 'text' } => isRecord(item) && item.type === 'text' && typeof item.text === 'string')
    .map((item) => item.text.trim())
    .filter(Boolean);
  return textParts.length ? textParts.join('\n') : undefined;
}

function executionGrantFromResult(result: unknown): { id: string; policyVersionHash?: string } | undefined {
  if (!isRecord(result) || !isRecord(result.grant) || typeof result.grant.id !== 'string') return undefined;
  return {
    id: result.grant.id,
    policyVersionHash: typeof result.grant.policyVersionHash === 'string' ? result.grant.policyVersionHash : undefined,
  };
}

function response(id: JsonRpcId | null | undefined, result: unknown): JsonRpcMessage {
  return { id: id ?? null, jsonrpc: '2.0', result };
}

function rpcError(id: JsonRpcId | null | undefined, code: number, message: string): JsonRpcMessage {
  return { error: { code, message }, id: id ?? null, jsonrpc: '2.0' };
}

function isRequest(message: JsonRpcMessage): message is JsonRpcMessage & { method: string } {
  return typeof message.method === 'string';
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

class ActionProxyRequestTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ActionProxyRequestTimeoutError';
  }
}

class McpFrameLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'McpFrameLimitError';
  }
}

class McpOutputLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'McpOutputLimitError';
  }
}

class McpRequestCancelledError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'McpRequestCancelledError';
  }
}

class McpRequestTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'McpRequestTimeoutError';
  }
}

class McpTransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'McpTransportError';
  }
}

export function validateDiscoveredMcpTools(tools: unknown): McpTool[] {
  if (!Array.isArray(tools) || tools.length > MAX_MCP_TOOLS) {
    throw new McpOutputLimitError(`Downstream MCP servers exposed more than ${MAX_MCP_TOOLS} tools or an invalid list.`);
  }
  for (const tool of tools) validateMcpTool(tool);
  return tools as McpTool[];
}

export function assertWrappedMcpToolListWithinLimit(tools: readonly McpTool[]): void {
  assertJsonWithinLimit(
    tools.map((tool) => ({
      ...tool,
      description: tool.description
        ? `${tool.description}\n\nWrapped by ActionProxy.`
        : 'Wrapped by ActionProxy.',
    })),
    DEFAULT_MAX_MCP_TOOL_LIST_BYTES,
    'MCP tool list',
  );
}

function validateMcpTool(tool: unknown): asserts tool is McpTool {
  if (
    !isRecord(tool) ||
    typeof tool.name !== 'string' ||
    !tool.name.trim() ||
    tool.name !== tool.name.trim() ||
    Buffer.byteLength(tool.name, 'utf8') > 256 ||
    /\p{Cc}/u.test(tool.name)
  ) {
    throw new McpOutputLimitError('Downstream MCP server returned an invalid tool descriptor.');
  }
  if (tool.description !== undefined && typeof tool.description !== 'string') {
    throw new McpOutputLimitError(`Downstream MCP tool ${tool.name} has an invalid description.`);
  }
  if (tool.inputSchema !== undefined && !isRecord(tool.inputSchema)) {
    throw new McpOutputLimitError(`Downstream MCP tool ${tool.name} has an invalid input schema.`);
  }
  if (tool.inputSchema !== undefined) {
    assertJsonWithinLimit(tool.inputSchema, DEFAULT_MAX_MCP_SCHEMA_BYTES, `MCP schema for ${tool.name}`);
  }
}

function validateMcpCallResult(result: McpCallResult): void {
  if (!isRecord(result) || !Array.isArray(result.content)) {
    throw new McpOutputLimitError('Downstream MCP server returned an invalid tool result.');
  }
  if (result.isError !== undefined && typeof result.isError !== 'boolean') {
    throw new McpOutputLimitError('Downstream MCP server returned an invalid isError value.');
  }
  for (const item of result.content) {
    if (!isRecord(item)) throw new McpOutputLimitError('Downstream MCP result content must contain objects.');
    if (item.type === 'text' && typeof item.text !== 'string') {
      throw new McpOutputLimitError('Downstream MCP text content must contain text.');
    }
  }
  assertJsonWithinLimit(result, DEFAULT_MAX_MCP_RESULT_BYTES, 'MCP tool result');
}

function assertJsonWithinLimit(value: unknown, maxBytes: number, label: string): void {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new McpOutputLimitError(`${label} is not valid JSON.`);
  }
  if (Buffer.byteLength(serialized, 'utf8') > maxBytes) {
    throw new McpOutputLimitError(`${label} exceeds ${maxBytes} bytes.`);
  }
}

async function readResponseTextBounded(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      const buffer = Buffer.from(chunk.value);
      length += buffer.byteLength;
      if (length > maxBytes) {
        await reader.cancel();
        throw new McpOutputLimitError(`ActionProxy response exceeds ${maxBytes} bytes.`);
      }
      chunks.push(buffer);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, length).toString('utf8');
}

function resolveBearerToken(
  environmentVariable: string | undefined,
  environment: Record<string, string | undefined>,
): string | undefined {
  if (!environmentVariable) return undefined;
  const token = environment[environmentVariable];
  if (!token || token.length > 8192 || token.trim() !== token || /\p{Cc}/u.test(token)) {
    throw new Error(`ActionProxy bearer token environment variable ${environmentVariable} is missing or invalid.`);
  }
  return token;
}

function leastPrivilegeChildEnvironment(
  parent: Record<string, string | undefined>,
  explicit: Record<string, string> | undefined,
  passthrough: string[] | undefined,
  forbidden: string[],
): NodeJS.ProcessEnv {
  const inheritedNames = [
    'ComSpec',
    'HOME',
    'LANG',
    'LC_ALL',
    'PATH',
    'Path',
    'PATHEXT',
    'SystemRoot',
    'TEMP',
    'TMP',
    'TMPDIR',
    'USERPROFILE',
  ];
  const result: NodeJS.ProcessEnv = {};
  for (const name of inheritedNames) {
    if (parent[name] !== undefined) result[name] = parent[name];
  }
  const forbiddenNames = new Set(forbidden.map((name) => name.toLowerCase()));
  for (const name of passthrough ?? []) {
    if (forbiddenNames.has(name.toLowerCase())) {
      throw new Error(`Downstream MCP environment passthrough must not include ActionProxy bearer variable ${name}.`);
    }
    const parentEntry = Object.entries(parent).find(([key]) => key.toLowerCase() === name.toLowerCase());
    const value = parentEntry?.[1];
    if (value === undefined) {
      throw new Error(`Downstream MCP environment passthrough variable ${name} is not set.`);
    }
    result[name] = value;
  }
  Object.assign(result, explicit ?? {});
  for (const name of Object.keys(result)) {
    if (forbiddenNames.has(name.toLowerCase())) delete result[name];
  }
  return result;
}

function mcpIdempotencyKey(sessionNonce: string, id: JsonRpcId | string): string {
  const material = `${sessionNonce}\0${typeof id}\0${String(id)}`;
  return `mcp-stdio-v1_${createHash('sha256').update(material).digest('hex')}`;
}

function typedJsonRpcId(id: JsonRpcId): string {
  return `${typeof id}:${String(id)}`;
}

function jsonRpcId(value: unknown): JsonRpcId | undefined {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  return undefined;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new McpRequestCancelledError('MCP request was cancelled.');
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timeout);
      reject(new McpRequestCancelledError('MCP request was cancelled.'));
    };
    const timeout = setTimeout(() => {
      signal?.removeEventListener('abort', abort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', abort, { once: true });
  });
}

function waitForChildExit(process: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<boolean> {
  if (process.exitCode !== null || process.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const onExit = () => finish(true);
    const timeout = setTimeout(() => finish(false), timeoutMs);
    const finish = (exited: boolean) => {
      clearTimeout(timeout);
      process.removeListener('exit', onExit);
      resolve(exited);
    };
    process.once('exit', onExit);
  });
}

function formatExit(code: number | null, signal: NodeJS.Signals | null): string {
  if (signal) return `signal ${signal}`;
  return `code ${code ?? 'unknown'}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function canonicalJsonStringify(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') return JSON.stringify(Object.is(value, -0) ? 0 : value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJsonStringify(item)).join(',')}]`;

  const entries = Object.entries(value as JsonObject)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJsonStringify(item)}`)
    .join(',')}}`;
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value);
}
