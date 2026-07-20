import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import type { McpWrapperProfile } from './integration-config';

export interface DiscoveredMcpTool {
  description?: string;
  inputSchema?: Record<string, unknown>;
  name: string;
  serverName: string;
}

interface JsonRpcMessage {
  error?: unknown;
  id?: number | string | null;
  jsonrpc: '2.0';
  method?: string;
  params?: unknown;
  result?: unknown;
}

export async function discoverMcpTools(profile: McpWrapperProfile): Promise<DiscoveredMcpTool[]> {
  const client = await StdioDiscoveryClient.start(profile);
  try {
    return await client.listTools();
  } finally {
    await client.close();
  }
}

class StdioDiscoveryClient {
  private constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    private readonly peer: JsonRpcPeer,
    private readonly serverName: string,
  ) {}

  static async start(profile: McpWrapperProfile): Promise<StdioDiscoveryClient> {
    const child = spawn(profile.server.command, profile.server.args ?? [], {
      cwd: profile.server.cwd,
      env: { ...process.env, ...(profile.server.env ?? {}) },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    child.stderr.on('data', (chunk) => process.stderr.write(chunk));
    const peer = new JsonRpcPeer(child.stdout, child.stdin);
    peer.start();
    await peer.request('initialize', {
      capabilities: {},
      clientInfo: { name: 'actionproxy-mcp-discovery', version: '0.1.0' },
      protocolVersion: '2025-06-18',
    });
    peer.notify('notifications/initialized', {});
    return new StdioDiscoveryClient(child, peer, profile.server.name);
  }

  async listTools(): Promise<DiscoveredMcpTool[]> {
    const response = await this.peer.request<{ tools?: Array<Record<string, unknown>> }>('tools/list', {});
    return (response.tools ?? [])
      .filter((tool) => typeof tool.name === 'string')
      .map((tool) => ({
        description: typeof tool.description === 'string' ? tool.description : undefined,
        inputSchema: isRecord(tool.inputSchema) ? tool.inputSchema : undefined,
        name: String(tool.name),
        serverName: this.serverName,
      }));
  }

  async close(): Promise<void> {
    this.child.kill();
  }
}

class JsonRpcPeer {
  private id = 1;
  private readonly pending = new Map<number | string, { reject(error: Error): void; resolve(value: unknown): void }>();
  private readonly framer = new JsonRpcFramer();

  constructor(
    private readonly readable: NodeJS.ReadableStream,
    private readonly writable: NodeJS.WritableStream,
  ) {}

  start(): void {
    this.readable.on('data', (chunk) => {
      for (const message of this.framer.push(Buffer.from(chunk))) {
        if (message.id === undefined || message.id === null) continue;
        const pending = this.pending.get(message.id);
        if (!pending) continue;
        this.pending.delete(message.id);
        if ('error' in message) {
          pending.reject(new Error(JSON.stringify(message.error)));
        } else {
          pending.resolve(message.result);
        }
      }
    });
  }

  notify(method: string, params: unknown): void {
    this.writable.write(encodeJsonRpcMessage({ jsonrpc: '2.0', method, params }));
  }

  request<T>(method: string, params: unknown): Promise<T> {
    const id = this.id++;
    this.writable.write(encodeJsonRpcMessage({ id, jsonrpc: '2.0', method, params }));
    return withTimeout(
      new Promise<T>((resolve, reject) => {
        this.pending.set(id, {
          reject,
          resolve: (value) => resolve(value as T),
        });
      }),
      10_000,
      `Timed out during MCP discovery method ${method}.`,
    );
  }
}

class JsonRpcFramer {
  private buffer = Buffer.alloc(0);

  push(chunk: Buffer): JsonRpcMessage[] {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const messages: JsonRpcMessage[] = [];

    while (true) {
      const headerEnd = this.buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return messages;

      const header = this.buffer.subarray(0, headerEnd).toString('utf8');
      const match = header.match(/content-length:\s*(\d+)/i);
      if (!match) throw new Error('Invalid JSON-RPC frame: missing Content-Length.');

      const length = Number(match[1]);
      const bodyStart = headerEnd + 4;
      const bodyEnd = bodyStart + length;
      if (this.buffer.length < bodyEnd) return messages;

      messages.push(JSON.parse(this.buffer.subarray(bodyStart, bodyEnd).toString('utf8')) as JsonRpcMessage);
      this.buffer = this.buffer.subarray(bodyEnd);
    }
  }
}

function encodeJsonRpcMessage(message: JsonRpcMessage): string {
  const body = JSON.stringify(message);
  return `Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
