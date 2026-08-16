#!/usr/bin/env node

const tools = [
  {
    name: 'docs.search',
    description: 'Search support policy docs.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
      },
      required: ['query'],
    },
  },
  {
    name: 'gmail.send_email',
    description: 'Send a customer email.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string' },
        subject: { type: 'string' },
        body: { type: 'string' },
      },
      required: ['to', 'subject', 'body'],
    },
  },
  {
    name: 'dangerous.delete_customer',
    description: 'Simulate deleting a customer. This demo tool must be denied by ActionProxy policy.',
    inputSchema: {
      type: 'object',
      properties: {
        customerId: { type: 'string' },
      },
      required: ['customerId'],
    },
  },
];

let buffer = Buffer.alloc(0);

process.stdin.on('data', (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);

  for (;;) {
    const headerEnd = buffer.indexOf('\r\n\r\n');
    if (headerEnd === -1) return;

    const header = buffer.subarray(0, headerEnd).toString('utf8');
    const match = header.match(/content-length:\s*(\d+)/i);
    if (!match) throw new Error('Missing Content-Length header.');

    const length = Number(match[1]);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + length;
    if (buffer.length < bodyEnd) return;

    const message = JSON.parse(buffer.subarray(bodyStart, bodyEnd).toString('utf8'));
    buffer = buffer.subarray(bodyEnd);
    handle(message);
  }
});

function handle(message) {
  if (!message.id || message.method?.startsWith('notifications/')) return;

  if (message.method === 'initialize') {
    send({
      id: message.id,
      jsonrpc: '2.0',
      result: {
        capabilities: { tools: {} },
        protocolVersion: '2025-06-18',
        serverInfo: { name: 'actionproxy-mcp-demo', version: '0.1.1' },
      },
    });
    return;
  }

  if (message.method === 'tools/list') {
    send({ id: message.id, jsonrpc: '2.0', result: { tools } });
    return;
  }

  if (message.method === 'tools/call') {
    const name = message.params?.name;
    const args = message.params?.arguments ?? {};
    if (name === 'docs.search') {
      send({
        id: message.id,
        jsonrpc: '2.0',
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ok: true,
                results: [{ title: 'Refund policy', snippet: 'Refund requests are reviewed within 5 business days.' }],
                tool: name,
                query: args.query ?? null,
              }),
            },
          ],
        },
      });
      return;
    }

    if (name === 'gmail.send_email') {
      send({
        id: message.id,
        jsonrpc: '2.0',
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ok: true,
                tool: name,
                to: args.to ?? null,
                subject: args.subject ?? null,
                note: 'MCP demo email only. No real email was sent.',
              }),
            },
          ],
        },
      });
      return;
    }

    if (name === 'dangerous.delete_customer') {
      send({
        id: message.id,
        jsonrpc: '2.0',
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ok: true,
                tool: name,
                customerId: args.customerId ?? null,
                note: 'MCP demo deletion only. No customer or external system was changed.',
              }),
            },
          ],
        },
      });
      return;
    }
  }

  send({ error: { code: -32601, message: `Unsupported method: ${message.method}` }, id: message.id, jsonrpc: '2.0' });
}

function send(message) {
  const body = JSON.stringify(message);
  process.stdout.write(`Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`);
}
