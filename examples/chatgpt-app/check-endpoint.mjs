#!/usr/bin/env node

const [rawEndpoint, unexpectedArgument] = process.argv.slice(2);
if (!rawEndpoint || unexpectedArgument !== undefined) {
  fail('Usage: node examples/chatgpt-app/check-endpoint.mjs https://your-host.example/mcp');
}

let endpoint;
try {
  endpoint = new URL(rawEndpoint);
} catch {
  fail('The MCP endpoint must be an absolute URL.');
}

const loopback = ['127.0.0.1', '::1', 'localhost'].includes(endpoint.hostname);
if (endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && loopback)) {
  fail('The MCP endpoint must use HTTPS, except for an explicit loopback smoke test.');
}
if (endpoint.pathname !== '/mcp' || endpoint.search || endpoint.hash || rawEndpoint.endsWith('/')) {
  fail('The MCP endpoint must identify the exact /mcp path without a trailing slash, query, or fragment.');
}

const metadataUrl = new URL('/.well-known/oauth-protected-resource/mcp', endpoint);
const metadataResponse = await fetch(metadataUrl, { headers: { accept: 'application/json' } });
if (!metadataResponse.ok) {
  fail(`Protected-resource metadata failed: HTTP ${metadataResponse.status}.`);
}
const metadata = await metadataResponse.json();

if (metadata.resource !== endpoint.toString()) fail('Protected-resource metadata does not name the exact MCP URL.');
if (!Array.isArray(metadata.authorization_servers) || metadata.authorization_servers.length === 0) {
  fail('Protected-resource metadata has no authorization server.');
}
for (const scope of ['tool_call:read', 'tool_call:submit']) {
  if (!Array.isArray(metadata.scopes_supported) || !metadata.scopes_supported.includes(scope)) {
    fail(`Protected-resource metadata is missing scope ${scope}.`);
  }
}

const challengeResponse = await fetch(endpoint, mcpRequest(initializePayload('actionproxy-preflight')));
if (challengeResponse.status !== 401) {
  fail(`Unauthenticated MCP initialization should return HTTP 401; received ${challengeResponse.status}.`);
}
const challenge = challengeResponse.headers.get('www-authenticate') ?? '';
if (!/^Bearer\b/iu.test(challenge) || !challenge.includes('resource_metadata=')) {
  fail('The MCP 401 response is missing its Bearer resource_metadata challenge.');
}

console.log(`Protected resource: ${metadata.resource}`);
console.log(`Authorization server: ${metadata.authorization_servers[0]}`);
console.log(`Scopes: ${metadata.scopes_supported.join(', ')}`);
console.log('OAuth discovery preflight passed. No access token or tool call was used.');

function initializePayload(id) {
  return {
    id,
    jsonrpc: '2.0',
    method: 'initialize',
    params: {
      capabilities: {},
      clientInfo: { name: 'actionproxy-chatgpt-preflight', version: '0.1.1' },
      protocolVersion: '2025-06-18',
    },
  };
}

function mcpRequest(payload) {
  return {
    body: JSON.stringify(payload),
    headers: {
      accept: 'application/json, text/event-stream',
      'content-type': 'application/json',
      origin: 'https://chatgpt.com',
    },
    method: 'POST',
  };
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
