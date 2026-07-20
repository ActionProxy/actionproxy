import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { promisify } from 'node:util';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const exampleDir = path.join(repoRoot, 'examples/chatgpt-app');

test('documents the local standard-MCP fixture and links the deployment guide', () => {
  const readme = readFileSync(path.join(exampleDir, 'README.md'), 'utf8');
  const env = readFileSync(path.join(exampleDir, 'actionproxy.env.example'), 'utf8');
  const combined = `${readme}\n${env}`;

  assert.match(readme, /protocol and lifecycle test, not a live ChatGPT test/u);
  assert.match(readme, /OAuth-protected MCP for ChatGPT/u);
  assert.match(readme, /zero email effects before approval and exactly one afterward/u);
  assert.match(env, /ACTIONPROXY_MCP_RESOURCE_URL=https:\/\/actionproxy\.example\.com\/mcp/u);
  assert.match(env, /ACTIONPROXY_MCP_ALLOWED_ORIGINS=https:\/\/chatgpt\.com/u);
  assert.match(env, /ACTIONPROXY_LOCAL_EXECUTION=mock/u);
  for (const name of [
    ['OPENAI', 'API', 'KEY'].join('_'),
    ['ACTIONPROXY', 'MODEL', 'PROVIDER'].join('_'),
  ]) {
    assert.equal(combined.includes(name), false);
  }
  assert.doesNotMatch(combined, /\/Users\/|\/private\/tmp\//u);
  assert.match(readme, /real Secure MCP Tunnel run is the required/u);
});

test('preflight validates metadata and OAuth discovery without a token', async (t) => {
  const server = createServer((request, response) => {
    const base = `http://127.0.0.1:${server.address().port}`;
    if (request.url === '/.well-known/oauth-protected-resource/mcp') {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({
        authorization_servers: [`${base}/oauth`],
        resource: `${base}/mcp`,
        scopes_supported: ['tool_call:read', 'tool_call:submit'],
      }));
      return;
    }
    if (request.url === '/mcp') {
      response.statusCode = 401;
      response.setHeader('www-authenticate', `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`);
      response.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }
    response.statusCode = 404;
    response.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const address = server.address();
  assert.equal(typeof address, 'object');

  const { stdout } = await execFileAsync(
    process.execPath,
    [path.join(exampleDir, 'check-endpoint.mjs'), `http://127.0.0.1:${address.port}/mcp`],
    { cwd: repoRoot },
  );
  assert.match(stdout, /OAuth discovery preflight passed/u);
  assert.match(stdout, /No access token or tool call was used/u);
});
