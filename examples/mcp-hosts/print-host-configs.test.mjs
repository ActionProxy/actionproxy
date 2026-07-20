import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';

const repoRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const scriptPath = resolve(repoRoot, 'examples/mcp-hosts/print-host-configs.mjs');
const docsWithHostSetup = [
  resolve(repoRoot, 'README.md'),
  resolve(repoRoot, 'examples/framework-integrations/README.md'),
  resolve(repoRoot, 'examples/mcp-hosts/README.md'),
];

test('prints Codex and Claude Code host setup commands', () => {
  const output = execFileSync(process.execPath, [scriptPath, '--json', '--root', repoRoot], {
    encoding: 'utf8',
  });
  const parsed = JSON.parse(output);

  assert.match(parsed.codexCli, /codex mcp add actionproxy-demo -- node /);
  assert.match(parsed.claudeCodeCli, /claude mcp add --transport stdio actionproxy-demo -- node /);
  assert.match(parsed.doctor.static, / doctor --config /);
  assert.doesNotMatch(parsed.doctor.static, /--discover/);
  assert.match(parsed.doctor.discover, / doctor --config .* --discover$/);
  assert.equal(parsed.generic.command, 'node');
  assert.equal(parsed.generic.args[0], parsed.wrapperPath);
  assert.deepEqual(parsed.generic.args.slice(1), ['wrap', '--config', parsed.configPath]);
  assert.ok(isAbsolute(parsed.wrapperPath));
  assert.ok(isAbsolute(parsed.configPath));
  assert.ok(parsed.generic.args.every((arg) => arg === 'wrap' || arg === '--config' || isAbsolute(arg)));
});

test('plain output frames ActionProxy as the MCP server used by the host', () => {
  const output = execFileSync(process.execPath, [scriptPath, '--root', repoRoot], {
    encoding: 'utf8',
  });

  assert.match(output, /Configure Codex or Claude Code to use ActionProxy as an MCP server/);
  assert.match(output, /ActionProxy does not call the host/);
  assert.match(output, /without spawning a downstream process/);
});

test('committed host examples contain one wrapper entry and no direct downstream entry', () => {
  const claude = JSON.parse(readFileSync(resolve(repoRoot, 'examples/mcp-hosts/claude.mcp.json.example'), 'utf8'));
  const generic = JSON.parse(readFileSync(resolve(repoRoot, 'examples/mcp-hosts/generic.mcp.json.example'), 'utf8'));
  const codex = readFileSync(resolve(repoRoot, 'examples/mcp-hosts/codex.config.toml.example'), 'utf8');

  for (const example of [claude, generic]) {
    assert.deepEqual(Object.keys(example.mcpServers), ['actionproxy-demo']);
    const entry = example.mcpServers['actionproxy-demo'];
    assert.deepEqual(entry.args.slice(1, 3), ['wrap', '--config']);
    assert.match(entry.args[0], /packages\/mcp-wrapper\/dist\/index\.js$/);
    assert.doesNotMatch(JSON.stringify(entry), /examples\/mcp-demo\/server\.mjs/);
  }

  assert.equal((codex.match(/^\[mcp_servers\./gmu) ?? []).length, 1);
  assert.match(codex, /packages\/mcp-wrapper\/dist\/index\.js/);
  assert.match(codex, /"wrap", "--config"/);
  assert.doesNotMatch(codex, /examples\/mcp-demo\/server\.mjs/);
});

test('committed MCP host docs do not hardcode private local paths', () => {
  const docs = docsWithHostSetup.map((filePath) => readFileSync(filePath, 'utf8')).join('\n');

  assert.match(docs, /Codex uses ActionProxy as an MCP server/);
  assert.doesNotMatch(docs, /\/Users\//);
  assert.doesNotMatch(docs, /\/private\/tmp\//);
  assert.doesNotMatch(docs, /\/tmp\/actionproxy-public-export/);
});
