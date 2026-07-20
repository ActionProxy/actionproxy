#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const defaultRepoRoot = path.resolve(scriptDir, '..', '..');
const args = process.argv.slice(2);
const json = args.includes('--json');
const rootArgIndex = args.indexOf('--root');
const repoRoot =
  rootArgIndex === -1 ? defaultRepoRoot : path.resolve(args[rootArgIndex + 1] ?? defaultRepoRoot);
const wrapperPath = path.join(repoRoot, 'packages/mcp-wrapper/dist/index.js');
const configPath = path.join(repoRoot, 'examples/mcp-demo/actionproxy.mcp.yaml');
const serverName = 'actionproxy-demo';

const generic = {
  command: 'node',
  args: [wrapperPath, 'wrap', '--config', configPath],
};

const doctor = {
  static: ['node', wrapperPath, 'doctor', '--config', configPath].map(shellArg).join(' '),
  discover: ['node', wrapperPath, 'doctor', '--config', configPath, '--discover'].map(shellArg).join(' '),
};

const codexCli = [
  'codex',
  'mcp',
  'add',
  serverName,
  '--',
  generic.command,
  ...generic.args,
]
  .map(shellArg)
  .join(' ');

const claudeCodeCli = [
  'claude',
  'mcp',
  'add',
  '--transport',
  'stdio',
  serverName,
  '--',
  generic.command,
  ...generic.args,
]
  .map(shellArg)
  .join(' ');

const codexToml = `[mcp_servers."${serverName}"]
command = "node"
args = ${jsonArray(generic.args)}
`;

const claudeMcpJson = JSON.stringify(
  {
    mcpServers: {
      [serverName]: {
        type: 'stdio',
        command: generic.command,
        args: generic.args,
      },
    },
  },
  null,
  2,
);

if (json) {
  console.log(
    JSON.stringify(
      {
        claudeCodeCli,
        claudeMcpJson,
        codexCli,
        codexToml,
        configPath,
        doctor,
        generic,
        repoRoot,
        serverName,
        wrapperPath,
      },
      null,
      2,
    ),
  );
} else {
  console.log(`# Configure Codex or Claude Code to use ActionProxy as an MCP server

Codex, Claude Code, or another MCP host starts this local stdio server as actionproxy-demo.
ActionProxy does not call the host; the host calls tools exposed through ActionProxy.

Run these from this checkout after starting ActionProxy with:

  corepack pnpm dev:proxy

Optional approval UI:

  corepack pnpm dev:web

Inspect configured wrapper without spawning a downstream process:

  ${doctor.static}

Opt-in initialize + tools/list discovery (never tools/call):

  ${doctor.discover}

Codex CLI:

  ${codexCli}

Claude Code:

  ${claudeCodeCli}

Generic stdio MCP host:

  command: ${generic.command}
  args: ${JSON.stringify(generic.args)}

Codex config.toml example:

${indent(codexToml)}

Claude Code .mcp.json example:

${indent(claudeMcpJson)}
`);
}

function shellArg(value) {
  if (/^[A-Za-z0-9_./:=@+-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function jsonArray(values) {
  return JSON.stringify(values);
}

function indent(value) {
  return value
    .trimEnd()
    .split('\n')
    .map((line) => `  ${line}`)
    .join('\n');
}
