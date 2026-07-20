import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const sourceRoot = path.resolve('src');
const communityEntrypoints = [
  path.join(sourceRoot, 'app.ts'),
  path.join(sourceRoot, 'index.ts'),
];
const forbiddenPathFragments = [
  '/e2e-platform-server',
  '/integrations/connector-token-crypto',
  '/integrations/google-workspace/',
  '/integrations/hubspot/',
  '/integrations/slack/slack-connector',
  '/integrations/slack/slack-oauth',
  '/integrations/stripe/',
  '/integrations/teams/',
  '/integrations/zendesk/',
  '/platform-app',
  '/platform-modules',
  '/platform/',
  '/routes/agent-flow-drafts',
  '/routes/agents',
  '/routes/chatgpt-work',
  '/routes/integrations-platform',
  '/routes/system',
  '/services/agent-flow-builder',
  '/services/agent-run',
  '/services/agent-templates',
  '/services/model-provider',
] as const;

describe('Community import boundary', () => {
  it('keeps Community entrypoints disconnected from private modules', () => {
    const imports = reachableSourceFiles(communityEntrypoints);
    const relativeImports = [...imports]
      .map((file) => `/${path.relative(sourceRoot, file).replaceAll(path.sep, '/')}`)
      .sort();

    for (const fragment of forbiddenPathFragments) {
      expect(relativeImports, fragment).not.toEqual(
        expect.arrayContaining([expect.stringContaining(fragment)]),
      );
    }
  });
});

function reachableSourceFiles(entrypoints: string[]): Set<string> {
  const seen = new Set<string>();
  const pending = [...entrypoints];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const source = fs.readFileSync(file, 'utf8');
    for (const specifier of relativeSpecifiers(source)) {
      const resolved = resolveTypeScriptImport(file, specifier);
      if (resolved && !seen.has(resolved)) pending.push(resolved);
    }
  }
  return seen;
}

function relativeSpecifiers(source: string): string[] {
  return [...source.matchAll(
    /(?:from\s+|import\s*\()(['"])(\.\.?\/[^'"]+)\1/gmu,
  )].map((match) => match[2]!);
}

function resolveTypeScriptImport(fromFile: string, specifier: string): string | undefined {
  const base = path.resolve(path.dirname(fromFile), specifier);
  const candidates = [`${base}.ts`, path.join(base, 'index.ts')];
  return candidates.find((candidate) => fs.existsSync(candidate));
}
