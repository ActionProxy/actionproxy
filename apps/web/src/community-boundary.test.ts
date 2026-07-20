import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const sourceRoot = path.resolve("src");
const communityEntrypoint = path.join(sourceRoot, "main.tsx");
const declaredCommunityGraph = [
  "/App.tsx",
  "/components/AgentDemoPanel.tsx",
  "/components/Dashboard.tsx",
  "/components/PolicyEditor.tsx",
  "/components/ToolIntegrationsCard.tsx",
  "/lib/actionproxy-client.ts",
  "/main.tsx",
  "/types.ts",
] as const;
const privatePathFragments = [
  "/components/MarketingLanding",
  "/components/comparison-data",
  "/components/generated-public-comparisons",
  "/lib/demo-catalog",
  "/lib/metrics",
  "/marketing-prerender",
  "/platform/",
  "/site/",
] as const;
const privateModulePattern =
  /(?:^|[/_.-])(?:e2e-platform|hosted|managed-delivery|marketing|native-provider|platform|site|workflow)(?:[/_.-]|$)/iu;

describe("Community web import boundary", () => {
  it("keeps the fixed entrypoint inside the declared Community graph", () => {
    const reachable = reachableSourceFiles(communityEntrypoint);
    const imports = [...reachable]
      .map(
        (file) =>
          `/${path.relative(sourceRoot, file).replaceAll(path.sep, "/")}`,
      )
      .sort();

    expect(imports).toEqual(declaredCommunityGraph);
    for (const fragment of privatePathFragments) {
      expect(imports, fragment).not.toEqual(
        expect.arrayContaining([expect.stringContaining(fragment)]),
      );
    }

    for (const file of reachable) {
      for (const specifier of sourceSpecifiers(fs.readFileSync(file, "utf8"))) {
        expect(
          privateModulePattern.test(specifier),
          `${path.relative(sourceRoot, file)} imports private module ${specifier}`,
        ).toBe(false);
      }
    }
  });
});

function reachableSourceFiles(entrypoint: string): Set<string> {
  const seen = new Set<string>();
  const pending = [entrypoint];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const source = fs.readFileSync(file, "utf8");
    for (const specifier of sourceSpecifiers(source).filter((candidate) =>
      candidate.startsWith("."),
    )) {
      const resolved = resolveTypeScriptImport(file, specifier);
      if (resolved && !seen.has(resolved)) pending.push(resolved);
    }
  }
  return seen;
}

function sourceSpecifiers(source: string): string[] {
  return [
    ...source.matchAll(/(?:from\s+|import\s*)(?:\(\s*)?(['"])([^'"]+)\1/gmu),
  ].map((match) => match[2]!);
}

function resolveTypeScriptImport(
  fromFile: string,
  specifier: string,
): string | undefined {
  const base = path.resolve(path.dirname(fromFile), specifier);
  const candidates = [
    `${base}.ts`,
    `${base}.tsx`,
    path.join(base, "index.ts"),
    path.join(base, "index.tsx"),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate));
}
