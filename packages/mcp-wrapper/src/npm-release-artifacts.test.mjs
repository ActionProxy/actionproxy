import { gunzipSync, gzipSync } from "node:zlib";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  SUPPORTED_NPM_RELEASE_COMMANDS,
  SUPPORTED_NPM_RELEASE_OPERATIONS,
  assertOperationTarget,
  assertReleaseRef,
  assertTrustedPublishingRuntime,
  compareSemanticVersions,
  createSensitiveNpmContext,
  expectedConfirmation,
  hasExactRegistryManifestMetadata,
  parseNpmTarball,
  planPublishLatestRegistryState,
  resolveWorkspaceYamlDependency,
  sanitizeChildEnvironment,
} from "./npm-release-artifacts.mjs";

describe("npm release artifacts", () => {
  it("requires exact operation-specific owner confirmations", () => {
    expect(expectedConfirmation("publish-latest", "0.1.2")).toBe(
      "PUBLISH @actionproxy 0.1.2 TO LATEST",
    );
    expect(() => expectedConfirmation("publish", "0.1.1")).toThrow(
      /Unsupported npm release operation/u,
    );
    expect(() =>
      expectedConfirmation("publish-latest", "0.1.2", "next"),
    ).toThrow(/requires the latest/u);
    expect(() =>
      expectedConfirmation("publish-latest", "0.1.2-rc.1"),
    ).toThrow(/stable semantic version/u);
    expect(() => assertOperationTarget("trusted-stage", "next")).toThrow(
      /Unsupported npm release operation/u,
    );
  });

  it("exposes registry verification as an explicit release command", () => {
    expect(SUPPORTED_NPM_RELEASE_COMMANDS).toContain("registry-verify");
    expect(SUPPORTED_NPM_RELEASE_COMMANDS).toEqual([
      "consume",
      "prepare",
      "registry-verify",
      "verify",
      "write",
    ]);
    expect(SUPPORTED_NPM_RELEASE_OPERATIONS).toEqual(["publish-latest"]);
  });

  it("strips credentials and narrowly restores only GitHub OIDC", () => {
    const environment = {
      ACTIONPROXY_SECRET: "placeholder-actionproxy-secret",
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "placeholder-oidc-token",
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://example.invalid/oidc",
      AWS_ACCESS_KEY_ID: "placeholder-aws-key",
      GITHUB_TOKEN: "placeholder-github-token",
      NODE_AUTH_TOKEN: "placeholder-npm-token",
      npm_config_registry: "https://attacker.invalid/",
      NPM_CONFIG_GLOBALCONFIG: "/tmp/setup-node-global-npmrc",
      NPM_CONFIG_USERCONFIG: "/tmp/setup-node-npmrc",
      BASH_ENV: "/tmp/untrusted-bash-env",
      ENV: "/tmp/untrusted-shell-env",
      NODE_OPTIONS: "--require=/tmp/untrusted-hook.cjs",
      PATH: "/usr/bin",
    };
    expect(sanitizeChildEnvironment(environment)).toMatchObject({
      PATH: "/usr/bin",
      npm_config_audit: "false",
      npm_config_fund: "false",
    });
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty(
      "NODE_AUTH_TOKEN",
    );
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty(
      "GITHUB_TOKEN",
    );
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty(
      "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    );
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty(
      "ACTIONS_ID_TOKEN_REQUEST_URL",
    );
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty(
      "NPM_CONFIG_USERCONFIG",
    );
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty(
      "NPM_CONFIG_GLOBALCONFIG",
    );
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty(
      "npm_config_registry",
    );
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty(
      "BASH_ENV",
    );
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty("ENV");
    expect(sanitizeChildEnvironment(environment)).not.toHaveProperty(
      "NODE_OPTIONS",
    );
    expect(
      sanitizeChildEnvironment(environment, { includeGitHubOidc: true }),
    ).toMatchObject({
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "placeholder-oidc-token",
      ACTIONS_ID_TOKEN_REQUEST_URL: "https://example.invalid/oidc",
      PATH: "/usr/bin",
    });
    expect(
      sanitizeChildEnvironment(environment, { includeGitHubOidc: true }),
    ).not.toHaveProperty("NODE_AUTH_TOKEN");
  });

  it("isolates sensitive npm commands from project and inherited npm configuration", () => {
    const repositoryPath = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "../../..",
    );
    const oidcUrl = [
      "https://pipelines",
      "actions.githubusercontent.com/example",
    ].join(".");
    const context = createSensitiveNpmContext(
      {
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "placeholder-oidc-token",
        ACTIONS_ID_TOKEN_REQUEST_URL: oidcUrl,
        NODE_AUTH_TOKEN: "placeholder-npm-token",
        NPM_CONFIG_REGISTRY: "https://attacker.invalid/",
        NPM_CONFIG_USERCONFIG: "/tmp/untrusted-user-npmrc",
        PATH: "/usr/bin",
      },
      { includeGitHubOidc: true },
    );
    try {
      expect(fs.statSync(context.cwd).mode & 0o777).toBe(0o700);
      expect(
        path.resolve(context.cwd).startsWith(`${repositoryPath}${path.sep}`),
      ).toBe(false);
      expect(context.environment).not.toHaveProperty("NPM_CONFIG_REGISTRY");
      expect(context.environment.NPM_CONFIG_USERCONFIG).toBe(
        path.join(context.cwd, "user-npmrc"),
      );
      expect(context.environment.NPM_CONFIG_GLOBALCONFIG).toBe(
        path.join(context.cwd, "global-npmrc"),
      );
      expect(context.environment.npm_config_cache).toBe(
        path.join(context.cwd, "cache"),
      );
      for (const filename of [".npmrc", "global-npmrc", "user-npmrc"]) {
        expect(fs.statSync(path.join(context.cwd, filename)).mode & 0o777).toBe(
          0o600,
        );
      }
      expect(fs.readFileSync(path.join(context.cwd, ".npmrc"), "utf8")).toBe(
        "",
      );
      expect(
        fs.readFileSync(path.join(context.cwd, "global-npmrc"), "utf8"),
      ).toBe("");
      expect(
        fs.readFileSync(path.join(context.cwd, "user-npmrc"), "utf8"),
      ).toBe("");
      expect(context.environment).not.toHaveProperty("NODE_AUTH_TOKEN");
      expect(context.environment).toMatchObject({
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "placeholder-oidc-token",
        ACTIONS_ID_TOKEN_REQUEST_URL: oidcUrl,
      });
    } finally {
      context.cleanup();
    }
    expect(fs.existsSync(context.cwd)).toBe(false);
  });

  it("requires GitHub OIDC and rejects token fallback", () => {
    const valid = {
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "placeholder-oidc-token",
      ACTIONS_ID_TOKEN_REQUEST_URL: [
        "https://pipelines",
        "actions.githubusercontent.com/example",
      ].join("."),
      GITHUB_ACTIONS: "true",
    };
    expect(assertTrustedPublishingRuntime(valid)).toBe(true);
    expect(() =>
      assertTrustedPublishingRuntime({
        ...valid,
        NODE_AUTH_TOKEN: "placeholder-npm-token",
      }),
    ).toThrow(/without an npm token/u);
    expect(() =>
      assertTrustedPublishingRuntime({
        ...valid,
        ACTIONS_ID_TOKEN_REQUEST_URL: "https://placeholder.invalid/oidc",
      }),
    ).toThrow(/without an npm token/u);
    expect(() =>
      assertTrustedPublishingRuntime({
        ...valid,
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "",
      }),
    ).toThrow(/OIDC is missing or malformed/u);
  });

  it("accepts only workflow dispatch on the exact version tag", () => {
    const valid = {
      eventName: "workflow_dispatch",
      ref: "refs/tags/v0.1.1",
      refName: "v0.1.1",
      refType: "tag",
    };
    expect(assertReleaseRef(valid, "0.1.1")).toBe(true);
    expect(() =>
      assertReleaseRef({ ...valid, eventName: "push" }, "0.1.1"),
    ).toThrow(/exact version tag/u);
    expect(() =>
      assertReleaseRef({ ...valid, ref: "refs/tags/v0.1.2" }, "0.1.1"),
    ).toThrow(/exact version tag/u);
  });

  it("resolves yaml from the MCP workspace when no root link exists", () => {
    const repositoryPath = fs.mkdtempSync(
      path.join(os.tmpdir(), "actionproxy-npm-yaml-layout-"),
    );
    const storeYaml = path.join(
      repositoryPath,
      "node_modules",
      ".pnpm",
      "yaml@2.9.0",
      "node_modules",
      "yaml",
    );
    const workspaceNodeModules = path.join(
      repositoryPath,
      "packages",
      "mcp-wrapper",
      "node_modules",
    );
    try {
      fs.mkdirSync(storeYaml, { recursive: true });
      fs.mkdirSync(workspaceNodeModules, { recursive: true });
      fs.symlinkSync(
        storeYaml,
        path.join(workspaceNodeModules, "yaml"),
        process.platform === "win32" ? "junction" : "dir",
      );

      expect(fs.existsSync(path.join(repositoryPath, "node_modules", "yaml"))).toBe(
        false,
      );
      expect(resolveWorkspaceYamlDependency(repositoryPath)).toBe(
        fs.realpathSync(storeYaml),
      );
    } finally {
      fs.rmSync(repositoryPath, { force: true, recursive: true });
    }
  });

  it("promotes only forward-moving semantic versions", () => {
    expect(compareSemanticVersions("0.1.0", "0.1.1")).toBe(-1);
    expect(compareSemanticVersions("0.1.1", "0.1.1")).toBe(0);
    expect(compareSemanticVersions("0.2.0", "0.1.1")).toBe(1);
    expect(compareSemanticVersions("1.0.0-beta.2", "1.0.0-beta.10")).toBe(-1);
    expect(compareSemanticVersions("1.0.0-beta", "1.0.0")).toBe(-1);
    expect(() => compareSemanticVersions("1.0.0-01", "1.0.0")).toThrow(
      /supported semantic version/u,
    );
  });

  it("binds npm registry install metadata to the exact packed manifest", () => {
    const expected = {
      name: "@actionproxy/mcp-wrapper",
      version: "0.1.1",
      type: "module",
      main: "dist/index.js",
      types: "dist/index.d.ts",
      exports: {
        ".": {
          import: "./dist/index.js",
          types: "./dist/index.d.ts",
        },
      },
      bin: { "actionproxy-mcp": "dist/index.js" },
      scripts: { build: "tsup", test: "vitest run" },
      dependencies: { yaml: "^2.5.1" },
      engines: { node: ">=22 <25" },
      files: ["dist"],
      license: "Apache-2.0",
      repository: {
        directory: "packages/mcp-wrapper",
        type: "git",
        url: "git+https://github.com/ActionProxy/actionproxy.git",
      },
    };
    const metadata = {
      ...structuredClone(expected),
      _id: "@actionproxy/mcp-wrapper@0.1.1",
      dist: { integrity: "sha512-placeholder" },
      maintainers: [{ name: "actionproxy" }],
    };
    expect(hasExactRegistryManifestMetadata(metadata, expected)).toBe(true);
    const normalized = structuredClone(metadata);
    delete normalized.files;
    normalized.directories = {};
    expect(hasExactRegistryManifestMetadata(normalized, expected)).toBe(true);
    expect(
      hasExactRegistryManifestMetadata(
        { ...structuredClone(metadata), files: ["lib"] },
        expected,
      ),
    ).toBe(false);
    expect(
      hasExactRegistryManifestMetadata(
        { ...structuredClone(normalized), directories: { lib: "dist" } },
        expected,
      ),
    ).toBe(false);
    expect(
      hasExactRegistryManifestMetadata(
        {
          ...structuredClone(metadata),
          dependencies: { yaml: "*" },
        },
        expected,
      ),
    ).toBe(false);
    expect(
      hasExactRegistryManifestMetadata(
        { ...structuredClone(metadata), hasInstallScript: true },
        expected,
      ),
    ).toBe(false);
    expect(
      hasExactRegistryManifestMetadata(
        { ...structuredClone(metadata), _hasShrinkwrap: true },
        expected,
      ),
    ).toBe(false);
    expect(
      hasExactRegistryManifestMetadata(
        { ...structuredClone(metadata), acceptDependencies: { yaml: "*" } },
        expected,
      ),
    ).toBe(false);
    expect(
      hasExactRegistryManifestMetadata(
        { ...structuredClone(metadata), bin: { other: "dist/index.js" } },
        expected,
      ),
    ).toBe(false);
    const missingTypes = structuredClone(metadata);
    delete missingTypes.types;
    expect(hasExactRegistryManifestMetadata(missingTypes, expected)).toBe(
      false,
    );
  });

  it("plans a resumable direct-latest publish without downgrade or replacement", () => {
    const absent = {
      exact: false,
      exists: false,
      packageExists: false,
      tags: {},
    };
    const exactLatest = {
      exact: true,
      exists: true,
      packageExists: true,
      tags: { latest: "0.1.2", next: "0.1.1" },
    };
    expect(
      planPublishLatestRegistryState([absent, absent], "0.1.2"),
    ).toEqual(["publish", "publish"]);
    expect(
      planPublishLatestRegistryState([exactLatest, absent], "0.1.2"),
    ).toEqual(["skip", "publish"]);
    expect(
      planPublishLatestRegistryState(
        [
          {
            ...absent,
            packageExists: true,
            tags: { latest: "0.1.1", next: "0.1.1" },
          },
          absent,
        ],
        "0.1.2",
      ),
    ).toEqual(["publish", "publish"]);
    expect(() =>
      planPublishLatestRegistryState(
        [{ ...exactLatest, exact: false }, absent],
        "0.1.2",
      ),
    ).toThrow(/outside the exact latest/u);
    expect(() =>
      planPublishLatestRegistryState(
        [{ ...exactLatest, tags: { latest: "0.1.1" } }, absent],
        "0.1.2",
      ),
    ).toThrow(/outside the exact latest/u);
    expect(() =>
      planPublishLatestRegistryState(
        [
          {
            ...absent,
            packageExists: true,
            tags: { latest: "0.1.2" },
          },
          absent,
        ],
        "0.1.2",
      ),
    ).toThrow(/replace or downgrade/u);
    expect(() =>
      planPublishLatestRegistryState(
        [
          {
            ...absent,
            packageExists: true,
            tags: { latest: "0.2.0" },
          },
          absent,
        ],
        "0.1.2",
      ),
    ).toThrow(/replace or downgrade/u);
    expect(() =>
      planPublishLatestRegistryState([absent, absent], "0.1.2-rc.1"),
    ).toThrow(/stable semantic version/u);
    expect(() =>
      planPublishLatestRegistryState(
        [{ ...absent, exact: true }, absent],
        "0.1.2",
      ),
    ).toThrow(/malformed/u);
  });

  it("parses safe npm tarballs and rejects path traversal, symlinks, and checksum drift", () => {
    const valid = npmTarball([
      { body: "license", mode: 0o644, name: "package/LICENSE" },
      { body: "readme", mode: 0o644, name: "package/README.md" },
      { body: "types", mode: 0o644, name: "package/dist/index.d.ts" },
      {
        body: "#!/usr/bin/env node\n",
        mode: 0o755,
        name: "package/dist/index.js",
      },
      { body: '{"name":"fixture"}', mode: 0o644, name: "package/package.json" },
    ]);
    expect(
      parseNpmTarball(valid).map(({ mode, path }) => ({ mode, path })),
    ).toEqual([
      { mode: 0o644, path: "LICENSE" },
      { mode: 0o644, path: "README.md" },
      { mode: 0o644, path: "dist/index.d.ts" },
      { mode: 0o755, path: "dist/index.js" },
      { mode: 0o644, path: "package.json" },
    ]);

    expect(() =>
      parseNpmTarball(
        npmTarball([{ body: "bad", mode: 0o644, name: "package/../secret" }]),
      ),
    ).toThrow(/unsafe path/u);
    expect(() =>
      parseNpmTarball(
        npmTarball([
          { body: "", mode: 0o777, name: "package/link", type: "2" },
        ]),
      ),
    ).toThrow(/unsupported entry type/u);

    expect(() =>
      parseNpmTarball(
        npmTarball([
          { body: "privileged", mode: 0o4755, name: "package/dist/index.js" },
        ]),
      ),
    ).toThrow(/unsupported permission bits/u);

    const padded = Buffer.from(
      gunzipSync(
        npmTarball([{ body: "x", mode: 0o644, name: "package/package.json" }]),
      ),
    );
    padded[513] = 1;
    expect(() => parseNpmTarball(gzipSync(padded))).toThrow(
      /nonzero entry padding/u,
    );

    const corrupted = Buffer.from(valid);
    // The helper deliberately accepts only gzip-compressed npm artifacts.
    const uncompressed = Buffer.from(gunzipSync(corrupted));
    uncompressed[0] ^= 1;
    expect(() => parseNpmTarball(gzipSync(uncompressed))).toThrow(
      /checksum mismatch/u,
    );

    const trailingData = Buffer.from(gunzipSync(valid));
    trailingData[trailingData.length - 1] = 1;
    expect(() => parseNpmTarball(gzipSync(trailingData))).toThrow(
      /data after its terminator/u,
    );
    expect(() =>
      parseNpmTarball(
        npmTarball([
          { body: "", mode: 0o755, name: "package/dist", type: "5" },
        ]),
      ),
    ).toThrow(/unsupported entry type/u);
  });
});

function npmTarball(entries) {
  const blocks = [];
  for (const entry of entries) {
    const body = Buffer.from(entry.body, "utf8");
    const header = Buffer.alloc(512);
    writeText(header, 0, 100, entry.name);
    writeOctal(header, 100, 8, entry.mode);
    writeOctal(header, 108, 8, 0);
    writeOctal(header, 116, 8, 0);
    writeOctal(header, 124, 12, body.length);
    writeOctal(header, 136, 12, 0);
    header.fill(32, 148, 156);
    header[156] = (entry.type ?? "0").charCodeAt(0);
    writeText(header, 257, 6, "ustar");
    writeText(header, 263, 2, "00");
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    writeOctal(header, 148, 8, checksum);
    blocks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

function writeText(buffer, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > length) throw new Error("fixture field is too long");
  bytes.copy(buffer, offset);
}

function writeOctal(buffer, offset, length, value) {
  const body = value.toString(8).padStart(length - 2, "0");
  writeText(buffer, offset, length, `${body}\0`);
}
