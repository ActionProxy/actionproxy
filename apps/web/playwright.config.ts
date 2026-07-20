import { defineConfig, devices } from "@playwright/test";
import { tmpdir } from "node:os";
import { join } from "node:path";

const serverPort = process.env.ACTIONPROXY_E2E_SERVER_PORT ?? "8787";
const webPort = process.env.ACTIONPROXY_E2E_WEB_PORT ?? "5173";
const runId = process.env.ACTIONPROXY_E2E_RUN_ID ?? String(process.pid);
const inheritedEnvironment = Object.fromEntries(
  Object.entries(process.env).filter(
    (entry): entry is [string, string] => typeof entry[1] === "string",
  ),
);

export default defineConfig({
  expect: { timeout: 10_000 },
  reporter: [["list"], ["html", { open: "never" }]],
  testDir: "./tests/e2e",
  testMatch: "community.spec.ts",
  workers: 1,
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: [
    {
      command:
        "corepack pnpm --filter @actionproxy/server exec node --import tsx src/index.ts",
      env: {
        ...inheritedEnvironment,
        ACTIONPROXY_DATA_DIR: join(
          tmpdir(),
          `actionproxy-community-e2e-${serverPort}-${runId}`,
        ),
        ACTIONPROXY_HOST: "127.0.0.1",
        ACTIONPROXY_LOCAL_EXECUTION: "mock",
        ACTIONPROXY_PORT: serverPort,
        TMPDIR: tmpdir(),
      },
      reuseExistingServer: process.env.ACTIONPROXY_E2E_REUSE_SERVER === "1",
      timeout: 30_000,
      url: `http://127.0.0.1:${serverPort}/health`,
    },
    {
      command: `corepack pnpm --filter @actionproxy/web exec vite --host 127.0.0.1 --port ${webPort}`,
      env: inheritedEnvironment,
      reuseExistingServer: process.env.ACTIONPROXY_E2E_REUSE_SERVER === "1",
      timeout: 30_000,
      url: `http://127.0.0.1:${webPort}`,
    },
  ],
  projects: [
    {
      name: "desktop",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { height: 900, width: 1440 },
      },
    },
    {
      name: "mobile",
      use: {
        ...devices["Desktop Chrome"],
        hasTouch: true,
        viewport: { height: 727, width: 393 },
      },
    },
  ],
});
