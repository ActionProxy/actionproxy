import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const actionProxyPort =
  process.env.ACTIONPROXY_E2E_SERVER_PORT ??
  process.env.ACTIONPROXY_PORT ??
  "8787";
const actionProxyProxyTarget = `http://127.0.0.1:${actionProxyPort}`;

export default defineConfig({
  plugins: [react()],
  publicDir: false,
  server: {
    proxy: {
      "/health": actionProxyProxyTarget,
      "/v1": actionProxyProxyTarget,
    },
  },
  test: {
    environment: "jsdom",
    include: [
      "src/App.test.tsx",
      "src/community-boundary.test.ts",
      "src/components/AgentDemoPanel.test.tsx",
      "src/components/Dashboard.community.test.tsx",
      "src/lib/actionproxy-client.test.ts",
    ],
    setupFiles: "./src/test-setup.ts",
  },
});
