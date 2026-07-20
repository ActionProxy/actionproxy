FROM node:24-bookworm-slim AS build

WORKDIR /app
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/server/package.json apps/server/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/mcp-wrapper/package.json packages/mcp-wrapper/package.json
COPY packages/sdk-js/package.json packages/sdk-js/package.json

RUN corepack pnpm install --frozen-lockfile

COPY . .
RUN corepack pnpm --filter @actionproxy/sdk-js build
RUN corepack pnpm --filter @actionproxy/mcp-wrapper build
RUN corepack pnpm --filter @actionproxy/web build
RUN corepack pnpm --filter @actionproxy/server build
RUN corepack pnpm --filter @actionproxy/server deploy --prod --legacy /prod/server
RUN corepack pnpm --filter @actionproxy/mcp-wrapper deploy --prod --legacy /prod/mcp-wrapper

FROM node:24-bookworm-slim AS runtime

WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends sqlite3 \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /data \
  && chown node:node /data
ENV NODE_ENV=production
ENV ACTIONPROXY_DATA_DIR=/data
ENV ACTIONPROXY_HOST=0.0.0.0
ENV ACTIONPROXY_LOCAL_EXECUTION=mock
ENV ACTIONPROXY_POLICY_PATH=apps/server/src/policies/default.policy.yaml
ENV ACTIONPROXY_PORT=8787
ENV ACTIONPROXY_STORAGE=memory
ENV ACTIONPROXY_WEB_DIST_PATH=apps/web/dist

COPY --from=build /app/apps/server/dist ./apps/server/dist
COPY --from=build /prod/server/node_modules ./apps/server/node_modules
COPY --from=build /prod/server/package.json ./apps/server/package.json
COPY --from=build /app/apps/server/src/policies ./apps/server/src/policies
COPY --from=build /app/apps/server/src/storage/migrations ./apps/server/src/storage/migrations
COPY --from=build /app/apps/web/dist ./apps/web/dist
COPY --from=build /app/packages/mcp-wrapper/dist ./packages/mcp-wrapper/dist
COPY --from=build /prod/mcp-wrapper/node_modules ./packages/mcp-wrapper/node_modules
COPY --from=build /prod/mcp-wrapper/package.json ./packages/mcp-wrapper/package.json
COPY --from=build /app/examples/chatgpt-tunnel/actionproxy.mcp.yaml ./examples/chatgpt-tunnel/actionproxy.mcp.yaml
COPY --from=build /app/examples/mcp-demo/server.mjs ./examples/mcp-demo/server.mjs

VOLUME ["/data"]
EXPOSE 8787

USER node
CMD ["node", "apps/server/dist/index.js"]
