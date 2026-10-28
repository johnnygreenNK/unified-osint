# UnifiedOSINT - worker (pg-boss). Budowane z korzenia monorepo, jak apps/api/Dockerfile.
FROM node:20-alpine AS base
RUN corepack enable
WORKDIR /repo

FROM base AS deps
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY packages/core/package.json packages/core/package.json
COPY packages/adapters/package.json packages/adapters/package.json
COPY packages/db/package.json packages/db/package.json
COPY apps/api/package.json apps/api/package.json
COPY apps/worker/package.json apps/worker/package.json
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY packages/core packages/core
COPY packages/adapters packages/adapters
COPY apps/worker apps/worker
RUN pnpm --filter @unified-osint/core build \
 && pnpm --filter @unified-osint/adapters build \
 && pnpm --filter @unified-osint/worker build

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=build /repo/node_modules ./node_modules
COPY --from=build /repo/package.json ./package.json
COPY --from=build /repo/pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY --from=build /repo/packages/core packages/core
COPY --from=build /repo/packages/adapters packages/adapters
COPY --from=build /repo/apps/worker apps/worker

WORKDIR /repo/apps/worker
CMD ["node", "dist/index.js"]
