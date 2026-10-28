# UnifiedOSINT - panel WWW (Next.js). Budowane z korzenia monorepo, bo
# instalacja pnpm wymaga calego workspace do spelnienia lockfile. Brak
# output: "standalone" (jego krok trace-copy uzywa symlinkow, co nie dziala
# pod Windowsem bez uprawnien administratora) - runtime kopiuje pelny
# node_modules i odpala `next start`, tak jak api/worker kopiuja dist.
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
COPY apps/web apps/web
ARG NEXT_PUBLIC_API_URL=http://localhost:4000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
RUN pnpm --filter @unified-osint/web build

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=build /repo/node_modules ./node_modules
COPY --from=build /repo/package.json ./package.json
COPY --from=build /repo/pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY --from=build /repo/apps/web apps/web

WORKDIR /repo/apps/web
EXPOSE 3000
CMD ["../../node_modules/.bin/next", "start", "-p", "3000"]
