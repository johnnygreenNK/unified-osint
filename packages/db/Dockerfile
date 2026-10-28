# UnifiedOSINT - runner migracji SQL. Lekki obraz, bez pnpm/workspace -
# `migrate.mjs` zalezy wylacznie od pakietu `pg`.
FROM node:20-alpine

WORKDIR /app

COPY packages/db/package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY packages/db/migrations ./migrations
COPY packages/db/scripts ./scripts

CMD ["node", "scripts/migrate.mjs"]
