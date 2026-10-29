import type { Pool } from "pg";
import type PgBoss from "pg-boss";
import {
  loadEnv,
  getPool,
  getBoss,
  createLogger,
  syncSourcesFromRegistry,
  SearchOrchestrator,
  type Env,
  type Logger,
} from "@unified-osint/core";
import { createDefaultRegistry, type StaticAdapterRegistry } from "@unified-osint/adapters";
import { ensureDefaultUser } from "./auth/ensureDefaultUser.js";

export interface AppContext {
  env: Env;
  logger: Logger;
  pool: Pool;
  boss: PgBoss;
  registry: StaticAdapterRegistry;
  orchestrator: SearchOrchestrator;
}

export async function buildAppContext(): Promise<AppContext> {
  const env = loadEnv();
  const logger = createLogger("api", env.LOG_LEVEL);
  const pool = getPool(env.DATABASE_URL);
  const boss = await getBoss(env.DATABASE_URL, env.WORKER_PG_SCHEMA);
  const registry = createDefaultRegistry(env, pool);

  await syncSourcesFromRegistry(pool, registry);
  await ensureDefaultUser(pool, env);

  const orchestrator = new SearchOrchestrator(
    pool,
    boss,
    registry,
    {
      maxSourcesPerSearch: env.MAX_SOURCES_PER_SEARCH,
      maxConcurrentSearchesPerUser: env.MAX_CONCURRENT_SEARCHES_PER_USER,
      globalSearchBudgetPerDay: env.GLOBAL_SEARCH_BUDGET_PER_DAY,
      defaultAdapterTimeoutMs: env.DEFAULT_ADAPTER_TIMEOUT_MS,
    },
    logger
  );

  return { env, logger, pool, boss, registry, orchestrator };
}
