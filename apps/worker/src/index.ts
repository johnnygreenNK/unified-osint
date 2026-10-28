import {
  loadEnv,
  getPool,
  getBoss,
  stopBoss,
  closePool,
  createLogger,
  syncSourcesFromRegistry,
  CircuitBreaker,
  SEARCH_TASK_QUEUE,
  processSearchTaskJob,
  type SearchTaskJobData,
} from "@unified-osint/core";
import { createDefaultRegistry } from "@unified-osint/adapters";

async function main(): Promise<void> {
  const env = loadEnv();
  const logger = createLogger("worker", env.LOG_LEVEL);
  const pool = getPool(env.DATABASE_URL);
  const boss = await getBoss(env.DATABASE_URL, env.WORKER_PG_SCHEMA);
  const registry = createDefaultRegistry();
  const circuitBreaker = new CircuitBreaker();

  await syncSourcesFromRegistry(pool, registry);

  await boss.work<SearchTaskJobData>(
    SEARCH_TASK_QUEUE,
    { batchSize: env.WORKER_CONCURRENCY, pollingIntervalSeconds: 1 },
    async (jobs) => {
      for (const job of jobs) {
        try {
          await processSearchTaskJob(job.data, {
            pool,
            boss,
            registry,
            circuitBreaker,
            logger,
            defaultTimeoutMs: env.DEFAULT_ADAPTER_TIMEOUT_MS,
          });
        } catch (err) {
          // processSearchTaskJob zawsze obsluguje bledy wewnetrznie i nie rzuca -
          // ten catch to ostatnia linia obrony, aby jeden zly job nigdy nie
          // zatrzymal petli workera dla pozostalych zadan w partii.
          logger.error({ err, jobId: job.id }, "unexpected_task_runner_crash");
        }
      }
    }
  );

  logger.info({ concurrency: env.WORKER_CONCURRENCY }, "worker_started");

  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, "worker_shutting_down");
    await stopBoss();
    await closePool();
    process.exit(0);
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  console.error("worker_startup_failed", err);
  process.exit(1);
});
