import { closePool, stopBoss } from "@unified-osint/core";
import { buildAppContext } from "./context.js";
import { buildServer } from "./server.js";

async function main(): Promise<void> {
  const appContext = await buildAppContext();
  const app = await buildServer(appContext);

  await app.listen({ host: appContext.env.API_HOST, port: appContext.env.API_PORT });
  appContext.logger.info({ port: appContext.env.API_PORT }, "api_started");

  const shutdown = async (signal: string): Promise<void> => {
    appContext.logger.info({ signal }, "api_shutting_down");
    await app.close();
    await stopBoss();
    await closePool();
    process.exit(0);
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  console.error("api_startup_failed", err);
  process.exit(1);
});
