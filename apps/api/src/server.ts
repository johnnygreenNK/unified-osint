import Fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import multipart from "@fastify/multipart";
import { z } from "zod";
import { AppError } from "@unified-osint/core";
import type { AppContext } from "./context.js";
import { authPlugin } from "./auth/plugin.js";
import { healthRoutes } from "./routes/health.js";
import { authRoutes } from "./routes/auth.js";
import { sourcesRoutes } from "./routes/sources.js";
import { searchesRoutes } from "./routes/searches.js";
import { sourceRecordsRoutes } from "./routes/sourceRecords.js";
import { canonicalRecordsRoutes } from "./routes/canonicalRecords.js";
import { importsRoutes } from "./routes/imports.js";

declare module "fastify" {
  interface FastifyInstance {
    appContext: AppContext;
  }
}

export async function buildServer(appContext: AppContext): Promise<FastifyInstance> {
  const app = Fastify({ logger: { level: appContext.env.LOG_LEVEL }, trustProxy: true });
  app.decorate("appContext", appContext);

  await app.register(cors, {
    origin: appContext.env.CORS_ALLOWED_ORIGINS,
    credentials: true,
  });
  await app.register(cookie);
  await app.register(multipart, { limits: { fileSize: 50 * 1024 * 1024 } });
  await app.register(authPlugin);

  app.setErrorHandler((err, request, reply) => {
    if (err instanceof z.ZodError) {
      reply.code(400).send({ error: "validation_error", issues: err.issues });
      return;
    }
    if (err instanceof AppError) {
      reply.code(err.httpStatus).send({ error: err.code, message: err.message });
      return;
    }
    request.log.error(err);
    reply.code(500).send({ error: "internal_error", message: "Wystapil nieoczekiwany blad" });
  });

  await app.register(healthRoutes);
  await app.register(authRoutes);
  await app.register(sourcesRoutes);
  await app.register(searchesRoutes);
  await app.register(sourceRecordsRoutes);
  await app.register(canonicalRecordsRoutes);
  await app.register(importsRoutes);

  return app;
}
