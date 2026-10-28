import type { FastifyInstance } from "fastify";

export async function healthRoutes(app: FastifyInstance): Promise<void> {
  app.get("/health", async (_request, reply) => {
    try {
      await app.appContext.pool.query("select 1");
      reply.send({ status: "ok", db: "ok" });
    } catch (err) {
      reply.code(503).send({ status: "error", db: "unreachable", message: (err as Error).message });
    }
  });
}
