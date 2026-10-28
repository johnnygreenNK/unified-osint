import type { FastifyInstance } from "fastify";
import { withAppContext, userContext } from "@unified-osint/core";

interface SourceRow {
  id: string;
  name: string;
  category: string;
  status: string;
  adapter_version: string;
  cost_info: Record<string, unknown>;
  last_ok_at: string | null;
  last_error_code: string | null;
}

export async function sourcesRoutes(app: FastifyInstance): Promise<void> {
  const { pool } = app.appContext;

  app.get("/sources", { preHandler: app.authenticate }, async (request, reply) => {
    const user = request.currentUser!;
    const result = await withAppContext(pool, userContext(user.id, user.role), (client) =>
      client.query<SourceRow>(
        `select id, name, category, status, adapter_version, cost_info, last_ok_at, last_error_code
         from sources order by category, id`
      )
    );
    reply.send({ sources: result.rows });
  });
}
