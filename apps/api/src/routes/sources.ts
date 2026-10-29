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
  const { pool, registry } = app.appContext;

  app.get("/sources", { preHandler: app.authenticate }, async (request, reply) => {
    const user = request.currentUser!;
    const result = await withAppContext(pool, userContext(user.id, user.role), (client) =>
      client.query<SourceRow>(
        `select id, name, category, status, adapter_version, cost_info, last_ok_at, last_error_code
         from sources order by category, id`
      )
    );
    // queryTypes nie jest w DB - to statyczna wlasciwosc kodu adaptera (descriptor.capabilities),
    // potrzebna w UI do filtrowania, ktore zrodla maja sens dla wybranego typu zapytania.
    const sources = result.rows.map((row) => ({
      ...row,
      queryTypes: registry.get(row.id)?.descriptor.capabilities.map((c) => c.queryType) ?? [],
    }));
    reply.send({ sources });
  });
}
