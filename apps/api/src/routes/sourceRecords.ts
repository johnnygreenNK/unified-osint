import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { withAppContext, userContext, insertAuditLog, NotFoundError, ForbiddenError } from "@unified-osint/core";

const idParamsSchema = z.object({ id: z.string().uuid() });
const revealBodySchema = z.object({ field: z.enum(["password", "pass", "hash", "salt"]) });

interface SourceRecordRow {
  raw: Record<string, unknown> | null;
}

/**
 * Jedyna droga odslonienia nieprzemaskowanej wartosci (haslo/hash/sol) z
 * `source_records.raw`. Adaptery (patrz packages/adapters/src/snusbase.ts)
 * maskuja te pola w `attrs`, ktore plynie dalej do SSE/UI/Telegrama - pelna
 * wartosc istnieje tylko tutaj, za RLS i za dodatkowa brama ролi (analyst/
 * admin), z kazdym odslonieciem logowanym w audit_logs (append-only).
 */
export async function sourceRecordsRoutes(app: FastifyInstance): Promise<void> {
  const { pool } = app.appContext;

  app.post("/source-records/:id/reveal", { preHandler: app.authenticate }, async (request, reply) => {
    const { id } = idParamsSchema.parse(request.params);
    const body = revealBodySchema.parse(request.body);
    const user = request.currentUser!;

    if (user.role !== "admin" && user.role !== "analyst") {
      throw new ForbiddenError("Odslonienie danych wrazliwych wymaga roli analyst lub admin");
    }

    const result = await withAppContext(pool, userContext(user.id, user.role), (client) =>
      client.query<SourceRecordRow>("select raw from source_records where id = $1", [id])
    );
    const row = result.rows[0];
    if (!row) throw new NotFoundError("Rekord zrodlowy nie istnieje lub brak dostepu");

    const value = row.raw?.[body.field] ?? null;

    await insertAuditLog(pool, {
      actorId: user.id,
      action: "source_record.reveal",
      target: id,
      meta: { field: body.field },
    });

    reply.send({ value });
  });
}
