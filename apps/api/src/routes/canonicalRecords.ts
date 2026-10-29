import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { withAppContext, userContext, NotFoundError } from "@unified-osint/core";

const idParamsSchema = z.object({ id: z.string().uuid() });

interface RelatedRecordRow {
  id: string;
  kind: string;
  title: string;
  summary: string | null;
  first_seen: string;
  last_seen: string;
  source_count: number;
  shared_keys: string[];
}

/**
 * Korelacja tozsamosci miedzy rekordami kanonicznymi (patrz migracja 0008 i
 * packages/core/src/dedup/dedupEngine.ts) - NIGDY automatyczne scalenie,
 * tylko sugestia "te rekordy dzielily ten e-mail/IP/telefon/domene".
 */
export async function canonicalRecordsRoutes(app: FastifyInstance): Promise<void> {
  const { pool } = app.appContext;

  app.get("/canonical-records/:id/related", { preHandler: app.authenticate }, async (request, reply) => {
    const { id } = idParamsSchema.parse(request.params);
    const user = request.currentUser!;
    const ctx = userContext(user.id, user.role);

    const ownRecordRes = await withAppContext(pool, ctx, (client) =>
      client.query<{ id: string }>("select id from canonical_records where id = $1", [id])
    );
    if (ownRecordRes.rows.length === 0) throw new NotFoundError("Rekord kanoniczny nie istnieje lub brak dostepu");

    const relatedRes = await withAppContext(pool, ctx, (client) =>
      client.query<RelatedRecordRow>(
        `select
           cr.id,
           cr.kind,
           cr.title,
           cr.summary,
           cr.first_seen,
           cr.last_seen,
           cr.source_count,
           array_agg(distinct rck.key_type || ':' || rck.key_value) as shared_keys
         from record_correlation_keys mine
         join record_correlation_keys rck
           on rck.key_type = mine.key_type and rck.key_value = mine.key_value and rck.canonical_id <> mine.canonical_id
         join canonical_records cr on cr.id = rck.canonical_id
         where mine.canonical_id = $1
         group by cr.id, cr.kind, cr.title, cr.summary, cr.first_seen, cr.last_seen, cr.source_count
         order by cr.last_seen desc
         limit 50`,
        [id]
      )
    );

    reply.send({ related: relatedRes.rows });
  });
}
