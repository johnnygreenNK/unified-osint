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

interface CanonicalRecordRow {
  id: string;
  kind: string;
  title: string;
  summary: string | null;
  attrs: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  source_count: number;
}

interface SourceRecordRow {
  id: string;
  source_id: string;
  source_record_id: string;
  url_canonical: string | null;
  observed_at: string;
  raw: Record<string, unknown> | null;
}

export async function canonicalRecordsRoutes(app: FastifyInstance): Promise<void> {
  const { pool } = app.appContext;

  // GET /canonical-records/:id — pełne dane rekordu kanonicznego + rekordy źródłowe
  // (łącznie z `raw`, bez maskowania — patrz decyzja uzytkownika w packages/adapters).
  app.get("/canonical-records/:id", { preHandler: app.authenticate }, async (request, reply) => {
    const { id } = idParamsSchema.parse(request.params);
    const user = request.currentUser!;
    const ctx = userContext(user.id, user.role);

    const canonRes = await withAppContext(pool, ctx, (client) =>
      client.query<CanonicalRecordRow>(
        `select id, kind, title, summary, attrs, first_seen, last_seen, source_count
         from canonical_records where id = $1`,
        [id]
      )
    );
    if (canonRes.rows.length === 0) throw new NotFoundError("Rekord kanoniczny nie istnieje lub brak dostepu");
    const canon = canonRes.rows[0]!;

    const srRes = await withAppContext(pool, ctx, (client) =>
      client.query<SourceRecordRow>(
        `select sr.id, sr.source_id, sr.source_record_id, sr.url_canonical, sr.observed_at, sr.raw
         from source_records sr
         join record_sources rs on rs.source_record_id = sr.id
         where rs.canonical_id = $1
         order by sr.observed_at desc`,
        [id]
      )
    );

    const sourceRecords = srRes.rows.map((sr) => ({
      id: sr.id,
      sourceId: sr.source_id,
      sourceRecordId: sr.source_record_id,
      urlCanonical: sr.url_canonical,
      observedAt: sr.observed_at,
      raw: sr.raw ?? {},
    }));

    reply.send({ ...canon, sourceRecords });
  });

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
