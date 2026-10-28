import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { withAppContext, userContext, QUERY_TYPES, NotFoundError } from "@unified-osint/core";

const startSearchSchema = z.object({
  query: z.string().min(1),
  queryType: z.enum(QUERY_TYPES).optional(),
  sourceIds: z.array(z.string()).optional(),
});

const idParamsSchema = z.object({ id: z.string().uuid() });

interface SearchEventRow {
  id: string;
  type: string;
  payload: Record<string, unknown>;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function searchesRoutes(app: FastifyInstance): Promise<void> {
  const { pool, orchestrator } = app.appContext;

  app.post("/searches", { preHandler: app.authenticate }, async (request, reply) => {
    const body = startSearchSchema.parse(request.body);
    const user = request.currentUser!;
    const result = await orchestrator.startSearch({
      userId: user.id,
      userRole: user.role,
      rawQuery: body.query,
      queryType: body.queryType,
      sourceIds: body.sourceIds,
    });
    reply.code(201).send(result);
  });

  app.get("/searches", { preHandler: app.authenticate }, async (request, reply) => {
    const user = request.currentUser!;
    const result = await withAppContext(pool, userContext(user.id, user.role), (client) =>
      client.query(
        `select id, query_raw, query_type, has_wildcards, status, partial, source_ids, created_at, completed_at
         from searches where user_id = $1 order by created_at desc limit 50`,
        [user.id]
      )
    );
    reply.send({ searches: result.rows });
  });

  app.get("/searches/:id", { preHandler: app.authenticate }, async (request, reply) => {
    const { id } = idParamsSchema.parse(request.params);
    const user = request.currentUser!;
    const searchRes = await withAppContext(pool, userContext(user.id, user.role), (client) =>
      client.query(
        `select id, query_raw, query_type, has_wildcards, status, partial, source_ids, created_at, started_at, completed_at
         from searches where id = $1`,
        [id]
      )
    );
    const search = searchRes.rows[0];
    if (!search) throw new NotFoundError("Wyszukiwanie nie istnieje lub brak dostepu");

    const tasksRes = await withAppContext(pool, userContext(user.id, user.role), (client) =>
      client.query(
        `select source_id, status, error_code, error_message, latency_ms, result_count, attempt
         from search_tasks where search_id = $1 order by source_id`,
        [id]
      )
    );
    reply.send({ search, tasks: tasksRes.rows });
  });

  app.post("/searches/:id/cancel", { preHandler: app.authenticate }, async (request, reply) => {
    const { id } = idParamsSchema.parse(request.params);
    const user = request.currentUser!;
    await orchestrator.cancelSearch(id, user.id, user.role);
    reply.send({ ok: true });
  });

  app.get("/searches/:id/events", { preHandler: app.authenticate }, async (request, reply) => {
    const { id } = idParamsSchema.parse(request.params);
    const user = request.currentUser!;
    const ctx = userContext(user.id, user.role);

    const searchRes = await withAppContext(pool, ctx, (client) =>
      client.query<{ id: string }>("select id from searches where id = $1", [id])
    );
    if (searchRes.rows.length === 0) throw new NotFoundError("Wyszukiwanie nie istnieje lub brak dostepu");

    reply.hijack();
    // reply.hijack() przejmuje surowa odpowiedz z pominieciem potoku Fastify,
    // wiec naglowki CORS dodawane normalnie przez @fastify/cors (onRequest hook
    // pluginu) nigdy nie trafiaja do odpowiedzi - trzeba je dolozyc recznie,
    // inaczej przegladarka blokuje polaczenie EventSource({withCredentials:true}).
    const origin = request.headers.origin;
    const corsHeaders: Record<string, string> = {};
    if (origin && app.appContext.env.CORS_ALLOWED_ORIGINS.includes(origin)) {
      corsHeaders["Access-Control-Allow-Origin"] = origin;
      corsHeaders["Access-Control-Allow-Credentials"] = "true";
      corsHeaders["Vary"] = "Origin";
    }
    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      ...corsHeaders,
    });
    reply.raw.write(":connected\n\n");

    const sendEvent = (row: SearchEventRow): void => {
      reply.raw.write(`id: ${row.id}\nevent: ${row.type}\ndata: ${JSON.stringify(row.payload)}\n\n`);
    };

    const lastEventIdHeader = request.headers["last-event-id"];
    let lastId = typeof lastEventIdHeader === "string" ? lastEventIdHeader : "0";

    let closed = false;
    request.raw.on("close", () => {
      closed = true;
    });

    const POLL_INTERVAL_MS = 500;
    const HEARTBEAT_EVERY_MS = 15_000;
    let sinceHeartbeat = 0;

    while (!closed) {
      const eventsRes = await withAppContext(pool, ctx, (client) =>
        client.query<SearchEventRow>(
          `select id::text, type, payload from search_events where search_id = $1 and id > $2::bigint order by id asc`,
          [id, lastId]
        )
      );

      let reachedEnd = false;
      for (const row of eventsRes.rows) {
        sendEvent(row);
        lastId = row.id;
        if (row.type === "search.completed") reachedEnd = true;
      }
      if (reachedEnd) break;

      sinceHeartbeat += POLL_INTERVAL_MS;
      if (sinceHeartbeat >= HEARTBEAT_EVERY_MS) {
        reply.raw.write(":heartbeat\n\n");
        sinceHeartbeat = 0;
      }

      await delay(POLL_INTERVAL_MS);
    }

    if (!closed) reply.raw.end();
  });
}
