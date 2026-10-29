import type { FastifyInstance } from "fastify";
import {
  withAppContext,
  userContext,
  insertAuditLog,
  ForbiddenError,
  ValidationError,
  parseCsv,
  parseSqlDump,
  extractFields,
} from "@unified-osint/core";

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024; // 50 MB
const MAX_ROWS_PER_IMPORT = 200_000;
const INSERT_BATCH_SIZE = 500;

interface ExtractedRow {
  attrs: Record<string, string | null>;
  email: string | null;
  username: string | null;
  ip: string | null;
  phone: string | null;
  domain: string | null;
}

function rowsFromCsv(content: string): ExtractedRow[] {
  const { rows } = parseCsv(content);
  return rows.map((row) => ({ attrs: row, ...extractFields(row) }));
}

function rowsFromSql(content: string): ExtractedRow[] {
  const tables = parseSqlDump(content);
  const rows: ExtractedRow[] = [];
  for (const table of tables) {
    for (const row of table.rows) {
      rows.push({ attrs: row, ...extractFields(row) });
    }
  }
  return rows;
}

/**
 * Import wlasnych dumpow danych (CSV/SQL) - logika parsowania inspirowana
 * githubesson/csves (CSV) i githubesson/sqlparser (SQL INSERT), przepisana
 * na TS (packages/core/src/imports/) bez zaleznosci od Elasticsearch/Go.
 * Wiersze trafiaja do `local_import_records` (RLS: tylko wlasciciel), a
 * adapter 'local_import' przeszukuje je jak kazde inne zrodlo.
 */
export async function importsRoutes(app: FastifyInstance): Promise<void> {
  const { pool } = app.appContext;

  app.post("/imports", { preHandler: app.authenticate }, async (request, reply) => {
    const user = request.currentUser!;
    if (user.role !== "admin" && user.role !== "analyst") {
      throw new ForbiddenError("Import wlasnych danych wymaga roli analyst lub admin");
    }

    const file = await request.file({ limits: { fileSize: MAX_UPLOAD_BYTES } });
    if (!file) throw new ValidationError("Brak przeslanego pliku");

    const filename = file.filename;
    const lower = filename.toLowerCase();
    const format: "csv" | "sql" = lower.endsWith(".sql") ? "sql" : "csv";

    const buffer = await file.toBuffer();
    const content = buffer.toString("utf8");

    const parsed = format === "sql" ? rowsFromSql(content) : rowsFromCsv(content);
    if (parsed.length === 0) {
      throw new ValidationError("Nie znaleziono zadnych wierszy w pliku - sprawdz format");
    }

    const rows = parsed.slice(0, MAX_ROWS_PER_IMPORT);
    const skippedCount = parsed.length - rows.length;

    const ctx = userContext(user.id, user.role);
    const batchId = await withAppContext(pool, ctx, async (client) => {
      const batchRes = await client.query<{ id: string }>(
        `insert into import_batches (owner_id, filename, format, row_count, skipped_count)
         values ($1, $2, $3, $4, $5) returning id`,
        [user.id, filename, format, rows.length, skippedCount]
      );
      const id = batchRes.rows[0]!.id;

      for (let i = 0; i < rows.length; i += INSERT_BATCH_SIZE) {
        const chunk = rows.slice(i, i + INSERT_BATCH_SIZE);
        const values: unknown[] = [];
        const placeholders: string[] = [];
        chunk.forEach((row, idx) => {
          const base = idx * 8;
          placeholders.push(
            `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}, $${base + 7}, $${base + 8})`
          );
          values.push(
            user.id,
            id,
            row.email,
            row.username,
            row.ip,
            row.phone,
            row.domain,
            JSON.stringify(row.attrs)
          );
        });
        await client.query(
          `insert into local_import_records (owner_id, batch_id, email, username, ip, phone, domain, attrs)
           values ${placeholders.join(", ")}`,
          values
        );
      }

      return id;
    });

    await insertAuditLog(pool, {
      actorId: user.id,
      action: "import.upload",
      target: batchId,
      meta: { filename, format, rowCount: rows.length, skippedCount },
    });

    reply.code(201).send({ batchId, filename, format, rowCount: rows.length, skippedCount });
  });

  app.get("/imports", { preHandler: app.authenticate }, async (request, reply) => {
    const user = request.currentUser!;
    const result = await withAppContext(pool, userContext(user.id, user.role), (client) =>
      client.query(
        `select id, filename, format, row_count, skipped_count, created_at
         from import_batches order by created_at desc limit 50`
      )
    );
    reply.send({ batches: result.rows });
  });
}
