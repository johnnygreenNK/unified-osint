#!/usr/bin/env node
// UnifiedOSINT - prosty, zaleznosciowy runner migracji SQL.
// Brak ORM: migracje to pliki .sql w packages/db/migrations, stosowane w
// porzadku alfabetycznym (prefiks 0001_, 0002_, ...). Zastosowane migracje
// sa zapisywane w tabeli `_migrations` (tworzonej przez migracje 0001).
//
// Uzycie:
//   node --env-file=.env packages/db/scripts/migrate.mjs
// W Docker Compose zmienne sa juz w env procesu, --env-file niepotrzebny.

import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const { Client } = pg;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.join(__dirname, "..", "migrations");

async function main() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error("Brak DATABASE_URL w zmiennych srodowiskowych. Przerywam.");
    process.exit(1);
  }

  const client = new Client({ connectionString: databaseUrl });
  await client.connect();

  try {
    const files = (await readdir(migrationsDir)).filter((f) => f.endsWith(".sql")).sort();

    // Migracja 0001 tworzy _migrations - jesli tabela jeszcze nie istnieje,
    // pierwsza iteracja i tak ja zastosuje (ON CONFLICT nie jest potrzebny,
    // bo dopiero po jej wykonaniu sprawdzamy _migrations dla kolejnych).
    let appliedIds = new Set();
    const hasMigrationsTable = await client.query(
      `select exists (select 1 from information_schema.tables where table_name = '_migrations') as exists`
    );
    if (hasMigrationsTable.rows[0].exists) {
      const applied = await client.query(`select id from _migrations`);
      appliedIds = new Set(applied.rows.map((r) => r.id));
    }

    for (const file of files) {
      if (appliedIds.has(file)) {
        console.log(`[skip]  ${file} (juz zastosowana)`);
        continue;
      }
      const sql = await readFile(path.join(migrationsDir, file), "utf8");
      console.log(`[apply] ${file}`);
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query(`insert into _migrations (id) values ($1) on conflict do nothing`, [file]);
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK");
        console.error(`[error] Migracja ${file} nie powiodla sie:`, err.message);
        throw err;
      }
    }

    console.log("Wszystkie migracje zastosowane.");
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
