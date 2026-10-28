import { afterAll, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";

/**
 * Testy polityk RLS - wymagaja dzialajacej bazy z zastosowanymi migracjami.
 *
 *   docker compose up -d postgres
 *   DATABASE_URL=postgresql://osint_app:...@localhost:5432/unified_osint_test \
 *     node packages/db/scripts/migrate.mjs
 *   DATABASE_URL=... pnpm --filter @unified-osint/db test
 *
 * Kazdy test laczy sie od nowa i recznie ustawia app.user_id / app.role,
 * tak jak robi to warstwa `withAppContext` w @unified-osint/core - to
 * sprawdza polityki SQL, a nie kod aplikacji.
 */

const databaseUrl = process.env.DATABASE_URL;
const describeOrSkip = databaseUrl ? describe : describe.skip;

describeOrSkip("RLS: izolacja danych miedzy uzytkownikami", () => {
  const client = new pg.Client({ connectionString: databaseUrl });
  let userAId: string;
  let userBId: string;

  beforeAll(async () => {
    await client.connect();

    await setContext(client, null, "service");
    const resA = await client.query(
      `insert into users (email, password_hash, display_name, role) values ($1, 'x', 'User A', 'viewer') returning id`,
      [`rls-test-a-${Date.now()}@example.test`]
    );
    const resB = await client.query(
      `insert into users (email, password_hash, display_name, role) values ($1, 'x', 'User B', 'viewer') returning id`,
      [`rls-test-b-${Date.now()}@example.test`]
    );
    userAId = resA.rows[0].id;
    userBId = resB.rows[0].id;
  });

  afterAll(async () => {
    await setContext(client, null, "service");
    await client.query(`delete from users where id in ($1, $2)`, [userAId, userBId]);
    await client.end();
  });

  it("uzytkownik A nie widzi wlasnej historii jako user B", async () => {
    await setContext(client, userAId, "viewer");
    await client.query(
      `insert into searches (user_id, query_raw, query_type, query_norm, norm_version, source_ids)
       values ($1, 'example.com', 'domain', 'example.com', 1, array['demo'])`,
      [userAId]
    );

    await setContext(client, userBId, "viewer");
    const asB = await client.query(`select * from searches where user_id = $1`, [userAId]);
    expect(asB.rows).toHaveLength(0);

    await setContext(client, userAId, "viewer");
    const asA = await client.query(`select * from searches where user_id = $1`, [userAId]);
    expect(asA.rows.length).toBeGreaterThan(0);
  });

  it("admin widzi wyszukiwania innych uzytkownikow", async () => {
    await setContext(client, null, "admin");
    const asAdmin = await client.query(`select * from searches where user_id = $1`, [userAId]);
    expect(asAdmin.rows.length).toBeGreaterThan(0);
  });

  it("viewer nie moze wstawic wyszukiwania dla innego uzytkownika", async () => {
    await setContext(client, userBId, "viewer");
    await expect(
      client.query(
        `insert into searches (user_id, query_raw, query_type, query_norm, norm_version, source_ids)
         values ($1, 'other', 'text', 'other', 1, array['demo'])`,
        [userAId]
      )
    ).rejects.toThrow();
  });

  it("audit_logs jest tylko do odczytu dla admina i nie da sie go zmodyfikowac", async () => {
    await setContext(client, null, "service");
    await client.query(
      `insert into audit_logs (actor_id, action, target) values ($1, 'test.action', 'test-target')`,
      [userAId]
    );

    await setContext(client, userAId, "viewer");
    const asViewer = await client.query(`select * from audit_logs where actor_id = $1`, [userAId]);
    expect(asViewer.rows).toHaveLength(0); // viewer nie widzi audytu

    await setContext(client, null, "admin");
    const asAdmin = await client.query(`select * from audit_logs where actor_id = $1`, [userAId]);
    expect(asAdmin.rows.length).toBeGreaterThan(0);

    // Brak polityki UPDATE -> FORCE RLS daje domyslne USING (false) dla tej
    // komendy, wiec zapytanie nie rzuca bledu, ale nie dotyka zadnego wiersza
    // (nawet jako admin). To jest wlasciwa gwarancja: audyt jest append-only.
    const updateResult = await client.query(
      `update audit_logs set action = 'tampered' where actor_id = $1`,
      [userAId]
    );
    expect(updateResult.rowCount).toBe(0);

    const unchanged = await client.query(`select action from audit_logs where actor_id = $1`, [userAId]);
    expect(unchanged.rows.every((r) => r.action === "test.action")).toBe(true);
  });

  it("rekordy kanoniczne jednego uzytkownika sa niewidoczne dla drugiego", async () => {
    await setContext(client, userAId, "viewer");
    await client.query(
      `insert into canonical_records (owner_scope, owner_id, kind, canonical_key, title, norm_version)
       values ('user', $1, 'domain', 'example.com', 'example.com', 1)`,
      [userAId]
    );

    await setContext(client, userBId, "viewer");
    const asB = await client.query(`select * from canonical_records where owner_id = $1`, [userAId]);
    expect(asB.rows).toHaveLength(0);
  });
});

async function setContext(client: pg.Client, userId: string | null, role: string): Promise<void> {
  await client.query("select set_config('app.user_id', $1, false)", [userId ?? ""]);
  await client.query("select set_config('app.role', $1, false)", [role]);
}
