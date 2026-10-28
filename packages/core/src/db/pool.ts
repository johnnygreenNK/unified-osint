import { Pool, type PoolClient } from "pg";

let sharedPool: Pool | undefined;

export function getPool(databaseUrl: string): Pool {
  if (!sharedPool) {
    sharedPool = new Pool({ connectionString: databaseUrl, max: 10 });
  }
  return sharedPool;
}

export async function closePool(): Promise<void> {
  if (sharedPool) {
    await sharedPool.end();
    sharedPool = undefined;
  }
}

export type AppRole = "admin" | "analyst" | "viewer" | "service";

export interface AppContext {
  userId: string | null;
  role: AppRole;
}

/**
 * Wykonuje `fn` w transakcji z ustawionymi zmiennymi sesyjnymi `app.user_id`
 * i `app.role`, na ktorych opierajaj sie wszystkie polityki RLS. To JEDYNY
 * dozwolony sposob wykonywania zapytan dotykajacych tabel z RLS - nigdy nie
 * pobieraj klienta z poola bezposrednio dla zapytan uzytkownika.
 */
export async function withAppContext<T>(
  pool: Pool,
  ctx: AppContext,
  fn: (client: PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.user_id', $1, true)", [ctx.userId ?? ""]);
    await client.query("SELECT set_config('app.role', $1, true)", [ctx.role]);
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

/** Kontekst systemowy (service) - do uzycia wylacznie przez zaufany kod backendu. */
export function serviceContext(): AppContext {
  return { userId: null, role: "service" };
}

export function userContext(userId: string, role: Exclude<AppRole, "service">): AppContext {
  return { userId, role };
}
