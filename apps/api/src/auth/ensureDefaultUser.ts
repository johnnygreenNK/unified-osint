import { randomBytes } from "node:crypto";
import type { Pool } from "pg";
import { withAppContext, serviceContext } from "@unified-osint/core";
import { hashPassword } from "./password.js";

/**
 * Tryb jednego konta: jesli w bazie nie ma jeszcze zadnego uzytkownika,
 * tworzy domyslne konto z rola 'admin' (lokalne narzedzie jednoosobowe -
 * pelny dostep bez recznego nadawania roli). Haslo jest losowe i
 * nieujawniane nigdzie - logowanie odbywa sie przez POST /auth/auto-login
 * (dziala tylko, gdy w systemie jest dokladnie jedno konto), nie przez haslo.
 */
export async function ensureDefaultUser(
  pool: Pool,
  env: { AUTH_ARGON2_MEMORY_KB: number; DEFAULT_USER_EMAIL: string; DEFAULT_USER_DISPLAY_NAME: string }
): Promise<void> {
  await withAppContext(pool, serviceContext(), async (client) => {
    const existing = await client.query<{ count: string }>("select count(*)::text as count from users");
    if (Number(existing.rows[0]?.count ?? "0") > 0) return;

    const randomPassword = randomBytes(32).toString("hex");
    const passwordHash = await hashPassword(randomPassword, env.AUTH_ARGON2_MEMORY_KB);
    await client.query(
      `insert into users (email, password_hash, display_name, role) values ($1, $2, $3, 'admin')`,
      [env.DEFAULT_USER_EMAIL.toLowerCase(), passwordHash, env.DEFAULT_USER_DISPLAY_NAME]
    );
  });
}
