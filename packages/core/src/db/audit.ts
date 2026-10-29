import type { Pool } from "pg";
import { withAppContext, serviceContext } from "./pool.js";

export interface AuditLogEntry {
  actorId: string | null;
  action: string;
  target?: string | null;
  meta?: Record<string, unknown>;
}

/**
 * Append-only wpis w audit_logs (migracja 0006). Zawsze przez serviceContext,
 * bo polityka insert wymaga roli 'service'/privileged - zwykly uzytkownik nie
 * moze pisac do wlasnego audytu. Wolajacy musi sam upewnic sie, ze wywoluje
 * to PO wykonaniu akcji wrazliwej (reveal, podglad korelacji), nie przed.
 */
export async function insertAuditLog(pool: Pool, entry: AuditLogEntry): Promise<void> {
  await withAppContext(pool, serviceContext(), (client) =>
    client.query(
      `insert into audit_logs (actor_id, action, target, meta) values ($1, $2, $3, $4)`,
      [entry.actorId, entry.action, entry.target ?? null, JSON.stringify(entry.meta ?? {})]
    )
  );
}
