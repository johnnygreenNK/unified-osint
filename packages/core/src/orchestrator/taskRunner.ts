import type PgBoss from "pg-boss";
import type { Pool } from "pg";
import { buildSearchQuery, type QueryType } from "../contracts/query.js";
import type { AdapterRegistry } from "../contracts/registry.js";
import type { SearchContext } from "../contracts/adapter.js";
import { withAppContext, userContext, serviceContext } from "../db/pool.js";
import { upsertNormalizedRecord } from "../dedup/dedupEngine.js";
import { CircuitBreaker } from "./circuitBreaker.js";
import { classifyHttpError, classifyNetworkError, computeBackoffWithJitter, MAX_RETRY_ATTEMPTS } from "./retry.js";
import { enqueueSearchTask, type SearchTaskJobData } from "./queue.js";
import type { Logger } from "../logger.js";
import type { UserRole } from "./searchOrchestrator.js";

export interface TaskRunnerDeps {
  pool: Pool;
  boss: PgBoss;
  registry: AdapterRegistry;
  circuitBreaker: CircuitBreaker;
  logger: Logger;
  defaultTimeoutMs: number;
}

/** Blad z klasyfikacja HTTP - adaptery rzucaja to, aby taskRunner wiedzial, czy ponowic. */
export class AdapterHttpError extends Error {
  constructor(message: string, public readonly status: number, public readonly retryAfterHeader?: string | null) {
    super(message);
    this.name = "AdapterHttpError";
  }
}

/**
 * Handler jednego zadania wyszukiwania w jednym zrodle. Wywolywany przez
 * `boss.work(SEARCH_TASK_QUEUE, ...)` w apps/worker. Blad jednego zrodla
 * NIE propaguje sie poza ten task - zawsze konczy sie aktualizacja statusu
 * w bazie, nigdy nieobsluzonym wyjatkiem, ktory zatrzymalby inne zadania.
 */
export async function processSearchTaskJob(data: SearchTaskJobData, deps: TaskRunnerDeps): Promise<void> {
  const { taskId, searchId, sourceId, userId, userRole, queryRaw, queryType, correlationId } = data;
  const log = deps.logger.child({ searchId, taskId, sourceId, correlationId });

  const adapter = deps.registry.get(sourceId);
  if (!adapter) {
    await finalizeTask(deps, data, { status: "failed", errorCode: "adapter_not_registered", errorMessage: "Adapter nieznany rejestrowi" });
    await maybeFinalizeSearch(deps, searchId);
    return;
  }

  const stillActive = await isSearchStillActive(deps.pool, searchId);
  if (!stillActive) {
    await finalizeTask(deps, data, { status: "cancelled" });
    return;
  }

  if (!deps.circuitBreaker.canAttempt(sourceId)) {
    log.warn("circuit_open - pomijam zadanie");
    await finalizeTask(deps, data, {
      status: "failed",
      errorCode: "circuit_open",
      errorMessage: "Adapter tymczasowo wylaczony po serii bledow (circuit breaker)",
    });
    await maybeFinalizeSearch(deps, searchId);
    return;
  }

  const attempt = await markTaskRunning(deps.pool, taskId);
  const timeoutMs = adapter.descriptor.timeoutMs ?? deps.defaultTimeoutMs;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = Date.now();

  let resultCount = 0;
  try {
    const query = buildSearchQuery(queryRaw, queryType as QueryType);
    const context: SearchContext = {
      searchId,
      userId,
      userRole,
      correlationId,
      signal: controller.signal,
      timeoutMs,
      logger: log,
    };

    for await (const record of adapter.search(query, context)) {
      if (controller.signal.aborted) break;

      const outcome = await withAppContext(deps.pool, userContext(userId, userRole), (client) =>
        upsertNormalizedRecord(client, { ownerId: userId, sourceId, searchId, record })
      );
      resultCount++;

      await emitEvent(
        deps.pool,
        searchId,
        outcome.isNewLink && outcome.sourceCount === 1 ? "result.added" : "result.merged",
        {
          canonicalRecordId: outcome.canonicalId,
          sourceId,
          kind: record.kind,
          title: record.title,
          sourceCount: outcome.sourceCount,
        }
      );
    }

    clearTimeout(timer);
    deps.circuitBreaker.recordSuccess(sourceId);
    await updateSourceHealth(deps.pool, sourceId, { ok: true });

    const latencyMs = Date.now() - startedAt;
    await finalizeTask(deps, data, { status: "succeeded", resultCount, latencyMs });
    await emitEvent(deps.pool, searchId, "task.status", {
      taskId,
      sourceId,
      status: "succeeded",
      latencyMs,
      resultCount,
      errorCode: null,
    });
  } catch (err) {
    clearTimeout(timer);
    deps.circuitBreaker.recordFailure(sourceId);

    const classified =
      err instanceof AdapterHttpError
        ? classifyHttpError(err.status, err.retryAfterHeader)
        : classifyNetworkError(err);

    const latencyMs = Date.now() - startedAt;
    const message = err instanceof Error ? err.message : String(err);
    log.error({ errorCode: classified.errorCode, retryable: classified.retryable, attempt }, "task_failed");

    if (classified.suggestDisableAdapter) {
      await updateSourceHealth(deps.pool, sourceId, { ok: false, errorCode: classified.errorCode, errorMessage: sanitizeErrorMessage(message) });
    }

    if (classified.retryable && attempt < MAX_RETRY_ATTEMPTS) {
      const delayMs = classified.retryAfterMs ?? computeBackoffWithJitter({ baseMs: 2000, maxMs: 60_000, attempt });
      await finalizeTask(deps, data, { status: "pending", errorCode: classified.errorCode, errorMessage: sanitizeErrorMessage(message) });
      await enqueueSearchTask(deps.boss, { ...data }, Math.ceil(delayMs / 1000));
      log.info({ delayMs, attempt: attempt + 1 }, "task_requeued");
      return; // nie finalizuj wyszukiwania - zadanie jeszcze zyje
    }

    await finalizeTask(deps, data, {
      status: "failed",
      resultCount,
      latencyMs,
      errorCode: classified.errorCode,
      errorMessage: sanitizeErrorMessage(message),
    });
    await emitEvent(deps.pool, searchId, "task.error", {
      taskId,
      sourceId,
      errorCode: classified.errorCode,
      message: sanitizeErrorMessage(message),
      retryable: classified.retryable,
    });
  }

  await maybeFinalizeSearch(deps, searchId);
}

/** Usuwa potencjalne sekrety (np. przypadkowo wklejony klucz w komunikacie bledu http) przed zapisem/emisja. */
function sanitizeErrorMessage(message: string): string {
  return message
    .replace(/[A-Za-z0-9_-]{24,}/g, "[REDACTED]")
    .slice(0, 500);
}

async function isSearchStillActive(pool: Pool, searchId: string): Promise<boolean> {
  return withAppContext(pool, serviceContext(), async (client) => {
    const res = await client.query<{ status: string }>(`select status from searches where id = $1`, [searchId]);
    return res.rows[0]?.status === "running";
  });
}

async function markTaskRunning(pool: Pool, taskId: string): Promise<number> {
  return withAppContext(pool, serviceContext(), async (client) => {
    const res = await client.query<{ attempt: number }>(
      `update search_tasks set status = 'running', attempt = attempt + 1, started_at = now() where id = $1 returning attempt`,
      [taskId]
    );
    return res.rows[0]?.attempt ?? 1;
  });
}

interface FinalizeTaskInput {
  status: "succeeded" | "failed" | "cancelled" | "pending";
  resultCount?: number;
  latencyMs?: number;
  errorCode?: string;
  errorMessage?: string;
}

async function finalizeTask(deps: TaskRunnerDeps, data: SearchTaskJobData, input: FinalizeTaskInput): Promise<void> {
  await withAppContext(deps.pool, serviceContext(), async (client) => {
    await client.query(
      `update search_tasks
       set status = $2, result_count = coalesce($3, result_count), latency_ms = $4,
           error_code = $5, error_message = $6,
           finished_at = case when $2 in ('succeeded', 'failed', 'cancelled') then now() else finished_at end
       where id = $1`,
      [data.taskId, input.status, input.resultCount ?? null, input.latencyMs ?? null, input.errorCode ?? null, input.errorMessage ?? null]
    );
  });
}

async function emitEvent(pool: Pool, searchId: string, type: string, payload: Record<string, unknown>): Promise<void> {
  await withAppContext(pool, serviceContext(), async (client) => {
    await client.query(`insert into search_events (search_id, type, payload) values ($1, $2, $3)`, [
      searchId,
      type,
      JSON.stringify(payload),
    ]);
  });
}

async function updateSourceHealth(
  pool: Pool,
  sourceId: string,
  input: { ok: true } | { ok: false; errorCode: string; errorMessage: string }
): Promise<void> {
  await withAppContext(pool, serviceContext(), async (client) => {
    if (input.ok) {
      await client.query(
        `update sources set status = 'active', last_ok_at = now(), last_error_code = null, last_error_message = null, updated_at = now() where id = $1`,
        [sourceId]
      );
    } else {
      await client.query(
        `update sources set status = 'error', last_error_code = $2, last_error_message = $3, updated_at = now() where id = $1`,
        [sourceId, input.errorCode, input.errorMessage]
      );
    }
  });
}

/**
 * Po kazdym zakonczonym zadaniu sprawdza, czy WSZYSTKIE zadania danego
 * wyszukiwania sa w stanie koncowym. Jesli tak - zamyka wyszukiwanie
 * (partial=true, gdy cokolwiek sie nie powiodlo/zostalo pominiete).
 */
async function maybeFinalizeSearch(deps: TaskRunnerDeps, searchId: string): Promise<void> {
  await withAppContext(deps.pool, serviceContext(), async (client) => {
    const tasks = await client.query<{ status: string; result_count: number }>(
      `select status, result_count from search_tasks where search_id = $1`,
      [searchId]
    );
    const terminalStatuses = new Set(["succeeded", "failed", "cancelled", "skipped"]);
    const allTerminal = tasks.rows.every((t) => terminalStatuses.has(t.status));
    if (!allTerminal) return;

    const search = await client.query<{ status: string; started_at: string }>(
      `select status, started_at from searches where id = $1`,
      [searchId]
    );
    if (search.rows[0]?.status !== "running") return; // juz zakonczone/anulowane gdzie indziej

    const partial = tasks.rows.some((t) => t.status === "failed" || t.status === "skipped" || t.status === "cancelled");
    const totalResults = tasks.rows.reduce((sum, t) => sum + (t.result_count ?? 0), 0);
    const durationMs = Date.now() - new Date(search.rows[0]!.started_at).getTime();

    await client.query(
      `update searches set status = 'completed', partial = $2, completed_at = now() where id = $1`,
      [searchId, partial]
    );
    await client.query(`insert into search_events (search_id, type, payload) values ($1, 'search.completed', $2)`, [
      searchId,
      JSON.stringify({ searchId, partial, totalResults, durationMs }),
    ]);
  });
}
