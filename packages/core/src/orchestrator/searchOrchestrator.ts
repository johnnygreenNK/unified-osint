import type { Pool } from "pg";
import type PgBoss from "pg-boss";
import { buildSearchQuery, countLiteralChars, MIN_LITERAL_CHARS_FOR_WILDCARD_QUERY, type QueryType } from "../contracts/query.js";
import type { AdapterRegistry } from "../contracts/registry.js";
import { withAppContext, userContext, serviceContext, type AppRole } from "../db/pool.js";
import { ValidationError, LimitExceededError, NotFoundError } from "../errors.js";
import { enqueueSearchTask } from "./queue.js";
import type { Logger } from "../logger.js";

export type UserRole = Exclude<AppRole, "service">;

export interface StartSearchInput {
  userId: string;
  userRole: UserRole;
  rawQuery: string;
  queryType?: QueryType;
  /** Puste/undefined = uzyj wszystkich zrodel obslugujacych wykryty typ zapytania. */
  sourceIds?: string[];
}

export interface StartSearchResult {
  searchId: string;
  correlationId: string;
  sourceIds: string[];
  skippedSourceIds: { sourceId: string; reason: string }[];
}

export interface OrchestratorLimits {
  maxSourcesPerSearch: number;
  maxConcurrentSearchesPerUser: number;
  globalSearchBudgetPerDay: number;
  defaultAdapterTimeoutMs: number;
}

export class SearchOrchestrator {
  constructor(
    private readonly pool: Pool,
    private readonly boss: PgBoss,
    private readonly registry: AdapterRegistry,
    private readonly limits: OrchestratorLimits,
    private readonly logger: Logger
  ) {}

  async startSearch(input: StartSearchInput): Promise<StartSearchResult> {
    const query = buildSearchQuery(input.rawQuery, input.queryType);
    if (!query.raw) throw new ValidationError("Zapytanie nie moze byc puste");

    if (query.hasWildcards && countLiteralChars(query.raw) < MIN_LITERAL_CHARS_FOR_WILDCARD_QUERY) {
      throw new ValidationError(
        `Zapytanie z wildcardami musi zawierac co najmniej ${MIN_LITERAL_CHARS_FOR_WILDCARD_QUERY} znaki literalne`
      );
    }

    await this.enforceDailyBudget(input.userId);
    await this.enforceConcurrentSearchLimit(input.userId);

    const candidateSources = input.sourceIds?.length
      ? input.sourceIds.map((id) => this.registry.get(id)).filter((a): a is NonNullable<typeof a> => !!a)
      : this.registry.list();

    if (candidateSources.length === 0) {
      throw new ValidationError("Brak dostepnych zrodel do wyszukiwania");
    }

    const accepted: string[] = [];
    const skipped: { sourceId: string; reason: string }[] = [];

    for (const adapter of candidateSources) {
      if (!adapter.isConfigured()) {
        skipped.push({ sourceId: adapter.descriptor.id, reason: "not_configured" });
        continue;
      }
      const validation = adapter.validateQuery(query);
      if (!validation.ok) {
        skipped.push({ sourceId: adapter.descriptor.id, reason: validation.reason });
        continue;
      }
      accepted.push(adapter.descriptor.id);
    }

    if (accepted.length === 0) {
      throw new ValidationError(
        "Zadne z wybranych zrodel nie obsluguje tego zapytania (sprawdz typ zapytania i wildcardy)"
      );
    }

    if (accepted.length > this.limits.maxSourcesPerSearch) {
      throw new LimitExceededError(
        `Przekroczono limit zrodel na jedno wyszukiwanie (max ${this.limits.maxSourcesPerSearch})`
      );
    }

    const correlationId = crypto.randomUUID();

    // Service context: search_tasks/search_events wymagaja roli service/privileged
    // do zapisu (patrz 0004_searches.sql) - userId wlasciciela jest i tak jawnie
    // zapisywany w kolumnie searches.user_id, wiec RLS przy odczycie dziala normalnie.
    const searchId = await withAppContext(this.pool, serviceContext(), async (client) => {
      const searchRes = await client.query<{ id: string }>(
        `insert into searches (user_id, query_raw, query_type, query_norm, has_wildcards, source_ids, correlation_id, norm_version, status, started_at)
         values ($1, $2, $3, $4, $5, $6, $7, 1, 'running', now())
         returning id`,
        [input.userId, query.raw, query.type, query.raw.toLowerCase(), query.hasWildcards, accepted, correlationId]
      );
      const id = searchRes.rows[0]!.id;

      for (const sourceId of accepted) {
        await client.query(
          `insert into search_tasks (search_id, source_id, status) values ($1, $2, 'pending')`,
          [id, sourceId]
        );
      }
      for (const { sourceId, reason } of skipped) {
        // Nie tworzymy search_tasks dla pominietych zrodel spoza wybranego zakresu,
        // ale jesli uzytkownik jawnie je wybral, zapisujemy skipped - widoczne w UI.
        if (input.sourceIds?.includes(sourceId)) {
          await client.query(
            `insert into search_tasks (search_id, source_id, status, error_code) values ($1, $2, 'skipped', $3)`,
            [id, sourceId, reason]
          );
        }
      }

      await client.query(
        `insert into search_events (search_id, type, payload) values ($1, 'search.started', $2)`,
        [id, JSON.stringify({ searchId: id, sourceIds: accepted, queryType: query.type })]
      );

      return id;
    });

    for (const sourceId of accepted) {
      const taskId = await this.getTaskId(searchId, sourceId);
      await enqueueSearchTask(this.boss, {
        taskId,
        searchId,
        sourceId,
        userId: input.userId,
        userRole: input.userRole,
        queryRaw: query.raw,
        queryType: query.type,
        hasWildcards: query.hasWildcards,
        correlationId,
      });
    }

    return { searchId, correlationId, sourceIds: accepted, skippedSourceIds: skipped };
  }

  async cancelSearch(searchId: string, userId: string, userRole: UserRole): Promise<void> {
    await withAppContext(this.pool, userContext(userId, userRole), async (client) => {
      const search = await client.query<{ id: string; status: string }>(
        `select id, status from searches where id = $1`,
        [searchId]
      );
      if (search.rows.length === 0) throw new NotFoundError("Wyszukiwanie nie istnieje lub brak dostepu");
      if (search.rows[0]!.status === "completed" || search.rows[0]!.status === "cancelled") return;

      await client.query(`update searches set status = 'cancelled', completed_at = now() where id = $1`, [searchId]);
      await client.query(
        `update search_tasks set status = 'cancelled', finished_at = now() where search_id = $1 and status in ('pending', 'running')`,
        [searchId]
      );
      await client.query(
        `insert into search_events (search_id, type, payload) values ($1, 'search.completed', $2)`,
        [searchId, JSON.stringify({ searchId, partial: true, cancelled: true })]
      );
    });
  }

  private async getTaskId(searchId: string, sourceId: string): Promise<string> {
    return withAppContext(this.pool, serviceContext(), async (client) => {
      const res = await client.query<{ id: string }>(
        `select id from search_tasks where search_id = $1 and source_id = $2`,
        [searchId, sourceId]
      );
      return res.rows[0]!.id;
    });
  }

  private async enforceConcurrentSearchLimit(userId: string): Promise<void> {
    const count = await withAppContext(this.pool, userContext(userId, "viewer"), async (client) => {
      const res = await client.query<{ count: string }>(
        `select count(*) from searches where user_id = $1 and status = 'running'`,
        [userId]
      );
      return Number(res.rows[0]!.count);
    });
    if (count >= this.limits.maxConcurrentSearchesPerUser) {
      throw new LimitExceededError(
        `Przekroczono limit rownoleglych wyszukiwan (max ${this.limits.maxConcurrentSearchesPerUser}). Zaczekaj na zakonczenie poprzedniego.`
      );
    }
  }

  private async enforceDailyBudget(userId: string): Promise<void> {
    const windowStart = new Date();
    windowStart.setUTCHours(0, 0, 0, 0);
    const subject = `search_budget:${userId}`;

    const count = await withAppContext(this.pool, serviceContext(), async (client) => {
      const res = await client.query<{ count: number }>(
        `insert into rate_limit_counters (subject, window_start, count)
         values ($1, $2, 1)
         on conflict (subject, window_start) do update set count = rate_limit_counters.count + 1
         returning count`,
        [subject, windowStart.toISOString()]
      );
      return res.rows[0]!.count;
    });

    if (count > this.limits.globalSearchBudgetPerDay) {
      throw new LimitExceededError(
        `Przekroczono dzienny budzet wyszukiwan (max ${this.limits.globalSearchBudgetPerDay}/dzien). Sprobuj ponownie jutro.`
      );
    }
  }
}
