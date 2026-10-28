import type { QueryType, SearchQuery } from "./query.js";

/** Status widoczny w rejestrze zrodel (tabela `sources`) i w UI. */
export const SOURCE_STATUSES = ["active", "disabled", "not_configured", "degraded", "error"] as const;
export type SourceStatus = (typeof SOURCE_STATUSES)[number];

export const SOURCE_CATEGORIES = [
  "demo",
  "dns_infra",
  "certificate_transparency",
  "web_archive",
  "breach_data",
  "username_recon",
  "threat_intel",
  "code_repository",
  "social_official_api",
  "messaging",
  "local_import",
] as const;
export type SourceCategory = (typeof SOURCE_CATEGORIES)[number];

export interface SourceCapability {
  queryType: QueryType;
  supportsWildcards: boolean;
  maxResults: number;
}

export interface SourceCostInfo {
  /** Jednostka kosztu wedlug dostawcy (np. "credit", "request"), null gdy darmowe. */
  unit: string | null;
  /** Szacowany koszt jednego zapytania w jednostkach `unit`. */
  estimatedCostPerQuery: number;
  /** True, gdy koszt jest nieznany i wymaga ostrzezenia w UI przed uzyciem. */
  unknown: boolean;
}

export interface AdapterDescriptor {
  id: string;
  name: string;
  category: SourceCategory;
  /** Zmienne srodowiskowe wymagane, aby adapter mogl wyjsc ze stanu not_configured. */
  requiredEnvVars: string[];
  adapterVersion: string;
  capabilities: SourceCapability[];
  cost: SourceCostInfo;
  /** Krotki opis wymaganych uprawnien/planu, pokazywany w UI gdy not_configured. */
  setupInstructions: string;
}

export interface SearchContext {
  searchId: string;
  userId: string;
  userRole: "admin" | "analyst" | "viewer";
  correlationId: string;
  /** Sygnal przerwania - adapter MUSI respektowac abort przy kazdym await. */
  signal: AbortSignal;
  /** Twardy timeout per adapter, w milisekundach (nadpisywalny per zrodlo). */
  timeoutMs: number;
  logger: {
    info: (msg: string, meta?: Record<string, unknown>) => void;
    warn: (msg: string, meta?: Record<string, unknown>) => void;
    error: (msg: string, meta?: Record<string, unknown>) => void;
  };
}

/** Wynik waliadacji zapytania przez adapter przed uruchomieniem search(). */
export type QueryValidation =
  | { ok: true }
  | { ok: false; reason: string };

/** Znormalizowany rekord zwracany przez adapter, przed deduplikacja. */
export interface AdapterRecord {
  /** Identyfikator rekordu w ramach zrodla (do klucza dedup warstwy 1). */
  sourceRecordId: string;
  /** Kanoniczny URL rekordu, jesli istnieje. */
  canonicalUrl: string | null;
  kind: string;
  title: string;
  summary: string | null;
  /** Dowolne dodatkowe atrybuty - traktowane jako NIEZAUFANE dane do wyswietlenia jako tekst. */
  attrs: Record<string, unknown>;
  observedAt: string | null;
  /** Surowa odpowiedz zrodla (przycinana przed zapisem przez orchestrator). */
  raw: unknown;
}

export type HealthCheckResult =
  | { ok: true; latencyMs: number }
  | { ok: false; errorCode: string; message: string };

/**
 * Wspolny interfejs kazdego adaptera zrodla OSINT.
 * Nowe zrodlo = nowa implementacja tego interfejsu + wpis w rejestrze
 * (packages/adapters/src/registry.ts). Rdzen orkiestratora nie zmienia sie.
 */
export interface SourceAdapter {
  readonly descriptor: AdapterDescriptor;

  /** True, gdy wymagane zmienne srodowiskowe sa obecne i adapter moze dzialac. */
  isConfigured(): boolean;

  getCapabilities(): SourceCapability[];

  validateQuery(query: SearchQuery): QueryValidation;

  /**
   * Zwraca asynchroniczny generator rekordow, aby orchestrator mogl
   * publikowac wyniki stopniowo, zamiast czekac na komplet odpowiedzi.
   */
  search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord>;

  normalizeResult(raw: unknown): AdapterRecord;

  healthCheck(): Promise<HealthCheckResult>;
}
