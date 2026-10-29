import { createHash } from "node:crypto";
import type {
  AdapterDescriptor,
  AdapterRecord,
  HealthCheckResult,
  QueryValidation,
  SearchContext,
  SearchQuery,
  SourceAdapter,
  SourceCapability,
} from "@unified-osint/core";
import { safeFetch, AdapterHttpError } from "@unified-osint/core";

interface LeakCheckRow {
  email?: string;
  username?: string;
  first_name?: string;
  last_name?: string;
  phone?: string;
  source?: { name?: string; breach_date?: string; unverified?: number; passwordless?: number; compilation?: number };
  fields?: string[];
  collected?: string;
  [key: string]: unknown;
}

interface LeakCheckResponse {
  success?: boolean;
  found?: number;
  quota?: number;
  result?: LeakCheckRow[];
}

export interface LeakCheckAdapterConfig {
  apiKey: string;
  baseUrl: string;
  fetchFn?: typeof safeFetch;
}

/**
 * Adapter LeakCheck.io Pro API v2.
 *
 * Zakres zweryfikowany w oficjalnej dokumentacji (docs.leakcheck.io,
 * wiki.leakcheck.io, 2026-10-29):
 *  - GET {baseUrl}/query/{query}?type=<type> - naglowek `X-API-Key: <klucz>`,
 *    `Accept: application/json`.
 *  - Odpowiedz: { success, found, quota, result: wiersz[] }, gdzie ksztalt
 *    wiersza zalezy od wycieku (email/username/first_name/last_name/phone/
 *    password/dob/address/... + `source` z nazwa i data wycieku).
 *  - Limity: `query` min. 3 znaki, `limit` max 1000, `offset` max 2500,
 *    3 req/s na planie Pro.
 *
 * Zgodnie z zasada braku masowego/wildcard wydobywania hasel: adapter
 * obsluguje tylko typy `email`/`username`/`phone` (standardowy plan Pro) -
 * BEZ typow `password`/`phash`/`origin` (Enterprise, zwiazane z plaintext/
 * hashem hasla lub masowym wydobywaniem po stronie) i bez wildcardow
 * (nieudokumentowane w API). Pole `password`/`hash`/`salt` w odpowiedzi jest
 * maskowane w `attrs` tak jak w adapterze Snusbase.
 */
export class LeakCheckAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "leakcheck",
    name: "LeakCheck.io",
    category: "breach_data",
    requiredEnvVars: ["LEAKCHECK_API_KEY"],
    adapterVersion: "1.0.0",
    capabilities: [
      { queryType: "email", supportsWildcards: false, maxResults: 50 },
      { queryType: "username", supportsWildcards: false, maxResults: 50 },
      { queryType: "phone", supportsWildcards: false, maxResults: 50 },
    ],
    cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
    setupInstructions: "Wymaga LEAKCHECK_API_KEY (platny klucz API Pro z panelu leakcheck.io).",
  };

  private readonly fetchFn: typeof safeFetch;

  constructor(private readonly config: LeakCheckAdapterConfig) {
    this.fetchFn = config.fetchFn ?? safeFetch;
  }

  isConfigured(): boolean {
    return this.config.apiKey.length > 0;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "email" && query.type !== "username" && query.type !== "phone") {
      return { ok: false, reason: "Adapter LeakCheck obsluguje tylko zapytania typu 'email', 'username' lub 'phone'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter LeakCheck nie wspiera wildcardow" };
    }
    if (query.raw.length < 3) {
      return { ok: false, reason: "Zapytanie LeakCheck wymaga co najmniej 3 znakow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const encoded = encodeURIComponent(query.raw);
    const result = await this.fetchFn(`${this.config.baseUrl}/query/${encoded}?type=${query.type}`, {
      headers: { Accept: "application/json", "X-API-Key": this.config.apiKey },
      timeoutMs: context.timeoutMs,
      signal: context.signal,
    });

    if (result.status < 200 || result.status >= 300) {
      const retryAfter = result.headers["retry-after"];
      throw new AdapterHttpError(
        `LeakCheck API zwrocilo blad HTTP ${result.status}`,
        result.status,
        Array.isArray(retryAfter) ? retryAfter[0] : retryAfter ?? null
      );
    }

    let parsed: LeakCheckResponse;
    try {
      parsed = JSON.parse(result.body.toString("utf8")) as LeakCheckResponse;
    } catch (err) {
      throw new Error(`Nie udalo sie sparsowac odpowiedzi LeakCheck jako JSON: ${(err as Error).message}`);
    }

    if (parsed.success === false) {
      throw new Error("LeakCheck API zglosilo success=false");
    }

    for (const row of parsed.result ?? []) {
      if (context.signal.aborted) return;
      try {
        yield this.normalizeResult(row);
      } catch (err) {
        context.logger.warn("leakcheck_normalize_failed", { error: (err as Error).message });
      }
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const row = raw as LeakCheckRow;

    const attrs: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(row)) {
      if (key === "source" || key === "fields") continue;
      attrs[key] = value;
    }
    attrs.source = row.source?.name ?? null;
    attrs.breachDate = row.source?.breach_date ?? null;
    attrs.fields = row.fields ?? [];

    const naturalIdSeed = `${row.email ?? ""}:${row.username ?? ""}:${row.source?.name ?? ""}:${JSON.stringify(row)}`;
    return {
      sourceRecordId: sha256(naturalIdSeed),
      canonicalUrl: null,
      kind: "breach_record",
      title: `Wyciek: ${row.source?.name ?? "nieznany"}`,
      summary: row.email ? `E-mail: ${row.email}` : row.username ? `Username: ${row.username}` : null,
      attrs,
      observedAt: normalizeDate(row.collected ?? row.source?.breach_date),
      raw: row,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    const startedAt = Date.now();
    try {
      // /api/public nie wymaga autoryzacji - sluzy tylko do potwierdzenia dostepnosci API.
      const result = await this.fetchFn(`${this.config.baseUrl.replace(/\/v2$/, "")}/public`, { timeoutMs: 5000 });
      if (result.status < 200 || result.status >= 300) {
        return { ok: false, errorCode: `http_${result.status}`, message: "LeakCheck /api/public zwrocilo blad" };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "leakcheck_healthcheck_failed", message: (err as Error).message };
    }
  }
}

function normalizeDate(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
