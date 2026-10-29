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

interface HibpBreach {
  Name: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  AddedDate?: string;
  ModifiedDate?: string;
  PwnCount?: number;
  Description?: string;
  DataClasses?: string[];
  IsVerified?: boolean;
  IsFabricated?: boolean;
  IsSensitive?: boolean;
  IsRetired?: boolean;
  IsSpamList?: boolean;
  IsMalware?: boolean;
  IsStealerLog?: boolean;
}

interface HibpPaste {
  Source?: string;
  Id?: string;
  Title?: string;
  Date?: string;
  EmailCount?: number;
}

export interface HibpAdapterConfig {
  apiKey: string;
  baseUrl: string;
  /** Wymagany przez API HIBP naglowek user-agent identyfikujacy aplikacje (bez niego 403). */
  userAgent: string;
  fetchFn?: typeof safeFetch;
}

/**
 * Adapter Have I Been Pwned (HIBP) API v3.
 *
 * Zakres zweryfikowany w oficjalnej dokumentacji (haveibeenpwned.com/API/v3,
 * 2026-10-29):
 *  - GET {baseUrl}/breachedaccount/{email}?truncateResponse=false - naglowek
 *    `hibp-api-key` (surowy 32-znakowy klucz hex) + wymagany `user-agent`.
 *    200 = tablica pelnych obiektow wycieku, 404 = brak wystapien (NIE blad).
 *  - GET {baseUrl}/pasteaccount/{email} - ten sam naglowek, zwraca tablice
 *    pastes (Source/Id/Title/Date/EmailCount). 404 = brak wystapien.
 *  - 429 zwraca `retry-after` w sekundach.
 *
 * Zgodnie z zasada braku masowego/wildcard wydobywania hasel: adapter
 * przyjmuje tylko typ `email`, bez wildcardow - HIBP i tak nigdy nie zwraca
 * hasel/hashy, tylko metadane wyciekow i pastes.
 */
export class HibpAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "hibp",
    name: "Have I Been Pwned",
    category: "breach_data",
    requiredEnvVars: ["HIBP_API_KEY"],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "email", supportsWildcards: false, maxResults: 50 }],
    cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
    setupInstructions: "Wymaga HIBP_API_KEY (platny klucz API z panelu haveibeenpwned.com/API/Key).",
  };

  private readonly fetchFn: typeof safeFetch;

  constructor(private readonly config: HibpAdapterConfig) {
    this.fetchFn = config.fetchFn ?? safeFetch;
  }

  isConfigured(): boolean {
    return this.config.apiKey.length > 0;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "email") {
      return { ok: false, reason: "Adapter HIBP obsluguje tylko zapytania typu 'email'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter HIBP nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const encoded = encodeURIComponent(query.raw);
    const headers = { "hibp-api-key": this.config.apiKey, "user-agent": this.config.userAgent };

    const breaches = await this.fetchList<HibpBreach>(
      `${this.config.baseUrl}/breachedaccount/${encoded}?truncateResponse=false`,
      headers,
      context
    );
    for (const breach of breaches) {
      if (context.signal.aborted) return;
      yield this.normalizeResult({ kind: "breach", data: breach });
    }

    const pastes = await this.fetchList<HibpPaste>(`${this.config.baseUrl}/pasteaccount/${encoded}`, headers, context);
    for (const paste of pastes) {
      if (context.signal.aborted) return;
      yield this.normalizeResult({ kind: "paste", data: paste });
    }
  }

  private async fetchList<T>(
    url: string,
    headers: Record<string, string>,
    context: SearchContext
  ): Promise<T[]> {
    const result = await this.fetchFn(url, { headers, timeoutMs: context.timeoutMs, signal: context.signal });

    if (result.status === 404) return [];
    if (result.status < 200 || result.status >= 300) {
      const retryAfter = result.headers["retry-after"];
      throw new AdapterHttpError(
        `HIBP API zwrocilo blad HTTP ${result.status}`,
        result.status,
        Array.isArray(retryAfter) ? retryAfter[0] : retryAfter ?? null
      );
    }

    try {
      return JSON.parse(result.body.toString("utf8")) as T[];
    } catch (err) {
      throw new Error(`Nie udalo sie sparsowac odpowiedzi HIBP jako JSON: ${(err as Error).message}`);
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { kind, data } = raw as { kind: "breach" | "paste"; data: HibpBreach | HibpPaste };

    if (kind === "breach") {
      const breach = data as HibpBreach;
      return {
        sourceRecordId: breach.Name,
        canonicalUrl: null,
        kind: "breach_record",
        title: `Wyciek: ${breach.Title ?? breach.Name}`,
        summary: breach.Description ?? null,
        attrs: {
          domain: breach.Domain ?? null,
          breachDate: breach.BreachDate ?? null,
          pwnCount: breach.PwnCount ?? null,
          dataClasses: breach.DataClasses ?? [],
          isVerified: breach.IsVerified ?? null,
          isSensitive: breach.IsSensitive ?? null,
          isMalware: breach.IsMalware ?? null,
          isStealerLog: breach.IsStealerLog ?? null,
        },
        observedAt: normalizeDate(breach.BreachDate ?? breach.AddedDate),
        raw: breach,
      };
    }

    const paste = data as HibpPaste;
    const naturalId = paste.Source && paste.Id ? `${paste.Source}:${paste.Id}` : `paste:${paste.Date ?? ""}`;
    return {
      sourceRecordId: naturalId,
      canonicalUrl: null,
      kind: "paste_record",
      title: `Paste: ${paste.Title ?? paste.Source ?? "nieznany"}`,
      summary: paste.EmailCount != null ? `Liczba adresow w paste: ${paste.EmailCount}` : null,
      attrs: { source: paste.Source ?? null, emailCount: paste.EmailCount ?? null },
      observedAt: normalizeDate(paste.Date),
      raw: paste,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    const startedAt = Date.now();
    try {
      // /latestbreach nie wymaga autoryzacji - sluzy tylko do potwierdzenia dostepnosci API.
      const result = await this.fetchFn(`${this.config.baseUrl}/latestbreach`, {
        headers: { "user-agent": this.config.userAgent },
        timeoutMs: 5000,
      });
      if (result.status < 200 || result.status >= 300) {
        return { ok: false, errorCode: `http_${result.status}`, message: "HIBP /latestbreach zwrocilo blad" };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "hibp_healthcheck_failed", message: (err as Error).message };
    }
  }
}

function normalizeDate(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}
