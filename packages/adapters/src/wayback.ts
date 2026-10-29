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
import { safeFetch, AdapterHttpError, normalizeDomain, normalizeUrl, normalizeDateToUtcIso } from "@unified-osint/core";

export interface WaybackAdapterConfig {
  enabled: boolean;
  baseUrl?: string;
  fetchFn?: typeof safeFetch;
}

const MAX_RESULTS = 500;

/**
 * Adapter Wayback Machine CDX Server API (Internet Archive) - bez klucza.
 *
 * Zrodlo (oficjalne, zweryfikowane): https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md
 * `GET http://web.archive.org/cdx/search/cdx?url=<url>&output=json&limit=<n>`.
 * Przy `output=json` pierwszy element tablicy jest wierszem naglowka z
 * nazwami pol (domyslnie: urlkey, timestamp, original, mimetype, statuscode,
 * digest, length) - adapter CZYTA ten naglowek, nie zaklada stalej kolejnosci.
 * Dla typu `domain` uzywa `matchType=domain` (obejmuje subdomeny), dla `url`
 * dopasowania dokladnego (domyslne zachowanie CDX).
 */
export class WaybackAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "wayback",
    name: "Wayback Machine (CDX)",
    category: "web_archive",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [
      { queryType: "domain", supportsWildcards: false, maxResults: MAX_RESULTS },
      { queryType: "url", supportsWildcards: false, maxResults: MAX_RESULTS },
    ],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions:
      "Brak klucza - wylacz przez ADAPTER_WAYBACK_ENABLED=false, jesli nie chcesz go uzywac.",
  };

  private readonly fetchFn: typeof safeFetch;
  private readonly baseUrl: string;

  constructor(private readonly config: WaybackAdapterConfig) {
    this.fetchFn = config.fetchFn ?? safeFetch;
    this.baseUrl = config.baseUrl ?? "http://web.archive.org/cdx/search/cdx";
  }

  isConfigured(): boolean {
    return this.config.enabled;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "domain" && query.type !== "url") {
      return { ok: false, reason: "Adapter Wayback CDX obsluguje tylko zapytania typu 'domain' lub 'url'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter Wayback CDX nie wspiera wildcardow UI" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const params = new URLSearchParams({ output: "json", limit: String(MAX_RESULTS) });
    if (query.type === "domain") {
      params.set("url", normalizeDomain(query.raw));
      params.set("matchType", "domain");
      params.set("collapse", "urlkey");
    } else {
      params.set("url", normalizeUrl(query.raw));
    }

    const result = await this.fetchFn(`${this.baseUrl}?${params.toString()}`, {
      timeoutMs: context.timeoutMs,
      signal: context.signal,
    });

    if (result.status === 404) return;
    if (result.status < 200 || result.status >= 300) {
      const retryAfter = result.headers["retry-after"];
      throw new AdapterHttpError(
        `Wayback CDX zwrocilo blad HTTP ${result.status}`,
        result.status,
        Array.isArray(retryAfter) ? retryAfter[0] : retryAfter ?? null
      );
    }

    const text = result.body.toString("utf8").trim();
    if (text.length === 0) return;

    let rows: string[][];
    try {
      rows = JSON.parse(text) as string[][];
    } catch (err) {
      throw new Error(`Nie udalo sie sparsowac odpowiedzi Wayback CDX jako JSON: ${(err as Error).message}`);
    }
    if (rows.length === 0) return;

    const header = rows[0]!;
    const fieldIndex = (name: string): number => header.indexOf(name);
    const idxUrlkey = fieldIndex("urlkey");
    const idxTimestamp = fieldIndex("timestamp");
    const idxOriginal = fieldIndex("original");
    const idxMimetype = fieldIndex("mimetype");
    const idxStatuscode = fieldIndex("statuscode");
    const idxDigest = fieldIndex("digest");
    const idxLength = fieldIndex("length");

    for (const row of rows.slice(1)) {
      if (context.signal.aborted) return;
      yield this.normalizeResult({
        urlkey: idxUrlkey >= 0 ? row[idxUrlkey] : null,
        timestamp: idxTimestamp >= 0 ? row[idxTimestamp] : null,
        original: idxOriginal >= 0 ? row[idxOriginal] : null,
        mimetype: idxMimetype >= 0 ? row[idxMimetype] : null,
        statuscode: idxStatuscode >= 0 ? row[idxStatuscode] : null,
        digest: idxDigest >= 0 ? row[idxDigest] : null,
        length: idxLength >= 0 ? row[idxLength] : null,
      });
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const entry = raw as {
      urlkey: string | null;
      timestamp: string | null;
      original: string | null;
      mimetype: string | null;
      statuscode: string | null;
      digest: string | null;
      length: string | null;
    };
    const snapshotUrl = entry.timestamp && entry.original ? `https://web.archive.org/web/${entry.timestamp}/${entry.original}` : null;
    return {
      sourceRecordId: entry.digest ? `${entry.digest}:${entry.timestamp ?? ""}` : `${entry.original ?? ""}:${entry.timestamp ?? ""}`,
      canonicalUrl: snapshotUrl,
      kind: "web_archive_snapshot",
      title: entry.original ?? "nieznany URL",
      summary: entry.mimetype ? `Typ: ${entry.mimetype}, status: ${entry.statuscode ?? "?"}` : null,
      attrs: {
        originalUrl: entry.original,
        mimetype: entry.mimetype,
        statusCode: entry.statuscode,
        digest: entry.digest,
        lengthBytes: entry.length,
      },
      observedAt: entry.timestamp ? normalizeWaybackTimestamp(entry.timestamp) : null,
      raw: entry,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    const startedAt = Date.now();
    try {
      const result = await this.fetchFn(`${this.baseUrl}?url=example.com&output=json&limit=1`, { timeoutMs: 5000 });
      if (result.status < 200 || result.status >= 300) {
        return { ok: false, errorCode: `http_${result.status}`, message: "Wayback CDX zwrocilo blad" };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "wayback_healthcheck_failed", message: (err as Error).message };
    }
  }
}

/** Timestamp CDX ma format yyyyMMddhhmmss (UTC) - brak separatorow, Date() go nie sparsuje bez pomocy. */
function normalizeWaybackTimestamp(ts: string): string | null {
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(ts);
  if (!match) return null;
  const [, y, mo, d, h, mi, s] = match;
  return normalizeDateToUtcIso(`${y}-${mo}-${d}T${h}:${mi}:${s}Z`);
}
