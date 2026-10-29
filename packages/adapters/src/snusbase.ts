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

interface SnusbaseResponse {
  took?: number;
  size?: number;
  results?: Record<string, Array<Record<string, unknown>>>;
}

interface SnusbaseRawRecord {
  breachTable: string;
  record: Record<string, unknown>;
}

export interface SnusbaseAdapterConfig {
  apiKey: string;
  baseUrl: string;
  /** Wstrzykiwalne dla testow - domyslnie prawdziwy safeFetch (SSRF-safe). */
  fetchFn?: typeof safeFetch;
}

/**
 * Adapter Snusbase (komercyjna wyszukiwarka wyciekow danych).
 *
 * Zakres zweryfikowany w oficjalnej dokumentacji (docs.snusbase.com,
 * github.com/snusbase/docs.snusbase.com) na 2026-10-28:
 *  - POST https://api.snusbase.com/data/search, naglowek `Auth: <surowy klucz>`
 *    (bez prefiksu, bez "Bearer"), `Content-Type: application/json`.
 *  - Body: { terms: string[], types: string[] } - "types" to nazwy pol do
 *    przeszukania (np. "email", "username"); nie wysylamy "wildcard" (brak
 *    wsparcia wildcardow w tym adapterze - patrz validateQuery).
 *  - Odpowiedz: { took, size, results: { "<nazwa_wycieku>": wiersz[] } },
 *    gdzie ksztalt wiersza rozni sie per tabela/wyciek (username/email/
 *    lastip/hash/salt/uid/created/updated i inne - traktowane generycznie).
 *
 * Zgodnie z zasada braku masowego/wildcard wydobywania hasel (patrz
 * query.ts): adapter przyjmuje tylko email/username, bez wildcardow, i
 * zwraca "czy i gdzie wystapil wyciek", maskujac hash/haslo/sol w `attrs`.
 */
export class SnusbaseAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "snusbase",
    name: "Snusbase (wyszukiwarka wyciekow danych)",
    category: "breach_data",
    requiredEnvVars: ["SNUSBASE_API_KEY"],
    adapterVersion: "1.0.0",
    capabilities: [
      { queryType: "email", supportsWildcards: false, maxResults: 20 },
      { queryType: "username", supportsWildcards: false, maxResults: 20 },
    ],
    cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
    setupInstructions:
      "Wymaga SNUSBASE_API_KEY (prawdziwy klucz API z panelu Snusbase, nie login do UI).",
  };

  private readonly fetchFn: typeof safeFetch;

  constructor(private readonly config: SnusbaseAdapterConfig) {
    this.fetchFn = config.fetchFn ?? safeFetch;
  }

  isConfigured(): boolean {
    return this.config.apiKey.length > 0;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "email" && query.type !== "username") {
      return { ok: false, reason: "Adapter Snusbase obsluguje tylko zapytania typu 'email' lub 'username'" };
    }
    if (query.hasWildcards) {
      return {
        ok: false,
        reason: "Adapter Snusbase nie wspiera wildcardow - sprawdza tylko dokladne wystapienie w wycieku",
      };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const result = await this.fetchFn(`${this.config.baseUrl}/data/search`, {
      method: "POST",
      headers: {
        Auth: this.config.apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ terms: [query.raw], types: [query.type] }),
      timeoutMs: context.timeoutMs,
      signal: context.signal,
    });

    if (result.status < 200 || result.status >= 300) {
      const retryAfter = result.headers["retry-after"];
      throw new AdapterHttpError(
        `Snusbase API zwrocilo blad HTTP ${result.status}`,
        result.status,
        Array.isArray(retryAfter) ? retryAfter[0] : retryAfter ?? null
      );
    }

    let parsed: SnusbaseResponse;
    try {
      parsed = JSON.parse(result.body.toString("utf8")) as SnusbaseResponse;
    } catch (err) {
      throw new Error(`Nie udalo sie sparsowac odpowiedzi Snusbase jako JSON: ${(err as Error).message}`);
    }

    const resultsByTable = parsed.results ?? {};
    for (const [breachTable, rows] of Object.entries(resultsByTable)) {
      for (const record of rows) {
        if (context.signal.aborted) return;
        try {
          yield this.normalizeResult({ breachTable, record } satisfies SnusbaseRawRecord);
        } catch (err) {
          context.logger.warn("snusbase_normalize_failed", {
            breachTable,
            error: (err as Error).message,
          });
          // Jeden zniekstalcony wiersz nie powinien ubic calego wyniku - pomijamy go.
        }
      }
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { breachTable, record } = raw as SnusbaseRawRecord;

    const attrs: Record<string, unknown> = { breachTable };
    for (const [key, value] of Object.entries(record)) {
      attrs[key] = value;
    }

    const email = typeof record.email === "string" ? record.email : null;
    const username = typeof record.username === "string" ? record.username : null;
    const naturalId = typeof record.uid === "string" || typeof record.uid === "number" ? String(record.uid) : null;

    return {
      sourceRecordId: naturalId ?? `${breachTable}:${sha256(JSON.stringify(record))}`,
      canonicalUrl: null,
      kind: "breach_record",
      title: `Wyciek: ${prettyBreachName(breachTable)}`,
      summary: email ? `E-mail: ${email}` : username ? `Username: ${username}` : null,
      attrs,
      observedAt: normalizeObservedAt(record.created ?? record.updated),
      raw: record,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    const startedAt = Date.now();
    try {
      // /data/stats nie wymaga autoryzacji - sluzy tylko do potwierdzenia
      // dostepnosci API, nie weryfikuje samego klucza.
      const result = await this.fetchFn(`${this.config.baseUrl}/data/stats`, { timeoutMs: 5000 });
      if (result.status < 200 || result.status >= 300) {
        return { ok: false, errorCode: `http_${result.status}`, message: "Snusbase /data/stats zwrocilo blad" };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "snusbase_healthcheck_failed", message: (err as Error).message };
    }
  }
}

function normalizeObservedAt(value: unknown): string | null {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Nazwy tabel Snusbase obserwowane w realnych odpowiedziach API maja postac
 * "<id>_<NAZWA_CZESCI>_<ROZMIAR>_<KATEGORIA>_<MMRRRR>", np.
 * "2042_TRELLO_COM_15M_TECH_012024" -> "trello.com". To wylacznie kosmetyka
 * wyswietlania (nie wplywa na dedup/fingerprint) - jesli wzorzec nie pasuje,
 * zwracamy surowa nazwe tabeli bez zgadywania.
 */
const SIZE_SUFFIX_RE = /^\d+(\.\d+)?[KMB]$/i;
const KNOWN_CATEGORY_SUFFIXES = new Set([
  "TECH", "HACKING", "MUSIC", "MALWARE", "GAMING", "SOCIAL", "FINANCE",
  "DATING", "EDUCATION", "SHOPPING", "FORUM", "NA", "MISC", "GOV",
]);
const KNOWN_TLDS = new Set(["COM", "NET", "ORG", "IO", "CO", "GG", "PL", "APP", "DEV", "ME"]);

export function prettyBreachName(breachTable: string): string {
  const parts = breachTable.split("_").filter(Boolean);
  if (parts.length === 0) return breachTable;

  if (/^\d+$/.test(parts[0]!)) parts.shift();
  // Rozmiar/kategoria/data moga wystapic w roznej kolejnosci na koncu nazwy -
  // zdejmujemy je az zaden wzorzec juz nie pasuje.
  let trimmed = true;
  while (trimmed && parts.length > 1) {
    trimmed = false;
    const last = parts[parts.length - 1]!;
    if (/^\d{4,6}$/.test(last) || SIZE_SUFFIX_RE.test(last) || KNOWN_CATEGORY_SUFFIXES.has(last.toUpperCase())) {
      parts.pop();
      trimmed = true;
    }
  }

  if (parts.length === 0) return breachTable;

  const last = parts[parts.length - 1]!.toUpperCase();
  if (KNOWN_TLDS.has(last)) {
    return parts.map((p) => p.toLowerCase()).join(".");
  }
  return parts.map((p) => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase()).join(" ");
}
