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
import { safeFetch, AdapterHttpError, normalizeDomain, normalizeDateToUtcIso } from "@unified-osint/core";

interface CrtShEntry {
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  /** Lista SAN-ow certyfikatu, wartosci rozdzielone znakiem nowej linii. */
  name_value: string;
  id: number;
  entry_timestamp?: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  result_count?: number;
}

export interface CrtShAdapterConfig {
  enabled: boolean;
  baseUrl?: string;
  fetchFn?: typeof safeFetch;
}

/**
 * Adapter crt.sh - nieoficjalne, ale powszechnie uzywane publiczne API
 * Certificate Transparency (bez klucza).
 *
 * Zweryfikowane zywym zapytaniem (2026-10-29) `GET https://crt.sh/?q=<domena>&output=json`:
 * tablica obiektow z polami issuer_ca_id, issuer_name, common_name, name_value
 * (SAN-y rozdzielone \n), id, not_before, not_after, serial_number, result_count.
 * Brak oficjalnej dokumentacji - endpoint potwierdzony przez proby na zywo,
 * nie wymyslony.
 */
export class CrtShAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "crtsh",
    name: "crt.sh (Certificate Transparency)",
    category: "certificate_transparency",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "domain", supportsWildcards: false, maxResults: 500 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions:
      "Brak klucza - wylacz przez ADAPTER_CRTSH_ENABLED=false, jesli nie chcesz go uzywac. " +
      "Nieoficjalne API crt.sh bez gwarantowanego SLA.",
  };

  private readonly fetchFn: typeof safeFetch;
  private readonly baseUrl: string;

  constructor(private readonly config: CrtShAdapterConfig) {
    this.fetchFn = config.fetchFn ?? safeFetch;
    this.baseUrl = config.baseUrl ?? "https://crt.sh";
  }

  isConfigured(): boolean {
    return this.config.enabled;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "domain") {
      return { ok: false, reason: "Adapter crt.sh obsluguje tylko zapytania typu 'domain'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter crt.sh nie wspiera wildcardow UI (crt.sh ma wlasna skladnie %, nieobslugiwana tutaj)" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const domain = normalizeDomain(query.raw);
    const url = `${this.baseUrl}/?q=${encodeURIComponent(domain)}&output=json`;

    const result = await this.fetchFn(url, { timeoutMs: context.timeoutMs, signal: context.signal });

    if (result.status === 404) return;
    if (result.status < 200 || result.status >= 300) {
      throw new AdapterHttpError(`crt.sh zwrocilo blad HTTP ${result.status}`, result.status, null);
    }

    let entries: CrtShEntry[];
    try {
      const text = result.body.toString("utf8").trim();
      entries = text.length === 0 ? [] : (JSON.parse(text) as CrtShEntry[]);
    } catch (err) {
      throw new Error(`Nie udalo sie sparsowac odpowiedzi crt.sh jako JSON: ${(err as Error).message}`);
    }

    // crt.sh zwraca jeden wiersz per (certyfikat, SAN) - deduplikujemy po id certyfikatu.
    const seen = new Set<number>();
    for (const entry of entries) {
      if (context.signal.aborted) return;
      if (seen.has(entry.id)) continue;
      seen.add(entry.id);
      yield this.normalizeResult(entry);
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const entry = raw as CrtShEntry;
    const sanNames = entry.name_value ? entry.name_value.split("\n").filter(Boolean) : [];
    return {
      sourceRecordId: String(entry.id),
      canonicalUrl: `https://crt.sh/?id=${entry.id}`,
      kind: "certificate",
      title: `Certyfikat: ${entry.common_name}`,
      summary: `Wystawca: ${entry.issuer_name}`,
      attrs: {
        commonName: entry.common_name,
        subjectAltNames: sanNames,
        issuerName: entry.issuer_name,
        issuerCaId: entry.issuer_ca_id,
        serialNumber: entry.serial_number,
        notBefore: entry.not_before,
        notAfter: entry.not_after,
      },
      observedAt: normalizeDateToUtcIso(entry.not_before) ?? null,
      raw: entry,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    const startedAt = Date.now();
    try {
      const result = await this.fetchFn(`${this.baseUrl}/?q=example.com&output=json`, { timeoutMs: 5000 });
      if (result.status < 200 || result.status >= 300) {
        return { ok: false, errorCode: `http_${result.status}`, message: "crt.sh zwrocilo blad" };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "crtsh_healthcheck_failed", message: (err as Error).message };
    }
  }
}
