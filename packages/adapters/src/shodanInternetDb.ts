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
import { safeFetch, AdapterHttpError, normalizeIp } from "@unified-osint/core";

interface ShodanInternetDbResponse {
  ip: string;
  ports: number[];
  hostnames: string[];
  cpes: string[];
  tags: string[];
  vulns: string[];
}

export interface ShodanInternetDbAdapterConfig {
  enabled: boolean;
  baseUrl?: string;
  fetchFn?: typeof safeFetch;
}

/**
 * Adapter Shodan InternetDB - oficjalne darmowe API Shodan, bez klucza.
 *
 * Zrodlo: https://blog.shodan.io/introducing-the-internetdb-api/
 * `GET https://internetdb.shodan.io/{ip}`. Zweryfikowane zywym zapytaniem
 * (2026-10-29): 200 = {ip, ports, hostnames, cpes, tags, vulns}; 404 =
 * {"detail":"No information available"} dla adresu bez danych (potwierdzone
 * zywym testem na adresie bez wynikow, nie zgadywane).
 * UWAGA: darmowe TYLKO do uzytku niekomercyjnego (Shodan ToS) - dane
 * odswiezane tygodniowo, nie w czasie rzeczywistym.
 */
export class ShodanInternetDbAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "shodan_internetdb",
    name: "Shodan InternetDB",
    category: "threat_intel",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "ip", supportsWildcards: false, maxResults: 1 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions:
      "Brak klucza - wylacz przez ADAPTER_SHODAN_INTERNETDB_ENABLED=false, jesli nie chcesz go uzywac. " +
      "Darmowe wylacznie do uzytku niekomercyjnego (ToS Shodan); dane odswiezane tygodniowo.",
  };

  private readonly fetchFn: typeof safeFetch;
  private readonly baseUrl: string;

  constructor(private readonly config: ShodanInternetDbAdapterConfig) {
    this.fetchFn = config.fetchFn ?? safeFetch;
    this.baseUrl = config.baseUrl ?? "https://internetdb.shodan.io";
  }

  isConfigured(): boolean {
    return this.config.enabled;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "ip") {
      return { ok: false, reason: "Adapter Shodan InternetDB obsluguje tylko zapytania typu 'ip'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter Shodan InternetDB nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const ip = normalizeIp(query.raw);
    if (!ip) return;

    const result = await this.fetchFn(`${this.baseUrl}/${encodeURIComponent(ip)}`, {
      timeoutMs: context.timeoutMs,
      signal: context.signal,
    });

    if (result.status === 404) return; // brak danych dla tego IP - to nie blad
    if (result.status < 200 || result.status >= 300) {
      throw new AdapterHttpError(`Shodan InternetDB zwrocilo blad HTTP ${result.status}`, result.status, null);
    }

    let data: ShodanInternetDbResponse;
    try {
      data = JSON.parse(result.body.toString("utf8")) as ShodanInternetDbResponse;
    } catch (err) {
      throw new Error(`Nie udalo sie sparsowac odpowiedzi Shodan InternetDB jako JSON: ${(err as Error).message}`);
    }

    yield this.normalizeResult(data);
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const data = raw as ShodanInternetDbResponse;
    return {
      sourceRecordId: data.ip,
      canonicalUrl: null,
      kind: "host_exposure",
      title: `Ekspozycja sieciowa: ${data.ip}`,
      summary: data.ports?.length ? `Otwarte porty: ${data.ports.join(", ")}` : null,
      attrs: {
        ip: data.ip,
        ports: data.ports ?? [],
        hostnames: data.hostnames ?? [],
        cpes: data.cpes ?? [],
        tags: data.tags ?? [],
        vulns: data.vulns ?? [],
      },
      observedAt: null,
      raw: data,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    const startedAt = Date.now();
    try {
      const result = await this.fetchFn(`${this.baseUrl}/1.1.1.1`, { timeoutMs: 5000 });
      if (result.status < 200 || result.status >= 300) {
        return { ok: false, errorCode: `http_${result.status}`, message: "Shodan InternetDB zwrocilo blad" };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "shodan_internetdb_healthcheck_failed", message: (err as Error).message };
    }
  }
}
