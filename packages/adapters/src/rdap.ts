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
import {
  safeFetch,
  AdapterHttpError,
  normalizeDomain,
  normalizeIp,
  normalizeDateToUtcIso,
} from "@unified-osint/core";

interface RdapEvent {
  eventAction: string;
  eventDate: string;
}

interface RdapEntity {
  objectClassName?: string;
  handle?: string;
  roles?: string[];
}

interface RdapResponse {
  objectClassName?: string;
  handle?: string;
  ldhName?: string;
  status?: string[];
  entities?: RdapEntity[];
  events?: RdapEvent[];
  secureDNS?: { delegationSigned?: boolean };
  nameservers?: Array<{ ldhName?: string }>;
  notices?: Array<{ title?: string }>;
}

export interface RdapAdapterConfig {
  enabled: boolean;
  baseUrl?: string;
  fetchFn?: typeof safeFetch;
}

/**
 * Adapter RDAP (RFC 7480/7481/9082/9083/9224) - bez klucza, standard IETF.
 *
 * `rdap.org` to publiczny bootstrap redirector: GET /domain/{domena} lub
 * /ip/{ip} odpowiada przekierowaniem HTTP 302 do wlasciwego serwera RDAP
 * danego rejestru. `safeFetch` juz podaza za przekierowaniami (do 5 hopow)
 * i ponownie waliduje SSRF na kazdym kroku, wiec adapter nie potrzebuje
 * zadnej specjalnej logiki - zweryfikowane zywym zapytaniem 2026-10-29
 * (`curl -L https://rdap.org/domain/example.com`).
 * Zrodlo: https://rdap.org/ (Cloudflare limituje do 10 zadan / 10 s).
 */
export class RdapAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "rdap",
    name: "RDAP (rdap.org)",
    category: "dns_infra",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [
      { queryType: "domain", supportsWildcards: false, maxResults: 1 },
      { queryType: "ip", supportsWildcards: false, maxResults: 1 },
    ],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions:
      "Brak klucza - wylacz przez ADAPTER_RDAP_ENABLED=false, jesli nie chcesz go uzywac. " +
      "rdap.org limituje do 10 zadan / 10 s (Cloudflare).",
  };

  private readonly fetchFn: typeof safeFetch;
  private readonly baseUrl: string;

  constructor(private readonly config: RdapAdapterConfig) {
    this.fetchFn = config.fetchFn ?? safeFetch;
    this.baseUrl = config.baseUrl ?? "https://rdap.org";
  }

  isConfigured(): boolean {
    return this.config.enabled;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "domain" && query.type !== "ip") {
      return { ok: false, reason: "Adapter RDAP obsluguje tylko zapytania typu 'domain' lub 'ip'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter RDAP nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    let url: string;
    if (query.type === "ip") {
      const ip = normalizeIp(query.raw);
      if (!ip) return;
      url = `${this.baseUrl}/ip/${encodeURIComponent(ip)}`;
    } else {
      const domain = normalizeDomain(query.raw);
      url = `${this.baseUrl}/domain/${encodeURIComponent(domain)}`;
    }

    const result = await this.fetchFn(url, { timeoutMs: context.timeoutMs, signal: context.signal });

    if (result.status === 404) return; // brak znanego serwera RDAP dla tego zasobu
    if (result.status < 200 || result.status >= 300) {
      const retryAfter = result.headers["retry-after"];
      throw new AdapterHttpError(
        `RDAP zwrocilo blad HTTP ${result.status}`,
        result.status,
        Array.isArray(retryAfter) ? retryAfter[0] : retryAfter ?? null
      );
    }

    let data: RdapResponse;
    try {
      data = JSON.parse(result.body.toString("utf8")) as RdapResponse;
    } catch (err) {
      throw new Error(`Nie udalo sie sparsowac odpowiedzi RDAP jako JSON: ${(err as Error).message}`);
    }

    yield this.normalizeResult({ query: query.raw, data });
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { query, data } = raw as { query: string; data: RdapResponse };
    const registrationRaw = data.events?.find((e) => e.eventAction === "registration")?.eventDate ?? null;
    const registration = registrationRaw ? normalizeDateToUtcIso(registrationRaw) : null;
    return {
      sourceRecordId: data.handle ?? data.ldhName ?? query,
      canonicalUrl: null,
      kind: "rdap_record",
      title: `RDAP: ${data.ldhName ?? query}`,
      summary: data.status?.join(", ") ?? null,
      attrs: {
        objectClassName: data.objectClassName ?? null,
        handle: data.handle ?? null,
        status: data.status ?? [],
        events: data.events ?? [],
        nameservers: data.nameservers?.map((ns) => ns.ldhName).filter(Boolean) ?? [],
        secureDnsSigned: data.secureDNS?.delegationSigned ?? null,
        entities: data.entities?.map((e) => ({ handle: e.handle ?? null, roles: e.roles ?? [] })) ?? [],
      },
      observedAt: registration,
      raw: data,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    const startedAt = Date.now();
    try {
      const result = await this.fetchFn(`${this.baseUrl}/domain/example.com`, { timeoutMs: 5000 });
      if (result.status < 200 || result.status >= 300) {
        return { ok: false, errorCode: `http_${result.status}`, message: "RDAP zwrocilo blad" };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "rdap_healthcheck_failed", message: (err as Error).message };
    }
  }
}
