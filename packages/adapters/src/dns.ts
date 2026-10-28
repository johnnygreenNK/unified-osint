import dns from "node:dns/promises";
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
import { normalizeDomain } from "@unified-osint/core";

type DnsRecordType = "A" | "AAAA" | "MX" | "TXT" | "NS" | "CNAME";
const RECORD_TYPES: DnsRecordType[] = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"];

/**
 * Adapter DNS - wylacznie publiczne zapytania resolwera (A/AAAA/MX/TXT/NS/CNAME).
 * Brak klucza API, brak kosztu. Nie wspiera wildcardow - DNS wymaga
 * dokladnej nazwy domeny.
 */
export class DnsAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "dns",
    name: "DNS (resolver publiczny)",
    category: "dns_infra",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "domain", supportsWildcards: false, maxResults: RECORD_TYPES.length }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions: "Brak konfiguracji - adapter dziala od razu.",
  };

  isConfigured(): boolean {
    return true;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "domain") {
      return { ok: false, reason: "Adapter DNS obsluguje tylko zapytania typu 'domain'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter DNS nie wspiera wildcardow - podaj dokladna nazwe domeny" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const domain = normalizeDomain(query.raw);

    for (const type of RECORD_TYPES) {
      if (context.signal.aborted) return;
      try {
        const values = await resolveWithTimeout(domain, type, context.signal);
        if (!values || values.length === 0) continue;
        yield this.normalizeResult({ domain, type, values });
      } catch (err) {
        if (isNoDataError(err)) continue; // brak rekordu danego typu - to nie blad
        context.logger.warn("dns_resolve_failed", { type, error: (err as Error).message });
        // Dalej probujemy pozostale typy rekordow - czesciowa awaria jednego typu
        // nie powinna przerywac calego zadania.
      }
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { domain, type, values } = raw as { domain: string; type: string; values: unknown[] };
    return {
      sourceRecordId: `${domain}:${type}`,
      canonicalUrl: null,
      kind: "dns_record",
      title: `${type} dla ${domain}`,
      summary: null,
      attrs: { domain, recordType: type, values },
      observedAt: new Date().toISOString(),
      raw,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    const startedAt = Date.now();
    try {
      await dns.resolve4("example.com");
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "dns_healthcheck_failed", message: (err as Error).message };
    }
  }
}

async function resolveWithTimeout(domain: string, type: DnsRecordType, signal: AbortSignal): Promise<unknown[]> {
  const resolvePromise: Promise<unknown[]> = (async () => {
    switch (type) {
      case "A":
        return dns.resolve4(domain);
      case "AAAA":
        return dns.resolve6(domain);
      case "MX":
        return dns.resolveMx(domain);
      case "TXT":
        return dns.resolveTxt(domain);
      case "NS":
        return dns.resolveNs(domain);
      case "CNAME":
        return dns.resolveCname(domain);
    }
  })();

  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new Error("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    resolvePromise
      .then((v) => {
        signal.removeEventListener("abort", onAbort);
        resolve(v);
      })
      .catch((err) => {
        signal.removeEventListener("abort", onAbort);
        reject(err);
      });
  });
}

function isNoDataError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException)?.code;
  return code === "ENODATA" || code === "ENOTFOUND" || code === "ESERVFAIL";
}
