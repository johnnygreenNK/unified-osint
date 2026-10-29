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
import { safeFetch, AdapterHttpError, normalizeEmail } from "@unified-osint/core";

interface EmailRepDetails {
  blacklisted?: boolean;
  malicious_activity?: boolean;
  malicious_activity_recent?: boolean;
  credentials_leaked?: boolean;
  credentials_leaked_recent?: boolean;
  data_breach?: boolean;
  first_seen?: string;
  last_seen?: string;
  domain_exists?: boolean;
  domain_reputation?: string;
  new_domain?: boolean;
  days_since_domain_creation?: number;
  suspicious_tld?: boolean;
  spam?: boolean;
  free_provider?: boolean;
  disposable?: boolean;
  deliverable?: boolean;
  accept_all?: boolean;
  valid_mx?: boolean;
  spoofable?: boolean;
  spf_strict?: boolean;
  dmarc_enforced?: boolean;
  profiles?: string[];
}

interface EmailRepResponse {
  email: string;
  reputation: "high" | "medium" | "low" | "none";
  suspicious: boolean;
  references: number;
  details?: EmailRepDetails;
}

export interface EmailRepAdapterConfig {
  apiKey: string;
  /** Wymagany przez API EmailRep naglowek user-agent (bez niego 403). */
  userAgent: string;
  baseUrl?: string;
  fetchFn?: typeof safeFetch;
}

/**
 * Adapter EmailRep.io (Sublime Security) - reputacja adresu e-mail.
 *
 * UWAGA: wbrew zalozeniu "bez klucza" - zweryfikowane na zywo (2026-10-29,
 * `curl -i https://emailrep.io/test@example.com` -> 429 "the unauthenticated
 * API is currently disabled. please use an API key") oraz w oficjalnej
 * dokumentacji (docs.sublime.security/reference/emailrep-introduction):
 * nieautoryzowane API jest wylaczone, a Sublime NIE WYDAJE nowych kluczy
 * EmailRep (serwis nie jest juz aktywnie rozwijany - tylko istniejace klucze
 * dalej dzialaja w ramach swoich limitow). Adapter wchodzi w stan
 * `not_configured`, dopoki ktos nie poda wlasnego, wczesniej wydanego klucza.
 *
 * Kontrakt (z dokumentacji):
 *  - `GET https://emailrep.io/{email}` z naglowkami `Key: <apikey>` i
 *    `User-Agent: <nazwa aplikacji>` (brak User-Agent = 403, zly klucz = 401,
 *    limit przekroczony = 429).
 *  - Odpowiedz: { email, reputation: high|medium|low|none, suspicious,
 *    references, details: { blacklisted, malicious_activity,
 *    malicious_activity_recent, credentials_leaked, credentials_leaked_recent,
 *    data_breach, first_seen, last_seen, domain_exists, domain_reputation,
 *    new_domain, days_since_domain_creation, suspicious_tld, spam,
 *    free_provider, disposable, deliverable, accept_all, valid_mx,
 *    spoofable, spf_strict, dmarc_enforced, profiles[] } }.
 */
export class EmailRepAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "emailrep",
    name: "EmailRep.io",
    category: "threat_intel",
    requiredEnvVars: ["EMAILREP_API_KEY"],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "email", supportsWildcards: false, maxResults: 1 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions:
      "Wymaga EMAILREP_API_KEY. Sublime Security NIE WYDAJE juz nowych kluczy EmailRep " +
      "(serwis wygaszony, dziala tylko dla wczesniej wydanych kluczy) - zobacz " +
      "docs.sublime.security/reference/emailrep-introduction.",
  };

  private readonly fetchFn: typeof safeFetch;
  private readonly baseUrl: string;

  constructor(private readonly config: EmailRepAdapterConfig) {
    this.fetchFn = config.fetchFn ?? safeFetch;
    this.baseUrl = config.baseUrl ?? "https://emailrep.io";
  }

  isConfigured(): boolean {
    return this.config.apiKey.length > 0;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "email") {
      return { ok: false, reason: "Adapter EmailRep.io obsluguje tylko zapytania typu 'email'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter EmailRep.io nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const email = normalizeEmail(query.raw);
    const result = await this.fetchFn(`${this.baseUrl}/${encodeURIComponent(email)}`, {
      headers: { Key: this.config.apiKey, "User-Agent": this.config.userAgent },
      timeoutMs: context.timeoutMs,
      signal: context.signal,
    });

    if (result.status < 200 || result.status >= 300) {
      const retryAfter = result.headers["x-rate-limit-daily-remaining"];
      throw new AdapterHttpError(
        `EmailRep.io zwrocilo blad HTTP ${result.status}`,
        result.status,
        Array.isArray(retryAfter) ? retryAfter[0] : retryAfter ?? null
      );
    }

    let data: EmailRepResponse;
    try {
      data = JSON.parse(result.body.toString("utf8")) as EmailRepResponse;
    } catch (err) {
      throw new Error(`Nie udalo sie sparsowac odpowiedzi EmailRep.io jako JSON: ${(err as Error).message}`);
    }

    yield this.normalizeResult(data);
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const data = raw as EmailRepResponse;
    return {
      sourceRecordId: data.email,
      canonicalUrl: null,
      kind: "email_reputation",
      title: `Reputacja: ${data.email} (${data.reputation})`,
      summary: data.suspicious ? "Oznaczony jako podejrzany" : null,
      attrs: {
        reputation: data.reputation,
        suspicious: data.suspicious,
        references: data.references,
        ...data.details,
      },
      observedAt: null,
      raw: data,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    if (!this.isConfigured()) {
      return { ok: false, errorCode: "not_configured", message: "EMAILREP_API_KEY nie jest ustawiony" };
    }
    const startedAt = Date.now();
    try {
      const result = await this.fetchFn(`${this.baseUrl}/test@example.com`, {
        headers: { Key: this.config.apiKey, "User-Agent": this.config.userAgent },
        timeoutMs: 5000,
      });
      if (result.status === 401) {
        return { ok: false, errorCode: "http_401", message: "EmailRep.io odrzucilo klucz API" };
      }
      if (result.status < 200 || result.status >= 300) {
        return { ok: false, errorCode: `http_${result.status}`, message: "EmailRep.io zwrocilo blad" };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "emailrep_healthcheck_failed", message: (err as Error).message };
    }
  }
}
