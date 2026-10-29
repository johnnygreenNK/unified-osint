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

interface HudsonRockCredential {
  url?: string;
  domain?: string;
  username?: string;
  password?: string;
  type?: "employee" | "user" | "third_party";
}

interface HudsonRockStealer {
  stealer?: string;
  employeeAt?: string;
  clientAt?: string;
  date_compromised?: string;
  date_uploaded?: string;
  stealer_family?: string;
  ip?: string;
  computer_name?: string;
  operating_system?: string;
  malware_path?: string;
  credentials?: HudsonRockCredential[];
}

interface HudsonRockResponse {
  data?: HudsonRockStealer[];
  nextCursor?: string;
}

export interface HudsonRockAdapterConfig {
  apiKey: string;
  baseUrl: string;
  fetchFn?: typeof safeFetch;
}

/**
 * Adapter Hudson Rock (Cavalier Infostealers API v3).
 *
 * Zakres zweryfikowany w oficjalnej dokumentacji (docs.hudsonrock.com,
 * 2026-10-29):
 *  - POST {baseUrl}/json/v3/search-by-login/emails i
 *    POST {baseUrl}/json/v3/search-by-login/usernames - naglowek `api-key`,
 *    body `{ logins: string[] }` (1-50 pozycji, tu zawsze 1).
 *  - Limit: 50 req/10s, max 20 "stealerow" w odpowiedzi, timeout serwera 90s.
 *  - Odpowiedz: { data: Stealer[], nextCursor }, gdzie kazdy Stealer opisuje
 *    jeden skompromitowany komputer (stealer, data kompromitacji, IP,
 *    nazwa komputera, OS) i liste `credentials` (url/domain/username/
 *    password/type) znalezionych na nim - w tym PLAINTEXT hasla.
 *
 * Zgodnie z zasada braku masowego wydobywania hasel: adapter przyjmuje
 * tylko `email`/`username` (nie szuka po hasle), a kazde pole `password`
 * w `attrs` jest maskowane - pelna wartosc istnieje wylacznie w
 * `AdapterRecord.raw` (ten sam wzorzec co Snusbase).
 */
export class HudsonRockAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "hudsonrock",
    name: "Hudson Rock (Cavalier Infostealers)",
    category: "breach_data",
    requiredEnvVars: ["HUDSONROCK_API_KEY"],
    adapterVersion: "1.0.0",
    capabilities: [
      { queryType: "email", supportsWildcards: false, maxResults: 20 },
      { queryType: "username", supportsWildcards: false, maxResults: 20 },
    ],
    cost: { unit: "credit", estimatedCostPerQuery: 1, unknown: true },
    setupInstructions:
      "Wymaga HUDSONROCK_API_KEY (platny klucz API z panelu Cavalier, wymaga uprawnienia 'search-by-login').",
  };

  private readonly fetchFn: typeof safeFetch;

  constructor(private readonly config: HudsonRockAdapterConfig) {
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
      return { ok: false, reason: "Adapter Hudson Rock obsluguje tylko zapytania typu 'email' lub 'username'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter Hudson Rock nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const path = query.type === "email" ? "search-by-login/emails" : "search-by-login/usernames";
    const result = await this.fetchFn(`${this.config.baseUrl}/json/v3/${path}`, {
      method: "POST",
      headers: { "api-key": this.config.apiKey, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ logins: [query.raw] }),
      timeoutMs: context.timeoutMs,
      signal: context.signal,
    });

    if (result.status < 200 || result.status >= 300) {
      const retryAfter = result.headers["retry-after"];
      throw new AdapterHttpError(
        `Hudson Rock API zwrocilo blad HTTP ${result.status}`,
        result.status,
        Array.isArray(retryAfter) ? retryAfter[0] : retryAfter ?? null
      );
    }

    let parsed: HudsonRockResponse;
    try {
      parsed = JSON.parse(result.body.toString("utf8")) as HudsonRockResponse;
    } catch (err) {
      throw new Error(`Nie udalo sie sparsowac odpowiedzi Hudson Rock jako JSON: ${(err as Error).message}`);
    }

    for (const stealer of parsed.data ?? []) {
      if (context.signal.aborted) return;
      try {
        yield this.normalizeResult(stealer);
      } catch (err) {
        context.logger.warn("hudsonrock_normalize_failed", { error: (err as Error).message });
      }
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const stealer = raw as HudsonRockStealer;

    const credentials = (stealer.credentials ?? []).map((cred) => ({ ...cred }));

    const attrs: Record<string, unknown> = {
      stealer: stealer.stealer ?? null,
      stealerFamily: stealer.stealer_family ?? null,
      employeeAt: stealer.employeeAt ?? null,
      clientAt: stealer.clientAt ?? null,
      ip: stealer.ip ?? null,
      computerName: stealer.computer_name ?? null,
      operatingSystem: stealer.operating_system ?? null,
      dateCompromised: stealer.date_compromised ?? null,
      credentials,
      credentialCount: stealer.credentials?.length ?? 0,
    };

    const naturalIdSeed = `${stealer.computer_name ?? ""}:${stealer.date_compromised ?? ""}:${stealer.stealer ?? ""}`;
    return {
      sourceRecordId: sha256(naturalIdSeed),
      canonicalUrl: null,
      kind: "infostealer_infection",
      title: `Infostealer: ${stealer.stealer ?? stealer.stealer_family ?? "nieznany"}`,
      summary: stealer.computer_name ? `Komputer: ${stealer.computer_name}` : null,
      attrs,
      observedAt: normalizeDate(stealer.date_compromised ?? stealer.date_uploaded),
      raw: stealer,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    const startedAt = Date.now();
    try {
      // Pusty body (bez logins) wystarcza, aby odrozniac blad autoryzacji (401/403) od
      // bledu walidacji (400) - oba potwierdzaja, ze API jest dostepne i odpowiada.
      const result = await this.fetchFn(`${this.config.baseUrl}/json/v3/search-by-login/emails`, {
        method: "POST",
        headers: { "api-key": this.config.apiKey, "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ logins: [] }),
        timeoutMs: 5000,
      });
      if (result.status === 401 || result.status === 403) {
        return { ok: false, errorCode: `http_${result.status}`, message: "Hudson Rock API odrzucilo klucz" };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "hudsonrock_healthcheck_failed", message: (err as Error).message };
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
