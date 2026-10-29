import type { Pool } from "pg";
import type {
  AdapterDescriptor,
  AdapterRecord,
  HealthCheckResult,
  QueryType,
  QueryValidation,
  SearchContext,
  SearchQuery,
  SourceAdapter,
  SourceCapability,
} from "@unified-osint/core";
import { withAppContext, userContext, normalizeEmail, normalizeIp, normalizePhone, normalizeDomain } from "@unified-osint/core";

export interface LocalImportAdapterConfig {
  pool: Pool;
}

interface LocalImportRow {
  id: string;
  batch_id: string;
  email: string | null;
  username: string | null;
  ip: string | null;
  phone: string | null;
  domain: string | null;
  attrs: Record<string, unknown>;
  created_at: string;
}

const COLUMN_BY_QUERY_TYPE: Record<string, "email" | "username" | "ip" | "phone" | "domain"> = {
  email: "email",
  username: "username",
  ip: "ip",
  phone: "phone",
  domain: "domain",
};

/**
 * Adapter danych wgranych samodzielnie (CSV/SQL dump) przez endpoint
 * `POST /imports` (apps/api/src/routes/imports.ts). Nie odpytuje zewnetrznego
 * serwisu - przeszukuje `local_import_records` nalezace do biezacego
 * uzytkownika (RLS wymusza izolacje), wiec wyniki przechodza przez ten sam
 * pipeline dedupu/maskowania/SSE co pozostale zrodla.
 */
export class LocalImportAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "local_import",
    name: "Wlasne importy (CSV/SQL)",
    category: "local_import",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [
      { queryType: "email", supportsWildcards: false, maxResults: 500 },
      { queryType: "username", supportsWildcards: false, maxResults: 500 },
      { queryType: "ip", supportsWildcards: false, maxResults: 500 },
      { queryType: "phone", supportsWildcards: false, maxResults: 500 },
      { queryType: "domain", supportsWildcards: false, maxResults: 500 },
    ],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions: "Brak konfiguracji - dane pochodza z wlasnych importow (patrz panel 'Importuj dane').",
  };

  constructor(private readonly config: LocalImportAdapterConfig) {}

  isConfigured(): boolean {
    return true;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (!(query.type in COLUMN_BY_QUERY_TYPE)) {
      return { ok: false, reason: "Adapter wlasnych importow obsluguje tylko email/username/ip/phone/domain" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter wlasnych importow nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  private normalizeQueryValue(type: QueryType, raw: string): string | null {
    switch (type) {
      case "email":
        return normalizeEmail(raw);
      case "username":
        return raw.trim().toLowerCase();
      case "ip":
        return normalizeIp(raw);
      case "phone":
        return normalizePhone(raw);
      case "domain":
        return normalizeDomain(raw);
      default:
        return null;
    }
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const column = COLUMN_BY_QUERY_TYPE[query.type];
    if (!column) return;
    const value = this.normalizeQueryValue(query.type, query.raw);
    if (!value) return;

    const rows = await withAppContext(this.config.pool, userContext(context.userId, context.userRole), (client) =>
      client.query<LocalImportRow>(
        `select id, batch_id, email, username, ip, phone, domain, attrs, created_at
         from local_import_records
         where owner_id = $1 and ${column} = $2
         limit 500`,
        [context.userId, value]
      )
    );

    for (const row of rows.rows) {
      if (context.signal.aborted) return;
      yield this.normalizeResult(row);
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const row = raw as LocalImportRow;
    const label = row.email ?? row.username ?? row.ip ?? row.phone ?? row.domain ?? row.id;
    return {
      sourceRecordId: row.id,
      canonicalUrl: null,
      kind: "breach_record",
      title: `Wlasny import: ${label}`,
      summary: "Rekord z pliku wgranego samodzielnie przez uzytkownika",
      attrs: { ...row.attrs, batchId: row.batch_id },
      observedAt: row.created_at,
      raw,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    return { ok: true, latencyMs: 0 };
  }
}
