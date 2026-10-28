import { createHash } from "node:crypto";
import type {
  AdapterDescriptor,
  AdapterRecord,
  HealthCheckResult,
  QueryValidation,
  SearchContext,
  SourceAdapter,
  SourceCapability,
} from "@unified-osint/core";
import type { SearchQuery } from "@unified-osint/core";

/**
 * Adapter demonstracyjny - dane SYNTETYCZNE, generowane deterministycznie
 * z zapytania (bez zadnego zewnetrznego wywolania). Kazdy rekord ma w
 * tytule i atrybutach jawny prefiks "[DEMO]" / `attrs.demo = true`, aby
 * NIGDY nie mozna go pomylic z prawdziwym wynikiem OSINT.
 *
 * Cel: pozwolic przetestowac cala platforme (orchestrator, dedup, SSE,
 * Telegram) bez jakiegokolwiek klucza API.
 */
export class DemoAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "demo",
    name: "Demo (dane syntetyczne)",
    category: "demo",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [
      "email",
      "username",
      "name",
      "domain",
      "ip",
      "phone",
      "hash",
      "url",
      "text",
    ].map((queryType) => ({ queryType, supportsWildcards: true, maxResults: 5 }) as SourceCapability),
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions: "Brak konfiguracji - adapter dziala od razu, dane sa syntetyczne.",
  };

  isConfigured(): boolean {
    return true;
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(_query: SearchQuery): QueryValidation {
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const seed = createHash("sha256").update(query.raw.toLowerCase()).digest("hex");
    const count = 1 + (parseInt(seed.slice(0, 2), 16) % 3); // 1-3 rekordy, deterministycznie

    for (let i = 0; i < count; i++) {
      if (context.signal.aborted) return;
      // Symulacja naturalnego opoznienia sieciowego, zeby UI live-search mialo co pokazac.
      await delay(150, context.signal);

      const recordSeed = `${seed}-${i}`;
      yield this.normalizeResult({ recordSeed, query: query.raw, index: i });
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { recordSeed, query, index } = raw as { recordSeed: string; query: string; index: number };
    return {
      sourceRecordId: recordSeed,
      canonicalUrl: null,
      kind: "demo_record",
      title: `[DEMO] Wynik ${index + 1} dla "${query}"`,
      summary: "To jest syntetyczny rekord demonstracyjny - nie pochodzi z zadnego prawdziwego zrodla.",
      attrs: { demo: true, query, index },
      observedAt: new Date().toISOString(),
      raw,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    return { ok: true, latencyMs: 1 };
  }
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}
