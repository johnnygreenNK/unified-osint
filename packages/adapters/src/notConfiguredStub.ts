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

/**
 * Adapter-zaslepka dla zrodel, ktorych integracji HTTP NIE zaimplementowano
 * jeszcze w tym repozytorium - niezaleznie od obecnosci klucza API w .env.
 *
 * Dlaczego "niezaleznie od klucza": zgodnie z zasada "nie wymyslaj
 * endpointow API" z Etapu 1, implementacja wywolan do Snusbase/IntelX/Epieos
 * zostanie dodana PO weryfikacji ich oficjalnej dokumentacji. Do tego czasu
 * ten adapter zawsze zglasza `not_configured`, aby nigdy nie sugerowac
 * dzialajacej integracji, ktora w rzeczywistosci nic nie robi.
 *
 * Gdy integracja zostanie zaimplementowana, zastap uzycie tej klasy
 * dedykowanym adapterem (patrz docs/adding-an-adapter.md).
 */
export function createNotConfiguredStub(params: {
  id: string;
  name: string;
  category: AdapterDescriptor["category"];
  requiredEnvVars: string[];
  capabilities: SourceCapability[];
  cost: AdapterDescriptor["cost"];
  verificationNote: string;
}): SourceAdapter {
  const descriptor: AdapterDescriptor = {
    id: params.id,
    name: params.name,
    category: params.category,
    requiredEnvVars: params.requiredEnvVars,
    adapterVersion: "0.0.0-stub",
    capabilities: params.capabilities,
    cost: params.cost,
    setupInstructions: `Integracja NIE jest jeszcze zaimplementowana (status zawsze 'not_configured'). ${params.verificationNote}`,
  };

  return {
    descriptor,
    isConfigured(): boolean {
      return false;
    },
    getCapabilities(): SourceCapability[] {
      return descriptor.capabilities;
    },
    validateQuery(_query: SearchQuery): QueryValidation {
      return { ok: false, reason: "Adapter nie jest jeszcze zaimplementowany (wymaga weryfikacji API)" };
    },
    // eslint-disable-next-line require-yield
    async *search(_query: SearchQuery, _context: SearchContext): AsyncGenerator<AdapterRecord> {
      throw new Error(
        `Adapter '${params.id}' nie jest zaimplementowany. ${params.verificationNote} Nigdy nie powinien byc wywolany, bo isConfigured() zwraca false.`
      );
    },
    normalizeResult(raw: unknown): AdapterRecord {
      throw new Error(`normalizeResult() niedostepne dla niezaimplementowanego adaptera '${params.id}'`);
    },
    async healthCheck(): Promise<HealthCheckResult> {
      return { ok: false, errorCode: "not_configured", message: "Integracja nie jest jeszcze zaimplementowana" };
    },
  };
}
