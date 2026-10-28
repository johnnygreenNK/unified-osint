import type { SourceAdapter } from "./adapter.js";

/**
 * Rejestr adapterow - zdefiniowany tutaj (core), implementowany w
 * @unified-osint/adapters, aby orchestrator nie musial zalezec od
 * konkretnych adapterow. Dodanie nowego zrodla = nowy wpis w rejestrze,
 * zero zmian w core.
 */
export interface AdapterRegistry {
  get(sourceId: string): SourceAdapter | undefined;
  list(): SourceAdapter[];
}
