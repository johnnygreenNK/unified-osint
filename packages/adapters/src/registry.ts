import type { AdapterRegistry, SourceAdapter } from "@unified-osint/core";
import { DemoAdapter } from "./demo.js";
import { DnsAdapter } from "./dns.js";
import { epieosStub, intelxStub, snusbaseStub } from "./stubs.js";

/**
 * Jedyne miejsce w repozytorium, ktore wie o wszystkich konkretnych
 * adapterach. Dodanie nowego zrodla = nowy wpis tutaj, zero zmian w
 * packages/core.
 */
export class StaticAdapterRegistry implements AdapterRegistry {
  private readonly adapters: Map<string, SourceAdapter>;

  constructor(adapters: SourceAdapter[]) {
    this.adapters = new Map(adapters.map((adapter) => [adapter.descriptor.id, adapter]));
  }

  get(sourceId: string): SourceAdapter | undefined {
    return this.adapters.get(sourceId);
  }

  list(): SourceAdapter[] {
    return [...this.adapters.values()];
  }
}

export function createDefaultRegistry(): StaticAdapterRegistry {
  return new StaticAdapterRegistry([new DemoAdapter(), new DnsAdapter(), snusbaseStub, intelxStub, epieosStub]);
}
