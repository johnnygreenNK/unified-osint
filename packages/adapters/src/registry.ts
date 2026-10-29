import type { AdapterRegistry, Env, SourceAdapter } from "@unified-osint/core";
import { DemoAdapter } from "./demo.js";
import { DnsAdapter } from "./dns.js";
import { SnusbaseAdapter } from "./snusbase.js";
import { epieosStub, intelxStub } from "./stubs.js";
import { AmassAdapter } from "./amass.js";
import { TruffleHogAdapter } from "./trufflehog.js";
import { GitleaksAdapter } from "./gitleaks.js";
import { SherlockAdapter } from "./sherlock.js";
import { MaigretAdapter } from "./maigret.js";
import { HoleheAdapter } from "./holehe.js";
import { TheHarvesterAdapter } from "./theHarvester.js";

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

export function createDefaultRegistry(
  env?: Pick<
    Env,
    | "SNUSBASE_API_KEY"
    | "SNUSBASE_API_BASE_URL"
    | "CLI_ADAPTER_TIMEOUT_MS"
    | "GITLEAKS_BIN_PATH"
    | "GIT_BIN_PATH"
    | "AMASS_BIN_PATH"
    | "TRUFFLEHOG_BIN_PATH"
    | "SHERLOCK_BIN_PATH"
    | "MAIGRET_BIN_PATH"
    | "HOLEHE_BIN_PATH"
    | "THEHARVESTER_BIN_PATH"
  >
): StaticAdapterRegistry {
  const snusbase = new SnusbaseAdapter({
    apiKey: env?.SNUSBASE_API_KEY ?? "",
    baseUrl: env?.SNUSBASE_API_BASE_URL ?? "https://api.snusbase.com",
  });
  const cliTimeoutMs = env?.CLI_ADAPTER_TIMEOUT_MS ?? 120000;

  const amass = new AmassAdapter({
    binPath: env?.AMASS_BIN_PATH ?? "amass",
    timeoutMs: cliTimeoutMs,
  });
  const trufflehog = new TruffleHogAdapter({
    binPath: env?.TRUFFLEHOG_BIN_PATH ?? "trufflehog",
  });
  const gitleaks = new GitleaksAdapter({
    binPath: env?.GITLEAKS_BIN_PATH ?? "gitleaks",
    gitBinPath: env?.GIT_BIN_PATH ?? "git",
  });
  const sherlock = new SherlockAdapter({
    binPath: env?.SHERLOCK_BIN_PATH ?? "sherlock",
  });
  const maigret = new MaigretAdapter({
    binPath: env?.MAIGRET_BIN_PATH ?? "maigret",
  });
  const holehe = new HoleheAdapter({
    binPath: env?.HOLEHE_BIN_PATH ?? "holehe",
  });
  const theHarvester = new TheHarvesterAdapter({
    binPath: env?.THEHARVESTER_BIN_PATH ?? "theHarvester",
  });

  // Adaptery CLI (klonowanie repo/skanowanie/web scraping subprocess) potrzebuja
  // dluzszego budzetu niz szybkie adaptery HTTP - patrz CLI_ADAPTER_TIMEOUT_MS w env.ts.
  // Bez tego taskRunner uzywa DEFAULT_ADAPTER_TIMEOUT_MS (15s), ktory zabija np.
  // TruffleHog (pelny klon historii git trwa ~60-90s) zanim zwroci jakikolwiek wynik.
  for (const cliAdapter of [amass, trufflehog, gitleaks, sherlock, maigret, holehe, theHarvester]) {
    cliAdapter.descriptor.timeoutMs = cliTimeoutMs;
  }

  return new StaticAdapterRegistry([
    new DemoAdapter(),
    new DnsAdapter(),
    snusbase,
    intelxStub,
    epieosStub,
    amass,
    trufflehog,
    gitleaks,
    sherlock,
    maigret,
    holehe,
    theHarvester,
  ]);
}
