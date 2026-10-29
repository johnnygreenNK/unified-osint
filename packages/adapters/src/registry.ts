import type { Pool } from "pg";
import type { AdapterRegistry, Env, SourceAdapter } from "@unified-osint/core";
import { DemoAdapter } from "./demo.js";
import { DnsAdapter } from "./dns.js";
import { SnusbaseAdapter } from "./snusbase.js";
import { HibpAdapter } from "./hibp.js";
import { LeakCheckAdapter } from "./leakcheck.js";
import { HudsonRockAdapter } from "./hudsonrock.js";
import { CrtShAdapter } from "./crtsh.js";
import { RdapAdapter } from "./rdap.js";
import { WaybackAdapter } from "./wayback.js";
import { ShodanInternetDbAdapter } from "./shodanInternetDb.js";
import { EmailRepAdapter } from "./emailrep.js";
import {
  epieosStub,
  intelxStub,
  dehashedStub,
  spycloudStub,
  flareStub,
  kelaStub,
  constellaStub,
} from "./stubs.js";
import { AmassAdapter } from "./amass.js";
import { TruffleHogAdapter } from "./trufflehog.js";
import { GitleaksAdapter } from "./gitleaks.js";
import { SherlockAdapter } from "./sherlock.js";
import { MaigretAdapter } from "./maigret.js";
import { HoleheAdapter } from "./holehe.js";
import { TheHarvesterAdapter } from "./theHarvester.js";
import { LocalImportAdapter } from "./localImport.js";

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
    | "ADAPTER_DEMO_ENABLED"
    | "SNUSBASE_API_KEY"
    | "SNUSBASE_API_BASE_URL"
    | "HIBP_API_KEY"
    | "HIBP_API_BASE_URL"
    | "HIBP_USER_AGENT"
    | "LEAKCHECK_API_KEY"
    | "LEAKCHECK_API_BASE_URL"
    | "HUDSONROCK_API_KEY"
    | "HUDSONROCK_API_BASE_URL"
    | "ADAPTER_RDAP_ENABLED"
    | "ADAPTER_CRTSH_ENABLED"
    | "ADAPTER_WAYBACK_ENABLED"
    | "ADAPTER_SHODAN_INTERNETDB_ENABLED"
    | "EMAILREP_API_KEY"
    | "EMAILREP_USER_AGENT"
    | "CLI_ADAPTER_TIMEOUT_MS"
    | "GITLEAKS_BIN_PATH"
    | "GIT_BIN_PATH"
    | "AMASS_BIN_PATH"
    | "TRUFFLEHOG_BIN_PATH"
    | "SHERLOCK_BIN_PATH"
    | "MAIGRET_BIN_PATH"
    | "HOLEHE_BIN_PATH"
    | "THEHARVESTER_BIN_PATH"
  >,
  pool?: Pool
): StaticAdapterRegistry {
  const snusbase = new SnusbaseAdapter({
    apiKey: env?.SNUSBASE_API_KEY ?? "",
    baseUrl: env?.SNUSBASE_API_BASE_URL ?? "https://api.snusbase.com",
  });
  const hibp = new HibpAdapter({
    apiKey: env?.HIBP_API_KEY ?? "",
    baseUrl: env?.HIBP_API_BASE_URL ?? "https://haveibeenpwned.com/api/v3",
    userAgent: env?.HIBP_USER_AGENT ?? "UnifiedOSINT",
  });
  const leakcheck = new LeakCheckAdapter({
    apiKey: env?.LEAKCHECK_API_KEY ?? "",
    baseUrl: env?.LEAKCHECK_API_BASE_URL ?? "https://leakcheck.io/api/v2",
  });
  const hudsonrock = new HudsonRockAdapter({
    apiKey: env?.HUDSONROCK_API_KEY ?? "",
    baseUrl: env?.HUDSONROCK_API_BASE_URL ?? "https://api.hudsonrock.com",
  });
  const crtsh = new CrtShAdapter({ enabled: env?.ADAPTER_CRTSH_ENABLED ?? true });
  const rdap = new RdapAdapter({ enabled: env?.ADAPTER_RDAP_ENABLED ?? true });
  const wayback = new WaybackAdapter({ enabled: env?.ADAPTER_WAYBACK_ENABLED ?? true });
  const shodanInternetDb = new ShodanInternetDbAdapter({
    enabled: env?.ADAPTER_SHODAN_INTERNETDB_ENABLED ?? true,
  });
  const emailrep = new EmailRepAdapter({
    apiKey: env?.EMAILREP_API_KEY ?? "",
    userAgent: env?.EMAILREP_USER_AGENT ?? "UnifiedOSINT",
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

  const adapters: SourceAdapter[] = [
    new DnsAdapter(),
    snusbase,
    hibp,
    leakcheck,
    hudsonrock,
    crtsh,
    rdap,
    wayback,
    shodanInternetDb,
    emailrep,
    intelxStub,
    epieosStub,
    dehashedStub,
    spycloudStub,
    flareStub,
    kelaStub,
    constellaStub,
    amass,
    trufflehog,
    gitleaks,
    sherlock,
    maigret,
    holehe,
    theHarvester,
  ];

  // DemoAdapter zwraca wylacznie syntetyczne dane testowe - domyslnie
  // wylaczony, zeby nie zaśmiecal realnych wynikow wyszukiwania.
  if (env?.ADAPTER_DEMO_ENABLED) {
    adapters.push(new DemoAdapter());
  }

  // Bez poola nie da sie przeszukac tabeli wlasnych importow (wymaga RLS
  // app.user_id) - adapter jest wtedy po prostu nieobecny w rejestrze
  // (np. w testach jednostkowych, ktore nie przekazuja bazy).
  if (pool) {
    adapters.push(new LocalImportAdapter({ pool }));
  }

  return new StaticAdapterRegistry(adapters);
}
