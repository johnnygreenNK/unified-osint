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
import { safeSpawn, binaryExists, type SafeSpawnResult } from "@unified-osint/core";

export interface SherlockAdapterConfig {
  binPath: string;
  spawnFn?: (args: string[], timeoutMs: number, signal: AbortSignal) => Promise<SafeSpawnResult>;
}

const FOUND_LINE = /^\[\+\]\s+([^:]+):\s+(\S+)/;

/**
 * Adapter Sherlock - sprawdza istnienie konta o danym username na ~400
 * publicznych serwisach. Parsuje stdout (`--print-found`), nie plik wyjsciowy,
 * bo format linii `[+] Site: URL` jest stabilny i prostszy niz lokalizowanie
 * pliku wynikowego.
 */
export class SherlockAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "sherlock",
    name: "Sherlock - wyszukiwanie username",
    category: "username_recon",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "username", supportsWildcards: false, maxResults: 400 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions: "Wymaga zainstalowanego Sherlock (SHERLOCK_BIN_PATH).",
  };

  constructor(private readonly config: SherlockAdapterConfig) {}

  isConfigured(): boolean {
    return binaryExists(this.config.binPath);
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "username") {
      return { ok: false, reason: "Adapter Sherlock obsluguje tylko zapytania typu 'username'" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter Sherlock nie wspiera wildcardow" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const username = query.raw.trim();
    const run = this.config.spawnFn ?? ((args, timeoutMs, signal) => safeSpawn(this.config.binPath, { args, timeoutMs, signal }));
    const result = await run(
      [username, "--print-found", "--no-color", "--timeout", "10"],
      context.timeoutMs,
      context.signal
    );

    if (context.signal.aborted) return;
    if (result.timedOut) {
      context.logger.warn("sherlock_timed_out", { username });
    }

    for (const line of result.stdout.split(/\r?\n/)) {
      if (context.signal.aborted) return;
      const match = FOUND_LINE.exec(line.trim());
      const site = match?.[1];
      const url = match?.[2];
      if (!site || !url) continue;
      yield this.normalizeResult({ username, site: site.trim(), url: url.trim() });
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { username, site, url } = raw as { username: string; site: string; url: string };
    return {
      sourceRecordId: `${site}:${username}`,
      canonicalUrl: url,
      kind: "social_profile",
      title: `${site}: ${username}`,
      summary: `Profil znaleziony na ${site}`,
      attrs: { username, site, url },
      observedAt: new Date().toISOString(),
      raw,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    if (!this.isConfigured()) {
      return { ok: false, errorCode: "not_configured", message: "SHERLOCK_BIN_PATH nie wskazuje na istniejacy plik" };
    }
    const startedAt = Date.now();
    try {
      const controller = new AbortController();
      const result = await safeSpawn(this.config.binPath, { args: ["--version"], timeoutMs: 5000, signal: controller.signal });
      if (result.exitCode !== 0) {
        return { ok: false, errorCode: "sherlock_healthcheck_failed", message: result.stderr.slice(0, 300) };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "sherlock_healthcheck_failed", message: (err as Error).message };
    }
  }
}
