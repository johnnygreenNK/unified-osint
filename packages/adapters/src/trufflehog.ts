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
import { safeSpawn, binaryExists, type SafeSpawnResult } from "@unified-osint/core";

interface TruffleHogFinding {
  SourceMetadata?: { Data?: { Git?: { commit?: string; file?: string; email?: string; repository?: string; timestamp?: string; line?: number } } };
  DetectorName?: string;
  Verified?: boolean;
  Redacted?: string;
  Raw?: string;
  RawV2?: string;
  SecretParts?: Record<string, unknown>;
}

export interface TruffleHogAdapterConfig {
  binPath: string;
  spawnFn?: (args: string[], timeoutMs: number, signal: AbortSignal) => Promise<SafeSpawnResult>;
}

/**
 * Adapter TruffleHog - skanuje publiczne repozytorium git (podane jako URL)
 * pod katem wyciekniętych sekretow (API keys, tokeny).
 *
 * `--no-verification` jest ustawione swiadomie na trwale: TruffleHog domyslnie
 * moze *aktywnie weryfikowac* znalezione dane logujac sie nimi do zewnetrznych
 * API (np. AWS). To wykraczaloby poza pasywne OSINT w nieautoryzowany sposob
 * - wiec adapter tylko *wykrywa* obecnosc sekretu, nigdy go nie testuje.
 * Znaleziona wartosc w pelnej, nieshaskowanej postaci istnieje tylko w `raw`
 * (ten sam wzorzec maskowania co w SnusbaseAdapter) - attrs dostaje jedynie
 * wersje zredagowana przez samo TruffleHog (`Redacted`).
 */
export class TruffleHogAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "trufflehog",
    name: "TruffleHog - sekrety w repozytoriach git",
    category: "code_repository",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "url", supportsWildcards: false, maxResults: 200 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions: "Wymaga zainstalowanego binarium TruffleHog (TRUFFLEHOG_BIN_PATH).",
  };

  constructor(private readonly config: TruffleHogAdapterConfig) {}

  isConfigured(): boolean {
    return binaryExists(this.config.binPath);
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "url") {
      return { ok: false, reason: "Adapter TruffleHog obsluguje tylko zapytania typu 'url' (adres repozytorium git)" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter TruffleHog nie wspiera wildcardow" };
    }
    if (!/^https:\/\//i.test(query.raw)) {
      return { ok: false, reason: "Adapter TruffleHog wymaga adresu repozytorium zaczynajacego sie od https://" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const repoUrl = query.raw.trim();
    const run = this.config.spawnFn ?? ((args, timeoutMs, signal) => safeSpawn(this.config.binPath, { args, timeoutMs, signal }));
    const result = await run(["git", repoUrl, "--json", "--no-verification"], context.timeoutMs, context.signal);

    if (context.signal.aborted) return;
    if (result.timedOut) {
      context.logger.warn("trufflehog_timed_out", { repoUrl });
    }

    for (const line of result.stdout.split(/\r?\n/)) {
      if (context.signal.aborted) return;
      if (!line.trim()) continue;
      let parsed: TruffleHogFinding;
      try {
        parsed = JSON.parse(line) as TruffleHogFinding;
      } catch {
        continue; // linie logow/postepu, nie JSON znaleziska - ignorujemy
      }
      if (typeof parsed.DetectorName !== "string") continue; // linia logu, nie wynik
      try {
        yield this.normalizeResult({ repoUrl, finding: parsed });
      } catch (err) {
        context.logger.warn("trufflehog_normalize_failed", { error: (err as Error).message });
      }
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { repoUrl, finding } = raw as { repoUrl: string; finding: TruffleHogFinding };
    const git = finding.SourceMetadata?.Data?.Git;
    const file = git?.file ?? "?";
    const line = git?.line ?? 0;
    const commit = git?.commit ?? "";
    const detector = finding.DetectorName ?? "unknown";

    return {
      sourceRecordId: sha256(`${commit}:${file}:${line}:${detector}:${finding.Raw ?? ""}`),
      canonicalUrl: git?.repository ?? repoUrl,
      kind: "leaked_secret",
      title: `Sekret (${detector}) w ${file}`,
      summary: `Commit ${commit.slice(0, 10)}, linia ${line}`,
      attrs: {
        repository: git?.repository ?? repoUrl,
        file,
        line,
        commit,
        detector,
        verified: finding.Verified ?? false,
        redacted: finding.Redacted ?? null,
        commitAuthorEmail: git?.email ?? null,
        commitTimestamp: git?.timestamp ?? null,
      },
      observedAt: normalizeObservedAt(git?.timestamp),
      raw: finding,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    if (!this.isConfigured()) {
      return { ok: false, errorCode: "not_configured", message: "TRUFFLEHOG_BIN_PATH nie wskazuje na istniejacy plik" };
    }
    const startedAt = Date.now();
    try {
      const controller = new AbortController();
      const result = await safeSpawn(this.config.binPath, { args: ["--version"], timeoutMs: 5000, signal: controller.signal });
      if (result.exitCode !== 0) {
        return { ok: false, errorCode: "trufflehog_healthcheck_failed", message: result.stderr.slice(0, 300) };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "trufflehog_healthcheck_failed", message: (err as Error).message };
    }
  }
}

function normalizeObservedAt(value: string | undefined): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
