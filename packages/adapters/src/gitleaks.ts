import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { randomUUID } from "node:crypto";
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

interface GitleaksFinding {
  RuleID?: string;
  Description?: string;
  Secret?: string;
  Match?: string;
  File?: string;
  Commit?: string;
  Link?: string;
  Author?: string;
  Email?: string;
  Date?: string;
  Fingerprint?: string;
  StartLine?: number;
}

export interface GitleaksAdapterConfig {
  binPath: string;
  gitBinPath: string;
  spawnFn?: (binPath: string, args: string[], timeoutMs: number, signal: AbortSignal) => Promise<SafeSpawnResult>;
}

/**
 * Adapter Gitleaks - skanuje publiczne repozytorium git (URL) pod katem
 * wyciekniętych sekretow w aktualnym stanie plikow (HEAD).
 *
 * Gitleaks nie potrafi skanowac zdalnego URL bez lokalnej kopii, wiec adapter
 * najpierw robi `git clone --depth 1` do katalogu tymczasowego (tylko HEAD,
 * bez pelnej historii - pelna historia jest juz pokryta przez adapter
 * TruffleHog, ktory klonuje ja sam; powtarzanie tego kosztu w dwoch adapterach
 * nie dawaloby nowej wartosci), skanuje, po czym USUWA katalog tymczasowy
 * niezaleznie od wyniku.
 */
export class GitleaksAdapter implements SourceAdapter {
  readonly descriptor: AdapterDescriptor = {
    id: "gitleaks",
    name: "Gitleaks - sekrety w repozytoriach git (HEAD)",
    category: "code_repository",
    requiredEnvVars: [],
    adapterVersion: "1.0.0",
    capabilities: [{ queryType: "url", supportsWildcards: false, maxResults: 200 }],
    cost: { unit: null, estimatedCostPerQuery: 0, unknown: false },
    setupInstructions: "Wymaga zainstalowanego binarium Gitleaks (GITLEAKS_BIN_PATH) oraz git (GIT_BIN_PATH).",
  };

  constructor(private readonly config: GitleaksAdapterConfig) {}

  isConfigured(): boolean {
    return binaryExists(this.config.binPath);
  }

  getCapabilities(): SourceCapability[] {
    return this.descriptor.capabilities;
  }

  validateQuery(query: SearchQuery): QueryValidation {
    if (query.type !== "url") {
      return { ok: false, reason: "Adapter Gitleaks obsluguje tylko zapytania typu 'url' (adres repozytorium git)" };
    }
    if (query.hasWildcards) {
      return { ok: false, reason: "Adapter Gitleaks nie wspiera wildcardow" };
    }
    if (!/^https:\/\//i.test(query.raw)) {
      return { ok: false, reason: "Adapter Gitleaks wymaga adresu repozytorium zaczynajacego sie od https://" };
    }
    return { ok: true };
  }

  async *search(query: SearchQuery, context: SearchContext): AsyncGenerator<AdapterRecord> {
    const repoUrl = query.raw.trim();
    const run = this.config.spawnFn ?? ((binPath, args, timeoutMs, signal) => safeSpawn(binPath, { args, timeoutMs, signal }));
    const workDir = path.join(os.tmpdir(), `gitleaks-${randomUUID()}`);
    const reportFile = path.join(os.tmpdir(), `gitleaks-report-${randomUUID()}.json`);

    try {
      const cloneTimeoutMs = Math.min(context.timeoutMs, 60_000);
      const clone = await run(this.config.gitBinPath, ["clone", "--quiet", "--depth", "1", repoUrl, workDir], cloneTimeoutMs, context.signal);
      if (context.signal.aborted) return;
      if (clone.exitCode !== 0) {
        context.logger.warn("gitleaks_clone_failed", { repoUrl, stderr: clone.stderr.slice(0, 500) });
        return;
      }

      const scan = await run(
        this.config.binPath,
        ["detect", "-s", workDir, "-f", "json", "-r", reportFile, "--exit-code", "0", "--no-banner"],
        context.timeoutMs,
        context.signal
      );
      if (context.signal.aborted) return;
      if (scan.exitCode !== 0) {
        context.logger.warn("gitleaks_scan_failed", { repoUrl, exitCode: scan.exitCode, stderr: scan.stderr.slice(0, 500) });
        return;
      }

      const findings = await readJsonArrayIfExists(reportFile);
      for (const finding of findings) {
        if (context.signal.aborted) return;
        try {
          yield this.normalizeResult({ repoUrl, finding: finding as GitleaksFinding });
        } catch (err) {
          context.logger.warn("gitleaks_normalize_failed", { error: (err as Error).message });
        }
      }
    } finally {
      await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
      await fs.rm(reportFile, { force: true }).catch(() => {});
    }
  }

  normalizeResult(raw: unknown): AdapterRecord {
    const { repoUrl, finding } = raw as { repoUrl: string; finding: GitleaksFinding };
    const rule = finding.RuleID ?? "unknown";
    const file = finding.File ?? "?";

    return {
      sourceRecordId: finding.Fingerprint ?? `${rule}:${file}:${finding.StartLine ?? 0}`,
      canonicalUrl: finding.Link ?? repoUrl,
      kind: "leaked_secret",
      title: `Sekret (${rule}) w ${file}`,
      summary: finding.Description ?? null,
      attrs: {
        repository: repoUrl,
        file,
        rule,
        commit: finding.Commit ?? null,
        commitAuthor: finding.Author ?? null,
        commitAuthorEmail: finding.Email ?? null,
        // Pelny sekret NIE trafia do attrs (wyswietlanych bez kontroli) - tylko do `raw`.
        secretMasked: true,
        secretPrefix: finding.Secret ? `${finding.Secret.slice(0, 4)}…` : null,
      },
      observedAt: normalizeObservedAt(finding.Date),
      raw: finding,
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    if (!this.isConfigured()) {
      return { ok: false, errorCode: "not_configured", message: "GITLEAKS_BIN_PATH nie wskazuje na istniejacy plik" };
    }
    const startedAt = Date.now();
    try {
      const controller = new AbortController();
      const result = await safeSpawn(this.config.binPath, { args: ["version"], timeoutMs: 5000, signal: controller.signal });
      if (result.exitCode !== 0) {
        return { ok: false, errorCode: "gitleaks_healthcheck_failed", message: result.stderr.slice(0, 300) };
      }
      return { ok: true, latencyMs: Date.now() - startedAt };
    } catch (err) {
      return { ok: false, errorCode: "gitleaks_healthcheck_failed", message: (err as Error).message };
    }
  }
}

function normalizeObservedAt(value: string | undefined): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

async function readJsonArrayIfExists(filePath: string): Promise<unknown[]> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(content);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}
